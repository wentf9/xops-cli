package sshenv

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	core "github.com/wentf9/xops-cli/core/ssh"
)

type mockDNSBehavior struct {
	rcode     uint16
	ad        bool
	truncate  bool // UDP answers with TC=1 and no records
	badID     bool
	silent    bool
	records   []core.SSHFPRecord
	queryFlag func(flags uint16, hasDO bool)
}

// buildMockDNSResponse echoes the question and answers with compressed-name SSHFP RRs.
func buildMockDNSResponse(query []byte, b mockDNSBehavior, overUDP bool) []byte {
	qEnd := sshfpQuestionEnd(query)
	resp := append([]byte(nil), query[:qEnd]...)
	id := binary.BigEndian.Uint16(query[0:])
	if b.badID {
		id++
	}
	binary.BigEndian.PutUint16(resp[0:], id)
	flags := uint16(dnsFlagQR|dnsFlagRD) | b.rcode
	if b.ad {
		flags |= dnsFlagAD
	}
	records := b.records
	if overUDP && b.truncate {
		flags |= dnsFlagTC
		records = nil
	}
	binary.BigEndian.PutUint16(resp[2:], flags)
	binary.BigEndian.PutUint16(resp[6:], uint16(len(records)+1))
	binary.BigEndian.PutUint16(resp[8:], 0)
	binary.BigEndian.PutUint16(resp[10:], 0)
	// A non-SSHFP answer (CNAME-like type 5) that must be skipped.
	resp = append(resp, 0xc0, 0x0c)
	resp = binary.BigEndian.AppendUint16(resp, 5)
	resp = binary.BigEndian.AppendUint16(resp, dnsClassIN)
	resp = binary.BigEndian.AppendUint32(resp, 60)
	resp = binary.BigEndian.AppendUint16(resp, 2)
	resp = append(resp, 0xc0, 0x0c)
	for _, r := range records {
		resp = append(resp, 0xc0, 0x0c)
		resp = binary.BigEndian.AppendUint16(resp, dnsTypeSSHFP)
		resp = binary.BigEndian.AppendUint16(resp, dnsClassIN)
		resp = binary.BigEndian.AppendUint32(resp, 60)
		resp = binary.BigEndian.AppendUint16(resp, uint16(2+len(r.Fingerprint)))
		resp = append(resp, r.Algorithm, r.FingerprintType)
		resp = append(resp, r.Fingerprint...)
	}
	return resp
}

func inspectQuery(query []byte, b mockDNSBehavior) {
	if b.queryFlag == nil || len(query) < 12 {
		return
	}
	flags := binary.BigEndian.Uint16(query[2:])
	qEnd := sshfpQuestionEnd(query)
	hasDO := len(query) >= qEnd+11 && binary.BigEndian.Uint16(query[qEnd+1:]) == dnsTypeOPT &&
		binary.BigEndian.Uint32(query[qEnd+5:])&0x8000 != 0
	b.queryFlag(flags, hasDO)
}

// startMockDNS serves one behavior over loopback UDP and TCP. Both servers stop at test cleanup.
func startMockDNS(t *testing.T, b mockDNSBehavior) (udpAddr, tcpAddr string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = pc.Close()
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = pc.Close()
		_ = ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			query := append([]byte(nil), buf[:n]...)
			inspectQuery(query, b)
			if b.silent {
				continue
			}
			_, _ = pc.WriteTo(buildMockDNSResponse(query, b, true), from)
		}
	})
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			func() {
				defer func() { _ = conn.Close() }()
				var lenBuf [2]byte
				if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				resp := buildMockDNSResponse(query, b, false)
				out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
				_, _ = conn.Write(append(out, resp...))
			}()
		}
	})
	return pc.LocalAddr().String(), ln.Addr().String()
}

func testResolver(servers []string, tcpAddrs map[string]string) *sshfpResolver {
	var dialer net.Dialer
	return &sshfpResolver{
		servers: func() []string { return servers },
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network == "tcp" {
				address = tcpAddrs[address]
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
}

func loopbackRecords() []core.SSHFPRecord {
	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = byte(i)
	}
	return []core.SSHFPRecord{{Algorithm: 4, FingerprintType: 2, Fingerprint: fp}, {Algorithm: 1, FingerprintType: 1, Fingerprint: fp[:20]}}
}

func TestSSHFPResolver_AuthenticatedAnswerWithRdAdDoQueryFlags(t *testing.T) {
	records := loopbackRecords()
	var sawFlags, sawDO bool
	var mu sync.Mutex
	udp, tcp := startMockDNS(t, mockDNSBehavior{ad: true, records: records, queryFlag: func(flags uint16, hasDO bool) {
		mu.Lock()
		defer mu.Unlock()
		sawFlags = flags&dnsFlagRD != 0 && flags&dnsFlagAD != 0
		sawDO = hasDO
	}})
	res, err := testResolver([]string{udp}, map[string]string{udp: tcp}).Lookup(t.Context(), "host.example.com.")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Authenticated || len(res.Records) != 2 || res.Records[0].Algorithm != 4 || len(res.Records[0].Fingerprint) != 32 {
		t.Fatalf("unexpected result %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if !sawFlags || !sawDO {
		t.Fatalf("query flags RD+AD=%v DO=%v", sawFlags, sawDO)
	}
}

func TestSSHFPResolver_UnauthenticatedAnswer(t *testing.T) {
	records := loopbackRecords()
	udp, tcp := startMockDNS(t, mockDNSBehavior{records: records})
	res, err := testResolver([]string{udp}, map[string]string{udp: tcp}).Lookup(t.Context(), "host.example.com")
	if err != nil || res.Authenticated || len(res.Records) != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestSSHFPResolver_TruncatedUdpRetriesOverTcp(t *testing.T) {
	records := loopbackRecords()
	udp, tcp := startMockDNS(t, mockDNSBehavior{ad: true, truncate: true, records: records})
	res, err := testResolver([]string{udp}, map[string]string{udp: tcp}).Lookup(t.Context(), "host.example.com")
	if err != nil || !res.Authenticated || len(res.Records) != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestSSHFPResolver_NxdomainReturnsNoRecords(t *testing.T) {
	udp, tcp := startMockDNS(t, mockDNSBehavior{rcode: dnsRcodeNXDomain})
	res, err := testResolver([]string{udp}, map[string]string{udp: tcp}).Lookup(t.Context(), "missing.example.com")
	if err != nil || len(res.Records) != 0 || res.Authenticated {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestSSHFPResolver_ServfailAndBadIdFallThroughToNextServer(t *testing.T) {
	records := loopbackRecords()
	failUDP, failTCP := startMockDNS(t, mockDNSBehavior{rcode: 2})
	spoofUDP, spoofTCP := startMockDNS(t, mockDNSBehavior{badID: true, ad: true, records: records})
	okUDP, okTCP := startMockDNS(t, mockDNSBehavior{records: records[:1]})
	r := testResolver([]string{failUDP, spoofUDP, okUDP}, map[string]string{failUDP: failTCP, spoofUDP: spoofTCP, okUDP: okTCP})
	res, err := r.Lookup(t.Context(), "host.example.com")
	if err != nil || res.Authenticated || len(res.Records) != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if _, err := testResolver([]string{spoofUDP}, map[string]string{spoofUDP: spoofTCP}).Lookup(t.Context(), "host.example.com"); err == nil {
		t.Fatal("spoofed ID response must be rejected")
	}
}

func TestSSHFPResolver_SilentServerHonorsContextCancellation(t *testing.T) {
	udp, tcp := startMockDNS(t, mockDNSBehavior{silent: true})
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := testResolver([]string{udp}, map[string]string{udp: tcp}).Lookup(ctx, "host.example.com")
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("lookup took %s after cancellation", elapsed)
	}
}

func TestSSHFPResolver_InvalidNamesRejectedWithoutNetwork(t *testing.T) {
	r := testResolver(nil, nil)
	for _, name := range []string{"", "192.0.2.1", "::1", "bad..name", "sp ace.example"} {
		if _, err := r.Lookup(t.Context(), name); err == nil {
			t.Fatalf("expected error for %q", name)
		}
	}
	if _, err := r.Lookup(t.Context(), "host.example.com"); err == nil {
		t.Fatal("expected error with no servers")
	}
}

func TestParseSSHFPAnswersRejectsMalformed(t *testing.T) {
	query, _, err := buildSSHFPQuery("host.example.com")
	if err != nil {
		t.Fatal(err)
	}
	resp := buildMockDNSResponse(query, mockDNSBehavior{records: []core.SSHFPRecord{{Algorithm: 4, FingerprintType: 2, Fingerprint: make([]byte, 32)}}}, false)
	for cut := sshfpQuestionEnd(query) + 1; cut < len(resp); cut += 7 {
		if _, err := parseSSHFPAnswers(resp[:cut]); err == nil {
			t.Fatalf("truncated response at %d must fail", cut)
		}
	}
	if !errors.Is(func() error { _, err := skipDNSName([]byte{0x80}, 0); return err }(), errDNSMalformed) {
		t.Fatal("reserved label type must be malformed")
	}
}
