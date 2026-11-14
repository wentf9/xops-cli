package sshenv

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
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
	customUDP func(pc net.PacketConn, from net.Addr, query []byte)
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
	// A non-SSHFP answer (A record type 1) that must be tolerated alongside SSHFP RRs.
	resp = append(resp, 0xc0, 0x0c)
	resp = binary.BigEndian.AppendUint16(resp, 1) // A
	resp = binary.BigEndian.AppendUint16(resp, dnsClassIN)
	resp = binary.BigEndian.AppendUint32(resp, 60)
	resp = binary.BigEndian.AppendUint16(resp, 4)
	resp = append(resp, 127, 0, 0, 1)
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

func appendWireDNSName(dst []byte, name string) []byte {
	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return append(dst, 0)
	}
	for _, label := range strings.Split(trimmed, ".") {
		dst = append(dst, byte(len(label)))
		dst = append(dst, label...)
	}
	return append(dst, 0)
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
			if b.customUDP != nil {
				b.customUDP(pc, from, query)
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
	return testResolverWithConfig(dnsConfig{servers: servers}, nil, tcpAddrs)
}

func testResolverWithConfig(cfg dnsConfig, udpAddrs, tcpAddrs map[string]string) *sshfpResolver {
	var dialer net.Dialer
	return &sshfpResolver{
		config: func() dnsConfig { return cfg },
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			switch network {
			case "tcp":
				if mapped, ok := tcpAddrs[address]; ok {
					address = mapped
				}
			case "udp":
				if mapped, ok := udpAddrs[address]; ok {
					address = mapped
				}
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

func TestSSHFPResolver_ADBitTrustedOnlyOnLoopbackOrTrustAD(t *testing.T) {
	records := loopbackRecords()
	udp, tcp := startMockDNS(t, mockDNSBehavior{ad: true, records: records})

	// 1. Non-loopback server with AD=1 on wire and trustAD=false MUST return Authenticated=false.
	nonLoopback := "192.0.2.53:53"
	rUntrusted := testResolverWithConfig(
		dnsConfig{servers: []string{nonLoopback}, trustAD: false},
		map[string]string{nonLoopback: udp},
		map[string]string{nonLoopback: tcp},
	)
	res, err := rUntrusted.Lookup(t.Context(), "host.example.com")
	if err != nil {
		t.Fatalf("non-loopback lookup failed: %v", err)
	}
	if res.Authenticated {
		t.Fatalf("non-loopback AD=1 without trust-ad must force Authenticated=false, got %+v", res)
	}
	if len(res.Records) != 2 {
		t.Fatalf("expected 2 unauthenticated SSHFP records, got %d", len(res.Records))
	}

	// 2. systemd-resolved loopback stub 127.0.0.53:53 and IPv6 [::1]:53 with AD=1 and trustAD=false return Authenticated=true.
	for _, lb := range []string{"127.0.0.53:53", "[::1]:53"} {
		rLoopback := testResolverWithConfig(
			dnsConfig{servers: []string{lb}, trustAD: false},
			map[string]string{lb: udp},
			map[string]string{lb: tcp},
		)
		lbRes, lbErr := rLoopback.Lookup(t.Context(), "host.example.com")
		if lbErr != nil {
			t.Fatalf("loopback %s lookup failed: %v", lb, lbErr)
		}
		if !lbRes.Authenticated || len(lbRes.Records) != 2 {
			t.Fatalf("loopback %s AD=1 should be Authenticated=true, got %+v", lb, lbRes)
		}
	}

	// 3. Non-loopback server with AD=1 AND options trust-ad (trustAD=true) returns Authenticated=true.
	rTrustAD := testResolverWithConfig(
		dnsConfig{servers: []string{nonLoopback}, trustAD: true},
		map[string]string{nonLoopback: udp},
		map[string]string{nonLoopback: tcp},
	)
	trustRes, err := rTrustAD.Lookup(t.Context(), "host.example.com")
	if err != nil {
		t.Fatalf("trust-ad lookup failed: %v", err)
	}
	if !trustRes.Authenticated || len(trustRes.Records) != 2 {
		t.Fatalf("non-loopback AD=1 with trust-ad should be Authenticated=true, got %+v", trustRes)
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

	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	r := testResolver([]string{failUDP, spoofUDP, okUDP}, map[string]string{failUDP: failTCP, spoofUDP: spoofTCP, okUDP: okTCP})
	res, err := r.Lookup(ctx, "host.example.com")
	if err != nil || res.Authenticated || len(res.Records) != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}

	spoofCtx, spoofCancel := context.WithTimeout(t.Context(), 120*time.Millisecond)
	defer spoofCancel()
	if _, err := testResolver([]string{spoofUDP}, map[string]string{spoofUDP: spoofTCP}).Lookup(spoofCtx, "host.example.com"); err == nil {
		t.Fatal("spoofed ID response must be rejected")
	}
}

func TestSSHFPResolver_BlackholedFirstServerDoesNotStarveFallbackAndDropsStrayUDP(t *testing.T) {
	records := loopbackRecords()
	silentUDP, silentTCP := startMockDNS(t, mockDNSBehavior{silent: true})

	// Second server sends a wrong-txid datagram and a wrong-question datagram BEFORE the valid reply!
	resilientUDP, resilientTCP := startMockDNS(t, mockDNSBehavior{
		ad:      true,
		records: records[:1],
		customUDP: func(pc net.PacketConn, from net.Addr, query []byte) {
			badTx := buildMockDNSResponse(query, mockDNSBehavior{badID: true, ad: true, records: records}, true)
			_, _ = pc.WriteTo(badTx, from)

			otherQuery, _, qErr := buildSSHFPQuery("other.example.com")
			if qErr == nil {
				binary.BigEndian.PutUint16(otherQuery[0:], binary.BigEndian.Uint16(query[0:]))
				badQ := buildMockDNSResponse(otherQuery, mockDNSBehavior{ad: true, records: records}, true)
				_, _ = pc.WriteTo(badQ, from)
			}

			good := buildMockDNSResponse(query, mockDNSBehavior{ad: true, records: records[:1]}, true)
			_, _ = pc.WriteTo(good, from)
		},
	})

	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	r := testResolver(
		[]string{silentUDP, resilientUDP},
		map[string]string{silentUDP: silentTCP, resilientUDP: resilientTCP},
	)
	res, err := r.Lookup(ctx, "host.example.com")
	if err != nil {
		t.Fatalf("expected failover to second server and recovery past stray UDP packets, got err: %v", err)
	}
	if !res.Authenticated || len(res.Records) != 1 || res.Records[0].Algorithm != 4 {
		t.Fatalf("unexpected failover result: %+v", res)
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

func TestParseSSHFPAnswers_RejectsUnrelatedOwnerAndFollowsCNAMEChain(t *testing.T) {
	query, id, err := buildSSHFPQuery("App.Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	qEnd := sshfpQuestionEnd(query)
	fpEvil := bytesRepeat(0xaa, 32)
	fpMid := bytesRepeat(0xbb, 32)
	fpCanon := bytesRepeat(0xcc, 32)

	// 1. Unrelated owner injection alone -> 0 accepted records.
	unrelated := append([]byte(nil), query[:qEnd]...)
	binary.BigEndian.PutUint16(unrelated[0:], id)
	binary.BigEndian.PutUint16(unrelated[2:], dnsFlagQR|dnsFlagRD|dnsFlagAD)
	binary.BigEndian.PutUint16(unrelated[6:], 1) // ANCOUNT = 1
	binary.BigEndian.PutUint16(unrelated[10:], 0)
	unrelated = appendWireDNSName(unrelated, "evil.example.com")
	unrelated = binary.BigEndian.AppendUint16(unrelated, dnsTypeSSHFP)
	unrelated = binary.BigEndian.AppendUint16(unrelated, dnsClassIN)
	unrelated = binary.BigEndian.AppendUint32(unrelated, 60)
	unrelated = binary.BigEndian.AppendUint16(unrelated, uint16(2+len(fpEvil)))
	unrelated = append(unrelated, 4, 2)
	unrelated = append(unrelated, fpEvil...)

	gotUnrelated, err := parseSSHFPAnswers(unrelated)
	if err != nil {
		t.Fatalf("parseSSHFPAnswers(unrelated) failed: %v", err)
	}
	if len(gotUnrelated) != 0 {
		t.Fatalf("unrelated owner SSHFP must be ignored, got %+v", gotUnrelated)
	}

	// 2. Valid 2-hop case-insensitive CNAME chain:
	//    app.example.com -> mid.example.com -> canon.example.net
	//    plus injected SSHFP at evil.example.com and mid.example.com; only canon.example.net SSHFP is accepted!
	cnameResp := append([]byte(nil), query[:qEnd]...)
	binary.BigEndian.PutUint16(cnameResp[0:], id)
	binary.BigEndian.PutUint16(cnameResp[2:], dnsFlagQR|dnsFlagRD|dnsFlagAD)
	binary.BigEndian.PutUint16(cnameResp[6:], 5) // 2 CNAME + 3 SSHFP
	binary.BigEndian.PutUint16(cnameResp[10:], 0)

	// RR 1: app.example.com (compressed 0xc0 0x0c) CNAME MID.example.com
	cnameResp = append(cnameResp, 0xc0, 0x0c)
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, dnsTypeCNAME)
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, dnsClassIN)
	cnameResp = binary.BigEndian.AppendUint32(cnameResp, 60)
	midTarget := appendWireDNSName(nil, "MID.example.com")
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, uint16(len(midTarget)))
	cnameResp = append(cnameResp, midTarget...)

	// RR 2: mid.example.com CNAME Canon.Example.NET
	cnameResp = appendWireDNSName(cnameResp, "mid.example.com")
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, dnsTypeCNAME)
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, dnsClassIN)
	cnameResp = binary.BigEndian.AppendUint32(cnameResp, 60)
	canonTarget := appendWireDNSName(nil, "Canon.Example.NET")
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, uint16(len(canonTarget)))
	cnameResp = append(cnameResp, canonTarget...)

	// RR 3: evil.example.com SSHFP (must be rejected)
	cnameResp = appendWireDNSName(cnameResp, "evil.example.com")
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, dnsTypeSSHFP)
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, dnsClassIN)
	cnameResp = binary.BigEndian.AppendUint32(cnameResp, 60)
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, uint16(2+len(fpEvil)))
	cnameResp = append(cnameResp, 1, 2)
	cnameResp = append(cnameResp, fpEvil...)

	// RR 4: mid.example.com SSHFP (intermediate CNAME hop, not canonical target; must be rejected)
	cnameResp = appendWireDNSName(cnameResp, "mid.example.com")
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, dnsTypeSSHFP)
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, dnsClassIN)
	cnameResp = binary.BigEndian.AppendUint32(cnameResp, 60)
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, uint16(2+len(fpMid)))
	cnameResp = append(cnameResp, 2, 2)
	cnameResp = append(cnameResp, fpMid...)

	// RR 5: canon.example.net SSHFP (canonical target; must be accepted!)
	cnameResp = appendWireDNSName(cnameResp, "canon.example.net")
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, dnsTypeSSHFP)
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, dnsClassIN)
	cnameResp = binary.BigEndian.AppendUint32(cnameResp, 60)
	cnameResp = binary.BigEndian.AppendUint16(cnameResp, uint16(2+len(fpCanon)))
	cnameResp = append(cnameResp, 4, 2)
	cnameResp = append(cnameResp, fpCanon...)

	gotCNAME, err := parseSSHFPAnswers(cnameResp)
	if err != nil {
		t.Fatalf("parseSSHFPAnswers(cnameResp) failed: %v", err)
	}
	if len(gotCNAME) != 1 || gotCNAME[0].Algorithm != 4 || string(gotCNAME[0].Fingerprint) != string(fpCanon) {
		t.Fatalf("expected only canonical CNAME target SSHFP record, got %+v", gotCNAME)
	}

	// 3. Alias-owned SSHFP forged alongside a CNAME (app.example.com CNAME canon.example.net + app.example.com SSHFP)
	//    must NOT be accepted (only canonicalTarget SSHFP is valid).
	aliasForged := append([]byte(nil), query[:qEnd]...)
	binary.BigEndian.PutUint16(aliasForged[0:], id)
	binary.BigEndian.PutUint16(aliasForged[2:], dnsFlagQR|dnsFlagRD|dnsFlagAD)
	binary.BigEndian.PutUint16(aliasForged[6:], 2) // 1 CNAME + 1 SSHFP on qname
	binary.BigEndian.PutUint16(aliasForged[10:], 0)
	aliasForged = append(aliasForged, 0xc0, 0x0c)
	aliasForged = binary.BigEndian.AppendUint16(aliasForged, dnsTypeCNAME)
	aliasForged = binary.BigEndian.AppendUint16(aliasForged, dnsClassIN)
	aliasForged = binary.BigEndian.AppendUint32(aliasForged, 60)
	aliasForged = binary.BigEndian.AppendUint16(aliasForged, uint16(len(canonTarget)))
	aliasForged = append(aliasForged, canonTarget...)
	aliasForged = append(aliasForged, 0xc0, 0x0c) // owner == qname (alias, NOT canonicalTarget!)
	aliasForged = binary.BigEndian.AppendUint16(aliasForged, dnsTypeSSHFP)
	aliasForged = binary.BigEndian.AppendUint16(aliasForged, dnsClassIN)
	aliasForged = binary.BigEndian.AppendUint32(aliasForged, 60)
	aliasForged = binary.BigEndian.AppendUint16(aliasForged, uint16(2+len(fpEvil)))
	aliasForged = append(aliasForged, 4, 2)
	aliasForged = append(aliasForged, fpEvil...)

	gotAliasForged, err := parseSSHFPAnswers(aliasForged)
	if err != nil {
		t.Fatalf("parseSSHFPAnswers(aliasForged) failed: %v", err)
	}
	if len(gotAliasForged) != 0 {
		t.Fatalf("SSHFP owned by alias qname must be ignored when CNAME points elsewhere, got %+v", gotAliasForged)
	}

	// 4. Multi-node CNAME cycle (app -> mid -> app) with SSHFP on mid must fail closed (errDNSMalformed),
	//    never accepting intermediate alias SSHFP RRs!
	cycleResp := append([]byte(nil), query[:qEnd]...)
	binary.BigEndian.PutUint16(cycleResp[0:], id)
	binary.BigEndian.PutUint16(cycleResp[2:], dnsFlagQR|dnsFlagRD|dnsFlagAD)
	binary.BigEndian.PutUint16(cycleResp[6:], 3)
	binary.BigEndian.PutUint16(cycleResp[10:], 0)
	// app.example.com -> mid.example.com
	cycleResp = append(cycleResp, 0xc0, 0x0c)
	cycleResp = binary.BigEndian.AppendUint16(cycleResp, dnsTypeCNAME)
	cycleResp = binary.BigEndian.AppendUint16(cycleResp, dnsClassIN)
	cycleResp = binary.BigEndian.AppendUint32(cycleResp, 60)
	cycleResp = binary.BigEndian.AppendUint16(cycleResp, uint16(len(midTarget)))
	cycleResp = append(cycleResp, midTarget...)
	// mid.example.com -> app.example.com
	appTarget := appendWireDNSName(nil, "app.example.com")
	cycleResp = appendWireDNSName(cycleResp, "mid.example.com")
	cycleResp = binary.BigEndian.AppendUint16(cycleResp, dnsTypeCNAME)
	cycleResp = binary.BigEndian.AppendUint16(cycleResp, dnsClassIN)
	cycleResp = binary.BigEndian.AppendUint32(cycleResp, 60)
	cycleResp = binary.BigEndian.AppendUint16(cycleResp, uint16(len(appTarget)))
	cycleResp = append(cycleResp, appTarget...)
	// mid.example.com SSHFP
	cycleResp = appendWireDNSName(cycleResp, "mid.example.com")
	cycleResp = binary.BigEndian.AppendUint16(cycleResp, dnsTypeSSHFP)
	cycleResp = binary.BigEndian.AppendUint16(cycleResp, dnsClassIN)
	cycleResp = binary.BigEndian.AppendUint32(cycleResp, 60)
	cycleResp = binary.BigEndian.AppendUint16(cycleResp, uint16(2+len(fpMid)))
	cycleResp = append(cycleResp, 4, 2)
	cycleResp = append(cycleResp, fpMid...)

	if gotCycle, cycleErr := parseSSHFPAnswers(cycleResp); !errors.Is(cycleErr, errDNSMalformed) || len(gotCycle) != 0 {
		t.Fatalf("multi-node CNAME cycle = (%+v, %v), want (nil, errDNSMalformed)", gotCycle, cycleErr)
	}

	// 5. >8-hop CNAME chain (9 hops) with intermediate SSHFP must also fail closed (errDNSMalformed).
	longResp := append([]byte(nil), query[:qEnd]...)
	binary.BigEndian.PutUint16(longResp[0:], id)
	binary.BigEndian.PutUint16(longResp[2:], dnsFlagQR|dnsFlagRD|dnsFlagAD)
	binary.BigEndian.PutUint16(longResp[6:], uint16(dnsMaxCNAMEHops+2)) // 9 CNAMEs + 1 intermediate SSHFP
	binary.BigEndian.PutUint16(longResp[10:], 0)
	curOwner := "app.example.com"
	for hopIdx := range dnsMaxCNAMEHops + 1 {
		nextOwner := "hop" + string(rune('a'+hopIdx)) + ".example.net"
		longResp = appendWireDNSName(longResp, curOwner)
		longResp = binary.BigEndian.AppendUint16(longResp, dnsTypeCNAME)
		longResp = binary.BigEndian.AppendUint16(longResp, dnsClassIN)
		longResp = binary.BigEndian.AppendUint32(longResp, 60)
		targetWire := appendWireDNSName(nil, nextOwner)
		longResp = binary.BigEndian.AppendUint16(longResp, uint16(len(targetWire)))
		longResp = append(longResp, targetWire...)
		curOwner = nextOwner
	}
	hop8Name := "hop" + string(rune('a'+dnsMaxCNAMEHops-1)) + ".example.net"
	longResp = appendWireDNSName(longResp, hop8Name)
	longResp = binary.BigEndian.AppendUint16(longResp, dnsTypeSSHFP)
	longResp = binary.BigEndian.AppendUint16(longResp, dnsClassIN)
	longResp = binary.BigEndian.AppendUint32(longResp, 60)
	longResp = binary.BigEndian.AppendUint16(longResp, uint16(2+len(fpMid)))
	longResp = append(longResp, 4, 2)
	longResp = append(longResp, fpMid...)

	if gotLong, longErr := parseSSHFPAnswers(longResp); !errors.Is(longErr, errDNSMalformed) || len(gotLong) != 0 {
		t.Fatalf(">8-hop CNAME chain = (%+v, %v), want (nil, errDNSMalformed)", gotLong, longErr)
	}
}

func TestSSHFPResolver_DeduplicatesServersBeforeMaxServerCap(t *testing.T) {
	records := loopbackRecords()
	failUDP, failTCP := startMockDNS(t, mockDNSBehavior{rcode: 2})
	okUDP, okTCP := startMockDNS(t, mockDNSBehavior{ad: true, records: records[:1]})

	// Without deduplication before dnsMaxServers (3), three copies of failUDP would crowd out okUDP!
	r := testResolver(
		[]string{failUDP, failUDP, failUDP, okUDP},
		map[string]string{failUDP: failTCP, okUDP: okTCP},
	)
	res, err := r.Lookup(t.Context(), "host.example.com")
	if err != nil {
		t.Fatalf("Lookup with duplicate servers before fallback failed: %v", err)
	}
	if !res.Authenticated || len(res.Records) != 1 {
		t.Fatalf("unexpected deduplicated failover result: %+v", res)
	}
}

func TestReadCanonicalDNSName_RejectsSelfForwardAndExcessivePointers(t *testing.T) {
	// Self-compression pointer at offset 12 (0xc0 0x0c) -> rejected!
	selfMsg := append(make([]byte, 12), 0xc0, 0x0c)
	if _, _, err := readCanonicalDNSName(selfMsg, 12); !errors.Is(err, errDNSMalformed) {
		t.Fatalf("self-pointer error = %v, want errDNSMalformed", err)
	}

	// Forward compression pointer at offset 12 -> offset 14 -> rejected!
	fwdMsg := append(make([]byte, 12), 0xc0, 0x0e, 0x01, 'a', 0x00)
	if _, _, err := readCanonicalDNSName(fwdMsg, 12); !errors.Is(err, errDNSMalformed) {
		t.Fatalf("forward-pointer error = %v, want errDNSMalformed", err)
	}

	// Pointer into 12-byte DNS header (0xc0 0x04) -> rejected!
	hdrMsg := append(make([]byte, 12), 0x01, 'a', 0xc0, 0x04)
	if _, _, err := readCanonicalDNSName(hdrMsg, 12); !errors.Is(err, errDNSMalformed) {
		t.Fatalf("header-pointer error = %v, want errDNSMalformed", err)
	}

	// Backward pointer chain exceeding dnsMaxCompressionJumps -> rejected!
	chain := make([]byte, 12)
	chain = append(chain, 0x01, 'z', 0x00) // offset 12..14
	prev := 12
	for range dnsMaxCompressionJumps + 2 {
		cur := len(chain)
		chain = append(chain, 0x01, 'a', 0xc0|byte(prev>>8), byte(prev))
		prev = cur
	}
	if _, _, err := readCanonicalDNSName(chain, prev); !errors.Is(err, errDNSMalformed) {
		t.Fatalf("excessive compression jump chain error = %v, want errDNSMalformed", err)
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

func TestFormatWindowsDNSServerIPv6_PreservesScopeIDZone(t *testing.T) {
	ll := netip.MustParseAddr("fe80::1").As16()
	got, ok := formatWindowsDNSServerIPv6(ll, 12)
	if !ok || got != "[fe80::1%12]:53" {
		t.Fatalf("link-local with ScopeId=12 = (%q, %v), want ([fe80::1%%12]:53, true)", got, ok)
	}

	global := netip.MustParseAddr("2001:4860:4860::8888").As16()
	gotGlobal, ok := formatWindowsDNSServerIPv6(global, 0)
	if !ok || gotGlobal != "[2001:4860:4860::8888]:53" {
		t.Fatalf("global IPv6 = (%q, %v), want ([2001:4860:4860::8888]:53, true)", gotGlobal, ok)
	}

	siteLocal := netip.MustParseAddr("fec0:0:0:ffff::1").As16()
	if _, ok := formatWindowsDNSServerIPv6(siteLocal, 0); ok {
		t.Fatal("fec0::/10 site-local Windows placeholder DNS address must be skipped")
	}
	if _, ok := formatWindowsDNSServerIPv6([16]byte{}, 0); ok {
		t.Fatal("unspecified :: address must be skipped")
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestSSHFPResolver_SelfCNAMEFailover(t *testing.T) {
	records := loopbackRecords()
	// Primary DNS returns a malformed self-referential CNAME (host -> host) with no SSHFP.
	primaryUDP, primaryTCP := startMockDNS(t, mockDNSBehavior{
		ad: true,
		customUDP: func(pc net.PacketConn, from net.Addr, query []byte) {
			qEnd := sshfpQuestionEnd(query)
			resp := append([]byte(nil), query[:qEnd]...)
			binary.BigEndian.PutUint16(resp[2:], dnsFlagQR|dnsFlagRD|dnsFlagAD)
			binary.BigEndian.PutUint16(resp[6:], 1)
			binary.BigEndian.PutUint16(resp[8:], 0)
			binary.BigEndian.PutUint16(resp[10:], 0)
			resp = append(resp, 0xc0, 0x0c)
			resp = binary.BigEndian.AppendUint16(resp, dnsTypeCNAME)
			resp = binary.BigEndian.AppendUint16(resp, dnsClassIN)
			resp = binary.BigEndian.AppendUint32(resp, 60)
			resp = binary.BigEndian.AppendUint16(resp, 2)
			resp = append(resp, 0xc0, 0x0c)
			_, _ = pc.WriteTo(resp, from)
		},
	})
	// Secondary DNS returns a valid AD=1 SSHFP answer.
	secondaryUDP, secondaryTCP := startMockDNS(t, mockDNSBehavior{ad: true, records: records})

	res, err := testResolver(
		[]string{primaryUDP, secondaryUDP},
		map[string]string{primaryUDP: primaryTCP, secondaryUDP: secondaryTCP},
	).Lookup(t.Context(), "host.example.com.")
	if err != nil {
		t.Fatalf("expected failover to secondary DNS on self-CNAME, got error: %v", err)
	}
	if !res.Authenticated || len(res.Records) != len(records) {
		t.Fatalf("unexpected failover result: %+v", res)
	}
}
