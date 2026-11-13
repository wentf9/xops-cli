package sshenv

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	core "github.com/wentf9/xops-cli/core/ssh"
)

const (
	dnsTypeSSHFP      = 44
	dnsTypeOPT        = 41
	dnsClassIN        = 1
	dnsUDPPayloadSize = 4096
	dnsMaxLookupTime  = 5 * time.Second
	dnsMaxServers     = 3

	dnsFlagQR = 1 << 15
	dnsFlagTC = 1 << 9
	dnsFlagRD = 1 << 8
	dnsFlagAD = 1 << 5

	dnsRcodeSuccess  = 0
	dnsRcodeNXDomain = 3
)

var errDNSMalformed = errors.New("malformed DNS response")

// sshfpResolver is a minimal RFC 1035 + EDNS0 (DO=1) stub resolver for SSHFP.
// It sets RD and AD on queries and reports the response AD bit as
// Authenticated, so DNSSEC validation is delegated to the configured resolver.
type sshfpResolver struct {
	servers func() []string
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
}

func newSystemSSHFPLookup() func(context.Context, string) (core.SSHFPResult, error) {
	var dialer net.Dialer
	r := &sshfpResolver{servers: systemDNSServers, dial: dialer.DialContext}
	return r.Lookup
}

// Lookup queries the configured servers in order and returns the first
// authoritative answer. NXDOMAIN and empty answers return no records.
func (r *sshfpResolver) Lookup(ctx context.Context, hostname string) (core.SSHFPResult, error) {
	name, err := normalizeDNSName(hostname)
	if err != nil {
		return core.SSHFPResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, dnsMaxLookupTime)
	defer cancel()

	servers := r.servers()
	if len(servers) > dnsMaxServers {
		servers = servers[:dnsMaxServers]
	}
	if len(servers) == 0 {
		return core.SSHFPResult{}, errors.New("no DNS servers configured")
	}
	var errs []error
	for _, server := range servers {
		result, err := r.exchange(ctx, server, name)
		if err == nil {
			return result, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", server, err))
		if ctx.Err() != nil {
			break
		}
	}
	return core.SSHFPResult{}, fmt.Errorf("SSHFP lookup %q failed: %w", name, errors.Join(errs...))
}

func normalizeDNSName(hostname string) (string, error) {
	name := strings.TrimSuffix(strings.TrimSpace(hostname), ".")
	if name == "" || len(name) > 253 {
		return "", fmt.Errorf("invalid DNS name %q", hostname)
	}
	if net.ParseIP(name) != nil {
		return "", fmt.Errorf("SSHFP lookup not applicable to IP literal %q", hostname)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("invalid DNS name %q", hostname)
		}
		for i := 0; i < len(label); i++ {
			if c := label[i]; c <= 0x20 || c >= 0x7f {
				return "", fmt.Errorf("invalid DNS name %q", hostname)
			}
		}
	}
	return name, nil
}

func (r *sshfpResolver) exchange(ctx context.Context, server, name string) (core.SSHFPResult, error) {
	query, id, err := buildSSHFPQuery(name)
	if err != nil {
		return core.SSHFPResult{}, err
	}
	resp, err := r.roundTrip(ctx, "udp", server, query)
	if err != nil {
		return core.SSHFPResult{}, err
	}
	header, err := checkDNSResponse(resp, id, query)
	if err != nil {
		return core.SSHFPResult{}, err
	}
	if header&dnsFlagTC != 0 {
		resp, err = r.roundTrip(ctx, "tcp", server, query)
		if err != nil {
			return core.SSHFPResult{}, err
		}
		if header, err = checkDNSResponse(resp, id, query); err != nil {
			return core.SSHFPResult{}, err
		}
		if header&dnsFlagTC != 0 {
			return core.SSHFPResult{}, errors.New("truncated DNS response over TCP")
		}
	}
	switch rcode := header & 0x000f; rcode {
	case dnsRcodeSuccess:
	case dnsRcodeNXDomain:
		return core.SSHFPResult{}, nil
	default:
		return core.SSHFPResult{}, fmt.Errorf("DNS server returned rcode %d", rcode)
	}
	records, err := parseSSHFPAnswers(resp)
	if err != nil {
		return core.SSHFPResult{}, err
	}
	return core.SSHFPResult{Records: records, Authenticated: header&dnsFlagAD != 0}, nil
}

// roundTrip owns conn for the duration of one exchange and closes it on return;
// ctx cancellation closes the connection to unblock reads.
func (r *sshfpResolver) roundTrip(ctx context.Context, network, server string, query []byte) ([]byte, error) {
	conn, err := r.dial(ctx, network, server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	if network == "tcp" {
		msg := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(msg, uint16(len(query)))
		copy(msg[2:], query)
		if _, err := conn.Write(msg); err != nil {
			return nil, err
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, err
		}
		return resp, nil
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, dnsUDPPayloadSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func buildSSHFPQuery(name string) ([]byte, uint16, error) {
	var idBuf [2]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return nil, 0, fmt.Errorf("generate DNS query id: %w", err)
	}
	id := binary.BigEndian.Uint16(idBuf[:])
	msg := make([]byte, 12, 12+len(name)+2+4+11)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], dnsFlagRD|dnsFlagAD)
	binary.BigEndian.PutUint16(msg[4:], 1)  // QDCOUNT
	binary.BigEndian.PutUint16(msg[10:], 1) // ARCOUNT (OPT)
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypeSSHFP)
	msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
	// EDNS0 OPT pseudo-RR: root name, UDP payload size, DO=1, no options.
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, dnsTypeOPT)
	msg = binary.BigEndian.AppendUint16(msg, dnsUDPPayloadSize)
	msg = binary.BigEndian.AppendUint32(msg, 0x00008000)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	return msg, id, nil
}

// checkDNSResponse verifies ID, QR and that the question section echoes ours.
func checkDNSResponse(resp []byte, id uint16, query []byte) (uint16, error) {
	if len(resp) < 12 {
		return 0, errDNSMalformed
	}
	if binary.BigEndian.Uint16(resp[0:]) != id {
		return 0, errors.New("DNS response id mismatch")
	}
	header := binary.BigEndian.Uint16(resp[2:])
	if header&dnsFlagQR == 0 {
		return 0, errors.New("DNS packet is not a response")
	}
	if binary.BigEndian.Uint16(resp[4:]) != 1 {
		return 0, errors.New("DNS response question count mismatch")
	}
	questionEnd := sshfpQuestionEnd(query)
	if len(resp) < questionEnd || !strings.EqualFold(string(resp[12:questionEnd]), string(query[12:questionEnd])) {
		return 0, errors.New("DNS response question mismatch")
	}
	return header, nil
}

func sshfpQuestionEnd(query []byte) int {
	off := 12
	for off < len(query) && query[off] != 0 {
		off += int(query[off]) + 1
	}
	return off + 1 + 4
}

func parseSSHFPAnswers(resp []byte) ([]core.SSHFPRecord, error) {
	ancount := int(binary.BigEndian.Uint16(resp[6:]))
	off, err := skipDNSName(resp, 12)
	if err != nil {
		return nil, err
	}
	off += 4 // QTYPE + QCLASS
	var records []core.SSHFPRecord
	for range ancount {
		if off, err = skipDNSName(resp, off); err != nil {
			return nil, err
		}
		if off+10 > len(resp) {
			return nil, errDNSMalformed
		}
		rrType := binary.BigEndian.Uint16(resp[off:])
		rrClass := binary.BigEndian.Uint16(resp[off+2:])
		rdLen := int(binary.BigEndian.Uint16(resp[off+8:]))
		off += 10
		if off+rdLen > len(resp) {
			return nil, errDNSMalformed
		}
		if rrType == dnsTypeSSHFP && rrClass == dnsClassIN && rdLen >= 2 {
			rdata := resp[off : off+rdLen]
			records = append(records, core.SSHFPRecord{
				Algorithm:       rdata[0],
				FingerprintType: rdata[1],
				Fingerprint:     append([]byte(nil), rdata[2:]...),
			})
		}
		off += rdLen
	}
	return records, nil
}

// skipDNSName returns the offset after a (possibly compressed) name at off.
func skipDNSName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, errDNSMalformed
		}
		length := int(msg[off])
		switch {
		case length == 0:
			return off + 1, nil
		case length&0xc0 == 0xc0:
			if off+2 > len(msg) {
				return 0, errDNSMalformed
			}
			return off + 2, nil
		case length&0xc0 != 0:
			return 0, errDNSMalformed
		default:
			off += length + 1
		}
	}
}
