package sshenv

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	core "github.com/wentf9/xops-cli/core/ssh"
)

const (
	dnsTypeCNAME           = 5
	dnsTypeOPT             = 41
	dnsTypeSSHFP           = 44
	dnsClassIN             = 1
	dnsUDPPayloadSize      = 4096
	dnsMaxLookupTime       = 5 * time.Second
	dnsMaxServers          = 3
	dnsMaxCompressionJumps = 16
	dnsMaxCNAMEHops        = 8
	dnsMaxWireNameBytes    = 255

	dnsFlagQR     = 1 << 15
	dnsMaskOpcode = 0x0f << 11
	dnsFlagTC     = 1 << 9
	dnsFlagRD     = 1 << 8
	dnsFlagAD     = 1 << 5
	dnsFlagCD     = 1 << 4

	dnsRcodeSuccess  = 0
	dnsRcodeNXDomain = 3
	dnsRcodeBADVERS  = 16
)

var errDNSMalformed = errors.New("malformed DNS response")

type dnsConfig struct {
	servers []string
	trustAD bool
}

// sshfpResolver is a minimal RFC 1035 + EDNS0 (DO=1) stub resolver for SSHFP.
// Matching glibc 2.31+ (RES_TRUSTAD) resolver hardening, the response AD bit is
// trusted only when resolv.conf explicitly configures "options trust-ad".
type sshfpResolver struct {
	config  func() dnsConfig
	servers func() []string
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
}

func newSystemSSHFPLookup() func(context.Context, string) (core.SSHFPResult, error) {
	var dialer net.Dialer
	r := &sshfpResolver{config: systemDNSConfig, dial: dialer.DialContext}
	return r.Lookup
}

func (r *sshfpResolver) resolveConfig() dnsConfig {
	if r.config != nil {
		return r.config()
	}
	if r.servers != nil {
		return dnsConfig{servers: r.servers()}
	}
	return dnsConfig{}
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

	cfg := r.resolveConfig()
	servers := deduplicateDNSServers(cfg.servers)
	if len(servers) > dnsMaxServers {
		servers = servers[:dnsMaxServers]
	}
	if len(servers) == 0 {
		return core.SSHFPResult{}, errors.New("no DNS servers configured")
	}

	deadline, _ := ctx.Deadline()
	var errs []error
	for i, server := range servers {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if ctxErr := ctx.Err(); ctxErr != nil {
				errs = append(errs, ctxErr)
			} else {
				errs = append(errs, context.DeadlineExceeded)
			}
			break
		}
		perServer := remaining / time.Duration(len(servers)-i)
		srvCtx, srvCancel := context.WithTimeout(ctx, perServer)
		result, exchErr := r.exchange(srvCtx, server, name, cfg.trustAD)
		srvCancel()
		if exchErr == nil {
			return result, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", server, exchErr))
		if ctx.Err() != nil {
			break
		}
	}
	return core.SSHFPResult{}, fmt.Errorf("SSHFP lookup %q failed: %w", name, errors.Join(errs...))
}

func deduplicateDNSServers(raw []string) []string {
	if len(raw) <= 1 {
		return raw
	}
	dedup := make([]string, 0, len(raw))
	for _, srv := range raw {
		if srv == "" || slices.Contains(dedup, srv) {
			continue
		}
		dedup = append(dedup, srv)
	}
	return dedup
}

func formatWindowsDNSServerIPv6(raw [16]byte, scopeID uint32) (string, bool) {
	// Skip IPv6 site-local "fec0::/10" defaults Windows reports when unconfigured.
	if raw[0] == 0xfe && (raw[1]&0xc0) == 0xc0 {
		return "", false
	}
	addr := netip.AddrFrom16(raw)
	if !addr.IsValid() || addr.IsUnspecified() {
		return "", false
	}
	if scopeID != 0 {
		addr = addr.WithZone(strconv.FormatUint(uint64(scopeID), 10))
	}
	return net.JoinHostPort(addr.String(), "53"), true
}

func normalizeDNSName(hostname string) (string, error) {
	name := strings.TrimSuffix(strings.TrimSpace(hostname), ".")
	if name == "" || len(name) > 253 {
		return "", fmt.Errorf("invalid DNS name %q", hostname)
	}
	ipCandidate := name
	if strings.HasPrefix(ipCandidate, "[") && strings.HasSuffix(ipCandidate, "]") {
		ipCandidate = ipCandidate[1 : len(ipCandidate)-1]
	}
	if _, err := netip.ParseAddr(ipCandidate); err == nil {
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

func (r *sshfpResolver) exchange(ctx context.Context, server, name string, trustAD bool) (core.SSHFPResult, error) {
	query, id, err := buildSSHFPQuery(name)
	if err != nil {
		return core.SSHFPResult{}, err
	}
	resp, header, err := r.roundTrip(ctx, "udp", server, id, query)
	if err != nil {
		return core.SSHFPResult{}, err
	}
	if header&dnsFlagTC != 0 && len(resp) >= 12 && binary.BigEndian.Uint16(resp[4:]) > 0 {
		query, id, err = buildSSHFPQuery(name)
		if err != nil {
			return core.SSHFPResult{}, err
		}
		resp, header, err = r.roundTrip(ctx, "tcp", server, id, query)
		if err != nil {
			return core.SSHFPResult{}, err
		}
		if header&dnsFlagTC != 0 {
			return core.SSHFPResult{}, errors.New("truncated DNS response over TCP")
		}
	}
	parsed, err := parseSSHFPResponse(resp, header)
	if err != nil {
		return core.SSHFPResult{}, err
	}
	switch parsed.rcode {
	case dnsRcodeSuccess:
	case dnsRcodeNXDomain:
		return core.SSHFPResult{}, nil
	default:
		return core.SSHFPResult{}, fmt.Errorf("DNS server returned rcode %d", parsed.rcode)
	}
	authenticated := trustAD && parsed.hasValidOPT && (header&dnsFlagAD != 0) && (header&dnsFlagCD == 0)
	return core.SSHFPResult{Records: parsed.records, Authenticated: authenticated}, nil
}

// roundTrip owns conn for the duration of one exchange and closes it on return;
// ctx cancellation expires the socket deadline to unblock reads. On UDP, stray
// datagrams with a mismatched transaction ID or question section are ignored
// until a matching response arrives or the per-server deadline expires.
func (r *sshfpResolver) roundTrip(ctx context.Context, network, server string, id uint16, query []byte) ([]byte, uint16, error) {
	conn, err := r.dial(ctx, network, server)
	if err != nil {
		return nil, 0, err
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
			return nil, 0, err
		}
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, 0, err
		}
		resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, 0, err
		}
		header, err := checkDNSResponse(resp, id, query)
		if err != nil {
			return nil, 0, err
		}
		return resp, header, nil
	}

	if _, err := conn.Write(query); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, dnsUDPPayloadSize)
	var lastDropErr error
	for {
		n, readErr := conn.Read(buf)
		if readErr != nil {
			if lastDropErr != nil {
				return nil, 0, fmt.Errorf("%w (after dropping mismatched packet: %w)", readErr, lastDropErr)
			}
			return nil, 0, readErr
		}
		pkt := buf[:n]
		header, checkErr := checkDNSResponse(pkt, id, query)
		if checkErr != nil {
			lastDropErr = checkErr
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, 0, fmt.Errorf("%w (after dropping mismatched packet: %w)", ctxErr, lastDropErr)
			}
			continue
		}
		return append([]byte(nil), pkt...), header, nil
	}
}

func buildSSHFPQuery(name string) ([]byte, uint16, error) {
	var idBuf [2]byte
	if _, err := rand.Read(idBuf[:]); err != nil {
		return nil, 0, fmt.Errorf("generate DNS query id: %w", err)
	}
	id := binary.BigEndian.Uint16(idBuf[:])
	msg := make([]byte, 12, 12+len(name)+2+4+11)
	binary.BigEndian.PutUint16(msg[0:], id)
	binary.BigEndian.PutUint16(msg[2:], dnsFlagRD)
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

// checkDNSResponse verifies ID, QR, OPCODE=0, and question (or QDCOUNT=0 non-NOERROR/non-NXDOMAIN errors for failover).
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
	if header&dnsMaskOpcode != 0 {
		return 0, errors.New("DNS response opcode mismatch")
	}
	qdcount := binary.BigEndian.Uint16(resp[4:])
	if qdcount == 0 {
		parsed, err := parseSSHFPResponse(resp, header)
		if err == nil && parsed.rcode != dnsRcodeSuccess && parsed.rcode != dnsRcodeNXDomain {
			return header, nil
		}
		return 0, errors.New("DNS response question count mismatch")
	}
	if qdcount != 1 {
		return 0, errors.New("DNS response question count mismatch")
	}
	questionEnd := sshfpQuestionEnd(query)
	if len(resp) < questionEnd || !equalFoldASCIIBytes(resp[12:questionEnd], query[12:questionEnd]) {
		return 0, errors.New("DNS response question mismatch")
	}
	return header, nil
}

func equalFoldASCIIBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func sshfpQuestionEnd(query []byte) int {
	off := 12
	for off < len(query) && query[off] != 0 {
		off += int(query[off]) + 1
	}
	return off + 1 + 4
}

type parsedSSHFPResponse struct {
	records     []core.SSHFPRecord
	rcode       uint16
	hasValidOPT bool
}

func isValidSSHFPFingerprintLen(fpType uint8, fpLen int) bool {
	switch fpType {
	case 1: // SHA-1 (RFC 4255)
		return fpLen == 20
	case 2: // SHA-256 (RFC 6594)
		return fpLen == 32
	default:
		return fpLen > 0
	}
}

func parseSSHFPAnswers(resp []byte) ([]core.SSHFPRecord, error) {
	if len(resp) < 12 {
		return nil, errDNSMalformed
	}
	parsed, err := parseSSHFPResponse(resp, binary.BigEndian.Uint16(resp[2:]))
	if err != nil {
		return nil, err
	}
	return parsed.records, nil
}

type candidateSSHFP struct {
	owner  string
	record core.SSHFPRecord
}

func parseSSHFPResponse(resp []byte, header uint16) (parsedSSHFPResponse, error) {
	if len(resp) < 12 || header&dnsMaskOpcode != 0 {
		return parsedSSHFPResponse{}, errDNSMalformed
	}
	qdcount := int(binary.BigEndian.Uint16(resp[4:]))
	ancount := int(binary.BigEndian.Uint16(resp[6:]))
	nscount := int(binary.BigEndian.Uint16(resp[8:]))
	arcount := int(binary.BigEndian.Uint16(resp[10:]))

	off := 12
	var qname string
	var err error
	if qdcount > 0 {
		qname, off, err = skipDNSQuestions(resp, off, qdcount)
		if err != nil {
			return parsedSSHFPResponse{}, err
		}
	}

	cnames, candidates, off, err := parseSSHFPAnswerSection(resp, off, ancount)
	if err != nil {
		return parsedSSHFPResponse{}, err
	}
	off, err = skipDNSAuthoritySection(resp, off, nscount)
	if err != nil {
		return parsedSSHFPResponse{}, err
	}
	fullRcode, hasValidOPT, err := parseSSHFPAdditionalSection(resp, off, arcount, header)
	if err != nil {
		return parsedSSHFPResponse{}, err
	}
	if qdcount < 1 && (fullRcode == dnsRcodeSuccess || fullRcode == dnsRcodeNXDomain) {
		return parsedSSHFPResponse{}, errDNSMalformed
	}
	if fullRcode != dnsRcodeSuccess {
		return parsedSSHFPResponse{
			rcode:       fullRcode,
			hasValidOPT: hasValidOPT,
		}, nil
	}

	canonicalTarget, ok := resolveCNAMEChainTarget(qname, cnames)
	if !ok {
		return parsedSSHFPResponse{}, errDNSMalformed
	}
	var records []core.SSHFPRecord
	for _, c := range candidates {
		if c.owner == canonicalTarget {
			records = append(records, c.record)
		}
	}
	return parsedSSHFPResponse{
		records:     records,
		rcode:       fullRcode,
		hasValidOPT: hasValidOPT,
	}, nil
}

func parseSSHFPAnswerSection(resp []byte, off, ancount int) (map[string]string, []candidateSSHFP, int, error) {
	var cnames map[string]string
	var candidates []candidateSSHFP
	for range ancount {
		owner, nextOff, err := readCanonicalDNSName(resp, off)
		if err != nil {
			return nil, nil, 0, err
		}
		off = nextOff
		if off+10 > len(resp) {
			return nil, nil, 0, errDNSMalformed
		}
		rrType := binary.BigEndian.Uint16(resp[off:])
		if rrType == dnsTypeOPT {
			// RFC 6891 section 6.1.1: OPT MUST NOT appear outside the Additional section.
			return nil, nil, 0, errDNSMalformed
		}
		rrClass := binary.BigEndian.Uint16(resp[off+2:])
		rdLen := int(binary.BigEndian.Uint16(resp[off+8:]))
		off += 10
		if off+rdLen > len(resp) {
			return nil, nil, 0, errDNSMalformed
		}
		if rrClass == dnsClassIN {
			switch rrType {
			case dnsTypeCNAME:
				if err := recordSSHFPCNAME(&cnames, owner, resp, off, rdLen); err != nil {
					return nil, nil, 0, err
				}
			case dnsTypeSSHFP:
				if rdLen >= 2 {
					rdata := resp[off : off+rdLen]
					if isValidSSHFPFingerprintLen(rdata[1], len(rdata)-2) {
						candidates = append(candidates, candidateSSHFP{
							owner: owner,
							record: core.SSHFPRecord{
								Algorithm:       rdata[0],
								FingerprintType: rdata[1],
								Fingerprint:     append([]byte(nil), rdata[2:]...),
							},
						})
					}
				}
			}
		}
		off += rdLen
	}
	return cnames, candidates, off, nil
}

func skipDNSQuestions(resp []byte, off, qdcount int) (string, int, error) {
	qname, nextOff, err := readCanonicalDNSName(resp, off)
	if err != nil {
		return "", 0, err
	}
	off = nextOff
	if off+4 > len(resp) {
		return "", 0, errDNSMalformed
	}
	off += 4 // QTYPE + QCLASS
	for i := 1; i < qdcount; i++ {
		off, err = skipDNSName(resp, off)
		if err != nil || off+4 > len(resp) {
			return "", 0, errDNSMalformed
		}
		off += 4
	}
	return qname, off, nil
}

func skipDNSAuthoritySection(resp []byte, off, nscount int) (int, error) {
	for range nscount {
		nextOff, err := skipDNSName(resp, off)
		if err != nil {
			return 0, err
		}
		off = nextOff
		if off+10 > len(resp) {
			return 0, errDNSMalformed
		}
		if binary.BigEndian.Uint16(resp[off:]) == dnsTypeOPT {
			// RFC 6891 section 6.1.1: OPT MUST NOT appear in Authority section.
			return 0, errDNSMalformed
		}
		rdLen := int(binary.BigEndian.Uint16(resp[off+8:]))
		off += 10
		if off+rdLen > len(resp) {
			return 0, errDNSMalformed
		}
		off += rdLen
	}
	return off, nil
}

func parseSSHFPAdditionalSection(resp []byte, off, arcount int, header uint16) (uint16, bool, error) {
	fullRcode := header & 0x000f
	seenOPT := false
	hasValidOPT := false
	for range arcount {
		ownerStart := off
		owner, nextOff, err := readCanonicalDNSName(resp, off)
		if err != nil {
			return 0, false, err
		}
		off = nextOff
		if off+10 > len(resp) {
			return 0, false, errDNSMalformed
		}
		rrType := binary.BigEndian.Uint16(resp[off:])
		ttl := binary.BigEndian.Uint32(resp[off+4:])
		rdLen := int(binary.BigEndian.Uint16(resp[off+8:]))
		off += 10
		if off+rdLen > len(resp) {
			return 0, false, errDNSMalformed
		}
		if rrType == dnsTypeOPT {
			// RFC 6891 section 6.1.2: OPT owner must be uncompressed single-byte root (0x00) and appear at most once.
			if owner != "\x00" || nextOff != ownerStart+1 || resp[ownerStart] != 0x00 || seenOPT {
				return 0, false, errDNSMalformed
			}
			seenOPT = true
			extRcode := uint16(ttl >> 24)
			fullRcode = (extRcode << 4) | (header & 0x000f)
			ednsVersion := uint8(ttl >> 16)
			if ednsVersion != 0 {
				if fullRcode != dnsRcodeBADVERS {
					return 0, false, errDNSMalformed
				}
				off += rdLen
				continue
			}
			hasValidOPT = true
		}
		off += rdLen
	}
	return fullRcode, hasValidOPT, nil
}

func recordSSHFPCNAME(cnames *map[string]string, owner string, resp []byte, off, rdLen int) error {
	target, targetEnd, err := readCanonicalDNSName(resp[:off+rdLen], off)
	if err != nil || targetEnd != off+rdLen {
		return errDNSMalformed
	}
	if owner == target {
		return errDNSMalformed
	}
	if *cnames == nil {
		*cnames = make(map[string]string)
	}
	if existing, exists := (*cnames)[owner]; exists && existing != target {
		return errDNSMalformed
	}
	(*cnames)[owner] = target
	return nil
}

func resolveCNAMEChainTarget(qname string, cnames map[string]string) (string, bool) {
	if len(cnames) == 0 {
		return qname, true
	}
	canonicalTarget := qname
	visited := map[string]struct{}{qname: {}}
	for range dnsMaxCNAMEHops {
		next, ok := cnames[canonicalTarget]
		if !ok {
			return canonicalTarget, true
		}
		if _, seen := visited[next]; seen {
			return "", false
		}
		visited[next] = struct{}{}
		canonicalTarget = next
	}
	if _, hasMore := cnames[canonicalTarget]; hasMore {
		return "", false
	}
	return canonicalTarget, true
}

// readCanonicalDNSName decompresses a DNS wire name at msg[off:] into canonical
// lowercased wire format (<len><lower-label>...<0x00>) and returns the offset
// immediately after the name in msg. Compression pointers are strictly limited
// to backward offsets (12 <= ptr < cur) and capped at dnsMaxCompressionJumps.
func readCanonicalDNSName(msg []byte, off int) (string, int, error) {
	var wire [dnsMaxWireNameBytes]byte
	wireLen := 0
	cur := off
	nextOff := 0
	jumped := false
	jumps := 0

	for {
		if cur < 0 || cur >= len(msg) {
			return "", 0, errDNSMalformed
		}
		length := int(msg[cur])
		switch {
		case length == 0:
			if wireLen+1 > dnsMaxWireNameBytes {
				return "", 0, errDNSMalformed
			}
			wire[wireLen] = 0
			wireLen++
			if !jumped {
				nextOff = cur + 1
			}
			return string(wire[:wireLen]), nextOff, nil
		case length&0xc0 == 0xc0:
			if cur+2 > len(msg) {
				return "", 0, errDNSMalformed
			}
			ptr := int(binary.BigEndian.Uint16(msg[cur:cur+2]) & 0x3fff)
			if ptr < 12 || ptr >= cur {
				return "", 0, errDNSMalformed
			}
			jumps++
			if jumps > dnsMaxCompressionJumps {
				return "", 0, errDNSMalformed
			}
			if !jumped {
				nextOff = cur + 2
				jumped = true
			}
			cur = ptr
		case length&0xc0 != 0:
			return "", 0, errDNSMalformed
		default:
			if cur+1+length > len(msg) || wireLen+1+length >= dnsMaxWireNameBytes {
				return "", 0, errDNSMalformed
			}
			wire[wireLen] = byte(length)
			wireLen++
			for i := range length {
				b := msg[cur+1+i]
				if b >= 'A' && b <= 'Z' {
					b += 'a' - 'A'
				}
				wire[wireLen] = b
				wireLen++
			}
			cur += 1 + length
		}
	}
}

// skipDNSName returns the offset after a (possibly compressed) name at off.
func skipDNSName(msg []byte, off int) (int, error) {
	_, nextOff, err := readCanonicalDNSName(msg, off)
	return nextOff, err
}
