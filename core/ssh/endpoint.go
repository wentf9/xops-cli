package ssh

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

// DefaultSSHPort is the canonical SSH TCP port used when port 0 is normalized.
const DefaultSSHPort uint16 = 22

// ErrInvalidEndpoint indicates a malformed host, IP literal, zone ID, or port.
var ErrInvalidEndpoint = errors.New("invalid SSH endpoint")

// Endpoint is an immutable, canonical SSH host+port target.
//
// An Endpoint holds either a validated IP address (netip.Addr, preserving IPv6
// zone IDs and keeping IPv4-mapped IPv6 addresses distinct from IPv4) or a
// validated, ASCII-lowercased RFC 1123 hostname, paired with a normalized TCP
// port (0 -> 22). Construct exclusively via NewEndpoint, NewAddrEndpoint, or
// ParseEndpoint.
type Endpoint struct {
	addr     netip.Addr
	hostname string
	port     uint16
}

// NewAddrEndpoint constructs a canonical Endpoint from a validated netip.Addr
// and TCP port (0 is normalized to 22).
func NewAddrEndpoint(addr netip.Addr, port uint16) (Endpoint, error) {
	if !addr.IsValid() {
		return Endpoint{}, fmt.Errorf("%w: invalid IP address", ErrInvalidEndpoint)
	}
	if err := ValidateIPv6Zone(addr.Zone()); err != nil {
		return Endpoint{}, err
	}
	if port == 0 {
		port = DefaultSSHPort
	}
	return Endpoint{addr: addr, port: port}, nil
}

// NewEndpoint validates host (IP literal, bracketed IPv6 literal, or RFC 1123
// hostname) and port (0 normalized to 22, 1..65535 preserved) and returns a
// canonical Endpoint.
func NewEndpoint(host string, port int) (Endpoint, error) {
	if port < 0 || port > 65535 {
		return Endpoint{}, fmt.Errorf("%w: port %d out of range [0, 65535]", ErrInvalidEndpoint, port)
	}
	if hasControlOrLineSepChar(host) {
		return Endpoint{}, fmt.Errorf("%w: host %q contains control character", ErrInvalidEndpoint, host)
	}
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return Endpoint{}, fmt.Errorf("%w: host cannot be empty", ErrInvalidEndpoint)
	}

	normPort := uint16(port)
	if normPort == 0 {
		normPort = DefaultSSHPort
	}

	if strings.HasPrefix(trimmed, "[") || strings.HasSuffix(trimmed, "]") {
		if len(trimmed) < 3 || trimmed[0] != '[' || trimmed[len(trimmed)-1] != ']' {
			return Endpoint{}, fmt.Errorf("%w: malformed bracketed host %q", ErrInvalidEndpoint, host)
		}
		inner := trimmed[1 : len(trimmed)-1]
		if strings.ContainsAny(inner, "[]") {
			return Endpoint{}, fmt.Errorf("%w: nested brackets in host %q", ErrInvalidEndpoint, host)
		}
		addr, err := netip.ParseAddr(inner)
		if err != nil || !addr.Is6() {
			return Endpoint{}, fmt.Errorf("%w: bracketed host %q must be a valid IPv6 literal", ErrInvalidEndpoint, host)
		}
		return NewAddrEndpoint(addr, normPort)
	}

	if strings.ContainsAny(trimmed, "[]") {
		return Endpoint{}, fmt.Errorf("%w: unexpected bracket in host %q", ErrInvalidEndpoint, host)
	}

	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return NewAddrEndpoint(addr, normPort)
	}

	folded, err := validateRFC1123Hostname(trimmed)
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidEndpoint, err)
	}
	return Endpoint{hostname: folded, port: normPort}, nil
}

// ParseEndpoint parses a host or host:port specification into a canonical
// Endpoint. Accepted forms:
//   - "host" or "host:port" (RFC 1123 hostname or IPv4)
//   - "[ipv6]" or "[ipv6]:port" (including IPv6 zone IDs such as "[fe80::1%eth0]:2222")
//   - bare unbracketed IPv6 literal ("2001:db8::1" or "fe80::1%eth0", port defaults to 22)
//
// Missing ports and port 0 normalize to 22.
func ParseEndpoint(raw string) (Endpoint, error) {
	if hasControlOrLineSepChar(raw) {
		return Endpoint{}, fmt.Errorf("%w: %q contains control character", ErrInvalidEndpoint, raw)
	}
	s := strings.TrimSpace(raw)
	if s == "" {
		return Endpoint{}, fmt.Errorf("%w: empty endpoint", ErrInvalidEndpoint)
	}
	if strings.ContainsFunc(s, unicode.IsSpace) {
		return Endpoint{}, fmt.Errorf("%w: endpoint %q contains internal whitespace", ErrInvalidEndpoint, raw)
	}

	if s[0] == '[' {
		closeIdx := strings.IndexByte(s, ']')
		if closeIdx < 2 {
			return Endpoint{}, fmt.Errorf("%w: malformed bracketed endpoint %q", ErrInvalidEndpoint, raw)
		}
		hostPart := s[:closeIdx+1]
		rest := s[closeIdx+1:]
		if rest == "" {
			return NewEndpoint(hostPart, 0)
		}
		if rest[0] != ':' {
			return Endpoint{}, fmt.Errorf("%w: unexpected trailing data in %q", ErrInvalidEndpoint, raw)
		}
		port, err := parseStrictEndpointPort(rest[1:])
		if err != nil {
			return Endpoint{}, err
		}
		return NewEndpoint(hostPart, port)
	}

	if strings.ContainsAny(s, "[]") {
		return Endpoint{}, fmt.Errorf("%w: unexpected bracket in %q", ErrInvalidEndpoint, raw)
	}

	switch strings.Count(s, ":") {
	case 0:
		return NewEndpoint(s, 0)
	case 1:
		hostPart, portPart, _ := strings.Cut(s, ":")
		if hostPart == "" {
			return Endpoint{}, fmt.Errorf("%w: missing host in %q", ErrInvalidEndpoint, raw)
		}
		port, err := parseStrictEndpointPort(portPart)
		if err != nil {
			return Endpoint{}, err
		}
		return NewEndpoint(hostPart, port)
	default:
		// Two or more colons: only a bare IPv6 literal (with optional %zone) is valid.
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is6() {
			return Endpoint{}, fmt.Errorf("%w: invalid IPv6 address or malformed host:port %q", ErrInvalidEndpoint, raw)
		}
		return NewAddrEndpoint(addr, 0)
	}
}

// IsValid reports whether e was constructed via an Endpoint constructor and holds
// a valid host and non-zero port. Zero-value Endpoints return false.
func (e Endpoint) IsValid() bool {
	return e.port != 0 && (e.addr.IsValid() || e.hostname != "")
}

// IsIP reports whether e holds a numeric IP address rather than a hostname.
func (e Endpoint) IsIP() bool {
	return e.IsValid() && e.addr.IsValid()
}

// Addr returns the IP address and true when e holds an IP literal.
func (e Endpoint) Addr() (netip.Addr, bool) {
	if !e.IsIP() {
		return netip.Addr{}, false
	}
	return e.addr, true
}

// Hostname returns the canonical case-folded RFC 1123 hostname and true when e
// holds a hostname rather than an IP literal.
func (e Endpoint) Hostname() (string, bool) {
	if !e.IsValid() || e.addr.IsValid() {
		return "", false
	}
	return e.hostname, true
}

// Host returns the canonical unbracketed host representation (RFC 5952 IP literal
// with zone ID if any, or lowercase RFC 1123 hostname), or "" for invalid endpoints.
func (e Endpoint) Host() string {
	if !e.IsValid() {
		return ""
	}
	if e.addr.IsValid() {
		return e.addr.String()
	}
	return e.hostname
}

// Port returns the normalized TCP port (1..65535), or 0 for an invalid endpoint.
func (e Endpoint) Port() uint16 {
	if !e.IsValid() {
		return 0
	}
	return e.port
}

// WithPort returns a copy of e with port normalized (0 -> 22).
// Calling WithPort on an invalid (zero-value) Endpoint returns an error.
func (e Endpoint) WithPort(port uint16) (Endpoint, error) {
	if !e.IsValid() {
		return Endpoint{}, fmt.Errorf("%w: cannot set port on invalid endpoint", ErrInvalidEndpoint)
	}
	if port == 0 {
		port = DefaultSSHPort
	}
	e.port = port
	return e, nil
}

// Equal reports whether e and other are both valid and represent the exact same
// canonical host and port. Invalid (zero-value) endpoints never compare equal
// to anything, including each other (fail-closed).
func (e Endpoint) Equal(other Endpoint) bool {
	if !e.IsValid() || !other.IsValid() {
		return false
	}
	return e.port == other.port && e.addr == other.addr && e.hostname == other.hostname
}

// HostEqual reports whether e and other are both valid and represent the same
// canonical host, ignoring port. Invalid (zero-value) endpoints never compare
// equal to anything, including each other (fail-closed).
//
// SECURITY: NOT for security scoping (such as Tier-4 OpenSSH stanza scoping,
// known_hosts matching, or credential binding). Always use Equal when port
// identity matters. Use HostEqual only where port-agnostic host matching is
// explicitly intended and justified (for example CLI --exclude <addr>).
func (e Endpoint) HostEqual(other Endpoint) bool {
	if !e.IsValid() || !other.IsValid() {
		return false
	}
	return e.addr == other.addr && e.hostname == other.hostname
}

// String formats e in canonical host:port syntax (bracketing IPv6 literals via
// net.JoinHostPort), or "" for an invalid zero-value Endpoint.
func (e Endpoint) String() string {
	if !e.IsValid() {
		return ""
	}
	return net.JoinHostPort(e.Host(), strconv.Itoa(int(e.port)))
}

func parseStrictEndpointPort(raw string) (int, error) {
	if raw == "" {
		return 0, fmt.Errorf("%w: empty port", ErrInvalidEndpoint)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, fmt.Errorf("%w: invalid port %q", ErrInvalidEndpoint, raw)
		}
	}
	p, err := strconv.Atoi(raw)
	if err != nil || p < 0 || p > 65535 {
		return 0, fmt.Errorf("%w: port %q out of range [0, 65535]", ErrInvalidEndpoint, raw)
	}
	return p, nil
}

// ValidateIPv6Zone validates an IPv6 link-local zone identifier (the portion
// after '%' in an IPv6 literal) as the single authority shared across Endpoint
// and config TargetRef parsing. Control/whitespace/line-separator characters
// and structural delimiters ('[', ']', ':', '%', '/', '\', '@', ',') are rejected.
func ValidateIPv6Zone(zone string) error {
	if zone == "" {
		return nil
	}
	for _, r := range zone {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '\u2028' || r == '\u2029' {
			return fmt.Errorf("%w: invalid IPv6 zone %q", ErrInvalidEndpoint, zone)
		}
		switch r {
		case '[', ']', ':', '%', '/', '\\', '@', ',':
			return fmt.Errorf("%w: invalid character %q in IPv6 zone %q", ErrInvalidEndpoint, r, zone)
		}
	}
	return nil
}

// validateRFC1123Hostname validates an ASCII RFC 1123 hostname and returns its
// lowercase canonical form. Total length is 1..253 bytes; each '.'-separated
// label is 1..63 bytes of [A-Za-z0-9-] with alphanumeric start and end; the
// final label must contain at least one ASCII letter so invalid numeric forms
// like "999.999.999.999" or "127.1" cannot slip past IP parsing as hostnames.
func validateRFC1123Hostname(raw string) (string, error) {
	if raw == "" || len(raw) > 253 {
		return "", fmt.Errorf("hostname %q length must be in [1, 253]", raw)
	}
	if raw[0] == '.' || raw[len(raw)-1] == '.' {
		return "", fmt.Errorf("hostname %q cannot start or end with '.'", raw)
	}

	var b strings.Builder
	b.Grow(len(raw))
	lastLabelHasAlpha := false
	labelStart := 0
	for i := 0; i <= len(raw); i++ {
		if i < len(raw) && raw[i] != '.' {
			continue
		}
		label := raw[labelStart:i]
		hasAlpha, err := validateAndFoldRFC1123Label(&b, label, raw)
		if err != nil {
			return "", err
		}
		lastLabelHasAlpha = hasAlpha
		if i < len(raw) {
			b.WriteByte('.')
		}
		labelStart = i + 1
	}
	if !lastLabelHasAlpha {
		return "", fmt.Errorf("hostname %q final label cannot be all-numeric", raw)
	}
	return b.String(), nil
}

func validateAndFoldRFC1123Label(b *strings.Builder, label, full string) (bool, error) {
	if len(label) == 0 || len(label) > 63 {
		return false, fmt.Errorf("hostname %q contains invalid label %q", full, label)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false, fmt.Errorf("hostname %q label %q cannot start or end with '-'", full, label)
	}
	hasAlpha := false
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'A' && c <= 'Z':
			hasAlpha = true
			b.WriteByte(c + ('a' - 'A'))
		case c >= 'a' && c <= 'z':
			hasAlpha = true
			b.WriteByte(c)
		case (c >= '0' && c <= '9') || c == '-':
			b.WriteByte(c)
		default:
			return false, fmt.Errorf("hostname %q contains invalid character %q", full, c)
		}
	}
	return hasAlpha, nil
}
