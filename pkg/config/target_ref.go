package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"github.com/wentf9/xops-cli/core/ssh"
)

// hasOpenSSHPrefix reports whether s starts with the reserved "openssh:" prefix
// using a single case-insensitive rule shared across TargetRef, IsOpenSSHNodeID,
// ValidateNodeAlias, and ProxyJump resolution.
func hasOpenSSHPrefix(s string) bool {
	return len(s) >= len(OpenSSHNodePrefix) && strings.EqualFold(s[:len(OpenSSHNodePrefix)], OpenSSHNodePrefix)
}

// cutOpenSSHPrefix trims a leading case-insensitive "openssh:" prefix from s.
func cutOpenSSHPrefix(s string) (string, bool) {
	if hasOpenSSHPrefix(s) {
		return s[len(OpenSSHNodePrefix):], true
	}
	return s, false
}

// IsOpenSSHNodeID reports whether id carries the explicit "openssh:" namespace
// prefix (case-insensitive).
func IsOpenSSHNodeID(id string) bool {
	return hasOpenSSHPrefix(id)
}

// TrimOpenSSHNodePrefix trims a leading case-insensitive "openssh:" namespace
// prefix from id while preserving any user@host:port qualifiers intact.
// Unlike UnwrapOpenSSHSelector, it does not strip user@ or :port components.
func TrimOpenSSHNodePrefix(id string) (string, bool) {
	return cutOpenSSHPrefix(id)
}

func isBareOrBracketedIPv6Literal(s string) bool {
	if s == "" {
		return false
	}
	candidate := s
	if strings.HasPrefix(s, "[") {
		if !strings.HasSuffix(s, "]") || len(s) < 3 {
			return false
		}
		candidate = s[1 : len(s)-1]
	}
	addr, err := netip.ParseAddr(candidate)
	return err == nil && addr.Is6() && ssh.ValidateIPv6Zone(addr.Zone()) == nil
}

// IsPlainOpenSSHHostSelector reports whether s is a single host/alias selector
// (including bare or portless bracketed IPv6 literals such as "2001:db8::1",
// "fe80::1%eth0", or "[2001:db8::1]") and not a composite user@host or host:port.
func IsPlainOpenSSHHostSelector(s string) bool {
	if s == "" || hasControlOrLineSepChar(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) {
			return false
		}
	}
	if strings.ContainsAny(s, "@,") {
		return false
	}
	if strings.Contains(s, ":") || strings.ContainsAny(s, "[]") {
		return isBareOrBracketedIPv6Literal(s)
	}
	return true
}

func validateTargetRefRaw(raw, emptyMsg string) (string, error) {
	if hasControlOrLineSepChar(raw) {
		return "", fmt.Errorf("invalid address %q: contains invalid control character", raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%s", emptyMsg)
	}
	if strings.ContainsRune(trimmed, ',') {
		return "", fmt.Errorf("invalid address %q: contains comma", raw)
	}
	for _, r := range trimmed {
		if unicode.IsSpace(r) {
			return "", fmt.Errorf("invalid address %q: contains whitespace", raw)
		}
	}
	return trimmed, nil
}

// validateBareAliasTargetRef allows interior ASCII space (' ') ONLY on a bare
// non-"openssh:" alias selector without composite/address delimiters (@, :, [, ])
// so saved Node.Alias values such as "Prod Web 01" remain selectable through
// ParseTargetRef while ParseHostPort, openssh: selectors, and composites stay strict.
func validateBareAliasTargetRef(raw string) (string, bool, error) {
	if hasControlOrLineSepChar(raw) {
		return "", false, fmt.Errorf("invalid address %q: contains invalid control character", raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", false, fmt.Errorf("address cannot be empty")
	}
	if strings.ContainsRune(trimmed, ',') {
		return "", false, fmt.Errorf("invalid address %q: contains comma", raw)
	}
	if hasOpenSSHPrefix(trimmed) || strings.ContainsAny(trimmed, "@:[]") {
		return "", false, nil
	}
	hasSpace := false
	for _, r := range trimmed {
		if r == ' ' {
			hasSpace = true
			continue
		}
		if unicode.IsSpace(r) {
			return "", false, fmt.Errorf("invalid address %q: contains whitespace", raw)
		}
	}
	if !hasSpace {
		return "", false, nil
	}
	return trimmed, true, nil
}

// TargetRef represents a parsed target selector `[openssh:][user@]host[:port]`,
// supporting hostnames, IPv4 addresses, and IPv6 literals (including zone IDs).
//
// Reserved "openssh:" prefix invariant:
//   - Any selector string beginning with "openssh:" is unconditionally parsed as
//     an OpenSSH virtual selector (OpenSSH=true), never as a non-OpenSSH host
//     named "openssh" with a port (e.g. "openssh:22" parses as OpenSSH=true,
//     Host="22").
//   - Consequently, a non-OpenSSH TargetRef with empty User whose formatted
//     host:port starts with "openssh:" (such as Host="openssh", HasPort=true)
//     has no unambiguous bare string representation: Validate() rejects it and
//     NormalizedString() returns "". Specify an explicit user ("user@openssh:22")
//     or omit the port ("openssh") for lossless round-trips.
//   - Likewise, double-prefixed OpenSSH forms (OpenSSH=true whose body begins
//     with "openssh:") are rejected by Validate() and NormalizedString().
type TargetRef struct {
	OpenSSH bool
	User    string
	Host    string
	Port    uint16
	HasPort bool
}

// Selector returns the target host selector, preserving the "openssh:" prefix
// when OpenSSH is true (and stripping any user/port specifiers).
func (r TargetRef) Selector() string {
	if r.OpenSSH {
		return OpenSSHNodePrefix + r.Host
	}
	return r.Host
}

func (r TargetRef) formatNormalizedBody() string {
	var b strings.Builder
	if r.User != "" {
		b.WriteString(r.User)
		b.WriteByte('@')
	}
	if r.HasPort && r.Port > 0 {
		b.WriteString(FormatHostPort(r.Host, r.Port))
	} else {
		b.WriteString(r.Host)
	}
	return b.String()
}

// Validate verifies that r is a well-formed, canonically representable TargetRef
// whose NormalizedString() round-trips losslessly through ParseTargetRef.
func (r TargetRef) Validate() error {
	if r.Host == "" {
		return fmt.Errorf("target host cannot be empty")
	}
	if r.HasPort && r.Port == 0 {
		return fmt.Errorf("invalid port 0: must be between 1 and 65535")
	}
	if !r.HasPort && r.Port != 0 {
		return fmt.Errorf("target port %d specified with HasPort=false", r.Port)
	}
	body := r.formatNormalizedBody()
	if hasOpenSSHPrefix(body) {
		if r.OpenSSH {
			return fmt.Errorf("invalid openssh selector %q: duplicate %q prefix", OpenSSHNodePrefix+body, OpenSSHNodePrefix)
		}
		return fmt.Errorf("ambiguous non-OpenSSH target %q: prefix %q is reserved for OpenSSH virtual selectors (specify user@host:port)", body, OpenSSHNodePrefix)
	}
	out := body
	if r.OpenSSH {
		out = OpenSSHNodePrefix + body
	}
	reparsed, err := ParseTargetRef(out)
	if err != nil {
		return fmt.Errorf("invalid target ref %q: %w", out, err)
	}
	if reparsed != r {
		return fmt.Errorf("target ref %q is not in canonical form", out)
	}
	return nil
}

// NormalizedString formats the canonical string form `[openssh:][user@]host[:port]`.
// It returns "" when r has an empty host, inconsistent port state, or would
// collide with the reserved "openssh:" prefix (non-OpenSSH bare "openssh:<port>"
// or duplicate "openssh:openssh:..."). Call Validate() for a diagnostic error.
func (r TargetRef) NormalizedString() string {
	if r.Host == "" || (r.HasPort && r.Port == 0) || (!r.HasPort && r.Port != 0) {
		return ""
	}
	body := r.formatNormalizedBody()
	if hasOpenSSHPrefix(body) {
		return ""
	}
	if r.OpenSSH {
		return OpenSSHNodePrefix + body
	}
	return body
}

// ParseTargetRef parses `[openssh:][user@]host[:port]`.
// Leading "openssh:" (case-insensitive) is reserved for OpenSSH virtual selectors
// (e.g. "openssh:22" parses as OpenSSH=true, Host="22"; use "user@openssh:22" to
// specify a port on a non-OpenSSH host named "openssh"). Double prefixes such as
// "openssh:openssh:..." or "openssh:OPENSSH:..." are rejected. Every successfully
// parsed TargetRef satisfies Validate() and round-trips losslessly through NormalizedString().
func ParseTargetRef(raw string) (TargetRef, error) {
	if bareAlias, ok, err := validateBareAliasTargetRef(raw); err != nil {
		return TargetRef{}, err
	} else if ok {
		return TargetRef{Host: bareAlias}, nil
	}
	trimmed, err := validateTargetRefRaw(raw, "address cannot be empty")
	if err != nil {
		return TargetRef{}, err
	}
	var isOpenSSH bool
	rest := trimmed
	if after, ok := cutOpenSSHPrefix(trimmed); ok {
		if after == "" || hasOpenSSHPrefix(after) || hasAnyWhitespace(raw) {
			return TargetRef{}, fmt.Errorf("invalid openssh selector %q", raw)
		}
		isOpenSSH = true
		rest = after
	}
	host, userName, port, hasPort, err := parseTargetRefPlain(rest)
	if err != nil {
		return TargetRef{}, err
	}
	return TargetRef{
		OpenSSH: isOpenSSH,
		User:    userName,
		Host:    host,
		Port:    port,
		HasPort: hasPort,
	}, nil
}

func parseTargetRefPlain(spec string) (host, userName string, port uint16, hasPort bool, err error) {
	spec, err = validateTargetRefRaw(spec, "host is empty")
	if err != nil {
		return "", "", 0, false, err
	}
	hostPart := spec
	if at := strings.LastIndex(spec, "@"); at >= 0 {
		userName = spec[:at]
		hostPart = spec[at+1:]
		if userName == "" {
			return "", "", 0, false, fmt.Errorf("invalid address %q: username before '@' cannot be empty", spec)
		}
		if hostPart == "" {
			return "", "", 0, false, fmt.Errorf("invalid address %q: host after '@' cannot be empty", spec)
		}
	}
	host, port, hasPort, err = ParseHostPort(hostPart)
	if err != nil {
		return "", "", 0, false, err
	}
	return host, userName, port, hasPort, nil
}

// ParseHostPort parses `host`, `host:port`, `[ipv6]`, `[ipv6]:port`, or bare `ipv6`
// (including IPv6 link-local addresses with zone IDs such as `[fe80::1%eth0]:22`).
func ParseHostPort(raw string) (host string, port uint16, hasPort bool, err error) {
	s, err := validateTargetRefRaw(raw, "host cannot be empty")
	if err != nil {
		return "", 0, false, err
	}
	if strings.HasPrefix(s, "[") {
		return parseBracketedHostPort(s, raw)
	}
	if strings.ContainsAny(s, "[]") {
		return "", 0, false, fmt.Errorf("malformed bracketed address %q", raw)
	}
	if addr, addrErr := netip.ParseAddr(s); addrErr == nil && addr.Is6() {
		if zErr := ssh.ValidateIPv6Zone(addr.Zone()); zErr != nil {
			return "", 0, false, fmt.Errorf("invalid IPv6 address %q: %w", raw, zErr)
		}
		return s, 0, false, nil
	}
	if strings.HasSuffix(s, ":") {
		return "", 0, false, fmt.Errorf("invalid host-port format %q: missing port after colon", raw)
	}
	if strings.Count(s, ":") == 1 {
		h, pStr, splitErr := net.SplitHostPort(s)
		if splitErr != nil {
			return "", 0, false, fmt.Errorf("parse host and port failed: %w", splitErr)
		}
		p, pErr := parseTargetPort(pStr)
		if pErr != nil {
			return "", 0, false, pErr
		}
		if h == "" {
			return "", 0, false, fmt.Errorf("host cannot be empty")
		}
		return h, p, true, nil
	}
	if strings.Contains(s, ":") {
		return "", 0, false, fmt.Errorf("invalid address or host-port %q", raw)
	}
	return s, 0, false, nil
}

func parseBracketedHostPort(s, raw string) (host string, port uint16, hasPort bool, err error) {
	end := strings.IndexByte(s, ']')
	if end < 0 {
		return "", 0, false, fmt.Errorf("malformed bracketed address %q", raw)
	}
	inner := s[1:end]
	addr, addrErr := netip.ParseAddr(inner)
	if addrErr != nil || !addr.Is6() {
		return "", 0, false, fmt.Errorf("invalid bracketed IPv6 address %q", raw)
	}
	if zErr := ssh.ValidateIPv6Zone(addr.Zone()); zErr != nil {
		return "", 0, false, fmt.Errorf("invalid bracketed IPv6 address %q: %w", raw, zErr)
	}
	suffix := s[end+1:]
	if suffix == "" {
		return inner, 0, false, nil
	}
	if !strings.HasPrefix(suffix, ":") {
		return "", 0, false, fmt.Errorf("invalid host suffix %q", suffix)
	}
	p, pErr := parseTargetPort(suffix[1:])
	if pErr != nil {
		return "", 0, false, pErr
	}
	return inner, p, true, nil
}

func parseTargetPort(raw string) (uint16, error) {
	trimmed, err := validateTargetRefRaw(raw, "port cannot be empty")
	if err != nil {
		return 0, err
	}
	parsedPort, err := strconv.ParseUint(trimmed, 10, 16)
	if err != nil || parsedPort == 0 {
		return 0, fmt.Errorf("invalid port %q: must be between 1 and 65535", raw)
	}
	return uint16(parsedPort), nil
}
