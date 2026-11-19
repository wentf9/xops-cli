package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// IsOpenSSHNodeID reports whether id carries the explicit "openssh:" namespace prefix.
func IsOpenSSHNodeID(id string) bool {
	return strings.HasPrefix(id, OpenSSHNodePrefix)
}

// TargetRef represents a parsed target selector `[openssh:][user@]host[:port]`,
// supporting hostnames, IPv4 addresses, and IPv6 literals (including zone IDs).
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

// NormalizedString formats the canonical string form `[openssh:][user@]host[:port]`.
func (r TargetRef) NormalizedString() string {
	var b strings.Builder
	if r.OpenSSH {
		b.WriteString(OpenSSHNodePrefix)
	}
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

// ParseTargetRef parses `[openssh:][user@]host[:port]`.
func ParseTargetRef(raw string) (TargetRef, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return TargetRef{}, fmt.Errorf("address cannot be empty")
	}
	var isOpenSSH bool
	rest := trimmed
	if after, ok := strings.CutPrefix(trimmed, OpenSSHNodePrefix); ok {
		if after == "" || strings.TrimSpace(after) != after || strings.HasPrefix(after, OpenSSHNodePrefix) {
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
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", "", 0, false, fmt.Errorf("host is empty")
	}
	hostPart := spec
	if at := strings.LastIndex(spec, "@"); at >= 0 {
		userName = strings.TrimSpace(spec[:at])
		hostPart = strings.TrimSpace(spec[at+1:])
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
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", 0, false, fmt.Errorf("host cannot be empty")
	}
	if strings.HasPrefix(s, "[") {
		return parseBracketedHostPort(s, raw)
	}
	if strings.ContainsAny(s, "[]") {
		return "", 0, false, fmt.Errorf("malformed bracketed address %q", raw)
	}
	if addr, addrErr := netip.ParseAddr(s); addrErr == nil && addr.Is6() {
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
		h = strings.TrimSpace(h)
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
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("port cannot be empty")
	}
	parsedPort, err := strconv.ParseUint(trimmed, 10, 16)
	if err != nil || parsedPort == 0 {
		return 0, fmt.Errorf("invalid port %q: must be between 1 and 65535", raw)
	}
	return uint16(parsedPort), nil
}
