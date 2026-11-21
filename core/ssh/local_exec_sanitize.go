package ssh

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ErrUnsafeExecToken reports that a host, user, or environment token interpolated
// into ProxyCommand or LocalCommand violates strict parameter-injection whitelists.
var ErrUnsafeExecToken = errors.New("unsafe token in local execution command")

const (
	maxSafeHostTokenLen = 255
	maxSafeUserTokenLen = 128
	maxSafeUIDTokenLen  = 64
	maxSafeHomeTokenLen = 1024
)

func validateLocalExecCommandOption(name, raw string) (string, error) {
	if hasControlOrLineSepChar(raw) {
		return "", fmt.Errorf("invalid %s: value cannot contain control characters, null bytes, or newlines", name)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("invalid %s: value cannot be empty", name)
	}
	if strings.EqualFold(trimmed, "none") {
		return "none", nil
	}
	return trimmed, nil
}

// ProxyCommand returns the normalized ProxyCommand option ("none" or command), or "" if unset.
func (o *Options) ProxyCommand() string {
	return o.Get(OptionProxyCommand)
}

// ActiveProxyCommand returns the configured ProxyCommand when non-empty and not "none", or "".
func (o *Options) ActiveProxyCommand() string {
	v := o.Get(OptionProxyCommand)
	if v == "" || v == "none" {
		return ""
	}
	return v
}

// LocalCommand returns the normalized LocalCommand option ("none" or command), or "" if unset.
func (o *Options) LocalCommand() string {
	return o.Get(OptionLocalCommand)
}

// PermitLocalCommand reports whether LocalCommand execution is permitted (default false).
func (o *Options) PermitLocalCommand() bool {
	v, ok := o.boolOption(OptionPermitLocalCommand)
	return ok && v
}

// ValidateSafeExecToken enforces strict allowlists before interpolating tokens into
// ProxyCommand or LocalCommand templates (defending against CVE-2023-51385 option/shell injection).
func ValidateSafeExecToken(kind, val string) error {
	switch normalizeExecTokenKind(kind) {
	case "host":
		return validateSafeHostToken(kind, val)
	case "user":
		return validateSafeUserToken(kind, val)
	case "port":
		return validateSafePortToken(kind, val)
	case "uid":
		return validateSafeUIDToken(kind, val)
	case "hash":
		return validateSafeHashToken(kind, val)
	case "homedir":
		return validateSafeHomeToken(kind, val)
	default:
		return fmt.Errorf("%w: unsupported token kind %q", ErrUnsafeExecToken, kind)
	}
}

func normalizeExecTokenKind(kind string) string {
	switch strings.TrimSpace(kind) {
	case "%h", "h", "%n", "n", "%l", "l", "%L", "L", "host", "hostname", "original_host", "local_host", "short_local_host":
		return "host"
	case "%r", "r", "%u", "u", "user", "remote_user", "local_user":
		return "user"
	case "%p", "p", "port":
		return "port"
	case "%i", "i", "uid":
		return "uid"
	case "%C", "C", "hash":
		return "hash"
	case "%d", "d", "homedir":
		return "homedir"
	default:
		return ""
	}
}

func validateSafeHostToken(kind, val string) error {
	if val == "" {
		return fmt.Errorf("%w: %s cannot be empty", ErrUnsafeExecToken, kind)
	}
	if len(val) > maxSafeHostTokenLen {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrUnsafeExecToken, kind, maxSafeHostTokenLen)
	}
	if val[0] == '-' {
		return fmt.Errorf("%w: %s %q cannot start with '-'", ErrUnsafeExecToken, kind, val)
	}

	body := val
	bracketed := false
	if strings.ContainsAny(val, "[]") {
		if len(val) < 4 || val[0] != '[' || val[len(val)-1] != ']' {
			return fmt.Errorf("%w: %s %q contains invalid bracket syntax", ErrUnsafeExecToken, kind, val)
		}
		body = val[1 : len(val)-1]
		if strings.ContainsAny(body, "[]") {
			return fmt.Errorf("%w: %s %q contains nested brackets", ErrUnsafeExecToken, kind, val)
		}
		bracketed = true
	}

	addrPart, zonePart, hasZone := strings.Cut(body, "%")
	if hasZone {
		if err := validateSafeIPv6Zone(kind, val, zonePart); err != nil {
			return err
		}
	}

	if bracketed || hasZone || strings.IndexByte(addrPart, ':') >= 0 {
		if strings.IndexByte(addrPart, ':') < 0 {
			return fmt.Errorf("%w: %s %q requires an IPv6 literal", ErrUnsafeExecToken, kind, val)
		}
		ip, err := netip.ParseAddr(addrPart)
		if err != nil || !ip.Is6() {
			return fmt.Errorf("%w: %s %q contains invalid IPv6 literal", ErrUnsafeExecToken, kind, val)
		}
		return nil
	}

	for i := 0; i < len(val); i++ {
		if !isSafeHostTokenChar(val[i]) {
			return fmt.Errorf("%w: %s %q contains disallowed character %q", ErrUnsafeExecToken, kind, val, val[i])
		}
	}
	return nil
}

func validateSafeIPv6Zone(kind, val, zonePart string) error {
	if zonePart == "" || strings.IndexByte(zonePart, '%') >= 0 {
		return fmt.Errorf("%w: %s %q contains invalid zone identifier", ErrUnsafeExecToken, kind, val)
	}
	for i := 0; i < len(zonePart); i++ {
		if !isSafeIPv6ZoneChar(zonePart[i]) {
			return fmt.Errorf("%w: %s %q contains disallowed character %q in zone identifier", ErrUnsafeExecToken, kind, val, zonePart[i])
		}
	}
	return nil
}

func isSafeHostTokenChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '.' || c == '_' || c == '-'
}

func isSafeIPv6ZoneChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '.' || c == '_' || c == '-'
}

func validateSafeUserToken(kind, val string) error {
	if val == "" {
		return fmt.Errorf("%w: %s cannot be empty", ErrUnsafeExecToken, kind)
	}
	if len(val) > maxSafeUserTokenLen {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrUnsafeExecToken, kind, maxSafeUserTokenLen)
	}
	if val[0] == '-' {
		return fmt.Errorf("%w: %s %q cannot start with '-'", ErrUnsafeExecToken, kind, val)
	}
	for i := 0; i < len(val); i++ {
		if !isSafeUserTokenChar(val[i]) {
			return fmt.Errorf("%w: %s %q contains disallowed character %q", ErrUnsafeExecToken, kind, val, val[i])
		}
	}
	return nil
}

func isSafeUserTokenChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '.' || c == '_' || c == '-' || c == '@'
}

func validateSafePortToken(kind, val string) error {
	if val == "" {
		return fmt.Errorf("%w: %s cannot be empty", ErrUnsafeExecToken, kind)
	}
	for i := 0; i < len(val); i++ {
		if val[i] < '0' || val[i] > '9' {
			return fmt.Errorf("%w: %s %q must be numeric", ErrUnsafeExecToken, kind, val)
		}
	}
	port, err := strconv.Atoi(val)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%w: %s %q must be in 1..65535", ErrUnsafeExecToken, kind, val)
	}
	return nil
}

func validateSafeUIDToken(kind, val string) error {
	if val == "" || len(val) > maxSafeUIDTokenLen || val[0] == '-' {
		return fmt.Errorf("%w: invalid %s %q", ErrUnsafeExecToken, kind, val)
	}
	for i := 0; i < len(val); i++ {
		if !isSafeUIDTokenChar(val[i]) {
			return fmt.Errorf("%w: %s %q contains disallowed character %q", ErrUnsafeExecToken, kind, val, val[i])
		}
	}
	return nil
}

func isSafeUIDTokenChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
}

func validateSafeHashToken(kind, val string) error {
	if val == "" || len(val) > 128 {
		return fmt.Errorf("%w: invalid %s %q", ErrUnsafeExecToken, kind, val)
	}
	for i := 0; i < len(val); i++ {
		if !isHexDigit(val[i]) {
			return fmt.Errorf("%w: %s %q must be hexadecimal", ErrUnsafeExecToken, kind, val)
		}
	}
	return nil
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func validateSafeHomeToken(kind, val string) error {
	if val == "" || len(val) > maxSafeHomeTokenLen || val[0] == '-' {
		return fmt.Errorf("%w: invalid %s %q", ErrUnsafeExecToken, kind, val)
	}
	// Accept pure Windows drive paths (e.g. C:\Users\alice.dev) without trailing
	// backslash or mixed POSIX separators, so a backslash can never act as a shell
	// escape in POSIX paths (e.g. /home/alice\escape).
	if isWindowsDriveHomePath(val) {
		return validateSafeWindowsHomeToken(kind, val)
	}
	for i := 0; i < len(val); i++ {
		if !isSafePOSIXHomeTokenChar(val[i]) {
			return fmt.Errorf("%w: %s %q contains disallowed character %q", ErrUnsafeExecToken, kind, val, val[i])
		}
	}
	return nil
}

func isWindowsDriveHomePath(val string) bool {
	return len(val) >= 4 &&
		((val[0] >= 'a' && val[0] <= 'z') || (val[0] >= 'A' && val[0] <= 'Z')) &&
		val[1] == ':' && val[2] == '\\'
}

func validateSafeWindowsHomeToken(kind, val string) error {
	if val[len(val)-1] == '\\' {
		return fmt.Errorf("%w: %s %q cannot end with backslash", ErrUnsafeExecToken, kind, val)
	}
	prevSlash := true
	for i := 3; i < len(val); i++ {
		c := val[i]
		if c == '\\' {
			if prevSlash {
				return fmt.Errorf("%w: %s %q contains empty path segment", ErrUnsafeExecToken, kind, val)
			}
			prevSlash = true
			continue
		}
		prevSlash = false
		if !isSafeHomeSegmentChar(c) {
			return fmt.Errorf("%w: %s %q contains disallowed character %q", ErrUnsafeExecToken, kind, val, c)
		}
	}
	return nil
}

func isSafeHomeSegmentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '.' || c == '_' || c == '-'
}

func isSafePOSIXHomeTokenChar(c byte) bool {
	return isSafeHomeSegmentChar(c) || c == '/'
}

// ExpandProxyCommand expands OpenSSH ProxyCommand percent tokens (%%, %h, %p, %r, %n)
// after validating the target host/port and any referenced percent-token values against
// ValidateSafeExecToken. Enclosing '[' and ']' around valid IPv6 host tokens are stripped
// (matching OpenSSH cleanhostname) so templates like "ssh -W [%h]:%p" expand cleanly.
func ExpandProxyCommand(pattern string, env Environment, target TargetContext) (string, error) {
	return expandLocalExecTemplate("ProxyCommand", pattern, env, target, false)
}

// ExpandLocalCommand expands OpenSSH LocalCommand percent tokens
// (%%, %C, %d, %h, %i, %l, %L, %n, %p, %r, %u) after validating the target host/port and
// any referenced percent-token values against ValidateSafeExecToken. Enclosing '[' and ']'
// around valid IPv6 host tokens are stripped (matching OpenSSH cleanhostname).
func ExpandLocalCommand(pattern string, env Environment, target TargetContext) (string, error) {
	return expandLocalExecTemplate("LocalCommand", pattern, env, target, true)
}

func expandLocalExecTemplate(optionName, pattern string, env Environment, target TargetContext, allowLocalTokens bool) (string, error) {
	if hasControlOrLineSepChar(pattern) {
		return "", fmt.Errorf("%s cannot contain control characters or null bytes", optionName)
	}
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return "", nil
	}
	if strings.EqualFold(trimmed, "none") {
		return "none", nil
	}

	// Always validate TargetContext.Host (%h) and Port up front so a hostile
	// endpoint is rejected even when the command string omits %h. Other tokens
	// (%r, %n, %d, %u, etc.) are validated lazily below only when referenced in
	// pattern so unused values (e.g. Windows DOMAIN\user or spaces in LocalUser/HomeDir)
	// do not reject commands like "nc %h %p".
	if err := ValidateSafeExecToken("%h", target.Host); err != nil {
		return "", err
	}
	if target.Port < 0 || target.Port > 65535 {
		return "", fmt.Errorf("%w: invalid port %d", ErrUnsafeExecToken, target.Port)
	}
	target.Host = cleanHostLiteral(target.Host)

	tokens := buildRemoteCommandTokenMap(env, target)
	var sb strings.Builder
	sb.Grow(len(trimmed) + 32)
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] != '%' {
			sb.WriteByte(trimmed[i])
			continue
		}
		if i+1 >= len(trimmed) {
			return "", fmt.Errorf("trailing '%%' in %s", optionName)
		}
		i++
		tok := trimmed[i]
		if tok == '%' {
			sb.WriteByte('%')
			continue
		}
		if !isAllowedLocalExecToken(tok, allowLocalTokens) {
			return "", fmt.Errorf("unknown %s token %%%c", optionName, tok)
		}
		val := tokens[tok]
		kind := "%" + string(tok)
		if err := ValidateSafeExecToken(kind, val); err != nil {
			return "", err
		}
		if normalizeExecTokenKind(kind) == "host" {
			val = cleanHostLiteral(val)
		}
		sb.WriteString(val)
	}

	expanded := sb.String()
	if hasControlOrLineSepChar(expanded) {
		return "", fmt.Errorf("expanded %s cannot contain control characters or null bytes", optionName)
	}
	return expanded, nil
}

// cleanHostLiteral trims surrounding whitespace and strips a single non-empty
// outer "[...]" pair containing no internal '[' or ']' characters (matching
// OpenSSH cleanhostname for bracketed IPv6 literals such as "[2001:db8::1]" or
// "[fe80::1%eth0]") without altering nested, multi-segment, empty, or unbalanced brackets.
func cleanHostLiteral(host string) string {
	return stripEnclosingBrackets(strings.TrimSpace(host))
}

func stripEnclosingBrackets(val string) string {
	if len(val) > 2 && val[0] == '[' && val[len(val)-1] == ']' {
		inner := val[1 : len(val)-1]
		if !strings.ContainsAny(inner, "[]") && strings.TrimSpace(inner) == inner {
			return inner
		}
	}
	return val
}

func isAllowedLocalExecToken(tok byte, allowLocalTokens bool) bool {
	switch tok {
	case 'h', 'p', 'r', 'n':
		return true
	case 'C', 'd', 'i', 'l', 'L', 'u':
		return allowLocalTokens
	default:
		return false
	}
}

// templateUsesPercentToken reports whether pattern references %want (ignoring %%).
func templateUsesPercentToken(pattern string, want byte) bool {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '%' || i+1 >= len(pattern) {
			continue
		}
		i++
		if pattern[i] == '%' {
			continue
		}
		if pattern[i] == want {
			return true
		}
	}
	return false
}
