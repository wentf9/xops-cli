package ssh

import (
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
)

// TunnelIDAny represents the OpenSSH "any" tunnel unit identifier (SSH_TUNID_ANY = 0x7fffffff).
const TunnelIDAny = math.MaxInt32

// TunnelMode represents an OpenSSH Tunnel forwarding mode.
type TunnelMode string

const (
	TunnelModeNo           TunnelMode = "no"
	TunnelModePointToPoint TunnelMode = "point-to-point"
	TunnelModeEthernet     TunnelMode = "ethernet"
	TunnelModeYes          TunnelMode = "yes"
)

// TunnelDeviceSpec represents parsed local and remote tunnel unit numbers.
type TunnelDeviceSpec struct {
	LocalUnit  int
	RemoteUnit int
}

// String formats TunnelDeviceSpec in canonical "local:remote" form.
func (s TunnelDeviceSpec) String() string {
	return formatTunnelUnit(s.LocalUnit) + ":" + formatTunnelUnit(s.RemoteUnit)
}

func formatTunnelUnit(unit int) string {
	if unit == TunnelIDAny {
		return "any"
	}
	return strconv.Itoa(unit)
}

// RequestTTYMode represents an OpenSSH RequestTTY option mode.
type RequestTTYMode string

const (
	RequestTTYAuto  RequestTTYMode = "auto"
	RequestTTYNo    RequestTTYMode = "no"
	RequestTTYYes   RequestTTYMode = "yes"
	RequestTTYForce RequestTTYMode = "force"
)

// ForwardSpec represents a normalized TCP port forwarding specification.
type ForwardSpec struct {
	BindAddr string
	DestAddr string
}

// String formats ForwardSpec in canonical OpenSSH two-token form "<bind_addr> <dest_addr>".
func (f ForwardSpec) String() string {
	return f.BindAddr + " " + f.DestAddr
}

// ParseTunnelOption validates and normalizes an OpenSSH Tunnel option value.
func ParseTunnelOption(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "yes", "true":
		return string(TunnelModeYes), nil
	case "point-to-point":
		return string(TunnelModePointToPoint), nil
	case "ethernet":
		return string(TunnelModeEthernet), nil
	case "no", "false":
		return string(TunnelModeNo), nil
	default:
		return "", fmt.Errorf("invalid Tunnel option %q (expected yes, point-to-point, ethernet, or no)", raw)
	}
}

// EffectiveTunnelModeFromValue maps a raw/normalized Tunnel value ("yes", "point-to-point",
// "ethernet", "no", or "") into its concrete runtime TunnelMode.
func EffectiveTunnelModeFromValue(val string) TunnelMode {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "yes", "true", "point-to-point":
		return TunnelModePointToPoint
	case "ethernet":
		return TunnelModeEthernet
	default:
		return TunnelModeNo
	}
}

// ParseTunnelDevice parses an OpenSSH -w / TunnelDevice value ("local_tun[:remote_tun]").
// Omitted remote_tun defaults to TunnelIDAny ("any").
func ParseTunnelDevice(raw string) (TunnelDeviceSpec, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return TunnelDeviceSpec{}, errors.New("invalid TunnelDevice: value cannot be empty")
	}
	parts := strings.Split(trimmed, ":")
	if len(parts) > 2 {
		return TunnelDeviceSpec{}, fmt.Errorf("invalid TunnelDevice %q: expected local_tun[:remote_tun]", raw)
	}
	localUnit, err := parseTunnelUnit(parts[0])
	if err != nil {
		return TunnelDeviceSpec{}, fmt.Errorf("invalid local tunnel unit in %q: %w", raw, err)
	}
	remoteUnit := TunnelIDAny
	if len(parts) == 2 {
		remoteUnit, err = parseTunnelUnit(parts[1])
		if err != nil {
			return TunnelDeviceSpec{}, fmt.Errorf("invalid remote tunnel unit in %q: %w", raw, err)
		}
	}
	return TunnelDeviceSpec{
		LocalUnit:  localUnit,
		RemoteUnit: remoteUnit,
	}, nil
}

func parseTunnelUnit(token string) (int, error) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return 0, errors.New("tunnel unit cannot be empty")
	}
	if strings.EqualFold(trimmed, "any") {
		return TunnelIDAny, nil
	}
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] < '0' || trimmed[i] > '9' {
			return 0, fmt.Errorf("expected non-negative integer or \"any\", got %q", token)
		}
	}
	u, err := strconv.ParseUint(trimmed, 10, 32)
	if err != nil || u >= uint64(TunnelIDAny) {
		return 0, fmt.Errorf("tunnel unit %q out of range (0..%d)", token, TunnelIDAny-1)
	}
	return int(u), nil
}

// ParseRequestTTYMode validates and normalizes an OpenSSH RequestTTY option value.
func ParseRequestTTYMode(raw string) (RequestTTYMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "no", "false":
		return RequestTTYNo, nil
	case "yes", "true":
		return RequestTTYYes, nil
	case "force":
		return RequestTTYForce, nil
	case "auto":
		return RequestTTYAuto, nil
	default:
		return "", fmt.Errorf("invalid RequestTTY option %q (expected no, yes, force, or auto)", raw)
	}
}

// ParseStdioForward parses an OpenSSH -W host:port (or [ipv6]:port) specification.
func ParseStdioForward(raw string) (host string, port uint16, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", 0, errors.New("stdio forward specification cannot be empty")
	}
	parts, err := splitBracketAwareColons(trimmed)
	if err != nil {
		return "", 0, fmt.Errorf("invalid stdio forward %q: %w", raw, err)
	}
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid stdio forward %q: expected host:port", raw)
	}
	cleanHost, err := unwrapForwardHost(parts[0], false)
	if err != nil {
		return "", 0, fmt.Errorf("invalid stdio forward host in %q: %w", raw, err)
	}
	portNum, err := parsePortNumber(parts[1], false)
	if err != nil {
		return "", 0, fmt.Errorf("invalid stdio forward port in %q: %w", raw, err)
	}
	return cleanHost, portNum, nil
}

// ParseForwardSpec parses a LocalForward or RemoteForward specification in either
// OpenSSH two-token whitespace form ("[bind_address:]port host:hostport") or CLI
// colon-delimited form ("[bind_address:]port:host:hostport").
func ParseForwardSpec(raw string) (ForwardSpec, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ForwardSpec{}, errors.New("forward specification cannot be empty")
	}
	fields := strings.Fields(trimmed)
	if len(fields) > 2 {
		return ForwardSpec{}, fmt.Errorf("invalid forward specification %q: expected '[bind_address:]port host:hostport'", raw)
	}
	if len(fields) == 2 {
		bindAddr, err := parseBindEndpointSpec(fields[0])
		if err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid bind endpoint in %q: %w", raw, err)
		}
		destHost, destPort, err := ParseStdioForward(fields[1])
		if err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid target endpoint in %q: %w", raw, err)
		}
		return ForwardSpec{
			BindAddr: bindAddr,
			DestAddr: net.JoinHostPort(destHost, strconv.Itoa(int(destPort))),
		}, nil
	}

	parts, err := splitBracketAwareColons(fields[0])
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid forward specification %q: %w", raw, err)
	}
	if len(parts) < 3 || len(parts) > 4 {
		return ForwardSpec{}, fmt.Errorf("invalid forward specification %q: expected [bind_address:]port:host:hostport", raw)
	}
	var bindHost, bindPortStr string
	if len(parts) == 3 {
		bindHost = "127.0.0.1"
		bindPortStr = parts[0]
	} else {
		bindHost, err = unwrapBindHost(parts[0])
		if err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid bind address in %q: %w", raw, err)
		}
		bindPortStr = parts[1]
	}
	bindPort, err := parsePortNumber(bindPortStr, true)
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid bind port in %q: %w", raw, err)
	}
	destHost, err := unwrapForwardHost(parts[len(parts)-2], false)
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid destination host in %q: %w", raw, err)
	}
	destPort, err := parsePortNumber(parts[len(parts)-1], false)
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid destination port in %q: %w", raw, err)
	}
	return ForwardSpec{
		BindAddr: net.JoinHostPort(bindHost, strconv.Itoa(int(bindPort))),
		DestAddr: net.JoinHostPort(destHost, strconv.Itoa(int(destPort))),
	}, nil
}

// ParseDynamicForwardSpec parses a DynamicForward specification ("[bind_address:]port")
// into a normalized host:port listen address.
func ParseDynamicForwardSpec(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("dynamic forward specification cannot be empty")
	}
	if len(strings.Fields(trimmed)) != 1 {
		return "", fmt.Errorf("invalid dynamic forward specification %q: expected [bind_address:]port", raw)
	}
	return parseBindEndpointSpec(trimmed)
}

func parseBindEndpointSpec(spec string) (string, error) {
	if strings.Contains(spec, "/") {
		return "", fmt.Errorf("unix domain socket forwarding %q is not supported", spec)
	}
	parts, err := splitBracketAwareColons(spec)
	if err != nil {
		return "", err
	}
	switch len(parts) {
	case 1:
		portNum, err := parsePortNumber(parts[0], true)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(portNum))), nil
	case 2:
		bindHost, err := unwrapBindHost(parts[0])
		if err != nil {
			return "", err
		}
		portNum, err := parsePortNumber(parts[1], true)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(bindHost, strconv.Itoa(int(portNum))), nil
	default:
		return "", fmt.Errorf("expected [bind_address:]port, got %q", spec)
	}
}

func unwrapBindHost(token string) (string, error) {
	if token == "" || token == "*" {
		return "", nil
	}
	return unwrapForwardHost(token, false)
}

func unwrapForwardHost(token string, allowEmpty bool) (string, error) {
	if token == "" {
		if allowEmpty {
			return "", nil
		}
		return "", errors.New("host cannot be empty")
	}
	if strings.Contains(token, "/") {
		return "", fmt.Errorf("unix domain socket path %q is not supported", token)
	}
	if strings.HasPrefix(token, "[") {
		if !strings.HasSuffix(token, "]") {
			return "", fmt.Errorf("unclosed bracket in host %q", token)
		}
		inner := token[1 : len(token)-1]
		if inner == "" || strings.ContainsAny(inner, "[]") {
			return "", fmt.Errorf("invalid bracketed host %q", token)
		}
		if inner == "*" {
			return "", nil
		}
		return inner, nil
	}
	if strings.ContainsAny(token, "[]") {
		return "", fmt.Errorf("unexpected bracket in host %q", token)
	}
	return token, nil
}

func parsePortNumber(token string, allowZero bool) (uint16, error) {
	if token == "" {
		return 0, errors.New("port cannot be empty")
	}
	for i := 0; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return 0, fmt.Errorf("invalid port %q", token)
		}
	}
	p, err := strconv.ParseUint(token, 10, 16)
	if err != nil || (!allowZero && p == 0) {
		return 0, fmt.Errorf("port %q out of range", token)
	}
	return uint16(p), nil
}

func splitBracketAwareColons(s string) ([]string, error) {
	var parts []string
	var current strings.Builder
	inBracket := false
	for _, r := range s {
		switch r {
		case '[':
			if inBracket {
				return nil, errors.New("nested '[' in address")
			}
			inBracket = true
			current.WriteRune(r)
		case ']':
			if !inBracket {
				return nil, errors.New("unmatched ']' in address")
			}
			inBracket = false
			current.WriteRune(r)
		case ':':
			if !inBracket {
				parts = append(parts, current.String())
				current.Reset()
				continue
			}
			current.WriteRune(r)
		default:
			current.WriteRune(r)
		}
	}
	if inBracket {
		return nil, errors.New("unclosed '[' in address")
	}
	parts = append(parts, current.String())
	return parts, nil
}

func normalizeMultiForwardEntries(optionName, raw string, normalizeItem func(string) (string, error)) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("invalid %s: value cannot be empty", optionName)
	}
	var normalized []string
	for line := range strings.SplitSeq(trimmed, "\n") {
		item := strings.TrimSpace(line)
		if item == "" {
			continue
		}
		norm, err := normalizeItem(item)
		if err != nil {
			return "", fmt.Errorf("invalid %s %q: %w", optionName, item, err)
		}
		if !slices.Contains(normalized, norm) {
			normalized = append(normalized, norm)
		}
	}
	if len(normalized) == 0 {
		return "", fmt.Errorf("invalid %s: value cannot be empty", optionName)
	}
	return strings.Join(normalized, "\n"), nil
}

// Append validates and appends rawValue for multi-value options (LocalForward,
// RemoteForward, DynamicForward), deduplicating identical normalized entries while
// preserving insertion order. For scalar options, Append behaves identically to Set.
func (o *Options) Append(key, rawValue string) error {
	if o == nil {
		return fmt.Errorf("%w: options receiver is nil", ErrSSHOptionsValidation)
	}
	spec, ok := LookupOptionSpec(key)
	if !ok {
		return fmt.Errorf("%w: unknown ssh option %q", ErrSSHOptionsValidation, key)
	}
	if !spec.MultiValue {
		return o.Set(key, rawValue)
	}
	if strings.TrimSpace(rawValue) == "" {
		return fmt.Errorf("%w: invalid %s: value cannot be empty", ErrSSHOptionsValidation, spec.OpenSSHName)
	}
	normalized, err := spec.Normalize(rawValue)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	o.appendNormalizedRaw(spec.CanonicalKey, normalized)
	return nil
}

func (o *Options) appendNormalizedRaw(canonicalKey, normalized string) {
	if normalized == "" {
		return
	}
	existing := o.GetAll(canonicalKey)
	for item := range strings.SplitSeq(normalized, "\n") {
		if item != "" && !slices.Contains(existing, item) {
			existing = append(existing, item)
		}
	}
	if len(existing) > 0 {
		o.setRaw(canonicalKey, strings.Join(existing, "\n"))
	}
}

// GetAll returns all normalized entries for key, or nil if unset.
func (o *Options) GetAll(key string) []string {
	val := o.Get(key)
	if val == "" {
		return nil
	}
	spec, ok := LookupOptionSpec(key)
	if ok && spec.MultiValue {
		parts := strings.Split(val, "\n")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return []string{val}
}

// ExitOnForwardFailure returns (enabled, true) if explicitly configured, or (false, false) if unset.
func (o *Options) ExitOnForwardFailure() (bool, bool) {
	return o.boolOption(OptionExitOnForwardFailure)
}

// ClearAllForwardings returns (enabled, true) if explicitly configured, or (false, false) if unset.
func (o *Options) ClearAllForwardings() (bool, bool) {
	return o.boolOption(OptionClearAllForwardings)
}

// Tunnel returns the raw normalized Tunnel option value ("yes", "point-to-point", "ethernet", "no"), or "" if unset.
func (o *Options) Tunnel() string {
	return o.Get(OptionTunnel)
}

// EffectiveTunnelMode returns the resolved TunnelMode ("point-to-point", "ethernet", or "no").
func (o *Options) EffectiveTunnelMode() TunnelMode {
	return EffectiveTunnelModeFromValue(o.Tunnel())
}

// TunnelDevice returns the parsed TunnelDeviceSpec and true if configured, or zero and false if unset.
func (o *Options) TunnelDevice() (TunnelDeviceSpec, bool) {
	val := o.Get(OptionTunnelDevice)
	if val == "" {
		return TunnelDeviceSpec{}, false
	}
	spec, err := ParseTunnelDevice(val)
	if err != nil {
		return TunnelDeviceSpec{}, false
	}
	return spec, true
}

// RequestTTY returns the configured RequestTTYMode, or "" if unset.
func (o *Options) RequestTTY() RequestTTYMode {
	return RequestTTYMode(o.Get(OptionRequestTTY))
}

// LocalForwards returns all configured LocalForward entries in canonical "<bind_addr> <dest_addr>" form.
func (o *Options) LocalForwards() []string {
	return o.GetAll(OptionLocalForward)
}

// RemoteForwards returns all configured RemoteForward entries in canonical "<bind_addr> <dest_addr>" form.
func (o *Options) RemoteForwards() []string {
	return o.GetAll(OptionRemoteForward)
}

// DynamicForwards returns all configured DynamicForward listen addresses.
func (o *Options) DynamicForwards() []string {
	return o.GetAll(OptionDynamicForward)
}
