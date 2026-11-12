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

// DefaultStreamLocalBindMask is the default OpenSSH StreamLocalBindMask (0177).
const DefaultStreamLocalBindMask uint32 = 0o177

// ParseStreamLocalBindMask parses a StreamLocalBindMask octal string (1 to 4 octal digits, <= 0777).
func ParseStreamLocalBindMask(raw string) (uint32, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, errors.New("StreamLocalBindMask cannot be empty")
	}
	if len(trimmed) < 1 || len(trimmed) > 4 {
		return 0, fmt.Errorf("invalid StreamLocalBindMask %q: expected 1 to 4 octal digits", raw)
	}
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] < '0' || trimmed[i] > '7' {
			return 0, fmt.Errorf("invalid StreamLocalBindMask %q: octal digits expected", raw)
		}
	}
	val, err := strconv.ParseUint(trimmed, 8, 32)
	if err != nil || val > 0o777 {
		return 0, fmt.Errorf("invalid StreamLocalBindMask %q: value %04o exceeds 0777", raw, val)
	}
	return uint32(val), nil
}

// ParseStreamLocalBindMaskOption normalizes raw StreamLocalBindMask into 4-digit zero-padded octal string.
func ParseStreamLocalBindMaskOption(raw string) (string, error) {
	mask, err := ParseStreamLocalBindMask(raw)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%04o", mask), nil
}

// SessionTypeMode represents an OpenSSH SessionType mode.
type SessionTypeMode string

const (
	SessionTypeDefault SessionTypeMode = "default"
	SessionTypeNone    SessionTypeMode = "none"
)

// ParseSessionTypeMode validates and normalizes an OpenSSH SessionType value ("default" or "none").
func ParseSessionTypeMode(raw string) (SessionTypeMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "default":
		return SessionTypeDefault, nil
	case "none":
		return SessionTypeNone, nil
	default:
		return "", fmt.Errorf("invalid SessionType %q (expected default or none)", raw)
	}
}

// ForwardEndpoint represents an endpoint for TCP or Unix domain socket port forwarding.
type ForwardEndpoint struct {
	SocketPath string // Non-empty for Unix domain socket (StreamLocal) endpoints
	Host       string // Explicit unwrapped host, or "" when omitted/wildcard
	Port       uint16 // TCP port
	HasHost    bool   // True if a host token was explicitly written in TCP form (including wildcard "*" or "")
	Wildcard   bool   // True if bind host token was "*", "[*]", or "" (e.g. "*:8080", ":8080")
}

// IsUnix returns true if the endpoint is a Unix domain socket path.
func (e ForwardEndpoint) IsUnix() bool {
	return e.SocketPath != ""
}

// String returns the canonical OpenSSH string representation of the endpoint.
func (e ForwardEndpoint) String() string {
	if e.IsUnix() {
		return e.SocketPath
	}
	if !e.HasHost {
		return strconv.Itoa(int(e.Port))
	}
	if e.Wildcard {
		return "*:" + strconv.Itoa(int(e.Port))
	}
	return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port)))
}

// LocalListenAddress returns the network and address for local listening.
func (e ForwardEndpoint) LocalListenAddress(gatewayPorts bool) (network, addr string) {
	if e.IsUnix() {
		return "unix", e.SocketPath
	}
	if e.Wildcard {
		return "tcp", ":" + strconv.Itoa(int(e.Port))
	}
	if !e.HasHost {
		if gatewayPorts {
			return "tcp", ":" + strconv.Itoa(int(e.Port))
		}
		return "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(e.Port)))
	}
	return "tcp", net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port)))
}

// RemoteListenAddress returns the network and address for remote listening.
func (e ForwardEndpoint) RemoteListenAddress() (network, addr string) {
	if e.IsUnix() {
		return "unix", e.SocketPath
	}
	if e.Wildcard {
		return "tcp", ":" + strconv.Itoa(int(e.Port))
	}
	if !e.HasHost {
		return "tcp", net.JoinHostPort("localhost", strconv.Itoa(int(e.Port)))
	}
	return "tcp", net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port)))
}

// ConnectAddress returns the network and address for outbound connection.
func (e ForwardEndpoint) ConnectAddress() (network, addr string) {
	if e.IsUnix() {
		return "unix", e.SocketPath
	}
	return "tcp", net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port)))
}

// MuxListenEndpoint returns the host string and port uint32 for multiplexing protocol listen requests.
func (e ForwardEndpoint) MuxListenEndpoint() (host string, port uint32) {
	if e.IsUnix() {
		return e.SocketPath, MUX_SPECIAL_PORT_UNIX
	}
	if e.Wildcard {
		return "*", uint32(e.Port)
	}
	if !e.HasHost {
		return "", uint32(e.Port)
	}
	return e.Host, uint32(e.Port)
}

// MuxConnectEndpoint returns the host string and port uint32 for multiplexing protocol connect requests.
func (e ForwardEndpoint) MuxConnectEndpoint() (host string, port uint32) {
	if e.IsUnix() {
		return e.SocketPath, MUX_SPECIAL_PORT_UNIX
	}
	return e.Host, uint32(e.Port)
}

// ForwardSpec represents a normalized port forwarding specification.
type ForwardSpec struct {
	Bind      ForwardEndpoint
	Dest      ForwardEndpoint
	IsDynamic bool   // True for single-endpoint RemoteForward (reverse dynamic SOCKS proxy)
	BindAddr  string // Default local bind string view (for backward compatibility: SocketPath for unix, ":port" for wildcard, "127.0.0.1:port" for !HasHost, JoinHostPort(Host,port) otherwise)
	DestAddr  string // Default connect string view ("" when IsDynamic, SocketPath for unix, JoinHostPort(Host,port) otherwise)
}

// String formats ForwardSpec in canonical OpenSSH form.
func (f ForwardSpec) String() string {
	if f.IsDynamic {
		return f.Bind.String()
	}
	return f.Bind.String() + " " + f.Dest.String()
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

func isUnixSocketToken(tok string) bool {
	return strings.ContainsAny(tok, "/\\")
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func formatSpecBindAddr(e ForwardEndpoint) string {
	if e.IsUnix() {
		return e.SocketPath
	}
	portStr := strconv.Itoa(int(e.Port))
	if e.Wildcard {
		return ":" + portStr
	}
	if !e.HasHost {
		return net.JoinHostPort("127.0.0.1", portStr)
	}
	return net.JoinHostPort(e.Host, portStr)
}

func formatSpecDestAddr(e ForwardEndpoint) string {
	if e.IsUnix() {
		return e.SocketPath
	}
	return net.JoinHostPort(e.Host, strconv.Itoa(int(e.Port)))
}

func parseBindHostToken(token string) (host string, wildcard bool, err error) {
	if token == "" || token == "*" || token == "[*]" {
		return "", true, nil
	}
	unwrapped, err := unwrapForwardHost(token, false)
	if err != nil {
		return "", false, err
	}
	if unwrapped == "*" {
		return "", true, nil
	}
	return unwrapped, false, nil
}

func parseBindEndpoint(token string) (ForwardEndpoint, error) {
	if isUnixSocketToken(token) {
		if err := ValidateStreamLocalPathSyntax(token); err != nil {
			return ForwardEndpoint{}, fmt.Errorf("invalid streamlocal socket path %q: %w", token, err)
		}
		return ForwardEndpoint{SocketPath: token}, nil
	}
	parts, err := splitBracketAwareColons(token)
	if err != nil {
		return ForwardEndpoint{}, err
	}
	switch len(parts) {
	case 1:
		portNum, err := parsePortNumber(parts[0], true)
		if err != nil {
			return ForwardEndpoint{}, err
		}
		return ForwardEndpoint{
			Port:     portNum,
			HasHost:  false,
			Wildcard: false,
		}, nil
	case 2:
		bindHost, wildcard, err := parseBindHostToken(parts[0])
		if err != nil {
			return ForwardEndpoint{}, err
		}
		portNum, err := parsePortNumber(parts[1], true)
		if err != nil {
			return ForwardEndpoint{}, err
		}
		return ForwardEndpoint{
			Host:     bindHost,
			Port:     portNum,
			HasHost:  true,
			Wildcard: wildcard,
		}, nil
	default:
		return ForwardEndpoint{}, fmt.Errorf("expected [bind_address:]port or socket path, got %q", token)
	}
}

func parseDestEndpoint(token string) (ForwardEndpoint, error) {
	if isUnixSocketToken(token) {
		if err := ValidateStreamLocalPathSyntax(token); err != nil {
			return ForwardEndpoint{}, fmt.Errorf("invalid streamlocal socket path %q: %w", token, err)
		}
		return ForwardEndpoint{SocketPath: token}, nil
	}
	parts, err := splitBracketAwareColons(token)
	if err != nil {
		return ForwardEndpoint{}, err
	}
	if len(parts) != 2 {
		return ForwardEndpoint{}, fmt.Errorf("expected host:port, got %q", token)
	}
	if parts[0] == "*" || parts[0] == "[*]" || parts[0] == "" {
		return ForwardEndpoint{}, errors.New("destination host cannot be empty or wildcard")
	}
	destHost, err := unwrapForwardHost(parts[0], false)
	if err != nil {
		return ForwardEndpoint{}, err
	}
	if destHost == "*" || destHost == "" {
		return ForwardEndpoint{}, errors.New("destination host cannot be empty or wildcard")
	}
	destPort, err := parsePortNumber(parts[1], false)
	if err != nil {
		return ForwardEndpoint{}, err
	}
	return ForwardEndpoint{
		Host:     destHost,
		Port:     destPort,
		HasHost:  true,
		Wildcard: false,
	}, nil
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
		return parseWhitespaceForwardSpec(raw, fields)
	}

	parts, err := splitBracketAwareColons(fields[0])
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid forward specification %q: %w", raw, err)
	}

	return parseColonForwardSpec(raw, parts)
}

func parseWhitespaceForwardSpec(raw string, fields []string) (ForwardSpec, error) {
	bindEp, err := parseBindEndpoint(fields[0])
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid bind endpoint in %q: %w", raw, err)
	}
	destEp, err := parseDestEndpoint(fields[1])
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid target endpoint in %q: %w", raw, err)
	}
	return ForwardSpec{
		Bind:      bindEp,
		Dest:      destEp,
		IsDynamic: false,
		BindAddr:  formatSpecBindAddr(bindEp),
		DestAddr:  formatSpecDestAddr(destEp),
	}, nil
}

func parseColonForwardSpec(raw string, parts []string) (ForwardSpec, error) {
	switch len(parts) {
	case 2:
		return parseColonForwardSpec2(raw, parts)
	case 3:
		return parseColonForwardSpec3(raw, parts)
	case 4:
		return parseColonForwardSpec4(raw, parts)
	default:
		return ForwardSpec{}, fmt.Errorf("invalid forward specification %q: expected [bind_address:]port:host:hostport", raw)
	}
}

func parseColonForwardSpec2(raw string, parts []string) (ForwardSpec, error) {
	if !isUnixSocketToken(parts[1]) {
		return ForwardSpec{}, fmt.Errorf("invalid forward specification %q: expected [bind_address:]port:host:hostport", raw)
	}
	if err := ValidateStreamLocalPathSyntax(parts[1]); err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid destination socket path in %q: %w", raw, err)
	}
	destEp := ForwardEndpoint{SocketPath: parts[1]}

	var bindEp ForwardEndpoint
	if isUnixSocketToken(parts[0]) {
		if err := ValidateStreamLocalPathSyntax(parts[0]); err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid bind socket path in %q: %w", raw, err)
		}
		bindEp = ForwardEndpoint{SocketPath: parts[0]}
	} else {
		bindPort, err := parsePortNumber(parts[0], true)
		if err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid bind port in %q: %w", raw, err)
		}
		bindEp = ForwardEndpoint{
			Port:     bindPort,
			HasHost:  false,
			Wildcard: false,
		}
	}
	return ForwardSpec{
		Bind:      bindEp,
		Dest:      destEp,
		IsDynamic: false,
		BindAddr:  formatSpecBindAddr(bindEp),
		DestAddr:  formatSpecDestAddr(destEp),
	}, nil
}

func parseColonForwardSpec3(raw string, parts []string) (ForwardSpec, error) {
	if isUnixSocketToken(parts[2]) {
		if isUnixSocketToken(parts[0]) {
			return ForwardSpec{}, fmt.Errorf("invalid forward specification %q: bind host cannot be a unix socket", raw)
		}
		if err := ValidateStreamLocalPathSyntax(parts[2]); err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid destination socket path in %q: %w", raw, err)
		}
		destEp := ForwardEndpoint{SocketPath: parts[2]}
		bindHost, wildcard, err := parseBindHostToken(parts[0])
		if err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid bind address in %q: %w", raw, err)
		}
		bindPort, err := parsePortNumber(parts[1], true)
		if err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid bind port in %q: %w", raw, err)
		}
		bindEp := ForwardEndpoint{
			Host:     bindHost,
			Port:     bindPort,
			HasHost:  true,
			Wildcard: wildcard,
		}
		return ForwardSpec{
			Bind:      bindEp,
			Dest:      destEp,
			IsDynamic: false,
			BindAddr:  formatSpecBindAddr(bindEp),
			DestAddr:  formatSpecDestAddr(destEp),
		}, nil
	}

	destPort, err := parsePortNumber(parts[2], false)
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid destination port in %q: %w", raw, err)
	}
	if parts[1] == "*" || parts[1] == "[*]" || parts[1] == "" {
		return ForwardSpec{}, fmt.Errorf("invalid destination host in %q: wildcard or empty host not allowed", raw)
	}
	destHost, err := unwrapForwardHost(parts[1], false)
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid destination host in %q: %w", raw, err)
	}
	if destHost == "*" || destHost == "" {
		return ForwardSpec{}, fmt.Errorf("invalid destination host in %q: wildcard or empty host not allowed", raw)
	}
	destEp := ForwardEndpoint{
		Host:     destHost,
		Port:     destPort,
		HasHost:  true,
		Wildcard: false,
	}

	var bindEp ForwardEndpoint
	if isUnixSocketToken(parts[0]) {
		if err := ValidateStreamLocalPathSyntax(parts[0]); err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid bind socket path in %q: %w", raw, err)
		}
		bindEp = ForwardEndpoint{SocketPath: parts[0]}
	} else {
		bindPort, err := parsePortNumber(parts[0], true)
		if err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid bind port in %q: %w", raw, err)
		}
		bindEp = ForwardEndpoint{
			Port:     bindPort,
			HasHost:  false,
			Wildcard: false,
		}
	}
	return ForwardSpec{
		Bind:      bindEp,
		Dest:      destEp,
		IsDynamic: false,
		BindAddr:  formatSpecBindAddr(bindEp),
		DestAddr:  formatSpecDestAddr(destEp),
	}, nil
}

func parseColonForwardSpec4(raw string, parts []string) (ForwardSpec, error) {
	if isUnixSocketToken(parts[0]) || isUnixSocketToken(parts[2]) {
		return ForwardSpec{}, fmt.Errorf("invalid forward specification %q: unix socket not allowed in 4-part form", raw)
	}
	bindHost, wildcard, err := parseBindHostToken(parts[0])
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid bind address in %q: %w", raw, err)
	}
	bindPort, err := parsePortNumber(parts[1], true)
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid bind port in %q: %w", raw, err)
	}
	bindEp := ForwardEndpoint{
		Host:     bindHost,
		Port:     bindPort,
		HasHost:  true,
		Wildcard: wildcard,
	}

	if parts[2] == "*" || parts[2] == "[*]" || parts[2] == "" {
		return ForwardSpec{}, fmt.Errorf("invalid destination host in %q: wildcard or empty host not allowed", raw)
	}
	destHost, err := unwrapForwardHost(parts[2], false)
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid destination host in %q: %w", raw, err)
	}
	if destHost == "*" || destHost == "" {
		return ForwardSpec{}, fmt.Errorf("invalid destination host in %q: wildcard or empty host not allowed", raw)
	}
	destPort, err := parsePortNumber(parts[3], false)
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid destination port in %q: %w", raw, err)
	}
	destEp := ForwardEndpoint{
		Host:     destHost,
		Port:     destPort,
		HasHost:  true,
		Wildcard: false,
	}
	return ForwardSpec{
		Bind:      bindEp,
		Dest:      destEp,
		IsDynamic: false,
		BindAddr:  formatSpecBindAddr(bindEp),
		DestAddr:  formatSpecDestAddr(destEp),
	}, nil
}

// ParseRemoteForwardSpec parses a RemoteForward specification, supporting all two-endpoint
// specifications accepted by ParseForwardSpec as well as single-endpoint reverse dynamic
// port forwarding specifications (e.g. "1080", "127.0.0.1:1080", "*:1080", "/tmp/remote.sock").
func ParseRemoteForwardSpec(raw string) (ForwardSpec, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ForwardSpec{}, errors.New("remote forward specification cannot be empty")
	}
	fields := strings.Fields(trimmed)
	if len(fields) > 2 {
		return ForwardSpec{}, fmt.Errorf("invalid remote forward specification %q: expected at most two fields", raw)
	}
	if len(fields) == 2 {
		return ParseForwardSpec(raw)
	}

	parts, err := splitBracketAwareColons(fields[0])
	if err != nil {
		return ForwardSpec{}, fmt.Errorf("invalid remote forward specification %q: %w", raw, err)
	}

	switch len(parts) {
	case 1:
		if isUnixSocketToken(parts[0]) {
			if err := ValidateStreamLocalPathSyntax(parts[0]); err != nil {
				return ForwardSpec{}, fmt.Errorf("invalid remote forward socket path %q: %w", parts[0], err)
			}
			bindEp := ForwardEndpoint{SocketPath: parts[0]}
			return ForwardSpec{
				Bind:      bindEp,
				IsDynamic: true,
				BindAddr:  bindEp.SocketPath,
				DestAddr:  "",
			}, nil
		}
		port, err := parsePortNumber(parts[0], true)
		if err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid remote forward port in %q: %w", raw, err)
		}
		bindEp := ForwardEndpoint{
			Port:     port,
			HasHost:  false,
			Wildcard: false,
		}
		return ForwardSpec{
			Bind:      bindEp,
			IsDynamic: true,
			BindAddr:  formatSpecBindAddr(bindEp),
			DestAddr:  "",
		}, nil

	case 2:
		if isUnixSocketToken(parts[1]) {
			return ParseForwardSpec(raw)
		}
		if isUnixSocketToken(parts[0]) {
			return ForwardSpec{}, fmt.Errorf("invalid remote forward specification %q: unix socket cannot have a port", raw)
		}
		port, err := parsePortNumber(parts[1], true)
		if err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid remote forward port in %q: %w", raw, err)
		}
		host, wildcard, err := parseBindHostToken(parts[0])
		if err != nil {
			return ForwardSpec{}, fmt.Errorf("invalid remote forward bind host in %q: %w", raw, err)
		}
		bindEp := ForwardEndpoint{
			Host:     host,
			Port:     port,
			HasHost:  true,
			Wildcard: wildcard,
		}
		return ForwardSpec{
			Bind:      bindEp,
			IsDynamic: true,
			BindAddr:  formatSpecBindAddr(bindEp),
			DestAddr:  "",
		}, nil

	case 3, 4:
		return ParseForwardSpec(raw)

	default:
		return ForwardSpec{}, fmt.Errorf("invalid remote forward specification %q", raw)
	}
}

// ParseDynamicForwardEndpoint parses a DynamicForward specification ("[bind_address:]port" or socket path)
// into a ForwardEndpoint.
func ParseDynamicForwardEndpoint(raw string) (ForwardEndpoint, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ForwardEndpoint{}, errors.New("dynamic forward specification cannot be empty")
	}
	if len(strings.Fields(trimmed)) != 1 {
		return ForwardEndpoint{}, fmt.Errorf("invalid dynamic forward specification %q: expected [bind_address:]port or socket path", raw)
	}
	return parseBindEndpoint(trimmed)
}

// ParseDynamicForwardSpec parses a DynamicForward specification into its canonical OpenSSH string representation.
func ParseDynamicForwardSpec(raw string) (string, error) {
	ep, err := ParseDynamicForwardEndpoint(raw)
	if err != nil {
		return "", err
	}
	return ep.String(), nil
}

func unwrapForwardHost(token string, allowEmpty bool) (string, error) {
	if token == "" {
		if allowEmpty {
			return "", nil
		}
		return "", errors.New("host cannot be empty")
	}
	if strings.ContainsAny(token, "/\\") {
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
			if current.Len() == 0 {
				inBracket = true
			}
			current.WriteRune(r)
		case ']':
			if inBracket {
				inBracket = false
			} else if !strings.ContainsAny(current.String(), "/\\") {
				return nil, errors.New("unmatched ']' in address")
			}
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

	// Merge Windows drive-letter prefix tokens:
	// If a token is a single ASCII letter (A-Z/a-z) and the immediately following token
	// starts with '\' or '/', merge them back with ':'.
	if len(parts) >= 2 {
		merged := make([]string, 0, len(parts))
		for i := 0; i < len(parts); i++ {
			if len(parts[i]) == 1 && isASCIILetter(parts[i][0]) &&
				i+1 < len(parts) && len(parts[i+1]) > 0 && (parts[i+1][0] == '\\' || parts[i+1][0] == '/') {
				merged = append(merged, parts[i]+":"+parts[i+1])
				i++
			} else {
				merged = append(merged, parts[i])
			}
		}
		parts = merged
	}

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

// GatewayPorts returns (enabled, true) if explicitly configured, or (false, false) if unset.
func (o *Options) GatewayPorts() (bool, bool) {
	return o.boolOption(OptionGatewayPorts)
}

// EffectiveGatewayPorts returns true if GatewayPorts is enabled, false otherwise.
func (o *Options) EffectiveGatewayPorts() bool {
	v, _ := o.GatewayPorts()
	return v
}

// StreamLocalBindUnlink returns (enabled, true) if explicitly configured, or (false, false) if unset.
func (o *Options) StreamLocalBindUnlink() (bool, bool) {
	return o.boolOption(OptionStreamLocalBindUnlink)
}

// EffectiveStreamLocalBindUnlink returns true if StreamLocalBindUnlink is enabled, false otherwise.
func (o *Options) EffectiveStreamLocalBindUnlink() bool {
	v, _ := o.StreamLocalBindUnlink()
	return v
}

// StreamLocalBindMask returns (mask, true) if explicitly configured, or (0, false) if unset.
func (o *Options) StreamLocalBindMask() (uint32, bool) {
	val := o.Get(OptionStreamLocalBindMask)
	if val == "" {
		return 0, false
	}
	mask, err := ParseStreamLocalBindMask(val)
	if err != nil {
		return 0, false
	}
	return mask, true
}

// EffectiveStreamLocalBindMask returns the effective StreamLocalBindMask (defaults to DefaultStreamLocalBindMask = 0177).
func (o *Options) EffectiveStreamLocalBindMask() uint32 {
	if mask, ok := o.StreamLocalBindMask(); ok {
		return mask
	}
	return DefaultStreamLocalBindMask
}

// ForkAfterAuthentication returns (enabled, true) if explicitly configured, or (false, false) if unset.
func (o *Options) ForkAfterAuthentication() (bool, bool) {
	return o.boolOption(OptionForkAfterAuthentication)
}

// StdinNull returns (enabled, true) if explicitly configured, or (false, false) if unset.
func (o *Options) StdinNull() (bool, bool) {
	return o.boolOption(OptionStdinNull)
}

// SessionType returns the configured SessionTypeMode, or "" if unset.
func (o *Options) SessionType() SessionTypeMode {
	val := o.Get(OptionSessionType)
	if val == "" {
		return ""
	}
	mode, err := ParseSessionTypeMode(val)
	if err != nil {
		return ""
	}
	return mode
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
