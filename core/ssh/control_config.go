package ssh

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ControlMasterMode specifies connection sharing master behavior.
// Compatible with OpenSSH ssh_config(5) ControlMaster options.
type ControlMasterMode string

const (
	// ControlMasterNo disables listening on the control socket.
	// If a control socket exists and is active, client will reuse it; otherwise connects normally.
	ControlMasterNo ControlMasterMode = "no"

	// ControlMasterYes listens on the control socket as master.
	ControlMasterYes ControlMasterMode = "yes"

	// ControlMasterAsk listens as master, prompting confirmation before opening new sessions.
	ControlMasterAsk ControlMasterMode = "ask"

	// ControlMasterAuto opportunistically attempts client reuse on ControlPath;
	// if none exists or the socket is stale, it establishes master listening on ControlPath.
	ControlMasterAuto ControlMasterMode = "auto"

	// ControlMasterAutoAsk opportunistic reuse like auto, but prompting confirmation like ask.
	ControlMasterAutoAsk ControlMasterMode = "autoask"
)

// ParseControlMasterMode normalizes string inputs into a valid ControlMasterMode.
// Supports OpenSSH keywords ("no", "yes", "ask", "auto", "autoask") and boolean aliases ("true", "false").
func ParseControlMasterMode(val string) (ControlMasterMode, error) {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "no", "false", "":
		return ControlMasterNo, nil
	case "yes", "true":
		return ControlMasterYes, nil
	case "ask":
		return ControlMasterAsk, nil
	case "auto":
		return ControlMasterAuto, nil
	case "autoask":
		return ControlMasterAutoAsk, nil
	default:
		return "", fmt.Errorf("unsupported ControlMaster option %q", val)
	}
}

// ControlPathKind classifies a parsed ControlPath setting into mutually exclusive states.
type ControlPathKind uint8

const (
	// ControlPathUnset indicates no ControlPath was configured.
	ControlPathUnset ControlPathKind = iota
	// ControlPathDisabled indicates multiplexing was explicitly disabled via "none".
	ControlPathDisabled
	// ControlPathTemplate indicates an expandable ControlPath template (~, ${VAR}, % tokens).
	ControlPathTemplate
	// ControlPathLiteral indicates an already-expanded literal socket path.
	ControlPathLiteral
)

// ControlPathSetting is the typed, parsed representation of a ControlPath value.
type ControlPathSetting struct {
	Kind ControlPathKind
	Raw  string
}

// Unset reports whether no ControlPath is configured.
func (s ControlPathSetting) Unset() bool { return s.Kind == ControlPathUnset }

// Disabled reports whether ControlPath is explicitly disabled ("none").
func (s ControlPathSetting) Disabled() bool { return s.Kind == ControlPathDisabled }

// Enabled reports whether ControlPath specifies a concrete template or literal path.
func (s ControlPathSetting) Enabled() bool {
	return s.Kind == ControlPathTemplate || s.Kind == ControlPathLiteral
}

// ParseControlPathSetting parses raw into a typed ControlPathSetting.
func ParseControlPathSetting(raw string, literal bool) (ControlPathSetting, error) {
	if raw == "" {
		return ControlPathSetting{Kind: ControlPathUnset}, nil
	}
	if hasControlOrLineSepChar(raw) {
		return ControlPathSetting{}, fmt.Errorf("invalid ControlPath %q: contains invalid ASCII control character", raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ControlPathSetting{}, errors.New("invalid ControlPath: value cannot be empty")
	}
	if IsNoneValue(trimmed) {
		return ControlPathSetting{Kind: ControlPathDisabled, Raw: "none"}, nil
	}
	if literal {
		return ControlPathSetting{Kind: ControlPathLiteral, Raw: raw}, nil
	}
	if err := ValidateControlPathSyntax(trimmed); err != nil {
		return ControlPathSetting{}, fmt.Errorf("invalid ControlPath %q: %w", raw, err)
	}
	return ControlPathSetting{Kind: ControlPathTemplate, Raw: trimmed}, nil
}

// PersistKind classifies a parsed ControlPersist setting into mutually exclusive states.
type PersistKind uint8

const (
	// PersistUnset indicates ControlPersist was not specified.
	PersistUnset PersistKind = iota
	// PersistNo indicates ControlPersist was explicitly disabled ("no" / "false").
	PersistNo
	// PersistIndefinite indicates the master persists indefinitely ("yes" / "true" / "0").
	PersistIndefinite
	// PersistDuration indicates the master persists for a bounded idle Duration.
	PersistDuration
)

// PersistSetting is the typed, parsed representation of a ControlPersist value.
type PersistSetting struct {
	Kind     PersistKind
	Raw      string
	Duration time.Duration
}

// Explicit reports whether ControlPersist was explicitly specified (including "no"/"false").
func (s PersistSetting) Explicit() bool { return s.Kind != PersistUnset }

// Enabled reports whether ControlPersist keeps the master alive after client exit.
func (s PersistSetting) Enabled() bool {
	return s.Kind == PersistIndefinite || s.Kind == PersistDuration
}

// Indefinite reports whether ControlPersist keeps the master alive indefinitely.
func (s PersistSetting) Indefinite() bool { return s.Kind == PersistIndefinite }

// ParsePersistSetting parses OpenSSH ControlPersist values into a typed PersistSetting.
func ParsePersistSetting(val string) (PersistSetting, error) {
	if hasControlOrLineSepChar(val) {
		return PersistSetting{}, fmt.Errorf("bad ControlPersist argument %q: contains invalid control character", val)
	}
	trimmed := strings.ToLower(strings.TrimSpace(val))
	switch trimmed {
	case "":
		return PersistSetting{Kind: PersistUnset}, nil
	case "no", "false":
		return PersistSetting{Kind: PersistNo, Raw: trimmed}, nil
	case "yes", "true", "0":
		return PersistSetting{Kind: PersistIndefinite, Raw: trimmed}, nil
	}
	d, err := parseOpenSSHDuration(trimmed)
	if err != nil {
		return PersistSetting{}, fmt.Errorf("bad ControlPersist argument %q: %w", val, err)
	}
	return PersistSetting{Kind: PersistDuration, Raw: trimmed, Duration: d}, nil
}

// ControlConfig specifies the connection multiplexing parameters for an SSH connection.
// Matches the contract defined in PROJECT.md and Schema V2.
type ControlConfig struct {
	Master      ControlMasterMode `json:"master,omitempty" yaml:"master,omitempty" digest:"include"`
	Path        string            `json:"path,omitempty" yaml:"path,omitempty" digest:"include"`
	LiteralPath bool              `json:"-" yaml:"-" digest:"include"`
	Persist     string            `json:"persist,omitempty" yaml:"persist,omitempty" digest:"include"`
	// ImplicitTier4 is true when multiplexing was resolved solely from ~/.ssh/config
	// (Tier 4) without any CLI flag or xops node/global configuration.
	ImplicitTier4 bool `json:"-" yaml:"-" digest:"include"`
	// AllowReuse is true when the CLI explicitly specified -S <path> without -M or
	// -o ControlMaster=..., allowing attachment to an existing master even when a
	// lower-priority config layer sets ControlMaster=yes or ControlMaster=ask.
	AllowReuse bool `json:"-" yaml:"-" digest:"include"`
}

// ResolvePath returns the concrete socket path for c. When LiteralPath is true,
// c.Path is treated as an already-expanded path and validated without rescanning
// ~, ${VAR}, or % tokens; otherwise c.Path is expanded with ExpandControlPath.
func (c *ControlConfig) ResolvePath(env Environment, target TargetContext) (string, error) {
	if c == nil || c.Path == "" {
		return "", nil
	}
	if hasControlOrLineSepChar(c.Path) {
		return "", fmt.Errorf("invalid ControlPath %q: contains invalid control character", c.Path)
	}
	if IsNoneValue(c.Path) {
		return "none", nil
	}
	if c.LiteralPath {
		if strings.TrimSpace(c.Path) == "" {
			return "", errors.New("ControlPath is empty")
		}
		return c.Path, nil
	}
	return ExpandControlPath(c.Path, env, target)
}

// IsEnabled returns true if multiplexing is enabled (either master or reuse).
func (c *ControlConfig) IsEnabled() bool {
	if c == nil {
		return false
	}
	return strings.TrimSpace(c.Path) != "" && !IsNoneValue(c.Path)
}

// Clone returns a deep copy of ControlConfig.
func (c *ControlConfig) Clone() *ControlConfig {
	if c == nil {
		return nil
	}
	cloned := *c
	return &cloned
}

// Equal reports whether two ControlConfig values are equal.
func (c *ControlConfig) Equal(other *ControlConfig) bool {
	if c == other {
		return true
	}
	if c == nil || other == nil {
		return false
	}
	return c.Master == other.Master && c.Path == other.Path && c.LiteralPath == other.LiteralPath && c.Persist == other.Persist
}

// ControlProvider provides multiplexing configuration for a node.
type ControlProvider interface {
	GetControlConfig(nodeID string) (*ControlConfig, error)
}

// TargetContext supplies destination, port, user, and routing context for ControlPath token expansion.
type TargetContext struct {
	Host          string         // Target host or IP address (%h)
	Port          int            // Target port (%p), defaults to 22 if <= 0
	User          string         // Target remote username (%r)
	OriginalHost  string         // Original command-line host or alias (%n), defaults to Host if empty
	CanonicalHost string         // Canonicalized FQDN when OpenSSH two-pass canonicalization resolved one
	JumpHost      string         // ProxyJump host if any (%j), used in %C connection hash calculation
	KeyPath       string         // Effective private key path for this target, if any
	Control       *ControlConfig // Multiplexing control configuration
}

const muxTargetExtensionName = "target@xops"

// ErrControlTargetMismatch indicates that an active control socket belongs to
// a master connected to a different remote destination than the requested target.
var ErrControlTargetMismatch = errors.New("control socket target mismatch")

// CanonicalTargetIdentity returns a normalized "user@host:port[via jump]"
// descriptor used to verify that a static ControlPath is not accidentally
// reused across different destination hosts, ports, users, or jump hosts.
// Returns "" if Host is empty.
func (t TargetContext) CanonicalTargetIdentity() string {
	host := strings.ToLower(cleanHostLiteral(t.Host))
	if host == "" {
		return ""
	}
	port := t.Port
	if port <= 0 {
		port = 22
	}
	user := strings.TrimSpace(t.User)
	jump := strings.ToLower(NormalizeProxyJump(t.JumpHost))
	return fmt.Sprintf("host=%s;port=%d;user=%s;jump=%s", host, port, user, jump)
}

// MatchesMasterTarget reports whether the requested target is compatible with
// the master target identity advertised via the "target@xops" hello extension.
//
// An empty masterIdentity ("") returns true solely for legacy OpenSSH master
// interoperability (masters that do not send the "target@xops" extension).
// Any non-empty masterIdentity is validated fail-closed: an empty local target
// host, missing/empty "host=", invalid/non-positive/out-of-range "port=",
// duplicate fields, or malformed key=value segments all return false.
func (t TargetContext) MatchesMasterTarget(masterIdentity string) bool {
	if masterIdentity == "" {
		return true
	}
	tHost := strings.ToLower(cleanHostLiteral(t.Host))
	if tHost == "" {
		return false
	}
	mHost, mPort, mUser, mJump, ok := parseMasterTargetIdentity(masterIdentity)
	if !ok {
		return false
	}
	tPort := t.Port
	if tPort <= 0 {
		tPort = 22
	}
	tUser := strings.TrimSpace(t.User)
	tJump := strings.ToLower(NormalizeProxyJump(t.JumpHost))

	if tHost != mHost || tPort != mPort || tJump != mJump {
		return false
	}
	if tUser != "" && mUser != "" && tUser != mUser {
		return false
	}
	return true
}

func parseMasterTargetIdentity(masterIdentity string) (host string, port int, user, jump string, ok bool) {
	port = 22
	var seenHost, seenPort, seenUser, seenJump bool
	for part := range strings.SplitSeq(masterIdentity, ";") {
		key, val, found := strings.Cut(part, "=")
		if !found || key == "" || strings.TrimSpace(key) != key {
			return "", 0, "", "", false
		}
		switch key {
		case "host":
			if seenHost {
				return "", 0, "", "", false
			}
			seenHost = true
			host = strings.ToLower(cleanHostLiteral(val))
			if host == "" {
				return "", 0, "", "", false
			}
		case "port":
			if seenPort {
				return "", 0, "", "", false
			}
			seenPort = true
			p, err := strconv.Atoi(strings.TrimSpace(val))
			if err != nil || p <= 0 || p > 65535 {
				return "", 0, "", "", false
			}
			port = p
		case "user":
			if seenUser {
				return "", 0, "", "", false
			}
			seenUser = true
			user = strings.TrimSpace(val)
		case "jump":
			if seenJump {
				return "", 0, "", "", false
			}
			seenJump = true
			jump = strings.ToLower(NormalizeProxyJump(val))
		}
	}
	if host == "" {
		return "", 0, "", "", false
	}
	return host, port, user, jump, true
}

// FormatTargetIdentity formats a canonical target identity string for human-readable error messages.
func FormatTargetIdentity(identity string) string {
	var host, user, jump string
	port := 22
	for _, part := range strings.Split(identity, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "host":
			host = cleanHostLiteral(kv[1])
		case "port":
			if p, err := strconv.Atoi(kv[1]); err == nil && p > 0 {
				port = p
			}
		case "user":
			user = kv[1]
		case "jump":
			jump = kv[1]
		}
	}
	if host == "" {
		return identity
	}
	base := joinHostPort(host, port)
	if user != "" {
		base = fmt.Sprintf("%s@%s", user, base)
	}
	if jump != "" {
		base = fmt.Sprintf("%s (via %s)", base, jump)
	}
	return base
}

type pathExpandOptions struct {
	kind          string
	tildeFallback func(string) string
	expandTilde   bool
}

// ExpandControlPath expands tokens (%%, %h, %p, %r, %n, %u, %l, %L, %i, %d, %j, %C), tilde (~),
// and environment variables (${VAR}) in rawPath in a single pass according to OpenSSH ssh_config(5) rules.
func ExpandControlPath(rawPath string, env Environment, target TargetContext) (string, error) {
	if hasControlOrLineSepChar(rawPath) {
		return "", fmt.Errorf("ControlPath %q contains invalid control character", rawPath)
	}
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		return "", nil
	}
	if IsNoneValue(rawPath) {
		return "none", nil
	}
	expanded, err := expandPathTokensSinglePass(rawPath, env, target, pathExpandOptions{
		kind:        "ControlPath",
		expandTilde: true,
	})
	if err != nil {
		return "", err
	}
	if hasControlOrLineSepChar(expanded) {
		return "", fmt.Errorf("expanded ControlPath %q contains invalid control character", expanded)
	}
	if IsNoneValue(expanded) {
		return "none", nil
	}
	return expanded, nil
}

func expandPathTokensSinglePass(rawPath string, env Environment, target TargetContext, opts pathExpandOptions) (string, error) {
	if opts.expandTilde {
		if rawPath == "~" {
			if env.HomeDir != "" {
				return env.HomeDir, nil
			}
			if opts.tildeFallback != nil {
				return opts.tildeFallback("~"), nil
			}
			return "", errors.New("cannot expand '~': home directory is not set")
		}
		if strings.HasPrefix(rawPath, "~/") || (runtime.GOOS == "windows" && strings.HasPrefix(rawPath, `~\`)) {
			if env.HomeDir == "" && opts.tildeFallback == nil {
				return "", errors.New("cannot expand '~': home directory is not set")
			}
			tildePrefix := rawPath[:2]
			expandedRest, err := expandPathBodySinglePass(rawPath[2:], env, target, opts.kind)
			if err != nil {
				return "", err
			}
			if env.HomeDir != "" {
				return filepath.Join(env.HomeDir, expandedRest), nil
			}
			return opts.tildeFallback(tildePrefix + expandedRest), nil
		}
	}
	return expandPathBodySinglePass(rawPath, env, target, opts.kind)
}

func expandPathBodySinglePass(raw string, env Environment, target TargetContext, kind string) (string, error) {
	host := cleanHostLiteral(target.Host)

	portStr := "22"
	if target.Port > 0 {
		portStr = strconv.Itoa(target.Port)
	}

	origHost := target.OriginalHost
	if origHost == "" {
		origHost = host
	}

	remoteUser := target.User
	if remoteUser == "" {
		remoteUser = env.LocalUser
	}

	shortLocalHost := env.LocalHost
	if idx := strings.Index(shortLocalHost, "."); idx != -1 {
		shortLocalHost = shortLocalHost[:idx]
	}

	connHash := ""
	connHashReady := false

	var sb strings.Builder
	sb.Grow(len(raw) + 32)

	for i := 0; i < len(raw); {
		if raw[i] == '$' && i+1 < len(raw) && raw[i+1] == '{' {
			val, nextIdx, err := expandPathEnvToken(raw, i, env, kind)
			if err != nil {
				return "", err
			}
			sb.WriteString(val)
			i = nextIdx
			continue
		}
		if raw[i] == '%' {
			if i+1 >= len(raw) {
				return "", fmt.Errorf("trailing '%%' in %s", kind)
			}
			expanded, err := expandPathPercentToken(raw[i+1], target, env, host, portStr, origHost, remoteUser, shortLocalHost, &connHash, &connHashReady, kind)
			if err != nil {
				return "", err
			}
			sb.WriteString(expanded)
			i += 2
			continue
		}
		sb.WriteByte(raw[i])
		i++
	}
	return sb.String(), nil
}

func expandPathEnvToken(raw string, i int, env Environment, kind string) (string, int, error) {
	relEnd := strings.IndexByte(raw[i+2:], '}')
	if relEnd < 0 {
		return "", 0, fmt.Errorf("invalid environment variable expansion: unclosed environment variable in %s: %q", kind, raw[i:])
	}
	end := i + 2 + relEnd
	varName := raw[i+2 : end]
	if !isValidEnvIdentifier(varName) {
		return "", 0, fmt.Errorf("invalid environment variable expansion: invalid environment variable name ${%s} in %s", varName, kind)
	}
	val, ok := lookupEnv(env, varName)
	if !ok || val == "" {
		return "", 0, fmt.Errorf("invalid environment variable expansion: env var ${%s} has no value", varName)
	}
	return val, end + 1, nil
}

func validateExpandedPathToken(tok byte, val, kind string) error {
	if val == "" {
		return nil
	}
	if strings.ContainsRune(val, 0) || hasControlOrLineSepChar(val) {
		return fmt.Errorf("invalid %s token %%%c expansion %q: contains invalid control character", kind, tok, val)
	}
	if strings.ContainsAny(val, `/\`) {
		return fmt.Errorf("invalid %s token %%%c expansion %q: contains path separator", kind, tok, val)
	}
	if val == "." || val == ".." || strings.Contains(val, "..") {
		return fmt.Errorf("invalid %s token %%%c expansion %q: contains path traversal segment", kind, tok, val)
	}
	return nil
}

// validateWindowsSocketPath rejects Windows NTFS Alternate Data Stream (':')
// and invalid Windows filename characters ('*', '?', '"', '<', '>', '|')
// anywhere after an optional leading drive-letter prefix (e.g. "C:"). Enforcing
// this at the Windows socket bind boundary covers literal ":%p", ${VAR}, and
// IPv6 "%h" uniformly without breaking cross-platform token expansion parity.
func validateWindowsSocketPath(socketPath string) error {
	if socketPath == "" {
		return errors.New("windows socket path cannot be empty")
	}
	if strings.ContainsRune(socketPath, 0) || hasControlOrLineSepChar(socketPath) {
		return fmt.Errorf("windows socket path %q contains invalid control character", socketPath)
	}
	rest := socketPath
	if len(rest) >= 2 && ((rest[0] >= 'a' && rest[0] <= 'z') || (rest[0] >= 'A' && rest[0] <= 'Z')) && rest[1] == ':' {
		rest = rest[2:]
	}
	if strings.ContainsAny(rest, `:*?"<>|`) {
		return fmt.Errorf("windows socket path %q contains invalid Windows filename or NTFS stream character", socketPath)
	}
	return nil
}

func expandPathPercentToken(
	tok byte,
	target TargetContext,
	env Environment,
	host, portStr, origHost, remoteUser, shortLocalHost string,
	connHash *string,
	connHashReady *bool,
	kind string,
) (string, error) {
	var val string
	switch tok {
	case '%':
		return "%", nil
	case 'p':
		return portStr, nil
	case 'd':
		return env.HomeDir, nil
	case 'C':
		if !*connHashReady {
			*connHash = ComputeConnectionHash(env.LocalHost, host, portStr, remoteUser, NormalizeProxyJump(target.JumpHost))
			*connHashReady = true
		}
		return *connHash, nil
	case 'h':
		val = host
	case 'r':
		val = remoteUser
	case 'n':
		val = origHost
	case 'u':
		val = env.LocalUser
	case 'l':
		val = env.LocalHost
	case 'L':
		val = shortLocalHost
	case 'i':
		val = env.LocalUID
	case 'j':
		val = NormalizeProxyJump(target.JumpHost)
	default:
		return "", fmt.Errorf("unknown %s token %%%c", kind, tok)
	}
	if err := validateExpandedPathToken(tok, val, kind); err != nil {
		return "", err
	}
	return val, nil
}

// lookupEnv reads a ControlPath ${VAR} value from the injected environment. The
// core never inspects the process environment on its own.
func lookupEnv(env Environment, key string) (string, bool) {
	if env.LookupEnv != nil {
		return env.LookupEnv(key)
	}
	return "", false
}

// ComputeConnectionHash computes the 40-character lowercase hexadecimal SHA-1 hash
// matching OpenSSH ssh_connection_hash(%l%h%p%r%j).
func ComputeConnectionHash(localHost, host, portStr, user, jumpHost string) string {
	hasher := sha1.New()
	hasher.Write([]byte(localHost))
	hasher.Write([]byte(host))
	hasher.Write([]byte(portStr))
	hasher.Write([]byte(user))
	hasher.Write([]byte(jumpHost))
	return hex.EncodeToString(hasher.Sum(nil))
}

// MaxControlPathLength returns the maximum socket path length allowed by the OS sockaddr_un buffer.
// Linux / Windows AF_UNIX: 108 bytes.
// Darwin (macOS) / BSD: 104 bytes.
func MaxControlPathLength() int {
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd", "netbsd":
		return 104
	default:
		return 108
	}
}

// ValidateControlPath validates that the expanded socket path is non-empty, free of
// control characters, and fits within OS limits.
func ValidateControlPath(expandedPath string) error {
	if hasControlOrLineSepChar(expandedPath) {
		return fmt.Errorf("ControlPath %q contains invalid control character", expandedPath)
	}
	if strings.TrimSpace(expandedPath) == "" {
		return errors.New("ControlPath is empty")
	}
	if IsNoneValue(expandedPath) {
		return nil
	}
	maxLen := MaxControlPathLength()
	if len(expandedPath) >= maxLen {
		return fmt.Errorf("ControlPath too long ('%s' >= %d bytes)", expandedPath, maxLen)
	}
	return nil
}

// ValidateStreamLocalPathSyntax verifies raw StreamLocal socket path token syntax without environment dependencies.
// Rejects empty strings and strings containing null bytes or control characters.
func ValidateStreamLocalPathSyntax(rawPath string) error {
	if rawPath == "" {
		return errors.New("StreamLocal path cannot be empty")
	}
	if strings.ContainsRune(rawPath, 0) {
		return errors.New("StreamLocal path cannot contain null bytes")
	}
	if hasControlOrLineSepChar(rawPath) {
		return fmt.Errorf("StreamLocal path %q contains invalid control character", rawPath)
	}
	return validatePathTokenSyntax(rawPath, "StreamLocal path")
}

// ExpandStreamLocalPath expands tokens (%%, %h, %p, %r, %n, %u, %l, %L, %i, %d, %j, %C),
// environment variables (${VAR}), and optionally local tilde (~) in rawPath in a single pass.
func ExpandStreamLocalPath(rawPath string, env Environment, target TargetContext, expandLocalTilde bool) (string, error) {
	if rawPath == "" {
		return "", errors.New("StreamLocal path cannot be empty")
	}
	if strings.ContainsRune(rawPath, 0) {
		return "", errors.New("StreamLocal path cannot contain null bytes")
	}
	if hasControlOrLineSepChar(rawPath) {
		return "", fmt.Errorf("StreamLocal path %q contains invalid control character", rawPath)
	}
	expanded, err := expandPathTokensSinglePass(rawPath, env, target, pathExpandOptions{
		kind:        "StreamLocal path",
		expandTilde: expandLocalTilde,
	})
	if err != nil {
		return "", err
	}
	if strings.ContainsRune(expanded, 0) {
		return "", errors.New("StreamLocal path cannot contain null bytes")
	}
	if hasControlOrLineSepChar(expanded) {
		return "", fmt.Errorf("expanded StreamLocal path %q contains invalid control character", expanded)
	}
	return expanded, nil
}

// ParseControlPersist parses OpenSSH ControlPersist specifications:
// - "no" / "false" / "": disabled
// - "yes" / "true" / "0": enabled indefinitely (indefinite=true, timeout=0)
// - duration: time formats documented in sshd_config(5), e.g. "10m", "1h", "600s", "600", "1d", "1w", "1h30m"
func ParseControlPersist(val string) (enabled bool, indefinite bool, timeout time.Duration, err error) {
	setting, err := ParsePersistSetting(val)
	if err != nil {
		return false, false, 0, err
	}
	return setting.Enabled(), setting.Indefinite(), setting.Duration, nil
}

// parseOpenSSHDuration parses a sequence of integer+qualifier units into time.Duration
// according to sshd_config(5) TIME FORMATS with int64 overflow checks:
//
//	<none>  seconds
//	s | S   seconds
//	m | M   minutes
//	h | H   hours
//	d | D   days
//	w | W   weeks
//
// Example: "600" -> 600s, "10m" -> 600s, "1h30m" -> 5400s.
func parseOpenSSHDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty duration string")
	}

	const maxDuration = time.Duration(math.MaxInt64)
	addScaledDuration := func(total time.Duration, count int64, unit time.Duration) (time.Duration, error) {
		if count > int64(maxDuration/unit) {
			return 0, fmt.Errorf("duration overflows int64 in %q", s)
		}
		part := time.Duration(count) * unit
		if total > maxDuration-part {
			return 0, fmt.Errorf("duration overflows int64 in %q", s)
		}
		return total + part, nil
	}

	var total time.Duration
	remaining := s
	for len(remaining) > 0 {
		// Read numeric digits
		i := 0
		for i < len(remaining) && remaining[i] >= '0' && remaining[i] <= '9' {
			i++
		}
		if i == 0 {
			return 0, fmt.Errorf("invalid time format %q", s)
		}
		num, err := strconv.ParseInt(remaining[:i], 10, 64)
		if err != nil || num < 0 {
			return 0, fmt.Errorf("invalid number %q in %q", remaining[:i], s)
		}
		remaining = remaining[i:]

		// Read unit qualifier
		unit := time.Second
		if len(remaining) > 0 {
			unitChar := remaining[0]
			remaining = remaining[1:]
			unit, err = parseOpenSSHDurationUnit(unitChar, s)
			if err != nil {
				return 0, err
			}
		}
		total, err = addScaledDuration(total, num, unit)
		if err != nil {
			return 0, err
		}
	}

	if total <= 0 {
		return 0, fmt.Errorf("duration must be positive: %v", total)
	}
	return total, nil
}

func parseOpenSSHDurationUnit(unitChar byte, full string) (time.Duration, error) {
	switch unitChar {
	case 's', 'S':
		return time.Second, nil
	case 'm', 'M':
		return time.Minute, nil
	case 'h', 'H':
		return time.Hour, nil
	case 'd', 'D':
		return 24 * time.Hour, nil
	case 'w', 'W':
		return 7 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown time qualifier '%c' in %q", unitChar, full)
	}
}
