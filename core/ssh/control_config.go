package ssh

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
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

// ControlConfig specifies the connection multiplexing parameters for an SSH connection.
// Matches the contract defined in PROJECT.md and Schema V2.
type ControlConfig struct {
	Master  ControlMasterMode `json:"master,omitempty" yaml:"master,omitempty"`
	Path    string            `json:"path,omitempty" yaml:"path,omitempty"`
	Persist string            `json:"persist,omitempty" yaml:"persist,omitempty"`
	// ImplicitTier4 is true when multiplexing was resolved solely from ~/.ssh/config
	// (Tier 4) without any CLI flag or xops node/global configuration.
	ImplicitTier4 bool `json:"-" yaml:"-"`
	// AllowReuse is true when the CLI explicitly specified -S <path> without -M or
	// -o ControlMaster=..., allowing attachment to an existing master even when a
	// lower-priority config layer sets ControlMaster=yes or ControlMaster=ask.
	AllowReuse bool `json:"-" yaml:"-"`
}

// IsEnabled returns true if multiplexing is enabled (either master or reuse).
func (c *ControlConfig) IsEnabled() bool {
	if c == nil {
		return false
	}
	return c.Path != "" && c.Path != "none"
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
	return c.Master == other.Master && c.Path == other.Path && c.Persist == other.Persist
}

// ResolveControl merges a child (higher priority) multiplexing config with a
// parent (lower priority) config according to inheritance rules:
// - Master inherits from parent unless child explicitly sets it.
// - Path inherits from parent unless child explicitly sets it.
// - Persist inherits from parent unless child explicitly sets it.
// - If child sets Path="none", multiplexing is disabled for the child.
func ResolveControl(child, parent *ControlConfig) (*ControlConfig, error) {
	if child == nil && parent == nil {
		return nil, nil
	}
	if child == nil {
		return parent.Clone(), nil
	}
	if parent == nil {
		res := child.Clone()
		if res.Path == "none" {
			res.Master = ControlMasterNo
			res.Persist = ""
			res.AllowReuse = false
		}
		return res, nil
	}

	res := &ControlConfig{
		Master:     parent.Master,
		Path:       parent.Path,
		Persist:    parent.Persist,
		AllowReuse: parent.AllowReuse,
	}

	if child.Master != "" {
		res.Master = child.Master
		res.AllowReuse = false
	}
	if child.Path != "" {
		res.Path = child.Path
	}
	if child.Persist != "" {
		res.Persist = child.Persist
	}
	if child.AllowReuse && child.Master == "" {
		res.AllowReuse = true
	}

	// If child sets Path="none", multiplexing is disabled for the child.
	if child.Path == "none" {
		res.Master = ControlMasterNo
		res.Persist = ""
		res.AllowReuse = false
	}

	return res, nil
}

// EffectiveControl resolves a hierarchy of multiplexing configs from highest
// priority to lowest priority (e.g. session CLI overrides, node, global, openssh).
func EffectiveControl(layers ...*ControlConfig) (*ControlConfig, error) {
	var effective *ControlConfig
	for i := len(layers) - 1; i >= 0; i-- {
		var err error
		effective, err = ResolveControl(layers[i], effective)
		if err != nil {
			return nil, err
		}
	}
	return effective, nil
}

// ControlProvider provides multiplexing configuration for a node.
type ControlProvider interface {
	GetControlConfig(nodeID string) (*ControlConfig, error)
}

// TargetContext supplies destination, port, user, and routing context for ControlPath token expansion.
type TargetContext struct {
	Host         string         // Target host or IP address (%h)
	Port         int            // Target port (%p), defaults to 22 if <= 0
	User         string         // Target remote username (%r)
	OriginalHost string         // Original command-line host or alias (%n), defaults to Host if empty
	JumpHost     string         // ProxyJump host if any (%j), used in %C connection hash calculation
	KeyPath      string         // Effective private key path for this target, if any
	Control      *ControlConfig // Multiplexing control configuration
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
	host := strings.ToLower(strings.TrimSpace(t.Host))
	if host == "" {
		return ""
	}
	port := t.Port
	if port <= 0 {
		port = 22
	}
	user := strings.TrimSpace(t.User)
	jump := strings.ToLower(strings.TrimSpace(t.JumpHost))
	return fmt.Sprintf("host=%s;port=%d;user=%s;jump=%s", host, port, user, jump)
}

// MatchesMasterTarget reports whether the requested target is compatible with
// the master target identity advertised via the "target@xops" hello extension.
func (t TargetContext) MatchesMasterTarget(masterIdentity string) bool {
	if strings.TrimSpace(masterIdentity) == "" || strings.TrimSpace(t.Host) == "" {
		return true
	}
	var mHost, mUser, mJump string
	mPort := 22
	for _, part := range strings.Split(masterIdentity, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "host":
			mHost = strings.ToLower(strings.TrimSpace(kv[1]))
		case "port":
			if p, err := strconv.Atoi(strings.TrimSpace(kv[1])); err == nil && p > 0 {
				mPort = p
			}
		case "user":
			mUser = strings.TrimSpace(kv[1])
		case "jump":
			mJump = strings.ToLower(strings.TrimSpace(kv[1]))
		}
	}
	if mHost == "" {
		return true
	}
	tHost := strings.ToLower(strings.TrimSpace(t.Host))
	tPort := t.Port
	if tPort <= 0 {
		tPort = 22
	}
	tUser := strings.TrimSpace(t.User)
	tJump := strings.ToLower(strings.TrimSpace(t.JumpHost))

	if tHost != mHost || tPort != mPort || tJump != mJump {
		return false
	}
	if tUser != "" && mUser != "" && tUser != mUser {
		return false
	}
	return true
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
			host = kv[1]
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
	base := fmt.Sprintf("%s:%d", host, port)
	if user != "" {
		base = fmt.Sprintf("%s@%s", user, base)
	}
	if jump != "" {
		base = fmt.Sprintf("%s (via %s)", base, jump)
	}
	return base
}

var envVarRegex = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// ExpandControlPath expands tokens (%%, %h, %p, %r, %n, %u, %l, %L, %i, %d, %j, %C), tilde (~),
// and environment variables (${VAR}) in rawPath according to OpenSSH ssh_config(5) rules.
func ExpandControlPath(rawPath string, env Environment, target TargetContext) (string, error) {
	if rawPath == "" || rawPath == "none" {
		return rawPath, nil
	}

	// 1. Expand ${VAR} environment variables
	expanded, err := expandEnvironmentVariables(rawPath, env)
	if err != nil {
		return "", err
	}

	// 2. Expand leading tilde (~)
	expanded, err = expandTilde(expanded, env.HomeDir)
	if err != nil {
		return "", err
	}

	// 3. Expand percent tokens (%)
	return expandPercentTokens(expanded, env, target)
}

func expandEnvironmentVariables(raw string, env Environment) (string, error) {
	if !strings.Contains(raw, "${") {
		return raw, nil
	}

	var matchErr error
	result := envVarRegex.ReplaceAllStringFunc(raw, func(m string) string {
		if matchErr != nil {
			return m
		}
		varName := m[2 : len(m)-1]
		val, ok := lookupEnv(env, varName)
		if !ok || val == "" {
			matchErr = fmt.Errorf("env var ${%s} has no value", varName)
			return m
		}
		return val
	})
	if matchErr != nil {
		return "", fmt.Errorf("invalid environment variable expansion: %w", matchErr)
	}
	return result, nil
}

// lookupEnv reads a ControlPath ${VAR} value from the injected environment. The
// core never inspects the process environment on its own.
func lookupEnv(env Environment, key string) (string, bool) {
	if env.LookupEnv != nil {
		return env.LookupEnv(key)
	}
	return "", false
}

func expandTilde(path string, homeDir string) (string, error) {
	if path == "~" {
		if homeDir == "" {
			return "", errors.New("cannot expand '~': home directory is not set")
		}
		return homeDir, nil
	}
	if strings.HasPrefix(path, "~/") {
		if homeDir == "" {
			return "", errors.New("cannot expand '~': home directory is not set")
		}
		return filepath.Join(homeDir, path[2:]), nil
	}
	if runtime.GOOS == "windows" && strings.HasPrefix(path, `~\`) {
		if homeDir == "" {
			return "", errors.New("cannot expand '~': home directory is not set")
		}
		return filepath.Join(homeDir, path[2:]), nil
	}
	return path, nil
}

func expandPercentTokens(raw string, env Environment, target TargetContext) (string, error) {
	portStr := "22"
	if target.Port > 0 {
		portStr = strconv.Itoa(target.Port)
	}

	origHost := target.OriginalHost
	if origHost == "" {
		origHost = target.Host
	}

	remoteUser := target.User
	if remoteUser == "" {
		remoteUser = env.LocalUser
	}

	shortLocalHost := env.LocalHost
	if idx := strings.Index(shortLocalHost, "."); idx != -1 {
		shortLocalHost = shortLocalHost[:idx]
	}

	// Compute %C connection hash: SHA-1 over %l%h%p%r%j
	connHash := ComputeConnectionHash(env.LocalHost, target.Host, portStr, remoteUser, target.JumpHost)

	var sb strings.Builder
	sb.Grow(len(raw) + 32)

	for i := 0; i < len(raw); i++ {
		if raw[i] == '%' {
			if i+1 >= len(raw) {
				return "", errors.New("trailing '%' in ControlPath")
			}
			i++
			switch raw[i] {
			case '%':
				sb.WriteByte('%')
			case 'h':
				sb.WriteString(target.Host)
			case 'p':
				sb.WriteString(portStr)
			case 'r':
				sb.WriteString(remoteUser)
			case 'n':
				sb.WriteString(origHost)
			case 'u':
				sb.WriteString(env.LocalUser)
			case 'l':
				sb.WriteString(env.LocalHost)
			case 'L':
				sb.WriteString(shortLocalHost)
			case 'i':
				sb.WriteString(env.LocalUID)
			case 'd':
				sb.WriteString(env.HomeDir)
			case 'j':
				sb.WriteString(target.JumpHost)
			case 'C':
				sb.WriteString(connHash)
			default:
				return "", fmt.Errorf("unknown ControlPath token %%%c", raw[i])
			}
		} else {
			sb.WriteByte(raw[i])
		}
	}
	return sb.String(), nil
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

// ValidateControlPath validates that the expanded socket path is non-empty and fits within OS limits.
func ValidateControlPath(expandedPath string) error {
	if expandedPath == "" {
		return errors.New("ControlPath is empty")
	}
	if expandedPath == "none" {
		return nil
	}
	maxLen := MaxControlPathLength()
	if len(expandedPath) >= maxLen {
		return fmt.Errorf("ControlPath too long ('%s' >= %d bytes)", expandedPath, maxLen)
	}
	return nil
}

// ValidateStreamLocalPathSyntax verifies raw StreamLocal socket path token syntax without environment dependencies.
// Rejects empty strings and strings containing null bytes.
func ValidateStreamLocalPathSyntax(rawPath string) error {
	if rawPath == "" {
		return errors.New("StreamLocal path cannot be empty")
	}
	if strings.Contains(rawPath, "\x00") {
		return errors.New("StreamLocal path cannot contain null bytes")
	}
	return validatePathTokenSyntax(rawPath, "StreamLocal path")
}

// ExpandStreamLocalPath expands tokens (%%, %h, %p, %r, %n, %u, %l, %L, %i, %d, %j, %C),
// environment variables (${VAR}), and optionally local tilde (~) in rawPath for StreamLocal forwarding endpoints.
func ExpandStreamLocalPath(rawPath string, env Environment, target TargetContext, expandLocalTilde bool) (string, error) {
	if rawPath == "" {
		return "", errors.New("StreamLocal path cannot be empty")
	}
	if strings.Contains(rawPath, "\x00") {
		return "", errors.New("StreamLocal path cannot contain null bytes")
	}

	// 1. Expand ${VAR} environment variables
	expanded, err := expandEnvironmentVariables(rawPath, env)
	if err != nil {
		return "", err
	}

	// 2. Expand leading tilde (~) if enabled
	if expandLocalTilde {
		expanded, err = expandTilde(expanded, env.HomeDir)
		if err != nil {
			return "", err
		}
	}

	// 3. Expand percent tokens (%)
	return expandPercentTokens(expanded, env, target)
}

// ParseControlPersist parses OpenSSH ControlPersist specifications:
// - "no" / "false" / "": disabled
// - "yes" / "true" / "0": enabled indefinitely (indefinite=true, timeout=0)
// - duration: time formats documented in sshd_config(5), e.g. "10m", "1h", "600s", "600", "1d", "1w", "1h30m"
func ParseControlPersist(val string) (enabled bool, indefinite bool, timeout time.Duration, err error) {
	trimmed := strings.ToLower(strings.TrimSpace(val))
	switch trimmed {
	case "", "no", "false":
		return false, false, 0, nil
	case "yes", "true", "0":
		return true, true, 0, nil
	}

	d, err := parseOpenSSHDuration(trimmed)
	if err != nil {
		return false, false, 0, fmt.Errorf("bad ControlPersist argument %q: %w", val, err)
	}
	return true, false, d, nil
}

// parseOpenSSHDuration parses a sequence of integer+qualifier units according to sshd_config(5) TIME FORMATS:
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

	// Bare integer represents seconds
	if val, err := strconv.ParseInt(s, 10, 64); err == nil {
		if val <= 0 {
			return 0, fmt.Errorf("duration must be positive: %d", val)
		}
		return time.Duration(val) * time.Second, nil
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
		if len(remaining) == 0 {
			total += time.Duration(num) * time.Second
			break
		}

		unitChar := remaining[0]
		remaining = remaining[1:]

		var unit time.Duration
		switch unitChar {
		case 's', 'S':
			unit = time.Second
		case 'm', 'M':
			unit = time.Minute
		case 'h', 'H':
			unit = time.Hour
		case 'd', 'D':
			unit = 24 * time.Hour
		case 'w', 'W':
			unit = 7 * 24 * time.Hour
		default:
			return 0, fmt.Errorf("unknown time qualifier '%c' in %q", unitChar, s)
		}
		total += time.Duration(num) * unit
	}

	if total <= 0 {
		return 0, fmt.Errorf("duration must be positive: %v", total)
	}
	return total, nil
}
