package ssh

import (
	"fmt"
	"slices"
	"strings"
)

// ProxyKind classifies the active observable state of a ProxySetting into four
// mutually exclusive variants.
type ProxyKind uint8

const (
	// ProxyUnset indicates neither ProxyJump nor ProxyCommand was configured.
	ProxyUnset ProxyKind = iota
	// ProxyDisabled indicates proxying is disabled ("ProxyCommand none" or "ProxyJump none").
	ProxyDisabled
	// ProxyJump indicates connection routing through one or more SSH jump hops.
	ProxyJump
	// ProxyCommand indicates connection routing through a local proxy command.
	ProxyCommand
)

// String returns the canonical state name ("unset", "disabled", "jump", or "command").
func (k ProxyKind) String() string {
	switch k {
	case ProxyUnset:
		return "unset"
	case ProxyDisabled:
		return "disabled"
	case ProxyJump:
		return "jump"
	case ProxyCommand:
		return "command"
	default:
		return fmt.Sprintf("invalid(%d)", uint8(k))
	}
}

type proxyCommandSlot uint8

const (
	proxyCmdUnset proxyCommandSlot = iota
	proxyCmdDisabled
	proxyCmdActive
)

// ProxySetting is an immutable, mutually exclusive representation of OpenSSH
// ProxyJump / ProxyCommand routing configuration.
//
// Active routing is strictly mutually exclusive by Kind():
//   - ProxyJump exposes JumpTargets() and returns ("", false) from Command().
//   - ProxyCommand exposes Command() and returns (nil, false) from JumpTargets().
//
// Merging follows exact OpenSSH first-wins semantics while preserving monoid
// associativity across layers:
//   - Unset (zero value) is the two-sided identity.
//   - ProxyCommand=none (DisabledProxySetting) disables BOTH ProxyCommand and
//     lower ProxyJump directives (absorbs all lower layers).
//   - ProxyJump=none (DisabledProxyJumpSetting / ParseProxyJump("none"))
//     disables ONLY lower ProxyJump directives and exposes any lower
//     ProxyCommand or ProxyCommand=none.
//   - An active ProxyJump retains an unexported shadowed command fallback
//     (unset, disabled, or command) so merging a higher ProxyJump=none over
//     (ProxyJump ⊕ ProxyCommand) reveals the lower ProxyCommand regardless of
//     parenthesization.
//
// Construct exclusively via UnsetProxySetting, DisabledProxySetting,
// DisabledProxyJumpSetting, NewProxyJump, ParseProxyJump, NewProxyCommand,
// ParseProxyCommand, or ParseProxySetting.
type ProxySetting struct {
	kind     ProxyKind
	jump     []string
	cmdSlot  proxyCommandSlot
	cmdValue string
}

// UnsetProxySetting returns the zero-value identity ProxySetting.
func UnsetProxySetting() ProxySetting {
	return ProxySetting{}
}

// DisabledProxySetting returns the full-disable ("ProxyCommand none") state,
// which disables both ProxyCommand and all lower-priority ProxyJump directives.
func DisabledProxySetting() ProxySetting {
	return ProxySetting{kind: ProxyDisabled, cmdSlot: proxyCmdDisabled}
}

// DisabledProxyJumpSetting returns the jump-only disable ("ProxyJump none")
// state, which cancels lower-priority ProxyJump directives while still allowing
// a lower-priority ProxyCommand (or ProxyCommand=none) to take effect.
func DisabledProxyJumpSetting() ProxySetting {
	return ProxySetting{kind: ProxyDisabled, cmdSlot: proxyCmdUnset}
}

// NewProxyJump constructs an active ProxyJump setting from one or more hop targets.
// Each target must be non-empty after trimming, free of control characters and
// commas, and not the reserved "none" sentinel.
func NewProxyJump(targets ...string) (ProxySetting, error) {
	if len(targets) == 0 {
		return ProxySetting{}, fmt.Errorf("%w: ProxyJump requires at least one target", ErrSSHOptionsValidation)
	}
	cleaned := make([]string, 0, len(targets))
	for _, raw := range targets {
		if hasControlOrLineSepChar(raw) {
			return ProxySetting{}, fmt.Errorf("%w: invalid ProxyJump target %q: contains control character", ErrSSHOptionsValidation, raw)
		}
		tok := strings.TrimSpace(raw)
		if tok == "" {
			return ProxySetting{}, fmt.Errorf("%w: ProxyJump target cannot be empty", ErrSSHOptionsValidation)
		}
		if strings.ContainsRune(tok, ',') {
			return ProxySetting{}, fmt.Errorf("%w: ProxyJump target %q cannot contain ','", ErrSSHOptionsValidation, raw)
		}
		if IsNoneValue(tok) {
			return ProxySetting{}, fmt.Errorf("%w: ProxyJump target cannot be 'none'; use DisabledProxyJumpSetting or ParseProxyJump", ErrSSHOptionsValidation)
		}
		cleaned = append(cleaned, tok)
	}
	return ProxySetting{kind: ProxyJump, jump: cleaned}, nil
}

// ParseProxyJump parses an OpenSSH ProxyJump directive value ("none" /
// "none,none" -> DisabledProxyJumpSetting, or a comma-separated list of
// non-empty jump targets). Empty hop tokens (e.g. ",", "a,,b", "none,") and
// mixed "none" + hop chains are rejected with ErrSSHOptionsValidation.
func ParseProxyJump(raw string) (ProxySetting, error) {
	if hasControlOrLineSepChar(raw) {
		return ProxySetting{}, fmt.Errorf("%w: invalid ProxyJump %q: contains control character", ErrSSHOptionsValidation, raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ProxySetting{}, fmt.Errorf("%w: invalid ProxyJump: value cannot be empty", ErrSSHOptionsValidation)
	}
	parts := strings.Split(trimmed, ",")
	allNone := true
	for _, part := range parts {
		tok := strings.TrimSpace(part)
		if tok == "" {
			return ProxySetting{}, fmt.Errorf("%w: invalid ProxyJump %q: empty target", ErrSSHOptionsValidation, raw)
		}
		if !IsNoneValue(tok) {
			allNone = false
		}
	}
	if allNone {
		return DisabledProxyJumpSetting(), nil
	}
	return NewProxyJump(parts...)
}

// NewProxyCommand constructs an active ProxyCommand setting using the canonical
// local-exec command validator. "none" is rejected (use DisabledProxySetting or
// ParseProxyCommand).
func NewProxyCommand(cmd string) (ProxySetting, error) {
	norm, err := validateLocalExecCommandOption("ProxyCommand", cmd)
	if err != nil {
		return ProxySetting{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	if IsNoneValue(norm) {
		return ProxySetting{}, fmt.Errorf("%w: ProxyCommand cannot be 'none'; use DisabledProxySetting or ParseProxyCommand", ErrSSHOptionsValidation)
	}
	return ProxySetting{kind: ProxyCommand, cmdSlot: proxyCmdActive, cmdValue: norm}, nil
}

// ParseProxyCommand parses an OpenSSH ProxyCommand directive value ("none" ->
// DisabledProxySetting, or a non-empty command line).
func ParseProxyCommand(raw string) (ProxySetting, error) {
	norm, err := validateLocalExecCommandOption("ProxyCommand", raw)
	if err != nil {
		return ProxySetting{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	if IsNoneValue(norm) {
		return DisabledProxySetting(), nil
	}
	return ProxySetting{kind: ProxyCommand, cmdSlot: proxyCmdActive, cmdValue: norm}, nil
}

// ParseProxySetting parses the canonical string produced by ProxySetting.String()
// (single directive or newline-delimited directives folded in highest-to-lowest
// priority order):
//   - ""                 -> Unset
//   - "none"             -> DisabledProxySetting (ProxyCommand=none)
//   - "ProxyJump=<list>" -> Jump or DisabledProxyJumpSetting
//   - "ProxyCommand=<c>" -> Command or DisabledProxySetting
func ParseProxySetting(raw string) (ProxySetting, error) {
	if raw == "" {
		return UnsetProxySetting(), nil
	}
	acc := UnsetProxySetting()
	for line := range strings.SplitSeq(raw, "\n") {
		step, err := parseProxySettingLine(line)
		if err != nil {
			return ProxySetting{}, err
		}
		acc = acc.Merge(step)
	}
	return acc, nil
}

func parseProxySettingLine(line string) (ProxySetting, error) {
	if hasControlOrLineSepChar(line) {
		return ProxySetting{}, fmt.Errorf("%w: invalid ProxySetting %q: contains control character", ErrSSHOptionsValidation, line)
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ProxySetting{}, fmt.Errorf("%w: invalid ProxySetting: empty directive", ErrSSHOptionsValidation)
	}
	if IsNoneValue(trimmed) {
		return DisabledProxySetting(), nil
	}
	key, val, ok := strings.Cut(trimmed, "=")
	if !ok {
		return ProxySetting{}, fmt.Errorf("%w: invalid ProxySetting %q: expected none, ProxyJump=<targets>, or ProxyCommand=<cmd>", ErrSSHOptionsValidation, line)
	}
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "proxyjump", "proxy_jump":
		return ParseProxyJump(val)
	case "proxycommand", "proxy_command":
		return ParseProxyCommand(val)
	default:
		return ProxySetting{}, fmt.Errorf("%w: unsupported ProxySetting directive %q", ErrSSHOptionsValidation, key)
	}
}

// Kind returns the mutually exclusive observable ProxyKind of p.
func (p ProxySetting) Kind() ProxyKind { return p.kind }

// IsUnset reports whether no proxy setting is configured.
func (p ProxySetting) IsUnset() bool { return p.kind == ProxyUnset }

// IsDisabled reports whether proxying is currently disabled (either full
// ProxyCommand=none or jump-only ProxyJump=none with no exposed ProxyCommand).
func (p ProxySetting) IsDisabled() bool { return p.kind == ProxyDisabled }

// IsJumpDisabledOnly reports whether p is the jump-only disable state
// ("ProxyJump none"), which suppresses lower ProxyJump directives without
// suppressing lower ProxyCommand directives.
func (p ProxySetting) IsJumpDisabledOnly() bool {
	return p.kind == ProxyDisabled && p.cmdSlot == proxyCmdUnset
}

// IsActive reports whether p configures an active ProxyJump chain or ProxyCommand.
func (p ProxySetting) IsActive() bool {
	return p.kind == ProxyJump || p.kind == ProxyCommand
}

// JumpTargets returns a defensive copy of the jump targets and true when
// p.Kind() == ProxyJump; otherwise (nil, false).
func (p ProxySetting) JumpTargets() ([]string, bool) {
	if p.kind != ProxyJump || len(p.jump) == 0 {
		return nil, false
	}
	return slices.Clone(p.jump), true
}

// Command returns the active proxy command string and true when
// p.Kind() == ProxyCommand; otherwise ("", false). When p.Kind() == ProxyJump,
// any shadowed lower ProxyCommand is never exposed here.
func (p ProxySetting) Command() (string, bool) {
	if p.kind != ProxyCommand || p.cmdSlot != proxyCmdActive || p.cmdValue == "" {
		return "", false
	}
	return p.cmdValue, true
}

func (p ProxySetting) clone() ProxySetting {
	switch p.kind {
	case ProxyJump:
		return ProxySetting{
			kind:     ProxyJump,
			jump:     slices.Clone(p.jump),
			cmdSlot:  p.cmdSlot,
			cmdValue: p.cmdValue,
		}
	case ProxyCommand:
		return ProxySetting{
			kind:     ProxyCommand,
			cmdSlot:  proxyCmdActive,
			cmdValue: p.cmdValue,
		}
	case ProxyDisabled:
		return ProxySetting{
			kind:    ProxyDisabled,
			cmdSlot: p.cmdSlot,
		}
	default:
		return UnsetProxySetting()
	}
}

// Merge combines higher-priority p over lower-priority lower according to exact
// OpenSSH ProxyJump/ProxyCommand precedence:
//   - Unset is the two-sided identity.
//   - ProxyCommand (active or "none") absorbs all lower proxy directives.
//   - ProxyJump=none cancels lower ProxyJump and reveals lower ProxyCommand (or
//     ProxyCommand=none), remaining ProxyJump=none if lower has no command slot.
//   - Active ProxyJump keeps its jump targets and inherits lower's command slot
//     as a shadowed fallback if its own command slot is still unset.
func (p ProxySetting) Merge(lower ProxySetting) ProxySetting {
	switch p.kind {
	case ProxyUnset:
		return lower.clone()
	case ProxyCommand:
		return p.clone()
	case ProxyDisabled:
		if p.cmdSlot == proxyCmdDisabled {
			return DisabledProxySetting()
		}
		switch lower.cmdSlot {
		case proxyCmdDisabled:
			return DisabledProxySetting()
		case proxyCmdActive:
			return ProxySetting{kind: ProxyCommand, cmdSlot: proxyCmdActive, cmdValue: lower.cmdValue}
		default:
			return DisabledProxyJumpSetting()
		}
	case ProxyJump:
		out := p.clone()
		if out.cmdSlot == proxyCmdUnset && lower.cmdSlot != proxyCmdUnset {
			out.cmdSlot = lower.cmdSlot
			out.cmdValue = lower.cmdValue
		}
		return out
	default:
		return lower.clone()
	}
}

// MergeProxySetting merges higher over lower using OpenSSH ProxyJump/ProxyCommand semantics.
func MergeProxySetting(higher, lower ProxySetting) ProxySetting {
	return higher.Merge(lower)
}

// MergeProxySettings folds settings from highest priority to lowest priority.
func MergeProxySettings(layers ...ProxySetting) ProxySetting {
	acc := UnsetProxySetting()
	for _, layer := range layers {
		acc = acc.Merge(layer)
	}
	return acc
}

// Equal reports whether p and other represent the exact same monoid element
// (including shadowed command fallback state on ProxyJump and jump-only vs full
// disable distinction on ProxyDisabled).
func (p ProxySetting) Equal(other ProxySetting) bool {
	return p.kind == other.kind &&
		p.cmdSlot == other.cmdSlot &&
		p.cmdValue == other.cmdValue &&
		slices.Equal(p.jump, other.jump)
}

// String formats p losslessly for round-tripping through ParseProxySetting:
//   - Unset:                          ""
//   - ProxyJump=none (jump-only):     "ProxyJump=none"
//   - ProxyCommand=none (full):       "ProxyCommand=none"
//   - ProxyCommand=<cmd>:             "ProxyCommand=<cmd>"
//   - ProxyJump=<list>:               "ProxyJump=<list>"
//   - ProxyJump w/ shadowed none:     "ProxyJump=<list>\nProxyCommand=none"
//   - ProxyJump w/ shadowed command:  "ProxyJump=<list>\nProxyCommand=<cmd>"
func (p ProxySetting) String() string {
	switch p.kind {
	case ProxyUnset:
		return ""
	case ProxyDisabled:
		if p.cmdSlot == proxyCmdDisabled {
			return "ProxyCommand=none"
		}
		return "ProxyJump=none"
	case ProxyCommand:
		return "ProxyCommand=" + p.cmdValue
	case ProxyJump:
		base := "ProxyJump=" + strings.Join(p.jump, ",")
		switch p.cmdSlot {
		case proxyCmdDisabled:
			return base + "\nProxyCommand=none"
		case proxyCmdActive:
			return base + "\nProxyCommand=" + p.cmdValue
		default:
			return base
		}
	default:
		return ""
	}
}
