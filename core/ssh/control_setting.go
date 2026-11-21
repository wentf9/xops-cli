package ssh

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ControlSetting is an immutable, validated effective multiplexing setting
// combining ControlMaster, ControlPath, and ControlPersist.
//
// Every non-zero ControlSetting is guaranteed at construction time to satisfy
// all intra-field and cross-field invariants enforced by
// Options.validateControlLayerInvariants and Options.ValidateEffective.
// Construct exclusively via UnsetControlSetting, NewControlSetting,
// ParseControlSetting, ParseControlSettingString, ControlSettingFromConfig, or
// ControlSettingFromOptions.
type ControlSetting struct {
	master  ControlMasterMode
	path    ControlPathSetting
	persist PersistSetting
}

// UnsetControlSetting returns the zero-value unconfigured ControlSetting.
func UnsetControlSetting() ControlSetting {
	return ControlSetting{}
}

// NewControlSetting validates master, path, and persist individually and across
// fields by delegating directly to the canonical Options.ValidateEffective and
// validateProjectedControl engines (which enforce validateControlLayerInvariants
// and ValidateEffective without forking validation rules).
func NewControlSetting(master ControlMasterMode, path ControlPathSetting, persist PersistSetting) (ControlSetting, error) {
	normMaster, err := normalizeControlSettingMaster(master)
	if err != nil {
		return ControlSetting{}, err
	}
	normPath, err := normalizeControlSettingPath(path)
	if err != nil {
		return ControlSetting{}, err
	}
	normPersist, err := normalizeControlSettingPersist(persist)
	if err != nil {
		return ControlSetting{}, err
	}

	opts := &Options{}
	if normMaster != "" {
		opts.setRaw(OptionControlMaster, string(normMaster))
	}
	switch normPath.Kind {
	case ControlPathDisabled:
		opts.setRaw(OptionControlPath, "none")
	case ControlPathTemplate:
		opts.setRaw(OptionControlPath, normPath.Raw)
	case ControlPathLiteral:
		if err := opts.SetLiteralControlPath(normPath.Raw); err != nil {
			return ControlSetting{}, err
		}
	}
	if normPersist.Explicit() {
		opts.setRaw(OptionControlPersist, normPersist.Raw)
	}

	// Reuse Options.ValidateEffective (which invokes Options.Validate ->
	// validateControlLayerInvariants and validateEffectiveControlSetting) plus
	// validateProjectedControl for literal path checks.
	if err := opts.ValidateEffective(); err != nil {
		return ControlSetting{}, err
	}
	effectiveMaster := normMaster
	if effectiveMaster == "" {
		effectiveMaster = ControlMasterNo
	}
	if err := validateProjectedControl(effectiveMaster, normPath, normPersist); err != nil {
		return ControlSetting{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}

	return ControlSetting{
		master:  normMaster,
		path:    normPath,
		persist: normPersist,
	}, nil
}

// ParseControlSetting parses raw ControlMaster, ControlPath, and ControlPersist
// strings and constructs a validated ControlSetting.
func ParseControlSetting(masterRaw, pathRaw string, literalPath bool, persistRaw string) (ControlSetting, error) {
	var master ControlMasterMode
	if masterRaw != "" {
		if hasControlOrLineSepChar(masterRaw) {
			return ControlSetting{}, fmt.Errorf("%w: unsupported ControlMaster option %q: contains invalid control character", ErrSSHOptionsValidation, masterRaw)
		}
		trimmed := strings.TrimSpace(masterRaw)
		if trimmed == "" {
			return ControlSetting{}, fmt.Errorf("%w: unsupported ControlMaster option %q", ErrSSHOptionsValidation, masterRaw)
		}
		parsed, err := ParseControlMasterMode(trimmed)
		if err != nil {
			return ControlSetting{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		master = parsed
	}
	pathSetting, err := ParseControlPathSetting(pathRaw, literalPath)
	if err != nil {
		return ControlSetting{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	persistSetting, err := ParsePersistSetting(persistRaw)
	if err != nil {
		return ControlSetting{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	return NewControlSetting(master, pathSetting, persistSetting)
}

// ControlSettingFromConfig validates and converts a *ControlConfig into a
// ControlSetting. A nil or completely empty ControlConfig returns UnsetControlSetting.
func ControlSettingFromConfig(ctrl *ControlConfig) (ControlSetting, error) {
	if ctrl == nil {
		return UnsetControlSetting(), nil
	}
	return ParseControlSetting(string(ctrl.Master), ctrl.Path, ctrl.LiteralPath, ctrl.Persist)
}

// ControlSettingFromOptions extracts and validates the effective ControlSetting
// from opts via opts.ValidatedControlConfig and NewControlSetting.
func ControlSettingFromOptions(opts *Options) (ControlSetting, error) {
	if opts.IsEmpty() {
		return UnsetControlSetting(), nil
	}
	mux := opts.FilterByClasses(OptionClassMux)
	if mux.IsEmpty() {
		return UnsetControlSetting(), nil
	}
	if _, err := mux.ValidatedControlConfig(); err != nil {
		return ControlSetting{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	return ParseControlSetting(string(mux.ControlMaster()), mux.ControlPath(), mux.LiteralControlPath, mux.ControlPersist())
}

// ParseControlSettingString parses the canonical newline-delimited string
// produced by ControlSetting.String() back into a validated ControlSetting.
func ParseControlSettingString(raw string) (ControlSetting, error) {
	if raw == "" {
		return UnsetControlSetting(), nil
	}
	var (
		masterRaw   string
		pathRaw     string
		literalPath bool
		persistRaw  string
		seenMaster  bool
		seenPath    bool
		seenPersist bool
	)
	for line := range strings.SplitSeq(raw, "\n") {
		key, val, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return ControlSetting{}, fmt.Errorf("%w: malformed ControlSetting entry %q", ErrSSHOptionsValidation, line)
		}
		switch key {
		case "ControlMaster":
			if seenMaster || val == "" {
				return ControlSetting{}, fmt.Errorf("%w: duplicate or empty ControlMaster entry", ErrSSHOptionsValidation)
			}
			seenMaster = true
			masterRaw = val
		case "ControlPath":
			if seenPath || val == "" {
				return ControlSetting{}, fmt.Errorf("%w: duplicate or empty ControlPath entry", ErrSSHOptionsValidation)
			}
			seenPath = true
			pathRaw = val
		case "ControlPathLiteral":
			if seenPath || val == "" || IsNoneValue(val) {
				return ControlSetting{}, fmt.Errorf("%w: duplicate, empty, or none ControlPathLiteral entry", ErrSSHOptionsValidation)
			}
			seenPath = true
			literalPath = true
			pathRaw = val
		case "ControlPersist":
			if seenPersist || val == "" {
				return ControlSetting{}, fmt.Errorf("%w: duplicate or empty ControlPersist entry", ErrSSHOptionsValidation)
			}
			seenPersist = true
			persistRaw = val
		default:
			return ControlSetting{}, fmt.Errorf("%w: unknown ControlSetting key %q", ErrSSHOptionsValidation, key)
		}
	}
	return ParseControlSetting(masterRaw, pathRaw, literalPath, persistRaw)
}

func normalizeControlSettingMaster(master ControlMasterMode) (ControlMasterMode, error) {
	if master == "" {
		return "", nil
	}
	raw := string(master)
	if hasControlOrLineSepChar(raw) {
		return "", fmt.Errorf("%w: unsupported ControlMaster option %q: contains invalid control character", ErrSSHOptionsValidation, raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("%w: unsupported ControlMaster option %q", ErrSSHOptionsValidation, raw)
	}
	parsed, err := ParseControlMasterMode(trimmed)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	return parsed, nil
}

func normalizeControlSettingPath(path ControlPathSetting) (ControlPathSetting, error) {
	switch path.Kind {
	case ControlPathUnset:
		if path.Raw != "" {
			return ControlPathSetting{}, fmt.Errorf("%w: unset ControlPath must have empty raw value", ErrSSHOptionsValidation)
		}
		return ControlPathSetting{Kind: ControlPathUnset}, nil
	case ControlPathDisabled:
		if path.Raw != "" && !IsNoneValue(path.Raw) {
			return ControlPathSetting{}, fmt.Errorf("%w: disabled ControlPath has non-none value %q", ErrSSHOptionsValidation, path.Raw)
		}
		return ControlPathSetting{Kind: ControlPathDisabled, Raw: "none"}, nil
	case ControlPathTemplate:
		if path.Raw == "" {
			return ControlPathSetting{}, fmt.Errorf("%w: invalid ControlPath: value cannot be empty", ErrSSHOptionsValidation)
		}
		parsed, err := ParseControlPathSetting(path.Raw, false)
		if err != nil {
			return ControlPathSetting{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		if parsed.Kind != ControlPathTemplate {
			return ControlPathSetting{}, fmt.Errorf("%w: ControlPath %q is not a template path", ErrSSHOptionsValidation, path.Raw)
		}
		return parsed, nil
	case ControlPathLiteral:
		if path.Raw == "" {
			return ControlPathSetting{}, fmt.Errorf("%w: invalid ControlPath: value cannot be empty", ErrSSHOptionsValidation)
		}
		parsed, err := ParseControlPathSetting(path.Raw, true)
		if err != nil {
			return ControlPathSetting{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		if parsed.Kind != ControlPathLiteral {
			return ControlPathSetting{}, fmt.Errorf("%w: ControlPath %q is not a literal path", ErrSSHOptionsValidation, path.Raw)
		}
		return parsed, nil
	default:
		return ControlPathSetting{}, fmt.Errorf("%w: unknown ControlPathKind %d", ErrSSHOptionsValidation, path.Kind)
	}
}

func normalizeControlSettingPersist(persist PersistSetting) (PersistSetting, error) {
	switch persist.Kind {
	case PersistUnset:
		if persist.Raw != "" || persist.Duration != 0 {
			return PersistSetting{}, fmt.Errorf("%w: unset ControlPersist must have empty raw and zero duration", ErrSSHOptionsValidation)
		}
		return PersistSetting{Kind: PersistUnset}, nil
	case PersistNo:
		if persist.Duration != 0 {
			return PersistSetting{}, fmt.Errorf("%w: disabled ControlPersist cannot have non-zero duration", ErrSSHOptionsValidation)
		}
		raw := persist.Raw
		if raw == "" {
			raw = "no"
		}
		parsed, err := ParsePersistSetting(raw)
		if err != nil || parsed.Kind != PersistNo {
			return PersistSetting{}, fmt.Errorf("%w: invalid disabled ControlPersist %q", ErrSSHOptionsValidation, raw)
		}
		return parsed, nil
	case PersistIndefinite:
		if persist.Duration != 0 {
			return PersistSetting{}, fmt.Errorf("%w: indefinite ControlPersist cannot have non-zero duration", ErrSSHOptionsValidation)
		}
		raw := persist.Raw
		if raw == "" {
			raw = "yes"
		}
		parsed, err := ParsePersistSetting(raw)
		if err != nil || parsed.Kind != PersistIndefinite {
			return PersistSetting{}, fmt.Errorf("%w: invalid indefinite ControlPersist %q", ErrSSHOptionsValidation, raw)
		}
		return parsed, nil
	case PersistDuration:
		return normalizeControlSettingPersistDuration(persist)
	default:
		return PersistSetting{}, fmt.Errorf("%w: unknown PersistKind %d", ErrSSHOptionsValidation, persist.Kind)
	}
}

func normalizeControlSettingPersistDuration(persist PersistSetting) (PersistSetting, error) {
	raw := persist.Raw
	if raw == "" {
		if persist.Duration <= 0 || persist.Duration%time.Second != 0 {
			return PersistSetting{}, fmt.Errorf("%w: ControlPersist duration %v must be a positive whole number of seconds", ErrSSHOptionsValidation, persist.Duration)
		}
		raw = strconv.FormatInt(int64(persist.Duration/time.Second), 10) + "s"
	}
	parsed, err := ParsePersistSetting(raw)
	if err != nil || parsed.Kind != PersistDuration {
		return PersistSetting{}, fmt.Errorf("%w: invalid ControlPersist duration %q", ErrSSHOptionsValidation, raw)
	}
	if persist.Duration != 0 && persist.Duration != parsed.Duration {
		return PersistSetting{}, fmt.Errorf("%w: ControlPersist duration %v disagrees with raw %q (%v)", ErrSSHOptionsValidation, persist.Duration, raw, parsed.Duration)
	}
	return parsed, nil
}

// Master returns the explicitly configured ControlMasterMode (or "" if unset).
func (c ControlSetting) Master() ControlMasterMode { return c.master }

// EffectiveMaster returns Master(), or ControlMasterNo when Master() is unset.
func (c ControlSetting) EffectiveMaster() ControlMasterMode {
	if c.master == "" {
		return ControlMasterNo
	}
	return c.master
}

// Path returns the typed ControlPathSetting.
func (c ControlSetting) Path() ControlPathSetting { return c.path }

// Persist returns the typed PersistSetting.
func (c ControlSetting) Persist() PersistSetting { return c.persist }

// IsUnset reports whether no multiplexing fields are configured.
func (c ControlSetting) IsUnset() bool {
	return c.master == "" && c.path.Unset() && !c.persist.Explicit()
}

// IsDisabled reports whether ControlPath is explicitly set to "none".
func (c ControlSetting) IsDisabled() bool { return c.path.Disabled() }

// IsEnabled reports whether ControlPath specifies an active socket path.
func (c ControlSetting) IsEnabled() bool { return c.path.Enabled() }

// ToControlConfig converts c to a *ControlConfig, or nil when c is unset.
func (c ControlSetting) ToControlConfig() *ControlConfig {
	if c.IsUnset() {
		return nil
	}
	return &ControlConfig{
		Master:      c.EffectiveMaster(),
		Path:        c.path.Raw,
		LiteralPath: c.path.Kind == ControlPathLiteral,
		Persist:     c.persist.Raw,
	}
}

// Equal reports whether c and other have identical master, path, and persist values.
func (c ControlSetting) Equal(other ControlSetting) bool {
	return c.master == other.master && c.path == other.path && c.persist == other.persist
}

// String formats c losslessly as canonical newline-delimited directives suitable
// for round-tripping through ParseControlSettingString.
func (c ControlSetting) String() string {
	if c.IsUnset() {
		return ""
	}
	var parts []string
	if c.master != "" {
		parts = append(parts, "ControlMaster="+string(c.master))
	}
	switch c.path.Kind {
	case ControlPathDisabled:
		parts = append(parts, "ControlPath=none")
	case ControlPathTemplate:
		parts = append(parts, "ControlPath="+c.path.Raw)
	case ControlPathLiteral:
		parts = append(parts, "ControlPathLiteral="+c.path.Raw)
	}
	if c.persist.Explicit() {
		parts = append(parts, "ControlPersist="+c.persist.Raw)
	}
	return strings.Join(parts, "\n")
}
