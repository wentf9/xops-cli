package ssh

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// OptionSource identifies the syntax surface from which a raw OpenSSH option
// directive originated. All surfaces share the single ParseOption entry point.
type OptionSource uint8

const (
	// OptionSourceCLI parses strict OpenSSH CLI "-o Key=Value" arguments.
	OptionSourceCLI OptionSource = iota
	// OptionSourceOpenSSHConfig parses ~/.ssh/config directives (strict syntax
	// validation, filtering syntactically valid OpenSSH-only algorithm tokens
	// against Go's supported algorithm registry).
	OptionSourceOpenSSHConfig
	// OptionSourceYAML parses xops YAML ssh_options entries.
	OptionSourceYAML
	// OptionSourceJSON parses xops JSON ssh_options entries.
	OptionSourceJSON
)

// ParsedOption is the typed result returned by ParseOption.
type ParsedOption struct {
	CanonicalKey   string
	OpenSSHName    string
	Normalized     string
	IsTargetOption bool
	// IsNoOp is true when an OpenSSH config modifier directive (e.g. "+algo" or
	// "^algo") was syntactically valid but contained no locally supported
	// algorithms, making it an explicit no-op against defaults.
	IsNoOp bool

	// Typed values populated for domain-typed options:
	PathList       PathList
	AlgoPolicy     AlgoPolicy
	ProxySetting   ProxySetting
	ControlMaster  ControlMasterMode
	ControlPath    ControlPathSetting
	ControlPersist PersistSetting
	Port           uint16
}

// ParseOption is the single canonical option parser shared by CLI (-o),
// ~/.ssh/config, YAML, and JSON option ingestion paths.
//
// It validates syntax strictly for every source (rejecting empty values,
// control characters, bare algorithm modifiers "-", "+", "^", and invalid
// algorithm tokens) and produces typed values for IdentityFile/CertificateFile
// (PathList), Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms (AlgoPolicy),
// ControlMaster/ControlPath/ControlPersist, and ProxyJump/ProxyCommand
// (ProxySetting).
func ParseOption(key, raw string, source OptionSource) (ParsedOption, error) {
	if strings.TrimSpace(key) == "" {
		return ParsedOption{}, fmt.Errorf("%w: empty ssh option key", ErrSSHOptionsValidation)
	}
	canonical := CanonicalOptionKey(key)
	if canonical == "" {
		if source == OptionSourceCLI {
			return ParsedOption{}, fmt.Errorf("%w: unsupported -o option %q", ErrSSHOptionsValidation, key)
		}
		return ParsedOption{}, fmt.Errorf("%w: unknown ssh option %q", ErrSSHOptionsValidation, key)
	}

	if parsed, handled, err := parseTargetOption(canonical, raw); handled {
		return parsed, err
	}

	spec, ok := LookupOptionSpec(canonical)
	if !ok {
		return ParsedOption{}, fmt.Errorf("%w: unknown ssh option %q", ErrSSHOptionsValidation, key)
	}
	if strings.TrimSpace(raw) == "" {
		return ParsedOption{}, fmt.Errorf("%w: invalid %s: value cannot be empty", ErrSSHOptionsValidation, spec.OpenSSHName)
	}
	return parseRegisteredOption(spec, raw, source)
}

func parseTargetOption(canonical, raw string) (ParsedOption, bool, error) {
	switch canonical {
	case OptionPort:
		parsed, err := parseTargetPortOption(raw)
		return parsed, true, err
	case OptionUser:
		parsed, err := parseTargetUserOption(raw)
		return parsed, true, err
	case OptionHostName:
		parsed, err := parseTargetHostNameOption(raw)
		return parsed, true, err
	case OptionProxyJump:
		parsed, err := parseTargetProxyJumpOption(raw)
		return parsed, true, err
	default:
		return ParsedOption{}, false, nil
	}
}

func parseRegisteredOption(spec OptionSpec, raw string, source OptionSource) (ParsedOption, error) {
	switch spec.CanonicalKey {
	case OptionControlMaster:
		return parseControlMasterOption(spec, raw)
	case OptionControlPath:
		return parseControlPathOption(spec, raw)
	case OptionControlPersist:
		return parseControlPersistOption(spec, raw)
	case OptionIdentityFile, OptionCertificateFile:
		return parsePathListOption(spec, raw, source)
	case OptionCiphers, OptionMACs, OptionKexAlgorithms, OptionHostKeyAlgorithms:
		return parseAlgorithmOption(spec, raw, source)
	case OptionPreferredAuthentications:
		return parsePreferredAuthOption(spec, raw, source)
	case OptionProxyCommand:
		return parseProxyCommandOption(spec, raw)
	default:
		return parseGenericOption(spec, raw, source)
	}
}

func parseGenericOption(spec OptionSpec, raw string, source OptionSource) (ParsedOption, error) {
	if spec.MultiValue && (source == OptionSourceCLI || source == OptionSourceOpenSSHConfig) {
		if hasMultiValueDelimiterOrLineBreak(raw) || hasKnownHostsControlChar(raw) {
			return ParsedOption{}, fmt.Errorf("%w: invalid %s: value cannot contain newlines or control characters", ErrSSHOptionsValidation, spec.OpenSSHName)
		}
	}
	norm, err := spec.Normalize(raw)
	if err != nil {
		return ParsedOption{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	return ParsedOption{
		CanonicalKey: spec.CanonicalKey,
		OpenSSHName:  spec.OpenSSHName,
		Normalized:   norm,
	}, nil
}

func parseTargetPortOption(raw string) (ParsedOption, error) {
	if hasControlOrLineSepChar(raw) {
		return ParsedOption{}, fmt.Errorf("%w: invalid Port %q: contains invalid control character", ErrSSHOptionsValidation, raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedOption{}, fmt.Errorf("%w: invalid Port: value cannot be empty", ErrSSHOptionsValidation)
	}
	p, err := strconv.ParseUint(trimmed, 10, 16)
	if err != nil || p == 0 {
		return ParsedOption{}, fmt.Errorf("%w: invalid Port %q: must be between 1 and 65535", ErrSSHOptionsValidation, raw)
	}
	return ParsedOption{
		CanonicalKey:   OptionPort,
		OpenSSHName:    "Port",
		Normalized:     strconv.FormatUint(p, 10),
		IsTargetOption: true,
		Port:           uint16(p),
	}, nil
}

func parseTargetUserOption(raw string) (ParsedOption, error) {
	if hasControlOrLineSepChar(raw) {
		return ParsedOption{}, fmt.Errorf("%w: invalid User %q: contains invalid control character", ErrSSHOptionsValidation, raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedOption{}, fmt.Errorf("%w: invalid User: value cannot be empty", ErrSSHOptionsValidation)
	}
	return ParsedOption{
		CanonicalKey:   OptionUser,
		OpenSSHName:    "User",
		Normalized:     trimmed,
		IsTargetOption: true,
	}, nil
}

func parseTargetHostNameOption(raw string) (ParsedOption, error) {
	if hasControlOrLineSepChar(raw) {
		return ParsedOption{}, fmt.Errorf("%w: invalid HostName %q: contains invalid control character", ErrSSHOptionsValidation, raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedOption{}, fmt.Errorf("%w: invalid HostName: value cannot be empty", ErrSSHOptionsValidation)
	}
	if _, err := ExpandHostName(trimmed, "host"); err != nil {
		return ParsedOption{}, fmt.Errorf("%w: invalid HostName %q: %w", ErrSSHOptionsValidation, raw, err)
	}
	return ParsedOption{
		CanonicalKey:   OptionHostName,
		OpenSSHName:    "HostName",
		Normalized:     trimmed,
		IsTargetOption: true,
	}, nil
}

func parseTargetProxyJumpOption(raw string) (ParsedOption, error) {
	if hasControlOrLineSepChar(raw) {
		return ParsedOption{}, fmt.Errorf("%w: invalid ProxyJump %q: contains control character", ErrSSHOptionsValidation, raw)
	}
	if IsDisabledProxyJump(raw) {
		return ParsedOption{
			CanonicalKey:   OptionProxyJump,
			OpenSSHName:    "ProxyJump",
			Normalized:     "none",
			IsTargetOption: true,
			ProxySetting:   DisabledProxyJumpSetting(),
		}, nil
	}
	ps, err := ParseProxyJump(raw)
	if err != nil {
		return ParsedOption{}, err
	}
	norm := "none"
	if targets, ok := ps.JumpTargets(); ok {
		norm = strings.Join(targets, ",")
	}
	return ParsedOption{
		CanonicalKey:   OptionProxyJump,
		OpenSSHName:    "ProxyJump",
		Normalized:     norm,
		IsTargetOption: true,
		ProxySetting:   ps,
	}, nil
}

func parseControlMasterOption(spec OptionSpec, raw string) (ParsedOption, error) {
	if hasControlOrLineSepChar(raw) {
		return ParsedOption{}, fmt.Errorf("%w: invalid ControlMaster %q: contains invalid control character", ErrSSHOptionsValidation, raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedOption{}, fmt.Errorf("%w: invalid ControlMaster: value cannot be empty", ErrSSHOptionsValidation)
	}
	mode, err := ParseControlMasterMode(trimmed)
	if err != nil {
		return ParsedOption{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	return ParsedOption{
		CanonicalKey:  spec.CanonicalKey,
		OpenSSHName:   spec.OpenSSHName,
		Normalized:    string(mode),
		ControlMaster: mode,
	}, nil
}

func parseControlPathOption(spec OptionSpec, raw string) (ParsedOption, error) {
	setting, err := ParseControlPathSetting(raw, false)
	if err != nil {
		return ParsedOption{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	if setting.Unset() {
		return ParsedOption{}, fmt.Errorf("%w: invalid ControlPath: value cannot be empty", ErrSSHOptionsValidation)
	}
	return ParsedOption{
		CanonicalKey: spec.CanonicalKey,
		OpenSSHName:  spec.OpenSSHName,
		Normalized:   setting.Raw,
		ControlPath:  setting,
	}, nil
}

func parseControlPersistOption(spec OptionSpec, raw string) (ParsedOption, error) {
	setting, err := ParsePersistSetting(raw)
	if err != nil {
		return ParsedOption{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	if !setting.Explicit() {
		return ParsedOption{}, fmt.Errorf("%w: invalid ControlPersist: value cannot be empty", ErrSSHOptionsValidation)
	}
	return ParsedOption{
		CanonicalKey:   spec.CanonicalKey,
		OpenSSHName:    spec.OpenSSHName,
		Normalized:     setting.Raw,
		ControlPersist: setting,
	}, nil
}

func parsePathListOption(spec OptionSpec, raw string, source OptionSource) (ParsedOption, error) {
	var (
		pl  PathList
		err error
	)
	if source == OptionSourceCLI || source == OptionSourceOpenSSHConfig {
		if hasMultiValueDelimiterOrLineBreak(raw) || hasKnownHostsControlChar(raw) {
			return ParsedOption{}, fmt.Errorf("%w: invalid %s: value cannot contain newlines or control characters", ErrSSHOptionsValidation, spec.OpenSSHName)
		}
		pl, err = ParsePathListItems([]string{raw})
	} else {
		pl, err = ParsePathList(raw)
	}
	if err != nil {
		return ParsedOption{}, err
	}
	return ParsedOption{
		CanonicalKey: spec.CanonicalKey,
		OpenSSHName:  spec.OpenSSHName,
		Normalized:   pl.String(),
		PathList:     pl,
	}, nil
}

func parseProxyCommandOption(spec OptionSpec, raw string) (ParsedOption, error) {
	ps, err := ParseProxyCommand(raw)
	if err != nil {
		return ParsedOption{}, err
	}
	norm := "none"
	if cmd, ok := ps.Command(); ok {
		norm = cmd
	}
	return ParsedOption{
		CanonicalKey: spec.CanonicalKey,
		OpenSSHName:  spec.OpenSSHName,
		Normalized:   norm,
		ProxySetting: ps,
	}, nil
}

func parseAlgorithmOption(spec OptionSpec, raw string, source OptionSource) (ParsedOption, error) {
	if hasControlOrLineSepChar(raw) {
		return ParsedOption{}, fmt.Errorf("%w: invalid %s %q: contains invalid control character", ErrSSHOptionsValidation, spec.OpenSSHName, raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedOption{}, fmt.Errorf("%w: invalid %s: value cannot be empty", ErrSSHOptionsValidation, spec.OpenSSHName)
	}

	if source != OptionSourceOpenSSHConfig {
		policy, err := ParseAlgoPolicy(spec.CanonicalKey, trimmed)
		if err != nil {
			return ParsedOption{}, err
		}
		if _, err := policy.Resolve(defaultAlgorithmsForOption(spec.CanonicalKey)); err != nil {
			return ParsedOption{}, fmt.Errorf("%w: invalid %s %q: %w", ErrSSHOptionsValidation, spec.OpenSSHName, raw, err)
		}
		return ParsedOption{
			CanonicalKey: spec.CanonicalKey,
			OpenSSHName:  spec.OpenSSHName,
			Normalized:   policy.String(),
			AlgoPolicy:   policy,
		}, nil
	}

	return parseOpenSSHAlgorithmOption(spec, raw, trimmed)
}

func parseOpenSSHAlgorithmOption(spec OptionSpec, raw, trimmed string) (ParsedOption, error) {
	var prefix string
	body := trimmed
	if trimmed[0] == '+' || trimmed[0] == '-' || trimmed[0] == '^' {
		prefix = trimmed[:1]
		body = trimmed[1:]
	}
	if strings.TrimSpace(body) == "" {
		return ParsedOption{}, fmt.Errorf("%w: invalid %s %q: bare modifier %q without algorithm tokens", ErrSSHOptionsValidation, spec.OpenSSHName, raw, prefix)
	}

	supported := spec.SupportedTokens()
	var kept []string
	for part := range strings.SplitSeq(body, ",") {
		tok := strings.TrimSpace(part)
		if tok == "" {
			return ParsedOption{}, fmt.Errorf("%w: invalid %s %q: empty algorithm token", ErrSSHOptionsValidation, spec.OpenSSHName, raw)
		}
		if !isValidAlgorithmName(tok) {
			return ParsedOption{}, fmt.Errorf("%w: invalid %s %q: invalid algorithm token %q", ErrSSHOptionsValidation, spec.OpenSSHName, raw, tok)
		}
		if prefix == "-" || slices.Contains(supported, tok) {
			if !slices.Contains(kept, tok) {
				kept = append(kept, tok)
			}
		}
	}
	if len(kept) == 0 {
		if prefix == "+" || prefix == "^" {
			return ParsedOption{
				CanonicalKey: spec.CanonicalKey,
				OpenSSHName:  spec.OpenSSHName,
				IsNoOp:       true,
				AlgoPolicy:   UnsetAlgoPolicy(),
			}, nil
		}
		return ParsedOption{}, fmt.Errorf("%w: no supported %s in %q", ErrSSHOptionsValidation, spec.OpenSSHName, raw)
	}

	rebuilt := prefix + strings.Join(kept, ",")
	policy, err := ParseAlgoPolicy(spec.CanonicalKey, rebuilt)
	if err != nil {
		return ParsedOption{}, err
	}
	if _, err := policy.Resolve(defaultAlgorithmsForOption(spec.CanonicalKey)); err != nil {
		return ParsedOption{}, fmt.Errorf("%w: invalid %s %q: %w", ErrSSHOptionsValidation, spec.OpenSSHName, raw, err)
	}
	return ParsedOption{
		CanonicalKey: spec.CanonicalKey,
		OpenSSHName:  spec.OpenSSHName,
		Normalized:   policy.String(),
		AlgoPolicy:   policy,
	}, nil
}

func parsePreferredAuthOption(spec OptionSpec, raw string, source OptionSource) (ParsedOption, error) {
	if hasControlOrLineSepChar(raw) {
		return ParsedOption{}, fmt.Errorf("%w: invalid PreferredAuthentications %q: contains invalid control character", ErrSSHOptionsValidation, raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedOption{}, fmt.Errorf("%w: invalid PreferredAuthentications: value cannot be empty", ErrSSHOptionsValidation)
	}
	if source != OptionSourceOpenSSHConfig {
		norm, err := spec.Normalize(trimmed)
		if err != nil {
			return ParsedOption{}, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		return ParsedOption{
			CanonicalKey: spec.CanonicalKey,
			OpenSSHName:  spec.OpenSSHName,
			Normalized:   norm,
		}, nil
	}

	supported := spec.SupportedTokens()
	failClosed := spec.FailClosedTokens
	var kept, keptFailClosed []string
	for part := range strings.SplitSeq(trimmed, ",") {
		tok := strings.ToLower(strings.TrimSpace(part))
		if tok == "" {
			return ParsedOption{}, fmt.Errorf("%w: invalid PreferredAuthentications %q: empty method token", ErrSSHOptionsValidation, raw)
		}
		if slices.Contains(supported, tok) {
			if !slices.Contains(kept, tok) {
				kept = append(kept, tok)
			}
			continue
		}
		if slices.Contains(failClosed, tok) && !slices.Contains(keptFailClosed, tok) {
			keptFailClosed = append(keptFailClosed, tok)
		}
	}
	if len(kept) == 0 {
		if len(keptFailClosed) == 0 {
			return ParsedOption{}, fmt.Errorf("%w: no supported PreferredAuthentications in %q", ErrSSHOptionsValidation, raw)
		}
		kept = keptFailClosed
	}
	return ParsedOption{
		CanonicalKey: spec.CanonicalKey,
		OpenSSHName:  spec.OpenSSHName,
		Normalized:   strings.Join(kept, ","),
	}, nil
}

func defaultAlgorithmsForOption(canonicalKey string) []string {
	supported := cryptoSSH.SupportedAlgorithms()
	switch canonicalKey {
	case OptionCiphers:
		return supported.Ciphers
	case OptionMACs:
		return supported.MACs
	case OptionKexAlgorithms:
		return supported.KeyExchanges
	case OptionHostKeyAlgorithms:
		return supported.HostKeys
	default:
		return nil
	}
}
