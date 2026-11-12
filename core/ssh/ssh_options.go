package ssh

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

// ErrSSHOptionsValidation indicates an invalid SSH option key or value.
var ErrSSHOptionsValidation = errors.New("ssh options validation error")

// Standard canonical snake_case option keys used for persistence in ssh_options.
const (
	OptionControlMaster                = "control_master"
	OptionControlPath                  = "control_path"
	OptionControlPersist               = "control_persist"
	OptionConnectTimeout               = "connect_timeout"
	OptionServerAliveInterval          = "server_alive_interval"
	OptionServerAliveCountMax          = "server_alive_count_max"
	OptionTCPKeepAlive                 = "tcp_keep_alive"
	OptionStrictHostKeyChecking        = "strict_host_key_checking"
	OptionUserKnownHostsFile           = "user_known_hosts_file"
	OptionPubkeyAuthentication         = "pubkey_authentication"
	OptionPasswordAuthentication       = "password_authentication"
	OptionKbdInteractiveAuthentication = "kbd_interactive_authentication"
	OptionIdentitiesOnly               = "identities_only"
	OptionPreferredAuthentications     = "preferred_authentications"
	OptionBatchMode                    = "batch_mode"
	OptionHostKeyAlgorithms            = "host_key_algorithms"
	OptionCiphers                      = "ciphers"
	OptionMACs                         = "macs"
	OptionKexAlgorithms                = "kex_algorithms"
	OptionExitOnForwardFailure         = "exit_on_forward_failure"
	OptionClearAllForwardings          = "clear_all_forwardings"
	OptionGatewayPorts                 = "gateway_ports"
	OptionStreamLocalBindUnlink        = "stream_local_bind_unlink"
	OptionStreamLocalBindMask          = "stream_local_bind_mask"
	OptionForkAfterAuthentication      = "fork_after_authentication"
	OptionStdinNull                    = "stdin_null"
	OptionSessionType                  = "session_type"
	OptionTunnel                       = "tunnel"
	OptionTunnelDevice                 = "tunnel_device"
	OptionRequestTTY                   = "request_tty"
	OptionLocalForward                 = "local_forward"
	OptionRemoteForward                = "remote_forward"
	OptionDynamicForward               = "dynamic_forward"
)

// OptionClass categorizes OpenSSH options by security and functional domain.
type OptionClass string

const (
	OptionClassMux       OptionClass = "mux"
	OptionClassTransport OptionClass = "transport"
	OptionClassAuth      OptionClass = "auth"
	OptionClassTrust     OptionClass = "trust"
	OptionClassForward   OptionClass = "forward"
	OptionClassSession   OptionClass = "session"
)

// StrictHostKeyCheckingMode defines OpenSSH StrictHostKeyChecking values.
const (
	StrictHostKeyCheckingYes       = "yes"
	StrictHostKeyCheckingNo        = "no"
	StrictHostKeyCheckingAsk       = "ask"
	StrictHostKeyCheckingAcceptNew = "accept-new"
)

// OptionSpec describes a supported OpenSSH client option in the registry.
type OptionSpec struct {
	CanonicalKey string      // Persistent snake_case key (e.g. "control_master")
	OpenSSHName  string      // Canonical OpenSSH name (e.g. "ControlMaster")
	Class        OptionClass // Functional/security category
	Aliases      []string    // Accepted aliases (e.g. "ChallengeResponseAuthentication")
	AllowList    bool        // Whether YAML sequence values are accepted and joined with ","
	MultiValue   bool        // Whether multiple directives accumulate (newline-delimited internally, YAML/JSON array externally)
	Normalize    func(raw string) (string, error)
}

var optionRegistry = []OptionSpec{
	{
		CanonicalKey: OptionControlMaster,
		OpenSSHName:  "ControlMaster",
		Class:        OptionClassMux,
		Normalize: func(raw string) (string, error) {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				return "", fmt.Errorf("unsupported ControlMaster option %q", raw)
			}
			m, err := ParseControlMasterMode(trimmed)
			if err != nil {
				return "", err
			}
			return string(m), nil
		},
	},
	{
		CanonicalKey: OptionControlPath,
		OpenSSHName:  "ControlPath",
		Class:        OptionClassMux,
		Normalize: func(raw string) (string, error) {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				return "", errors.New("invalid ControlPath: value cannot be empty")
			}
			if strings.EqualFold(trimmed, "none") {
				return "none", nil
			}
			if err := ValidateControlPathSyntax(trimmed); err != nil {
				return "", fmt.Errorf("invalid ControlPath %q: %w", raw, err)
			}
			return trimmed, nil
		},
	},
	{
		CanonicalKey: OptionControlPersist,
		OpenSSHName:  "ControlPersist",
		Class:        OptionClassMux,
		Normalize: func(raw string) (string, error) {
			trimmed := strings.ToLower(strings.TrimSpace(raw))
			if trimmed == "" {
				return "", errors.New("invalid ControlPersist: value cannot be empty")
			}
			if _, _, _, err := ParseControlPersist(trimmed); err != nil {
				return "", fmt.Errorf("invalid ControlPersist %q: %w", raw, err)
			}
			return trimmed, nil
		},
	},
	{
		CanonicalKey: OptionConnectTimeout,
		OpenSSHName:  "ConnectTimeout",
		Class:        OptionClassTransport,
		Normalize: func(raw string) (string, error) {
			return normalizeOptionalDurationOption("ConnectTimeout", raw)
		},
	},
	{
		CanonicalKey: OptionServerAliveInterval,
		OpenSSHName:  "ServerAliveInterval",
		Class:        OptionClassTransport,
		Normalize: func(raw string) (string, error) {
			return normalizeOptionalDurationOption("ServerAliveInterval", raw)
		},
	},
	{
		CanonicalKey: OptionServerAliveCountMax,
		OpenSSHName:  "ServerAliveCountMax",
		Class:        OptionClassTransport,
		Normalize: func(raw string) (string, error) {
			trimmed := strings.TrimSpace(raw)
			val, err := strconv.Atoi(trimmed)
			if err != nil || val < 0 {
				return "", fmt.Errorf("invalid ServerAliveCountMax %q: must be a non-negative integer", raw)
			}
			return strconv.Itoa(val), nil
		},
	},
	{
		CanonicalKey: OptionTCPKeepAlive,
		OpenSSHName:  "TCPKeepAlive",
		Class:        OptionClassTransport,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("TCPKeepAlive", raw)
		},
	},
	{
		CanonicalKey: OptionStrictHostKeyChecking,
		OpenSSHName:  "StrictHostKeyChecking",
		Class:        OptionClassTrust,
		Normalize:    ParseStrictHostKeyChecking,
	},
	{
		CanonicalKey: OptionUserKnownHostsFile,
		OpenSSHName:  "UserKnownHostsFile",
		Class:        OptionClassTrust,
		Normalize: func(raw string) (string, error) {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				return "", errors.New("invalid UserKnownHostsFile: value cannot be empty")
			}
			return trimmed, nil
		},
	},
	{
		CanonicalKey: OptionPubkeyAuthentication,
		OpenSSHName:  "PubkeyAuthentication",
		Class:        OptionClassAuth,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("PubkeyAuthentication", raw)
		},
	},
	{
		CanonicalKey: OptionPasswordAuthentication,
		OpenSSHName:  "PasswordAuthentication",
		Class:        OptionClassAuth,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("PasswordAuthentication", raw)
		},
	},
	{
		CanonicalKey: OptionKbdInteractiveAuthentication,
		OpenSSHName:  "KbdInteractiveAuthentication",
		Class:        OptionClassAuth,
		Aliases:      []string{"ChallengeResponseAuthentication", "challenge_response_authentication"},
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("KbdInteractiveAuthentication", raw)
		},
	},
	{
		CanonicalKey: OptionIdentitiesOnly,
		OpenSSHName:  "IdentitiesOnly",
		Class:        OptionClassAuth,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("IdentitiesOnly", raw)
		},
	},
	{
		CanonicalKey: OptionPreferredAuthentications,
		OpenSSHName:  "PreferredAuthentications",
		Class:        OptionClassAuth,
		AllowList:    true,
		Normalize:    normalizePreferredAuthentications,
	},
	{
		CanonicalKey: OptionBatchMode,
		OpenSSHName:  "BatchMode",
		Class:        OptionClassAuth,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("BatchMode", raw)
		},
	},
	{
		CanonicalKey: OptionHostKeyAlgorithms,
		OpenSSHName:  "HostKeyAlgorithms",
		Class:        OptionClassTransport,
		AllowList:    true,
		Normalize: func(raw string) (string, error) {
			defaults := cryptoSSH.SupportedAlgorithms().HostKeys
			return normalizeAlgorithmSpec("HostKeyAlgorithms", raw, defaults, allSupportedAlgorithms(
				defaults,
				cryptoSSH.InsecureAlgorithms().HostKeys,
			))
		},
	},
	{
		CanonicalKey: OptionCiphers,
		OpenSSHName:  "Ciphers",
		Class:        OptionClassTransport,
		AllowList:    true,
		Normalize: func(raw string) (string, error) {
			defaults := cryptoSSH.SupportedAlgorithms().Ciphers
			return normalizeAlgorithmSpec("Ciphers", raw, defaults, allSupportedAlgorithms(
				defaults,
				cryptoSSH.InsecureAlgorithms().Ciphers,
			))
		},
	},
	{
		CanonicalKey: OptionMACs,
		OpenSSHName:  "MACs",
		Class:        OptionClassTransport,
		AllowList:    true,
		Normalize: func(raw string) (string, error) {
			defaults := cryptoSSH.SupportedAlgorithms().MACs
			return normalizeAlgorithmSpec("MACs", raw, defaults, allSupportedAlgorithms(
				defaults,
				cryptoSSH.InsecureAlgorithms().MACs,
			))
		},
	},
	{
		CanonicalKey: OptionKexAlgorithms,
		OpenSSHName:  "KexAlgorithms",
		Class:        OptionClassTransport,
		AllowList:    true,
		Normalize: func(raw string) (string, error) {
			defaults := cryptoSSH.SupportedAlgorithms().KeyExchanges
			return normalizeAlgorithmSpec("KexAlgorithms", raw, defaults, allSupportedAlgorithms(
				defaults,
				cryptoSSH.InsecureAlgorithms().KeyExchanges,
			))
		},
	},
	{
		CanonicalKey: OptionExitOnForwardFailure,
		OpenSSHName:  "ExitOnForwardFailure",
		Class:        OptionClassForward,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("ExitOnForwardFailure", raw)
		},
	},
	{
		CanonicalKey: OptionClearAllForwardings,
		OpenSSHName:  "ClearAllForwardings",
		Class:        OptionClassForward,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("ClearAllForwardings", raw)
		},
	},
	{
		CanonicalKey: OptionGatewayPorts,
		OpenSSHName:  "GatewayPorts",
		Class:        OptionClassForward,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("GatewayPorts", raw)
		},
	},
	{
		CanonicalKey: OptionStreamLocalBindUnlink,
		OpenSSHName:  "StreamLocalBindUnlink",
		Class:        OptionClassForward,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("StreamLocalBindUnlink", raw)
		},
	},
	{
		CanonicalKey: OptionStreamLocalBindMask,
		OpenSSHName:  "StreamLocalBindMask",
		Class:        OptionClassForward,
		Normalize:    ParseStreamLocalBindMaskOption,
	},
	{
		CanonicalKey: OptionForkAfterAuthentication,
		OpenSSHName:  "ForkAfterAuthentication",
		Class:        OptionClassSession,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("ForkAfterAuthentication", raw)
		},
	},
	{
		CanonicalKey: OptionStdinNull,
		OpenSSHName:  "StdinNull",
		Class:        OptionClassSession,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("StdinNull", raw)
		},
	},
	{
		CanonicalKey: OptionSessionType,
		OpenSSHName:  "SessionType",
		Class:        OptionClassSession,
		Normalize: func(raw string) (string, error) {
			m, err := ParseSessionTypeMode(raw)
			if err != nil {
				return "", err
			}
			return string(m), nil
		},
	},
	{
		CanonicalKey: OptionTunnel,
		OpenSSHName:  "Tunnel",
		Class:        OptionClassForward,
		Normalize:    ParseTunnelOption,
	},
	{
		CanonicalKey: OptionTunnelDevice,
		OpenSSHName:  "TunnelDevice",
		Class:        OptionClassForward,
		Normalize: func(raw string) (string, error) {
			spec, err := ParseTunnelDevice(raw)
			if err != nil {
				return "", err
			}
			return spec.String(), nil
		},
	},
	{
		CanonicalKey: OptionRequestTTY,
		OpenSSHName:  "RequestTTY",
		Class:        OptionClassSession,
		Normalize: func(raw string) (string, error) {
			mode, err := ParseRequestTTYMode(raw)
			if err != nil {
				return "", err
			}
			return string(mode), nil
		},
	},
	{
		CanonicalKey: OptionLocalForward,
		OpenSSHName:  "LocalForward",
		Class:        OptionClassForward,
		MultiValue:   true,
		Normalize: func(raw string) (string, error) {
			return normalizeMultiForwardEntries("LocalForward", raw, func(item string) (string, error) {
				spec, err := ParseForwardSpec(item)
				if err != nil {
					return "", err
				}
				return spec.String(), nil
			})
		},
	},
	{
		CanonicalKey: OptionRemoteForward,
		OpenSSHName:  "RemoteForward",
		Class:        OptionClassForward,
		MultiValue:   true,
		Normalize: func(raw string) (string, error) {
			return normalizeMultiForwardEntries("RemoteForward", raw, func(item string) (string, error) {
				spec, err := ParseRemoteForwardSpec(item)
				if err != nil {
					return "", err
				}
				return spec.String(), nil
			})
		},
	},
	{
		CanonicalKey: OptionDynamicForward,
		OpenSSHName:  "DynamicForward",
		Class:        OptionClassForward,
		MultiValue:   true,
		Normalize: func(raw string) (string, error) {
			return normalizeMultiForwardEntries("DynamicForward", raw, ParseDynamicForwardSpec)
		},
	},
}

var optionLookupMap = buildOptionLookupMap()

func buildOptionLookupMap() map[string]OptionSpec {
	m := make(map[string]OptionSpec, len(optionRegistry)*3)
	for _, spec := range optionRegistry {
		m[strings.ToLower(spec.CanonicalKey)] = spec
		m[strings.ToLower(spec.OpenSSHName)] = spec
		for _, alias := range spec.Aliases {
			m[strings.ToLower(alias)] = spec
		}
	}
	return m
}

// RegisteredOptionSpecs returns a copy of all registered OpenSSH option specs.
func RegisteredOptionSpecs() []OptionSpec {
	return slices.Clone(optionRegistry)
}

// LookupOptionSpec resolves a key (in either snake_case or OpenSSH case-insensitive format)
// to its OptionSpec.
func LookupOptionSpec(key string) (OptionSpec, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(key))
	if trimmed == "" {
		return OptionSpec{}, false
	}
	spec, ok := optionLookupMap[trimmed]
	return spec, ok
}

// ParseStrictHostKeyChecking validates and normalizes StrictHostKeyChecking values.
func ParseStrictHostKeyChecking(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "yes", "true":
		return StrictHostKeyCheckingYes, nil
	case "no", "off", "false":
		return StrictHostKeyCheckingNo, nil
	case "ask":
		return StrictHostKeyCheckingAsk, nil
	case "accept-new":
		return StrictHostKeyCheckingAcceptNew, nil
	default:
		return "", fmt.Errorf("unsupported StrictHostKeyChecking option %q (expected yes, no, ask, accept-new, or off)", raw)
	}
}

func normalizeYesNoOption(name, raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "yes", "true":
		return "yes", nil
	case "no", "false":
		return "no", nil
	default:
		return "", fmt.Errorf("invalid %s option %q (expected yes or no)", name, raw)
	}
}

func normalizeOptionalDurationOption(name, raw string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	switch trimmed {
	case "none", "0", "0s":
		return "0", nil
	}
	if _, err := parseOpenSSHDuration(trimmed); err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", name, raw, err)
	}
	return strings.TrimSpace(raw), nil
}

func normalizePreferredAuthentications(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("invalid PreferredAuthentications: value cannot be empty")
	}
	parts := strings.Split(trimmed, ",")
	var normalized []string
	for _, p := range parts {
		token := strings.ToLower(strings.TrimSpace(p))
		switch token {
		case "publickey", "keyboard-interactive", "password", "gssapi-with-mic", "hostbased":
			if !slices.Contains(normalized, token) {
				normalized = append(normalized, token)
			}
		default:
			return "", fmt.Errorf("invalid PreferredAuthentications method %q", p)
		}
	}
	if len(normalized) == 0 {
		return "", errors.New("invalid PreferredAuthentications: no methods specified")
	}
	return strings.Join(normalized, ","), nil
}

func allSupportedAlgorithms(secure, insecure []string) []string {
	out := make([]string, 0, len(secure)+len(insecure))
	out = append(out, secure...)
	for _, a := range insecure {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

func normalizeAlgorithmSpec(name, raw string, defaults, supported []string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("invalid %s: value cannot be empty", name)
	}
	checkSpec := trimmed
	var modifier byte
	if checkSpec[0] == '+' || checkSpec[0] == '-' || checkSpec[0] == '^' {
		modifier = checkSpec[0]
		checkSpec = strings.TrimSpace(checkSpec[1:])
	}
	if checkSpec == "" {
		return "", fmt.Errorf("invalid %s %q: empty algorithm list", name, raw)
	}
	for part := range strings.SplitSeq(checkSpec, ",") {
		algo := strings.TrimSpace(part)
		if algo == "" {
			return "", fmt.Errorf("invalid %s %q: empty algorithm name in list", name, raw)
		}
		if modifier != '-' && !slices.Contains(supported, algo) {
			return "", fmt.Errorf("invalid %s %q: unsupported algorithm %q", name, raw, algo)
		}
	}
	if _, err := ResolveAlgorithmList(trimmed, defaults); err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", name, raw, err)
	}
	return trimmed, nil
}

// FilterSupportedListValue filters a comma-separated option value (for algorithm lists
// or PreferredAuthentications) down to tokens supported by this implementation.
// Used when leniently parsing ~/.ssh/config so OpenSSH-only algorithms (such as
// sntrup761x25519-sha512@openssh.com or umac-128-etm@openssh.com) do not reject the
// remaining supported algorithms.
func FilterSupportedListValue(canonicalKey, raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	var supported []string
	switch canonicalKey {
	case OptionPreferredAuthentications:
		supported = []string{"publickey", "keyboard-interactive", "password"}
	case OptionHostKeyAlgorithms:
		supported = allSupportedAlgorithms(cryptoSSH.SupportedAlgorithms().HostKeys, cryptoSSH.InsecureAlgorithms().HostKeys)
	case OptionCiphers:
		supported = allSupportedAlgorithms(cryptoSSH.SupportedAlgorithms().Ciphers, cryptoSSH.InsecureAlgorithms().Ciphers)
	case OptionMACs:
		supported = allSupportedAlgorithms(cryptoSSH.SupportedAlgorithms().MACs, cryptoSSH.InsecureAlgorithms().MACs)
	case OptionKexAlgorithms:
		supported = allSupportedAlgorithms(cryptoSSH.SupportedAlgorithms().KeyExchanges, cryptoSSH.InsecureAlgorithms().KeyExchanges)
	default:
		return raw
	}

	var prefix string
	body := trimmed
	if canonicalKey != OptionPreferredAuthentications && (body[0] == '+' || body[0] == '-' || body[0] == '^') {
		prefix = body[:1]
		body = strings.TrimSpace(body[1:])
	}
	var kept []string
	for part := range strings.SplitSeq(body, ",") {
		tok := strings.TrimSpace(part)
		if canonicalKey == OptionPreferredAuthentications {
			tok = strings.ToLower(tok)
		}
		if tok != "" && (prefix == "-" || slices.Contains(supported, tok)) {
			kept = append(kept, tok)
		}
	}
	if len(kept) == 0 {
		return ""
	}
	return prefix + strings.Join(kept, ",")
}

// ResolveAlgorithmList resolves an OpenSSH algorithm specification (explicit list,
// +append, -remove, or ^prepend) against the provided default list.
func ResolveAlgorithmList(spec string, defaults []string) ([]string, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return slices.Clone(defaults), nil
	}

	var modifier byte
	if trimmed[0] == '+' || trimmed[0] == '-' || trimmed[0] == '^' {
		modifier = trimmed[0]
		trimmed = strings.TrimSpace(trimmed[1:])
	}
	if trimmed == "" {
		return nil, errors.New("empty algorithm list")
	}

	var items []string
	for part := range strings.SplitSeq(trimmed, ",") {
		algo := strings.TrimSpace(part)
		if algo == "" {
			return nil, errors.New("empty algorithm name in list")
		}
		if !slices.Contains(items, algo) {
			items = append(items, algo)
		}
	}

	var result []string
	switch modifier {
	case 0:
		result = items
	case '+':
		result = slices.Clone(defaults)
		for _, algo := range items {
			if !slices.Contains(result, algo) {
				result = append(result, algo)
			}
		}
	case '^':
		result = slices.Clone(items)
		for _, algo := range defaults {
			if !slices.Contains(result, algo) {
				result = append(result, algo)
			}
		}
	case '-':
		for _, algo := range defaults {
			if !slices.Contains(items, algo) {
				result = append(result, algo)
			}
		}
	}

	if len(result) == 0 {
		return nil, errors.New("resolved algorithm list is empty")
	}
	return result, nil
}

// ValidateControlPathSyntax verifies raw ControlPath string token syntax without environment dependencies.
func ValidateControlPathSyntax(rawPath string) error {
	if rawPath == "" || rawPath == "none" {
		return nil
	}
	return validatePathTokenSyntax(rawPath, "ControlPath")
}

func validatePathTokenSyntax(rawPath, kind string) error {
	if strings.Contains(rawPath, "${") {
		idx := 0
		for {
			start := strings.Index(rawPath[idx:], "${")
			if start == -1 {
				break
			}
			start += idx
			end := strings.Index(rawPath[start:], "}")
			if end == -1 {
				return fmt.Errorf("unclosed environment variable in %s: %q", kind, rawPath[start:])
			}
			end += start
			varName := rawPath[start+2 : end]
			if varName == "" || !isValidEnvIdentifier(varName) {
				return fmt.Errorf("invalid environment variable name ${%s} in %s", varName, kind)
			}
			idx = end + 1
		}
	}

	for i := 0; i < len(rawPath); i++ {
		if rawPath[i] == '%' {
			if i+1 >= len(rawPath) {
				return fmt.Errorf("trailing '%%' in %s", kind)
			}
			i++
			switch rawPath[i] {
			case '%', 'h', 'p', 'r', 'n', 'u', 'l', 'L', 'i', 'd', 'j', 'C':
			default:
				return fmt.Errorf("unknown %s token %%%c", kind, rawPath[i])
			}
		}
	}
	return nil
}

func isValidEnvIdentifier(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && r != '_' {
				return false
			}
		} else {
			if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
				return false
			}
		}
	}
	return true
}

// Options represents an extensible set of OpenSSH client options.
// On disk (YAML/JSON) it serializes using canonical snake_case keys, while
// accepting both snake_case and OpenSSH standard names on input.
type Options struct {
	values map[string]string
	// ImplicitTier4 is true when multiplexing was resolved solely from ~/.ssh/config
	// without any CLI flag or xops node/global configuration.
	ImplicitTier4 bool `json:"-" yaml:"-"`
}

// NewOptions creates an Options instance from alternating key, value pairs.
func NewOptions(kv ...string) (*Options, error) {
	if len(kv)%2 != 0 {
		return nil, fmt.Errorf("%w: odd number of key-value arguments", ErrSSHOptionsValidation)
	}
	opts := &Options{}
	for i := 0; i < len(kv); i += 2 {
		if err := opts.Set(kv[i], kv[i+1]); err != nil {
			return nil, err
		}
	}
	return opts, nil
}

// MustOptions creates an Options instance from alternating key, value pairs and panics on error.
func MustOptions(kv ...string) *Options {
	opts, err := NewOptions(kv...)
	if err != nil {
		panic(err)
	}
	return opts
}

// OptionsFromControl constructs an Options instance from a ControlConfig.
func OptionsFromControl(ctrl *ControlConfig) *Options {
	if ctrl == nil {
		return nil
	}
	if ctrl.Master == "" && ctrl.Path == "" && ctrl.Persist == "" {
		return nil
	}
	opts := &Options{ImplicitTier4: ctrl.ImplicitTier4}
	if ctrl.Master != "" {
		opts.setRaw(OptionControlMaster, string(ctrl.Master))
	}
	if ctrl.Path != "" {
		opts.setRaw(OptionControlPath, ctrl.Path)
	}
	if ctrl.Persist != "" {
		opts.setRaw(OptionControlPersist, ctrl.Persist)
	}
	return opts
}

// IsEmpty reports whether no options are configured.
func (o *Options) IsEmpty() bool {
	return o == nil || len(o.values) == 0
}

// IsZero implements yaml.IsZeroer so empty non-nil Options are omitted with omitempty.
func (o Options) IsZero() bool {
	return len(o.values) == 0
}

// Clone returns a deep copy of Options.
func (o *Options) Clone() *Options {
	if o == nil {
		return nil
	}
	cloned := &Options{
		ImplicitTier4: o.ImplicitTier4,
	}
	if len(o.values) > 0 {
		cloned.values = make(map[string]string, len(o.values))
		for k, v := range o.values {
			cloned.values[k] = v
		}
	}
	return cloned
}

// Equal reports whether two Options contain identical key-value pairs.
func (o *Options) Equal(other *Options) bool {
	if o.IsEmpty() && other.IsEmpty() {
		return true
	}
	if o.IsEmpty() || other.IsEmpty() {
		return false
	}
	if len(o.values) != len(other.values) {
		return false
	}
	for k, v := range o.values {
		if other.values[k] != v {
			return false
		}
	}
	return true
}

// Set validates and sets an option by either snake_case or OpenSSH key name.
// Passing an empty value removes the option.
func (o *Options) Set(key, rawValue string) error {
	if o == nil {
		return fmt.Errorf("%w: options receiver is nil", ErrSSHOptionsValidation)
	}
	spec, ok := LookupOptionSpec(key)
	if !ok {
		return fmt.Errorf("%w: unknown ssh option %q", ErrSSHOptionsValidation, key)
	}
	if strings.TrimSpace(rawValue) == "" {
		o.Delete(spec.CanonicalKey)
		return nil
	}
	normalized, err := spec.Normalize(rawValue)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	o.setRaw(spec.CanonicalKey, normalized)
	return nil
}

// setRaw stores a value directly under its canonical key without running Normalize.
func (o *Options) setRaw(canonicalKey, val string) {
	if val == "" {
		o.Delete(canonicalKey)
		return
	}
	if o.values == nil {
		o.values = make(map[string]string)
	}
	o.values[canonicalKey] = val
}

// Delete removes an option by key.
func (o *Options) Delete(key string) {
	if o == nil || len(o.values) == 0 {
		return
	}
	if spec, ok := LookupOptionSpec(key); ok {
		delete(o.values, spec.CanonicalKey)
	} else {
		delete(o.values, key)
	}
	if len(o.values) == 0 {
		o.values = nil
	}
}

// Get returns the normalized string value for key, or "" if unset.
func (o *Options) Get(key string) string {
	if o == nil || len(o.values) == 0 {
		return ""
	}
	if spec, ok := LookupOptionSpec(key); ok {
		return o.values[spec.CanonicalKey]
	}
	return o.values[key]
}

// Has reports whether key is explicitly configured in o.
func (o *Options) Has(key string) bool {
	if o == nil || len(o.values) == 0 {
		return false
	}
	if spec, ok := LookupOptionSpec(key); ok {
		_, exists := o.values[spec.CanonicalKey]
		return exists
	}
	_, exists := o.values[key]
	return exists
}

// Map returns a defensive copy of the canonical snake_case key-value map.
func (o *Options) Map() map[string]string {
	if o.IsEmpty() {
		return nil
	}
	cp := make(map[string]string, len(o.values))
	for k, v := range o.values {
		cp[k] = v
	}
	return cp
}

// ControlMaster returns the configured ControlMasterMode, or "" if unset.
func (o *Options) ControlMaster() ControlMasterMode {
	return ControlMasterMode(o.Get(OptionControlMaster))
}

// SetControlMaster sets the ControlMasterMode directly.
func (o *Options) SetControlMaster(m ControlMasterMode) {
	o.setRaw(OptionControlMaster, string(m))
}

// ControlPath returns the configured ControlPath, or "" if unset.
func (o *Options) ControlPath() string {
	return o.Get(OptionControlPath)
}

// SetControlPath sets the ControlPath directly.
func (o *Options) SetControlPath(path string) {
	o.setRaw(OptionControlPath, path)
}

// ControlPersist returns the configured ControlPersist, or "" if unset.
func (o *Options) ControlPersist() string {
	return o.Get(OptionControlPersist)
}

// SetControlPersist sets the ControlPersist directly.
func (o *Options) SetControlPersist(persist string) {
	o.setRaw(OptionControlPersist, persist)
}

// ControlConfig extracts the multiplexing ControlConfig view from o, or returns
// nil if no multiplexing options are present.
func (o *Options) ControlConfig() *ControlConfig {
	if o.IsEmpty() {
		return nil
	}
	master := o.ControlMaster()
	path := o.ControlPath()
	persist := o.ControlPersist()
	if master == "" && path == "" && persist == "" {
		return nil
	}
	return &ControlConfig{
		Master:        master,
		Path:          path,
		Persist:       persist,
		ImplicitTier4: o.ImplicitTier4,
	}
}

// ConnectTimeout returns the configured ConnectTimeout duration, or 0 if unset/disabled.
func (o *Options) ConnectTimeout() time.Duration {
	val := o.Get(OptionConnectTimeout)
	if val == "" || val == "0" || strings.EqualFold(val, "none") {
		return 0
	}
	d, err := parseOpenSSHDuration(strings.ToLower(val))
	if err != nil {
		return 0
	}
	return d
}

// ServerAliveInterval returns the configured ServerAliveInterval, or 0 if unset/disabled.
func (o *Options) ServerAliveInterval() time.Duration {
	val := o.Get(OptionServerAliveInterval)
	if val == "" || val == "0" || strings.EqualFold(val, "none") {
		return 0
	}
	d, err := parseOpenSSHDuration(strings.ToLower(val))
	if err != nil {
		return 0
	}
	return d
}

// ServerAliveCountMax returns the configured ServerAliveCountMax (defaulting to 3 if unset).
func (o *Options) ServerAliveCountMax() int {
	val := o.Get(OptionServerAliveCountMax)
	if val == "" {
		return 3
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 0 {
		return 3
	}
	return n
}

// TCPKeepAlive returns (enabled, true) if TCPKeepAlive is explicitly set, or (false, false) if unset.
func (o *Options) TCPKeepAlive() (bool, bool) {
	return o.boolOption(OptionTCPKeepAlive)
}

// StrictHostKeyChecking returns the normalized StrictHostKeyChecking mode ("yes", "no", "ask", "accept-new"), or "" if unset.
func (o *Options) StrictHostKeyChecking() string {
	return o.Get(OptionStrictHostKeyChecking)
}

// UserKnownHostsFile returns the configured UserKnownHostsFile path, or "" if unset.
func (o *Options) UserKnownHostsFile() string {
	return o.Get(OptionUserKnownHostsFile)
}

// PubkeyAuthentication returns (enabled, true) if PubkeyAuthentication is set, or (true, false) if unset.
func (o *Options) PubkeyAuthentication() (bool, bool) {
	return o.boolOption(OptionPubkeyAuthentication)
}

// PasswordAuthentication returns (enabled, true) if PasswordAuthentication is set, or (true, false) if unset.
func (o *Options) PasswordAuthentication() (bool, bool) {
	return o.boolOption(OptionPasswordAuthentication)
}

// KbdInteractiveAuthentication returns (enabled, true) if KbdInteractiveAuthentication is set, or (true, false) if unset.
func (o *Options) KbdInteractiveAuthentication() (bool, bool) {
	return o.boolOption(OptionKbdInteractiveAuthentication)
}

// IdentitiesOnly reports whether IdentitiesOnly is set to "yes".
func (o *Options) IdentitiesOnly() bool {
	v, ok := o.boolOption(OptionIdentitiesOnly)
	return ok && v
}

// PreferredAuthentications returns the configured list of preferred authentication methods, or nil if unset.
func (o *Options) PreferredAuthentications() []string {
	val := o.Get(OptionPreferredAuthentications)
	if val == "" {
		return nil
	}
	return strings.Split(val, ",")
}

// BatchMode reports whether BatchMode is set to "yes".
func (o *Options) BatchMode() bool {
	v, ok := o.boolOption(OptionBatchMode)
	return ok && v
}

// HostKeyAlgorithms returns the raw HostKeyAlgorithms specification, or "" if unset.
func (o *Options) HostKeyAlgorithms() string {
	return o.Get(OptionHostKeyAlgorithms)
}

// Ciphers returns the raw Ciphers specification, or "" if unset.
func (o *Options) Ciphers() string {
	return o.Get(OptionCiphers)
}

// MACs returns the raw MACs specification, or "" if unset.
func (o *Options) MACs() string {
	return o.Get(OptionMACs)
}

// KexAlgorithms returns the raw KexAlgorithms specification, or "" if unset.
func (o *Options) KexAlgorithms() string {
	return o.Get(OptionKexAlgorithms)
}

// FilterByClasses returns a new Options containing only keys matching the allowed OptionClasses.
// Returns nil if the filtered result is empty.
func (o *Options) FilterByClasses(allowed ...OptionClass) *Options {
	if o.IsEmpty() || len(allowed) == 0 {
		return nil
	}
	res := &Options{ImplicitTier4: o.ImplicitTier4}
	for k, v := range o.values {
		spec, ok := LookupOptionSpec(k)
		if !ok {
			continue
		}
		if slices.Contains(allowed, spec.Class) {
			res.setRaw(k, v)
		}
	}
	if res.IsEmpty() {
		return nil
	}
	return res
}

// StripClasses removes all options belonging to any of the specified OptionClasses in place.
func (o *Options) StripClasses(classes ...OptionClass) {
	if o.IsEmpty() || len(classes) == 0 {
		return
	}
	for k := range o.values {
		spec, ok := LookupOptionSpec(k)
		if ok && slices.Contains(classes, spec.Class) {
			delete(o.values, k)
		}
	}
}

func (o *Options) boolOption(canonicalKey string) (bool, bool) {
	val := o.Get(canonicalKey)
	switch strings.ToLower(val) {
	case "yes", "true":
		return true, true
	case "no", "false":
		return false, true
	default:
		return false, false
	}
}

// Validate validates all individual option values and standalone cross-field rules.
func (o *Options) Validate() error {
	if o.IsEmpty() {
		return nil
	}
	for k, v := range o.values {
		spec, ok := LookupOptionSpec(k)
		if !ok {
			return fmt.Errorf("%w: unknown ssh option %q", ErrSSHOptionsValidation, k)
		}
		if _, err := spec.Normalize(v); err != nil {
			return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
	}

	normMaster := strings.ToLower(strings.TrimSpace(string(o.ControlMaster())))
	persist := o.ControlPersist()
	path := o.ControlPath()

	if normMaster == string(ControlMasterNo) && persist != "" &&
		!strings.EqualFold(persist, "no") && !strings.EqualFold(persist, "false") {
		return fmt.Errorf("%w: ControlPersist %q cannot be specified when ControlMaster is 'no'", ErrSSHOptionsValidation, persist)
	}

	if path == "none" && isActiveControlMaster(normMaster) {
		return fmt.Errorf("%w: ControlPath cannot be 'none' when ControlMaster is %q", ErrSSHOptionsValidation, o.ControlMaster())
	}

	return nil
}

// ValidateEffective validates cross-field constraints on a resolved effective Options set.
func (o *Options) ValidateEffective() error {
	if o.IsEmpty() {
		return nil
	}
	if err := o.Validate(); err != nil {
		return err
	}
	normMaster := strings.ToLower(strings.TrimSpace(string(o.ControlMaster())))
	path := o.ControlPath()
	persist := o.ControlPersist()
	if isActiveControlMaster(normMaster) {
		if path == "" || path == "none" {
			return fmt.Errorf("%w: ControlMaster %q requires non-empty ControlPath", ErrSSHOptionsValidation, o.ControlMaster())
		}
	}
	if persist != "" && !strings.EqualFold(persist, "no") && !strings.EqualFold(persist, "false") && path == "" {
		return fmt.Errorf("%w: ControlPath is required when ControlPersist is configured", ErrSSHOptionsValidation)
	}
	return nil
}

func isActiveControlMaster(mode string) bool {
	return mode == string(ControlMasterYes) ||
		mode == string(ControlMasterAsk) ||
		mode == string(ControlMasterAuto) ||
		mode == string(ControlMasterAutoAsk)
}

// MergeOptionLayers merges a slice of Options from highest priority to lowest priority
// using first-match-wins per option key, without applying cross-field effective finalization.
func MergeOptionLayers(layers ...*Options) *Options {
	res := &Options{}
	hasExplicitPersist := false
	hasImplicitTier4 := false
	for _, layer := range layers {
		if layer.IsEmpty() {
			continue
		}
		if !layer.ImplicitTier4 && layer.ControlPersist() != "" {
			hasExplicitPersist = true
		}
		if layer.ImplicitTier4 {
			hasImplicitTier4 = true
		}
		for k, v := range layer.values {
			spec, ok := LookupOptionSpec(k)
			if ok && spec.MultiValue {
				res.appendNormalizedRaw(spec.CanonicalKey, v)
				continue
			}
			if _, exists := res.values[k]; !exists {
				res.setRaw(k, v)
			}
		}
	}
	if res.IsEmpty() {
		return nil
	}
	res.ImplicitTier4 = !hasExplicitPersist && hasImplicitTier4
	return res
}

func finalizeEffectiveOptions(opts *Options) *Options {
	if opts.IsEmpty() {
		return nil
	}
	if opts.ControlPath() == "none" {
		opts.SetControlMaster(ControlMasterNo)
		opts.Delete(OptionControlPersist)
	}
	return opts
}

// ResolveOptions merges a higher-priority child Options with a lower-priority parent Options.
// Every option is inherited orthogonally unless overridden by child.
// Special multiplexing rule: if the effective control_path is "none", multiplexing is disabled
// (control_master="no", control_persist="").
func ResolveOptions(child, parent *Options) (*Options, error) {
	return finalizeEffectiveOptions(MergeOptionLayers(child, parent)), nil
}

// EffectiveOptions resolves a hierarchy of Options from highest priority to lowest priority.
func EffectiveOptions(layers ...*Options) (*Options, error) {
	return finalizeEffectiveOptions(MergeOptionLayers(layers...)), nil
}

// MarshalYAML serializes Options as a YAML mapping using canonical snake_case keys in registry order.
func (o Options) MarshalYAML() (any, error) {
	node := &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
	}
	if len(o.values) == 0 {
		return node, nil
	}
	for _, spec := range optionRegistry {
		val, ok := o.values[spec.CanonicalKey]
		if !ok || val == "" {
			continue
		}
		if spec.MultiValue {
			seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			for item := range strings.SplitSeq(val, "\n") {
				if item != "" {
					seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: item})
				}
			}
			node.Content = append(node.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: spec.CanonicalKey},
				seq,
			)
			continue
		}
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: spec.CanonicalKey},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val},
		)
	}
	return node, nil
}

// UnmarshalYAML decodes a YAML mapping into Options, accepting both canonical snake_case
// and OpenSSH standard option names while rejecting unknown or duplicate options.
func (o *Options) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || value.Tag == "!!null" {
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("%w: expected mapping for ssh_options", ErrSSHOptionsValidation)
	}

	seen := make(map[string]string, len(value.Content)/2)
	parsed := &Options{}
	for i := 0; i < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valNode := value.Content[i+1]
		rawKey := keyNode.Value

		spec, ok := LookupOptionSpec(rawKey)
		if !ok {
			return fmt.Errorf("%w: unknown ssh option %q in ssh_options", ErrSSHOptionsValidation, rawKey)
		}
		if prevKey, dup := seen[spec.CanonicalKey]; dup {
			return fmt.Errorf("%w: duplicate ssh option %q (conflicts with %q)", ErrSSHOptionsValidation, rawKey, prevKey)
		}
		seen[spec.CanonicalKey] = rawKey

		if spec.MultiValue && valNode != nil && valNode.Kind == yaml.SequenceNode && len(valNode.Content) == 0 {
			continue
		}

		rawVal, err := extractYAMLOptionValue(spec, valNode)
		if err != nil {
			return fmt.Errorf("%w: option %q: %w", ErrSSHOptionsValidation, rawKey, err)
		}
		normVal, err := spec.Normalize(rawVal)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		parsed.setRaw(spec.CanonicalKey, normVal)
	}

	if err := parsed.Validate(); err != nil {
		return err
	}
	*o = *parsed
	return nil
}

func extractYAMLOptionValue(spec OptionSpec, valNode *yaml.Node) (string, error) {
	if valNode == nil || valNode.Tag == "!!null" {
		return "", errors.New("value cannot be null")
	}
	switch valNode.Kind {
	case yaml.ScalarNode:
		return valNode.Value, nil
	case yaml.SequenceNode:
		if !spec.AllowList && !spec.MultiValue {
			return "", fmt.Errorf("%s does not accept a list value", spec.OpenSSHName)
		}
		var items []string
		for _, elem := range valNode.Content {
			if elem.Kind != yaml.ScalarNode || elem.Tag == "!!null" {
				return "", fmt.Errorf("%s list elements must be scalar strings", spec.OpenSSHName)
			}
			items = append(items, elem.Value)
		}
		if spec.MultiValue {
			return strings.Join(items, "\n"), nil
		}
		return strings.Join(items, ","), nil
	default:
		return "", fmt.Errorf("unexpected YAML value kind for %s", spec.OpenSSHName)
	}
}

// MarshalJSON serializes Options as a JSON object with canonical snake_case keys in deterministic order.
func (o Options) MarshalJSON() ([]byte, error) {
	if len(o.values) == 0 {
		return []byte("{}"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true
	for _, spec := range optionRegistry {
		val, ok := o.values[spec.CanonicalKey]
		if !ok || val == "" {
			continue
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		keyBytes, _ := json.Marshal(spec.CanonicalKey)
		var valBytes []byte
		if spec.MultiValue {
			valBytes, _ = json.Marshal(strings.Split(val, "\n"))
		} else {
			valBytes, _ = json.Marshal(val)
		}
		buf.Write(keyBytes)
		buf.WriteByte(':')
		buf.Write(valBytes)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// UnmarshalJSON decodes a JSON object into Options, accepting both snake_case and OpenSSH option names.
func (o *Options) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &rawMap); err != nil {
		return fmt.Errorf("%w: decode ssh_options json: %w", ErrSSHOptionsValidation, err)
	}
	seen := make(map[string]string, len(rawMap))
	parsed := &Options{}
	for rawKey, rawMsg := range rawMap {
		spec, ok := LookupOptionSpec(rawKey)
		if !ok {
			return fmt.Errorf("%w: unknown ssh option %q", ErrSSHOptionsValidation, rawKey)
		}
		if prevKey, dup := seen[spec.CanonicalKey]; dup {
			return fmt.Errorf("%w: duplicate ssh option %q (conflicts with %q)", ErrSSHOptionsValidation, rawKey, prevKey)
		}
		seen[spec.CanonicalKey] = rawKey

		if spec.MultiValue {
			trimmedMsg := bytes.TrimSpace(rawMsg)
			if len(trimmedMsg) > 0 && trimmedMsg[0] == '[' {
				var listVal []string
				if json.Unmarshal(trimmedMsg, &listVal) == nil && len(listVal) == 0 {
					continue
				}
			}
		}

		rawVal, err := extractJSONOptionValue(spec, rawMsg)
		if err != nil {
			return fmt.Errorf("%w: option %q: %w", ErrSSHOptionsValidation, rawKey, err)
		}
		normVal, err := spec.Normalize(rawVal)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		parsed.setRaw(spec.CanonicalKey, normVal)
	}
	if err := parsed.Validate(); err != nil {
		return err
	}
	*o = *parsed
	return nil
}

func extractJSONOptionValue(spec OptionSpec, rawMsg json.RawMessage) (string, error) {
	var strVal string
	if err := json.Unmarshal(rawMsg, &strVal); err == nil {
		return strVal, nil
	}
	var boolVal bool
	if err := json.Unmarshal(rawMsg, &boolVal); err == nil {
		if boolVal {
			return "yes", nil
		}
		return "no", nil
	}
	var intVal int64
	if err := json.Unmarshal(rawMsg, &intVal); err == nil {
		return strconv.FormatInt(intVal, 10), nil
	}
	if spec.AllowList || spec.MultiValue {
		var listVal []string
		if err := json.Unmarshal(rawMsg, &listVal); err == nil {
			if spec.MultiValue {
				return strings.Join(listVal, "\n"), nil
			}
			return strings.Join(listVal, ","), nil
		}
	}
	return "", fmt.Errorf("invalid value format for %s", spec.OpenSSHName)
}
