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
	"unicode"

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
	OptionAddressFamily                = "address_family"
	OptionConnectTimeout               = "connect_timeout"
	OptionServerAliveInterval          = "server_alive_interval"
	OptionServerAliveCountMax          = "server_alive_count_max"
	OptionTCPKeepAlive                 = "tcp_keep_alive"
	OptionStrictHostKeyChecking        = "strict_host_key_checking"
	OptionUserKnownHostsFile           = "user_known_hosts_file"
	OptionGlobalKnownHostsFile         = "global_known_hosts_file"
	OptionHashKnownHosts               = "hash_known_hosts"
	OptionVerifyHostKeyDNS             = "verify_host_key_dns"
	OptionCanonicalizeHostname         = "canonicalize_hostname"
	OptionCanonicalDomains             = "canonical_domains"
	OptionCanonicalizeMaxDots          = "canonicalize_max_dots"
	OptionCanonicalizeFallbackLocal    = "canonicalize_fallback_local"
	OptionCanonicalizePermittedCNAMEs  = "canonicalize_permitted_cnames"
	OptionIdentityFile                 = "identity_file"
	OptionCertificateFile              = "certificate_file"
	OptionIdentityAgent                = "identity_agent"
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
	OptionForwardAgent                 = "forward_agent"
	OptionGatewayPorts                 = "gateway_ports"
	OptionStreamLocalBindUnlink        = "stream_local_bind_unlink"
	OptionStreamLocalBindMask          = "stream_local_bind_mask"
	OptionForkAfterAuthentication      = "fork_after_authentication"
	OptionStdinNull                    = "stdin_null"
	OptionSessionType                  = "session_type"
	OptionTunnel                       = "tunnel"
	OptionTunnelDevice                 = "tunnel_device"
	OptionRequestTTY                   = "request_tty"
	OptionSendEnv                      = "send_env"
	OptionSetEnv                       = "set_env"
	OptionRemoteCommand                = "remote_command"
	OptionEscapeChar                   = "escape_char"
	OptionLocalForward                 = "local_forward"
	OptionRemoteForward                = "remote_forward"
	OptionDynamicForward               = "dynamic_forward"
	OptionProxyCommand                 = "proxy_command"
	OptionLocalCommand                 = "local_command"
	OptionPermitLocalCommand           = "permit_local_command"
)

// Target-level OpenSSH CLI/config directives (resolved onto connection target, not stored in Options).
const (
	OptionPort      = "port"
	OptionUser      = "user"
	OptionHostName  = "hostname"
	OptionProxyJump = "proxy_jump"
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
	OptionClassLocalExec OptionClass = "local_exec"
)

// AddressFamily values supported by OpenSSH.
const (
	AddressFamilyAny   = "any"
	AddressFamilyInet  = "inet"
	AddressFamilyInet6 = "inet6"
)

// GatewayPorts values supported by OpenSSH.
const (
	GatewayPortsYes             = "yes"
	GatewayPortsNo              = "no"
	GatewayPortsClientSpecified = "clientspecified"
)

// StrictHostKeyCheckingMode defines OpenSSH StrictHostKeyChecking values.
const (
	StrictHostKeyCheckingYes       = "yes"
	StrictHostKeyCheckingNo        = "no"
	StrictHostKeyCheckingAsk       = "ask"
	StrictHostKeyCheckingAcceptNew = "accept-new"
)

// VerifyHostKeyDNS values supported by OpenSSH.
const (
	VerifyHostKeyDNSNo  = "no"
	VerifyHostKeyDNSYes = "yes"
	VerifyHostKeyDNSAsk = "ask"
)

// CanonicalizeHostname values supported by OpenSSH.
const (
	CanonicalizeHostnameNo     = "no"
	CanonicalizeHostnameYes    = "yes"
	CanonicalizeHostnameAlways = "always"
)

// DefaultCanonicalizeMaxDots is OpenSSH's CanonicalizeMaxDots default.
const DefaultCanonicalizeMaxDots = 1

const maxCanonicalizeMaxDots = 64

// OptionScope declares whether a CLI Tier-1 option propagates across ProxyJump
// chains and jump mux daemons or applies only to the final target connection.
type OptionScope uint8

const (
	// OptionScopeTargetOnly confines an option to the target connection (default).
	OptionScopeTargetOnly OptionScope = iota
	// OptionScopeConnectionWide propagates CLI Tier-1 overrides to ProxyJump hops and jump mux daemons.
	OptionScopeConnectionWide
)

// OptionMergeMode declares how an option resolves within a single CLI or
// ssh_config layer and across priority layers in MergeOptionLayers.
type OptionMergeMode uint8

const (
	// OptionMergeUnset indicates an uninitialized merge mode (invalid in optionRegistry).
	OptionMergeUnset OptionMergeMode = iota
	// OptionMergeFirstWins selects the first directive within a layer and the
	// highest-priority layer across layers.
	OptionMergeFirstWins
	// OptionMergeAppendDedup appends normalized entries in order, deduplicating
	// identical entries (LocalForward, RemoteForward, DynamicForward).
	OptionMergeAppendDedup
	// OptionMergeNoneTerminated appends normalized entries in order, deduplicating
	// identical entries and truncating accumulation at "none" during MergeOptionLayers
	// (IdentityFile, CertificateFile).
	OptionMergeNoneTerminated
	// OptionMergeOrderedEnv appends all directives within a layer and merges layers
	// lowest-to-highest without dropping repeated tokens (SendEnv).
	OptionMergeOrderedEnv
	// OptionMergeSingleDirectiveOrderedEnv accepts only the first directive within
	// a single CLI/ssh_config layer while merging layers lowest-to-highest (SetEnv).
	OptionMergeSingleDirectiveOrderedEnv
)

// IsMultiValue reports whether m represents a multi-value option stored as
// newline-delimited entries internally and as a YAML/JSON sequence externally.
func (m OptionMergeMode) IsMultiValue() bool {
	switch m {
	case OptionMergeAppendDedup, OptionMergeNoneTerminated, OptionMergeOrderedEnv, OptionMergeSingleDirectiveOrderedEnv:
		return true
	default:
		return false
	}
}

// IsOrderedOverride reports whether layers must be merged lowest-to-highest
// without dropping repeated entries (SendEnv, SetEnv).
func (m OptionMergeMode) IsOrderedOverride() bool {
	return m == OptionMergeOrderedEnv || m == OptionMergeSingleDirectiveOrderedEnv
}

// IsNoneTerminated reports whether encountering "none" terminates accumulation
// of subsequent and lower-priority entries during MergeOptionLayers.
func (m OptionMergeMode) IsNoneTerminated() bool {
	return m == OptionMergeNoneTerminated
}

// SingleDirectivePerLayer reports whether only the first directive within a
// single CLI or ssh_config layer takes effect.
func (m OptionMergeMode) SingleDirectivePerLayer() bool {
	return m == OptionMergeFirstWins || m == OptionMergeSingleDirectiveOrderedEnv
}

// OptionConfigSyntax declares how an OpenSSH ssh_config directive line is
// tokenized after its keyword and optional '=' separator.
type OptionConfigSyntax uint8

const (
	// OptionSyntaxUnset indicates an uninitialized config syntax (invalid in optionRegistry).
	OptionSyntaxUnset OptionConfigSyntax = iota
	// OptionSyntaxStrictScalar expects a single argv token; >1 token is rejected by ssh_config parser.
	OptionSyntaxStrictScalar
	// OptionSyntaxMultiTokenList joins parsed argv tokens with a single space " ".
	OptionSyntaxMultiTokenList
	// OptionSyntaxRawTokenList preserves the raw comment-stripped token list verbatim.
	OptionSyntaxRawTokenList
	// OptionSyntaxWholeLineCommand preserves the trimmed rest of line without comment/quote stripping.
	OptionSyntaxWholeLineCommand
)

// PreservesRawValue reports whether ssh_config option evaluation reads the
// raw directive text rather than the argv-unquoted value.
func (s OptionConfigSyntax) PreservesRawValue() bool {
	return s == OptionSyntaxRawTokenList || s == OptionSyntaxWholeLineCommand
}

// OptionTier4Policy declares whether an option may be inherited from Tier 4
// (~/.ssh/config) and under what security restriction.
type OptionTier4Policy uint8

const (
	// OptionTier4Unset indicates an uninitialized Tier-4 policy (invalid in optionRegistry).
	OptionTier4Unset OptionTier4Policy = iota
	// OptionTier4Inherit permits normal inheritance from ~/.ssh/config.
	OptionTier4Inherit
	// OptionTier4Deny blocks inheritance from ~/.ssh/config so wildcard host
	// blocks cannot implicitly weaken host trust verification.
	OptionTier4Deny
	// OptionTier4OneWayYes permits inheritance from ~/.ssh/config only when the
	// value enables the security-hardening setting ("yes"/"true").
	OptionTier4OneWayYes
)

// OptionMuxPolicy declares how the detached ControlPersist mux daemon handles
// an option in MuxDaemonSpec.
type OptionMuxPolicy uint8

const (
	// OptionMuxUnset indicates an uninitialized mux policy (invalid in optionRegistry).
	OptionMuxUnset OptionMuxPolicy = iota
	// OptionMuxAuthoritative means MuxDaemonSpec carries this setting in a
	// dedicated authoritative field rather than in raw Options.
	OptionMuxAuthoritative
	// OptionMuxAllowNoneOnly permits the option in MuxDaemonSpec.Options only
	// when its value is "none" (ProxyCommand).
	OptionMuxAllowNoneOnly
	// OptionMuxAllow permits the option in MuxDaemonSpec.Options.
	OptionMuxAllow
	// OptionMuxReject forbids the option in MuxDaemonSpec.Options.
	OptionMuxReject
)

// OptionSpec describes a supported OpenSSH client option in the registry.
type OptionSpec struct {
	CanonicalKey          string             // Persistent snake_case key (e.g. "control_master")
	OpenSSHName           string             // Canonical OpenSSH name (e.g. "ControlMaster")
	Class                 OptionClass        // Functional/security category
	Scope                 OptionScope        // Propagation scope across ProxyJump hops (default: TargetOnly)
	MergeMode             OptionMergeMode    // Single-layer and multi-layer merge semantics
	ConfigSyntax          OptionConfigSyntax // ssh_config line lexing syntax
	Tier4Policy           OptionTier4Policy  // Tier-4 (~/.ssh/config) inheritance policy
	StrictInOpenSSHConfig bool               // Whether invalid ~/.ssh/config values fail closed instead of skipping
	MuxPolicy             OptionMuxPolicy    // Detached ControlPersist mux daemon option policy
	Aliases               []string           // Accepted aliases (e.g. "ChallengeResponseAuthentication")
	AllowList             bool               // Whether YAML sequence values are accepted and joined with ","
	MultiValue            bool               // Whether multiple directives accumulate (matches MergeMode.IsMultiValue())
	SupportedTokens       func() []string    // Returns supported tokens for AllowList options (auth methods or algorithms)
	FailClosedTokens      []string           // Recognized unimplemented tokens retained by FilterSupportedListValue so callers fail closed
	Normalize             func(raw string) (string, error)
}

// IsConnectionWide reports whether CLI Tier-1 overrides for this option propagate
// across ProxyJump chains and jump mux daemons.
func (s OptionSpec) IsConnectionWide() bool {
	return s.Scope == OptionScopeConnectionWide
}

var optionRegistry = []OptionSpec{
	{
		CanonicalKey:          OptionControlMaster,
		OpenSSHName:           "ControlMaster",
		Class:                 OptionClassMux,
		MergeMode:             OptionMergeFirstWins,
		ConfigSyntax:          OptionSyntaxStrictScalar,
		Tier4Policy:           OptionTier4Inherit,
		StrictInOpenSSHConfig: true,
		MuxPolicy:             OptionMuxAuthoritative,
		Normalize: func(raw string) (string, error) {
			if hasControlOrLineSepChar(raw) {
				return "", fmt.Errorf("unsupported ControlMaster option %q: contains invalid control character", raw)
			}
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
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAuthoritative,
		Normalize: func(raw string) (string, error) {
			setting, err := ParseControlPathSetting(raw, false)
			if err != nil {
				return "", err
			}
			if setting.Unset() {
				return "", errors.New("invalid ControlPath: value cannot be empty")
			}
			return setting.Raw, nil
		},
	},
	{
		CanonicalKey:          OptionControlPersist,
		OpenSSHName:           "ControlPersist",
		Class:                 OptionClassMux,
		MergeMode:             OptionMergeFirstWins,
		ConfigSyntax:          OptionSyntaxStrictScalar,
		Tier4Policy:           OptionTier4Inherit,
		StrictInOpenSSHConfig: true,
		MuxPolicy:             OptionMuxAuthoritative,
		Normalize: func(raw string) (string, error) {
			if hasControlOrLineSepChar(raw) {
				return "", fmt.Errorf("invalid ControlPersist %q: contains invalid control character", raw)
			}
			setting, err := ParsePersistSetting(raw)
			if err != nil {
				return "", fmt.Errorf("invalid ControlPersist %q: %w", raw, err)
			}
			if !setting.Explicit() {
				return "", errors.New("invalid ControlPersist: value cannot be empty")
			}
			return setting.Raw, nil
		},
	},
	{
		CanonicalKey: OptionAddressFamily,
		OpenSSHName:  "AddressFamily",
		Class:        OptionClassTransport,
		Scope:        OptionScopeConnectionWide,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize:    validateAddressFamily,
	},
	{
		CanonicalKey: OptionConnectTimeout,
		OpenSSHName:  "ConnectTimeout",
		Class:        OptionClassTransport,
		Scope:        OptionScopeConnectionWide,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize: func(raw string) (string, error) {
			return normalizeOptionalDurationOption("ConnectTimeout", raw)
		},
	},
	{
		CanonicalKey: OptionServerAliveInterval,
		OpenSSHName:  "ServerAliveInterval",
		Class:        OptionClassTransport,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize: func(raw string) (string, error) {
			return normalizeOptionalDurationOption("ServerAliveInterval", raw)
		},
	},
	{
		CanonicalKey: OptionServerAliveCountMax,
		OpenSSHName:  "ServerAliveCountMax",
		Class:        OptionClassTransport,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize: func(raw string) (string, error) {
			if hasControlOrLineSepChar(raw) {
				return "", fmt.Errorf("invalid ServerAliveCountMax %q: contains invalid control character", raw)
			}
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
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("TCPKeepAlive", raw)
		},
	},
	{
		CanonicalKey: OptionStrictHostKeyChecking,
		OpenSSHName:  "StrictHostKeyChecking",
		Class:        OptionClassTrust,
		Scope:        OptionScopeConnectionWide,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Deny,
		MuxPolicy:    OptionMuxAllow,
		Normalize:    ParseStrictHostKeyChecking,
	},
	{
		CanonicalKey: OptionUserKnownHostsFile,
		OpenSSHName:  "UserKnownHostsFile",
		Class:        OptionClassTrust,
		Scope:        OptionScopeConnectionWide,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxMultiTokenList,
		Tier4Policy:  OptionTier4Deny,
		MuxPolicy:    OptionMuxAllow,
		Normalize:    validateUserKnownHostsFile,
	},
	{
		CanonicalKey: OptionGlobalKnownHostsFile,
		OpenSSHName:  "GlobalKnownHostsFile",
		Class:        OptionClassTrust,
		Scope:        OptionScopeConnectionWide,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxMultiTokenList,
		Tier4Policy:  OptionTier4Deny,
		MuxPolicy:    OptionMuxAllow,
		Normalize:    validateGlobalKnownHostsFile,
	},
	{
		CanonicalKey: OptionHashKnownHosts,
		OpenSSHName:  "HashKnownHosts",
		Class:        OptionClassTrust,
		Scope:        OptionScopeConnectionWide,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4OneWayYes,
		MuxPolicy:    OptionMuxAllow,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("HashKnownHosts", raw)
		},
	},
	{
		CanonicalKey: OptionVerifyHostKeyDNS,
		OpenSSHName:  "VerifyHostKeyDNS",
		Class:        OptionClassTrust,
		Scope:        OptionScopeConnectionWide,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Deny,
		MuxPolicy:    OptionMuxAllow,
		Normalize:    validateVerifyHostKeyDNS,
	},
	{
		CanonicalKey: OptionCanonicalizeHostname,
		OpenSSHName:  "CanonicalizeHostname",
		Class:        OptionClassTransport,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize:    validateCanonicalizeHostname,
	},
	{
		CanonicalKey: OptionCanonicalDomains,
		OpenSSHName:  "CanonicalDomains",
		Class:        OptionClassTransport,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxMultiTokenList,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize:    validateCanonicalDomains,
	},
	{
		CanonicalKey: OptionCanonicalizeMaxDots,
		OpenSSHName:  "CanonicalizeMaxDots",
		Class:        OptionClassTransport,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize:    validateCanonicalizeMaxDots,
	},
	{
		CanonicalKey: OptionCanonicalizeFallbackLocal,
		OpenSSHName:  "CanonicalizeFallbackLocal",
		Class:        OptionClassTransport,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("CanonicalizeFallbackLocal", raw)
		},
	},
	{
		CanonicalKey: OptionCanonicalizePermittedCNAMEs,
		OpenSSHName:  "CanonicalizePermittedCNAMEs",
		Class:        OptionClassTransport,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxMultiTokenList,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize:    validateCanonicalizePermittedCNAMEs,
	},
	{
		CanonicalKey: OptionIdentityFile,
		OpenSSHName:  "IdentityFile",
		Class:        OptionClassAuth,
		MergeMode:    OptionMergeNoneTerminated,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAuthoritative,
		MultiValue:   true,
		Normalize:    validateIdentityFiles,
	},
	{
		CanonicalKey: OptionCertificateFile,
		OpenSSHName:  "CertificateFile",
		Class:        OptionClassAuth,
		MergeMode:    OptionMergeNoneTerminated,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		MultiValue:   true,
		Normalize:    validateCertificateFiles,
	},
	{
		CanonicalKey: OptionIdentityAgent,
		OpenSSHName:  "IdentityAgent",
		Class:        OptionClassAuth,
		Scope:        OptionScopeConnectionWide,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize:    validateIdentityAgent,
	},
	{
		CanonicalKey: OptionPubkeyAuthentication,
		OpenSSHName:  "PubkeyAuthentication",
		Class:        OptionClassAuth,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("PubkeyAuthentication", raw)
		},
	},
	{
		CanonicalKey: OptionPasswordAuthentication,
		OpenSSHName:  "PasswordAuthentication",
		Class:        OptionClassAuth,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("PasswordAuthentication", raw)
		},
	},
	{
		CanonicalKey: OptionKbdInteractiveAuthentication,
		OpenSSHName:  "KbdInteractiveAuthentication",
		Class:        OptionClassAuth,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Aliases:      []string{"ChallengeResponseAuthentication", "challenge_response_authentication"},
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("KbdInteractiveAuthentication", raw)
		},
	},
	{
		CanonicalKey: OptionIdentitiesOnly,
		OpenSSHName:  "IdentitiesOnly",
		Class:        OptionClassAuth,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("IdentitiesOnly", raw)
		},
	},
	newPreferredAuthenticationsOptionSpec(),
	{
		CanonicalKey: OptionBatchMode,
		OpenSSHName:  "BatchMode",
		Class:        OptionClassAuth,
		Scope:        OptionScopeConnectionWide,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("BatchMode", raw)
		},
	},
	newAlgorithmOptionSpec(
		OptionHostKeyAlgorithms,
		"HostKeyAlgorithms",
		func() []string { return cryptoSSH.SupportedAlgorithms().HostKeys },
		func() []string { return cryptoSSH.InsecureAlgorithms().HostKeys },
	),
	newAlgorithmOptionSpec(
		OptionCiphers,
		"Ciphers",
		func() []string { return cryptoSSH.SupportedAlgorithms().Ciphers },
		func() []string { return cryptoSSH.InsecureAlgorithms().Ciphers },
	),
	newAlgorithmOptionSpec(
		OptionMACs,
		"MACs",
		func() []string { return cryptoSSH.SupportedAlgorithms().MACs },
		func() []string { return cryptoSSH.InsecureAlgorithms().MACs },
	),
	newAlgorithmOptionSpec(
		OptionKexAlgorithms,
		"KexAlgorithms",
		func() []string { return cryptoSSH.SupportedAlgorithms().KeyExchanges },
		func() []string { return cryptoSSH.InsecureAlgorithms().KeyExchanges },
	),
	{
		CanonicalKey: OptionExitOnForwardFailure,
		OpenSSHName:  "ExitOnForwardFailure",
		Class:        OptionClassForward,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("ExitOnForwardFailure", raw)
		},
	},
	{
		CanonicalKey: OptionClearAllForwardings,
		OpenSSHName:  "ClearAllForwardings",
		Class:        OptionClassForward,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAuthoritative,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("ClearAllForwardings", raw)
		},
	},
	{
		CanonicalKey: OptionForwardAgent,
		OpenSSHName:  "ForwardAgent",
		Class:        OptionClassForward,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
		Normalize:    validateForwardAgent,
	},
	{
		CanonicalKey: OptionGatewayPorts,
		OpenSSHName:  "GatewayPorts",
		Class:        OptionClassForward,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize:    validateGatewayPorts,
	},
	{
		CanonicalKey: OptionStreamLocalBindUnlink,
		OpenSSHName:  "StreamLocalBindUnlink",
		Class:        OptionClassForward,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("StreamLocalBindUnlink", raw)
		},
	},
	{
		CanonicalKey: OptionStreamLocalBindMask,
		OpenSSHName:  "StreamLocalBindMask",
		Class:        OptionClassForward,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllow,
		Normalize:    ParseStreamLocalBindMaskOption,
	},
	{
		CanonicalKey: OptionForkAfterAuthentication,
		OpenSSHName:  "ForkAfterAuthentication",
		Class:        OptionClassSession,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("ForkAfterAuthentication", raw)
		},
	},
	{
		CanonicalKey: OptionStdinNull,
		OpenSSHName:  "StdinNull",
		Class:        OptionClassSession,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("StdinNull", raw)
		},
	},
	{
		CanonicalKey: OptionSessionType,
		OpenSSHName:  "SessionType",
		Class:        OptionClassSession,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
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
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
		Normalize:    ParseTunnelOption,
	},
	{
		CanonicalKey: OptionTunnelDevice,
		OpenSSHName:  "TunnelDevice",
		Class:        OptionClassForward,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
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
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
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
		MergeMode:    OptionMergeAppendDedup,
		ConfigSyntax: OptionSyntaxRawTokenList,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
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
		MergeMode:    OptionMergeAppendDedup,
		ConfigSyntax: OptionSyntaxRawTokenList,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
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
		MergeMode:    OptionMergeAppendDedup,
		ConfigSyntax: OptionSyntaxRawTokenList,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
		MultiValue:   true,
		Normalize: func(raw string) (string, error) {
			return normalizeMultiForwardEntries("DynamicForward", raw, ParseDynamicForwardSpec)
		},
	},
	{
		CanonicalKey: OptionSendEnv,
		OpenSSHName:  "SendEnv",
		Class:        OptionClassSession,
		MergeMode:    OptionMergeOrderedEnv,
		ConfigSyntax: OptionSyntaxRawTokenList,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
		MultiValue:   true,
		Normalize:    validateSendEnvOption,
	},
	{
		CanonicalKey: OptionSetEnv,
		OpenSSHName:  "SetEnv",
		Class:        OptionClassSession,
		MergeMode:    OptionMergeSingleDirectiveOrderedEnv,
		ConfigSyntax: OptionSyntaxRawTokenList,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
		MultiValue:   true,
		Normalize:    validateSetEnvOption,
	},
	{
		CanonicalKey: OptionRemoteCommand,
		OpenSSHName:  "RemoteCommand",
		Class:        OptionClassSession,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxWholeLineCommand,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
		Normalize:    validateRemoteCommandOption,
	},
	{
		CanonicalKey: OptionEscapeChar,
		OpenSSHName:  "EscapeChar",
		Class:        OptionClassSession,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
		Normalize:    validateEscapeCharOption,
	},
	{
		CanonicalKey: OptionProxyCommand,
		OpenSSHName:  "ProxyCommand",
		Class:        OptionClassLocalExec,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxWholeLineCommand,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxAllowNoneOnly,
		Normalize: func(raw string) (string, error) {
			return validateLocalExecCommandOption("ProxyCommand", raw)
		},
	},
	{
		CanonicalKey: OptionLocalCommand,
		OpenSSHName:  "LocalCommand",
		Class:        OptionClassLocalExec,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxWholeLineCommand,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
		Normalize: func(raw string) (string, error) {
			return validateLocalExecCommandOption("LocalCommand", raw)
		},
	},
	{
		CanonicalKey: OptionPermitLocalCommand,
		OpenSSHName:  "PermitLocalCommand",
		Class:        OptionClassLocalExec,
		MergeMode:    OptionMergeFirstWins,
		ConfigSyntax: OptionSyntaxStrictScalar,
		Tier4Policy:  OptionTier4Inherit,
		MuxPolicy:    OptionMuxReject,
		Normalize: func(raw string) (string, error) {
			return normalizeYesNoOption("PermitLocalCommand", raw)
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

// LookupDirectiveSyntax resolves the ssh_config parsing syntax for any
// registered OpenSSH option (canonical snake_case, OpenSSH name, or alias,
// case-insensitive) or target-level directive (Port, User, HostName, ProxyJump).
func LookupDirectiveSyntax(key string) (OptionConfigSyntax, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(key))
	switch trimmed {
	case "":
		return OptionSyntaxUnset, false
	case "port", "user", "hostname":
		return OptionSyntaxStrictScalar, true
	case "proxyjump", "proxy_jump":
		return OptionSyntaxMultiTokenList, true
	}
	if spec, ok := optionLookupMap[trimmed]; ok {
		return spec.ConfigSyntax, true
	}
	return OptionSyntaxUnset, false
}

// CanonicalOptionKey resolves any supported OpenSSH option or target-level CLI
// directive (in OpenSSH PascalCase, lowercase, alias, or snake_case form) to
// its canonical key. Returns "" if key is unknown.
func CanonicalOptionKey(key string) string {
	trimmed := strings.ToLower(strings.TrimSpace(key))
	switch trimmed {
	case "":
		return ""
	case "port":
		return OptionPort
	case "user":
		return OptionUser
	case "hostname":
		return OptionHostName
	case "proxyjump", "proxy_jump":
		return OptionProxyJump
	}
	if spec, ok := optionLookupMap[trimmed]; ok {
		return spec.CanonicalKey
	}
	return ""
}

// ProxyJumpKind classifies a ProxyJump directive into its canonical tri-state.
type ProxyJumpKind uint8

const (
	// ProxyJumpUnset means no ProxyJump directive was supplied (empty/whitespace).
	ProxyJumpUnset ProxyJumpKind = iota
	// ProxyJumpDisabled means ProxyJump was explicitly supplied with no active hop
	// (e.g. "none", "none,none", ",", " , ").
	ProxyJumpDisabled
	// ProxyJumpActive means ProxyJump contains at least one concrete non-"none" hop.
	ProxyJumpActive
)

// ClassifyProxyJump classifies raw into ProxyJumpUnset, ProxyJumpDisabled, or ProxyJumpActive.
func ClassifyProxyJump(raw string) ProxyJumpKind {
	if strings.TrimSpace(raw) == "" {
		return ProxyJumpUnset
	}
	for part := range strings.SplitSeq(raw, ",") {
		tok := strings.TrimSpace(part)
		if tok != "" && !strings.EqualFold(tok, "none") {
			return ProxyJumpActive
		}
	}
	return ProxyJumpDisabled
}

// NormalizeProxyJump extracts active non-"none" hops joined by ",", or returns ""
// when ProxyJump is unset or disabled.
func NormalizeProxyJump(raw string) string {
	return strings.Join(splitProxyJumpChain(raw), ",")
}

// IsDisabledProxyJump reports whether raw explicitly disables ProxyJump
// (e.g. "none", "none,none", or comma-only values with no active hop).
func IsDisabledProxyJump(raw string) bool {
	return ClassifyProxyJump(raw) == ProxyJumpDisabled
}

// HasActiveProxyJump reports whether raw contains at least one non-empty hop
// other than "none".
func HasActiveProxyJump(raw string) bool {
	return ClassifyProxyJump(raw) == ProxyJumpActive
}

// IsNoneValue reports whether s is the OpenSSH sentinel value "none"
// (case-insensitive after trimming surrounding whitespace).
func IsNoneValue(s string) bool {
	return strings.EqualFold(strings.TrimSpace(s), "none")
}

// ParseStrictHostKeyChecking validates and normalizes StrictHostKeyChecking values.
func ParseStrictHostKeyChecking(raw string) (string, error) {
	if hasControlOrLineSepChar(raw) {
		return "", fmt.Errorf("unsupported StrictHostKeyChecking option %q: contains invalid control character", raw)
	}
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
	if hasControlOrLineSepChar(raw) {
		return "", fmt.Errorf("invalid %s option %q: contains invalid control character", name, raw)
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "yes", "true":
		return "yes", nil
	case "no", "false":
		return "no", nil
	default:
		return "", fmt.Errorf("invalid %s option %q (expected yes or no)", name, raw)
	}
}

func validateAddressFamily(raw string) (string, error) {
	if hasControlOrLineSepChar(raw) {
		return "", fmt.Errorf("invalid AddressFamily option %q: contains invalid control character", raw)
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case AddressFamilyAny:
		return AddressFamilyAny, nil
	case AddressFamilyInet:
		return AddressFamilyInet, nil
	case AddressFamilyInet6:
		return AddressFamilyInet6, nil
	default:
		return "", fmt.Errorf("invalid AddressFamily option %q (expected any, inet, or inet6)", raw)
	}
}

func validateGatewayPorts(raw string) (string, error) {
	if hasControlOrLineSepChar(raw) {
		return "", fmt.Errorf("invalid GatewayPorts option %q: contains invalid control character", raw)
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "yes", "true":
		return GatewayPortsYes, nil
	case "no", "false":
		return GatewayPortsNo, nil
	case GatewayPortsClientSpecified:
		return GatewayPortsClientSpecified, nil
	default:
		return "", fmt.Errorf("invalid GatewayPorts option %q (expected yes, no, or clientspecified)", raw)
	}
}

func normalizeMultiPathEntries(optionName, raw string, normalizeItem func(string) (string, error)) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("invalid %s: value cannot be empty", optionName)
	}
	var normalized []string
	terminated := false
	for line := range strings.SplitSeq(raw, "\n") {
		if hasControlOrLineSepChar(line) {
			return "", fmt.Errorf("invalid %s %q: value contains invalid ASCII control character", optionName, line)
		}
		item := strings.TrimSpace(line)
		if item == "" {
			return "", fmt.Errorf("invalid %s: value cannot be empty", optionName)
		}
		norm, err := normalizeItem(item)
		if err != nil {
			return "", fmt.Errorf("invalid %s %q: %w", optionName, item, err)
		}
		if terminated {
			continue
		}
		if IsNoneValue(norm) {
			normalized = append(normalized, "none")
			terminated = true
			continue
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

func validateIdentityFiles(raw string) (string, error) {
	return normalizeMultiPathEntries("IdentityFile", raw, func(item string) (string, error) {
		setting, err := ParseIdentityPathSetting(item, true)
		if err != nil {
			return "", err
		}
		if setting.Unset() {
			return "", errors.New("value cannot be empty")
		}
		return setting.Raw, nil
	})
}

func validateCertificateFiles(raw string) (string, error) {
	return normalizeMultiPathEntries("CertificateFile", raw, func(item string) (string, error) {
		setting, err := ParseIdentityPathSetting(item, true)
		if err != nil {
			return "", err
		}
		if setting.Unset() {
			return "", errors.New("value cannot be empty")
		}
		return setting.Raw, nil
	})
}

func validateIdentityAgent(raw string) (string, error) {
	if hasControlOrLineSepChar(raw) {
		return "", fmt.Errorf("invalid IdentityAgent %q: contains invalid ASCII control character", raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("invalid IdentityAgent: value cannot be empty")
	}
	if strings.EqualFold(trimmed, "none") {
		return "none", nil
	}
	if trimmed == "SSH_AUTH_SOCK" {
		return "SSH_AUTH_SOCK", nil
	}
	if err := validateAgentSocketSyntax(trimmed, "IdentityAgent"); err != nil {
		return "", err
	}
	return trimmed, nil
}

func validateForwardAgent(raw string) (string, error) {
	if hasControlOrLineSepChar(raw) {
		return "", fmt.Errorf("invalid ForwardAgent %q: contains invalid ASCII control character", raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("invalid ForwardAgent: value cannot be empty")
	}
	switch strings.ToLower(trimmed) {
	case "yes", "true":
		return "yes", nil
	case "no", "false":
		return "no", nil
	}
	if trimmed == "SSH_AUTH_SOCK" {
		return "SSH_AUTH_SOCK", nil
	}
	if err := validateAgentSocketSyntax(trimmed, "ForwardAgent"); err != nil {
		return "", err
	}
	return trimmed, nil
}

func validateAgentSocketSyntax(rawPath, kind string) error {
	if strings.HasPrefix(rawPath, "$") && !strings.HasPrefix(rawPath, "${") {
		varName := rawPath[1:]
		if !isValidEnvIdentifier(varName) {
			return fmt.Errorf("invalid environment variable name %q in %s", rawPath, kind)
		}
		return nil
	}
	return validatePathTokenSyntax(rawPath, kind)
}

func hasControlOrLineSepChar(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

func hasMultiValueDelimiterOrLineBreak(s string) bool {
	for _, r := range s {
		switch r {
		case '\n', '\r', '\x00', '\u0085', '\u2028', '\u2029':
			return true
		}
	}
	return false
}

// ExpandHostName expands OpenSSH HostName tokens (%% -> % and %h -> originalHost)
// and rejects any other %x token, empty result, or control/line-separator characters.
func ExpandHostName(pattern, originalHost string) (string, error) {
	if hasControlOrLineSepChar(pattern) {
		return "", fmt.Errorf("HostName %q contains invalid ASCII control characters", pattern)
	}
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return "", errors.New("HostName cannot be empty")
	}
	origTrimmed := strings.TrimSpace(originalHost)

	var sb strings.Builder
	sb.Grow(len(trimmed))
	for i := 0; i < len(trimmed); i++ {
		ch := trimmed[i]
		if ch != '%' {
			sb.WriteByte(ch)
			continue
		}
		if i+1 >= len(trimmed) {
			return "", fmt.Errorf("trailing '%%' in HostName %q", pattern)
		}
		i++
		switch trimmed[i] {
		case '%':
			sb.WriteByte('%')
		case 'h':
			if hasControlOrLineSepChar(originalHost) {
				return "", fmt.Errorf("cannot expand %%h in HostName %q: original host contains invalid ASCII control characters", pattern)
			}
			if origTrimmed == "" {
				return "", fmt.Errorf("cannot expand %%h in HostName %q: original host is empty", pattern)
			}
			sb.WriteString(origTrimmed)
		default:
			return "", fmt.Errorf("unsupported token %%%c in HostName %q", trimmed[i], pattern)
		}
	}

	expanded := strings.TrimSpace(sb.String())
	if expanded == "" {
		return "", errors.New("expanded HostName cannot be empty")
	}
	if hasControlOrLineSepChar(expanded) {
		return "", fmt.Errorf("expanded HostName %q contains invalid ASCII control characters", expanded)
	}
	return expanded, nil
}

func validateRemoteCommandOption(raw string) (string, error) {
	if hasMultiValueDelimiterOrLineBreak(raw) {
		return "", errors.New("invalid RemoteCommand: value cannot contain null bytes or newlines")
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("invalid RemoteCommand: value cannot be empty")
	}
	if strings.EqualFold(trimmed, "none") {
		return "none", nil
	}
	return trimmed, nil
}

// ParseEscapeChar parses an OpenSSH EscapeChar specification:
//   - "none" (case-insensitive) -> (0, false, nil)
//   - "^A".."^Z" / "^a".."^z"   -> (upper-'@', true, nil)
//   - "^?"                      -> (0x7f, true, nil)
//   - single printable ASCII (0x21..0x7e) -> (b, true, nil)
//
// Any other input returns an error wrapping ErrSSHOptionsValidation.
func ParseEscapeChar(spec string) (ch byte, enabled bool, err error) {
	ch, enabled, _, err = parseEscapeCharNormalized(spec)
	if err != nil {
		return 0, false, fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	return ch, enabled, nil
}

func validateEscapeCharOption(raw string) (string, error) {
	_, _, norm, err := parseEscapeCharNormalized(raw)
	return norm, err
}

func parseEscapeCharNormalized(spec string) (byte, bool, string, error) {
	if hasControlOrLineSepChar(spec) {
		return 0, false, "", fmt.Errorf("invalid EscapeChar %q: contains invalid control character", spec)
	}
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return 0, false, "", fmt.Errorf("invalid EscapeChar %q: value cannot be empty", spec)
	}
	if IsNoneValue(trimmed) {
		return 0, false, "none", nil
	}
	if len(trimmed) == 1 {
		b := trimmed[0]
		if b >= 0x21 && b <= 0x7e {
			return b, true, trimmed, nil
		}
		return 0, false, "", fmt.Errorf("invalid EscapeChar %q: expected printable ASCII character, ^A-^Z, ^?, or none", spec)
	}
	if len(trimmed) == 2 && trimmed[0] == '^' {
		c := trimmed[1]
		if c == '?' {
			return 0x7f, true, "^?", nil
		}
		if c >= 'a' && c <= 'z' {
			c = c - 'a' + 'A'
		}
		if c >= 'A' && c <= 'Z' {
			return c - '@', true, "^" + string(c), nil
		}
		return 0, false, "", fmt.Errorf("invalid EscapeChar control sequence %q: expected ^A-^Z or ^?", spec)
	}
	return 0, false, "", fmt.Errorf("invalid EscapeChar %q: expected single character, ^A-^Z, ^?, or none", spec)
}

// ExpandRemoteCommand expands OpenSSH RemoteCommand percent tokens (%%, %C, %d, %h, %i,
// %l, %L, %n, %p, %r, %u) against env and target without mutating slashes or cleaning paths.
// Every referenced percent token is validated against control characters and shell
// metacharacters before interpolation to prevent remote command injection.
func ExpandRemoteCommand(pattern string, env Environment, target TargetContext) (string, error) {
	if hasMultiValueDelimiterOrLineBreak(pattern) {
		return "", errors.New("RemoteCommand cannot contain null bytes or line breaks")
	}
	trimmed := strings.TrimSpace(pattern)
	if trimmed == "" {
		return "", nil
	}
	if IsNoneValue(trimmed) {
		return "none", nil
	}

	tokens := buildRemoteCommandTokenMap(env, target)
	var sb strings.Builder
	sb.Grow(len(pattern) + 32)
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '%' {
			sb.WriteByte(pattern[i])
			continue
		}
		if i+1 >= len(pattern) {
			return "", errors.New("trailing '%' in RemoteCommand")
		}
		i++
		tok := pattern[i]
		repl, ok := tokens[tok]
		if !ok {
			return "", fmt.Errorf("unknown RemoteCommand token %%%c", tok)
		}
		if tok != '%' {
			if err := validateRemoteCommandToken(tok, repl); err != nil {
				return "", err
			}
		}
		sb.WriteString(repl)
	}
	expanded := sb.String()
	if hasMultiValueDelimiterOrLineBreak(expanded) {
		return "", errors.New("expanded RemoteCommand cannot contain null bytes or line breaks")
	}
	return expanded, nil
}

func validateRemoteCommandToken(tok byte, val string) error {
	if hasControlOrLineSepChar(val) {
		return fmt.Errorf("%w: %%%c %q contains invalid control character", ErrUnsafeExecToken, tok, val)
	}
	if tok == 'd' {
		return validateSafeRemoteHomeToken(val)
	}
	return ValidateSafeExecToken("%"+string(tok), val)
}

func validateSafeRemoteHomeToken(val string) error {
	if val == "" || len(val) > maxSafeHomeTokenLen || val[0] == '-' {
		return fmt.Errorf("%w: invalid %%d %q", ErrUnsafeExecToken, val)
	}
	if hasControlOrLineSepChar(val) {
		return fmt.Errorf("%w: %%d %q contains invalid control character", ErrUnsafeExecToken, val)
	}
	if strings.ContainsAny(val, ";|&$`()<>'\"") {
		return fmt.Errorf("%w: %%d %q contains disallowed shell metacharacter", ErrUnsafeExecToken, val)
	}
	return nil
}

func buildRemoteCommandTokenMap(env Environment, target TargetContext) map[byte]string {
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
	connHash := ComputeConnectionHash(env.LocalHost, host, portStr, remoteUser, NormalizeProxyJump(target.JumpHost))
	return map[byte]string{
		'%': "%",
		'C': connHash,
		'd': env.HomeDir,
		'h': host,
		'i': env.LocalUID,
		'l': env.LocalHost,
		'L': shortLocalHost,
		'n': origHost,
		'p': portStr,
		'r': remoteUser,
		'u': env.LocalUser,
	}
}

func normalizeOptionalDurationOption(name, raw string) (string, error) {
	if hasControlOrLineSepChar(raw) {
		return "", fmt.Errorf("invalid %s %q: contains invalid control character", name, raw)
	}
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

func newPreferredAuthenticationsOptionSpec() OptionSpec {
	supportedFn := func() []string {
		return []string{"publickey", "keyboard-interactive", "password"}
	}
	failClosed := []string{"gssapi-with-mic", "hostbased"}
	return OptionSpec{
		CanonicalKey:          OptionPreferredAuthentications,
		OpenSSHName:           "PreferredAuthentications",
		Class:                 OptionClassAuth,
		MergeMode:             OptionMergeFirstWins,
		ConfigSyntax:          OptionSyntaxStrictScalar,
		Tier4Policy:           OptionTier4Inherit,
		StrictInOpenSSHConfig: true,
		MuxPolicy:             OptionMuxAllow,
		AllowList:             true,
		SupportedTokens:       supportedFn,
		FailClosedTokens:      failClosed,
		Normalize: func(raw string) (string, error) {
			return normalizePreferredAuthentications(raw, supportedFn(), failClosed)
		},
	}
}

func newAlgorithmOptionSpec(
	canonicalKey, openSSHName string,
	defaultsFn func() []string,
	insecureFn func() []string,
) OptionSpec {
	supportedFn := func() []string {
		return allSupportedAlgorithms(defaultsFn(), insecureFn())
	}
	return OptionSpec{
		CanonicalKey:          canonicalKey,
		OpenSSHName:           openSSHName,
		Class:                 OptionClassTransport,
		MergeMode:             OptionMergeFirstWins,
		ConfigSyntax:          OptionSyntaxStrictScalar,
		Tier4Policy:           OptionTier4Inherit,
		StrictInOpenSSHConfig: true,
		MuxPolicy:             OptionMuxAllow,
		AllowList:             true,
		SupportedTokens:       supportedFn,
		Normalize: func(raw string) (string, error) {
			return normalizeAlgorithmSpec(openSSHName, raw, defaultsFn(), supportedFn())
		},
	}
}

func normalizePreferredAuthentications(raw string, supported, failClosed []string) (string, error) {
	if hasControlOrLineSepChar(raw) {
		return "", fmt.Errorf("invalid PreferredAuthentications %q: contains invalid control character", raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("invalid PreferredAuthentications: value cannot be empty")
	}
	parts := strings.Split(trimmed, ",")
	var normalized []string
	for _, p := range parts {
		token := strings.ToLower(strings.TrimSpace(p))
		if !slices.Contains(supported, token) && !slices.Contains(failClosed, token) {
			return "", fmt.Errorf("invalid PreferredAuthentications method %q", p)
		}
		if !slices.Contains(normalized, token) {
			normalized = append(normalized, token)
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

func isValidAlgorithmName(algo string) bool {
	if algo == "" {
		return false
	}
	for i := 0; i < len(algo); i++ {
		c := algo[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '@' {
			continue
		}
		return false
	}
	return true
}

func normalizeAlgorithmSpec(name, raw string, defaults, supported []string) (string, error) {
	if hasControlOrLineSepChar(raw) {
		return "", fmt.Errorf("invalid %s %q: contains invalid control character", name, raw)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("invalid %s: value cannot be empty", name)
	}
	checkSpec := trimmed
	var prefix string
	var modifier byte
	if checkSpec[0] == '+' || checkSpec[0] == '-' || checkSpec[0] == '^' {
		modifier = checkSpec[0]
		prefix = checkSpec[:1]
		checkSpec = strings.TrimSpace(checkSpec[1:])
	}
	if checkSpec == "" {
		return "", fmt.Errorf("invalid %s %q: empty algorithm list", name, raw)
	}
	var cleanAlgos []string
	for part := range strings.SplitSeq(checkSpec, ",") {
		algo := strings.TrimSpace(part)
		if algo == "" {
			return "", fmt.Errorf("invalid %s %q: empty algorithm name in list", name, raw)
		}
		if !isValidAlgorithmName(algo) {
			return "", fmt.Errorf("invalid %s %q: invalid algorithm name %q", name, raw, algo)
		}
		if modifier != '-' && !slices.Contains(supported, algo) {
			return "", fmt.Errorf("invalid %s %q: unsupported algorithm %q", name, raw, algo)
		}
		cleanAlgos = append(cleanAlgos, algo)
	}
	rebuilt := prefix + strings.Join(cleanAlgos, ",")
	if _, err := ResolveAlgorithmList(rebuilt, defaults); err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", name, raw, err)
	}
	return rebuilt, nil
}

func supportedListTokens(canonicalKey string) (supported, failClosed []string, ok bool) {
	spec, found := LookupOptionSpec(canonicalKey)
	if !found || spec.SupportedTokens == nil {
		return nil, nil, false
	}
	return spec.SupportedTokens(), slices.Clone(spec.FailClosedTokens), true
}

// FilterSupportedListValue filters a comma-separated option value (for algorithm lists
// or PreferredAuthentications) down to tokens supported by this implementation.
// Used when leniently parsing ~/.ssh/config so OpenSSH-only algorithms (such as
// sntrup761x25519-sha512@openssh.com or umac-128-etm@openssh.com) do not reject the
// remaining supported algorithms.
//
// For PreferredAuthentications, implemented methods ("publickey", "keyboard-interactive",
// "password") are kept when any are present; if only recognized unimplemented OpenSSH
// methods ("gssapi-with-mic", "hostbased") are present, those tokens are retained so
// authentication fails closed instead of falling back to defaults.
func FilterSupportedListValue(canonicalKey, raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	spec, found := LookupOptionSpec(canonicalKey)
	if !found || spec.SupportedTokens == nil {
		return raw
	}
	supported := spec.SupportedTokens()
	failClosedAuth := spec.FailClosedTokens

	var prefix string
	body := trimmed
	if spec.CanonicalKey != OptionPreferredAuthentications && (body[0] == '+' || body[0] == '-' || body[0] == '^') {
		prefix = body[:1]
		body = strings.TrimSpace(body[1:])
	}
	var kept, keptFailClosed []string
	for part := range strings.SplitSeq(body, ",") {
		tok := strings.TrimSpace(part)
		if spec.CanonicalKey == OptionPreferredAuthentications {
			tok = strings.ToLower(tok)
		}
		if tok == "" {
			continue
		}
		if (prefix == "-" && isValidAlgorithmName(tok)) || slices.Contains(supported, tok) {
			if !slices.Contains(kept, tok) {
				kept = append(kept, tok)
			}
			continue
		}
		if slices.Contains(failClosedAuth, tok) && !slices.Contains(keptFailClosed, tok) {
			keptFailClosed = append(keptFailClosed, tok)
		}
	}
	if len(kept) == 0 {
		return strings.Join(keptFailClosed, ",")
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
	if hasControlOrLineSepChar(rawPath) {
		return fmt.Errorf("ControlPath %q contains invalid ASCII control character", rawPath)
	}
	if rawPath == "" || IsNoneValue(rawPath) {
		return nil
	}
	return validatePathTokenSyntax(rawPath, "ControlPath")
}

func validateLiteralControlPath(rawPath string) error {
	if hasControlOrLineSepChar(rawPath) {
		return fmt.Errorf("invalid ControlPath %q: contains invalid ASCII control character", rawPath)
	}
	if strings.TrimSpace(rawPath) == "" {
		return errors.New("invalid ControlPath: value cannot be empty")
	}
	return nil
}

func validatePathTokenSyntax(rawPath, kind string) error {
	for i := 0; i < len(rawPath); {
		if rawPath[i] == '$' && i+1 < len(rawPath) && rawPath[i+1] == '{' {
			relEnd := strings.IndexByte(rawPath[i+2:], '}')
			if relEnd < 0 {
				return fmt.Errorf("unclosed environment variable in %s: %q", kind, rawPath[i:])
			}
			end := i + 2 + relEnd
			varName := rawPath[i+2 : end]
			if varName == "" || !isValidEnvIdentifier(varName) {
				return fmt.Errorf("invalid environment variable name ${%s} in %s", varName, kind)
			}
			i = end + 1
			continue
		}
		if rawPath[i] == '%' {
			if i+1 >= len(rawPath) {
				return fmt.Errorf("trailing '%%' in %s", kind)
			}
			switch rawPath[i+1] {
			case '%', 'h', 'p', 'r', 'n', 'u', 'l', 'L', 'i', 'd', 'j', 'C':
			default:
				return fmt.Errorf("unknown %s token %%%c", kind, rawPath[i+1])
			}
			i += 2
			continue
		}
		i++
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
	values map[string]string `digest:"include"`
	// ImplicitTier4 is true when multiplexing was resolved solely from ~/.ssh/config
	// without any CLI flag or xops node/global configuration.
	ImplicitTier4 bool `json:"-" yaml:"-" digest:"include"`
	// LiteralControlPath marks OptionControlPath as an already-expanded literal
	// socket path so Validate and resolution skip ~, ${VAR}, and % token parsing.
	LiteralControlPath bool `json:"-" yaml:"-" digest:"include"`
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
	opts := &Options{
		ImplicitTier4:      ctrl.ImplicitTier4,
		LiteralControlPath: ctrl.Path != "" && !IsNoneValue(ctrl.Path) && ctrl.LiteralPath,
	}
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
		ImplicitTier4:      o.ImplicitTier4,
		LiteralControlPath: o.LiteralControlPath,
	}
	if len(o.values) > 0 {
		cloned.values = make(map[string]string, len(o.values))
		for k, v := range o.values {
			cloned.values[k] = v
		}
	}
	return cloned
}

func (o *Options) hasEffectiveLiteralControlPath() bool {
	if o == nil || !o.LiteralControlPath {
		return false
	}
	path := o.ControlPath()
	return strings.TrimSpace(path) != "" && !IsNoneValue(path)
}

// Equal reports whether two Options contain identical key-value pairs and effective control-path mode.
func (o *Options) Equal(other *Options) bool {
	if o.IsEmpty() && other.IsEmpty() {
		return true
	}
	if o.IsEmpty() || other.IsEmpty() {
		return false
	}
	if o.hasEffectiveLiteralControlPath() != other.hasEffectiveLiteralControlPath() {
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
	if rawValue == "" {
		o.Delete(spec.CanonicalKey)
		return nil
	}
	normalized, err := spec.Normalize(rawValue)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	if spec.CanonicalKey == OptionControlPath {
		o.LiteralControlPath = false
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
	if o == nil {
		return
	}
	if spec, ok := LookupOptionSpec(key); ok {
		if spec.CanonicalKey == OptionControlPath {
			o.LiteralControlPath = false
		}
		if len(o.values) == 0 {
			return
		}
		delete(o.values, spec.CanonicalKey)
	} else {
		if key == OptionControlPath {
			o.LiteralControlPath = false
		}
		if len(o.values) == 0 {
			return
		}
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
	if o != nil {
		o.LiteralControlPath = false
	}
	o.setRaw(OptionControlPath, path)
}

// SetLiteralControlPath sets ControlPath directly as a pre-expanded literal
// path (bypassing ~, ${VAR}, and % token validation/expansion).
func (o *Options) SetLiteralControlPath(path string) error {
	if o == nil {
		return fmt.Errorf("%w: options receiver is nil", ErrSSHOptionsValidation)
	}
	if path == "" {
		o.Delete(OptionControlPath)
		return nil
	}
	if err := validateLiteralControlPath(path); err != nil {
		return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	if IsNoneValue(path) {
		o.LiteralControlPath = false
		o.setRaw(OptionControlPath, "none")
		return nil
	}
	o.LiteralControlPath = true
	o.setRaw(OptionControlPath, path)
	return nil
}

// ControlPersist returns the configured ControlPersist, or "" if unset.
func (o *Options) ControlPersist() string {
	return o.Get(OptionControlPersist)
}

// SetControlPersist sets the ControlPersist directly.
func (o *Options) SetControlPersist(persist string) {
	o.setRaw(OptionControlPersist, persist)
}

// ControlPathSetting parses the configured ControlPath into its typed domain representation.
func (o *Options) ControlPathSetting() (ControlPathSetting, error) {
	if o.IsEmpty() {
		return ControlPathSetting{Kind: ControlPathUnset}, nil
	}
	return ParseControlPathSetting(o.ControlPath(), o.LiteralControlPath)
}

// PersistSetting parses the configured ControlPersist into its typed domain representation.
func (o *Options) PersistSetting() (PersistSetting, error) {
	if o.IsEmpty() {
		return PersistSetting{Kind: PersistUnset}, nil
	}
	return ParsePersistSetting(o.ControlPersist())
}

// ControlConfig extracts the normalized multiplexing ControlConfig view from o,
// or returns nil if no multiplexing options are present.
func (o *Options) ControlConfig() *ControlConfig {
	ctrl, err := o.projectControl(false)
	if err != nil {
		return nil
	}
	return ctrl
}

// ValidatedControlConfig projects and validates the effective multiplexing
// ControlConfig from o. It shares the single canonical projection engine with
// ControlConfig() and ValidateEffective():
//   - "none" (case-insensitive) ControlPath disables multiplexing (Master=no, Persist="").
//   - ControlMaster, ControlPath, and ControlPersist syntax are validated via typed settings.
//   - Active ControlMaster modes and enabled PersistSetting values require a concrete ControlPath
//     (explicit PersistNo values "no"/"false" do not require ControlPath).
//   - Enabled ControlPersist cannot be combined with ControlMaster="no" (or unset).
//   - Returns (nil, nil) when multiplexing is completely unconfigured.
func (o *Options) ValidatedControlConfig() (*ControlConfig, error) {
	return o.projectControl(true)
}

func (o *Options) projectControl(validateEffective bool) (*ControlConfig, error) {
	mux, err := o.prepareProjectedMux(validateEffective)
	if err != nil || mux.IsEmpty() {
		return nil, err
	}

	pathSetting, pathErr := mux.ControlPathSetting()
	if validateEffective && pathErr != nil {
		return nil, pathErr
	}
	if pathSetting.Disabled() || IsNoneValue(mux.ControlPath()) {
		return &ControlConfig{
			Master:        ControlMasterNo,
			Path:          "none",
			ImplicitTier4: mux.ImplicitTier4,
		}, nil
	}

	master, err := parseProjectedControlMaster(mux.ControlMaster(), validateEffective)
	if err != nil {
		return nil, err
	}
	persistSetting, persistErr := mux.PersistSetting()
	if validateEffective && persistErr != nil {
		return nil, persistErr
	}

	if validateEffective {
		if master == ControlMasterNo && pathSetting.Unset() && !persistSetting.Explicit() {
			return nil, nil
		}
		if err := validateProjectedControl(master, pathSetting, persistSetting); err != nil {
			return nil, err
		}
	}

	effectivePath := mux.ControlPath()
	if pathErr == nil && pathSetting.Enabled() {
		effectivePath = pathSetting.Raw
	}
	return &ControlConfig{
		Master:        master,
		Path:          effectivePath,
		LiteralPath:   mux.LiteralControlPath && pathSetting.Kind == ControlPathLiteral,
		Persist:       strings.TrimSpace(mux.ControlPersist()),
		ImplicitTier4: mux.ImplicitTier4,
	}, nil
}

func (o *Options) prepareProjectedMux(validateEffective bool) (*Options, error) {
	rawMux := o.FilterByClasses(OptionClassMux)
	if rawMux.IsEmpty() {
		return nil, nil
	}
	if validateEffective && !rawMux.ImplicitTier4 {
		if err := rawMux.validateControlLayerInvariants(); err != nil {
			return nil, err
		}
	}
	return finalizeEffectiveOptions(rawMux), nil
}

func parseProjectedControlMaster(raw ControlMasterMode, validateEffective bool) (ControlMasterMode, error) {
	if raw == "" {
		if validateEffective {
			return ControlMasterNo, nil
		}
		return "", nil
	}
	parsed, err := ParseControlMasterMode(string(raw))
	if err != nil {
		if validateEffective {
			return "", err
		}
		return raw, nil
	}
	return parsed, nil
}

func validateProjectedControl(master ControlMasterMode, pathSetting ControlPathSetting, persistSetting PersistSetting) error {
	if pathSetting.Kind == ControlPathLiteral {
		if _, err := (&ControlConfig{Path: pathSetting.Raw, LiteralPath: true}).ResolvePath(Environment{}, TargetContext{}); err != nil {
			return err
		}
	}
	return validateEffectiveControlSetting(master, pathSetting, persistSetting)
}

func validateEffectiveControlSetting(master ControlMasterMode, pathSetting ControlPathSetting, persistSetting PersistSetting) error {
	if isActiveControlMaster(string(master)) && !pathSetting.Enabled() {
		return fmt.Errorf("ControlMaster %q requires non-empty ControlPath", master)
	}
	if persistSetting.Enabled() && !pathSetting.Enabled() {
		return errors.New("ControlPath is required when ControlPersist is configured")
	}
	if master == ControlMasterNo && persistSetting.Enabled() {
		return fmt.Errorf("ControlPersist %q cannot be specified when ControlMaster is 'no'", persistSetting.Raw)
	}
	return nil
}

// ConnectionWideOptions returns a new Options containing only entries declared
// OptionScopeConnectionWide in the option registry (propagated across ProxyJump chains).
func (o *Options) ConnectionWideOptions() *Options {
	if o.IsEmpty() {
		return nil
	}
	res := &Options{}
	for k, v := range o.values {
		spec, ok := LookupOptionSpec(k)
		if !ok || !spec.IsConnectionWide() {
			continue
		}
		res.setRaw(k, v)
	}
	if res.IsEmpty() {
		return nil
	}
	return res
}

// AddressFamily returns the normalized AddressFamily ("any", "inet", "inet6"), or "" if unset.
func (o *Options) AddressFamily() string {
	return o.Get(OptionAddressFamily)
}

// DialNetwork maps AddressFamily to Go's net dial/listen network string:
// "inet" -> "tcp4", "inet6" -> "tcp6", nil/empty/"any" -> "tcp".
func (o *Options) DialNetwork() string {
	switch o.AddressFamily() {
	case AddressFamilyInet:
		return "tcp4"
	case AddressFamilyInet6:
		return "tcp6"
	default:
		return "tcp"
	}
}

// IdentityFiles returns all configured IdentityFile entries in order, trimmed and non-empty.
func (o *Options) IdentityFiles() []string {
	entries := o.GetAll(OptionIdentityFile)
	if len(entries) == 0 {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// IdentityFile returns the first configured IdentityFile entry, or "" if unset.
func (o *Options) IdentityFile() string {
	files := o.IdentityFiles()
	if len(files) == 0 {
		return ""
	}
	return files[0]
}

// CertificateFiles returns all configured CertificateFile entries in order, trimmed and non-empty.
func (o *Options) CertificateFiles() []string {
	entries := o.GetAll(OptionCertificateFile)
	if len(entries) == 0 {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// IdentityAgent returns the configured IdentityAgent specification, or "" if unset.
func (o *Options) IdentityAgent() string {
	return o.Get(OptionIdentityAgent)
}

// ForwardAgent returns the configured ForwardAgent specification, or "" if unset.
func (o *Options) ForwardAgent() string {
	return o.Get(OptionForwardAgent)
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

// SendEnvPatterns returns all configured SendEnv pattern tokens in evaluation order, or nil if unset.
func (o *Options) SendEnvPatterns() []string {
	entries := o.GetAll(OptionSendEnv)
	if len(entries) == 0 {
		return nil
	}
	var out []string
	for _, entry := range entries {
		for tok := range strings.FieldsSeq(entry) {
			out = append(out, tok)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// SetEnvDirectives returns all configured SetEnv directives in evaluation order, or nil if unset.
func (o *Options) SetEnvDirectives() []string {
	entries := o.GetAll(OptionSetEnv)
	if len(entries) == 0 {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// RemoteCommand returns the configured RemoteCommand (or "none"), or "" if unset.
func (o *Options) RemoteCommand() string {
	return o.Get(OptionRemoteCommand)
}

// EscapeChar returns the normalized EscapeChar specification (or "none"), or "" if unset.
func (o *Options) EscapeChar() string {
	return o.Get(OptionEscapeChar)
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
			if spec.CanonicalKey == OptionControlPath {
				res.LiteralControlPath = o.LiteralControlPath && !IsNoneValue(v)
			}
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
			if spec.CanonicalKey == OptionControlPath {
				o.LiteralControlPath = false
			}
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
		if k == OptionControlPath && o.LiteralControlPath {
			if err := validateLiteralControlPath(v); err != nil {
				return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
			}
			continue
		}
		spec, ok := LookupOptionSpec(k)
		if !ok {
			return fmt.Errorf("%w: unknown ssh option %q", ErrSSHOptionsValidation, k)
		}
		if _, err := spec.Normalize(v); err != nil {
			return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
	}

	return o.validateControlLayerInvariants()
}

func (o *Options) validateControlLayerInvariants() error {
	if o.IsEmpty() {
		return nil
	}
	var parsedMaster ControlMasterMode
	if rawMaster := o.ControlMaster(); rawMaster != "" {
		parsed, err := ParseControlMasterMode(string(rawMaster))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		parsedMaster = parsed
	}
	persistSetting, err := o.PersistSetting()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	pathSetting, err := o.ControlPathSetting()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}

	if parsedMaster == ControlMasterNo && persistSetting.Enabled() {
		return fmt.Errorf("%w: ControlPersist %q cannot be specified when ControlMaster is 'no'", ErrSSHOptionsValidation, o.ControlPersist())
	}

	if pathSetting.Disabled() && isActiveControlMaster(string(parsedMaster)) {
		return fmt.Errorf("%w: ControlPath cannot be 'none' when ControlMaster is %q", ErrSSHOptionsValidation, o.ControlMaster())
	}

	if pathSetting.Disabled() && persistSetting.Enabled() {
		return fmt.Errorf("%w: ControlPath cannot be 'none' when ControlPersist is %q", ErrSSHOptionsValidation, o.ControlPersist())
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
	master := ControlMasterNo
	if rawMaster := o.ControlMaster(); rawMaster != "" {
		parsed, err := ParseControlMasterMode(string(rawMaster))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		master = parsed
	}
	pathSetting, err := o.ControlPathSetting()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	persistSetting, err := o.PersistSetting()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
	}
	if err := validateEffectiveControlSetting(master, pathSetting, persistSetting); err != nil {
		return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
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
// according to each registered OptionSpec's MergeMode, without applying cross-field
// effective finalization:
//   - OptionMergeFirstWins: highest-priority layer wins.
//   - OptionMergeAppendDedup: appends normalized entries in order, deduplicating identical entries.
//   - OptionMergeNoneTerminated: appends normalized entries in order, truncating at "none".
//   - OptionMergeOrderedEnv / OptionMergeSingleDirectiveOrderedEnv: merges lowest-to-highest
//     without dropping repeated entries so higher-tier exclusions and overrides win left-to-right.
func MergeOptionLayers(layers ...*Options) *Options {
	res := &Options{}
	hasExplicitPersist := false
	hasImplicitTier4 := false
	noneTerminated := make(map[string]bool, 2)
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
		mergeOptionLayerValues(res, layer, noneTerminated)
	}
	for i := len(layers) - 1; i >= 0; i-- {
		layer := layers[i]
		if layer.IsEmpty() {
			continue
		}
		for _, spec := range optionRegistry {
			if !spec.MergeMode.IsOrderedOverride() {
				continue
			}
			if v, ok := layer.values[spec.CanonicalKey]; ok && v != "" {
				res.appendOrderedRaw(spec.CanonicalKey, v)
			}
		}
	}
	if res.IsEmpty() {
		return nil
	}
	res.ImplicitTier4 = !hasExplicitPersist && hasImplicitTier4
	return res
}

func mergeOptionLayerValues(res, layer *Options, noneTerminated map[string]bool) {
	for k, v := range layer.values {
		if spec, ok := LookupOptionSpec(k); ok {
			switch spec.MergeMode {
			case OptionMergeOrderedEnv, OptionMergeSingleDirectiveOrderedEnv:
				continue
			case OptionMergeNoneTerminated:
				if !noneTerminated[spec.CanonicalKey] && res.appendNoneTerminatedRaw(spec.CanonicalKey, v) {
					noneTerminated[spec.CanonicalKey] = true
				}
				continue
			case OptionMergeAppendDedup:
				res.appendNormalizedRaw(spec.CanonicalKey, v)
				continue
			}
		}
		if _, exists := res.values[k]; !exists {
			res.setRaw(k, v)
			if k == OptionControlPath {
				res.LiteralControlPath = layer.LiteralControlPath && !IsNoneValue(v)
			}
		}
	}
}

// appendNoneTerminatedRaw appends normalized newline-delimited entries for IdentityFile or
// CertificateFile, stopping at the first "none" sentinel. If "none" is the very first entry
// for canonicalKey, "none" is stored; if concrete entries already precede "none", those
// concrete entries are kept without "none". Returns true when a "none" terminator was seen.
func (o *Options) appendNoneTerminatedRaw(canonicalKey, normalized string) bool {
	if normalized == "" {
		return false
	}
	existing := o.GetAll(canonicalKey)
	terminated := false
	for item := range strings.SplitSeq(normalized, "\n") {
		if item == "" {
			continue
		}
		if IsNoneValue(item) {
			if len(existing) == 0 {
				existing = append(existing, "none")
			}
			terminated = true
			break
		}
		if !slices.Contains(existing, item) {
			existing = append(existing, item)
		}
	}
	if len(existing) > 0 {
		o.setRaw(canonicalKey, strings.Join(existing, "\n"))
	}
	return terminated
}

func finalizeEffectiveOptions(opts *Options) *Options {
	if opts.IsEmpty() {
		return nil
	}
	if IsNoneValue(opts.ControlPath()) {
		opts.SetControlPath("none")
		opts.SetControlMaster(ControlMasterNo)
		opts.Delete(OptionControlPersist)
		opts.LiteralControlPath = false
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

// MergeEffectiveOptions resolves a hierarchy of Options from highest priority to
// lowest priority via EffectiveOptions and validates the resulting effective
// option set (including cross-field constraints) via ValidateEffective.
func MergeEffectiveOptions(layers ...*Options) (*Options, error) {
	for _, layer := range layers {
		if layer.IsEmpty() || layer.ImplicitTier4 {
			continue
		}
		if err := layer.validateControlLayerInvariants(); err != nil {
			return nil, err
		}
	}
	eff, err := EffectiveOptions(layers...)
	if err != nil {
		return nil, err
	}
	if eff.IsEmpty() {
		return nil, nil
	}
	if err := eff.ValidateEffective(); err != nil {
		return nil, err
	}
	return eff, nil
}

// SplitOptionKeyValue parses an OpenSSH -o directive into its key and value tokens.
// It supports "Key=Value", "Key Value", and "Key = Value" syntax, matching standard
// OpenSSH -o CLI argument conventions.
func SplitOptionKeyValue(opt string) (key, val string, err error) {
	opt = strings.TrimSpace(opt)
	if opt == "" {
		return "", "", nil
	}
	eqIdx := strings.IndexByte(opt, '=')
	wsIdx := strings.IndexAny(opt, " \t")
	if eqIdx >= 0 && (wsIdx == -1 || eqIdx < wsIdx) {
		key = strings.TrimSpace(opt[:eqIdx])
		val = strings.TrimSpace(opt[eqIdx+1:])
		if key == "" {
			return "", "", fmt.Errorf("%w: invalid -o option format (expected Key=Value): %q", ErrSSHOptionsValidation, opt)
		}
		return key, val, nil
	}
	if wsIdx > 0 {
		key = strings.TrimSpace(opt[:wsIdx])
		val = strings.TrimSpace(opt[wsIdx+1:])
		if strings.HasPrefix(val, "=") {
			val = strings.TrimSpace(strings.TrimPrefix(val, "="))
		}
		if key == "" {
			return "", "", fmt.Errorf("%w: invalid -o option format (expected Key=Value): %q", ErrSSHOptionsValidation, opt)
		}
		return key, val, nil
	}
	return "", "", fmt.Errorf("%w: invalid -o option format (expected Key=Value): %q", ErrSSHOptionsValidation, opt)
}

// ProjectCLIOptions deterministically projects o in optionRegistry order to
// OpenSSH CLI "-o" strings ("<OpenSSHName>=<value>").
//
// Multi-value options emit one "<OpenSSHName>=<entry>" per non-empty line,
// except SetEnv (OptionMergeSingleDirectiveOrderedEnv), which flattens all
// layers with last-value-wins preserving first-appearance position (without
// applying the session denylist) into a single canonical
// SetEnv="K1=V1" "K2=V2" directive so re-parsing via ParseCLIOptions is
// lossless and idempotent.
func ProjectCLIOptions(o *Options) []string {
	if o.IsEmpty() {
		return nil
	}
	var out []string
	for _, spec := range optionRegistry {
		val, ok := o.values[spec.CanonicalKey]
		if !ok || val == "" {
			continue
		}
		switch spec.MergeMode {
		case OptionMergeSingleDirectiveOrderedEnv:
			out = appendProjectedSetEnv(out, spec.OpenSSHName, o.GetAll(spec.CanonicalKey))
		case OptionMergeAppendDedup, OptionMergeNoneTerminated, OptionMergeOrderedEnv:
			for _, entry := range o.GetAll(spec.CanonicalKey) {
				if entry != "" {
					out = append(out, spec.OpenSSHName+"="+entry)
				}
			}
		default:
			out = append(out, spec.OpenSSHName+"="+val)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func appendProjectedSetEnv(out []string, openSSHName string, directives []string) []string {
	flattened, err := flattenSetEnvDirectives(directives)
	if err == nil {
		if formatted := formatCanonicalSetEnvDirective(flattened); formatted != "" {
			return append(out, openSSHName+"="+formatted)
		}
		return out
	}
	for _, entry := range directives {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			out = append(out, openSSHName+"="+trimmed)
		}
	}
	return out
}

// ParseCLIOptions parses OpenSSH CLI "-o" option strings into a single Options
// layer according to each registered OptionSpec's MergeMode.
//
// Unknown keys and target-level directives (Port, User, HostName, ProxyJump)
// are rejected. Every directive's syntax is validated even when an earlier
// directive has already won for FirstWins or SingleDirectiveOrderedEnv options.
func ParseCLIOptions(optionStrings []string) (*Options, error) {
	if len(optionStrings) == 0 {
		return nil, nil
	}
	opts := &Options{}
	seen := make(map[string]bool)
	for _, raw := range optionStrings {
		key, val, err := SplitOptionKeyValue(raw)
		if err != nil {
			return nil, err
		}
		if key == "" {
			continue
		}
		spec, ok := LookupOptionSpec(key)
		if !ok {
			return nil, fmt.Errorf("%w: unsupported -o option %q", ErrSSHOptionsValidation, key)
		}
		if val == "" {
			return nil, fmt.Errorf("%w: invalid %s in -o option: value cannot be empty", ErrSSHOptionsValidation, spec.OpenSSHName)
		}
		if err := applyCLIOptionDirective(opts, seen, spec, val); err != nil {
			return nil, err
		}
	}
	if opts.IsEmpty() {
		return nil, nil
	}
	return opts, nil
}

func applyCLIOptionDirective(opts *Options, seen map[string]bool, spec OptionSpec, val string) error {
	switch spec.MergeMode {
	case OptionMergeFirstWins:
		normalized, err := spec.Normalize(val)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		if !seen[spec.CanonicalKey] {
			if spec.CanonicalKey == OptionControlPath {
				opts.LiteralControlPath = false
			}
			opts.setRaw(spec.CanonicalKey, normalized)
		}
		seen[spec.CanonicalKey] = true
		return nil
	case OptionMergeSingleDirectiveOrderedEnv:
		if hasMultiValueDelimiterOrLineBreak(val) || hasKnownHostsControlChar(val) {
			return fmt.Errorf("%w: invalid %s: value cannot contain newlines or control characters", ErrSSHOptionsValidation, spec.OpenSSHName)
		}
		normalized, err := spec.Normalize(val)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSSHOptionsValidation, err)
		}
		if !seen[spec.CanonicalKey] {
			opts.appendOrderedRaw(spec.CanonicalKey, normalized)
		}
		seen[spec.CanonicalKey] = true
		return nil
	case OptionMergeAppendDedup, OptionMergeNoneTerminated, OptionMergeOrderedEnv:
		return opts.Append(spec.CanonicalKey, val)
	default:
		return fmt.Errorf("%w: unsupported merge mode for %s", ErrSSHOptionsValidation, spec.OpenSSHName)
	}
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
			if spec.MultiValue {
				if strings.TrimSpace(elem.Value) == "" {
					return "", fmt.Errorf("invalid %s: list element cannot be empty", spec.OpenSSHName)
				}
				if hasMultiValueDelimiterOrLineBreak(elem.Value) {
					return "", fmt.Errorf("invalid %s: list element cannot contain newlines or control characters", spec.OpenSSHName)
				}
			} else if spec.AllowList && hasControlOrLineSepChar(elem.Value) {
				return "", fmt.Errorf("invalid %s: list element contains invalid control character", spec.OpenSSHName)
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
				for _, elem := range listVal {
					if strings.TrimSpace(elem) == "" {
						return "", fmt.Errorf("invalid %s: list element cannot be empty", spec.OpenSSHName)
					}
					if hasMultiValueDelimiterOrLineBreak(elem) {
						return "", fmt.Errorf("invalid %s: list element cannot contain newlines or control characters", spec.OpenSSHName)
					}
				}
				return strings.Join(listVal, "\n"), nil
			}
			for _, elem := range listVal {
				if hasControlOrLineSepChar(elem) {
					return "", fmt.Errorf("invalid %s: list element contains invalid control character", spec.OpenSSHName)
				}
			}
			return strings.Join(listVal, ","), nil
		}
	}
	return "", fmt.Errorf("invalid value format for %s", spec.OpenSSHName)
}
