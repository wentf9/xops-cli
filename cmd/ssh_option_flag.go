package cmd

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

// Environment markers shared with the detached background processes.
const (
	// sshBackgroundChildEnv marks the child that runs the real SSH session after
	// -f validates connectivity in the parent.
	sshBackgroundChildEnv = "XOPS_CLI_SSH_BG_CHILD"
	// sshMuxDaemonEnv marks the child that only serves a persistent control
	// socket, keeping the master alive after the foreground session ended.
	sshMuxDaemonEnv = "XOPS_CLI_SSH_MUX_DAEMON"
)

// Valid control commands for -O
var validControlCommands = map[string]bool{
	"check":        true,
	"exit":         true,
	"stop":         true,
	"forward":      true,
	"cancel":       true,
	"proxy":        true,
	"proxy-stream": true,
	"conninfo":     true,
	"channels":     true,
}

// SSHControlFlags encapsulates OpenSSH-compatible multiplexing and session control flags.
type SSHControlFlags struct {
	MasterCount        int      // -M count: 1 -> ControlMaster=yes, >=2 -> ControlMaster=ask
	ControlPath        string   // -S <path> or "none"
	CtlCmd             string   // -O <command>
	ConfigFile         string   // -F <configfile|none>
	AddressFamily      string   // -4 ("inet") or -6 ("inet6"), last flag wins
	Options            []string // -o Key=Value options
	controlPathLiteral bool
	ctlCmdSet          bool
	onOptionAdded      func(string)
}

type addressFamilyFlagValue struct {
	target *string
	value  string
}

func (v *addressFamilyFlagValue) String() string {
	if v == nil || v.target == nil {
		return "false"
	}
	return strconv.FormatBool(*v.target == v.value)
}

func (v *addressFamilyFlagValue) Set(s string) error {
	if v == nil || v.target == nil {
		return nil
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	if b {
		*v.target = v.value
	} else if *v.target == v.value {
		*v.target = ""
	}
	return nil
}

func (v *addressFamilyFlagValue) Type() string { return "bool" }

func (v *addressFamilyFlagValue) IsBoolFlag() bool { return true }

// RegisterSSHFlags registers -M, -S, -o, -O, -F, -4, -6 flags for xops ssh.
func (f *SSHControlFlags) RegisterSSHFlags(cmd *cobra.Command) {
	cmd.Flags().CountVarP(&f.MasterCount, "master", "M", i18n.T("flag_ssh_master"))
	cmd.Flags().StringVarP(&f.ControlPath, "control-path", "S", "", i18n.T("flag_ssh_control_path"))
	cmd.Flags().VarP(newOptionArrayFlagValue(&f.Options, func(val string) {
		if f.onOptionAdded != nil {
			f.onOptionAdded(val)
		}
	}), "option", "o", i18n.T("flag_ssh_option"))
	cmd.Flags().StringVarP(&f.CtlCmd, "control-command", "O", "", i18n.T("flag_ssh_control_command"))
	cmd.Flags().StringVarP(&f.ConfigFile, "config-file", "F", "", i18n.T("flag_ssh_config_file"))
	f.RegisterAddressFamilyFlags(cmd)
}

// RegisterCommonFlags registers -S, -o, -F flags for scp, sftp, and exec.
func (f *SSHControlFlags) RegisterCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.ControlPath, "control-path", "S", "", i18n.T("flag_ssh_control_path"))
	cmd.Flags().VarP(newOptionArrayFlagValue(&f.Options, func(val string) {
		if f.onOptionAdded != nil {
			f.onOptionAdded(val)
		}
	}), "option", "o", i18n.T("flag_ssh_option"))
	cmd.Flags().StringVarP(&f.ConfigFile, "config-file", "F", "", i18n.T("flag_ssh_config_file"))
}

// RegisterAddressFamilyFlags registers -4/--ipv4 and -6/--ipv6 with last-flag-wins semantics.
func (f *SSHControlFlags) RegisterAddressFamilyFlags(cmd *cobra.Command) {
	cmd.Flags().VarP(&addressFamilyFlagValue{target: &f.AddressFamily, value: "inet"}, "ipv4", "4", i18n.T("flag_ipv4"))
	cmd.Flags().VarP(&addressFamilyFlagValue{target: &f.AddressFamily, value: "inet6"}, "ipv6", "6", i18n.T("flag_ipv6"))
}

// ToSessionControlOptions converts SSHControlFlags into adapter.SessionControlOptions.
// Precedence: explicit CLI flags (-M, -S) override values parsed from -o options.
func (f *SSHControlFlags) ToSessionControlOptions() (adapter.SessionControlOptions, error) {
	return f.ToSessionControlOptionsWithJump("")
}

// ToSessionControlOptionsWithJump converts SSHControlFlags into adapter.SessionControlOptions
// while preserving precedence against an explicit CLI -J / --jump override.
func (f *SSHControlFlags) ToSessionControlOptionsWithJump(cliJump string) (adapter.SessionControlOptions, error) {
	var sessionOpts adapter.SessionControlOptions

	// 1. Parse -o options first if provided
	if len(f.Options) > 0 {
		parsed, err := adapter.ParseOptionStringsWithJump(f.Options, cliJump)
		if err != nil {
			return sessionOpts, err
		}
		sessionOpts = parsed
	}

	// 2. Command-line -M flag overrides any ControlMaster from -o
	if f.MasterCount == 1 {
		sessionOpts.SetMaster(ssh.ControlMasterYes)
	} else if f.MasterCount >= 2 {
		sessionOpts.SetMaster(ssh.ControlMasterAsk)
	}

	// 3. Command-line -S flag overrides any ControlPath from -o
	if f.ControlPath != "" {
		controlPath := f.ControlPath
		if ssh.IsNoneValue(controlPath) {
			controlPath = "none"
		} else if f.MasterCount == 0 && !sessionOpts.HasExplicitMaster() {
			sessionOpts.AllowReuse = true
		}
		if f.controlPathLiteral && controlPath != "none" {
			sessionOpts.SetLiteralPath(controlPath)
		} else {
			sessionOpts.SetPath(controlPath)
		}
	}

	// 4. Command-line -4 / -6 flag overrides any AddressFamily from -o
	if f.AddressFamily != "" {
		if err := sessionOpts.SetAddressFamily(f.AddressFamily); err != nil {
			return sessionOpts, err
		}
	}

	return sessionOpts, nil
}

// Validate validates control flags and detects conflicting combinations.
func (f *SSHControlFlags) Validate() error {
	// Reject unknown or malformed -o values here, before a command resolves or
	// prepares a node. Path resolution alone would skip them whenever -S is given
	// and an explicit control socket short-circuits the merged configuration.
	if _, err := f.ToSessionControlOptions(); err != nil {
		return f.controlUsageError(err)
	}
	if f.ctlCmdSet || f.CtlCmd != "" {
		cmdLower := strings.ToLower(strings.TrimSpace(f.CtlCmd))
		if !validControlCommands[cmdLower] {
			return f.controlUsageError(fmt.Errorf("unknown control command %q (supported: check, exit, stop, forward, cancel, proxy, proxy-stream, conninfo, channels)", f.CtlCmd))
		}
		if f.MasterCount > 0 {
			return f.controlUsageError(fmt.Errorf("control command (-O) cannot be combined with master mode (-M)"))
		}
		if ssh.IsNoneValue(f.ControlPath) {
			return f.controlUsageError(fmt.Errorf("control command (-O) cannot be specified with -S none"))
		}
	}
	return nil
}

// controlUsageError tags a flag or combination failure of a control command with
// the OpenSSH exit status: every -O failure exits 255, including arguments that
// were rejected before the socket was contacted.
func (f *SSHControlFlags) controlUsageError(err error) error {
	if err == nil || f == nil || (!f.ctlCmdSet && f.CtlCmd == "") {
		return err
	}
	var control *ControlExitError
	if errors.As(err, &control) {
		return err
	}
	return &ControlExitError{Code: 255, Message: err.Error(), Err: err}
}

// ControlCommandWithoutTarget reports whether -O addresses an explicit -S socket
// and therefore does not need a destination argument. Without -S the socket can
// only be derived from a resolved node or an inventory/global default.
// Note that `-O proxy` opens a multiplexed session and always requires a target
// destination (matching OpenSSH `ssh -O proxy`), whereas `-O proxy-stream` and
// management queries can address `-S` directly without a target.
func (f *SSHControlFlags) ControlCommandWithoutTarget() bool {
	cmdLower := strings.ToLower(strings.TrimSpace(f.CtlCmd))
	if cmdLower == "" || cmdLower == "proxy" {
		return false
	}
	path := strings.TrimSpace(f.ControlPath)
	return path != "" && !ssh.IsNoneValue(path)
}

func effectiveConnectionTarget(opts *SshOptions, nodeID string) config.ConnectionTarget {
	var target config.ConnectionTarget
	if opts != nil {
		target = opts.Target
		if strings.TrimSpace(target.Selector) == "" {
			target.Selector = strings.TrimSpace(opts.Host)
		}
		if strings.TrimSpace(target.OriginalHost) == "" && strings.TrimSpace(opts.originalHost) != "" {
			target.OriginalHost = strings.TrimSpace(opts.originalHost)
		}
		if strings.TrimSpace(opts.User) != "" && (!target.HasUser || target.User != strings.TrimSpace(opts.User)) {
			target.User = strings.TrimSpace(opts.User)
			target.HasUser = true
		}
		if opts.Port > 0 && (!target.HasPort || target.Port != opts.Port) {
			target.Port = opts.Port
			target.HasPort = true
		}
		if strings.TrimSpace(opts.JumpHost) != "" && (!target.HasProxyJump || target.ProxyJump != strings.TrimSpace(opts.JumpHost)) {
			target.ProxyJump = strings.TrimSpace(opts.JumpHost)
			target.HasProxyJump = true
		}
	}
	if strings.TrimSpace(target.Selector) == "" && strings.TrimSpace(nodeID) != "" {
		target.Selector = strings.TrimSpace(nodeID)
	}
	return target
}

func buildControlTargetRequest(
	opts *SshOptions,
	provider config.ConfigProvider,
	nodeID string,
	connTarget config.ConnectionTarget,
	sessionOpts adapter.SessionControlOptions,
) adapter.ControlTargetRequest {
	req := adapter.ControlTargetRequest{
		Provider:       provider,
		NodeID:         nodeID,
		Target:         connTarget,
		SessionControl: sessionOpts,
	}
	if opts != nil {
		req.FallbackHost = opts.Host
		req.FallbackPort = opts.Port
		req.FallbackUser = opts.User
		req.ApplyTargetNodeOverrides = isTargetControlNode(opts, nodeID)
		req.OverrideOriginalHost = opts.originalHost
		if expandedHost, err := opts.effectiveHostName(); err == nil {
			req.OverrideExpandedHost = expandedHost
		}
		req.CanonicalOriginalHost, req.CanonicalHost = canonicalControlOriginAndHost(opts)
	}
	return req
}

// controlSocketPath resolves and expands the effective control path for nodeID.
// It delegates to adapter.ResolveControlSocketPath so every caller expands
// %h/%p/%r/%n/%j/%C against the same canonical TargetContext as Connector.
func controlSocketPath(opts *SshOptions, provider config.ConfigProvider, nodeID string) (string, error) {
	if opts == nil {
		return "", nil
	}
	if err := opts.ensureGeneralOptionsApplied(); err != nil {
		return "", err
	}
	sessionOpts, err := opts.toSessionControlOptions()
	if err != nil {
		return "", err
	}
	if provider != nil {
		opts.syncResolvedTargetHosts(provider)
	}
	req := buildControlTargetRequest(opts, provider, nodeID, effectiveConnectionTarget(opts, nodeID), sessionOpts)
	expanded, _, err := adapter.ResolveControlSocketPath(req)
	return expanded, err
}

// resolveControlSessionLookup computes the effective adapter lookup key and
// SessionAuth metadata purely from caller inputs and read-only provider lookups
// without mutating any provider state.
func resolveControlSessionLookup(
	opts *SshOptions,
	provider config.ConfigProvider,
	nodeID string,
	connTarget config.ConnectionTarget,
	target ssh.TargetContext,
) (string, adapter.SessionAuth) {
	req := buildControlTargetRequest(opts, provider, nodeID, connTarget, adapter.SessionControlOptions{})
	if opts != nil {
		req.Target.ProxyJump = strings.TrimSpace(opts.JumpHost)
	}
	return adapter.ResolveControlSessionLookup(req, target)
}

// controlTarget builds the canonical token expansion context by delegating to
// adapter.ResolveControlTarget, mirroring Connector.buildTargetContext.
func controlTarget(opts *SshOptions, provider config.ConfigProvider, nodeID string) ssh.TargetContext {
	var sessionOpts adapter.SessionControlOptions
	if opts != nil {
		if provider != nil {
			opts.syncResolvedTargetHosts(provider)
		}
		if parsed, err := opts.toSessionControlOptions(); err == nil {
			sessionOpts = parsed
		}
	}
	req := buildControlTargetRequest(opts, provider, nodeID, effectiveConnectionTarget(opts, nodeID), sessionOpts)
	return adapter.ResolveControlTarget(req).Target
}

func isTargetControlNode(opts *SshOptions, nodeID string) bool {
	if opts == nil {
		return false
	}
	if nodeID == "" || len(opts.targetNodeIDs) == 0 {
		return true
	}
	return slices.Contains(opts.targetNodeIDs, nodeID)
}

func defaultLocalUser() string {
	return sshenv.Discover().LocalUser
}

type generalOptionState struct {
	allowPort     bool
	allowUser     bool
	allowIdentity bool
	allowJump     bool
	allowHostName bool
	seenPort      bool
	seenUser      bool
	seenJump      bool
	seenProxyCmd  bool
	seenHostName  bool
}

// ApplyGeneralOptions parses non-multiplexing OpenSSH options from -o
// (such as Port, User, IdentityFile, ProxyJump) and applies them to SshOptions
// if they were not already explicitly set via primary CLI flags.
func validateExplicitNonEmptyFlags(flags *pflag.FlagSet) error {
	if flags == nil {
		return nil
	}
	for _, name := range []string{"cipher", "escape-char", "control-path", "config-file", "login", "jump", "control-command"} {
		f := flags.Lookup(name)
		if f == nil || !f.Changed || f.Value.Type() != "string" {
			continue
		}
		val, err := flags.GetString(name)
		if err == nil && strings.TrimSpace(val) == "" {
			if name == "control-command" {
				return (&SSHControlFlags{CtlCmd: val, ctlCmdSet: true}).controlUsageError(fmt.Errorf("unknown control command %q (supported: check, exit, stop, forward, cancel, proxy, proxy-stream, conninfo, channels)", val))
			}
			return fmt.Errorf("flag --%s must not be empty", name)
		}
	}
	if f := flags.Lookup("identity"); f != nil && f.Changed {
		return validateNonEmptyIdentityFlag(f, flags)
	}
	return nil
}

func validateCLIAlias(alias string) error {
	if alias == "" {
		return nil
	}
	if err := config.ValidateNodeAlias(alias); err != nil {
		return err
	}
	if strings.Contains(alias, "@") || strings.Contains(alias, ":") {
		return errors.New(i18n.T("ssh_err_alias_invalid"))
	}
	return nil
}

func validateNonEmptyIdentityFlag(f *pflag.Flag, flags *pflag.FlagSet) error {
	switch f.Value.Type() {
	case "stringArray":
		vals, err := flags.GetStringArray("identity")
		if err == nil && (len(vals) == 0 || slices.ContainsFunc(vals, func(v string) bool { return strings.TrimSpace(v) == "" })) {
			return fmt.Errorf("flag --identity (-i) must not be empty")
		}
	case "stringSlice":
		vals, err := flags.GetStringSlice("identity")
		if err == nil && (len(vals) == 0 || slices.ContainsFunc(vals, func(v string) bool { return strings.TrimSpace(v) == "" })) {
			return fmt.Errorf("flag --identity (-i) must not be empty")
		}
	case "string":
		val, err := flags.GetString("identity")
		if err == nil && strings.TrimSpace(val) == "" {
			return fmt.Errorf("flag --identity (-i) must not be empty")
		}
	}
	return nil
}

// normalizeCLIIdentityFlagPath validates and converts plain relative or ~/ paths
// from CLI -i to absolute paths while preserving % tokens and ${VAR} placeholders
// without CWD mangling. Unlike -o IdentityFile=none, literal -i none resolves to
// <cwd>/none matching OpenSSH ssh.c add_identity_file().
func normalizeCLIIdentityFlagPath(raw string) (string, error) {
	setting, err := ssh.ParseIdentityPathSetting(raw, false)
	if err != nil {
		return "", fmt.Errorf("invalid --identity (-i) path: %w", err)
	}
	if setting.Unset() {
		return "", nil
	}
	if setting.IsTemplate() {
		return setting.Raw, nil
	}
	return utils.ToAbsolutePath(setting.Raw), nil
}

func ApplyGeneralOptions(opts *SshOptions, optionStrings []string, flags *pflag.FlagSet) error {
	if err := validateExplicitNonEmptyFlags(flags); err != nil {
		return err
	}
	opts.syncIdentityFiles()
	if flags != nil && flags.Changed("identity") && len(opts.IdentityFiles) > 0 {
		normalized := make([]string, 0, len(opts.IdentityFiles))
		persistable := ""
		for _, k := range opts.IdentityFiles {
			norm, err := normalizeCLIIdentityFlagPath(k)
			if err != nil {
				return err
			}
			if norm != "" {
				normalized = append(normalized, norm)
				if persistable == "" && config.IsPersistableIdentityPath(norm) {
					persistable = norm
				}
			}
		}
		opts.IdentityFiles = normalized
		opts.IdentityFile = persistable
	}
	allowJump := shouldApplyGeneralOption(flags, "jump", opts.JumpHost == "")
	st := generalOptionState{
		allowPort:     shouldApplyGeneralOption(flags, "port", opts.Port == 0),
		allowUser:     shouldApplyGeneralOption(flags, "login", opts.User == ""),
		allowIdentity: true,
		allowJump:     allowJump,
		allowHostName: opts.cliHostName == "" && opts.HostName == "",
	}
	for _, opt := range optionStrings {
		key, val, err := ssh.SplitOptionKeyValue(opt)
		if err != nil {
			return err
		}
		if key == "" {
			continue
		}
		if err := applyGeneralOption(opts, &st, key, val); err != nil {
			return err
		}
	}
	opts.appliedGeneralOpts = true
	return nil
}

func applyGeneralOption(opts *SshOptions, st *generalOptionState, key, val string) error {
	switch ssh.CanonicalOptionKey(key) {
	case ssh.OptionPort:
		p, err := strconv.ParseUint(val, 10, 16)
		if err != nil || p == 0 {
			return fmt.Errorf("invalid Port in -o option: %q", val)
		}
		if st.allowPort && !st.seenPort {
			opts.Port = uint16(p)
		}
		st.seenPort = true
	case ssh.OptionUser:
		if val == "" {
			return fmt.Errorf("invalid %s in -o option: value cannot be empty", key)
		}
		if st.allowUser && !st.seenUser {
			opts.User = val
		}
		st.seenUser = true
	case ssh.OptionIdentityFile:
		return applyIdentityFileGeneralOption(opts, st, key, val)
	case ssh.OptionProxyJump:
		return applyProxyJumpGeneralOption(opts, st, key, val)
	case ssh.OptionProxyCommand:
		return applyProxyCommandGeneralOption(st, key, val)
	case ssh.OptionHostName:
		return applyHostNameOption(opts, st, key, val)
	}
	return nil
}

func applyIdentityFileGeneralOption(opts *SshOptions, _ *generalOptionState, key, val string) error {
	setting, err := ssh.ParseIdentityPathSetting(val, true)
	if err != nil {
		return fmt.Errorf("invalid %s in -o option: %w", key, err)
	}
	if setting.Unset() {
		return fmt.Errorf("invalid %s in -o option: value cannot be empty", key)
	}
	opts.IdentityFiles = append(opts.IdentityFiles, val)
	opts.identityFromCLIOptions = true
	if opts.IdentityFile == "" && config.IsPersistableIdentityPath(val) {
		opts.IdentityFile = val
	}
	return nil
}

func applyProxyJumpGeneralOption(opts *SshOptions, st *generalOptionState, key, val string) error {
	if val == "" {
		return fmt.Errorf("invalid %s in -o option: value cannot be empty", key)
	}
	if st.allowJump && !st.seenJump && (!st.seenProxyCmd || !ssh.HasActiveProxyJump(val)) {
		opts.JumpHost = val
	}
	st.seenJump = true
	return nil
}

func applyProxyCommandGeneralOption(st *generalOptionState, key, val string) error {
	if val == "" {
		return fmt.Errorf("invalid %s in -o option: value cannot be empty", key)
	}
	var scratch ssh.Options
	if err := scratch.Set(ssh.OptionProxyCommand, val); err != nil {
		return fmt.Errorf("invalid ProxyCommand in -o option: %w", err)
	}
	if !st.seenJump {
		st.seenProxyCmd = true
	}
	return nil
}

func applyHostNameOption(opts *SshOptions, st *generalOptionState, key, val string) error {
	if val == "" {
		return fmt.Errorf("invalid %s in -o option: value cannot be empty", key)
	}
	if _, expErr := ssh.ExpandHostName(val, "host"); expErr != nil {
		return expErr
	}
	if st.allowHostName && !st.seenHostName {
		opts.cliHostName = val
		if orig := opts.originalHostForExpansion(); orig != "" {
			if expanded, expErr := ssh.ExpandHostName(val, orig); expErr == nil {
				opts.HostName = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(expanded), "]"), "[")
			}
		}
	}
	st.seenHostName = true
	return nil
}

func shouldApplyGeneralOption(flags *pflag.FlagSet, flagName string, unsetWhenProgrammatic bool) bool {
	if flags == nil {
		return unsetWhenProgrammatic
	}
	return !flags.Changed(flagName)
}
