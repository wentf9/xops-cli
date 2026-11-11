package cmd

import (
	"fmt"
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
	MasterCount   int      // -M count: 1 -> ControlMaster=yes, >=2 -> ControlMaster=ask
	ControlPath   string   // -S <path> or "none"
	CtlCmd        string   // -O <command>
	Options       []string // -o Key=Value options
	onOptionAdded func(string)
}

// RegisterSSHFlags registers -M, -S, -o, -O flags for xops ssh.
func (f *SSHControlFlags) RegisterSSHFlags(cmd *cobra.Command) {
	cmd.Flags().CountVarP(&f.MasterCount, "master", "M", i18n.T("flag_ssh_master"))
	cmd.Flags().StringVarP(&f.ControlPath, "control-path", "S", "", i18n.T("flag_ssh_control_path"))
	cmd.Flags().VarP(newOptionArrayFlagValue(&f.Options, func(val string) {
		if f.onOptionAdded != nil {
			f.onOptionAdded(val)
		}
	}), "option", "o", i18n.T("flag_ssh_option"))
	cmd.Flags().StringVarP(&f.CtlCmd, "control-command", "O", "", i18n.T("flag_ssh_control_command"))
}

// RegisterCommonFlags registers -S and -o flags for scp, sftp, and exec.
func (f *SSHControlFlags) RegisterCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.ControlPath, "control-path", "S", "", i18n.T("flag_ssh_control_path"))
	cmd.Flags().VarP(newOptionArrayFlagValue(&f.Options, func(val string) {
		if f.onOptionAdded != nil {
			f.onOptionAdded(val)
		}
	}), "option", "o", i18n.T("flag_ssh_option"))
}

// ToSessionControlOptions converts SSHControlFlags into adapter.SessionControlOptions.
// Precedence: explicit CLI flags (-M, -S) override values parsed from -o options.
func (f *SSHControlFlags) ToSessionControlOptions() (adapter.SessionControlOptions, error) {
	var sessionOpts adapter.SessionControlOptions

	// 1. Parse -o options first if provided
	if len(f.Options) > 0 {
		parsed, err := adapter.ParseOptionStrings(f.Options)
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
		if !strings.EqualFold(strings.TrimSpace(f.ControlPath), "none") && f.MasterCount == 0 && sessionOpts.Master == nil {
			sessionOpts.AllowReuse = true
		}
		sessionOpts.SetPath(f.ControlPath)
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
	if f.CtlCmd != "" {
		cmdLower := strings.ToLower(strings.TrimSpace(f.CtlCmd))
		if !validControlCommands[cmdLower] {
			return f.controlUsageError(fmt.Errorf("unknown control command %q (supported: check, exit, stop, forward, cancel, proxy, proxy-stream, conninfo, channels)", f.CtlCmd))
		}
		if f.MasterCount > 0 {
			return f.controlUsageError(fmt.Errorf("control command (-O) cannot be combined with master mode (-M)"))
		}
		if strings.TrimSpace(f.ControlPath) == "none" {
			return f.controlUsageError(fmt.Errorf("control command (-O) cannot be specified with -S none"))
		}
	}
	return nil
}

// controlUsageError tags a flag or combination failure of a control command with
// the OpenSSH exit status: every -O failure exits 255, including arguments that
// were rejected before the socket was contacted.
func (f *SSHControlFlags) controlUsageError(err error) error {
	if err == nil || strings.TrimSpace(f.CtlCmd) == "" {
		return err
	}
	return &ControlExitError{Code: 255, Message: err.Error()}
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
	return path != "" && path != "none"
}

func effectiveConnectionTarget(opts *SshOptions, nodeID string) config.ConnectionTarget {
	var target config.ConnectionTarget
	if opts != nil {
		target = opts.Target
		if strings.TrimSpace(target.Selector) == "" {
			target.Selector = strings.TrimSpace(opts.Host)
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

// controlSocketPath resolves and expands the effective control path for nodeID.
// It mirrors Connector.buildTargetContext so every caller expands %h/%p/%r/%j/%C
// against the same resolved target instead of raw CLI fields.
//
// nodeID may be empty for an ad-hoc host that resolves to no inventory node; the
// session/global/OpenSSH layers are still consulted and the expansion falls back
// to the CLI-supplied target.
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
	connTarget := effectiveConnectionTarget(opts, nodeID)
	target := controlTarget(opts, provider, nodeID)
	controlNodeID := resolveEffectiveControlNodeID(provider, nodeID, target.OriginalHost)
	ctrl, err := resolveControlConfig(provider, controlNodeID, connTarget.Selector, sessionOpts)
	if err != nil {
		return "", err
	}
	if ctrl == nil || ctrl.Path == "" || ctrl.Path == "none" {
		return "", nil
	}
	return ssh.ExpandControlPath(ctrl.Path, sshenv.Discover(), target)
}

func resolveEffectiveControlNodeID(provider config.ConfigProvider, nodeID, originalHost string) string {
	if originalHost == "" || originalHost == nodeID {
		return nodeID
	}
	if strings.HasPrefix(nodeID, config.OpenSSHNodePrefix) {
		alias := strings.TrimPrefix(nodeID, config.OpenSSHNodePrefix)
		if _, parsedHost, _, err := utils.ParseAddr(alias); err == nil && parsedHost != "" {
			alias = parsedHost
		}
		setProviderOpenSSHAlias(provider, originalHost, alias)
		return originalHost
	}
	if provider != nil {
		if baseNode, ok := provider.GetNode(nodeID); ok && baseNode.OpenSSHAlias != "" {
			setProviderOpenSSHAlias(provider, originalHost, baseNode.OpenSSHAlias)
		}
	}
	return originalHost
}

// resolveControlConfig resolves the effective multiplexing config for nodeID with
// the given session overrides. When the selector matches no inventory node the
// adapter still merges session, global, and OpenSSH layers, so an ad-hoc host is
// validated exactly like a managed one.
func resolveControlConfig(provider config.ConfigProvider, nodeID, selector string, sessionOpts adapter.SessionControlOptions) (*ssh.ControlConfig, error) {
	if provider == nil {
		if sessionOpts.IsEmpty() {
			return nil, nil
		}
		return ssh.EffectiveControl(mergeSessionControl(sessionOpts))
	}
	lookupKey := nodeID
	if lookupKey == "" {
		// ResolveControl treats an unknown selector as "no node layer" and falls
		// back to session > global > OpenSSH, which is the ad-hoc case.
		lookupKey = selector
	}
	return adapter.NewSSHAdapter(provider).ResolveControl(lookupKey, sessionOpts)
}

// mergeSessionControl converts session overrides into one ControlConfig layer.
func mergeSessionControl(sessionOpts adapter.SessionControlOptions) *ssh.ControlConfig {
	if opts := sessionOpts.ToSSHOptions(); opts != nil {
		if ctrl := opts.ControlConfig(); ctrl != nil {
			ctrl.AllowReuse = sessionOpts.AllowReuse && ctrl.Master == "" && ctrl.Path != "none"
			return ctrl
		}
	}
	ctrl := &ssh.ControlConfig{
		AllowReuse: sessionOpts.AllowReuse,
	}
	if sessionOpts.Master != nil {
		ctrl.Master = *sessionOpts.Master
		ctrl.AllowReuse = false
	}
	if sessionOpts.Path != nil {
		ctrl.Path = *sessionOpts.Path
		if ctrl.Path == "none" {
			ctrl.AllowReuse = false
		}
	}
	if sessionOpts.Persist != nil {
		ctrl.Persist = *sessionOpts.Persist
	}
	return ctrl
}

// controlTarget builds the token expansion context. The resolved target supplies
// address, port, user, and jump host; explicit CLI values still win, mirroring
// Connector.buildTargetContext.
func controlTarget(opts *SshOptions, provider config.ConfigProvider, nodeID string) ssh.TargetContext {
	connTarget := effectiveConnectionTarget(opts, nodeID)
	if strings.TrimSpace(connTarget.Selector) != "" {
		effectiveProvider := provider
		if effectiveProvider == nil {
			effectiveProvider = config.NewProviderWithoutOpenSSH(nil)
		}
		if resolved, err := config.ResolveTarget(effectiveProvider, connTarget); err == nil {
			return targetContextFromResolvedTarget(resolved)
		}
	}

	jump := strings.TrimSpace(connTarget.ProxyJump)
	if strings.EqualFold(jump, "none") {
		jump = ""
	}
	target := ssh.TargetContext{
		OriginalHost: connTarget.Selector,
		JumpHost:     jump,
	}
	if opts != nil {
		target.Host = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(opts.Host), "]"), "[")
		target.Port = int(opts.Port)
		target.User = opts.User
	}
	if connTarget.HasUser && connTarget.User != "" {
		target.User = connTarget.User
	}
	if connTarget.HasPort && connTarget.Port > 0 {
		target.Port = int(connTarget.Port)
	}
	if target.User == "" {
		target.User = sshenv.Discover().LocalUser
	}
	if target.Port <= 0 {
		target.Port = 22
	}
	return target
}

func targetContextFromResolvedTarget(resolved config.ResolvedTarget) ssh.TargetContext {
	user := resolved.User
	if user == "" {
		user = sshenv.Discover().LocalUser
	}
	port := int(resolved.Port)
	if port <= 0 {
		port = 22
	}
	orig := resolved.NodeID
	if orig == "" && resolved.Host != "" && user != "" && port > 0 {
		orig = config.FormatNodeID(user, resolved.Host, uint16(port))
	}
	return ssh.TargetContext{
		Host:         resolved.Host,
		Port:         port,
		User:         user,
		OriginalHost: orig,
		JumpHost:     resolved.ProxyJump,
		KeyPath:      resolved.KeyPath,
	}
}

// ApplyGeneralOptions parses non-multiplexing OpenSSH options from -o
// (such as Port, User, IdentityFile, ProxyJump) and applies them to SshOptions
// if they were not already explicitly set via primary CLI flags.
func ApplyGeneralOptions(opts *SshOptions, optionStrings []string, flags *pflag.FlagSet) error {
	for _, opt := range optionStrings {
		key, val, err := adapter.SplitOptionKeyValue(opt)
		if err != nil {
			return err
		}
		if key == "" {
			continue
		}

		switch strings.ToLower(key) {
		case "port":
			p, err := strconv.ParseUint(val, 10, 16)
			if err != nil || p == 0 {
				return fmt.Errorf("invalid Port in -o option: %q", val)
			}
			if shouldApplyGeneralOption(flags, "port", opts.Port == 0) {
				opts.Port = uint16(p)
			}
		case "user":
			if val == "" {
				return fmt.Errorf("invalid %s in -o option: value cannot be empty", key)
			}
			if shouldApplyGeneralOption(flags, "login", opts.User == "") {
				opts.User = val
			}
		case "identityfile":
			if val == "" {
				return fmt.Errorf("invalid %s in -o option: value cannot be empty", key)
			}
			if shouldApplyGeneralOption(flags, "identity", opts.IdentityFile == "") {
				opts.IdentityFile = val
			}
		case "proxyjump":
			if val == "" {
				return fmt.Errorf("invalid %s in -o option: value cannot be empty", key)
			}
			if shouldApplyGeneralOption(flags, "jump", opts.JumpHost == "") {
				opts.JumpHost = val
			}
		}
	}
	opts.appliedGeneralOpts = true
	return nil
}

func shouldApplyGeneralOption(flags *pflag.FlagSet, flagName string, unsetWhenProgrammatic bool) bool {
	if flags == nil {
		return unsetWhenProgrammatic
	}
	return !flags.Changed(flagName)
}
