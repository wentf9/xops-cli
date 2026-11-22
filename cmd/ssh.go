package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wentf9/xops-cli/cmd/utils"
	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/verdict"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

type SshOptions struct {
	interaction            *cliInteractionHandler
	diagnostic             sshDiagnosticOptions
	diagnostics            corelog.DiagnosticObserver
	control                SSHControlFlags
	Host                   string
	originalHost           string
	expandHost             string
	canonicalized          bool
	canonicalResolver      config.CanonicalResolver
	syncedTargetHosts      bool
	HostName               string
	cliHostName            string
	nonHostArgs            bool
	Port                   uint16
	User                   string
	Password               string
	PasswordStdin          bool
	OTP                    string
	OTPStdin               bool
	IdentityFile           string
	IdentityFiles          []string
	identityFromCLIOptions bool
	CipherSpec             string
	Passphrase             string
	PassphraseStdin        bool
	Remember               string
	Sudo                   bool
	Alias                  string
	JumpHost               string
	Tags                   []string
	LocalForwards          []string
	RemoteForwards         []string
	NoCmd                  bool
	Subsystem              bool
	EscapeCharSpec         string
	ForwardAgentSpec       string
	GatewayPorts           bool
	DynamicForward         string
	DynamicForwards        []string
	StdioForward           string
	stdioForwardSet        bool
	TunnelDevice           string
	tunnelDeviceSet        bool
	DisableTTY             bool
	ForceTTYCount          int
	cliTTYMode             ssh.RequestTTYMode
	cliTunnelMode          string
	cliTunnelLockedByW     bool
	BgRun                  bool
	StdinRedirect          bool
	args                   []string
	dashIdx                int
	parsedArgs             bool
	appliedGeneralOpts     bool
	stdinRedirected        bool
	isParentValidation     bool
	muxDaemonSpecFD        int
	muxDaemonMode          bool
	bgChildSpecFD          int
	bgChildMode            bool
	preserveDaemonSelector bool
	hostFromPositional     bool

	Target config.ConnectionTarget

	Command      string
	stdinScript  bool
	NoLoginShell bool

	execution           execExecutionOptions
	commandPlan         *ssh.CommandPlan
	effectiveSSHOptions *ssh.Options
	resolvedTarget      *ssh.TargetContext
	targetNodeIDs       []string
}

func NewSshOptions() *SshOptions {
	return &SshOptions{
		Sudo:            false,
		NoLoginShell:    false,
		dashIdx:         -1,
		muxDaemonSpecFD: -1,
		bgChildSpecFD:   -1,
	}
}

func NewCmdSsh() *cobra.Command {
	return newCmdSshWithOptions(NewSshOptions())
}

func newCmdSshWithOptions(o *SshOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh [user@]host[:port]",
		Short: i18n.T("ssh_short"),
		Long:  i18n.T("ssh_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Complete(cmd, args); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}
			return o.RunContext(cmd.Context())
		},
	}
	o.diagnostic.register(cmd)
	o.control.RegisterSSHFlags(cmd)
	// OpenSSH-compatible flags
	cmd.Flags().Uint16VarP(&o.Port, "port", "p", 0, i18n.T("flag_port"))
	cmd.Flags().StringVarP(&o.User, "login", "l", "", i18n.T("flag_login"))
	cmd.Flags().StringArrayVarP(&o.IdentityFiles, "identity", "i", nil, i18n.T("flag_identity"))
	cmd.Flags().StringVarP(&o.CipherSpec, "cipher", "c", "", i18n.T("flag_ssh_cipher"))
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "J", "", i18n.T("flag_jump"))
	cmd.Flags().StringArrayVarP(&o.LocalForwards, "local-forward", "L", []string{}, i18n.T("flag_local_forward"))
	cmd.Flags().StringArrayVarP(&o.RemoteForwards, "remote-forward", "R", []string{}, i18n.T("flag_remote_forward"))
	cmd.Flags().BoolVarP(&o.NoCmd, "no-cmd", "N", false, i18n.T("flag_no_cmd"))
	cmd.Flags().BoolVarP(&o.Subsystem, "subsystem", "s", false, i18n.T("flag_ssh_subsystem"))
	cmd.Flags().StringVarP(&o.EscapeCharSpec, "escape-char", "e", "", i18n.T("flag_ssh_escape_char"))
	cmd.Flags().VarP(&addressFamilyFlagValue{target: &o.ForwardAgentSpec, value: "yes"}, "forward-agent", "A", i18n.T("flag_ssh_forward_agent"))
	cmd.Flags().VarP(&addressFamilyFlagValue{target: &o.ForwardAgentSpec, value: "no"}, "no-forward-agent", "a", i18n.T("flag_ssh_no_forward_agent"))
	o.registerForwardAndSessionFlags(cmd)
	cmd.Flags().BoolVarP(&o.BgRun, "background", "f", false, i18n.T("flag_background"))
	cmd.Flags().BoolVarP(&o.StdinRedirect, "stdin-redirect", "n", false, i18n.T("flag_stdin_redirect"))

	// xops-enhanced flags (long-form only, no short flags to avoid OpenSSH conflicts)
	registerSelectorFlag(cmd.Flags(), &o.Host, "host", "", i18n.T("flag_host"))
	cmd.Flags().BoolVar(&o.PasswordStdin, "password-stdin", false, i18n.T("flag_password_stdin"))
	cmd.Flags().BoolVar(&o.PassphraseStdin, "passphrase-stdin", false, i18n.T("flag_passphrase_stdin"))
	cmd.Flags().StringVar(&o.OTP, "otp", "", i18n.T("flag_otp"))
	cmd.Flags().BoolVar(&o.OTPStdin, "otp-stdin", false, i18n.T("flag_otp_stdin"))
	cmd.Flags().StringVar(&o.Remember, "remember", "", i18n.T("flag_remember"))
	cmd.Flags().BoolVar(&o.Sudo, "sudo", false, i18n.T("flag_sudo"))
	cmd.Flags().StringVar(&o.Alias, "alias", "", i18n.T("flag_alias"))
	registerSelectorSliceFlag(cmd.Flags(), &o.Tags, "tag", i18n.T("flag_tag"))
	o.execution.register(cmd)
	cmd.Flags().BoolVar(&o.NoLoginShell, "no-login", false, i18n.T("flag_exec_no_login"))
	cmd.Flags().IntVar(&o.muxDaemonSpecFD, muxDaemonSpecFDFlag, -1, "")
	_ = cmd.Flags().MarkHidden(muxDaemonSpecFDFlag)
	cmd.Flags().IntVar(&o.bgChildSpecFD, bgChildSpecFDFlag, -1, "")
	_ = cmd.Flags().MarkHidden(bgChildSpecFDFlag)

	cmd.MarkFlagsMutuallyExclusive("otp", "otp-stdin")

	return cmd
}

func (o *SshOptions) readSecretsFromStdin() (bool, error) {
	return readCLISecretsFromStdin(o)
}

// canonicalIdentityFileSlice normalizes a CLI identity-file list through
// core/ssh.PathList so the first "none" sentinel truncates subsequent entries
// while preserving the sentinel for downstream cross-tier merging.
func canonicalIdentityFileSlice(keys []string) []string {
	if len(keys) == 0 {
		return nil
	}
	pl, err := ssh.ParsePathListItems(keys)
	if err != nil {
		return slices.Clone(keys)
	}
	if pl.IsUnset() {
		return nil
	}
	return strings.Split(pl.String(), "\n")
}

func (o *SshOptions) syncIdentityFiles() {
	if o == nil {
		return
	}
	if len(o.IdentityFiles) > 0 {
		o.IdentityFiles = canonicalIdentityFileSlice(o.IdentityFiles)
		if o.IdentityFile == "" && config.ValidatePersistableIdentityPath(o.IdentityFiles[0]) == nil {
			o.IdentityFile = o.IdentityFiles[0]
		}
	} else if o.IdentityFile != "" {
		o.IdentityFiles = canonicalIdentityFileSlice([]string{o.IdentityFile})
	}
}

func (o *SshOptions) effectiveIdentityFiles() []string {
	if o == nil {
		return nil
	}
	o.syncIdentityFiles()
	if len(o.IdentityFiles) > 0 {
		return append([]string(nil), o.IdentityFiles...)
	}
	if o.IdentityFile != "" {
		return []string{o.IdentityFile}
	}
	return nil
}

// normalizeCLIIdentityPath converts plain relative or ~/ paths to absolute paths
// while preserving "none" and token/env-bearing patterns (%d, ${VAR}) for core/ssh.
func normalizeCLIIdentityPath(raw string) string {
	setting, err := ssh.ParseIdentityPathSetting(raw, true)
	if err != nil {
		if strings.TrimSpace(raw) == "" {
			return ""
		}
		// Preserve invalid syntax/control chars verbatim so downstream core/ssh
		// option validation fails closed instead of mangling or dropping the entry.
		return raw
	}
	switch {
	case setting.Unset():
		return ""
	case setting.Disabled():
		return strings.TrimSpace(raw)
	case setting.IsTemplate():
		return setting.Raw
	default:
		return utils.ToAbsolutePath(setting.Raw)
	}
}

func (o *SshOptions) absIdentityFiles() []string {
	keys := o.effectiveIdentityFiles()
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if norm := normalizeCLIIdentityPath(k); norm != "" {
			out = append(out, norm)
		}
	}
	return out
}

func (o *SshOptions) effectiveCLIJumpHost() string {
	if o == nil {
		return ""
	}
	return strings.TrimSpace(o.JumpHost)
}

func (o *SshOptions) controlSessionOptions() (adapter.SessionControlOptions, error) {
	sessionOpts, err := o.control.ToSessionControlOptionsWithJump(o.effectiveCLIJumpHost())
	if err != nil {
		return sessionOpts, err
	}
	if o.identityFromCLIOptions && sessionOpts.Options != nil {
		sessionOpts.Options.Delete(ssh.OptionIdentityFile)
	}
	return sessionOpts, nil
}

func (o *SshOptions) originalHostForExpansion() string {
	if o == nil {
		return ""
	}
	if o.originalHost != "" {
		return o.originalHost
	}
	if s := strings.TrimSpace(o.Target.Selector); s != "" {
		return config.UnwrapOpenSSHSelector(s)
	}
	if s := strings.TrimSpace(o.Host); s != "" && !strings.Contains(s, ",") {
		return config.UnwrapOpenSSHSelector(s)
	}
	if !o.nonHostArgs && len(o.args) > 0 {
		if _, h, _, err := utils.ParseAddr(o.args[0]); err == nil && h != "" {
			return config.UnwrapOpenSSHSelector(h)
		}
		return strings.TrimSpace(o.args[0])
	}
	return ""
}

func (o *SshOptions) effectiveHostName() (string, error) {
	if o == nil {
		return "", nil
	}
	if strings.TrimSpace(o.expandHost) != "" {
		return o.effectiveHostNameForHost(o.expandHost)
	}
	return o.effectiveHostNameForHost(o.originalHostForExpansion())
}

func (o *SshOptions) syncResolvedTargetHosts(provider config.ConfigProvider) {
	if o == nil || provider == nil {
		return
	}
	connTarget := effectiveConnectionTarget(o, "")
	selector := strings.TrimSpace(connTarget.Selector)
	if selector == "" {
		return
	}
	hasPresetOriginal := o.canonicalized || (o.originalHost != "" && !o.syncedTargetHosts)
	resolved, err := config.ResolveTarget(provider, connTarget)
	origHost, expandHost := resolveTargetOriginalAndExpandHosts(
		hasPresetOriginal,
		o.originalHost,
		selector,
		resolved,
		err == nil,
	)
	o.syncedTargetHosts = true
	if (!o.isMuxDaemon() && !hasPresetOriginal) || o.originalHost == "" {
		o.originalHost = origHost
	}
	if expandHost != "" {
		o.expandHost = expandHost
	}
}

func (o *SshOptions) effectiveHostNameForHost(host string) (string, error) {
	if o == nil {
		return "", nil
	}
	if o.cliHostName != "" {
		base := strings.TrimSpace(host)
		if base == "" {
			base = o.originalHostForExpansion()
		}
		expanded, err := ssh.ExpandHostName(o.cliHostName, base)
		if err != nil {
			return "", err
		}
		return strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(expanded), "]"), "["), nil
	}
	return strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(o.HostName), "]"), "["), nil
}

func (o *SshOptions) Complete(cmd *cobra.Command, args []string) error {
	o.args = args
	o.dashIdx = -1
	o.parsedArgs = false
	o.hostFromPositional = false
	o.appliedGeneralOpts = false
	var flags *pflag.FlagSet
	if cmd != nil {
		flags = cmd.Flags()
		o.dashIdx = cmd.ArgsLenAtDash()
	}
	o.control.ctlCmdSet = flags != nil && flags.Changed("control-command")
	if flags != nil && flags.Changed(muxDaemonSpecFDFlag) {
		if flags.Changed(bgChildSpecFDFlag) {
			return fmt.Errorf("--%s and --%s are mutually exclusive", muxDaemonSpecFDFlag, bgChildSpecFDFlag)
		}
		spec, err := readMuxDaemonSpecFromFD(o.muxDaemonSpecFD)
		if err != nil {
			return err
		}
		return o.applyMuxDaemonSpec(spec)
	}
	if flags != nil && flags.Changed(bgChildSpecFDFlag) {
		if _, err := readBgChildSpecFromFD(o.bgChildSpecFD); err != nil {
			return o.control.controlUsageError(err)
		}
		o.bgChildMode = true
	}
	if err := ApplyGeneralOptions(o, o.control.Options, flags); err != nil {
		return o.control.controlUsageError(err)
	}
	if err := validateExplicitZeroPort(flags); err != nil {
		return o.control.controlUsageError(err)
	}
	if _, err := o.toSessionControlOptions(); err != nil {
		return o.control.controlUsageError(err)
	}
	isChild := o.isBackgroundChild()
	ctlCmd := strings.ToLower(strings.TrimSpace(o.control.CtlCmd))
	if o.isMuxDaemon() || isChild || (ctlCmd != "" && ctlCmd != "proxy") {
		o.PasswordStdin = false
		o.PassphraseStdin = false
		o.OTPStdin = false
	}
	if o.isMuxDaemon() {
		// The detached master daemon re-executes the original command line, but it
		// only serves the control socket. Normalize before Complete reads stdin:
		// with stdio on /dev/null a --password-stdin read would fail the child and
		// silently break ControlPersist.
		o.normalizeForMuxDaemon()
		o.StdinRedirect = true
		return nil
	}
	o.execution.capturePresence(cmd)
	return o.completeStdinAndScriptInput(isChild, ctlCmd)
}

func (o *SshOptions) completeStdinAndScriptInput(isChild bool, ctlCmd string) error {
	if isChild || (ctlCmd != "" && ctlCmd != "proxy") {
		return nil
	}
	if err := o.validateCompleteStdinCredentials(); err != nil {
		return o.control.controlUsageError(err)
	}
	hadCredentialStdin, err := o.readSecretsFromStdin()
	if err != nil {
		return o.control.controlUsageError(err)
	}
	if !o.effectiveStdinNull() && !o.effectiveNoCmd() && !hadCredentialStdin && o.StdioForward == "" && !o.Subsystem {
		if stat, err := os.Stdin.Stat(); err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
			o.stdinScript = true
		}
	}
	return nil
}

func (o *SshOptions) validateCompleteStdinCredentials() error {
	bgRun, bgErr := o.effectiveBgRunChecked()
	if bgErr != nil {
		return bgErr
	}
	if bgRun && (o.PasswordStdin || o.PassphraseStdin || o.OTPStdin || o.OTP != "") {
		return errors.New("background mode (-f) cannot be combined with stdin or one-time credential flags (--password-stdin, --passphrase-stdin, --otp, --otp-stdin); configure key/agent auth or persistent credentials instead")
	}
	if o.PasswordStdin || o.PassphraseStdin || o.OTPStdin {
		return o.Validate()
	}
	return nil
}

func (o *SshOptions) parseArgs() error {
	return o.parseTarget(o.control.ControlCommandWithoutTarget())
}

func (o *SshOptions) parseTarget(allowMissingHost bool) error {
	hasUser := false
	var finalUser string
	hasPort := false
	var finalPort uint16
	finalHost := o.Host

	if o.User != "" {
		hasUser = true
		finalUser = o.User
	}
	if o.Port != 0 {
		hasPort = true
		finalPort = o.Port
	}

	rawSelector := finalHost
	if len(o.args) == 0 && finalHost == "" {
		if !allowMissingHost {
			return errors.New(i18n.T("ssh_err_no_host"))
		}
	} else if finalHost == "" && len(o.args) >= 1 {
		rawSelector = o.args[0]
		u, h, p, err := utils.ParseAddr(o.args[0])
		if err != nil {
			return err
		}
		finalHost, finalUser, hasUser, finalPort, hasPort = applyParsedAddr(finalHost, finalUser, hasUser, finalPort, hasPort, h, u, p)
	} else if finalHost != "" && !o.preserveDaemonSelector {
		u, h, p, err := utils.ParseAddr(finalHost)
		if err != nil {
			if config.IsOpenSSHNodeID(strings.TrimSpace(finalHost)) || strings.ContainsRune(finalHost, ',') {
				return err
			}
		} else if h != "" {
			finalHost, finalUser, hasUser, finalPort, hasPort = applyParsedAddr("", finalUser, hasUser, finalPort, hasPort, h, u, p)
		}
	}

	o.Host = finalHost
	o.User = finalUser
	o.Port = finalPort

	selector := finalHost
	trimmedRaw := strings.TrimSpace(rawSelector)
	if o.isMuxDaemon() && strings.Contains(trimmedRaw, "@") && strings.Contains(trimmedRaw, ":") {
		selector = trimmedRaw
	}

	hasJump := o.JumpHost != "" || o.isMuxDaemon()
	targetOrig := o.resolveTargetOriginalHost(selector)

	o.Target = config.ConnectionTarget{
		Selector:     selector,
		RawSelector:  trimmedRaw,
		OriginalHost: targetOrig,
		User:         finalUser,
		HasUser:      hasUser,
		Port:         finalPort,
		HasPort:      hasPort,
		ProxyJump:    o.JumpHost,
		HasProxyJump: hasJump,
	}
	return nil
}

func (o *SshOptions) resolveTargetOriginalHost(selector string) string {
	if targetOrig := strings.TrimSpace(o.Target.OriginalHost); targetOrig != "" {
		return targetOrig
	}
	if o.canonicalized && o.originalHost != "" {
		return o.originalHost
	}
	if o.isMuxDaemon() {
		if orig := strings.TrimSpace(o.originalHost); orig != "" && !strings.ContainsAny(orig, "@:") {
			cleanSelector := strings.TrimSpace(config.UnwrapOpenSSHSelector(selector))
			if !strings.EqualFold(orig, cleanSelector) {
				return orig
			}
		}
	}
	return ""
}

func applyParsedAddr(finalHost, finalUser string, hasUser bool, finalPort uint16, hasPort bool, h, u string, p uint16) (string, string, bool, uint16, bool) {
	if finalHost == "" && h != "" {
		finalHost = h
	}
	if !hasUser && u != "" {
		hasUser = true
		finalUser = u
	}
	if !hasPort && p != 0 {
		hasPort = true
		finalPort = p
	}
	return finalHost, finalUser, hasUser, finalPort, hasPort
}

func (o *SshOptions) ensureGeneralOptionsApplied() error {
	if o == nil || o.appliedGeneralOpts || len(o.control.Options) == 0 {
		return nil
	}
	return ApplyGeneralOptions(o, o.control.Options, nil)
}

func (o *SshOptions) ensureArgsParsed() error {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return err
	}
	if o.parsedArgs {
		return nil
	}
	// A flag-selected target leaves every positional token for the command.
	// When no --host flag was given, the first positional argument is always
	// the target host (including `xops ssh -- host cmd`).
	commandArgs := o.args
	fromPositional := o.Host == "" && len(commandArgs) > 0
	if fromPositional {
		commandArgs = commandArgs[1:]
	}
	if err := o.parseArgs(); err != nil {
		return err
	}
	o.parsedArgs = true
	o.hostFromPositional = fromPositional
	if o.isMuxDaemon() {
		// parseArgs rebuilds the target from the preserved positional arguments, so
		// the daemon normalization above must be re-applied before the command
		// boundary is turned back into an executable command.
		o.normalizeForMuxDaemon()
		commandArgs = nil
	}
	if o.Command == "" && len(commandArgs) > 0 {
		o.Command = strings.Join(commandArgs, " ")
		if o.Command == "" {
			return fmt.Errorf("explicit SSH command must not be empty")
		}
	}
	return nil
}

func (o *SshOptions) Validate() error {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return o.control.controlUsageError(err)
	}
	if err := o.control.Validate(); err != nil {
		return err
	}
	if o.isMuxDaemon() {
		// Validate runs after Complete and would otherwise rebuild a command from
		// the preserved positional arguments that the daemon must never execute.
		o.normalizeForMuxDaemon()
	}
	if err := validateCommonSSHBaseOptions(o); err != nil {
		return o.control.controlUsageError(err)
	}
	if err := o.ensureArgsParsed(); err != nil {
		return o.control.controlUsageError(err)
	}
	if err := o.validateForwardAndSessionFlags(); err != nil {
		return o.control.controlUsageError(err)
	}
	ctlCmd := strings.ToLower(strings.TrimSpace(o.control.CtlCmd))
	if ctlCmd != "" && ctlCmd != "proxy" {
		if o.effectiveBgRun() {
			return o.control.controlUsageError(fmt.Errorf("background mode (-f / ForkAfterAuthentication) cannot be combined with control command -O %s", ctlCmd))
		}
		return nil
	}
	if err := o.validateBackgroundFlags(); err != nil {
		return o.control.controlUsageError(err)
	}
	if err := o.prepareCommandPlan(); err != nil {
		return o.control.controlUsageError(err)
	}
	return nil
}

func (o *SshOptions) validateBackgroundCredentialInvariants() error {
	if !o.effectiveBgRun() {
		return nil
	}
	if o.PasswordStdin || o.PassphraseStdin || o.Password != "" || o.Passphrase != "" {
		return errors.New("background mode (-f) cannot be combined with stdin or inline password/passphrase authentication; configure key/agent auth or persistent credentials instead")
	}
	if o.OTP != "" || o.OTPStdin {
		return errors.New("background mode (-f) cannot be combined with one-time --otp or --otp-stdin; configure persistent identity otp instead")
	}
	return nil
}

func (o *SshOptions) validateBackgroundFlags() error {
	if !o.effectiveBgRun() {
		return nil
	}
	if err := o.validateBackgroundCredentialInvariants(); err != nil {
		return err
	}
	if !o.effectiveNoCmd() && o.Command == "" && !o.stdinScript {
		hasRemoteCmd, err := o.hasNonEmptyRemoteCommand()
		if err != nil {
			return err
		}
		if hasRemoteCmd {
			return nil
		}
		allowed, err := o.canConfigSupplyBackgroundSession()
		if err != nil {
			return err
		}
		if allowed.Allowed() {
			return nil
		}
		return errors.New(i18n.T("ssh_err_background_requires_nocmd"))
	}
	return nil
}

func (o *SshOptions) canConfigSupplyBackgroundSession() (verdict.Verdict, error) {
	if o == nil || o.isMuxDaemon() {
		return verdict.Deny, nil
	}
	sessionOpts, err := o.toSessionControlOptions()
	if err != nil {
		return verdict.Deny, err
	}
	cliSessionTypeLocked := false
	cliRemoteCmdLocked := false
	if cliOpts := sessionOpts.ToSSHOptions(); cliOpts != nil {
		cliSessionTypeLocked = strings.TrimSpace(cliOpts.Get(ssh.OptionSessionType)) != ""
		cliRemoteCmdLocked = strings.TrimSpace(cliOpts.Get(ssh.OptionRemoteCommand)) != ""
	}
	if cliSessionTypeLocked && cliRemoteCmdLocked {
		return verdict.Deny, nil
	}
	provider, err := o.loadBackgroundSessionProbeProvider()
	if err != nil {
		return verdict.Deny, err
	}
	if provider == nil {
		return verdict.Deny, nil
	}
	if o.probeTargetBackgroundSession(provider, sessionOpts, cliSessionTypeLocked, cliRemoteCmdLocked) {
		return verdict.Allow, nil
	}
	return verdict.Deny, nil
}

func (o *SshOptions) loadBackgroundSessionProbeProvider() (config.ConfigProvider, error) {
	var cfg *config.Configuration
	configPath, keyPath, pathErr := utils.GetConfigFilePath()
	if pathErr != nil {
		return nil, fmt.Errorf("get config file path failed: %w", pathErr)
	}
	if _, statErr := os.Stat(configPath); statErr == nil {
		loaded, loadErr := config.NewDefaultStore(configPath, keyPath).Load()
		if loadErr != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ssh_err_load_config"), loadErr)
		}
		cfg = loaded
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("stat config file %q: %w", configPath, statErr)
	}
	var openSSH *config.OpenSSHParser
	cfgFile := strings.TrimSpace(o.control.ConfigFile)
	if cfgFile != "" {
		var base config.ConfigProvider
		if cfg != nil {
			base = config.NewProviderWithoutOpenSSH(cfg)
		}
		return config.WithOpenSSHConfigOverride(base, cfgFile)
	}
	if home, homeErr := os.UserHomeDir(); homeErr == nil && strings.TrimSpace(home) != "" {
		defaultPath := filepath.Join(home, ".ssh", "config")
		if _, statErr := os.Stat(defaultPath); statErr == nil {
			p, parseErr := config.NewOpenSSHParserFromPath(defaultPath)
			if parseErr != nil {
				return nil, parseErr
			}
			openSSH = p
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, fmt.Errorf("stat OpenSSH config %q: %w", defaultPath, statErr)
		}
	}
	if cfg == nil && openSSH == nil {
		return nil, nil
	}
	if openSSH != nil {
		return config.NewProviderWithOpenSSHParser(cfg, openSSH), nil
	}
	return config.NewProviderWithoutOpenSSH(cfg), nil
}

func (o *SshOptions) probeTargetBackgroundSession(
	provider config.ConfigProvider,
	sessionOpts adapter.SessionControlOptions,
	cliSessionTypeLocked, cliRemoteCmdLocked bool,
) bool {
	probe := *o
	connTarget := effectiveConnectionTarget(&probe, "")
	nodeID := ""
	if resolved, err := config.ResolveTarget(provider, connTarget); err == nil {
		if resolved.MatchedNodeID != "" {
			nodeID = resolved.MatchedNodeID
		} else {
			nodeID = resolved.NodeID
		}
	}
	if probe.probeCandidateBackgroundSession(provider, nodeID, connTarget, sessionOpts, cliSessionTypeLocked, cliRemoteCmdLocked) {
		return true
	}
	rawHost := strings.TrimSpace(connTarget.Selector)
	if rawHost == "" || config.IsOpenSSHNodeID(rawHost) {
		return false
	}
	for _, fqdn := range config.CanonicalDomainCandidatesWithOptions(provider, rawHost, probe.control.Options, probe.effectiveCLIJumpHost()) {
		candProbe := *o
		candProbe.canonicalized = true
		candProbe.originalHost = rawHost
		candProbe.expandHost = rawHost
		candProbe.Host = fqdn
		candProbe.Target.Selector = fqdn
		candProbe.Target.OriginalHost = rawHost
		candTarget := effectiveConnectionTarget(&candProbe, "")
		candNodeID := config.OpenSSHNodePrefix + fqdn
		if resolved, err := config.ResolveTarget(provider, candTarget); err == nil {
			if resolved.MatchedNodeID != "" {
				candNodeID = resolved.MatchedNodeID
			} else if resolved.NodeID != "" {
				candNodeID = resolved.NodeID
			}
		}
		if candProbe.probeCandidateBackgroundSession(provider, candNodeID, candTarget, sessionOpts, cliSessionTypeLocked, cliRemoteCmdLocked) {
			return true
		}
	}
	return false
}

func (o *SshOptions) probeCandidateBackgroundSession(
	provider config.ConfigProvider,
	nodeID string,
	connTarget config.ConnectionTarget,
	sessionOpts adapter.SessionControlOptions,
	cliSessionTypeLocked, cliRemoteCmdLocked bool,
) bool {
	target := controlTarget(o, provider, nodeID)
	lookupKey, sessionAuth := resolveControlSessionLookup(o, provider, nodeID, connTarget, target)
	var adpOpts []adapter.Option
	if lookupKey != "" && (sessionAuth.ProxyJump != "" || sessionAuth.OriginalHost != "" || sessionAuth.CanonicalHost != "") {
		adpOpts = append(adpOpts, adapter.WithSessionAuthOverride(lookupKey, sessionAuth))
	}
	pol, err := adapter.NewSSHAdapter(provider, adpOpts...).Resolve(context.Background(), adapter.ResolveRequest{
		NodeID:         lookupKey,
		SessionControl: &sessionOpts,
	})
	if err != nil {
		return false
	}
	eff := pol.Options()
	if eff == nil {
		return false
	}
	if !cliSessionTypeLocked && eff.SessionType() == ssh.SessionTypeNone {
		return true
	}
	if !cliRemoteCmdLocked {
		if rc := strings.TrimSpace(eff.Get(ssh.OptionRemoteCommand)); rc != "" && !ssh.IsNoneValue(rc) {
			return true
		}
	}
	canonMode := strings.TrimSpace(eff.Get(ssh.OptionCanonicalizeHostname))
	if (canonMode == ssh.CanonicalizeHostnameYes || canonMode == ssh.CanonicalizeHostnameAlways) &&
		strings.TrimSpace(eff.Get(ssh.OptionCanonicalizePermittedCNAMEs)) != "" {
		return true
	}
	return false
}

func (o *SshOptions) Run() error {
	return o.RunContext(context.Background())
}

// RunContext starts the SSH operation and propagates caller cancellation.
func (o *SshOptions) RunContext(ctx context.Context) (err error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return err
	}
	if o.control.CtlCmd != "" {
		return ExecuteControlCommand(ctx, o)
	}

	isChild := o.isBackgroundChild()
	if o.isMuxDaemon() {
		// A detached multiplexing daemon serves the control socket only. It must
		// never re-run the command or read the terminal the parent handed over.
		o.normalizeForMuxDaemon()
		o.StdinRedirect = true
	}

	ecBg := o.effectiveBgRun()

	observer, finishDiagnostics, diagnosticErr := o.startDiagnostics(ctx)
	if diagnosticErr != nil {
		return diagnosticErr
	}
	o.diagnostics = observer
	defer func() {
		o.diagnostics = nil
		err = errors.Join(err, finishDiagnostics())
	}()
	if ecBg && !isChild {
		return o.runParentDaemon(ctx)
	}

	return o.runConnection(ctx, isChild)
}

func (o *SshOptions) runParentDaemon(ctx context.Context) (err error) {
	configPath, keyPath, pathErr := utils.GetConfigFilePath()
	if pathErr != nil {
		return fmt.Errorf("get config file path failed: %w", pathErr)
	}
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ssh_err_load_config"), err)
	}

	repo, err := config.NewRepository(cfg, configStore)
	if err != nil {
		return fmt.Errorf("create configuration repository: %w", err)
	}
	provider, err := config.WithOpenSSHConfigOverride(repo, o.control.ConfigFile)
	if err != nil {
		return err
	}

	return o.runParentDaemonWithProvider(ctx, cfg, provider)
}

func (o *SshOptions) runParentDaemonWithProvider(ctx context.Context, cfg *config.Configuration, provider config.ConfigProvider) error {
	return o.withValidatedConnectionNode(ctx, provider, func(lease config.PendingLease) error {
		if err := o.validateBackgroundProxyCommand(provider, lease.NodeID()); err != nil {
			return err
		}
		return o.runParentDaemonWithLease(ctx, cfg, provider, lease)
	})
}

func (o *SshOptions) validateBackgroundProxyCommand(provider config.ConfigProvider, nodeID string) error {
	if o == nil || !o.effectiveBgRun() {
		return nil
	}
	hasProxy, err := o.hasActiveProxyCommandInPath(provider, nodeID, nil)
	if err != nil {
		return fmt.Errorf("verify background mode (-f) ProxyCommand failed: %w", err)
	}
	if hasProxy {
		return fmt.Errorf("background mode (-f) cannot be combined with ProxyCommand")
	}
	return nil
}

func (o *SshOptions) validatePostResolutionSessionInvariants() error {
	if o.effectiveStdinNull() || o.effectiveNoCmd() {
		o.stdinScript = false
	}
	if err := o.validateSubsystemFlags(); err != nil {
		return o.control.controlUsageError(err)
	}
	if o.effectiveNoCmd() && o.StdioForward == "" && o.Command != "" {
		return o.control.controlUsageError(errors.New(i18n.T("ssh_err_nocmd_with_command")))
	}
	if o.effectiveBgRun() && o.StdioForward != "" {
		return o.control.controlUsageError(errors.New(i18n.T("ssh_err_stdio_forward_with_bg")))
	}
	if err := o.validateBackgroundCredentialInvariants(); err != nil {
		return o.control.controlUsageError(err)
	}
	if o.effectiveBgRun() && !o.effectiveNoCmd() && o.Command == "" && !o.stdinScript {
		hasRemoteCmd, err := o.hasNonEmptyRemoteCommand()
		if err != nil {
			return o.control.controlUsageError(err)
		}
		if !hasRemoteCmd {
			return o.control.controlUsageError(errors.New(i18n.T("ssh_err_background_requires_nocmd")))
		}
	}
	return nil
}

func (o *SshOptions) runParentDaemonWithLease(ctx context.Context, cfg *config.Configuration, provider config.ConfigProvider, lease config.PendingLease) (err error) {
	nodeID := lease.NodeID()
	adpOpts, optErr := o.buildAdapterOptions(nodeID, cfg, provider)
	if optErr != nil {
		return optErr
	}
	// The parent only validates connectivity and tunnels. The background child
	// owns the control socket, so the parent must not bind it and then exit. The
	// disable is node-scoped on purpose: buildAdapterOptions above may have
	// registered a node-level session override, and a node override outranks the
	// global default used by other nodes.
	adpOpts = append(adpOpts, disableSessionControlForParent(nodeID))
	var (
		connector *ssh.Connector
		adp       *adapter.SSHAdapter
	)
	if o.isMuxDaemon() {
		connector, adp = newNonInteractiveConnectorAndAdapter(provider, adpOpts, ssh.WithSessionConfirmer(o.interaction), ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(o.diagnostics))
	} else {
		connector, adp = newCLIConnectorAndAdapter(provider, o.interaction, adpOpts, ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(o.diagnostics))
	}
	var connectorClosed bool
	defer func() {
		if !connectorClosed {
			joinConnectorCloseError(&err, connector)
		}
	}()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		promptErr := promptPressEnterIfTUI(os.Stdin, os.Stdout)
		return errors.Join(sshConnectionError(nodeID, err), promptErr)
	}
	if finalizeErr := adp.FinalizePendingConnection(ctx, lease, client); finalizeErr != nil {
		_ = connector.EvictClient(client)
		promptErr := promptPressEnterIfTUI(os.Stdin, os.Stdout)
		return errors.Join(sshConnectionError(nodeID, finalizeErr), promptErr)
	}

	// 无论如何，在 runParentDaemon 退出时，或者有任何 panic 发生时，确保 client 必被关闭
	var clientClosed bool
	defer func() {
		if !clientClosed {
			if closeErr := client.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close SSH daemon validation client failed: %w", closeErr))
			}
		}
	}()
	if lcErr := runPostAuthLocalCommand(ctx, client, o.effectiveSSHOptions, os.Stderr, o.isBackgroundChild()); lcErr != nil {
		return lcErr
	}

	// Validation tunnels own their child context. Closing them must leave the
	// command-owned output context alive until auxiliary output has flushed.
	o.isParentValidation = true
	defer func() { o.isParentValidation = false }()
	tunnels, err := o.startTunnels(ctx, nil, client)
	if err != nil {
		return err
	}
	if closeErr := tunnels.Close(); closeErr != nil {
		return fmt.Errorf("stop SSH daemon validation tunnels failed: %w", closeErr)
	}

	// 验证无误，可以断开，接下来由后台进程重新连接
	if err := client.Close(); err != nil {
		return fmt.Errorf("close SSH daemon validation client failed: %w", err)
	}
	clientClosed = true
	if closeErr := connector.CloseAll(); closeErr != nil {
		return fmt.Errorf("close SSH daemon validation connector failed: %w", closeErr)
	}
	connectorClosed = true

	return spawnBackgroundSSHChild()
}

func spawnBackgroundSSHChild() (err error) {
	// 启动后台子进程
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// 子进程的 stdin/stdout/stderr 均重定向到 /dev/null（Windows 下 stdin 为 spec 匿名管道）
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0) //nolint:forbidigo // open os.DevNull for detached child stdio redirection
	if err != nil {
		return fmt.Errorf("failed to open /dev/null: %w", err)
	}
	defer func() {
		if closeErr := devNull.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close SSH daemon stdio redirect failed: %w", closeErr))
		}
	}()

	if _, err := startBackgroundSSHCommand(exe, os.Args[1:], devNull); err != nil {
		return fmt.Errorf("failed to start background daemon: %w", err)
	}

	return nil
}

func (o *SshOptions) buildAdapterOptions(nodeID string, cfg *config.Configuration, repository config.ConfigProvider) ([]adapter.Option, error) {
	if o.interaction == nil {
		o.interaction = newCLIInteractionHandler()
	}
	policy := utils.EffectiveRememberPolicy(o.Remember, cfg)
	shouldRemember, adpOpts := o.interaction.rememberOptions(policy, cfg)
	isChild := o.isBackgroundChild()
	suppressConfirm := policy == utils.RememberPolicyNever || o.isMuxDaemon() || isChild
	if o.isMuxDaemon() {
		shouldRemember = false
		adpOpts = append(adpOpts, adapter.WithNonInteractive(true), adapter.WithSessionOptions(false))
	} else if isChild {
		shouldRemember = false
		adpOpts = append(adpOpts, adapter.WithNonInteractive(true), adapter.WithCredentialRecording(false))
	} else {
		adpOpts = append(adpOpts, adapter.WithLocalExecution(true))
	}
	if suppressConfirm {
		adpOpts = append(adpOpts, adapter.WithSuppressNodeConfirmation(true))
	}
	// The global policy also covers ProxyJump nodes. The target-specific override
	// below carries its explicit session material without leaking it to jumps.
	adpOpts = append(adpOpts, adapter.WithGlobalSessionAuth(adapter.SessionAuth{
		Remember:                 shouldRemember,
		SuppressNodeConfirmation: suppressConfirm,
	}))
	proxyJumpOverride := o.JumpHost
	if proxyJumpOverride == "" && o.isMuxDaemon() {
		proxyJumpOverride = "none"
	}
	o.syncResolvedTargetHosts(repository)
	hostNameOverride, hostErr := o.effectiveHostName()
	if hostErr != nil {
		return nil, hostErr
	}
	absKeys := o.absIdentityFiles()
	firstKey := normalizeCLIIdentityPath(o.IdentityFile)
	if firstKey == "" && len(absKeys) > 0 {
		firstKey = absKeys[0]
	}
	// 总是注入 SessionAuthOverride（即使密码为空），以便 UpdateAuth / UpdateSudo
	// 能根据 Remember 策略决定是否将交互提示获得的密码回写配置，而不是绕过策略检查。
	_, canonHost := canonicalControlOriginAndHost(o)
	adpOpts = append(adpOpts, adapter.WithSessionAuthOverride(nodeID, adapter.SessionAuth{
		Password:                 o.Password,
		Passphrase:               o.Passphrase,
		KeyPath:                  firstKey,
		KeyPaths:                 absKeys,
		HostName:                 hostNameOverride,
		OriginalHost:             o.originalHost,
		CanonicalHost:            canonHost,
		Remember:                 shouldRemember,
		SuppressNodeConfirmation: suppressConfirm,
		OTP:                      o.OTP,
		ProxyJump:                proxyJumpOverride,
	}))
	if reg, regErr := utils.GetCredentialRegistry(cfg); regErr != nil {
		return nil, fmt.Errorf("initialize credential resolver: %w", regErr)
	} else if reg != nil {
		adpOpts = append(adpOpts, adapter.WithCredentialSource(reg))
	}
	if err := o.appendRememberPersistenceOptions(&adpOpts, nodeID, cfg, repository, shouldRemember); err != nil {
		return nil, err
	}

	if err := o.appendSessionControlOverrides(&adpOpts, nodeID); err != nil {
		return nil, err
	}

	return adpOpts, nil
}

func (o *SshOptions) appendRememberPersistenceOptions(adpOpts *[]adapter.Option, nodeID string, cfg *config.Configuration, repository config.ConfigProvider, shouldRemember bool) error {
	repo, isRepo := repository.(*config.Repository)
	if !isRepo {
		*adpOpts = append(*adpOpts, adapter.WithCredentialRecording(false), adapter.WithSuppressNodeConfirmation(true))
		return nil
	}
	if !shouldRemember {
		return nil
	}
	*adpOpts = append(*adpOpts, enrollmentProbeOption())
	if o.execution.enabled() || o.execution.noLoginSet || o.StdioForward != "" || o.Subsystem {
		*adpOpts = append(*adpOpts, adapter.WithEnrollmentProbeExclusions(nodeID))
	}
	persistence, err := o.interaction.automaticPersistenceOptions(repo, cfg)
	if err != nil {
		return err
	}
	*adpOpts = append(*adpOpts, persistence...)
	return nil
}

func (o *SshOptions) appendSessionControlOverrides(adpOpts *[]adapter.Option, nodeID string) error {
	sessionCtrlOpts, err := o.toSessionControlOptions()
	if err != nil {
		return err
	}
	if sessionCtrlOpts.IsEmpty() {
		return nil
	}
	if globalCtrl := sessionCtrlOpts.ConnectionWideOptions(); !globalCtrl.IsEmpty() {
		*adpOpts = append(*adpOpts, adapter.WithGlobalSessionControl(globalCtrl))
	}
	*adpOpts = append(*adpOpts, adapter.WithSessionControlOverride(nodeID, sessionCtrlOpts))
	return nil
}

// disableSessionControlForParent stops a -f parent from claiming the control
// socket that the detached child owns, including any ProxyJump hops. It sets
// both global and node-level overrides so neither a jump hop nor a node-scoped
// -M/-S/-o override on the target can bind or attach to a control socket, while
// preserving non-multiplexing CLI -o options.
func disableSessionControlForParent(nodeID string) adapter.Option {
	return func(a *adapter.SSHAdapter) {
		a.DisableSessionControlSharing(nodeID)
	}
}

// getActiveMuxServer returns the in-process master serving this node, if any. The
// control path must be expanded from the resolved connection target, exactly as
// Connector.buildTargetContext does, otherwise %h/%p/%r/%C expand differently.
func (o *SshOptions) getActiveMuxServer(ctx context.Context, provider config.ConfigProvider, nodeID string) *ssh.MuxServer {
	expandedPath, err := controlSocketPath(o, provider, nodeID)
	if err != nil || expandedPath == "" {
		return nil
	}
	return ssh.GetActiveMuxServer(expandedPath)
}

// handoffPersistentMaster releases this process's master and starts a detached
// master so ControlPersist survives the session, matching OpenSSH behavior for a
// command or interactive shell that finished.
func (o *SshOptions) shouldSkipMasterHandoff(ctx context.Context, connector *ssh.Connector, provider config.ConfigProvider, nodeID string) (bool, error) {
	if o.isMuxDaemon() || o.effectiveBgRun() || o.effectiveNoCmd() {
		return true, nil
	}
	if ctx != nil && ctx.Err() != nil {
		// The session was interrupted (Ctrl-C/cancellation). Reviving the master
		// would resurrect what the user just stopped.
		return true, nil
	}
	if err := drainOwnedMastersWithProvider(ctx, provider, connector); err != nil {
		return true, err
	}
	if o.OTP != "" {
		// A one-time code was already consumed by this process. Re-playing it in
		// the daemon cannot succeed and may trip server-side MFA lockouts.
		logger.DefaultLogger().Debugf("mux: skipping master handoff because a one-time password was used")
		return true, nil
	}
	hasProxy, err := o.hasActiveProxyCommandInPath(provider, nodeID, connector)
	if err != nil {
		logger.DefaultLogger().Debugf("mux: skipping master handoff because ProxyCommand check failed: %v", err)
		return true, err
	}
	if hasProxy {
		// Detached --mux-daemon runs with localExecution disabled; keep ProxyCommand
		// masters in foreground instead of handing off to a daemon that cannot re-dial.
		logger.DefaultLogger().Debugf("mux: skipping master handoff because ProxyCommand is active")
		return true, nil
	}
	return false, nil
}

func (o *SshOptions) hasActiveProxyCommandInPath(provider config.ConfigProvider, nodeID string, connector *ssh.Connector) (bool, error) {
	sessionCtrlOpts, hasDirectProxy, err := o.resolveProxyCommandCheckSessionOptions()
	if err != nil || hasDirectProxy {
		return true, err
	}
	if provider == nil {
		return false, nil
	}
	checker := o.buildProxyCommandPathChecker(provider, nodeID, sessionCtrlOpts)
	if hasProxy, err := checker.checkNode(nodeID, true); err != nil || hasProxy {
		return true, err
	}
	if nodeID == "" {
		jumpChain, err := o.effectiveProxyJumpChain(provider, "")
		if err != nil {
			return true, err
		}
		for _, hop := range strings.Split(jumpChain, ",") {
			if hasProxy, err := checker.checkNode(hop, false); err != nil || hasProxy {
				return true, err
			}
		}
	}
	return checker.checkConnectorMasters(connector)
}

func (o *SshOptions) resolveProxyCommandCheckSessionOptions() (adapter.SessionControlOptions, bool, error) {
	if o == nil {
		return adapter.SessionControlOptions{}, false, nil
	}
	if o.effectiveSSHOptions != nil && o.effectiveSSHOptions.ActiveProxyCommand() != "" {
		return adapter.SessionControlOptions{}, true, nil
	}
	parsed, err := o.toSessionControlOptions()
	if err != nil {
		return adapter.SessionControlOptions{}, true, err
	}
	if opts := parsed.ToSSHOptions(); opts != nil && opts.ActiveProxyCommand() != "" {
		return parsed, true, nil
	}
	return parsed, false, nil
}

func (o *SshOptions) buildProxyCommandPathChecker(
	provider config.ConfigProvider,
	nodeID string,
	sessionCtrlOpts adapter.SessionControlOptions,
) *proxyCommandPathChecker {
	adpOpts := []adapter.Option{adapter.WithLocalExecution(true)}
	if o != nil && nodeID != "" {
		origHost, canonHost := canonicalControlOriginAndHost(o)
		if origHost == "" {
			origHost = strings.TrimSpace(o.originalHost)
		}
		jump := strings.TrimSpace(o.JumpHost)
		if jump != "" || origHost != "" || canonHost != "" {
			adpOpts = append(adpOpts, adapter.WithSessionAuthOverride(nodeID, adapter.SessionAuth{
				ProxyJump:     jump,
				OriginalHost:  origHost,
				CanonicalHost: canonHost,
			}))
		}
	}
	return &proxyCommandPathChecker{
		opts:            o,
		provider:        provider,
		adp:             adapter.NewSSHAdapter(provider, adpOpts...),
		sessionCtrlOpts: sessionCtrlOpts,
		visited:         make(map[string]struct{}),
	}
}

type proxyCommandPathChecker struct {
	opts            *SshOptions
	provider        config.ConfigProvider
	adp             *adapter.SSHAdapter
	sessionCtrlOpts adapter.SessionControlOptions
	visited         map[string]struct{}
}

func (c *proxyCommandPathChecker) checkNode(id string, isTarget bool) (bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return false, nil
	}
	if _, seen := c.visited[id]; seen {
		return false, nil
	}
	c.visited[id] = struct{}{}
	ctrlOpts := c.sessionCtrlOpts.ConnectionWideOptions()
	if isTarget {
		ctrlOpts = c.sessionCtrlOpts
	}
	pol, err := c.adp.Resolve(context.Background(), adapter.ResolveRequest{
		NodeID:         id,
		SessionControl: &ctrlOpts,
		ResolveProxy:   isTarget,
	})
	if err != nil {
		// Fail closed: if effective policy resolution fails, treat as unsafe to detach/handoff.
		return true, err
	}
	if opts := pol.Options(); opts != nil && opts.ActiveProxyCommand() != "" {
		return true, nil
	}
	if pol.Proxy().Kind() != ssh.ProxyJump {
		return false, nil
	}
	jumpChain := pol.EffectiveJump()
	for _, hop := range strings.Split(jumpChain, ",") {
		if hasProxy, hopErr := c.checkNode(hop, false); hopErr != nil || hasProxy {
			return true, hopErr
		}
	}
	return false, nil
}

func (c *proxyCommandPathChecker) checkConnectorMasters(connector *ssh.Connector) (bool, error) {
	if connector == nil {
		return false, nil
	}
	for _, m := range connector.Masters() {
		if m == nil {
			continue
		}
		if hasProxy, err := c.checkOwnedMaster(connector, m); err != nil || hasProxy {
			return true, err
		}
	}
	return false, nil
}

func (c *proxyCommandPathChecker) checkOwnedMaster(connector *ssh.Connector, m *ssh.MuxServer) (bool, error) {
	if ownedID := strings.TrimSpace(connector.MasterNodeID(m)); ownedID != "" {
		if hasProxy, err := c.checkNode(ownedID, false); err != nil || hasProxy {
			return true, err
		}
	}
	if resolvedID := resolveOwnedMasterNodeID(c.provider, connector, m); resolvedID != "" {
		if hasProxy, err := c.checkNode(resolvedID, false); err != nil || hasProxy {
			return true, err
		}
	}
	targetHost := strings.TrimSpace(m.Target().OriginalHost)
	if targetHost == "" {
		return false, nil
	}
	if hasProxy, err := c.checkNode(targetHost, false); err != nil || hasProxy {
		return true, err
	}
	if !config.IsOpenSSHNodeID(targetHost) {
		return c.checkNode(config.OpenSSHNodePrefix+targetHost, false)
	}
	return false, nil
}

func (o *SshOptions) effectiveProxyJumpChain(provider config.ConfigProvider, nodeID string) (string, error) {
	if o != nil {
		jump := strings.TrimSpace(o.JumpHost)
		if jump != "" {
			ps, err := ssh.ParseProxyJump(jump)
			if err != nil {
				return "", err
			}
			targets, ok := ps.JumpTargets()
			if !ok {
				return "", nil
			}
			if provider == nil {
				return strings.Join(targets, ","), nil
			}
			resolved, err := provider.ResolveProxyJumpChain(jump)
			if err != nil {
				return "", err
			}
			return resolved, nil
		}
	}
	if nodeID != "" && provider != nil {
		snap, err := provider.ResolveConnection(nodeID)
		if err != nil {
			if errors.Is(err, config.ErrNodeNotFound) {
				return "", nil
			}
			return "", err
		}
		return strings.TrimSpace(snap.Node.ProxyJump), nil
	}
	return "", nil
}

func (o *SshOptions) handoffPersistentMaster(ctx context.Context, connector *ssh.Connector, provider config.ConfigProvider, nodeID string) error {
	if skip, err := o.shouldSkipMasterHandoff(ctx, connector, provider, nodeID); err != nil || skip {
		return nil
	}
	if nodeID != "" && len(o.targetNodeIDs) == 0 {
		o.targetNodeIDs = []string{nodeID}
	}
	var master *ssh.MuxServer
	var cfgProvider config.ConfigProvider
	if provider != nil {
		cfgProvider = provider
	}
	expandedPath, err := controlSocketPath(o, cfgProvider, nodeID)
	if err == nil && expandedPath != "" {
		master = ssh.GetActiveMuxServer(expandedPath)
	}
	if isMasterClosed(master) && connector != nil {
		master = findOwnedMasterForNode(connector, nodeID)
	}
	if !canHandoffMaster(master) {
		return o.handoffConnectorMasters(ctx, provider, connector)
	}
	handoffNodeID := resolvePersistentHandoffNodeID(provider, connector, master, nodeID)
	rawOwnedID := nodeID
	if connector != nil {
		if ownedID := strings.TrimSpace(connector.MasterNodeID(master)); ownedID != "" {
			rawOwnedID = ownedID
		}
	}
	o.recordTargetHandoffNodeID(nodeID, handoffNodeID)
	return o.handoffMasterInstanceWithProviderAndRawNode(ctx, provider, connector, master, handoffNodeID, rawOwnedID)
}

func isMasterClosed(m *ssh.MuxServer) bool {
	if m == nil {
		return true
	}
	select {
	case <-m.Wait():
		return true
	default:
		return false
	}
}

func isMasterDeadOrStopped(m *ssh.MuxServer) bool {
	return m == nil || m.StoppedListening() || isMasterClosed(m)
}

func findOwnedMasterForNode(connector *ssh.Connector, nodeID string) *ssh.MuxServer {
	if connector == nil {
		return nil
	}
	masters := connector.Masters()
	if nodeID != "" {
		for i := len(masters) - 1; i >= 0; i-- {
			m := masters[i]
			if !isMasterClosed(m) && strings.TrimSpace(connector.MasterNodeID(m)) == nodeID {
				return m
			}
		}
	}
	cleanNodeID, _ := config.OpenSSHOriginalHost(nodeID)
	for i := len(masters) - 1; i >= 0; i-- {
		m := masters[i]
		if isMasterClosed(m) {
			continue
		}
		orig := m.Target().OriginalHost
		if orig == nodeID || (cleanNodeID != "" && orig == cleanNodeID) || nodeID == "" {
			return m
		}
	}
	return nil
}

func resolvePersistentHandoffNodeID(provider config.ConfigProvider, connector *ssh.Connector, master *ssh.MuxServer, nodeID string) string {
	handoffNodeID := strings.TrimSpace(nodeID)
	resolvedID := resolveOwnedMasterNodeID(provider, connector, master)
	if resolvedID == "" {
		return handoffNodeID
	}
	if connector != nil && strings.TrimSpace(connector.MasterNodeID(master)) != "" {
		return resolvedID
	}
	if handoffNodeID == "" || (!strings.HasPrefix(handoffNodeID, config.OpenSSHNodePrefix) && strings.HasPrefix(resolvedID, config.OpenSSHNodePrefix)) {
		return resolvedID
	}
	return handoffNodeID
}

func (o *SshOptions) recordTargetHandoffNodeID(rawNodeID, handoffNodeID string) {
	if o == nil || handoffNodeID == "" || handoffNodeID == rawNodeID || len(o.targetNodeIDs) == 0 {
		return
	}
	if rawNodeID != "" && !slices.Contains(o.targetNodeIDs, rawNodeID) {
		return
	}
	if !slices.Contains(o.targetNodeIDs, handoffNodeID) {
		o.targetNodeIDs = append(o.targetNodeIDs, handoffNodeID)
	}
}

func canHandoffMaster(master *ssh.MuxServer) bool {
	if master == nil || !master.PersistEnabled() {
		return false
	}
	if ctrl := master.Target().Control; ctrl != nil {
		if ctrl.ImplicitTier4 {
			return false
		}
	}
	return true
}

// handoffConnectorMasters drains and hands off any persistent multiplexing
// masters started by connector during scp, sftp, or exec operations.
func (o *SshOptions) handoffConnectorMasters(ctx context.Context, provider config.ConfigProvider, connector *ssh.Connector) error {
	if connector == nil {
		return nil
	}
	masters := connector.Masters()
	if len(masters) == 0 {
		return nil
	}
	if o.isMuxDaemon() || o.effectiveBgRun() || o.effectiveNoCmd() {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return nil
	}
	if err := drainOwnedMastersWithProvider(ctx, provider, connector); err != nil {
		return nil
	}
	if o.OTP != "" {
		logger.DefaultLogger().Debugf("mux: skipping master handoff because a one-time password was used")
		return nil
	}
	jumps := persistentJumpHopsWithProvider(connector, provider, masters)
	var firstErr error
	for _, m := range masters {
		if !canHandoffMaster(m) {
			continue
		}
		rawOwnedID := strings.TrimSpace(connector.MasterNodeID(m))
		nodeID := resolveOwnedMasterNodeID(provider, connector, m)
		if isSuppressedJumpMaster(jumps, rawOwnedID, nodeID) {
			continue
		}
		if rawOwnedID != "" {
			o.recordTargetHandoffNodeID(rawOwnedID, nodeID)
		}
		hasProxy, proxyErr := o.hasActiveProxyCommandForMaster(provider, rawOwnedID, nodeID)
		if proxyErr != nil {
			logger.DefaultLogger().Debugf("mux: skipping master handoff because ProxyCommand check failed: %v", proxyErr)
			continue
		}
		if hasProxy {
			logger.DefaultLogger().Debugf("mux: skipping master handoff because ProxyCommand is active")
			continue
		}
		if err := o.handoffMasterInstanceWithProviderAndRawNode(ctx, provider, connector, m, nodeID, rawOwnedID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func parseJumpHopSpec(spec string) (user, host string, port uint16, hasExplicit bool) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return "", "", 0, false
	}
	unwrapped := strings.TrimPrefix(trimmed, config.OpenSSHNodePrefix)
	u, h, p, err := utils.ParseAddr(unwrapped)
	if err != nil {
		clean, _ := config.OpenSSHOriginalHost(trimmed)
		return "", clean, 0, false
	}
	return u, h, p, u != "" || p != 0
}

func isSuppressedJumpMaster(jumps map[string]bool, rawOwnedID, resolvedNodeID string) bool {
	if len(jumps) == 0 {
		return false
	}
	_, _, _, rawExplicit := parseJumpHopSpec(rawOwnedID)
	if rawOwnedID != "" {
		if jumps[rawOwnedID] {
			return true
		}
		if !rawExplicit {
			if clean, ok := config.OpenSSHOriginalHost(rawOwnedID); ok && (jumps[clean] || jumps[config.OpenSSHNodePrefix+clean]) {
				return true
			}
		}
	}
	if resolvedNodeID == "" || (strings.HasPrefix(rawOwnedID, config.OpenSSHNodePrefix) && rawExplicit) {
		return false
	}
	if jumps[resolvedNodeID] {
		return true
	}
	if _, _, _, resExplicit := parseJumpHopSpec(resolvedNodeID); !resExplicit {
		if clean, ok := config.OpenSSHOriginalHost(resolvedNodeID); ok && (jumps[clean] || jumps[config.OpenSSHNodePrefix+clean]) {
			return true
		}
	}
	return false
}

func (o *SshOptions) hasActiveProxyCommandForMaster(provider config.ConfigProvider, rawOwnedID, resolvedNodeID string) (bool, error) {
	hasProxy, err := o.hasActiveProxyCommandInPath(provider, resolvedNodeID, nil)
	if err != nil || hasProxy {
		return true, err
	}
	if rawOwnedID != "" && rawOwnedID != resolvedNodeID {
		return o.hasActiveProxyCommandInPath(provider, rawOwnedID, nil)
	}
	return false, nil
}

func resolveOwnedMasterNodeID(provider config.ConfigProvider, connector *ssh.Connector, m *ssh.MuxServer) string {
	if m == nil {
		return ""
	}
	if connector != nil {
		if ownedID := strings.TrimSpace(connector.MasterNodeID(m)); ownedID != "" {
			return normalizeOwnedMasterNodeID(provider, ownedID, m)
		}
	}
	return resolveMasterNodeID(provider, m)
}

func normalizeOwnedMasterNodeID(provider config.ConfigProvider, ownedID string, m *ssh.MuxServer) string {
	if strings.HasPrefix(ownedID, config.OpenSSHNodePrefix) {
		return normalizeOwnedOpenSSHMasterNodeID(provider, ownedID, m)
	}
	if provider == nil {
		if m != nil {
			if canon := strings.TrimSpace(m.Target().CanonicalHost); canon != "" {
				orig := strings.TrimSpace(m.Target().OriginalHost)
				if orig == "" || !strings.EqualFold(orig, canon) {
					return config.OpenSSHNodePrefix + canon
				}
			}
		}
		return ownedID
	}
	_, isSaved := provider.GetNode(ownedID)
	alias := resolveNodeOpenSSHAlias(provider, ownedID)
	canon := resolveNodeCanonicalHost(provider, ownedID)
	if canon == "" && m != nil {
		canon = strings.TrimSpace(m.Target().CanonicalHost)
	}
	orig := ""
	if m != nil {
		orig = strings.TrimSpace(m.Target().OriginalHost)
	}
	if alias != "" && (!isSaved || (orig != "" && orig != ownedID)) {
		if canon != "" && !strings.EqualFold(alias, canon) {
			return config.OpenSSHNodePrefix + canon
		}
		return config.OpenSSHNodePrefix + alias
	}
	if !isSaved && canon != "" {
		return config.OpenSSHNodePrefix + canon
	}
	return ownedID
}

func normalizeOwnedOpenSSHMasterNodeID(provider config.ConfigProvider, ownedID string, m *ssh.MuxServer) string {
	alias := resolveNodeOpenSSHAlias(provider, ownedID)
	canon := resolveNodeCanonicalHost(provider, ownedID)
	if canon == "" && m != nil {
		canon = strings.TrimSpace(m.Target().CanonicalHost)
	}
	orig := alias
	if orig == "" && m != nil {
		orig = strings.TrimSpace(m.Target().OriginalHost)
	}
	if canon != "" && orig != "" && !strings.EqualFold(orig, canon) {
		return config.OpenSSHNodePrefix + canon
	}
	if alias != "" {
		return config.OpenSSHNodePrefix + alias
	}
	return ownedID
}

func resolveNodeOpenSSHAlias(provider config.ConfigProvider, nodeID string) string {
	if provider == nil || nodeID == "" {
		return ""
	}
	if snap, err := provider.ResolveConnection(nodeID); err == nil {
		if alias := strings.TrimSpace(snap.Node.OpenSSHAlias); alias != "" {
			return alias
		}
	}
	if src, ok := provider.(interface{ NodeOpenSSHAlias(string) string }); ok {
		return strings.TrimSpace(src.NodeOpenSSHAlias(nodeID))
	}
	return ""
}

func resolvePendingOpenSSHAlias(provider config.ConfigProvider, candidateID string) string {
	if provider == nil || candidateID == "" {
		return ""
	}
	if _, isSaved := provider.GetNode(candidateID); isSaved {
		return ""
	}
	return resolveNodeOpenSSHAlias(provider, candidateID)
}

func resolveNodeCanonicalHost(provider config.ConfigProvider, nodeID string) string {
	if provider == nil || nodeID == "" {
		return ""
	}
	if snap, err := provider.ResolveConnection(nodeID); err == nil {
		if canon := strings.TrimSpace(snap.Node.CanonicalHost); canon != "" {
			return canon
		}
	}
	if src, ok := provider.(interface{ NodeCanonicalHost(string) string }); ok {
		return strings.TrimSpace(src.NodeCanonicalHost(nodeID))
	}
	return ""
}

func resolvePendingCanonicalHost(provider config.ConfigProvider, candidateID string) string {
	if provider == nil || candidateID == "" {
		return ""
	}
	if _, isSaved := provider.GetNode(candidateID); isSaved {
		return ""
	}
	return resolveNodeCanonicalHost(provider, candidateID)
}

func resolveMasterNodeID(provider config.ConfigProvider, m *ssh.MuxServer) string {
	if m == nil {
		return ""
	}
	t := m.Target()
	orig := strings.TrimSpace(t.OriginalHost)
	targetHost := cleanMuxHost(t.Host)
	port := t.Port
	if port <= 0 {
		port = 22
	}
	if canonical := strings.TrimSpace(t.CanonicalHost); canonical != "" && (orig == "" || !strings.EqualFold(orig, canonical)) {
		if resolveSavedMasterNodeID(provider, orig, targetHost, t.User, uint16(port)) == "" {
			return config.OpenSSHNodePrefix + canonical
		}
	}
	if provider != nil && orig != "" {
		if id := resolveMasterNodeIDFromOriginalHost(provider, orig, targetHost, t.User, uint16(port)); id != "" {
			return id
		}
	}
	if targetHost != "" {
		if t.User != "" {
			compositeID := config.FormatNodeID(t.User, targetHost, uint16(port))
			if alias := resolvePendingOpenSSHAlias(provider, compositeID); alias != "" {
				if canon := resolvePendingCanonicalHost(provider, compositeID); canon != "" && !strings.EqualFold(alias, canon) {
					return config.OpenSSHNodePrefix + canon
				}
				return config.OpenSSHNodePrefix + alias
			}
			return compositeID
		}
		return targetHost
	}
	return orig
}

func sameMasterHostEndpoint(snapAddr string, snapPort uint16, targetHost string, targetPort uint16) bool {
	effSnapPort := int(snapPort)
	if effSnapPort == 0 {
		effSnapPort = 22
	}
	if targetPort != 0 {
		snapEp, err1 := ssh.NewEndpoint(snapAddr, effSnapPort)
		targetEp, err2 := ssh.NewEndpoint(targetHost, int(targetPort))
		return err1 == nil && err2 == nil && snapEp.Equal(targetEp)
	}
	snapEp, err1 := ssh.NewEndpoint(snapAddr, effSnapPort)
	targetEp, err2 := ssh.NewEndpoint(targetHost, effSnapPort)
	return err1 == nil && err2 == nil && snapEp.HostEqual(targetEp)
}

func collectSavedMasterCandidates(provider config.ConfigProvider, orig, user string, port uint16) []string {
	var candidates []string
	addCand := func(id string) {
		id = strings.TrimSpace(id)
		if id != "" && !strings.HasPrefix(id, config.OpenSSHNodePrefix) && !slices.Contains(candidates, id) {
			candidates = append(candidates, id)
		}
	}
	if _, ok := provider.GetNode(orig); ok {
		addCand(orig)
	}
	if aliasID := provider.FindAlias(orig); aliasID != "" {
		addCand(aliasID)
	}
	if selID, err := provider.ResolveSelector(orig); err == nil && selID != "" {
		addCand(selID)
	}
	if user != "" || port != 0 {
		if res, err := config.ResolveTarget(provider, config.ConnectionTarget{
			Selector: orig,
			User:     user,
			HasUser:  user != "",
			Port:     port,
			HasPort:  port != 0,
		}); err == nil && res.MatchedNodeID != "" && !config.IsOpenSSHNodeID(res.BaseNodeID) {
			addCand(res.MatchedNodeID)
		}
	}
	return candidates
}

func savedMasterNodeMatches(snap config.ConnectionSnapshot, targetHost, user string, port uint16) bool {
	if snap.Provenance.IsUnpersistedOpenSSH() {
		return false
	}
	if targetHost != "" && !sameMasterHostEndpoint(snap.Host.Address, snap.Host.Port, targetHost, port) {
		return false
	}
	snapUser := strings.TrimSpace(snap.Identity.User)
	if snapUser == "" {
		snapUser = defaultLocalUser()
	}
	if user != "" && snapUser != "" && snapUser != user {
		return false
	}
	snapPort := snap.Host.Port
	if snapPort == 0 {
		snapPort = 22
	}
	if port != 0 && snapPort != port {
		return false
	}
	return true
}

func resolveSavedMasterNodeID(provider config.ConfigProvider, orig, targetHost, user string, port uint16) string {
	orig = strings.TrimSpace(orig)
	if provider == nil || orig == "" || strings.HasPrefix(orig, config.OpenSSHNodePrefix) {
		return ""
	}
	for _, candID := range collectSavedMasterCandidates(provider, orig, user, port) {
		snap, err := provider.ResolveConnection(candID)
		if err == nil && savedMasterNodeMatches(snap, targetHost, user, port) {
			return candID
		}
	}
	return ""
}

func resolveMasterNodeIDFromOriginalHost(provider config.ConfigProvider, orig, targetHost, user string, port uint16) string {
	if savedID := resolveSavedMasterNodeID(provider, orig, targetHost, user, port); savedID != "" {
		return savedID
	}
	cleanOrig := config.UnwrapOpenSSHSelector(orig)
	if cleanOrig == "" {
		return ""
	}
	if user != "" {
		if id := resolveMasterNodeIDViaUserPending(provider, cleanOrig, targetHost, user, port); id != "" {
			return id
		}
	}
	if id := resolveMasterConcreteCanonicalNodeID(provider, cleanOrig, targetHost, port); id != "" {
		return id
	}
	return resolveMasterVirtualOpenSSHNodeID(provider, cleanOrig, targetHost, user, port)
}

func resolveMasterNodeIDViaUserPending(provider config.ConfigProvider, cleanOrig, targetHost, user string, port uint16) string {
	altID := config.OpenSSHNodePrefix + config.FormatNodeID(user, cleanOrig, port)
	if alias := resolvePendingOpenSSHAlias(provider, altID); alias != "" {
		if canon := resolvePendingCanonicalHost(provider, altID); canon != "" && !strings.EqualFold(alias, canon) {
			return config.OpenSSHNodePrefix + canon
		}
		return config.OpenSSHNodePrefix + alias
	}
	if targetHost != "" {
		targetPendingID := config.FormatNodeID(user, targetHost, port)
		canon := resolvePendingCanonicalHost(provider, targetPendingID)
		alias := resolvePendingOpenSSHAlias(provider, targetPendingID)
		if canon == "" {
			canon = resolveNodeCanonicalHost(provider, targetPendingID)
		}
		if alias == "" {
			alias = resolveNodeOpenSSHAlias(provider, targetPendingID)
		}
		if canon != "" && strings.EqualFold(alias, cleanOrig) {
			return config.OpenSSHNodePrefix + canon
		}
	}
	return ""
}

func resolveMasterConcreteCanonicalNodeID(provider config.ConfigProvider, cleanOrig, targetHost string, port uint16) string {
	if targetHost != "" {
		canonID := config.OpenSSHNodePrefix + targetHost
		if canon := resolveNodeCanonicalHost(provider, canonID); canon != "" && strings.EqualFold(resolveNodeOpenSSHAlias(provider, canonID), cleanOrig) {
			return config.OpenSSHNodePrefix + canon
		}
	}
	parser := providerOpenSSHParser(provider)
	if parser == nil || targetHost == "" {
		return ""
	}
	var candHosts []string
	if ep, err := ssh.NewEndpoint(targetHost, int(port)); err == nil {
		candHosts = append(candHosts, parser.FindConcreteHostsByAddress(ep)...)
		if port != 0 {
			for _, extra := range parser.FindConcreteHostsByHost(ep) {
				if !slices.Contains(candHosts, extra) {
					candHosts = append(candHosts, extra)
				}
			}
		}
	}
	candHosts = append(candHosts, config.CanonicalDomainCandidates(provider, cleanOrig)...)
	for _, cand := range candHosts {
		candID := config.OpenSSHNodePrefix + cand
		if canon := resolveNodeCanonicalHost(provider, candID); canon != "" && strings.EqualFold(canon, cand) && strings.EqualFold(resolveNodeOpenSSHAlias(provider, candID), cleanOrig) {
			return config.OpenSSHNodePrefix + canon
		}
	}
	return ""
}

func resolveMasterVirtualOpenSSHNodeID(provider config.ConfigProvider, cleanOrig, targetHost, user string, port uint16) string {
	parser := providerOpenSSHParser(provider)
	if parser == nil || !parser.HasHost(cleanOrig) {
		return ""
	}
	_, vhost, _, err := parser.GetVirtualNode(cleanOrig)
	if err != nil {
		return ""
	}
	if targetHost == "" || sameMasterHostEndpoint(vhost.Address, 0, targetHost, 0) {
		return config.OpenSSHNodePrefix + cleanOrig
	}
	if user != "" && vhost.Address != "" {
		pendingID := config.FormatNodeID(user, cleanMuxHost(vhost.Address), port)
		if alias := resolvePendingOpenSSHAlias(provider, pendingID); alias != "" {
			if canon := resolvePendingCanonicalHost(provider, pendingID); canon != "" && !strings.EqualFold(alias, canon) {
				return config.OpenSSHNodePrefix + canon
			}
			return config.OpenSSHNodePrefix + alias
		}
	}
	return ""
}

func providerOpenSSHParser(provider config.ConfigProvider) *config.OpenSSHParser {
	if provider == nil {
		return nil
	}
	if src, ok := provider.(interface{ GetOpenSSHParser() *config.OpenSSHParser }); ok {
		return src.GetOpenSSHParser()
	}
	return nil
}

func cleanMuxHost(h string) string {
	return strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(h), "]"), "[")
}

func resolveJumpHopConnection(provider config.ConfigProvider, hop string, hasExplicit bool) (config.ConnectionSnapshot, bool) {
	if provider == nil || hop == "" {
		return config.ConnectionSnapshot{}, false
	}
	unwrapped := strings.TrimPrefix(hop, config.OpenSSHNodePrefix)
	candidates := []string{hop, config.OpenSSHNodePrefix + unwrapped}
	if !hasExplicit {
		if cleanHop, ok := config.OpenSSHOriginalHost(hop); ok && cleanHop != "" {
			candidates = append(candidates, cleanHop)
		}
		if selID, err := provider.ResolveSelector(unwrapped); err == nil && selID != "" {
			candidates = append(candidates, selID)
		}
	}
	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		if snap, err := provider.ResolveConnection(cand); err == nil {
			return snap, true
		}
	}
	return config.ConnectionSnapshot{}, false
}

func addPersistentJumpHopKeys(jumps map[string]bool, hop string, hasExplicit bool) {
	jumps[hop] = true
	unwrapped := strings.TrimPrefix(hop, config.OpenSSHNodePrefix)
	if unwrapped != "" {
		jumps[unwrapped] = true
		jumps[config.OpenSSHNodePrefix+unwrapped] = true
	}
	if !hasExplicit {
		if cleanHop, ok := config.OpenSSHOriginalHost(hop); ok && cleanHop != "" {
			jumps[cleanHop] = true
			jumps[config.OpenSSHNodePrefix+cleanHop] = true
		}
	}
}

func persistentJumpHops(masters []*ssh.MuxServer) map[string]bool {
	return persistentJumpHopsWithProvider(nil, nil, masters)
}

func persistentJumpHopsWithProvider(connector *ssh.Connector, provider config.ConfigProvider, masters []*ssh.MuxServer) map[string]bool {
	jumps := make(map[string]bool, len(masters))
	for _, m := range masters {
		if !canHandoffMaster(m) || m.Target().JumpHost == "" {
			continue
		}
		collectPersistentJumpHopsForTarget(jumps, connector, provider, m, masters)
	}
	return jumps
}

func collectPersistentJumpHopsForTarget(
	jumps map[string]bool,
	connector *ssh.Connector,
	provider config.ConfigProvider,
	targetMaster *ssh.MuxServer,
	masters []*ssh.MuxServer,
) {
	byHost := indexJumpChainMasters(connector, targetMaster, masters)
	visitedHops := make(map[string]bool)
	queue := []string{targetMaster.Target().JumpHost}
	for len(queue) > 0 {
		raw := queue[0]
		queue = queue[1:]
		for hop := range strings.SplitSeq(raw, ",") {
			hop = strings.TrimSpace(hop)
			if hop == "" || visitedHops[hop] {
				continue
			}
			visitedHops[hop] = true
			_, _, _, hasExplicit := parseJumpHopSpec(hop)
			addPersistentJumpHopKeys(jumps, hop, hasExplicit)
			hopMaster, nextJump := lookupJumpHopMaster(connector, byHost, provider, hop, hasExplicit)
			if hopMaster != nil && connector != nil {
				if ownedID := strings.TrimSpace(connector.MasterNodeID(hopMaster)); ownedID != "" {
					jumps[ownedID] = true
				}
			}
			if nextJump != "" {
				queue = append(queue, nextJump)
			}
		}
	}
}

func (o *SshOptions) handoffMasterInstance(ctx context.Context, connector *ssh.Connector, master *ssh.MuxServer, nodeID string) error {
	return o.handoffMasterInstanceWithProvider(ctx, nil, connector, master, nodeID)
}

func (o *SshOptions) handoffMasterInstanceWithProvider(
	ctx context.Context,
	provider config.ConfigProvider,
	connector *ssh.Connector,
	master *ssh.MuxServer,
	nodeID string,
) error {
	return o.handoffMasterInstanceWithProviderAndRawNode(ctx, provider, connector, master, nodeID, nodeID)
}

func (o *SshOptions) handoffMasterInstanceWithProviderAndRawNode(
	ctx context.Context,
	provider config.ConfigProvider,
	connector *ssh.Connector,
	master *ssh.MuxServer,
	nodeID string,
	rawNodeID string,
) error {
	if master == nil || !master.PersistEnabled() {
		return nil
	}
	if ctrl := master.Target().Control; ctrl != nil {
		// 1.A: When multiplexing comes solely from ~/.ssh/config (Tier 4) without
		// explicit CLI or xops config, never spawn a detached background daemon.
		if ctrl.ImplicitTier4 {
			logger.DefaultLogger().Debugf("mux: skipping master handoff for implicit Tier 4 (OpenSSH config) control on %q", master.ControlPath())
			return nil
		}
	}
	if connector != nil && !connector.OwnsMaster(master) {
		return nil
	}
	expandedPath := master.ControlPath()
	if expandedPath == "" {
		return nil
	}
	ready, err := waitAndReleaseMastersForHandoffWithProvider(ctx, connector, provider, master, expandedPath)
	if err != nil || !ready {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable for multiplexing daemon failed: %w", err)
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0) //nolint:forbidigo // open os.DevNull for detached multiplexing daemon stdio redirection
	if err != nil {
		return fmt.Errorf("open %s for multiplexing daemon failed: %w", os.DevNull, err)
	}
	defer func() {
		if closeErr := devNull.Close(); closeErr != nil {
			logger.DefaultLogger().Debugf("close multiplexing daemon stdio failed: %v", closeErr)
		}
	}()

	spec := o.buildMuxDaemonSpecWithRawNode(provider, nodeID, rawNodeID, expandedPath, master)
	cmd, err := startMuxDaemonCommand(exe, spec, devNull)
	if err != nil {
		return fmt.Errorf("start multiplexing daemon failed: %w", err)
	}
	// The child re-authenticates on its own. Interactive-only credentials cannot
	// be inherited, so a failed handoff is advisory: the command already ran.
	// Watch for an early exit so a doomed daemon does not stall the shell for the
	// whole readiness timeout.
	daemonExited := make(chan struct{})
	go func() {
		defer close(daemonExited)
		_ = cmd.Wait()
	}()

	// The command already finished, so a slow or unauthenticated daemon must not
	// be reported as a command failure. Report it and keep the exit status.
	expectedPID := 0
	if cmd.Process != nil {
		expectedPID = cmd.Process.Pid
	}
	if err := waitForControlSocketPID(ctx, expandedPath, 10*time.Second, daemonExited, expectedPID); err != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			killTimer := time.NewTimer(2 * time.Second)
			select {
			case <-daemonExited:
			case <-killTimer.C:
			}
			killTimer.Stop()
		}
		logger.DefaultLogger().Debugf("mux: persistent master handoff on %q failed: %v", expandedPath, err)
		if _, writeErr := fmt.Fprintf(os.Stderr, "warning: connection sharing master could not be kept alive on %s: %v\n", expandedPath, err); writeErr != nil {
			logger.DefaultLogger().Debugf("write handoff warning failed: %v", writeErr)
		}
	}
	return nil
}

func waitAndReleaseMastersForHandoffWithProvider(
	ctx context.Context,
	connector *ssh.Connector,
	provider config.ConfigProvider,
	master *ssh.MuxServer,
	expandedPath string,
) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if isMasterDeadOrStopped(master) {
			return false, nil
		}
		if _, ok := collectLiveJumpMastersForHandoff(connector, provider, master); !ok {
			return false, nil
		}
		if err := drainOwnedMastersWithProvider(ctx, provider, connector); err != nil {
			return false, nil
		}
		if isMasterDeadOrStopped(master) {
			return false, nil
		}
		ready, terminalAbort, err := releaseMastersForHandoffWithProvider(connector, provider, master, expandedPath)
		if err != nil {
			return false, err
		}
		if ready {
			return true, nil
		}
		if terminalAbort || connector == nil || isMasterDeadOrStopped(master) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, nil
		case <-master.Wait():
			return false, nil
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// drainOwnedMasters waits for any secondary client sessions or dynamic forwards
// on masters started by connector to finish before the foreground process tears
// down its transport or hands the control socket over to a daemon.
func drainOwnedMasters(ctx context.Context, connector *ssh.Connector) error {
	return drainOwnedMastersWithProvider(ctx, nil, connector)
}

func drainOwnedMastersWithProvider(ctx context.Context, provider config.ConfigProvider, connector *ssh.Connector) error {
	if connector == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	masters := connector.Masters()
	for i := len(masters) - 1; i >= 0; i-- {
		m := masters[i]
		if m == nil || isMasterClosed(m) {
			continue
		}
		maxSessions := int32(0)
		if connector.HasMasterSession(m) {
			maxSessions = 1
		}
		if err := m.WaitForDrain(ctx, maxSessions); err != nil {
			return err
		}
		if m.StoppedListening() {
			if err := retireStoppedOwnedMaster(ctx, provider, connector, m, masters, masters[i+1:]); err != nil {
				return err
			}
		}
	}
	return nil
}

func retireStoppedOwnedMaster(
	ctx context.Context,
	provider config.ConfigProvider,
	connector *ssh.Connector,
	m *ssh.MuxServer,
	allMasters []*ssh.MuxServer,
	innerMasters []*ssh.MuxServer,
) error {
	var deps []*ssh.MuxServer
	for _, dep := range innerMasters {
		if dep == nil || isMasterClosed(dep) {
			continue
		}
		if slices.Contains(jumpChainMastersWithProvider(connector, provider, dep, allMasters), m) {
			deps = append(deps, dep)
		}
	}
	connector.ReleaseMaster(m)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.Wait():
	}
	for _, dep := range deps {
		connector.ReleaseMaster(dep)
		_ = dep.Shutdown()
	}
	return nil
}

type postAuthLocalRunner interface {
	RunPostAuthLocalCommand(ctx context.Context) error
}

func runPostAuthLocalCommand(ctx context.Context, client postAuthLocalRunner, effOpts *ssh.Options, stderr io.Writer, isChild bool) error {
	if isChild || client == nil || effOpts == nil {
		return nil
	}
	if !effOpts.PermitLocalCommand() {
		return nil
	}
	cmd := strings.TrimSpace(effOpts.LocalCommand())
	if cmd == "" || cmd == "none" {
		return nil
	}
	if err := client.RunPostAuthLocalCommand(ctx); err != nil {
		if exitOnFail, _ := effOpts.ExitOnForwardFailure(); exitOnFail {
			return fmt.Errorf("LocalCommand failed: %w", err)
		}
		if stderr != nil {
			_, _ = fmt.Fprintf(stderr, "Warning: LocalCommand failed: %v\n", err)
		}
	}
	return nil
}

// jumpChainMasters returns the subset of ownedMasters that belong to targetMaster's
// transitive ProxyJump chain so multi-host handoffs never shut down unrelated
// target masters.
func jumpChainMasters(connector *ssh.Connector, targetMaster *ssh.MuxServer, ownedMasters []*ssh.MuxServer) []*ssh.MuxServer {
	return jumpChainMastersWithProvider(connector, nil, targetMaster, ownedMasters)
}

func jumpChainMastersWithProvider(
	connector *ssh.Connector,
	provider config.ConfigProvider,
	targetMaster *ssh.MuxServer,
	ownedMasters []*ssh.MuxServer,
) []*ssh.MuxServer {
	if targetMaster == nil || len(ownedMasters) == 0 {
		return nil
	}
	byHost := indexJumpChainMasters(connector, targetMaster, ownedMasters)
	var chain []*ssh.MuxServer
	seen := make(map[*ssh.MuxServer]bool)
	visitedHops := make(map[string]bool)
	queue := []string{targetMaster.Target().JumpHost}
	for len(queue) > 0 {
		raw := queue[0]
		queue = queue[1:]
		for hop := range strings.SplitSeq(raw, ",") {
			hop = strings.TrimSpace(hop)
			if hop == "" || visitedHops[hop] {
				continue
			}
			visitedHops[hop] = true
			_, _, _, hasExplicit := parseJumpHopSpec(hop)
			hopMaster, nextJump := lookupJumpHopMaster(connector, byHost, provider, hop, hasExplicit)
			if hopMaster != nil && !seen[hopMaster] {
				seen[hopMaster] = true
				chain = append(chain, hopMaster)
			}
			if nextJump != "" {
				queue = append(queue, nextJump)
			}
		}
	}
	return chain
}

func lookupJumpHopMaster(
	connector *ssh.Connector,
	byHost map[string]*ssh.MuxServer,
	provider config.ConfigProvider,
	hop string,
	hasExplicit bool,
) (*ssh.MuxServer, string) {
	unwrapped := strings.TrimPrefix(hop, config.OpenSSHNodePrefix)
	candidates := []string{hop, unwrapped, config.OpenSSHNodePrefix + unwrapped}
	if !hasExplicit {
		if cleanHop, isOpenSSH := config.OpenSSHOriginalHost(hop); isOpenSSH && cleanHop != "" {
			candidates = append(candidates, cleanHop, config.OpenSSHNodePrefix+cleanHop)
		}
	}
	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		if hopMaster, ok := byHost[cand]; ok && hopMaster != nil {
			return hopMaster, strings.TrimSpace(hopMaster.Target().JumpHost)
		}
	}
	snap, resolved := resolveJumpHopConnection(provider, hop, hasExplicit)
	if !resolved {
		return nil, ""
	}
	if snap.Node.SSHOptions != nil && strings.EqualFold(snap.Node.SSHOptions.Get(ssh.OptionControlMaster), "no") {
		return nil, strings.TrimSpace(snap.Node.ProxyJump)
	}
	if snap.Identity.User != "" && snap.Host.Address != "" && snap.Host.Port > 0 {
		compKey := config.FormatNodeID(snap.Identity.User, cleanMuxHost(snap.Host.Address), snap.Host.Port)
		if hopMaster, ok := byHost[compKey]; ok && hopMaster != nil {
			ownedID := ""
			if connector != nil {
				ownedID = strings.TrimSpace(connector.MasterNodeID(hopMaster))
			}
			if ownedID == "" || ownedID == compKey {
				nextJump := strings.TrimSpace(hopMaster.Target().JumpHost)
				if nextJump == "" {
					nextJump = strings.TrimSpace(snap.Node.ProxyJump)
				}
				return hopMaster, nextJump
			}
		}
	}
	return nil, strings.TrimSpace(snap.Node.ProxyJump)
}

func indexJumpChainMasters(connector *ssh.Connector, targetMaster *ssh.MuxServer, ownedMasters []*ssh.MuxServer) map[string]*ssh.MuxServer {
	byHost := make(map[string]*ssh.MuxServer, len(ownedMasters)*2)
	for _, m := range ownedMasters {
		if m == nil || m == targetMaster {
			continue
		}
		indexSingleJumpChainMaster(byHost, connector, m)
	}
	return byHost
}

func indexSingleJumpChainMaster(byHost map[string]*ssh.MuxServer, connector *ssh.Connector, m *ssh.MuxServer) {
	var ownedExplicit bool
	if connector != nil {
		if ownedID := strings.TrimSpace(connector.MasterNodeID(m)); ownedID != "" {
			byHost[ownedID] = m
			_, _, _, ownedExplicit = parseJumpHopSpec(ownedID)
			unwrapped := strings.TrimPrefix(ownedID, config.OpenSSHNodePrefix)
			if unwrapped != "" {
				byHost[unwrapped] = m
				byHost[config.OpenSSHNodePrefix+unwrapped] = m
			}
			if !ownedExplicit {
				if cleanID, ok := config.OpenSSHOriginalHost(ownedID); ok && cleanID != "" {
					byHost[cleanID] = m
					byHost[config.OpenSSHNodePrefix+cleanID] = m
				}
			}
		}
	}
	t := m.Target()
	if orig := strings.TrimSpace(t.OriginalHost); orig != "" {
		cleanOrig := config.UnwrapOpenSSHSelector(orig)
		if cleanOrig != "" && t.User != "" && t.Port > 0 {
			comp := config.FormatNodeID(t.User, cleanOrig, uint16(t.Port))
			byHost[comp] = m
			byHost[config.OpenSSHNodePrefix+comp] = m
		}
		if !ownedExplicit {
			byHost[orig] = m
		}
	}
	if host := strings.TrimSpace(t.Host); host != "" {
		if t.User != "" && t.Port > 0 {
			byHost[config.FormatNodeID(t.User, cleanMuxHost(host), uint16(t.Port))] = m
		}
		if !ownedExplicit {
			byHost[host] = m
		}
	}
}

// releaseMastersForHandoff drops the connector's active-session references,
// reserves the target and any intermediate jump masters for handoff, and shuts
// them down so the detached daemon can claim the control sockets cleanly.
func releaseMastersForHandoff(connector *ssh.Connector, master *ssh.MuxServer, expandedPath string) (bool, error) {
	ready, _, err := releaseMastersForHandoffWithProvider(connector, nil, master, expandedPath)
	return ready, err
}

func collectLiveJumpMastersForHandoff(
	connector *ssh.Connector,
	provider config.ConfigProvider,
	master *ssh.MuxServer,
) (jumpMasters []*ssh.MuxServer, ok bool) {
	if connector == nil {
		return nil, true
	}
	if !connector.OwnsMaster(master) {
		return nil, false
	}
	jumpMasters = jumpChainMastersWithProvider(connector, provider, master, connector.Masters())
	for _, m := range jumpMasters {
		if isMasterDeadOrStopped(m) {
			return nil, false
		}
	}
	return jumpMasters, true
}

func rollbackHandoffReservation(connector *ssh.Connector, reserved, released []*ssh.MuxServer) {
	for _, r := range reserved {
		r.CancelHandoff()
	}
	if connector == nil {
		return
	}
	for _, m := range released {
		connector.AcquireMaster(m)
	}
}

func reserveJumpMasterForHandoff(
	connector *ssh.Connector,
	m *ssh.MuxServer,
	reserved, released *[]*ssh.MuxServer,
) (ok bool, deadOrStopped bool) {
	// Connector-owned non-persistent masters trigger immediate async Shutdown() inside
	// RemoveForegroundSession() when activeSessions reaches 0 (causing PrepareHandoff
	// to fail with s.shuttingDown == true and tearing down active forwards). Reserve
	// them atomically with maxSessions=1 while keeping the foreground session ref
	// until commit.
	if !m.PersistEnabled() && connector != nil && connector.HasMasterSession(m) {
		if !m.PrepareHandoffWithSessions(1) {
			return false, isMasterDeadOrStopped(m)
		}
		*reserved = append(*reserved, m)
		return true, false
	}
	if connector != nil && connector.HasMasterSession(m) && connector.ReleaseMaster(m) {
		*released = append(*released, m)
	}
	if !m.PrepareHandoff() {
		return false, isMasterDeadOrStopped(m)
	}
	*reserved = append(*reserved, m)
	return true, false
}

func releaseMastersForHandoffWithProvider(
	connector *ssh.Connector,
	provider config.ConfigProvider,
	master *ssh.MuxServer,
	expandedPath string,
) (ready bool, terminalAbort bool, err error) {
	if isMasterDeadOrStopped(master) {
		return false, true, nil
	}
	jumpMasters, ok := collectLiveJumpMastersForHandoff(connector, provider, master)
	if !ok {
		return false, true, nil
	}
	var released []*ssh.MuxServer
	if connector != nil && connector.HasMasterSession(master) && connector.ReleaseMaster(master) {
		released = append(released, master)
	}
	if !master.PrepareHandoff() {
		rollbackHandoffReservation(connector, nil, released)
		if isMasterDeadOrStopped(master) {
			return false, true, nil
		}
		logger.DefaultLogger().Debugf("mux: not handing off master on %q while it is busy or stopping", expandedPath)
		return false, false, nil
	}
	reserved := []*ssh.MuxServer{master}
	for _, m := range jumpMasters {
		jumpOK, jumpDead := reserveJumpMasterForHandoff(connector, m, &reserved, &released)
		if !jumpOK {
			rollbackHandoffReservation(connector, reserved, released)
			if jumpDead || isMasterDeadOrStopped(master) {
				return false, true, nil
			}
			logger.DefaultLogger().Debugf("mux: not handing off master on %q while jump master %q is busy or stopping", expandedPath, m.ControlPath())
			return false, false, nil
		}
	}
	if !master.CommitHandoffReady() {
		rollbackHandoffReservation(connector, reserved, released)
		return false, true, nil
	}
	for _, m := range jumpMasters {
		if m != nil && !m.CommitHandoffReady() {
			rollbackHandoffReservation(connector, reserved, released)
			return false, true, nil
		}
	}
	if err := master.Shutdown(); err != nil {
		rollbackHandoffReservation(connector, reserved[1:], released)
		return false, false, fmt.Errorf("release control socket before daemon handoff failed: %w", err)
	}
	for _, m := range jumpMasters {
		if connector != nil && connector.HasMasterSession(m) {
			connector.ReleaseMaster(m)
		}
		_ = m.Shutdown()
	}
	return true, false, nil
}

// waitForControlSocket blocks until a master answers on path, the deadline
// elapses, the caller cancels, or the daemon process we are waiting for exits.
func waitForControlSocket(ctx context.Context, path string, timeout time.Duration, daemonExited <-chan struct{}) error {
	return waitForControlSocketPID(ctx, path, timeout, daemonExited, 0)
}

func waitForControlSocketPID(ctx context.Context, path string, timeout time.Duration, daemonExited <-chan struct{}, expectedPID int) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	daemonExitErr := func() error {
		if lastErr == nil {
			return fmt.Errorf("master daemon exited before it answered on %q", path)
		}
		return fmt.Errorf("master daemon exited before it answered on %q: %w", path, lastErr)
	}

	for {
		if daemonExited != nil {
			select {
			case <-daemonExited:
				return daemonExitErr()
			default:
			}
		}

		probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		client, err := ssh.DialMuxClient(probeCtx, path)
		if err == nil {
			var pid uint32
			pid, lastErr = client.AliveCheck(probeCtx)
			_ = client.Close()
			if lastErr == nil {
				if expectedPID > 0 && int(pid) != expectedPID {
					lastErr = fmt.Errorf("control socket %q answered by pid %d, expected daemon pid %d", path, pid, expectedPID)
				} else {
					cancel()
					return nil
				}
			}
		} else {
			lastErr = err
		}
		cancel()

		if err := ctx.Err(); err != nil {
			return fmt.Errorf("waiting for master on %q canceled: %w", path, err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("master did not answer on %q within %s: %w", path, timeout, lastErr)
		}
		if remaining > controlSocketPollInterval {
			remaining = controlSocketPollInterval
		}

		// Waiting on the timer alone would hide an early daemon exit until the
		// next poll; wake on it (and on cancellation) instead.
		timer := time.NewTimer(remaining)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("waiting for master on %q canceled: %w", path, ctx.Err())
		case <-daemonExited:
			timer.Stop()
			return daemonExitErr()
		case <-timer.C:
		}
	}
}

// controlSocketPollInterval bounds how long the handoff waits between probes.
const controlSocketPollInterval = 100 * time.Millisecond

func (o *SshOptions) loadConfigRepository() (*config.Repository, *config.Configuration, error) {
	configPath, keyPath, pathErr := utils.GetConfigFilePath()
	if pathErr != nil {
		return nil, nil, fmt.Errorf("get config file path failed: %w", pathErr)
	}
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("ssh_err_load_config"), err)
	}
	provider, err := config.NewRepository(cfg, configStore)
	if err != nil {
		return nil, nil, fmt.Errorf("create configuration repository: %w", err)
	}
	return provider, cfg, nil
}

func (o *SshOptions) connectClient(ctx context.Context, connector *ssh.Connector, nodeID string, isChild bool) (*ssh.Client, error) {
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		if isChild || o.StdioForward != "" || o.Subsystem {
			// 子进程或 -W 标准流转发静默退出或记录错误，不污染二进制 stdout
			return nil, sshConnectionError(nodeID, err)
		}
		promptErr := promptPressEnterIfTUI(os.Stdin, os.Stdout)
		return nil, errors.Join(sshConnectionError(nodeID, err), promptErr)
	}
	return client, nil
}

func (o *SshOptions) maybeRedirectStdinNull() (func() error, error) {
	if !o.effectiveStdinNull() || o.stdinRedirected {
		return func() error { return nil }, nil
	}
	devNull, devErr := os.Open(os.DevNull) //nolint:forbidigo // open os.DevNull for SSH -n stdin redirection
	if devErr != nil {
		return nil, fmt.Errorf("open %s for SSH stdin failed: %w", os.DevNull, devErr)
	}
	oldStdin := os.Stdin
	os.Stdin = devNull
	o.stdinRedirected = true
	return func() error {
		os.Stdin = oldStdin
		o.stdinRedirected = false
		if closeErr := devNull.Close(); closeErr != nil {
			return fmt.Errorf("close SSH stdin redirect failed: %w", closeErr)
		}
		return nil
	}, nil
}

func (o *SshOptions) isNodeConfirmationSuppressed(cfg *config.Configuration, provider config.ConfigProvider) bool {
	if _, isRepo := provider.(*config.Repository); !isRepo {
		return true
	}
	policy := utils.EffectiveRememberPolicy(o.Remember, cfg)
	return policy == utils.RememberPolicyNever || o.isMuxDaemon() || o.isBackgroundChild()
}

func (o *SshOptions) withValidatedConnectionNode(ctx context.Context, provider config.ConfigProvider, fn func(config.PendingLease) error) error {
	req, err := o.buildPendingEnsureOptions(ctx, provider)
	if err != nil {
		return err
	}
	return config.WithPendingNode(ctx, provider, req, func(lease config.PendingLease) error {
		if _, err := o.resolveAndCacheSessionOptions(provider, lease.NodeID()); err != nil {
			return err
		}
		if err := o.validatePostResolutionSessionInvariants(); err != nil {
			return err
		}
		return fn(lease)
	})
}

func (o *SshOptions) newConnectionConnectorAndAdapter(cfg *config.Configuration, provider config.ConfigProvider, nodeID string, isChild bool) (*ssh.Connector, *adapter.SSHAdapter, error) {
	adpOpts, err := o.buildAdapterOptions(nodeID, cfg, provider)
	if err != nil {
		return nil, nil, err
	}
	if o.isMuxDaemon() || isChild {
		connector, adp := newNonInteractiveConnectorAndAdapter(provider, adpOpts, ssh.WithSessionConfirmer(o.interaction), ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(o.diagnostics))
		return connector, adp, nil
	}
	connector, adp := newCLIConnectorAndAdapter(provider, o.interaction, adpOpts, ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(o.diagnostics))
	return connector, adp, nil
}

func (o *SshOptions) runConnection(ctx context.Context, isChild bool) (err error) {
	repo, cfg, err := o.loadConfigRepository()
	if err != nil {
		return err
	}
	provider, err := config.WithOpenSSHConfigOverride(repo, o.control.ConfigFile)
	if err != nil {
		return err
	}
	return o.runConnectionWithProvider(ctx, cfg, provider, isChild)
}

func (o *SshOptions) runConnectionWithProvider(ctx context.Context, cfg *config.Configuration, provider config.ConfigProvider, isChild bool) error {
	return o.withValidatedConnectionNode(ctx, provider, func(lease config.PendingLease) (err error) {
		nodeID := lease.NodeID()
		if !isChild && !o.isMuxDaemon() && o.effectiveBgRun() {
			if err := o.validateBackgroundProxyCommand(provider, nodeID); err != nil {
				return err
			}
			return o.runParentDaemonWithLease(ctx, cfg, provider, lease)
		}
		connector, adp, err := o.newConnectionConnectorAndAdapter(cfg, provider, nodeID, isChild)
		if err != nil {
			return err
		}
		defer func() {
			joinConnectorCloseError(&err, connector)
		}()
		client, err := o.connectClient(ctx, connector, nodeID, isChild)
		if err != nil {
			return err
		}
		if finalizeErr := adp.FinalizePendingConnection(ctx, lease, client); finalizeErr != nil {
			_ = connector.EvictClient(client)
			promptErr := promptPressEnterIfTUI(os.Stdin, os.Stdout)
			return errors.Join(sshConnectionError(nodeID, finalizeErr), promptErr)
		}
		defer func() {
			if closeErr := client.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close SSH client failed: %w", closeErr))
			}
		}()
		if lcErr := runPostAuthLocalCommand(ctx, client, o.effectiveSSHOptions, os.Stderr, isChild); lcErr != nil {
			return lcErr
		}
		// Setup background context for tunnels and execution (runs until SigInt or command exit)
		runCtx, runCancel := context.WithCancel(ctx)
		defer runCancel()

		// Keep a persistent master alive across the process boundary. Registered
		// here so it runs after tunnels are closed but before the client and
		// connector are torn down, and it never changes the command's exit status.
		// Pass the outer ctx (not runCtx) so that normal tunnel closure does not
		// look like user cancellation to handoffPersistentMaster.
		defer func() {
			if handoffErr := o.handoffPersistentMaster(ctx, connector, provider, nodeID); handoffErr != nil {
				logger.DefaultLogger().Debugf("mux: master handoff failed: %v", handoffErr)
			}
		}()

		// Keep output on the command context while tunnels own their child context.
		tunnels, err := o.startTunnels(ctx, runCancel, client)
		if err != nil {
			return err
		}
		defer func() {
			if closeErr := tunnels.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("stop SSH tunnels failed: %w", closeErr))
			}
		}()

		restoreStdin, err := o.maybeRedirectStdinNull()
		if err != nil {
			return err
		}
		defer func() {
			if restoreErr := restoreStdin(); restoreErr != nil {
				err = errors.Join(err, restoreErr)
			}
		}()

		return o.runConnectedSession(runCtx, connector, client, provider, nodeID, tunnels, isChild)
	})
}

func (o *SshOptions) runConnectedSession(runCtx context.Context, connector *ssh.Connector, client *ssh.Client, provider config.ConfigProvider, nodeID string, tunnels *sshTunnelGroup, isChild bool) error {
	master := o.getActiveMuxServer(runCtx, provider, nodeID)
	if isMasterClosed(master) && connector != nil {
		master = findOwnedMasterForNode(connector, nodeID)
	}
	if o.isMuxDaemon() {
		if err := prepareMuxDaemonSession(connector, master, nodeID); err != nil {
			return err
		}
	}
	if o.StdioForward != "" {
		destHost, destPort, err := ssh.ParseStdioForward(o.StdioForward)
		if err != nil {
			return err
		}
		return client.ForwardStdio(runCtx, destHost, destPort, os.Stdin, os.Stdout)
	}
	if o.effectiveNoCmd() {
		return o.runNoCmdSession(runCtx, connector, client, master, nodeID, tunnels, isChild)
	}

	if o.Subsystem {
		return client.RunSubsystemWithIO(runCtx, strings.TrimSpace(o.Command), os.Stdin, os.Stdout, os.Stderr, o.subsystemAllocatePTY(os.Stdin))
	}

	if o.Command != "" || o.stdinScript {
		return o.runCommand(runCtx, client, o.Command)
	}

	var target ssh.TargetContext
	if o.resolvedTarget != nil {
		target = *o.resolvedTarget
	} else {
		target = controlTarget(o, provider, nodeID)
	}
	rc, rcErr := o.resolveEffectiveRemoteCommand(target)
	if rcErr != nil {
		return rcErr
	}
	if rc != "" {
		return o.runCommand(runCtx, client, rc)
	}

	return o.runShell(runCtx, client)
}

func (o *SshOptions) runNoCmdSession(runCtx context.Context, connector *ssh.Connector, client *ssh.Client, master *ssh.MuxServer, nodeID string, tunnels *sshTunnelGroup, isChild bool) error {
	if !isChild && !o.diagnostic.quiet {
		if o.control.MasterCount > 0 && master == nil && (connector == nil || len(connector.Masters()) == 0) {
			_, _ = fmt.Fprintln(os.Stderr, "warning: -M specified without an active ControlPath; connection sharing master is not listening")
		}
		if err := tunnels.reportReady(runCtx, os.Stdout, nodeID); err != nil {
			return err
		}
	}
	// A non-daemon -N master keeps the foreground-session reference acquired
	// by Connector until the operator stops it, and drops that reference on
	// -O stop so the process exits once any client sessions drain.
	if master != nil && !o.isMuxDaemon() {
		master.ReleaseForegroundOnStop()
	}
	var masterWait <-chan struct{}
	if master != nil {
		masterWait = master.Wait()
	}
	select {
	case <-runCtx.Done():
	case <-masterWait:
	}
	if o.isMuxDaemon() && runCtx.Err() == nil && connector != nil {
		_ = client.Close()
		waitForDaemonJumpMasters(runCtx, connector, master)
	}
	return nil
}

func prepareMuxDaemonSession(connector *ssh.Connector, master *ssh.MuxServer, nodeID string) error {
	if master == nil || (connector != nil && !connector.OwnsMaster(master)) {
		return fmt.Errorf("multiplexing daemon did not acquire control socket for %s", nodeID)
	}
	if connector != nil {
		// Release the foreground reference on the terminal master so its idle
		// timer can run. Any upstream ProxyJump masters owned by this daemon keep
		// their reference until the terminal master exits, preventing an earlier
		// jump idle timeout from tearing down the target's transport.
		connector.ReleaseMaster(master)
	}
	return nil
}

func waitForDaemonJumpMasters(ctx context.Context, connector *ssh.Connector, targetMaster *ssh.MuxServer) {
	masters := connector.Masters()
	for i := len(masters) - 1; i >= 0; i-- {
		m := masters[i]
		if m == nil || m == targetMaster || !m.PersistEnabled() {
			continue
		}
		connector.ReleaseMaster(m)
		select {
		case <-ctx.Done():
			return
		case <-m.Wait():
		}
	}
}

func (o *SshOptions) isMuxDaemon() bool {
	return o != nil && o.muxDaemonMode
}

func (o *SshOptions) isBackgroundChild() bool {
	return o != nil && (o.bgChildMode || o.muxDaemonMode)
}

func sshConnectionError(nodeID string, err error) error {
	return fmt.Errorf("[%s] %s: %w", nodeID, i18n.T("ssh_connection_failed_label"), err)
}

func passthroughOrWrapShellError(err error) error {
	var exitReported interface {
		ExitCode() int
		AlreadyReported() bool
	}
	if errors.As(err, &exitReported) && exitReported.AlreadyReported() {
		return err
	}
	return fmt.Errorf("%s: %w", i18n.T("ssh_err_shell"), err)
}

func (o *SshOptions) runShell(ctx context.Context, client *ssh.Client) error {
	if o.Sudo {
		if err := client.ShellWithSudo(ctx); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("sudo_exec_failed"), err)
		}
		return nil
	}
	switch o.effectiveRequestTTY() {
	case ssh.RequestTTYNo:
		if err := o.runPipedShellWithStreams(ctx, client, os.Stdin, os.Stdout, os.Stderr); err != nil {
			return passthroughOrWrapShellError(err)
		}
		return nil
	case ssh.RequestTTYForce:
		if _, isTerm := isLocalTerminal(os.Stdin); !isTerm {
			if err := client.RunShellWithRemotePTY(ctx, os.Stdin, os.Stdout, os.Stderr); err != nil {
				return passthroughOrWrapShellError(err)
			}
			return nil
		}
	}
	if err := client.Shell(ctx); err != nil {
		return passthroughOrWrapShellError(err)
	}
	return nil
}

// parseForwardArg parses standard SSH forward argument limits.
// Supports both [bind_address:]port:host:hostport and "[bind_address:]port host:hostport".
func parseForwardArg(arg string) (bindAddr, destAddr string, err error) {
	spec, err := ssh.ParseForwardSpec(arg)
	if err != nil {
		return "", "", err
	}
	return spec.BindAddr, spec.DestAddr, nil
}

func (o *SshOptions) applyHostnameCanonicalization(ctx context.Context, provider config.ConfigProvider, resolver config.CanonicalResolver) error {
	if o == nil || provider == nil || o.isMuxDaemon() || o.canonicalized {
		return nil
	}
	host := strings.TrimSpace(o.Target.Selector)
	if host == "" {
		host = strings.TrimSpace(o.Host)
	}
	if host == "" || config.IsOpenSSHNodeID(host) {
		return nil
	}
	var matchedSavedNode bool
	if resolved, err := config.ResolveTarget(provider, effectiveConnectionTarget(o, "")); err == nil {
		matchedSavedNode = isResolvedSavedNode(resolved)
	}
	if resolver == nil {
		resolver = o.canonicalResolver
	}
	res, err := config.CanonicalizeHost(ctx, config.CanonicalizeInput{
		Provider:         provider,
		Host:             host,
		RawCLIOptions:    o.control.Options,
		CLIProxyJump:     o.effectiveCLIJumpHost(),
		MatchedSavedNode: matchedSavedNode,
		Resolver:         resolver,
	})
	if err != nil {
		return err
	}
	if !res.Canonicalized {
		return nil
	}
	o.canonicalized = true
	o.originalHost = res.OriginalHost
	o.expandHost = res.OriginalHost
	o.Host = res.CanonicalHost
	o.Target.Selector = res.CanonicalHost
	o.Target.OriginalHost = res.OriginalHost
	return nil
}

func (o *SshOptions) buildPendingEnsureOptions(ctx context.Context, provider config.ConfigProvider) (config.EnsureNodeOptions, error) {
	o.syncIdentityFiles()
	if err := o.applyHostnameCanonicalization(ctx, provider, nil); err != nil {
		return config.EnsureNodeOptions{}, err
	}
	o.syncResolvedTargetHosts(provider)

	var defaultUser string
	if !o.Target.HasUser {
		var err error
		defaultUser, err = utils.GetCurrentUser()
		if err != nil {
			return config.EnsureNodeOptions{}, fmt.Errorf("get current user failed: %w", err)
		}
	}
	var snap *config.Configuration
	if provider != nil {
		snap = provider.Snapshot()
	}
	stageUpdate := !o.isNodeConfirmationSuppressed(snap, provider)
	shouldRemember := utils.EffectiveRememberPolicy(o.Remember, snap) == utils.RememberPolicyAlways

	return config.EnsureNodeOptions{
		Target:       o.Target,
		DefaultUser:  defaultUser,
		Password:     "",
		IdentityFile: o.IdentityFile,
		Passphrase:   "",
		Alias:        o.Alias,
		Tags:         o.Tags,
		ExistingUpdate: config.PendingNodeUpdate{
			Enabled:      stageUpdate,
			JumpHost:     o.JumpHost,
			Alias:        o.Alias,
			Tags:         o.Tags,
			RememberAuth: shouldRemember,
			HasPassword:  o.Password != "",
			IdentityFile: o.IdentityFile,
		},
	}, nil
}

type sshTunnelGroup struct {
	cancel     context.CancelFunc
	done       sync.WaitGroup
	errMu      sync.Mutex
	err        error
	stderr     *sshDiagnostics // Borrowed from the command, or owned when not verbose.
	ownsStderr bool
	stdout     *diagnosticOutput // Optional ready status, owned until Close.
}

func newSSHTunnelGroup(ctx context.Context, cancelParent context.CancelFunc) (*sshTunnelGroup, context.Context) {
	tunnelCtx, cancel := context.WithCancel(ctx)
	group := &sshTunnelGroup{cancel: cancel}
	if cancelParent == nil {
		cancelParent = func() {}
	}
	groupCancel := group.cancel
	group.cancel = func() {
		groupCancel()
		cancelParent()
	}
	return group, tunnelCtx
}

func (g *sshTunnelGroup) Add(forward *ssh.Forward) {
	g.addWait(forward.Wait)
}

func (g *sshTunnelGroup) addWait(wait func() error) {
	g.done.Go(func() {
		if err := wait(); err != nil {
			g.errMu.Lock()
			g.err = errors.Join(g.err, err)
			g.errMu.Unlock()
			g.cancel()
		}
	})
}

func (g *sshTunnelGroup) Close() error {
	if g == nil {
		return nil
	}
	g.cancel()
	g.done.Wait()
	// All callback producers have stopped. Never close a command-owned stderr;
	// RunContext releases that shared queue after its connector has also stopped.
	var outputErr error
	if g.ownsStderr {
		outputErr = g.stderr.finish()
	}
	if g.stdout != nil {
		outputErr = errors.Join(outputErr, g.stdout.finish())
	}
	g.errMu.Lock()
	defer g.errMu.Unlock()
	return errors.Join(g.err, outputErr)
}

// reportReady preserves stdout and the original status text without a raw
// write. The caller finishes setup before Close, which joins the owned writer.
func (g *sshTunnelGroup) reportReady(ctx context.Context, target io.Writer, nodeID string) error {
	if g.stdout == nil {
		output, err := newDiagnosticOutput(ctx, target, "stdout", "ssh")
		if err != nil {
			return err
		}
		g.stdout = output
	}
	g.stdout.enqueue(fmt.Sprintf("SSH tunnels established to %s. Press Ctrl+C to exit.\n", nodeID))
	return nil
}

func (o *SshOptions) attachTunnelDiagnostics(ctx context.Context, group *sshTunnelGroup, stderr io.Writer) error {
	if diagnostics, ok := o.diagnostics.(*sshDiagnostics); ok && diagnostics != nil {
		group.stderr = diagnostics
		return nil
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	var gates []chan struct{}
	if o.interaction != nil {
		gates = append(gates, o.interaction.promptGate)
	}
	output, err := newSSHDiagnostics(ctx, stderr, 0, gates...)
	if err != nil {
		return err
	}
	group.stderr, group.ownsStderr = output, true
	return nil
}

func (g *sshTunnelGroup) registerForward(forward *ssh.Forward, setupErr error, exitOnFailure bool) error {
	if setupErr != nil {
		if !exitOnFailure {
			g.stderr.message(logger.Yellow(fmt.Sprintf("warning: %v", setupErr)) + "\n")
			return nil
		}
		return setupErr
	}
	g.Add(forward)
	return nil
}

func startLocalForwards(tunnelCtx context.Context, group *sshTunnelGroup, client *ssh.Client, fwdCfg sessionForwardConfig, commonOpts []ssh.ForwardOption) error {
	for _, spec := range fwdCfg.localForwards {
		opts := append([]ssh.ForwardOption{
			ssh.WithForwardErrorHandler(func(err error) {
				group.stderr.message(logger.Red(fmt.Sprintf("ssh local forward connection failed: %v", err)) + "\n")
			}),
		}, commonOpts...)
		forward, err := client.LocalForwardEndpoint(tunnelCtx, spec.Bind, spec.Dest, fwdCfg.gatewayPorts, opts...)
		if err != nil {
			err = fmt.Errorf("setup local forward failed: %w", err)
		}
		if fatalErr := group.registerForward(forward, err, fwdCfg.exitOnForwardFailure); fatalErr != nil {
			return fatalErr
		}
	}
	return nil
}

func startRemoteForwards(tunnelCtx context.Context, group *sshTunnelGroup, client *ssh.Client, fwdCfg sessionForwardConfig, commonOpts []ssh.ForwardOption, reportAllocPort bool) error {
	for _, spec := range fwdCfg.remoteForwards {
		opts := append([]ssh.ForwardOption{
			ssh.WithForwardErrorHandler(func(err error) {
				group.stderr.message(logger.Red(fmt.Sprintf("ssh remote forward connection failed: %v", err)) + "\n")
			}),
		}, commonOpts...)
		forward, err := client.RemoteForwardEndpoint(tunnelCtx, spec, opts...)
		if err != nil {
			err = fmt.Errorf("setup remote forward failed: %w", err)
		}
		if fatalErr := group.registerForward(forward, err, fwdCfg.exitOnForwardFailure); fatalErr != nil {
			return fatalErr
		}
		if err == nil && reportAllocPort && !spec.Bind.IsUnix() && spec.Bind.Port == 0 && forward != nil && forward.Addr() != nil {
			_, portStr, splitErr := net.SplitHostPort(forward.Addr().String())
			if splitErr == nil && portStr != "" && portStr != "0" {
				targetDesc := spec.Dest.String()
				if spec.IsDynamic {
					targetDesc = "dynamic"
				}
				group.stderr.message(fmt.Sprintf("Allocated port %s for remote forward to %s\n", portStr, targetDesc))
			}
		}
	}
	return nil
}

func startDynamicForwards(tunnelCtx context.Context, group *sshTunnelGroup, client *ssh.Client, fwdCfg sessionForwardConfig, commonOpts []ssh.ForwardOption) error {
	for _, ep := range fwdCfg.dynamicForwards {
		opts := append([]ssh.ForwardOption{
			ssh.WithForwardErrorHandler(func(err error) {
				group.stderr.message(logger.Red(fmt.Sprintf("ssh SOCKS5 forward connection failed: %v", err)) + "\n")
			}),
		}, commonOpts...)
		forward, err := client.DynamicForwardEndpoint(tunnelCtx, ep, fwdCfg.gatewayPorts, opts...)
		if err != nil {
			err = fmt.Errorf("setup SOCKS5 proxy failed: %w", err)
		}
		if fatalErr := group.registerForward(forward, err, fwdCfg.exitOnForwardFailure); fatalErr != nil {
			return fatalErr
		}
	}
	return nil
}

func startConfiguredForwards(tunnelCtx context.Context, group *sshTunnelGroup, client *ssh.Client, fwdCfg sessionForwardConfig, reportAllocPort bool) error {
	commonOpts := []ssh.ForwardOption{
		ssh.WithStreamLocalBindMask(fwdCfg.streamLocalBindMask),
		ssh.WithStreamLocalBindUnlink(fwdCfg.streamLocalBindUnlink),
	}
	if err := startLocalForwards(tunnelCtx, group, client, fwdCfg, commonOpts); err != nil {
		return err
	}
	if err := startRemoteForwards(tunnelCtx, group, client, fwdCfg, commonOpts, reportAllocPort); err != nil {
		return err
	}
	if err := startDynamicForwards(tunnelCtx, group, client, fwdCfg, commonOpts); err != nil {
		return err
	}
	if fwdCfg.hasTunnelDevice {
		forward, err := client.TunnelDeviceForward(tunnelCtx, fwdCfg.tunnelMode, fwdCfg.tunnelDevice, ssh.WithForwardErrorHandler(func(err error) {
			group.stderr.message(logger.Red(fmt.Sprintf("ssh tunnel device forward failed: %v", err)) + "\n")
		}))
		if err != nil {
			err = fmt.Errorf("setup tunnel device forward failed: %w", err)
		}
		if fatalErr := group.registerForward(forward, err, fwdCfg.exitOnForwardFailure); fatalErr != nil {
			return fatalErr
		}
	}
	return nil
}

func (o *SshOptions) startTunnels(ctx context.Context, cancelParent context.CancelFunc, client *ssh.Client) (*sshTunnelGroup, error) {
	return o.startTunnelsWithStderr(ctx, cancelParent, client, os.Stderr)
}

func (o *SshOptions) startTunnelsWithStderr(ctx context.Context, cancelParent context.CancelFunc, client *ssh.Client, stderr io.Writer) (*sshTunnelGroup, error) {
	group, tunnelCtx := newSSHTunnelGroup(ctx, cancelParent)
	fail := func(err error) (*sshTunnelGroup, error) {
		return nil, errors.Join(err, group.Close())
	}
	fwdCfg, err := o.resolveSessionForwardConfig()
	if err != nil {
		return fail(err)
	}
	hasForwards := len(fwdCfg.localForwards) > 0 ||
		len(fwdCfg.remoteForwards) > 0 ||
		len(fwdCfg.dynamicForwards) > 0 ||
		fwdCfg.hasTunnelDevice
	if hasForwards {
		if err := o.attachTunnelDiagnostics(ctx, group, stderr); err != nil {
			return fail(err)
		}
	}
	if o.effectiveNoCmd() || hasForwards {
		group.addWait(func() error { return client.Wait(tunnelCtx) })
	}
	isChild := o.isBackgroundChild()
	reportAllocPort := !o.diagnostic.quiet && !isChild && !o.isParentValidation
	if err := startConfiguredForwards(tunnelCtx, group, client, fwdCfg, reportAllocPort); err != nil {
		return fail(err)
	}
	return group, nil
}

// Legacy launchers may still request this pause. The current TUI uses owned
// in-process SSH sessions and displays errors after restoring its terminal.
func promptPressEnterIfTUI(stdin io.Reader, stdout io.Writer) error {
	if os.Getenv("XOPS_CLI_SSH_FROM_TUI") == "true" {
		if _, err := fmt.Fprintln(stdout, i18n.T("tui_press_enter")); err != nil {
			return fmt.Errorf("prompt press enter write failed: %w", err)
		}
		var b [1]byte
		if _, err := stdin.Read(b[:]); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read press enter failed: %w", err)
		}
	}
	return nil
}

func (o *SshOptions) effectiveInterpreter(client *ssh.Client) ssh.Interpreter {
	if o.execution.interpreterSet && o.execution.interpreter != "" {
		return ssh.Interpreter(o.execution.interpreter)
	}
	if client != nil && client.Execution() != nil && client.Execution().EffectiveInterpreter() != "" {
		return client.Execution().EffectiveInterpreter()
	}
	return ssh.InterpreterServer
}

func (o *SshOptions) runPipedShellWithStreams(ctx context.Context, client *ssh.Client, stdin io.Reader, stdout, stderr io.Writer) error {
	strict, err := streamOutputSupported(ctx, stdout, stderr)
	if err != nil {
		return err
	}
	if o.execution.enabled() || strict {
		return client.RunShellWithoutPTY(ctx, stdin, stdout, stderr)
	}
	return client.RunShellWithIO(ctx, stdin, stdout, stderr)
}

func (o *SshOptions) runCommand(ctx context.Context, client *ssh.Client, command string) error {
	return o.runCommandWithStreams(ctx, client, command, os.Stdin, os.Stdout, os.Stderr)
}

func (o *SshOptions) commandPlanForPTY(client *ssh.Client, command string) (ssh.CommandPlan, error) {
	if o.commandPlan != nil {
		if o.commandPlan.Command() != command {
			return ssh.CommandPlan{}, fmt.Errorf("command changed after execution planning")
		}
		return *o.commandPlan, nil
	}
	var execCfg *ssh.ExecutionConfig
	if client != nil {
		execCfg = client.Execution()
	}
	if o.execution.enabled() || o.execution.noLoginSet {
		return o.resolveCommandPlan(command, execCfg)
	}
	plan, err := ssh.PlanCommand(command, execCfg.CommandOptions())
	if err != nil {
		return ssh.CommandPlan{}, fmt.Errorf("plan command: %w", err)
	}
	return plan, nil
}

func (o *SshOptions) runPTYCommandIfRequested(ctx context.Context, client *ssh.Client, command string, reqTTY ssh.RequestTTYMode, stdin io.Reader, stdout, stderr io.Writer) (bool, error) {
	if o.Sudo || command == "" || (reqTTY != ssh.RequestTTYYes && reqTTY != ssh.RequestTTYForce) {
		return false, nil
	}
	plan, err := o.commandPlanForPTY(client, command)
	if err != nil {
		return true, err
	}
	if stdinFile, isTerm := isLocalTerminal(stdin); isTerm {
		return true, client.RunInteractivePlanWithIO(ctx, plan, ssh.InteractiveIO{
			Stdin:  stdinFile,
			Stdout: stdout,
			Stderr: stderr,
		})
	}
	if reqTTY == ssh.RequestTTYForce {
		if o.execution.enabled() || o.execution.noLoginSet {
			return true, client.RunCommandPlanWithRemotePTY(ctx, plan, stdin, stdout, stderr)
		}
		strict, err := streamOutputSupported(ctx, stdout, stderr)
		if err != nil {
			return true, err
		}
		if strict {
			return true, client.RunCommandPlanWithRemotePTY(ctx, plan, stdin, stdout, stderr)
		}
		return true, client.RunCommandWithRemotePTY(ctx, command, stdin, stdout, stderr)
	}
	if !o.diagnostic.quiet && stderr != nil {
		_, _ = fmt.Fprintln(stderr, "Pseudo-terminal will not be allocated because stdin is not a terminal.")
	}
	return false, nil
}

func (o *SshOptions) runPipedScriptIfRequested(ctx context.Context, client *ssh.Client, reqTTY ssh.RequestTTYMode, stdin io.Reader, stdout, stderr io.Writer) (bool, error) {
	if o.Sudo || o.Command != "" || !o.stdinScript {
		return false, nil
	}
	if o.effectiveInterpreter(client) != ssh.InterpreterServer {
		switch reqTTY {
		case ssh.RequestTTYForce:
			return true, client.RunCommandWithRemotePTY(ctx, "", stdin, stdout, stderr)
		case ssh.RequestTTYYes:
			if !o.diagnostic.quiet && stderr != nil {
				_, _ = fmt.Fprintln(stderr, "Pseudo-terminal will not be allocated because stdin is not a terminal.")
			}
			return true, client.RunCommandWithIO(ctx, "", false, stdin, stdout, stderr)
		default:
			return false, nil
		}
	}
	if reqTTY == ssh.RequestTTYForce {
		if o.execution.enabled() {
			strict, err := streamOutputSupported(ctx, stdout, stderr)
			if err != nil {
				return true, err
			}
			if !strict {
				return true, fmt.Errorf("unsupported shell output: provide a ContextWriter, terminal, pipe, or regular file")
			}
		}
		return true, client.RunShellWithRemotePTY(ctx, stdin, stdout, stderr)
	}
	if reqTTY == ssh.RequestTTYYes && !o.diagnostic.quiet && stderr != nil {
		_, _ = fmt.Fprintln(stderr, "Pseudo-terminal will not be allocated because stdin is not a terminal.")
	}
	return true, o.runPipedShellWithStreams(ctx, client, stdin, stdout, stderr)
}

func (o *SshOptions) runCommandWithStreams(ctx context.Context, client *ssh.Client, command string, stdin io.Reader, stdout, stderr io.Writer) error {
	reqTTY := o.effectiveRequestTTY()
	if handled, err := o.runPTYCommandIfRequested(ctx, client, command, reqTTY, stdin, stdout, stderr); handled {
		return err
	}
	if o.commandPlan != nil {
		return client.RunCommandPlanWithIO(ctx, *o.commandPlan, stdin, stdout, stderr)
	}
	var execCfg *ssh.ExecutionConfig
	if client != nil {
		execCfg = client.Execution()
	}
	if (o.execution.enabled() || o.execution.noLoginSet) && !o.Sudo && command != "" {
		plan, err := o.resolveCommandPlan(command, execCfg)
		if err != nil {
			return err
		}
		return client.RunCommandPlanWithIO(ctx, plan, stdin, stdout, stderr)
	}
	if handled, err := o.runPipedScriptIfRequested(ctx, client, reqTTY, stdin, stdout, stderr); handled {
		return err
	}
	if !o.Sudo && command != "" {
		plan, err := ssh.PlanCommand(command, execCfg.CommandOptions())
		if err != nil {
			return fmt.Errorf("plan command: %w", err)
		}
		strict, err := streamOutputSupported(ctx, stdout, stderr)
		if err != nil {
			return err
		}
		if strict {
			return client.RunCommandPlanWithIO(ctx, plan, stdin, stdout, stderr)
		}
	}
	return client.RunCommandWithIO(ctx, command, o.Sudo, stdin, stdout, stderr)
}
