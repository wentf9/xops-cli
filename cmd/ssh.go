package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wentf9/xops-cli/cmd/utils"
	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
)

type SshOptions struct {
	interaction        *cliInteractionHandler
	diagnostic         sshDiagnosticOptions
	diagnostics        corelog.DiagnosticObserver
	control            SSHControlFlags
	Host               string
	Port               uint16
	User               string
	Password           string
	PasswordStdin      bool
	OTP                string
	OTPStdin           bool
	IdentityFile       string
	Passphrase         string
	PassphraseStdin    bool
	Remember           string
	Sudo               bool
	Alias              string
	JumpHost           string
	Tags               []string
	LocalForwards      []string
	RemoteForwards     []string
	NoCmd              bool
	DynamicForward     string
	DynamicForwards    []string
	StdioForward       string
	TunnelDevice       string
	DisableTTY         bool
	ForceTTYCount      int
	cliTTYMode         ssh.RequestTTYMode
	cliTunnelMode      string
	cliTunnelLockedByW bool
	BgRun              bool
	StdinRedirect      bool
	args               []string
	dashIdx            int
	parsedArgs         bool
	appliedGeneralOpts bool

	Target config.ConnectionTarget

	Command      string
	stdinScript  bool
	NoLoginShell bool

	execution           execExecutionOptions
	commandPlan         *ssh.CommandPlan
	effectiveSSHOptions *ssh.Options
	targetNodeIDs       []string
}

func NewSshOptions() *SshOptions {
	return &SshOptions{
		Sudo:         false,
		NoLoginShell: false,
		dashIdx:      -1,
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
	cmd.Flags().StringVarP(&o.IdentityFile, "identity", "i", "", i18n.T("flag_identity"))
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "J", "", i18n.T("flag_jump"))
	cmd.Flags().StringSliceVarP(&o.LocalForwards, "local-forward", "L", []string{}, i18n.T("flag_local_forward"))
	cmd.Flags().StringSliceVarP(&o.RemoteForwards, "remote-forward", "R", []string{}, i18n.T("flag_remote_forward"))
	cmd.Flags().BoolVarP(&o.NoCmd, "no-cmd", "N", false, i18n.T("flag_no_cmd"))
	o.registerForwardAndSessionFlags(cmd)
	cmd.Flags().BoolVarP(&o.BgRun, "background", "f", false, i18n.T("flag_background"))
	cmd.Flags().BoolVarP(&o.StdinRedirect, "stdin-redirect", "n", false, i18n.T("flag_stdin_redirect"))

	// xops-enhanced flags (long-form only, no short flags to avoid OpenSSH conflicts)
	cmd.Flags().StringVar(&o.Host, "host", "", i18n.T("flag_host"))
	cmd.Flags().BoolVar(&o.PasswordStdin, "password-stdin", false, i18n.T("flag_password_stdin"))
	cmd.Flags().BoolVar(&o.PassphraseStdin, "passphrase-stdin", false, i18n.T("flag_passphrase_stdin"))
	cmd.Flags().StringVar(&o.OTP, "otp", "", i18n.T("flag_otp"))
	cmd.Flags().BoolVar(&o.OTPStdin, "otp-stdin", false, i18n.T("flag_otp_stdin"))
	cmd.Flags().StringVar(&o.Remember, "remember", "", i18n.T("flag_remember"))
	cmd.Flags().BoolVar(&o.Sudo, "sudo", false, i18n.T("flag_sudo"))
	cmd.Flags().StringVar(&o.Alias, "alias", "", i18n.T("flag_alias"))
	cmd.Flags().StringSliceVar(&o.Tags, "tag", []string{}, i18n.T("flag_tag"))
	o.execution.register(cmd)
	cmd.Flags().BoolVar(&o.NoLoginShell, "no-login", false, i18n.T("flag_exec_no_login"))

	cmd.MarkFlagsMutuallyExclusive("otp", "otp-stdin")

	return cmd
}

func (o *SshOptions) readSecretsFromStdin() (bool, error) {
	hadCredentialStdin := o.OTPStdin || o.PasswordStdin || o.PassphraseStdin
	if o.OTP != "" && o.OTPStdin {
		return false, errors.New(i18n.T("err_otp_mutually_exclusive"))
	}
	if o.OTPStdin {
		otp, err := utils.ReadSecretLineFromStdin()
		if err != nil {
			return false, fmt.Errorf("read otp from stdin: %w", err)
		}
		o.OTP = otp
		o.OTPStdin = false
	}
	if o.PasswordStdin {
		pwd, err := utils.ReadSecretFromStdin()
		if err != nil {
			return false, fmt.Errorf("read password from stdin: %w", err)
		}
		o.Password = pwd
	}
	if o.PassphraseStdin {
		pass, err := utils.ReadSecretFromStdin()
		if err != nil {
			return false, fmt.Errorf("read passphrase from stdin: %w", err)
		}
		o.Passphrase = pass
	}
	return hadCredentialStdin, nil
}

func (o *SshOptions) Complete(cmd *cobra.Command, args []string) error {
	o.args = args
	o.dashIdx = -1
	o.parsedArgs = false
	o.appliedGeneralOpts = false
	var flags *pflag.FlagSet
	if cmd != nil {
		flags = cmd.Flags()
		o.dashIdx = cmd.ArgsLenAtDash()
	}
	if err := ApplyGeneralOptions(o, o.control.Options, flags); err != nil {
		return o.control.controlUsageError(err)
	}
	if isMuxDaemonChild() {
		// The detached master daemon re-executes the original command line, but it
		// only serves the control socket. Normalize before Complete reads stdin:
		// with stdio on /dev/null a --password-stdin read would fail the child and
		// silently break ControlPersist.
		o.PasswordStdin = false
		o.PassphraseStdin = false
		o.OTPStdin = false
		o.normalizeForMuxDaemon()
		o.StdinRedirect = true
		return nil
	}
	o.execution.capturePresence(cmd)
	hadCredentialStdin, err := o.readSecretsFromStdin()
	if err != nil {
		return err
	}
	ctlCmd := strings.ToLower(strings.TrimSpace(o.control.CtlCmd))
	if !o.StdinRedirect && !hadCredentialStdin && o.StdioForward == "" && (ctlCmd == "" || ctlCmd == "proxy") {
		stat, err := os.Stdin.Stat()
		if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
			o.stdinScript = true
		}
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
	} else if finalHost != "" && !strings.HasPrefix(finalHost, config.OpenSSHNodePrefix) {
		if u, h, p, err := utils.ParseAddr(finalHost); err == nil && h != "" {
			finalHost, finalUser, hasUser, finalPort, hasPort = applyParsedAddr("", finalUser, hasUser, finalPort, hasPort, h, u, p)
		}
	}

	o.Host = finalHost
	o.User = finalUser
	o.Port = finalPort

	selector := finalHost
	trimmedRaw := strings.TrimSpace(rawSelector)
	if isMuxDaemonChild() && strings.Contains(trimmedRaw, "@") && strings.Contains(trimmedRaw, ":") {
		selector = trimmedRaw
	}

	hasJump := o.JumpHost != "" || isMuxDaemonChild()

	o.Target = config.ConnectionTarget{
		Selector:     selector,
		RawSelector:  trimmedRaw,
		User:         finalUser,
		HasUser:      hasUser,
		Port:         finalPort,
		HasPort:      hasPort,
		ProxyJump:    o.JumpHost,
		HasProxyJump: hasJump,
	}
	return nil
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
	if o.appliedGeneralOpts || len(o.control.Options) == 0 {
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
	if o.Host == "" && len(commandArgs) > 0 {
		commandArgs = commandArgs[1:]
	}
	if err := o.parseArgs(); err != nil {
		return err
	}
	o.parsedArgs = true
	if isMuxDaemonChild() {
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
	if isMuxDaemonChild() {
		// Validate runs after Complete and would otherwise rebuild a command from
		// the preserved positional arguments that the daemon must never execute.
		o.normalizeForMuxDaemon()
	}
	if o.OTP != "" && o.OTPStdin {
		return errors.New(i18n.T("err_otp_mutually_exclusive"))
	}
	if err := utils.ValidateRememberPolicy(o.Remember); err != nil {
		return err
	}
	if err := o.ensureArgsParsed(); err != nil {
		return o.control.controlUsageError(err)
	}
	if err := o.validateForwardAndSessionFlags(); err != nil {
		return o.control.controlUsageError(err)
	}
	if o.BgRun && !o.NoCmd {
		return errors.New(i18n.T("ssh_err_background_requires_nocmd"))
	}
	if o.BgRun && (o.OTP != "" || o.OTPStdin) {
		return fmt.Errorf("background mode (-f) cannot be combined with one-time --otp or --otp-stdin; configure persistent identity otp instead")
	}
	if strings.Contains(o.Alias, "@") || strings.Contains(o.Alias, ":") {
		return errors.New(i18n.T("ssh_err_alias_invalid"))
	}
	ctlCmd := strings.ToLower(strings.TrimSpace(o.control.CtlCmd))
	if ctlCmd != "" && ctlCmd != "proxy" {
		return nil
	}
	return o.prepareCommandPlan()
}

func (o *SshOptions) Run() error {
	return o.RunContext(context.Background())
}

// RunContext starts the SSH operation and propagates caller cancellation.
func (o *SshOptions) RunContext(ctx context.Context) (err error) {
	if o.control.CtlCmd != "" {
		return ExecuteControlCommand(ctx, o)
	}

	isChild := os.Getenv(sshBackgroundChildEnv) == "true"
	if isMuxDaemonChild() {
		// A detached multiplexing daemon serves the control socket only. It must
		// never re-run the command or read the terminal the parent handed over.
		o.normalizeForMuxDaemon()
		o.StdinRedirect = true
	}

	// -n 功能：如果是非后台运行或已是后台子进程，且指定了 -n，直接重定向标准输入到 /dev/null
	if o.StdinRedirect && (!o.BgRun || isChild) {
		devNull, err := os.Open(os.DevNull)
		if err != nil {
			return fmt.Errorf("open %s for SSH stdin failed: %w", os.DevNull, err)
		}
		oldStdin := os.Stdin
		os.Stdin = devNull
		defer func() {
			os.Stdin = oldStdin
			if closeErr := devNull.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close SSH stdin redirect failed: %w", closeErr))
			}
		}()
	}

	observer, finishDiagnostics, diagnosticErr := o.startDiagnostics(ctx)
	if diagnosticErr != nil {
		return diagnosticErr
	}
	o.diagnostics = observer
	defer func() {
		o.diagnostics = nil
		err = errors.Join(err, finishDiagnostics())
	}()
	if o.BgRun && !isChild {
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

	provider, err := config.NewRepository(cfg, configStore)
	if err != nil {
		return fmt.Errorf("create configuration repository: %w", err)
	}

	nodeID, _, err := o.resolveNode(ctx, provider)
	if err != nil {
		return err
	}
	if _, err := o.resolveAndCacheSessionOptions(provider, nodeID); err != nil {
		return err
	}
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
	var connector *ssh.Connector
	if isMuxDaemonChild() {
		connector = newNonInteractiveConnector(provider, adpOpts, ssh.WithSessionConfirmer(o.interaction), ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(o.diagnostics))
	} else {
		connector = newCLIConnectorWithAdapterOptions(provider, o.interaction, adpOpts, ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(o.diagnostics))
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

	// 无论如何，在 runParentDaemon 退出时，或者有任何 panic 发生时，确保 client 必被关闭
	var clientClosed bool
	defer func() {
		if !clientClosed {
			if closeErr := client.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close SSH daemon validation client failed: %w", closeErr))
			}
		}
	}()

	// Validation tunnels own their child context. Closing them must leave the
	// command-owned output context alive until auxiliary output has flushed.
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

	// 启动后台子进程
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), sshBackgroundChildEnv+"=true")

	// 子进程的 stdin/stdout/stderr 均重定向到 /dev/null
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("failed to open /dev/null: %w", err)
	}
	defer func() {
		if closeErr := devNull.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close SSH daemon stdio redirect failed: %w", closeErr))
		}
	}()
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull

	if err := startDaemonProcess(cmd); err != nil {
		return fmt.Errorf("failed to start background daemon: %w", err)
	}

	return nil
}

func (o *SshOptions) buildAdapterOptions(nodeID string, cfg *config.Configuration, repository *config.Repository) ([]adapter.Option, error) {
	if o.interaction == nil {
		o.interaction = newCLIInteractionHandler()
	}
	shouldRemember, adpOpts := o.interaction.rememberOptions(utils.EffectiveRememberPolicy(o.Remember, cfg), cfg)
	if isMuxDaemonChild() {
		shouldRemember = false
		adpOpts = append(adpOpts, adapter.WithNonInteractive(true))
	}
	// The global policy also covers ProxyJump nodes. The target-specific override
	// below carries its explicit session material without leaking it to jumps.
	adpOpts = append(adpOpts, adapter.WithGlobalSessionAuth(adapter.SessionAuth{Remember: shouldRemember}))
	proxyJumpOverride := o.JumpHost
	if proxyJumpOverride == "" && isMuxDaemonChild() {
		proxyJumpOverride = "none"
	}
	// 总是注入 SessionAuthOverride（即使密码为空），以便 UpdateAuth / UpdateSudo
	// 能根据 Remember 策略决定是否将交互提示获得的密码回写配置，而不是绕过策略检查。
	adpOpts = append(adpOpts, adapter.WithSessionAuthOverride(nodeID, adapter.SessionAuth{
		Password:   o.Password,
		Passphrase: o.Passphrase,
		KeyPath:    utils.ToAbsolutePath(o.IdentityFile),
		Remember:   shouldRemember,
		OTP:        o.OTP,
		ProxyJump:  proxyJumpOverride,
	}))
	if reg, regErr := utils.GetCredentialRegistry(cfg); regErr != nil {
		return nil, fmt.Errorf("initialize credential resolver: %w", regErr)
	} else if reg != nil {
		adpOpts = append(adpOpts, adapter.WithCredentialSource(reg))
	}
	if shouldRemember {
		adpOpts = append(adpOpts, enrollmentProbeOption())
		if o.execution.enabled() || o.execution.noLoginSet || o.StdioForward != "" {
			adpOpts = append(adpOpts, adapter.WithEnrollmentProbeExclusions(nodeID))
		}
		persistence, err := o.interaction.automaticPersistenceOptions(repository, cfg)
		if err != nil {
			return nil, err
		}
		adpOpts = append(adpOpts, persistence...)
	}

	// Session Control Overrides (Tier 1)
	sessionCtrlOpts, err := o.toSessionControlOptions()
	if err != nil {
		return nil, err
	}
	if !sessionCtrlOpts.IsEmpty() {
		adpOpts = append(adpOpts, adapter.WithSessionControlOverride(nodeID, sessionCtrlOpts))
	}

	return adpOpts, nil
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
func (o *SshOptions) getActiveMuxServer(ctx context.Context, provider *config.Repository, nodeID string) *ssh.MuxServer {
	var cfgProvider config.ConfigProvider
	if provider != nil {
		cfgProvider = provider
	}
	expandedPath, err := controlSocketPath(o, cfgProvider, nodeID)
	if err != nil || expandedPath == "" {
		return nil
	}
	return ssh.GetActiveMuxServer(expandedPath)
}

// handoffPersistentMaster releases this process's master and starts a detached
// master so ControlPersist survives the session, matching OpenSSH behavior for a
// command or interactive shell that finished.
func (o *SshOptions) handoffPersistentMaster(ctx context.Context, connector *ssh.Connector, provider *config.Repository, nodeID string) error {
	if isMuxDaemonChild() || o.BgRun {
		// This process owns the master for its whole lifetime.
		return nil
	}
	if o.NoCmd {
		// A -N process holds the master until it stops; there is nothing to hand
		// over, and spawning a second daemon would duplicate the master.
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		// The session was interrupted (Ctrl-C/cancellation). Reviving the master
		// would resurrect what the user just stopped.
		return nil
	}
	if err := drainOwnedMasters(ctx, connector); err != nil {
		return nil
	}
	if o.OTP != "" {
		// A one-time code was already consumed by this process. Re-playing it in
		// the daemon cannot succeed and may trip server-side MFA lockouts.
		logger.DefaultLogger().Debugf("mux: skipping master handoff because a one-time password was used")
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
	if master == nil && connector != nil {
		for _, m := range connector.Masters() {
			if m.Target().OriginalHost == nodeID || nodeID == "" {
				master = m
				break
			}
		}
	}
	if !canHandoffMaster(master) {
		return o.handoffConnectorMasters(ctx, connector)
	}
	return o.handoffMasterInstance(ctx, connector, master, nodeID)
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
func (o *SshOptions) handoffConnectorMasters(ctx context.Context, connector *ssh.Connector) error {
	if connector == nil {
		return nil
	}
	masters := connector.Masters()
	if len(masters) == 0 {
		return nil
	}
	if isMuxDaemonChild() || o.BgRun || o.NoCmd {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return nil
	}
	if err := drainOwnedMasters(ctx, connector); err != nil {
		return nil
	}
	if o.OTP != "" {
		logger.DefaultLogger().Debugf("mux: skipping master handoff because a one-time password was used")
		return nil
	}
	jumps := persistentJumpHops(masters)
	var firstErr error
	for _, m := range masters {
		if !canHandoffMaster(m) {
			continue
		}
		nodeID := m.Target().OriginalHost
		if nodeID != "" && jumps[nodeID] {
			continue
		}
		if err := o.handoffMasterInstance(ctx, connector, m, nodeID); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func persistentJumpHops(masters []*ssh.MuxServer) map[string]bool {
	jumps := make(map[string]bool, len(masters))
	for _, m := range masters {
		if !canHandoffMaster(m) {
			continue
		}
		if j := m.Target().JumpHost; j != "" {
			for hop := range strings.SplitSeq(j, ",") {
				hop = strings.TrimSpace(hop)
				if hop != "" {
					jumps[hop] = true
				}
			}
		}
	}
	return jumps
}

func (o *SshOptions) handoffMasterInstance(ctx context.Context, connector *ssh.Connector, master *ssh.MuxServer, nodeID string) error {
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
	ready, err := waitAndReleaseMastersForHandoff(ctx, connector, master, expandedPath)
	if err != nil || !ready {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable for multiplexing daemon failed: %w", err)
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s for multiplexing daemon failed: %w", os.DevNull, err)
	}
	defer func() {
		if closeErr := devNull.Close(); closeErr != nil {
			logger.DefaultLogger().Debugf("close multiplexing daemon stdio failed: %v", closeErr)
		}
	}()

	cmd := exec.Command(exe, o.muxDaemonArgs(nodeID, expandedPath, master)...)
	cmd.Env = append(os.Environ(), sshMuxDaemonEnv+"=true", sshBackgroundChildEnv+"=true")
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull
	if err := startDaemonProcess(cmd); err != nil {
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
	if err := waitForControlSocket(ctx, expandedPath, 10*time.Second, daemonExited); err != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		logger.DefaultLogger().Debugf("mux: persistent master handoff on %q failed: %v", expandedPath, err)
		if _, writeErr := fmt.Fprintf(os.Stderr, "warning: connection sharing master could not be kept alive on %s: %v\n", expandedPath, err); writeErr != nil {
			logger.DefaultLogger().Debugf("write handoff warning failed: %v", writeErr)
		}
	}
	return nil
}

func waitAndReleaseMastersForHandoff(ctx context.Context, connector *ssh.Connector, master *ssh.MuxServer, expandedPath string) (bool, error) {
	for {
		if err := drainOwnedMasters(ctx, connector); err != nil {
			return false, nil
		}
		if master.StoppedListening() {
			return false, nil
		}
		ready, err := releaseMastersForHandoff(connector, master, expandedPath)
		if err != nil {
			return false, err
		}
		if ready {
			return true, nil
		}
		if connector == nil || master.StoppedListening() {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, nil
		case <-master.Wait():
			return false, nil
		default:
		}
	}
}

// drainOwnedMasters waits for any secondary client sessions or dynamic forwards
// on masters started by connector to finish before the foreground process tears
// down its transport or hands the control socket over to a daemon.
func drainOwnedMasters(ctx context.Context, connector *ssh.Connector) error {
	if connector == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, m := range connector.Masters() {
		maxSessions := int32(0)
		if connector.HasMasterSession(m) {
			maxSessions = 1
		}
		if err := m.WaitForDrain(ctx, maxSessions); err != nil {
			return err
		}
		if m.StoppedListening() {
			connector.ReleaseMaster(m)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-m.Wait():
			}
		}
	}
	return nil
}

func (o *SshOptions) muxDaemonArgs(nodeID string, expandedPath string, master *ssh.MuxServer) []string {
	targetHost, port, user := o.resolveMuxDaemonTarget(nodeID, master)
	args := []string{"ssh", "-N", "--host", targetHost, "-S", expandedPath}
	if port != 0 {
		args = append(args, "-p", strconv.Itoa(port))
	}
	if user != "" {
		args = append(args, "-l", user)
	}
	if keyPath := o.resolveMuxDaemonIdentityFile(nodeID, master); keyPath != "" {
		args = append(args, "-i", keyPath)
	}
	jumpHost := o.JumpHost
	if master != nil {
		jumpHost = master.Target().JumpHost
		if jumpHost == "" && strings.EqualFold(strings.TrimSpace(o.JumpHost), "none") {
			jumpHost = "none"
		}
	}
	if jumpHost != "" {
		args = append(args, "-J", jumpHost)
	}
	args = append(args, "--remember", "never")
	if o.shouldPassIdentityFile(nodeID, master) {
		for _, opt := range o.control.Options {
			if isSessionOrForwardOption(opt) {
				continue
			}
			if master != nil && isTargetSpecificOption(opt) {
				continue
			}
			args = append(args, "-o", opt)
		}
	}
	masterMode := ssh.ControlMasterYes
	if master != nil {
		if ctrl := master.Target().Control; ctrl != nil {
			if ctrl.Persist != "" {
				args = append(args, "-o", "ControlPersist="+ctrl.Persist)
			}
			if ctrl.Master == ssh.ControlMasterAsk || ctrl.Master == ssh.ControlMasterAutoAsk {
				masterMode = ssh.ControlMasterAsk
			}
		}
	}
	// Ensure the detached multiplexing daemon never opens configured port or
	// tunnel device forwardings from user/global SSH options.
	args = append(args, "-o", "ClearAllForwardings=yes")
	// Force an explicit master mode (yes or ask) on the detached daemon so it
	// never attaches as a passenger to a competing master while preserving
	// confirmation semantics across ControlPersist handoff.
	args = append(args, "-o", "ControlMaster="+string(masterMode))
	return args
}

func (o *SshOptions) resolveMuxDaemonIdentityFile(nodeID string, master *ssh.MuxServer) string {
	if o.IdentityFile != "" && o.shouldPassIdentityFile(nodeID, master) {
		return o.IdentityFile
	}
	if master != nil && master.Target().KeyPath != "" {
		if o.IdentityFile == "" || len(o.targetNodeIDs) > 0 || master.Target().KeyPath != utils.ToAbsolutePath(o.IdentityFile) {
			return master.Target().KeyPath
		}
	}
	return ""
}

func (o *SshOptions) shouldPassIdentityFile(nodeID string, master *ssh.MuxServer) bool {
	if master == nil {
		return true
	}
	if o.JumpHost != "" && master.Target().JumpHost == "" {
		return false
	}
	if len(o.targetNodeIDs) > 0 {
		return matchesAnyTargetNodeID(nodeID, master, o.targetNodeIDs)
	}
	if o.Port > 0 && master.Target().Port > 0 && int(o.Port) != master.Target().Port {
		return false
	}
	if o.User != "" && master.Target().User != "" && o.User != master.Target().User {
		return false
	}
	if o.JumpHost != "" && isMasterInJumpSpec(nodeID, master, o.JumpHost) {
		return false
	}
	if o.Host != "" || o.Target.Selector != "" {
		return matchesTargetSelector(nodeID, master, o.Host, o.Target.Selector)
	}
	return true
}

func isMasterInJumpSpec(nodeID string, master *ssh.MuxServer, jumpSpec string) bool {
	for hop := range strings.SplitSeq(jumpSpec, ",") {
		hop = strings.TrimSpace(hop)
		if hop == "" {
			continue
		}
		if matchesTargetSelector(nodeID, master, hop, hop) {
			return true
		}
	}
	return false
}

func matchesAnyTargetNodeID(nodeID string, master *ssh.MuxServer, targetIDs []string) bool {
	candidates := []string{
		strings.TrimSpace(nodeID),
		strings.TrimPrefix(strings.TrimSpace(nodeID), config.OpenSSHNodePrefix),
	}
	if master != nil {
		orig := strings.TrimSpace(master.Target().OriginalHost)
		candidates = append(candidates,
			orig,
			strings.TrimPrefix(orig, config.OpenSSHNodePrefix),
		)
	}
	for _, tid := range targetIDs {
		want := strings.TrimSpace(tid)
		if want == "" {
			continue
		}
		cleanWant := strings.TrimPrefix(want, config.OpenSSHNodePrefix)
		for _, c := range candidates {
			if c != "" && (c == want || c == cleanWant) {
				return true
			}
		}
	}
	return false
}

func matchesTargetSelector(nodeID string, master *ssh.MuxServer, host, selector string) bool {
	candidates := []string{
		strings.TrimSpace(nodeID),
		strings.TrimPrefix(strings.TrimSpace(nodeID), config.OpenSSHNodePrefix),
	}
	if master != nil {
		orig := strings.TrimSpace(master.Target().OriginalHost)
		candidates = append(candidates,
			orig,
			strings.TrimPrefix(orig, config.OpenSSHNodePrefix),
			strings.TrimSpace(master.Target().Host),
		)
	}
	for _, want := range []string{strings.TrimSpace(host), strings.TrimSpace(selector)} {
		if want == "" {
			continue
		}
		cleanWant := strings.TrimPrefix(want, config.OpenSSHNodePrefix)
		for _, c := range candidates {
			if c != "" && (c == want || c == cleanWant) {
				return true
			}
		}
	}
	return false
}

func isTargetSpecificOption(opt string) bool {
	key, _, err := adapter.SplitOptionKeyValue(opt)
	if err != nil || key == "" {
		return false
	}
	switch strings.ToLower(key) {
	case "port", "user", "proxyjump", "identityfile":
		return true
	default:
		return false
	}
}

func (o *SshOptions) resolveMuxDaemonTarget(nodeID string, master *ssh.MuxServer) (host string, port int, user string) {
	rawSelector := nodeID
	if rawSelector == "" && master != nil {
		rawSelector = master.Target().OriginalHost
	}
	if rawSelector == "" {
		rawSelector = o.Host
	}
	host = strings.TrimPrefix(rawSelector, config.OpenSSHNodePrefix)
	if host == "" && master != nil {
		host = master.Target().Host
	}
	if master != nil && master.Target().Port > 0 {
		port = master.Target().Port
	} else {
		port = int(o.Port)
	}
	if master != nil && master.Target().User != "" {
		user = master.Target().User
	} else {
		user = o.User
	}
	return host, port, user
}

// jumpChainMasters returns the subset of ownedMasters that belong to targetMaster's
// transitive ProxyJump chain so multi-host handoffs never shut down unrelated
// target masters.
func jumpChainMasters(targetMaster *ssh.MuxServer, ownedMasters []*ssh.MuxServer) []*ssh.MuxServer {
	if targetMaster == nil || len(ownedMasters) == 0 {
		return nil
	}
	byHost := make(map[string]*ssh.MuxServer, len(ownedMasters))
	for _, m := range ownedMasters {
		if m == nil || m == targetMaster {
			continue
		}
		if host := strings.TrimSpace(m.Target().OriginalHost); host != "" {
			byHost[host] = m
		}
		if host := strings.TrimSpace(m.Target().Host); host != "" {
			byHost[host] = m
		}
	}
	var chain []*ssh.MuxServer
	seen := make(map[*ssh.MuxServer]bool)
	queue := []string{targetMaster.Target().JumpHost}
	for len(queue) > 0 {
		raw := queue[0]
		queue = queue[1:]
		for hop := range strings.SplitSeq(raw, ",") {
			hop = strings.TrimSpace(hop)
			if hop == "" {
				continue
			}
			if hopMaster, ok := byHost[hop]; ok && !seen[hopMaster] {
				seen[hopMaster] = true
				chain = append(chain, hopMaster)
				if next := hopMaster.Target().JumpHost; next != "" {
					queue = append(queue, next)
				}
			}
		}
	}
	return chain
}

// releaseMastersForHandoff drops the connector's active-session references,
// reserves the target and any intermediate jump masters for handoff, and shuts
// them down so the detached daemon can claim the control sockets cleanly.
func releaseMastersForHandoff(connector *ssh.Connector, master *ssh.MuxServer, expandedPath string) (bool, error) {
	var jumpMasters []*ssh.MuxServer
	var released []*ssh.MuxServer
	if connector != nil {
		if !connector.OwnsMaster(master) {
			return false, nil
		}
		if connector.HasMasterSession(master) && connector.ReleaseMaster(master) {
			released = append(released, master)
		}
		jumpMasters = jumpChainMasters(master, connector.Masters())
	}
	restoreReleased := func() {
		if connector == nil {
			return
		}
		for _, m := range released {
			connector.AcquireMaster(m)
		}
	}
	if !master.PrepareHandoff() {
		restoreReleased()
		logger.DefaultLogger().Debugf("mux: not handing off master on %q while it is busy or stopping", expandedPath)
		return false, nil
	}
	reserved := []*ssh.MuxServer{master}
	for _, m := range jumpMasters {
		if !m.PersistEnabled() {
			continue
		}
		if connector != nil && connector.HasMasterSession(m) && connector.ReleaseMaster(m) {
			released = append(released, m)
		}
		if !m.PrepareHandoff() {
			for _, r := range reserved {
				r.CancelHandoff()
			}
			restoreReleased()
			logger.DefaultLogger().Debugf("mux: not handing off master on %q while jump master %q is busy or stopping", expandedPath, m.ControlPath())
			return false, nil
		}
		reserved = append(reserved, m)
	}
	if err := master.Shutdown(); err != nil {
		return false, fmt.Errorf("release control socket before daemon handoff failed: %w", err)
	}
	for _, m := range jumpMasters {
		_ = m.Shutdown()
	}
	return true, nil
}

// waitForControlSocket blocks until a master answers on path, the deadline
// elapses, the caller cancels, or the daemon process we are waiting for exits.
func waitForControlSocket(ctx context.Context, path string, timeout time.Duration, daemonExited <-chan struct{}) error {
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
			_, lastErr = client.AliveCheck(probeCtx)
			_ = client.Close()
			if lastErr == nil {
				cancel()
				return nil
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

func (o *SshOptions) runConnection(ctx context.Context, isChild bool) (err error) {
	configPath, keyPath, pathErr := utils.GetConfigFilePath()
	if pathErr != nil {
		return fmt.Errorf("get config file path failed: %w", pathErr)
	}
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ssh_err_load_config"), err)
	}

	provider, err := config.NewRepository(cfg, configStore)
	if err != nil {
		return fmt.Errorf("create configuration repository: %w", err)
	}

	nodeID, _, err := o.resolveNode(ctx, provider)
	if err != nil {
		return err
	}
	if _, err := o.resolveAndCacheSessionOptions(provider, nodeID); err != nil {
		return err
	}
	adpOpts, optErr := o.buildAdapterOptions(nodeID, cfg, provider)
	if optErr != nil {
		return optErr
	}
	var connector *ssh.Connector
	if isMuxDaemonChild() {
		connector = newNonInteractiveConnector(provider, adpOpts, ssh.WithSessionConfirmer(o.interaction), ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(o.diagnostics))
	} else {
		connector = newCLIConnectorWithAdapterOptions(provider, o.interaction, adpOpts, ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(o.diagnostics))
	}
	defer func() {
		joinConnectorCloseError(&err, connector)
	}()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		if isChild || o.StdioForward != "" {
			// 子进程或 -W 标准流转发静默退出或记录错误，不污染二进制 stdout
			return sshConnectionError(nodeID, err)
		}
		promptErr := promptPressEnterIfTUI(os.Stdin, os.Stdout)
		return errors.Join(sshConnectionError(nodeID, err), promptErr)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close SSH client failed: %w", closeErr))
		}
	}()
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

	return o.runConnectedSession(runCtx, connector, client, provider, nodeID, tunnels, isChild)
}

func (o *SshOptions) runConnectedSession(runCtx context.Context, connector *ssh.Connector, client *ssh.Client, provider *config.Repository, nodeID string, tunnels *sshTunnelGroup, isChild bool) error {
	master := o.getActiveMuxServer(runCtx, provider, nodeID)
	if isMuxDaemonChild() {
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
	if o.NoCmd {
		return o.runNoCmdSession(runCtx, connector, client, master, nodeID, tunnels, isChild)
	}

	if o.Command != "" || o.stdinScript {
		return o.runCommand(runCtx, client, o.Command)
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
	if master != nil && !isMuxDaemonChild() {
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
	if isMuxDaemonChild() && runCtx.Err() == nil && connector != nil {
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

// isMuxDaemonChild reports whether this process is the detached master daemon
// started by handoffPersistentMaster.
func isMuxDaemonChild() bool {
	return os.Getenv(sshMuxDaemonEnv) == "true"
}

func sshConnectionError(nodeID string, err error) error {
	return fmt.Errorf("[%s] %s: %w", nodeID, i18n.T("ssh_connection_failed_label"), err)
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
			return fmt.Errorf("%s: %w", i18n.T("ssh_err_shell"), err)
		}
		return nil
	case ssh.RequestTTYForce:
		if _, isTerm := isLocalTerminal(os.Stdin); !isTerm {
			if err := client.RunShellWithRemotePTY(ctx, os.Stdin, os.Stdout, os.Stderr); err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ssh_err_shell"), err)
			}
			return nil
		}
	}
	if err := client.Shell(ctx); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ssh_err_shell"), err)
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

func (o *SshOptions) resolveNode(ctx context.Context, provider *config.Repository) (string, bool, error) {
	var defaultUser string
	if !o.Target.HasUser {
		var err error
		defaultUser, err = utils.GetCurrentUser()
		if err != nil {
			return "", false, fmt.Errorf("get current user failed: %w", err)
		}
	}

	shouldRemember := !isMuxDaemonChild() && utils.EffectiveRememberPolicy(o.Remember, provider.Snapshot()) == utils.RememberPolicyAlways

	res, err := provider.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target:       o.Target,
		DefaultUser:  defaultUser,
		Password:     "",
		IdentityFile: o.IdentityFile,
		Passphrase:   "",
		Alias:        o.Alias,
		Tags:         o.Tags,
	})
	if err != nil {
		return "", false, err
	}
	if res.Created || isMuxDaemonChild() {
		return res.NodeID, res.Created, nil
	}
	updated, err := update(ctx, res.NodeID, o, provider, shouldRemember)
	return res.NodeID, updated, err
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

func startConfiguredForwards(tunnelCtx context.Context, group *sshTunnelGroup, client *ssh.Client, fwdCfg sessionForwardConfig) error {
	register := func(forward *ssh.Forward, setupErr error) error {
		if setupErr != nil {
			if !fwdCfg.exitOnForwardFailure {
				group.stderr.message(logger.Yellow(fmt.Sprintf("warning: %v", setupErr)) + "\n")
				return nil
			}
			return setupErr
		}
		group.Add(forward)
		return nil
	}
	// Connection failures stay visible even without verbose logging, but callbacks
	// only enqueue: a failed stderr must never hold up Forward.Wait or cancellation.
	for _, spec := range fwdCfg.localForwards {
		forward, err := client.LocalForward(tunnelCtx, spec.BindAddr, spec.DestAddr, ssh.WithForwardErrorHandler(func(err error) {
			group.stderr.message(logger.Red(fmt.Sprintf("ssh local forward connection failed: %v", err)) + "\n")
		}))
		if err != nil {
			err = fmt.Errorf("setup local forward failed: %w", err)
		}
		if fatalErr := register(forward, err); fatalErr != nil {
			return fatalErr
		}
	}
	for _, spec := range fwdCfg.remoteForwards {
		forward, err := client.RemoteForward(tunnelCtx, spec.BindAddr, spec.DestAddr, ssh.WithForwardErrorHandler(func(err error) {
			group.stderr.message(logger.Red(fmt.Sprintf("ssh remote forward connection failed: %v", err)) + "\n")
		}))
		if err != nil {
			err = fmt.Errorf("setup remote forward failed: %w", err)
		}
		if fatalErr := register(forward, err); fatalErr != nil {
			return fatalErr
		}
	}
	for _, listenAddr := range fwdCfg.dynamicForwards {
		forward, err := client.Socks5Forward(tunnelCtx, listenAddr, ssh.WithForwardErrorHandler(func(err error) {
			group.stderr.message(logger.Red(fmt.Sprintf("ssh SOCKS5 forward connection failed: %v", err)) + "\n")
		}))
		if err != nil {
			err = fmt.Errorf("setup SOCKS5 proxy failed: %w", err)
		}
		if fatalErr := register(forward, err); fatalErr != nil {
			return fatalErr
		}
	}
	if fwdCfg.hasTunnelDevice {
		forward, err := client.TunnelDeviceForward(tunnelCtx, fwdCfg.tunnelMode, fwdCfg.tunnelDevice, ssh.WithForwardErrorHandler(func(err error) {
			group.stderr.message(logger.Red(fmt.Sprintf("ssh tunnel device forward failed: %v", err)) + "\n")
		}))
		if err != nil {
			err = fmt.Errorf("setup tunnel device forward failed: %w", err)
		}
		if fatalErr := register(forward, err); fatalErr != nil {
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
	if o.NoCmd || hasForwards {
		group.addWait(func() error { return client.Wait(tunnelCtx) })
	}
	if err := startConfiguredForwards(tunnelCtx, group, client, fwdCfg); err != nil {
		return fail(err)
	}
	return group, nil
}

func parseDynamicForwardArg(arg string) (string, error) {
	return ssh.ParseDynamicForwardSpec(arg)
}

func updateNodeFields(node *models.Node, nodeID string, o *SshOptions, provider config.ConfigProvider) (bool, error) {
	nodeUpdated := false
	if o.JumpHost != "" {
		jumpHost, err := provider.ResolveProxyJumpChain(o.JumpHost)
		if err != nil {
			return false, fmt.Errorf("resolve SSH proxy jump %q failed: %w", o.JumpHost, err)
		}
		if jumpHost != "" && jumpHost != node.ProxyJump {
			node.ProxyJump = jumpHost
			nodeUpdated = true
		}
	}

	if o.Alias != "" {
		// 检查别名是否已被其他节点使用
		if existingNode := provider.FindAlias(o.Alias); existingNode != "" && existingNode != nodeID {
			// 别名已存在，跳过
		} else {
			node.Alias = append(node.Alias, o.Alias)
			nodeUpdated = true
		}
	}
	if len(o.Tags) > 0 {
		tagMap := make(map[string]bool)
		for _, t := range node.Tags {
			tagMap[t] = true
		}
		for _, t := range o.Tags {
			if !tagMap[t] {
				node.Tags = append(node.Tags, t)
				nodeUpdated = true
			}
		}
	}
	return nodeUpdated, nil
}

func updateIdentityFields(identity *models.Identity, o *SshOptions) bool {
	identityUpdated := false
	if o.Password != "" {
		if identity.AuthType != "password" {
			identity.AuthType = "password"
			identityUpdated = true
		}
	} else if o.IdentityFile != "" {
		identity.KeyPath = utils.ToAbsolutePath(o.IdentityFile)
		identity.AuthType = "key"
		identityUpdated = true
	}
	return identityUpdated
}

func update(ctx context.Context, nodeID string, o *SshOptions, provider *config.Repository, shouldRemember bool) (bool, error) {
	if strings.HasPrefix(nodeID, config.OpenSSHNodePrefix) {
		if o.JumpHost != "" {
			if _, err := provider.ResolveProxyJumpChain(o.JumpHost); err != nil {
				return false, fmt.Errorf("resolve SSH proxy jump %q failed: %w", o.JumpHost, err)
			}
		}
		return false, nil
	}
	if o.Password == "" && o.IdentityFile == "" && o.JumpHost == "" && !o.Sudo && o.Alias == "" && len(o.Tags) == 0 {
		return false, nil
	}
	ref, ok := provider.View().NodeRefs[nodeID]
	if !ok {
		return false, fmt.Errorf("resolve SSH node %q reference: %w", nodeID, config.ErrNodeNotFound)
	}
	node, host, identity, err := provider.Resolve(nodeID)
	if err != nil {
		return false, fmt.Errorf("resolve SSH node %q for update failed: %w", nodeID, err)
	}

	nodeUpdated, err := updateNodeFields(&node, nodeID, o, provider)
	if err != nil {
		return false, err
	}
	identityUpdated := false
	if shouldRemember {
		identityUpdated = updateIdentityFields(&identity, o)
	}

	if nodeUpdated || identityUpdated {
		if err := provider.ReplaceNodeAtRefContext(ctx, ref, nodeID, node, host, identity); err != nil {
			return false, fmt.Errorf("update SSH node %q failed: %w", nodeID, err)
		}
	}
	return nodeUpdated || identityUpdated, nil
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
