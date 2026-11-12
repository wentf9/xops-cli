package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// ExitCoder is implemented by errors that specify a process exit code.
type ExitCoder interface {
	ExitCode() int
}

// ControlExitError represents an OpenSSH control command exit status.
type ControlExitError struct {
	Code    int
	Message string
	// Reported marks a message already written to stderr in its final
	// OpenSSH-compatible form, so the top-level handler must not print it again.
	// Usage failures raised while parsing flags are not reported yet.
	Reported bool
}

func (e *ControlExitError) Error() string {
	return e.Message
}

func (e *ControlExitError) ExitCode() int {
	return e.Code
}

// ExitCodeFromError extracts the exit code if err implements ExitCoder,
// or unwraps cryptoSSH.ExitError / ssh.CommandExitError.
func ExitCodeFromError(err error) (int, bool) {
	var coder ExitCoder
	if errors.As(err, &coder) {
		return coder.ExitCode(), true
	}
	var exitErr *cryptoSSH.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitStatus()
		if code == 0 {
			code = 255
		}
		return code, true
	}
	var cmdExitErr *ssh.CommandExitError
	if errors.As(err, &cmdExitErr) && cmdExitErr.ExitCode != nil {
		return int(*cmdExitErr.ExitCode), true
	}
	return 0, false
}

// ErrorAlreadyReported reports whether err's message was already written to
// stderr in its final form and must not be printed a second time.
func ErrorAlreadyReported(err error) bool {
	var control *ControlExitError
	if errors.As(err, &control) {
		return control.Reported
	}
	return false
}

type controlStreams struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func defaultControlStreams() controlStreams {
	return controlStreams{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}

func controlError(stderr io.Writer, msg string) error {
	_, _ = fmt.Fprintln(stderr, msg)
	return &ControlExitError{Code: 255, Message: msg, Reported: true}
}

func controlConnectError(stderr io.Writer, socketPath string, err error) error {
	errText := formatSyscallError(err)
	if errText == "Connection refused" {
		if _, statErr := os.Lstat(socketPath); errors.Is(statErr, os.ErrNotExist) {
			errText = "No such file or directory"
		}
	}
	msg := fmt.Sprintf("Control socket connect(%s): %s", socketPath, errText)
	_, _ = fmt.Fprintln(stderr, msg)
	return &ControlExitError{Code: 255, Message: msg, Reported: true}
}

func formatSyscallError(err error) string {
	if err == nil {
		return ""
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		switch {
		case sysErr == syscall.ENOENT:
			return "No such file or directory"
		case sysErr == syscall.ECONNREFUSED || (runtime.GOOS == "windows" && sysErr == syscall.Errno(10061)):
			return "Connection refused"
		case sysErr == syscall.EACCES || (runtime.GOOS == "windows" && sysErr == syscall.Errno(10013)):
			return "Permission denied"
		}
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "no such file or directory") {
		return "No such file or directory"
	}
	if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "wsaeconnrefused") || strings.Contains(errStr, "actively refused") {
		return "Connection refused"
	}
	if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "access is denied") {
		return "Permission denied"
	}
	if sysErr != 0 {
		return sysErr.Error()
	}
	return err.Error()
}

// ExecuteControlCommand executes the -O subcommand on the active master process.
func ExecuteControlCommand(ctx context.Context, o *SshOptions) error {
	return executeControlCommandWithStreams(ctx, o, defaultControlStreams())
}

func executeControlCommandWithStreams(ctx context.Context, o *SshOptions, streams controlStreams) error {
	if err := o.control.Validate(); err != nil {
		return controlError(streams.Stderr, err.Error())
	}
	// -o Port/User/IdentityFile/ProxyJump are applied by the command's Complete
	// step, where the parsed flag set is available to keep primary flags winning.
	if err := o.ensureArgsParsed(); err != nil {
		return controlError(streams.Stderr, err.Error())
	}

	expandedPath, target, provider, nodeID, err := resolveControlContext(ctx, o, streams.Stderr)
	if err != nil {
		return err
	}

	cmdName := strings.ToLower(strings.TrimSpace(o.control.CtlCmd))
	switch cmdName {
	case "check":
		return executeCheck(ctx, expandedPath, streams)
	case "exit":
		return executeExit(ctx, expandedPath, streams)
	case "stop":
		return executeStop(ctx, expandedPath, streams)
	case "forward":
		return executeForward(ctx, expandedPath, target, o, streams)
	case "cancel":
		return executeCancel(ctx, expandedPath, target, o, streams)
	case "proxy":
		return executeProxy(ctx, expandedPath, target, provider, nodeID, o, streams)
	case "proxy-stream":
		return executeProxyStream(ctx, expandedPath, streams)
	case "conninfo":
		return executeInfo(ctx, expandedPath, "connection", streams)
	case "channels":
		return executeInfo(ctx, expandedPath, "channels", streams)
	default:
		return controlError(streams.Stderr, fmt.Sprintf("unknown control command %q", cmdName))
	}
}

// resolveControlSocketPath resolves the control socket for a -O request without
// mutating configuration. A -O request is a query against an existing master, so
// it must never create, prepare, or persist a node as a side effect.
func resolveControlSocketPath(ctx context.Context, o *SshOptions, stderr io.Writer) (string, error) {
	expandedPath, _, _, _, err := resolveControlContext(ctx, o, stderr)
	return expandedPath, err
}

func resolveControlContext(ctx context.Context, o *SshOptions, stderr io.Writer) (string, ssh.TargetContext, config.ConfigProvider, string, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return "", ssh.TargetContext{}, nil, "", err
		}
	}
	if o != nil {
		if err := o.ensureGeneralOptionsApplied(); err != nil {
			return "", ssh.TargetContext{}, nil, "", controlError(stderr, err.Error())
		}
	}

	provider, providerErr := loadReadOnlyControlProvider()
	nodeID := ""
	connTarget := effectiveConnectionTarget(o, "")
	if provider != nil && strings.TrimSpace(connTarget.Selector) != "" {
		resolved, err := resolveControlNodeID(provider, connTarget)
		if err != nil {
			return "", ssh.TargetContext{}, nil, "", controlError(stderr, fmt.Sprintf("resolve target %q failed: %v", connTarget.Selector, err))
		}
		nodeID = resolved
	} else if provider == nil && providerErr != nil && strings.TrimSpace(o.control.ControlPath) == "" {
		// Without configuration only an explicit -S path can be resolved; report
		// the configuration problem instead of silently using a wrong socket.
		return "", ssh.TargetContext{}, nil, "", controlError(stderr, fmt.Sprintf("%s: %v", i18n.T("ssh_err_load_config"), providerErr))
	}

	rawPath := strings.TrimSpace(o.control.ControlPath)
	if rawPath == "none" {
		return "", ssh.TargetContext{}, nil, "", controlError(stderr, "ControlPath must be specified when using -O")
	}

	target := controlTarget(o, provider, nodeID)
	if rawPath != "" {
		expanded, err := ssh.ExpandControlPath(rawPath, sshenv.Discover(), target)
		if err != nil {
			return "", ssh.TargetContext{}, nil, "", controlError(stderr, fmt.Sprintf("expand ControlPath %q failed: %v", rawPath, err))
		}
		return expanded, target, provider, nodeID, nil
	}

	// No -S: resolve from session (-o) / node / global / OpenSSH layers. An empty
	// nodeID still honours -o ControlPath and the global default for ad-hoc hosts.
	expanded, err := controlSocketPath(o, provider, nodeID)
	if err != nil {
		return "", ssh.TargetContext{}, nil, "", controlError(stderr, fmt.Sprintf("resolve control path failed: %v", err))
	}
	if expanded == "" || expanded == "none" {
		return "", ssh.TargetContext{}, nil, "", controlError(stderr, "ControlPath must be specified when using -O")
	}
	return expanded, target, provider, nodeID, nil
}

// resolveControlNodeID resolves a ConnectionTarget against a read-only
// ConfigProvider, returning the matched saved or OpenSSH virtual node ID when
// the effective (user, host, port) matches an existing node, or "" when the
// target is an unremembered override or ad-hoc destination.
func resolveControlNodeID(provider config.ConfigProvider, target config.ConnectionTarget) (string, error) {
	selector := strings.TrimSpace(target.Selector)
	if provider == nil || selector == "" {
		return "", nil
	}
	resolved, err := config.ResolveTarget(provider, target)
	if err != nil {
		return "", err
	}
	return resolved.MatchedNodeID, nil
}

func setProviderOpenSSHAlias(provider config.ConfigProvider, nodeID, alias string) {
	if p, ok := provider.(interface{ SetNodeOpenSSHAlias(string, string) }); ok {
		p.SetNodeOpenSSHAlias(nodeID, alias)
	}
}

// loadReadOnlyControlProvider loads the local configuration as a read-only view.
// It deliberately avoids the durable repository so control queries cannot apply
// pending node changes or rewrite configuration files.
func loadReadOnlyControlProvider() (config.ConfigProvider, error) {
	configPath, keyPath, err := utils.GetConfigFilePath()
	if err != nil {
		return nil, fmt.Errorf("get config file path: %w", err)
	}
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return nil, err
	}
	provider, err := config.NewProvider(cfg)
	if err != nil {
		logger.DefaultLogger().Debugf("mux: load OpenSSH config failed (%v); falling back to local config", err)
		return config.NewProviderWithoutOpenSSH(cfg), nil
	}
	return provider, nil
}

func executeCheck(ctx context.Context, socketPath string, streams controlStreams) error {
	client, err := ssh.DialMuxClient(ctx, socketPath)
	if err != nil {
		return controlConnectError(streams.Stderr, socketPath, err)
	}
	defer func() { _ = client.Close() }()

	pid, err := client.AliveCheck(ctx)
	if err != nil {
		return controlError(streams.Stderr, fmt.Sprintf("master alive check failed: %v", err))
	}

	_, _ = fmt.Fprintf(streams.Stderr, "Master running (pid=%d)\n", pid)
	return nil
}

func executeExit(ctx context.Context, socketPath string, streams controlStreams) error {
	client, err := ssh.DialMuxClient(ctx, socketPath)
	if err != nil {
		return controlConnectError(streams.Stderr, socketPath, err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Terminate(ctx); err != nil {
		return controlError(streams.Stderr, fmt.Sprintf("master exit failed: %v", err))
	}

	_, _ = fmt.Fprintln(streams.Stderr, "Exit request sent.")
	return nil
}

func executeStop(ctx context.Context, socketPath string, streams controlStreams) error {
	client, err := ssh.DialMuxClient(ctx, socketPath)
	if err != nil {
		return controlConnectError(streams.Stderr, socketPath, err)
	}
	defer func() { _ = client.Close() }()

	if err := client.StopListening(ctx); err != nil {
		return controlError(streams.Stderr, fmt.Sprintf("master stop listening failed: %v", err))
	}

	_, _ = fmt.Fprintln(streams.Stderr, "Stop listening request sent.")
	return nil
}

func executeForward(
	ctx context.Context,
	socketPath string,
	target ssh.TargetContext,
	o *SshOptions,
	streams controlStreams,
) error {
	reqs, err := parseForwardRequestsFromOptionsWithTarget(o, target)
	if err != nil {
		return controlError(streams.Stderr, err.Error())
	}
	if len(reqs) == 0 {
		return controlError(streams.Stderr, "no forwardings specified for -O forward (use -L, -R, or -D)")
	}

	client, err := ssh.DialMuxClient(ctx, socketPath)
	if err != nil {
		return controlConnectError(streams.Stderr, socketPath, err)
	}
	defer func() { _ = client.Close() }()

	for _, req := range reqs {
		allocPort, err := client.OpenForward(ctx, req)
		if err != nil {
			msg := err.Error()
			if !strings.HasPrefix(msg, "forwarding request failed:") {
				msg = fmt.Sprintf("forwarding request failed: %s", msg)
			}
			return controlError(streams.Stderr, msg)
		}
		if allocPort > 0 {
			_, _ = fmt.Fprintf(streams.Stdout, "%d\n", allocPort)
		}
	}

	if !o.diagnostic.quiet {
		_, _ = fmt.Fprintln(streams.Stderr, "Forwarding request sent.")
	}
	return nil
}

func executeCancel(
	ctx context.Context,
	socketPath string,
	target ssh.TargetContext,
	o *SshOptions,
	streams controlStreams,
) error {
	reqs, err := parseForwardRequestsFromOptionsWithTarget(o, target)
	if err != nil {
		return controlError(streams.Stderr, err.Error())
	}
	if len(reqs) == 0 {
		return controlError(streams.Stderr, "no forwardings specified for -O cancel (use -L, -R, or -D)")
	}

	client, err := ssh.DialMuxClient(ctx, socketPath)
	if err != nil {
		return controlConnectError(streams.Stderr, socketPath, err)
	}
	defer func() { _ = client.Close() }()

	for _, req := range reqs {
		if err := client.CloseForward(ctx, req); err != nil {
			msg := err.Error()
			if !strings.HasPrefix(msg, "cancel forward failed:") {
				msg = fmt.Sprintf("cancel forward failed: %s", msg)
			}
			return controlError(streams.Stderr, msg)
		}
	}

	if !o.diagnostic.quiet {
		_, _ = fmt.Fprintln(streams.Stderr, "Forwarding cancel request sent.")
	}
	return nil
}

func dialControlProxyClient(ctx context.Context, socketPath string, target ssh.TargetContext, cfg *ssh.ClientConfig, muxOpts []ssh.MuxClientOption, stderr io.Writer) (*ssh.Client, error) {
	client, err := ssh.DialControlProxyClient(ctx, socketPath, target, sshenv.Discover(), cfg, logger.DefaultLogger(), muxOpts...)
	if err != nil {
		if errors.Is(err, ssh.ErrUnauthorizedPeer) ||
			errors.Is(err, ssh.ErrControlProxyRejected) ||
			errors.Is(err, ssh.ErrControlTargetMismatch) {
			return nil, controlError(stderr, fmt.Sprintf("Control socket connect(%s): %v", socketPath, err))
		}
		return nil, controlConnectError(stderr, socketPath, err)
	}
	return client, nil
}

func (o *SshOptions) runControlProxySessionOrTunnels(runCtx context.Context, client *ssh.Client, tunnels *sshTunnelGroup, streams controlStreams) error {
	var sessionErr error
	switch {
	case o.StdioForward != "":
		destHost, destPort, fwdErr := ssh.ParseStdioForward(o.StdioForward)
		if fwdErr != nil {
			_ = tunnels.Close()
			return controlError(streams.Stderr, fwdErr.Error())
		}
		sessionErr = client.ForwardStdio(runCtx, destHost, destPort, streams.Stdin, streams.Stdout)
	case o.effectiveNoCmd():
		<-runCtx.Done()
	default:
		sessionErr = o.runControlProxySession(runCtx, client, streams)
	}
	closeErr := tunnels.Close()
	if sessionErr != nil {
		return mapControlProxySessionError(streams.Stderr, sessionErr)
	}
	if closeErr != nil {
		return mapControlProxySessionError(streams.Stderr, fmt.Errorf("stop SSH tunnels failed: %w", closeErr))
	}
	return nil
}

func executeProxy(
	ctx context.Context,
	socketPath string,
	target ssh.TargetContext,
	provider config.ConfigProvider,
	nodeID string,
	o *SshOptions,
	streams controlStreams,
) error {
	if err := o.validateForwardAndSessionFlags(); err != nil {
		return controlError(streams.Stderr, err.Error())
	}
	if o.commandPlan == nil {
		if err := o.prepareCommandPlan(); err != nil {
			return controlError(streams.Stderr, err.Error())
		}
	}

	cfg, muxOpts := buildControlProxyClientConfig(target, provider, nodeID, o)
	o.effectiveSSHOptions = cfg.Options
	o.resolvedTarget = &target
	if err := o.validatePostResolutionSessionInvariants(); err != nil {
		return controlError(streams.Stderr, err.Error())
	}
	if o.effectiveStdinNull() && streams.Stdin != nil {
		devNull, err := os.Open(os.DevNull)
		if err != nil {
			return controlError(streams.Stderr, fmt.Sprintf("open %s for SSH stdin failed: %v", os.DevNull, err))
		}
		defer func() { _ = devNull.Close() }()
		streams.Stdin = devNull
	}

	if err := o.prepareControlProxyCommandPlan(cfg.Execution); err != nil {
		return controlError(streams.Stderr, err.Error())
	}

	isChild := os.Getenv(sshBackgroundChildEnv) == "true"
	if !isChild && !isMuxDaemonChild() && o.effectiveBgRun() {
		return o.runControlProxyParentDaemon(ctx, socketPath, target, cfg, muxOpts, streams.Stderr)
	}

	client, err := dialControlProxyClient(ctx, socketPath, target, cfg, muxOpts, streams.Stderr)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	tunnels, tunnelErr := o.startTunnelsWithStderr(ctx, runCancel, client, streams.Stderr)
	if tunnelErr != nil {
		return controlError(streams.Stderr, tunnelErr.Error())
	}

	return o.runControlProxySessionOrTunnels(runCtx, client, tunnels, streams)
}

func (o *SshOptions) runControlProxyParentDaemon(
	ctx context.Context,
	socketPath string,
	target ssh.TargetContext,
	cfg *ssh.ClientConfig,
	muxOpts []ssh.MuxClientOption,
	stderr io.Writer,
) error {
	client, err := dialControlProxyClient(ctx, socketPath, target, cfg, muxOpts, stderr)
	if err != nil {
		return err
	}
	var clientClosed bool
	defer func() {
		if !clientClosed {
			_ = client.Close()
		}
	}()

	o.isParentValidation = true
	defer func() { o.isParentValidation = false }()
	tunnels, tunnelErr := o.startTunnelsWithStderr(ctx, nil, client, stderr)
	if tunnelErr != nil {
		return controlError(stderr, tunnelErr.Error())
	}
	if closeErr := tunnels.Close(); closeErr != nil {
		return controlError(stderr, fmt.Sprintf("stop SSH daemon validation tunnels failed: %v", closeErr))
	}
	if closeErr := client.Close(); closeErr != nil {
		return controlError(stderr, fmt.Sprintf("close SSH daemon validation client failed: %v", closeErr))
	}
	clientClosed = true

	if spawnErr := spawnBackgroundSSHChild(); spawnErr != nil {
		return controlError(stderr, spawnErr.Error())
	}
	return nil
}

func (o *SshOptions) prepareControlProxyCommandPlan(nodeExec *ssh.ExecutionConfig) error {
	if o.effectiveNoCmd() || o.StdioForward != "" || o.Sudo || o.Command == "" || o.commandPlan != nil || (!o.execution.enabled() && !o.execution.noLoginSet) {
		return nil
	}
	plan, err := o.resolveCommandPlan(o.Command, nodeExec)
	if err != nil {
		return err
	}
	o.commandPlan = &plan
	return nil
}

func (o *SshOptions) runControlProxySession(ctx context.Context, client *ssh.Client, streams controlStreams) error {
	if o.Command != "" || o.stdinScript {
		return o.runCommandWithStreams(ctx, client, o.Command, streams.Stdin, streams.Stdout, streams.Stderr)
	}
	if !o.Sudo {
		switch o.effectiveRequestTTY() {
		case ssh.RequestTTYNo:
			return o.runPipedShellWithStreams(ctx, client, streams.Stdin, streams.Stdout, streams.Stderr)
		case ssh.RequestTTYForce:
			if _, isTerm := isLocalTerminal(streams.Stdin); !isTerm {
				return client.RunShellWithRemotePTY(ctx, streams.Stdin, streams.Stdout, streams.Stderr)
			}
		}
	}
	stdinFile, _ := streams.Stdin.(*os.File)
	ioStreams := ssh.InteractiveIO{
		Stdin:  stdinFile,
		Stdout: streams.Stdout,
		Stderr: streams.Stderr,
	}
	if o.Sudo {
		return client.ShellWithSudoIO(ctx, ioStreams)
	}
	return client.ShellWithIO(ctx, ioStreams)
}

func buildControlProxyClientConfig(
	target ssh.TargetContext,
	provider config.ConfigProvider,
	nodeID string,
	o *SshOptions,
) (*ssh.ClientConfig, []ssh.MuxClientOption) {
	var (
		cfg      *ssh.ClientConfig
		snapshot *config.Configuration
		adp      *adapter.SSHAdapter
		muxOpts  []ssh.MuxClientOption
	)
	if provider != nil {
		snapshot = provider.Snapshot()
		adp = adapter.NewSSHAdapter(provider, buildControlProxyAdapterOptions(snapshot, nodeID, o)...)
		if nodeID != "" {
			if resolvedCfg, err := adp.GetConfig(nodeID); err == nil && resolvedCfg != nil {
				normalizeControlProxyResolvedConfig(resolvedCfg, target)
				cfg = resolvedCfg
				muxOpts = append(muxOpts, ssh.WithMuxConnectionProvider(adp), ssh.WithMuxSecretResolver(adp))
			}
		}
	}

	if cfg == nil {
		port := target.Port
		if port <= 0 {
			port = 22
		}
		var globalExec *ssh.ExecutionConfig
		var globalPattern string
		if snapshot != nil {
			globalExec = snapshot.Execution
			globalPattern = snapshot.PasswordPromptPattern
		}
		resolvedExec, _ := ssh.ResolveExecution(nil, globalExec)
		cfg = &ssh.ClientConfig{
			Address:               target.Host,
			Port:                  port,
			User:                  target.User,
			Password:              o.Password,
			SudoMode:              ssh.SudoModeAuto,
			ProxyJump:             target.JumpHost,
			Execution:             resolvedExec,
			Options:               resolveControlProxyFallbackOptions(adp, target.Host, o),
			PasswordPromptPattern: globalPattern,
		}
	}

	prompter := o.interaction
	if prompter == nil && !isControlProxyStdinNull(o, cfg.Options) && !o.stdinScript {
		if cliHandler := newCLIInteractionHandler(); cliHandler.canRemember {
			prompter = cliHandler
		}
	}
	if prompter != nil {
		muxOpts = append(muxOpts, ssh.WithMuxSecretPrompter(prompter))
	}
	if snapshot != nil && snapshot.PasswordPromptPattern != "" {
		muxOpts = append(muxOpts, ssh.WithMuxPasswordPromptPattern(snapshot.PasswordPromptPattern))
	}
	return cfg, muxOpts
}

func isControlProxyStdinNull(o *SshOptions, opts *ssh.Options) bool {
	if o != nil && (o.StdinRedirect || o.BgRun) {
		return true
	}
	if opts == nil {
		return false
	}
	if sn, ok := opts.StdinNull(); ok && sn {
		return true
	}
	if fork, ok := opts.ForkAfterAuthentication(); ok && fork {
		return true
	}
	return false
}

func resolveControlProxyFallbackOptions(adp *adapter.SSHAdapter, host string, o *SshOptions) *ssh.Options {
	var sessionCtrlOpts adapter.SessionControlOptions
	if o != nil {
		if parsed, err := o.toSessionControlOptions(); err == nil {
			sessionCtrlOpts = parsed
		}
	}
	if adp != nil {
		if opts, err := adp.ResolveSSHOptions(host, sessionCtrlOpts); err == nil {
			return opts
		}
	}
	if opts, err := ssh.EffectiveOptions(sessionCtrlOpts.ToSSHOptions()); err == nil && !opts.IsEmpty() {
		return opts
	}
	return nil
}

func buildControlProxyAdapterOptions(snapshot *config.Configuration, nodeID string, o *SshOptions) []adapter.Option {
	var sessionAuth adapter.SessionAuth
	var sessionCtrlOpts adapter.SessionControlOptions
	if o != nil {
		sessionAuth = adapter.SessionAuth{
			Password:   o.Password,
			Passphrase: o.Passphrase,
			KeyPath:    utils.ToAbsolutePath(o.IdentityFile),
			Remember:   false,
			OTP:        o.OTP,
			ProxyJump:  o.JumpHost,
		}
		if parsed, ctrlErr := o.toSessionControlOptions(); ctrlErr == nil {
			sessionCtrlOpts = parsed
		}
	}
	adpOpts := []adapter.Option{
		adapter.WithCredentialRecording(false),
		adapter.WithGlobalSessionAuth(sessionAuth),
	}
	if nodeID != "" {
		adpOpts = append(adpOpts, adapter.WithSessionAuthOverride(nodeID, sessionAuth))
	}
	if !sessionCtrlOpts.IsEmpty() {
		adpOpts = append(adpOpts, adapter.WithGlobalSessionControl(sessionCtrlOpts))
		if nodeID != "" {
			adpOpts = append(adpOpts, adapter.WithSessionControlOverride(nodeID, sessionCtrlOpts))
		}
	}
	if reg, regErr := utils.GetCredentialRegistry(snapshot); regErr == nil && reg != nil {
		adpOpts = append(adpOpts, adapter.WithCredentialSource(reg))
	}
	return adpOpts
}

func normalizeControlProxyResolvedConfig(resolvedCfg *ssh.ClientConfig, target ssh.TargetContext) {
	if resolvedCfg.Port <= 0 {
		resolvedCfg.Port = target.Port
		if resolvedCfg.Port <= 0 {
			resolvedCfg.Port = 22
		}
	}
	if resolvedCfg.User == "" {
		resolvedCfg.User = target.User
	}
}

func mapControlProxySessionError(stderr io.Writer, err error) error {
	if err == nil {
		return nil
	}
	var exitErr *cryptoSSH.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitStatus()
		if code == 0 {
			code = 255
		}
		return &ControlExitError{Code: code, Message: exitErr.Error(), Reported: true}
	}
	var cmdExitErr *ssh.CommandExitError
	if errors.As(err, &cmdExitErr) && cmdExitErr.ExitCode != nil {
		return &ControlExitError{Code: int(*cmdExitErr.ExitCode), Message: cmdExitErr.Error(), Reported: true}
	}
	return controlError(stderr, err.Error())
}

func executeProxyStream(ctx context.Context, socketPath string, streams controlStreams) error {
	// The shared dialer performs the same peer-UID check, HELLO exchange, and
	// MUX_C_PROXY switch as every other client path. A private handshake here
	// would skip the peer validation and let a forged socket pass.
	conn, err := ssh.DialMuxProxyStream(ctx, socketPath)
	if err != nil {
		if errors.Is(err, ssh.ErrUnauthorizedPeer) {
			return controlError(streams.Stderr, fmt.Sprintf("Control socket connect(%s): %v", socketPath, err))
		}
		if errors.Is(err, ssh.ErrControlProxyRejected) {
			return controlError(streams.Stderr, fmt.Sprintf("Control socket connect(%s): %v", socketPath, err))
		}
		return controlConnectError(streams.Stderr, socketPath, err)
	}
	defer func() { _ = conn.Close() }()

	// Bi-directional pipe between streams.Stdin/streams.Stdout and the raw socket connection.
	// Do not call conn.CloseWrite() when streams.Stdin hits EOF immediately (e.g. `< /dev/null`),
	// because half-closing the Unix control socket causes the Master's readUnpaddedPacket loop
	// to observe EOF and tear down the proxy session before buffered server packets are read.
	stdoutDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(conn, streams.Stdin)
	}()
	go func() {
		_, _ = io.Copy(streams.Stdout, conn)
		close(stdoutDone)
	}()

	select {
	case <-ctx.Done():
		_ = conn.Close()
		<-stdoutDone
		return ctx.Err()
	case <-stdoutDone:
		return nil
	}
}

func executeInfo(ctx context.Context, socketPath string, infoType string, streams controlStreams) error {
	client, err := ssh.DialMuxClient(ctx, socketPath)
	if err != nil {
		return controlConnectError(streams.Stderr, socketPath, err)
	}
	defer func() { _ = client.Close() }()

	info, err := client.RequestInfo(ctx, infoType)
	if err != nil {
		return controlError(streams.Stderr, err.Error())
	}

	_, _ = fmt.Fprint(streams.Stdout, info)
	return nil
}

func parseForwardRequestsFromOptions(o *SshOptions) ([]ssh.ForwardRequest, error) {
	return parseForwardRequestsFromOptionsWithTarget(o, controlTarget(o, nil, ""))
}

func buildForwardRequestsFromSpecs(
	localSpecs []ssh.ForwardSpec,
	remoteSpecs []ssh.ForwardSpec,
	dynamicEndpoints []ssh.ForwardEndpoint,
	gwOverride *bool,
) []ssh.ForwardRequest {
	reqs := make([]ssh.ForwardRequest, 0, len(localSpecs)+len(remoteSpecs)+len(dynamicEndpoints))
	for _, lSpec := range localSpecs {
		var req ssh.ForwardRequest
		req.Type = ssh.ForwardLocal
		req.ListenHost, req.ListenPort = lSpec.Bind.MuxListenEndpoint()
		if gwOverride != nil && !lSpec.Bind.IsUnix() && !lSpec.Bind.HasHost {
			if *gwOverride {
				req.ListenHost = "*"
			} else {
				req.ListenHost = "127.0.0.1"
			}
		}
		req.ConnectHost, req.ConnectPort = lSpec.Dest.MuxConnectEndpoint()
		reqs = append(reqs, req)
	}

	for _, rSpec := range remoteSpecs {
		var req ssh.ForwardRequest
		req.Type = ssh.ForwardRemote
		req.ListenHost, req.ListenPort = rSpec.Bind.MuxListenEndpoint()
		if !rSpec.IsDynamic {
			req.ConnectHost, req.ConnectPort = rSpec.Dest.MuxConnectEndpoint()
		}
		reqs = append(reqs, req)
	}

	for _, dEp := range dynamicEndpoints {
		var req ssh.ForwardRequest
		req.Type = ssh.ForwardDynamic
		req.ListenHost, req.ListenPort = dEp.MuxListenEndpoint()
		if gwOverride != nil && !dEp.IsUnix() && !dEp.HasHost {
			if *gwOverride {
				req.ListenHost = "*"
			} else {
				req.ListenHost = "127.0.0.1"
			}
		}
		reqs = append(reqs, req)
	}

	return reqs
}

func parseForwardRequestsFromOptionsWithTarget(o *SshOptions, target ssh.TargetContext) ([]ssh.ForwardRequest, error) {
	sessionOpts, err := o.toSessionControlOptions()
	if err != nil {
		return nil, err
	}
	cliEffOpts, err := ssh.EffectiveOptions(sessionOpts.ToSSHOptions())
	if err != nil {
		return nil, err
	}

	if err := o.validateCLIForwardArgs(); err != nil {
		return nil, err
	}

	if clearAll, ok := cliEffOpts.ClearAllForwardings(); ok && clearAll {
		return nil, nil
	}

	localSpecs, err := collectUniqueForwardSpecs(o.LocalForwards, cliEffOpts.LocalForwards())
	if err != nil {
		return nil, err
	}
	remoteSpecs, err := collectUniqueRemoteForwardSpecs(o.RemoteForwards, cliEffOpts.RemoteForwards())
	if err != nil {
		return nil, err
	}
	dynamicEndpoints, err := collectUniqueDynamicEndpoints(o.cliDynamicForwards(), cliEffOpts.DynamicForwards())
	if err != nil {
		return nil, err
	}

	dummyCfg := sessionForwardConfig{
		localForwards:   localSpecs,
		remoteForwards:  remoteSpecs,
		dynamicForwards: dynamicEndpoints,
	}
	if err := expandForwardSpecs(&dummyCfg, sshenv.Discover(), target); err != nil {
		return nil, err
	}

	var gwOverride *bool
	if o.GatewayPorts {
		t := true
		gwOverride = &t
	} else if gwVal, ok := cliEffOpts.GatewayPorts(); ok {
		gwOverride = &gwVal
	}

	return buildForwardRequestsFromSpecs(dummyCfg.localForwards, dummyCfg.remoteForwards, dummyCfg.dynamicForwards, gwOverride), nil
}
