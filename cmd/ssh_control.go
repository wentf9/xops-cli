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
	"github.com/wentf9/xops-cli/internal/terminal"
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
	Err     error
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

func (e *ControlExitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
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
	var reported interface{ AlreadyReported() bool }
	if errors.As(err, &reported) {
		return reported.AlreadyReported()
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
	if _, err := o.toSessionControlOptions(); err != nil {
		return controlError(streams.Stderr, err.Error())
	}
	// -o Port/User/IdentityFile/ProxyJump are applied by the command's Complete
	// step, where the parsed flag set is available to keep primary flags winning.
	if err := o.ensureArgsParsed(); err != nil {
		return controlError(streams.Stderr, err.Error())
	}
	cmdName := strings.ToLower(strings.TrimSpace(o.control.CtlCmd))
	if err := validateControlCommandBackground(o, cmdName); err != nil {
		return controlError(streams.Stderr, err.Error())
	}

	expandedPath, target, provider, nodeID, err := resolveControlContext(ctx, o, streams.Stderr)
	if err != nil {
		return err
	}

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

func validateControlCommandBackground(o *SshOptions, cmdName string) error {
	if cmdName == "" || cmdName == "proxy" {
		return nil
	}
	if o.BgRun {
		return fmt.Errorf("control command (-O %s) cannot be combined with background mode (-f)", cmdName)
	}
	sessionOpts, err := o.toSessionControlOptions()
	if err != nil {
		return err
	}
	eff := ssh.MergeOptions(sessionOpts.ToSSHOptions())
	if eff != nil {
		if fork, ok := eff.ForkAfterAuthentication(); ok && fork {
			return fmt.Errorf("control command (-O %s) cannot be combined with ForkAfterAuthentication=yes", cmdName)
		}
	}
	return nil
}

// resolveControlSocketPath resolves the control socket for a -O request without
// mutating configuration. A -O request is a query against an existing master, so
// it must never create, prepare, or persist a node as a side effect.
func resolveControlSocketPath(ctx context.Context, o *SshOptions, stderr io.Writer) (string, error) {
	expandedPath, _, _, _, err := resolveControlContext(ctx, o, stderr)
	return expandedPath, err
}

func canonicalizeControlOptions(ctx context.Context, o *SshOptions, provider config.ConfigProvider, stderr io.Writer) error {
	if o == nil || provider == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := o.applyHostnameCanonicalization(ctx, provider, nil); err != nil {
		return controlError(stderr, err.Error())
	}
	return nil
}

func resolveControlContext(ctx context.Context, o *SshOptions, stderr io.Writer) (string, ssh.TargetContext, config.ConfigProvider, string, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return "", ssh.TargetContext{}, nil, "", &ControlExitError{Code: 255, Message: err.Error(), Err: err}
		}
	}
	if o != nil {
		if err := o.ensureGeneralOptionsApplied(); err != nil {
			return "", ssh.TargetContext{}, nil, "", controlError(stderr, err.Error())
		}
	}

	provider, providerErr := loadControlProviderWithOverride(o)
	if providerErr != nil && o != nil && o.control.ConfigFile != "" {
		return "", ssh.TargetContext{}, nil, "", controlError(stderr, fmt.Sprintf("%s: %v", i18n.T("ssh_err_load_config"), providerErr))
	}
	if err := canonicalizeControlOptions(ctx, o, provider, stderr); err != nil {
		return "", ssh.TargetContext{}, nil, "", err
	}
	if o != nil {
		if provider != nil {
			o.syncResolvedTargetHosts(provider)
		}
		if o.cliHostName != "" {
			if _, err := o.effectiveHostName(); err != nil {
				return "", ssh.TargetContext{}, nil, "", controlError(stderr, err.Error())
			}
		}
	}
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

	target := controlTarget(o, provider, nodeID)
	expanded, err := expandControlSocketPath(o, provider, nodeID, target, stderr)
	if err != nil {
		return "", ssh.TargetContext{}, nil, "", err
	}
	return expanded, target, provider, nodeID, nil
}

func expandControlSocketPath(o *SshOptions, provider config.ConfigProvider, nodeID string, target ssh.TargetContext, stderr io.Writer) (string, error) {
	if o.control.controlPathLiteral {
		rawLiteral := o.control.ControlPath
		if ssh.IsNoneValue(rawLiteral) {
			return "", controlError(stderr, "ControlPath must be specified when using -O")
		}
		if rawLiteral != "" {
			expanded, err := (&ssh.ControlConfig{Path: rawLiteral, LiteralPath: true}).ResolvePath(sshenv.Discover(), target)
			if err != nil {
				return "", controlError(stderr, fmt.Sprintf("expand ControlPath %q failed: %v", rawLiteral, err))
			}
			if strings.TrimSpace(expanded) == "" || ssh.IsNoneValue(expanded) {
				return "", controlError(stderr, "ControlPath must be specified when using -O")
			}
			return expanded, nil
		}
	}
	rawPath := strings.TrimSpace(o.control.ControlPath)
	if ssh.IsNoneValue(rawPath) {
		return "", controlError(stderr, "ControlPath must be specified when using -O")
	}
	if rawPath != "" {
		expanded, err := ssh.ExpandControlPath(rawPath, sshenv.Discover(), target)
		if err != nil {
			return "", controlError(stderr, fmt.Sprintf("expand ControlPath %q failed: %v", rawPath, err))
		}
		if strings.TrimSpace(expanded) == "" || ssh.IsNoneValue(expanded) {
			return "", controlError(stderr, "ControlPath must be specified when using -O")
		}
		return expanded, nil
	}

	// No -S: resolve from session (-o) / node / global / OpenSSH layers. An empty
	// nodeID still honours -o ControlPath and the global default for ad-hoc hosts.
	expanded, err := controlSocketPath(o, provider, nodeID)
	if err != nil {
		return "", controlError(stderr, fmt.Sprintf("resolve control path failed: %v", err))
	}
	if strings.TrimSpace(expanded) == "" || ssh.IsNoneValue(expanded) {
		return "", controlError(stderr, "ControlPath must be specified when using -O")
	}
	return expanded, nil
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

func canonicalControlOriginAndHost(o *SshOptions) (origHost, canonHost string) {
	if o == nil || !o.canonicalized {
		return "", ""
	}
	origHost = strings.TrimSpace(config.UnwrapOpenSSHSelector(o.originalHost))
	if _, h, _, err := utils.ParseAddr(origHost); err == nil && h != "" {
		origHost = h
	}
	origHost = strings.TrimPrefix(strings.TrimSuffix(origHost, "]"), "[")
	canonHost = strings.TrimSpace(config.UnwrapOpenSSHSelector(o.Target.Selector))
	if canonHost == "" {
		canonHost = strings.TrimSpace(config.UnwrapOpenSSHSelector(o.Host))
	}
	if _, h, _, err := utils.ParseAddr(canonHost); err == nil && h != "" {
		canonHost = h
	}
	canonHost = strings.TrimPrefix(strings.TrimSuffix(canonHost, "]"), "[")
	if origHost == "" || canonHost == "" || strings.EqualFold(origHost, canonHost) {
		return "", ""
	}
	return origHost, canonHost
}

func loadControlProviderWithOverride(o *SshOptions) (config.ConfigProvider, error) {
	provider, err := loadReadOnlyControlProvider()
	if provider != nil && o != nil && o.control.ConfigFile != "" {
		overrideProvider, overrideErr := config.WithOpenSSHConfigOverride(provider, o.control.ConfigFile)
		if overrideErr != nil {
			return nil, overrideErr
		}
		return overrideProvider, nil
	}
	return provider, err
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
		logger.DefaultLogger().Debugf("mux: load OpenSSH config failed (%v); preserving saved-node control only", err)
		return config.NewProviderWithOpenSSHParser(cfg, config.NewBrokenOpenSSHParser(fmt.Errorf("load openssh config: %w", err))), nil
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
		devNull, err := os.Open(os.DevNull) //nolint:forbidigo // open os.DevNull for SSH -n control proxy stdin redirection
		if err != nil {
			return controlError(streams.Stderr, fmt.Sprintf("open %s for SSH stdin failed: %v", os.DevNull, err))
		}
		defer func() { _ = devNull.Close() }()
		streams.Stdin = devNull
	}

	if err := o.prepareControlProxyCommandPlan(cfg.Execution); err != nil {
		return controlError(streams.Stderr, err.Error())
	}

	isChild := o.isBackgroundChild()
	if !isChild && !o.isMuxDaemon() && o.effectiveBgRun() {
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
	if o.Subsystem {
		return client.RunSubsystemWithIO(ctx, strings.TrimSpace(o.Command), streams.Stdin, streams.Stdout, streams.Stderr, o.subsystemAllocatePTY(streams.Stdin))
	}
	if o.Command != "" || o.stdinScript {
		return o.runCommandWithStreams(ctx, client, o.Command, streams.Stdin, streams.Stdout, streams.Stderr)
	}
	var target ssh.TargetContext
	if o.resolvedTarget != nil {
		target = *o.resolvedTarget
	}
	rc, rcErr := o.resolveEffectiveRemoteCommand(target)
	if rcErr != nil {
		return rcErr
	}
	if rc != "" {
		return o.runCommandWithStreams(ctx, client, rc, streams.Stdin, streams.Stdout, streams.Stderr)
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
		if o != nil {
			o.syncResolvedTargetHosts(provider)
		}
		snapshot = provider.Snapshot()
		var (
			lookupKey  string
			lookupAuth adapter.SessionAuth
		)
		if nodeID != "" {
			lookupKey, lookupAuth = resolveControlSessionLookup(o, provider, nodeID, effectiveConnectionTarget(o, nodeID), target)
		}
		adp = adapter.NewSSHAdapter(provider, buildControlProxyAdapterOptionsWithLookup(snapshot, nodeID, lookupKey, lookupAuth, o)...)
		if nodeID != "" {
			resolvedCfg, err := adp.GetConfig(firstNonEmptyControlValue(lookupKey, nodeID))
			if (err != nil || resolvedCfg == nil) && lookupKey != "" && lookupKey != nodeID {
				resolvedCfg, err = adp.GetConfig(nodeID)
			}
			if err == nil && resolvedCfg != nil {
				normalizeControlProxyResolvedConfig(resolvedCfg, target)
				cfg = resolvedCfg
				muxOpts = append(muxOpts, ssh.WithMuxConnectionProvider(adp), ssh.WithMuxSecretResolver(adp))
			}
		}
	}

	if cfg == nil {
		cfg = newControlProxyFallbackConfig(target, provider, adp, snapshot, o)
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

func firstNonEmptyControlValue(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func newControlProxyFallbackConfig(
	target ssh.TargetContext,
	provider config.ConfigProvider,
	adp *adapter.SSHAdapter,
	snapshot *config.Configuration,
	o *SshOptions,
) *ssh.ClientConfig {
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
	fallbackLookup := resolveControlProxyFallbackLookup(target, provider, o)
	var pw string
	if o != nil {
		pw = o.Password
	}
	return ssh.NewClientConfig(ssh.ClientConfig{
		Address:               target.Host,
		Port:                  port,
		User:                  target.User,
		OriginalHost:          target.OriginalHost,
		CanonicalHost:         target.CanonicalHost,
		Password:              pw,
		SudoMode:              ssh.SudoModeAuto,
		ProxyJump:             target.JumpHost,
		Execution:             resolvedExec,
		Options:               resolveControlProxyFallbackOptions(adp, fallbackLookup, o),
		PasswordPromptPattern: globalPattern,
	})
}

func resolveControlProxyFallbackLookup(target ssh.TargetContext, provider config.ConfigProvider, o *SshOptions) string {
	if provider != nil && o != nil {
		explicit := strings.TrimSpace(o.Target.Selector)
		if explicit == "" {
			explicit = strings.TrimSpace(o.Host)
		}
		if config.IsOpenSSHNodeID(explicit) {
			if resolvedID, err := provider.ResolveSelector(explicit); err == nil && resolvedID != "" {
				return resolvedID
			}
			return explicit
		}
		if resolved, err := config.ResolveTarget(provider, effectiveConnectionTarget(o, "")); err == nil {
			if resolved.MatchedNodeID != "" {
				return resolved.MatchedNodeID
			}
			if resolved.BaseNodeID != "" {
				return resolved.BaseNodeID
			}
		}
	}

	candidates := make([]string, 0, 6)
	if o != nil {
		candidates = append(candidates,
			strings.TrimSpace(o.Target.Selector),
			strings.TrimSpace(o.Host),
			strings.TrimSpace(o.originalHost),
		)
	}
	candidates = append(candidates, target.OriginalHost)
	if o != nil {
		candidates = append(candidates, strings.TrimSpace(o.Target.OriginalHost))
	}
	candidates = append(candidates, target.Host)

	if provider != nil {
		for _, candidate := range candidates {
			if candidate == "" {
				continue
			}
			if resolvedID, err := provider.ResolveSelector(candidate); err == nil && resolvedID != "" {
				return resolvedID
			}
		}
	}
	for _, candidate := range candidates {
		if candidate != "" {
			return candidate
		}
	}
	return target.Host
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
		if pol, err := adp.Resolve(context.Background(), adapter.ResolveRequest{
			NodeID:         host,
			SessionControl: &sessionCtrlOpts,
		}); err == nil {
			return pol.Options()
		}
	}
	if opts := ssh.MergeOptions(sessionCtrlOpts.ToSSHOptions()); !opts.IsEmpty() {
		return opts
	}
	return nil
}

func buildControlProxyAdapterOptions(snapshot *config.Configuration, nodeID string, o *SshOptions) []adapter.Option {
	return buildControlProxyAdapterOptionsWithLookup(snapshot, nodeID, "", adapter.SessionAuth{}, o)
}

func buildControlProxyAdapterOptionsWithLookup(
	snapshot *config.Configuration,
	nodeID, lookupKey string,
	lookupAuth adapter.SessionAuth,
	o *SshOptions,
) []adapter.Option {
	var sessionAuth adapter.SessionAuth
	var sessionCtrlOpts adapter.SessionControlOptions
	if o != nil {
		origHost := o.originalHost
		if stripped, ok := config.OpenSSHOriginalHost(origHost); ok {
			origHost = stripped
		}
		canonOrig, canonHost := canonicalControlOriginAndHost(o)
		if origHost == "" {
			if lookupAuth.OriginalHost != "" {
				origHost = lookupAuth.OriginalHost
				canonHost = lookupAuth.CanonicalHost
			} else {
				origHost = canonOrig
			}
		} else if origHost == lookupAuth.OriginalHost && canonHost == "" {
			canonHost = lookupAuth.CanonicalHost
		}
		absKeys := o.absIdentityFiles()
		firstKey := normalizeCLIIdentityPath(o.IdentityFile)
		if firstKey == "" && len(absKeys) > 0 {
			firstKey = absKeys[0]
		}
		hostNameOverride, _ := o.effectiveHostName()
		sessionAuth = adapter.SessionAuth{
			Password:      o.Password,
			Passphrase:    o.Passphrase,
			KeyPath:       firstKey,
			KeyPaths:      absKeys,
			HostName:      hostNameOverride,
			OriginalHost:  origHost,
			CanonicalHost: canonHost,
			Remember:      false,
			OTP:           o.OTP,
			ProxyJump:     firstNonEmptyControlValue(o.JumpHost, lookupAuth.ProxyJump),
		}
		if parsed, ctrlErr := o.toSessionControlOptions(); ctrlErr == nil {
			sessionCtrlOpts = parsed
		}
	}
	adpOpts := []adapter.Option{
		adapter.WithCredentialRecording(false),
		adapter.WithControlProxyMode(true),
		adapter.WithGlobalSessionAuth(sessionAuth),
	}
	if nodeID != "" {
		overrideKey := firstNonEmptyControlValue(lookupKey, nodeID)
		adpOpts = append(adpOpts, adapter.WithSessionAuthOverride(overrideKey, sessionAuth))
		if overrideKey != nodeID {
			adpOpts = append(adpOpts, adapter.WithSessionAuthOverride(nodeID, sessionAuth))
		}
	}
	if !sessionCtrlOpts.IsEmpty() {
		if globalCtrl := sessionCtrlOpts.ConnectionWideOptions(); !globalCtrl.IsEmpty() {
			adpOpts = append(adpOpts, adapter.WithGlobalSessionControl(globalCtrl))
		}
		if nodeID != "" {
			overrideKey := firstNonEmptyControlValue(lookupKey, nodeID)
			adpOpts = append(adpOpts, adapter.WithSessionControlOverride(overrideKey, sessionCtrlOpts))
			if overrideKey != nodeID {
				adpOpts = append(adpOpts, adapter.WithSessionControlOverride(nodeID, sessionCtrlOpts))
			}
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
		return &ControlExitError{Code: code, Message: exitErr.Error(), Err: err, Reported: true}
	}
	var cmdExitErr *ssh.CommandExitError
	if errors.As(err, &cmdExitErr) && cmdExitErr.ExitCode != nil {
		return &ControlExitError{Code: int(*cmdExitErr.ExitCode), Message: cmdExitErr.Error(), Err: err, Reported: true}
	}
	var reportedErr interface {
		ExitCode() int
		AlreadyReported() bool
	}
	if errors.As(err, &reportedErr) && reportedErr.AlreadyReported() {
		code := reportedErr.ExitCode()
		if code == 0 {
			code = 255
		}
		return &ControlExitError{Code: code, Message: err.Error(), Err: err, Reported: true}
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
	stdinDone := make(chan struct{})
	var dupIn terminal.PromptInput
	if stdinFile, ok := streams.Stdin.(*os.File); ok && stdinFile != nil {
		if dup, dupErr := terminal.DuplicatePromptInput(stdinFile); dupErr == nil {
			dupIn = dup
		}
	}
	if dupIn != nil {
		go func() {
			defer close(stdinDone)
			_, _ = io.Copy(conn, dupIn)
		}()
	} else if streams.Stdin != nil {
		go func() {
			defer close(stdinDone)
			_, _ = io.Copy(conn, streams.Stdin)
		}()
	} else {
		close(stdinDone)
	}
	go func() {
		_, _ = io.Copy(streams.Stdout, conn)
		close(stdoutDone)
	}()

	var streamErr error
	select {
	case <-ctx.Done():
		_ = conn.Close()
		<-stdoutDone
		ctxErr := ctx.Err()
		streamErr = &ControlExitError{Code: 255, Message: ctxErr.Error(), Err: ctxErr}
	case <-stdoutDone:
		_ = conn.Close()
	}
	if dupIn != nil {
		_ = dupIn.Interrupt()
		<-stdinDone
		_ = dupIn.Close()
	}
	return streamErr
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
	cliEffOpts := ssh.MergeOptions(sessionOpts.ToSSHOptions())

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
