package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	logger "github.com/wentf9/xops-cli/core/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// RunWithSudoExecution honors a frozen execution configuration or rejects an
// unvalidated escalation adapter. Nil configuration preserves legacy behavior.
func (c *Client) RunWithSudoExecution(ctx context.Context, command string, execution *ExecutionConfig, extraOpts ...RunOption) (string, error) {
	opts, err := c.configuredSudoOptions(ctx, command, execution)
	if err != nil {
		return "", err
	}
	// Execution options are applied last so output selection cannot replace the
	// validated target interpreter, launch dialect or login mode.
	runOpts := append([]RunOption{}, extraOpts...)
	runOpts = append(runOpts, opts...)
	return c.RunWithSudo(ctx, command, runOpts...)
}

// RunScriptWithSudoExecution applies the same target/login capability checks
// to a script whose interpreter has already been resolved by the caller.
func (c *Client) RunScriptWithSudoExecution(ctx context.Context, content string, execution *ExecutionConfig, extraOpts ...RunOption) (string, error) {
	if strings.HasPrefix(content, "\xef\xbb\xbf") {
		return "", fmt.Errorf("%w: script contains unsupported UTF-8 BOM prefix", ErrExecutionValidation)
	}
	execOpts, err := c.configuredSudoOptions(ctx, ":", execution)
	if err != nil {
		return "", err
	}
	opts := make([]RunOption, len(extraOpts))
	copy(opts, extraOpts)
	opts = append(opts, execOpts...)
	return c.RunScriptWithSudo(ctx, content, opts...)
}

func (c *Client) configuredSudoOptions(ctx context.Context, command string, execution *ExecutionConfig) ([]RunOption, error) {
	opts, err := execution.SudoRunOptions(command)
	if err != nil {
		return nil, err
	}
	if isExecutionConfigured(execution) {
		if err := c.maybeDetectSudoMode(ctx); err != nil {
			return nil, err
		}
		// Legacy su cannot enforce a configured interpreter/login contract.
		// The portable adapter pins /bin/sh for control and starts user code separately.
		config := c.defaultRunConfig()
		for _, opt := range opts {
			opt(config)
		}
		if c.ConnectionConfig().SudoMode == SudoModeSu && !usesPortableShellAdapter(config) {
			return nil, fmt.Errorf("%w: configured su execution is not supported", ErrExecutionValidation)
		}
	}
	return opts, nil
}

func (c *Client) RunWithSudo(ctx context.Context, command string, opts ...RunOption) (string, error) {
	config := c.defaultRunConfig()
	for _, opt := range opts {
		opt(config)
	}

	if err := c.maybeDetectSudoMode(ctx); err != nil {
		return "", err
	}
	connCfg := c.ConnectionConfig()

	if usesPortableShellAdapter(config) {
		return c.runPortableWithSudo(ctx, command, false, config)
	}

	var wrappedCmd string
	switch config.Interpreter {
	case "", InterpreterBash:
		wrappedCmd = bashCommandPayload(command, config.LoginShell)
	case InterpreterSh:
		wrappedCmd = shCommandPayload(command)
	default:
		return "", fmt.Errorf("%w: unsupported interpreter %q for RunWithSudo (only bash and sh are supported)", ErrExecutionValidation, config.Interpreter)
	}

	switch connCfg.SudoMode {
	case SudoModeRoot:
		return c.Run(ctx, command, opts...)
	case SudoModeSudoer:
		return c.runWithSudo(ctx, wrappedCmd, nil, nil, config)
	case SudoModeSudo:
		return c.runPrivilegeWithConfig(ctx, connCfg.SudoMode, wrappedCmd, nil, config)
	case SudoModeSu:
		return c.runPrivilegeWithConfig(ctx, connCfg.SudoMode, command, nil, config)
	default:
		return "", fmt.Errorf("unknown sudo mode: %s, please check config to set sudo mode", connCfg.SudoMode)
	}
}

// RunScriptWithSudo 提权执行脚本
func (c *Client) RunScriptWithSudo(ctx context.Context, scriptContent string, opts ...RunOption) (string, error) {
	if strings.HasPrefix(scriptContent, "\xef\xbb\xbf") {
		return "", fmt.Errorf("%w: script contains unsupported UTF-8 BOM prefix", ErrExecutionValidation)
	}
	config := c.defaultRunConfig()
	for _, opt := range opts {
		opt(config)
	}

	if err := c.maybeDetectSudoMode(ctx); err != nil {
		return "", err
	}
	connCfg := c.ConnectionConfig()

	if usesPortableShellAdapter(config) {
		return c.runPortableWithSudo(ctx, scriptContent, true, config)
	}

	var bashArgs, bashCmd string
	switch config.Interpreter {
	case "", InterpreterBash:
		bashArgs = bashScriptPayload(config.LoginShell)
		bashCmd = bashCommandPayload(scriptContent, config.LoginShell)
	case InterpreterSh:
		bashArgs = shScriptPayload()
		bashCmd = shCommandPayload(scriptContent)
	default:
		return "", fmt.Errorf("%w: unsupported interpreter %q for RunScriptWithSudo (only bash and sh are supported)", ErrExecutionValidation, config.Interpreter)
	}

	switch connCfg.SudoMode {
	case SudoModeRoot:
		return c.RunScript(ctx, scriptContent, opts...)
	case SudoModeSudoer:
		return c.runWithSudo(ctx, bashArgs, nil, strings.NewReader(scriptContent), config)
	case SudoModeSudo:
		return c.runPrivilegeWithConfig(ctx, connCfg.SudoMode, bashArgs, strings.NewReader(scriptContent), config)
	case SudoModeSu:
		return c.runPrivilegeWithConfig(ctx, connCfg.SudoMode, bashCmd, nil, config)
	default:
		return "", fmt.Errorf("unsupported sudo mode: %s", connCfg.SudoMode)
	}
}

// RunInteractiveWithSudo 在 PTY 环境下以提权方式执行单条交互式命令
func (c *Client) RunInteractiveWithSudo(ctx context.Context, command string) error {
	return c.RunInteractiveWithSudoIO(ctx, command, c.defaultInteractiveIO())
}

// RunInteractiveWithSudoExecution applies a per-operation execution configuration
// without mutating the shared client's defaults. Terminal streams are borrowed
// from the host environment; the existing privilege lifecycle owns their binding.
func (c *Client) RunInteractiveWithSudoExecution(ctx context.Context, command string, execution *ExecutionConfig) (retErr error) {
	if execution == nil {
		return c.RunInteractiveWithSudo(ctx, command)
	}
	opts, err := c.configuredSudoOptions(ctx, command, execution)
	if err != nil {
		return err
	}
	config := c.defaultRunConfig()
	for _, opt := range opts {
		opt(config)
	}
	work, cancelOutput := context.WithCancel(ctx)
	defer cancelOutput()
	streams := c.defaultInteractiveIO()
	stdout, stderr, closeOutput, err := bindStrictOutputs(work, streams.Stdout, streams.Stderr)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, closeOutput()) }()
	streams.Stdout, streams.Stderr = stdout, stderr
	return c.runInteractivePortableWithSudo(work, c.ConnectionConfig().SudoMode, command, streams, false, config, cancelOutput)
}

// RunInteractiveWithSudoIO uses an authenticated terminal handoff before
// consuming caller input. The injected streams avoid process-global I/O changes.
func (c *Client) RunInteractiveWithSudoIO(ctx context.Context, command string, streams InteractiveIO) error {
	if err := c.maybeDetectSudoMode(ctx); err != nil {
		return err
	}
	mode := c.ConnectionConfig().SudoMode
	if usesPortableShellAdapter(c.defaultRunConfig()) {
		return c.runInteractivePortableWithSudo(ctx, mode, command, streams, false, c.defaultRunConfig())
	}
	switch mode {
	case SudoModeRoot:
		return c.RunInteractiveCmdWithIO(ctx, bashCommandPayload(command, true), streams)
	case SudoModeSudoer:
		wrapped, err := interactivePrivilegeCommand(mode, command)
		if err != nil {
			return err
		}
		return c.RunInteractiveCmdWithIO(ctx, wrapped, streams)
	case SudoModeSudo, SudoModeSu:
		return c.runInteractivePrivilege(ctx, mode, "exec "+bashCommandPayload(command, false), streams)
	default:
		return fmt.Errorf("interactive privilege escalation is unsupported for sudo mode %q", mode)
	}
}

// Commands travel in the SSH exec request, never through echoed PTY input.
func interactivePrivilegeCommand(mode SudoMode, command string) (string, error) {
	switch mode {
	case SudoModeSudo, SudoModeSudoer:
		return "sudo -i -- bash -c " + shellQuote(sudoLoginScript(command)), nil
	case SudoModeSu:
		bashCommand := "exec " + bashCommandPayload(command, false)
		return "su - root -c '" + strings.ReplaceAll(bashCommand, "'", "'\\''") + "'", nil
	default:
		return "", fmt.Errorf("interactive privilege escalation is unsupported for sudo mode %q", mode)
	}
}

func (c *Client) runWithSudo(ctx context.Context, command string, password []byte, extraStdin io.Reader, config *RunConfig, material ...*PrivilegeMaterial) (output string, retErr error) {
	connCfg := c.ConnectionConfig()
	if len(password) == 0 && connCfg.SudoMode == SudoModeSudo {
		return "", fmt.Errorf("sudo password is required but not provided")
	}

	session, err := c.newSessionContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create new session: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, c.closeSessionBounded(session)) }()

	if len(password) > 0 {
		pwdStr := string(password) + "\n"
		if extraStdin != nil {
			session.Stdin = io.MultiReader(strings.NewReader(pwdStr), extraStdin)
		} else {
			session.Stdin = strings.NewReader(pwdStr)
		}
	} else if extraStdin != nil {
		session.Stdin = extraStdin
	}

	fullCmd := fmt.Sprintf("sudo -S -p '' %s", command)
	if len(material) == 0 || material[0] == nil || material[0].confirmedSave == nil {
		return c.startWithTimeout(ctx, session, fullCmd, config)
	}
	prompt := "[xops-password-" + rand.Text() + "]"
	observer := &privilegePromptWriter{marker: []byte(prompt)}
	fullCmd = fmt.Sprintf("sudo -S -p '%s' %s", prompt, command)
	output, err = c.startWithTimeout(ctx, session, fullCmd, config, func(target io.Writer) io.Writer { observer.target = target; return observer })
	if err == nil && observer.observed {
		material[0].verified = true
		if !material[0].deferSave {
			err = c.confirmPrivilege(ctx, material[0])
		}
	}
	return output, err
}

// ShellWithSudo opens an interactive privileged shell using the default streams.
func (c *Client) ShellWithSudo(ctx context.Context) error {
	return c.ShellWithSudoIO(ctx, c.defaultInteractiveIO())
}

// ShellWithSudoIO authenticates before switching the local terminal to raw mode.
func (c *Client) ShellWithSudoIO(ctx context.Context, streams InteractiveIO) error {
	if err := c.maybeDetectSudoMode(ctx); err != nil {
		return err
	}
	mode := c.ConnectionConfig().SudoMode
	if usesPortableShellAdapter(c.defaultRunConfig()) {
		return c.runInteractivePortableWithSudo(ctx, mode, "", streams, true, c.defaultRunConfig())
	}
	switch mode {
	case SudoModeRoot:
		return c.ShellWithIO(ctx, streams)
	case SudoModeSudoer:
		return c.runTerminalSession(ctx, "sudo -i", streams, false, true)
	case SudoModeSudo, SudoModeSu:
		return c.runInteractivePrivilegeSession(ctx, mode, `exec "${SHELL:-/bin/bash}"`, streams, true, nil)
	default:
		return fmt.Errorf("privilege escalation is not supported for this host (sudo_mode=%s)", mode)
	}
}

// ignoreShellExitError 忽略交互式 shell 的 ExitError
// 交互式 shell 退出时可能继承用户执行的最后一条命令的退出码，这是正常行为
func ignoreShellExitError(err error) error {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var retained []error
		for _, cause := range joined.Unwrap() {
			retained = append(retained, ignoreShellExitError(cause))
		}
		return errors.Join(retained...)
	}
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			return nil
		}
	}
	return err
}

func startWindowResizeLoop(ctx context.Context, session *ssh.Session, fdOut, width, height int, l logger.DebugLogger, interrupt func() error) func() error {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		lastW, lastH := width, height
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				currW, currH, err := term.GetSize(fdOut)
				if err != nil {
					l.Debugf("read terminal size failed: %v", err)
					continue
				}
				if currW != lastW || currH != lastH {
					if err := session.WindowChange(currH, currW); err != nil {
						l.Debugf("resize remote terminal failed: %v", err)
						continue
					}
					lastW, lastH = currW, currH
				}
			}
		}
	}()
	return func() error {
		cancel()
		timer := time.NewTimer(sessionShutdownTimeout)
		defer timer.Stop()
		select {
		case <-done:
			return nil
		case <-timer.C:
			err := interrupt()
			<-done
			return errors.Join(fmt.Errorf("window resize worker shutdown timed out"), err)
		}
	}

}

// RunCommandWithInput executes a command (or interactive bash when command is empty) using finite byte input.
func (c *Client) RunCommandWithInput(ctx context.Context, command string, input []byte, stdout, stderr io.Writer) error {
	var stdin io.Reader
	if len(input) > 0 {
		stdin = bytes.NewReader(input)
	}
	return c.RunCommandWithIO(ctx, command, false, stdin, stdout, stderr)
}

func (c *Client) resolveCommandIOInterpreter(sudo bool, command string) (Interpreter, error) {
	if exec := c.Execution(); exec != nil {
		if err := exec.Validate(); err != nil {
			return "", err
		}
	}
	interp := InterpreterServer
	if exec := c.Execution(); exec != nil && exec.EffectiveInterpreter() != "" {
		interp = exec.EffectiveInterpreter()
	} else if sudo {
		interp = InterpreterBash
	}
	switch interp {
	case InterpreterServer, InterpreterBash, InterpreterSh, InterpreterZsh, InterpreterFish:
	default:
		return "", fmt.Errorf("%w: unsupported interpreter %q for RunCommandWithIO (only server, bash, sh, zsh and fish are supported)", ErrExecutionValidation, interp)
	}
	config := c.defaultRunConfig()
	config.Interpreter, config.LoginShell = interp, c.resolveExecutionLogin(interp)
	if usesPortableShellAdapter(config) && interp != InterpreterServer {
		if err := validatePortableShellConfig(config); err != nil {
			return "", err
		}
	}
	if interp == InterpreterServer && command == "" {
		return "", fmt.Errorf("%w: command must not be empty for server interpreter", ErrExecutionValidation)
	}
	if sudo && interp == InterpreterServer {
		return "", fmt.Errorf("%w: server interpreter does not support sudo escalation in RunCommandWithIO", ErrExecutionValidation)
	}
	return interp, nil
}

func (c *Client) resolveExecutionLogin(interp Interpreter) bool {
	if interp != InterpreterBash && interp != InterpreterZsh && interp != InterpreterFish {
		return false
	}
	if exec := c.Execution(); exec != nil {
		return exec.LoginMode() == LoginEnabled
	}
	return false
}

func (c *Client) resolveCommandIOPayload(interp Interpreter, command string) string {
	if interp == InterpreterServer {
		return command
	}
	login := c.resolveExecutionLogin(interp)
	config := c.defaultRunConfig()
	config.Interpreter, config.LoginShell = interp, login
	if usesPortableShellAdapter(config) {
		return portableUserCommand(command, config, config.LaunchDialect)
	}
	return legacyPayloadWithLogin(command, interp, login)
}

// RunCommandWithIO executes a command (or interactive bash when command is empty) using caller-provided I/O streams.
// If sudo is true, it escalates privileges according to the target node's SudoMode.
// stdin is borrowed from the caller and will never be closed by this method. To
// guarantee cancellation without leaking a goroutine, stdin must be nil, an
// *os.File, or a finite in-memory *bytes.Buffer, *bytes.Reader, or
// *strings.Reader. Use RunCommandWithInput for arbitrary finite input bytes.
func (c *Client) RunCommandWithIO(ctx context.Context, command string, sudo bool, stdin io.Reader, stdout, stderr io.Writer) (retErr error) {
	if _, ok := c.configSnapshot(); !ok {
		return fmt.Errorf("ssh client or config is nil")
	}
	if ctx == nil {
		return fmt.Errorf("command execution context is nil")
	}
	if err := validateCommandStdin(stdin, c.environment.InputBridge); err != nil {
		return err
	}

	interp, err := c.resolveCommandIOInterpreter(sudo, command)
	if err != nil {
		return err
	}

	// Native files, terminals and pipes are bound to ctx so cancellation cannot
	// leave the SSH session joined to a blocked caller stream. Unbindable
	// writers retain their legacy direct behavior; see BindOutput.
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout, stderr, closeOutput, err := c.bindCommandOutputs(work, stdout, stderr, false)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, closeOutput()) }()
	payload := c.resolveCommandIOPayload(interp, command)
	if !sudo {
		return c.runRawCommandWithPayload(work, payload, "", stdin, stdout, stderr, cancel)
	}

	if err := c.maybeDetectSudoMode(work); err != nil {
		return err
	}
	clientConfig, _ := c.configSnapshot()
	return c.dispatchSudoCommand(work, clientConfig, command, payload, interp, stdin, stdout, stderr, cancel)
}

func (c *Client) dispatchSudoCommand(ctx context.Context, clientConfig ClientConfig, command, payload string, interp Interpreter, stdin io.Reader, stdout, stderr io.Writer, cancel context.CancelFunc) error {
	config := c.defaultRunConfig()
	config.Interpreter, config.LoginShell = interp, c.resolveExecutionLogin(interp)
	if usesPortableShellAdapter(config) && clientConfig.SudoMode != SudoModeRoot {
		inner := portableUserCommand(command, config, LaunchPOSIX)
		return c.runPrivilegeOperation(ctx, clientConfig.SudoMode, inner, stdin, stdout, stderr, config, cancel)
	}
	switch clientConfig.SudoMode {
	case SudoModeRoot:
		return c.runRawCommandWithPayload(ctx, payload, "", stdin, stdout, stderr, cancel)
	case SudoModeSudoer:
		return c.runRawCommandWithPayload(ctx, "sudo -S -p '' "+payload, "", stdin, stdout, stderr, cancel)
	case SudoModeSudo, SudoModeSu:
		login := c.resolveExecutionLogin(interp)
		inner := "exec bash"
		if login {
			inner = "exec bash -l"
		}
		if interp == InterpreterSh {
			inner = "exec sh"
		}
		if command != "" {
			if interp == InterpreterSh {
				inner = shCommandPayload(command)
			} else {
				inner = bashCommandPayload(command, login)
			}
		}
		return c.runPrivilegeOperation(ctx, clientConfig.SudoMode, inner, stdin, stdout, stderr, interp, cancel)
	case SudoModeNone:
		return fmt.Errorf("privilege escalation is not supported for this host (sudo_mode=none)")
	default:
		return fmt.Errorf("unknown sudo mode: %s, please check config to set sudo mode", clientConfig.SudoMode)
	}
}

func legacyPayload(command string, interp Interpreter) string {
	return legacyPayloadWithLogin(command, interp, false)
}

func legacyPayloadWithLogin(command string, interp Interpreter, login bool) string {
	if interp == InterpreterSh {
		if command == "" {
			return "sh"
		}
		return shCommandPayload(command)
	}
	if command == "" {
		if login {
			return "bash -l"
		}
		return "bash"
	}
	return bashCommandPayload(command, login)
}

// legacyBashPayload keeps the historical empty-command behavior: Bash reads
// its program from stdin. Explicit empty commands are rejected by callers
// before reaching this compatibility path.
func legacyBashPayload(command string) string {
	return legacyPayload(command, InterpreterBash)
}

// alreadyBound is used only when the caller owns output bindings and supplies
// their cancellation to the operation. Do not duplicate or close them here.
func (c *Client) bindCommandOutputs(ctx context.Context, stdout, stderr io.Writer, alreadyBound bool) (io.Writer, io.Writer, func() error, error) {
	if alreadyBound {
		return stdout, stderr, func() error { return nil }, nil
	}
	boundOut, closeOut, outCancelable, err := BindOutput(ctx, stdout)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("bind command stdout: %w", err)
	}
	boundErr, closeErr, errCancelable, err := BindOutput(ctx, stderr)
	if err != nil {
		return nil, nil, nil, errors.Join(fmt.Errorf("bind command stderr: %w", err), closeOut())
	}
	c.logUncancelableOutput(outCancelable, stdout)
	c.logUncancelableOutput(errCancelable, stderr)
	return boundOut, boundErr, func() error { return errors.Join(closeOut(), closeErr()) }, nil
}

// startCommandWithStdinPipeline starts the remote command before performing any
// stdin write. Some SSH servers advertise a zero channel window until they
// receive the exec request, so writing an initial sudo or su password before
// startCommand returns can deadlock in SSH flow control.
func startCommandWithStdinPipeline(
	startCommand func() error,
	stdin io.Reader,
	stdinPipe io.WriteCloser,
	initialPayload string,
	options ...inputPipelineOptions,
) (finishStdin func() error, err error) {
	if startCommand == nil {
		return nil, fmt.Errorf("start SSH command function is nil")
	}
	var bridge InputBridge
	if len(options) > 0 {
		bridge = options[0].bridge
	}
	if err := validateCommandStdin(stdin, bridge); err != nil {
		return nil, err
	}
	if err := startCommand(); err != nil {
		return nil, err
	}
	return setupStdinPipeline(stdin, stdinPipe, initialPayload, options...)
}

func setupStdinPipeline(stdin io.Reader, stdinPipe io.WriteCloser, initialPayload string, options ...inputPipelineOptions) (finishStdin func() error, err error) {
	if stdinPipe == nil {
		return func() error { return nil }, nil
	}

	if initialPayload != "" && stdin != nil {
		closeErr := stdinPipe.Close()
		return nil, fmt.Errorf("%w: conflicting script payload and runtime stdin input", errors.Join(ErrExecutionValidation, closeErr))
	}

	if initialPayload != "" {
		if _, writeErr := io.WriteString(stdinPipe, initialPayload); writeErr != nil {
			closeErr := stdinPipe.Close()
			return nil, fmt.Errorf("write initial stdin payload failed: %w", errors.Join(writeErr, closeErr))
		}
	}

	if stdin == nil {
		if closeErr := stdinPipe.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) && !errors.Is(closeErr, io.EOF) {
			return nil, fmt.Errorf("close session stdin pipe failed: %w", closeErr)
		}
		return func() error { return nil }, nil
	}

	stopAndWait, pipeErr := pipeCommandStdin(stdin, stdinPipe, options...)
	if pipeErr != nil {
		closeErr := stdinPipe.Close()
		return nil, fmt.Errorf("start stdin pipe failed: %w", errors.Join(pipeErr, closeErr))
	}

	return stopAndWait, nil
}

func (c *Client) runRawCommandWithPayload(ctx context.Context, rawCmd, initialPayload string, stdin io.Reader, stdout, stderr io.Writer, cancelOutput ...context.CancelFunc) error {
	return c.runSessionWithInput(ctx, "exec", func(session *ssh.Session) error { return session.Start(rawCmd) }, initialPayload, stdin, stdout, stderr, cancelOutput...)
}

func openSessionPipes(session *ssh.Session) (io.WriteCloser, io.Reader, io.Reader, error) {
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open session stdin pipe failed: %w", err)
	}
	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open session stdout pipe failed: %w", err)
	}
	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open session stderr pipe failed: %w", err)
	}
	return stdinPipe, stdoutPipe, stderrPipe, nil
}

func (c *Client) waitNonTerminalSession(ctx context.Context, session *ssh.Session, waitDone <-chan error, outputFailed <-chan error, abort context.CancelFunc) (waitErr, outputFailedErr error) {
	select {
	case err := <-waitDone:
		return err, nil
	case err := <-outputFailed:
		abort()
		return c.closeCanceledSession(ctx, session, waitDone), err
	case <-ctx.Done():
		abort()
		return c.closeCanceledSession(ctx, session, waitDone), nil
	}
}

func combineOutputCancels(cancel context.CancelFunc, cancelOutput []context.CancelFunc) context.CancelFunc {
	return func() {
		cancel()
		for _, fn := range cancelOutput {
			if fn != nil {
				fn()
			}
		}
	}
}

func resolveSessionErrors(workErr, waitErr, outputFailedErr, closeErr, inputErr, outputErr error) error {
	if outputFailedErr != nil {
		return errors.Join(outputFailedErr, waitErr, closeErr, inputErr, outputErr)
	}
	if workErr != nil && waitErr != nil && (errors.Is(waitErr, context.Canceled) || errors.Is(waitErr, context.DeadlineExceeded)) {
		return errors.Join(workErr, waitErr, closeErr, inputErr, outputErr)
	}
	if waitErr != nil {
		return errors.Join(fmt.Errorf("session command execution failed: %w", waitErr), closeErr, inputErr, outputErr)
	}
	return errors.Join(closeErr, inputErr, outputErr)
}

// runSessionWithInput owns one non-PTY SSH session. request names the protocol
// request ("exec" or "shell") for deadline and error reporting; start sends it.
// cancelOutput registers cancellation callbacks for the output-binding contexts
// so drain timeouts and session aborts interrupt blocked output writes.
func (c *Client) runSessionWithInput(ctx context.Context, request string, start func(*ssh.Session) error, initialPayload string, stdin io.Reader, stdout, stderr io.Writer, cancelOutput ...context.CancelFunc) (retErr error) {
	if c == nil || c.sshClient == nil {
		return fmt.Errorf("ssh client is not connected")
	}
	session, err := c.newSessionContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to create new session: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, c.closeSessionBounded(session)) }()

	stdinPipe, stdoutPipe, stderrPipe, pipeErr := openSessionPipes(session)
	if pipeErr != nil {
		return pipeErr
	}

	work, cancel := context.WithCancel(ctx)
	defer cancel()

	finishStdin, setupErr := startCommandWithStdinPipeline(
		func() error {
			if err := c.sessionRequest(work, session, request, func() error { return start(session) }); err != nil {
				return fmt.Errorf("start session %s failed: %w", request, err)
			}
			return nil
		},
		stdin,
		stdinPipe,
		initialPayload,
		inputPipelineOptions{ctx: work, bridge: c.environment.InputBridge},
	)
	if setupErr != nil {
		return setupErr
	}
	finishStdinOnce := sync.OnceValue(finishStdin)
	defer func() {
		if finishErr := finishStdinOnce(); finishErr != nil && !errors.Is(retErr, finishErr) {
			retErr = errors.Join(retErr, finishErr)
		}
	}()

	output := startSessionOutput(stdoutPipe, stderrPipe, stdout, stderr)
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- c.waitSession(session)
	}()

	cancelAllOutputs := combineOutputCancels(cancel, cancelOutput)
	waitErr, outputFailedErr := c.waitNonTerminalSession(work, session, waitDone, output.failed, cancelAllOutputs)

	cancel()
	closeErr := c.closeSessionBounded(session)
	inputErr := finishStdinOnce()
	outputErr := waitSessionOutput(ctx, output.wait, cancelAllOutputs)

	return resolveSessionErrors(work.Err(), waitErr, outputFailedErr, closeErr, inputErr, outputErr)
}

func pipeCommandStdin(stdin io.Reader, dst io.WriteCloser, options ...inputPipelineOptions) (stopAndWait func() error, err error) {
	if stdin == nil {
		return nil, nil
	}
	ctx := context.Background()
	var bridge InputBridge
	if len(options) > 0 {
		ctx, bridge = options[0].ctx, options[0].bridge
	}
	if err := validateCommandStdin(stdin, bridge); err != nil {
		return nil, err
	}
	if fileStdin, ok := stdin.(*os.File); ok && fileStdin != nil {
		cancel, done, err := startInputCopy(ctx, bridge, InteractiveIO{Stdin: fileStdin}, dst)
		if err != nil {
			return nil, err
		}
		return sync.OnceValue(func() error {
			cancelErr := cancel()
			// The session owner closes/interrupts its channel before finishing
			// input, unblocking any SSH window write. Join that writer before
			// CloseWrite: x/crypto's stdin Write and Close are not concurrent-safe.
			copyErr := <-done
			if errors.Is(copyErr, io.EOF) || errors.Is(copyErr, os.ErrClosed) {
				copyErr = nil
			}
			closeErr := dst.Close()
			if errors.Is(closeErr, io.EOF) || errors.Is(closeErr, os.ErrClosed) {
				closeErr = nil
			}
			return errors.Join(cancelErr, copyErr, closeErr)
		}), nil
	}

	doneCh := make(chan error, 1)
	closeDst := sync.OnceValue(func() error {
		if closeErr := dst.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) && !errors.Is(closeErr, io.EOF) {
			return closeErr
		}
		return nil
	})

	go func() {
		defer close(doneCh)
		_, copyErr := io.Copy(dst, stdin)
		if errors.Is(copyErr, io.EOF) || errors.Is(copyErr, os.ErrClosed) {
			copyErr = nil
		}
		// Only the copying goroutine owns EOF on this finite input. Closing
		// from stopAndWait could race an in-flight channel.WriteExtended.
		doneCh <- errors.Join(copyErr, closeDst())
	}()

	// Supported memory readers are finite. A blocked destination write is
	// released by the caller's session/transport shutdown, not by racing EOF.
	stopAndWait = sync.OnceValue(func() error { return <-doneCh })
	return stopAndWait, nil
}

func validateCommandStdin(stdin io.Reader, bridge InputBridge) error {
	switch value := stdin.(type) {
	case nil:
		return nil
	case *os.File:
		if value == nil {
			return fmt.Errorf("command stdin file is nil")
		}
		if runtime.GOOS == "windows" && nilCapability(bridge) {
			return fmt.Errorf("native Windows file input requires an input bridge: %w", ErrInteractionRequired)
		}
	case *bytes.Buffer:
		if value == nil {
			return fmt.Errorf("command stdin buffer is nil")
		}
	case *bytes.Reader:
		if value == nil {
			return fmt.Errorf("command stdin bytes reader is nil")
		}
	case *strings.Reader:
		if value == nil {
			return fmt.Errorf("command stdin string reader is nil")
		}
	default:
		return fmt.Errorf("unsupported command stdin type %T: use an os file or RunCommandWithInput", stdin)
	}
	return nil
}

type subsystemSessionResult struct {
	session *ssh.Session
	err     error
}

func (c *Client) newSessionContext(ctx context.Context) (_ *ssh.Session, retErr error) {
	if ctx != nil && c != nil {
		work, cancel := withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
		defer cancel()
		ctx = work
	}
	if ctx == nil {
		return nil, fmt.Errorf("create SSH session context is nil")
	}
	if c == nil || c.sshClient == nil {
		return nil, fmt.Errorf("ssh client is not connected")
	}
	c.observeSession(logger.SessionRequest, 2, "open", "sending")
	defer func() {
		outcome := "accepted"
		if retErr != nil {
			outcome = "failed or interrupted"
		}
		c.observeSession(logger.SessionRequest, 2, "open", outcome)
	}()
	result := make(chan subsystemSessionResult, 1)
	go func() {
		session, err := c.sshClient.NewSession()
		result <- subsystemSessionResult{session: session, err: err}
	}()
	select {
	case created := <-result:
		if created.err != nil {
			return nil, fmt.Errorf("create SSH session failed: %w", created.err)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, errors.Join(ctxErr, c.closeSessionBounded(created.session))
		}
		return created.session, nil
	case <-ctx.Done():
		select {
		case created := <-result:
			var createErr error
			if created.err != nil {
				createErr = fmt.Errorf("create SSH session after cancellation failed: %w", created.err)
			}
			var sessionErr error
			if created.session != nil {
				sessionErr = c.closeSessionBounded(created.session)
			}
			return nil, errors.Join(ctx.Err(), createErr, sessionErr)
		default:
		}
		interruptErr := c.Interrupt()
		created := <-result
		var createErr error
		var sessionErr error
		if created.err != nil {
			createErr = fmt.Errorf("create SSH session after interrupt failed: %w", created.err)
		}
		if created.session != nil {
			sessionErr = c.closeSessionBounded(created.session)
		}
		return nil, errors.Join(ctx.Err(), interruptErr, createErr, sessionErr)
	}
}

// inputPipelineOptions binds file input cancellation to its SSH operation.
type inputPipelineOptions struct {
	ctx    context.Context
	bridge InputBridge
}
