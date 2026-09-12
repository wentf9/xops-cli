package ssh

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func (c *Client) RunWithSudo(ctx context.Context, command string, opts ...RunOption) (string, error) {
	config := DefaultRunConfig()
	for _, opt := range opts {
		opt(config)
	}

	if err := c.maybeDetectSudoMode(ctx); err != nil {
		return "", err
	}
	connCfg := c.ConnectionConfig()

	var wrappedCmd string
	if config.LoginShell {
		wrappedCmd = fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))
	} else {
		wrappedCmd = fmt.Sprintf("bash -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))
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
	config := DefaultRunConfig()
	for _, opt := range opts {
		opt(config)
	}

	if err := c.maybeDetectSudoMode(ctx); err != nil {
		return "", err
	}
	connCfg := c.ConnectionConfig()

	bashArgs := "bash -s"
	bashCmd := fmt.Sprintf("bash -c '%s'", strings.ReplaceAll(scriptContent, "'", "'\\''"))
	if config.LoginShell {
		bashArgs = "bash -l -s"
		bashCmd = fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(scriptContent, "'", "'\\''"))
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
	return c.RunInteractiveWithSudoIO(ctx, command, defaultInteractiveIO())
}

// RunInteractiveWithSudoIO uses an authenticated terminal handoff before
// consuming caller input. The injected streams avoid process-global I/O changes.
func (c *Client) RunInteractiveWithSudoIO(ctx context.Context, command string, streams InteractiveIO) error {
	if err := c.maybeDetectSudoMode(ctx); err != nil {
		return err
	}
	mode := c.ConnectionConfig().SudoMode
	switch mode {
	case SudoModeRoot:
		return c.RunInteractiveCmdWithIO(ctx, "bash -l -c "+shellQuote(command), streams)
	case SudoModeSudoer:
		wrapped, err := interactivePrivilegeCommand(mode, command)
		if err != nil {
			return err
		}
		return c.RunInteractiveCmdWithIO(ctx, wrapped, streams)
	case SudoModeSudo, SudoModeSu:
		return c.runInteractivePrivilege(ctx, mode, "exec bash -c "+shellQuote(command), streams)
	default:
		return fmt.Errorf("interactive privilege escalation is unsupported for sudo mode %q", mode)
	}
}

// Commands travel in the SSH exec request, never through echoed PTY input.
func interactivePrivilegeCommand(mode SudoMode, command string) (string, error) {
	quoted := "'" + strings.ReplaceAll(command, "'", "'\\''") + "'"
	switch mode {
	case SudoModeSudo, SudoModeSudoer:
		return "sudo -i -- bash -c " + shellQuote(sudoLoginScript(command)), nil
	case SudoModeSu:
		bashCommand := "exec bash -c " + quoted
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
	defer joinResourceCloseError(&retErr, session, "sudo session")

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
	return c.ShellWithSudoIO(ctx, defaultInteractiveIO())
}

// ShellWithSudoIO authenticates before switching the local terminal to raw mode.
func (c *Client) ShellWithSudoIO(ctx context.Context, streams InteractiveIO) error {
	if err := c.maybeDetectSudoMode(ctx); err != nil {
		return err
	}
	mode := c.ConnectionConfig().SudoMode
	switch mode {
	case SudoModeRoot:
		return c.ShellWithIO(ctx, streams)
	case SudoModeSudoer:
		return c.RunInteractiveCmdWithIO(ctx, "sudo -i", streams)
	case SudoModeSudo, SudoModeSu:
		return c.runInteractivePrivilege(ctx, mode, `exec "${SHELL:-/bin/bash}"`, streams)
	default:
		return fmt.Errorf("privilege escalation is not supported for this host (sudo_mode=%s)", mode)
	}
}

// ignoreShellExitError 忽略交互式 shell 的 ExitError
// 交互式 shell 退出时可能继承用户执行的最后一条命令的退出码，这是正常行为
func ignoreShellExitError(err error) error {
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
	if err := validateCommandStdin(stdin); err != nil {
		return err
	}
	if !sudo {
		var rawCmd string
		if command != "" {
			rawCmd = fmt.Sprintf("bash -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))
		} else {
			rawCmd = "bash"
		}
		return c.runRawCommandWithPayload(ctx, rawCmd, "", stdin, stdout, stderr)
	}

	if err := c.maybeDetectSudoMode(ctx); err != nil {
		return err
	}
	clientConfig, _ := c.configSnapshot()

	switch clientConfig.SudoMode {
	case SudoModeRoot:
		var rawCmd string
		if command != "" {
			rawCmd = fmt.Sprintf("bash -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))
		} else {
			rawCmd = "bash"
		}
		return c.runRawCommandWithPayload(ctx, rawCmd, "", stdin, stdout, stderr)
	case SudoModeSudoer:
		var rawCmd string
		if command != "" {
			rawCmd = fmt.Sprintf("sudo -S -p '' bash -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))
		} else {
			rawCmd = "sudo -S -p '' bash"
		}
		return c.runRawCommandWithPayload(ctx, rawCmd, "", stdin, stdout, stderr)
	case SudoModeSudo, SudoModeSu:
		inner := "exec bash"
		if command != "" {
			inner = "bash -c " + shellQuote(command)
		}
		return c.runPrivilegeOperation(ctx, clientConfig.SudoMode, inner, stdin, stdout, stderr)
	case SudoModeNone:
		return fmt.Errorf("privilege escalation is not supported for this host (sudo_mode=none)")
	default:
		return fmt.Errorf("unknown sudo mode: %s, please check config to set sudo mode", clientConfig.SudoMode)
	}
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
) (finishStdin func() error, err error) {
	if startCommand == nil {
		return nil, fmt.Errorf("start SSH command function is nil")
	}
	if err := validateCommandStdin(stdin); err != nil {
		return nil, err
	}
	if err := startCommand(); err != nil {
		return nil, err
	}
	return setupStdinPipeline(stdin, stdinPipe, initialPayload)
}

func setupStdinPipeline(stdin io.Reader, stdinPipe io.WriteCloser, initialPayload string) (finishStdin func() error, err error) {
	if stdinPipe == nil {
		return func() error { return nil }, nil
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

	stopAndWait, pipeErr := pipeCommandStdin(stdin, stdinPipe)
	if pipeErr != nil {
		closeErr := stdinPipe.Close()
		return nil, fmt.Errorf("start stdin pipe failed: %w", errors.Join(pipeErr, closeErr))
	}

	return stopAndWait, nil
}

func (c *Client) runRawCommandWithPayload(ctx context.Context, rawCmd, initialPayload string, stdin io.Reader, stdout, stderr io.Writer) (retErr error) {
	if c == nil || c.sshClient == nil {
		return fmt.Errorf("ssh client is not connected")
	}
	session, err := c.newSessionContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "ssh command session")

	stdinPipe, pipeErr := session.StdinPipe()
	if pipeErr != nil {
		return fmt.Errorf("open session stdin pipe failed: %w", pipeErr)
	}

	session.Stdout = stdout
	session.Stderr = stderr

	finishStdin, setupErr := startCommandWithStdinPipeline(
		func() error {
			if err := session.Start(rawCmd); err != nil {
				return fmt.Errorf("start session command failed: %w", err)
			}
			return nil
		},
		stdin,
		stdinPipe,
		initialPayload,
	)
	if setupErr != nil {
		return setupErr
	}
	defer func() {
		if finishErr := finishStdin(); finishErr != nil {
			retErr = errors.Join(retErr, finishErr)
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("session command execution failed: %w", err)
		}
		return nil
	case <-ctx.Done():
		interruptErr := c.Interrupt()
		finishErr := finishStdin()
		<-done
		return errors.Join(ctx.Err(), interruptErr, finishErr)
	}
}

func pipeCommandStdin(stdin io.Reader, dst io.WriteCloser) (stopAndWait func() error, err error) {
	if stdin == nil {
		return nil, nil
	}
	if err := validateCommandStdin(stdin); err != nil {
		return nil, err
	}
	if fileStdin, ok := stdin.(*os.File); ok && fileStdin != nil {
		cancel, done, err := copyStdinTo(fileStdin, dst)
		if err != nil {
			return nil, err
		}
		return sync.OnceValue(func() error {
			cancelErr := cancel()
			if closeErr := dst.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) && !errors.Is(closeErr, io.EOF) {
				cancelErr = errors.Join(cancelErr, closeErr)
			}
			copyErr := <-done
			if copyErr != nil && !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, os.ErrClosed) {
				cancelErr = errors.Join(cancelErr, copyErr)
			}
			return cancelErr
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
		doneCh <- errors.Join(copyErr, closeDst())
	}()

	stopAndWait = sync.OnceValue(func() error {
		closeErr := closeDst()
		copyErr := <-doneCh
		if copyErr != nil && !errors.Is(copyErr, io.EOF) && !errors.Is(copyErr, os.ErrClosed) {
			closeErr = errors.Join(closeErr, copyErr)
		}
		return closeErr
	})
	return stopAndWait, nil
}

func validateCommandStdin(stdin io.Reader) error {
	switch value := stdin.(type) {
	case nil:
		return nil
	case *os.File:
		if value == nil {
			return fmt.Errorf("command stdin file is nil")
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

func (c *Client) newSessionContext(ctx context.Context) (*ssh.Session, error) {
	if ctx == nil {
		return nil, fmt.Errorf("create SSH session context is nil")
	}
	if c == nil || c.sshClient == nil {
		return nil, fmt.Errorf("ssh client is not connected")
	}
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
			return nil, errors.Join(ctxErr, created.session.Close())
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
				sessionErr = created.session.Close()
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
			sessionErr = created.session.Close()
		}
		return nil, errors.Join(ctx.Err(), interruptErr, createErr, sessionErr)
	}
}
