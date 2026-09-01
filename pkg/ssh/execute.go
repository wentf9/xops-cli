package ssh

import (
	"bytes"
	"context"
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
	clientConfig, _ := c.configSnapshot()

	var wrappedCmd string
	if config.LoginShell {
		wrappedCmd = fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))
	} else {
		wrappedCmd = fmt.Sprintf("bash -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))
	}

	switch clientConfig.SudoMode {
	case SudoModeRoot:
		return c.Run(ctx, command, opts...)
	case SudoModeSudo:
		return c.runWithSudo(ctx, wrappedCmd, clientConfig.Password, nil, config)
	case SudoModeSudoer:
		return c.runWithSudo(ctx, wrappedCmd, "", nil, config)
	case SudoModeSu:
		return c.runWithSu(ctx, command, clientConfig.SuPwd, config)
	default:
		return "", fmt.Errorf("unknown sudo mode: %s, please check config to set sudo mode", clientConfig.SudoMode)
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
	clientConfig, _ := c.configSnapshot()

	bashArgs := "bash -s"
	bashCmd := fmt.Sprintf("bash -c '%s'", strings.ReplaceAll(scriptContent, "'", "'\\''"))
	if config.LoginShell {
		bashArgs = "bash -l -s"
		bashCmd = fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(scriptContent, "'", "'\\''"))
	}

	switch clientConfig.SudoMode {
	case SudoModeRoot:
		return c.RunScript(ctx, scriptContent, opts...)
	case SudoModeSudo:
		return c.runWithSudo(ctx, bashArgs, clientConfig.Password, strings.NewReader(scriptContent), config)
	case SudoModeSudoer:
		return c.runWithSudo(ctx, bashArgs, "", strings.NewReader(scriptContent), config)
	case SudoModeSu:
		return c.runWithSu(ctx, bashCmd, clientConfig.SuPwd, config)
	default:
		return "", fmt.Errorf("unsupported sudo mode: %s", clientConfig.SudoMode)
	}
}

// RunInteractiveWithSudo 在 PTY 环境下以提权方式执行单条交互式命令
func (c *Client) RunInteractiveWithSudo(ctx context.Context, command string) (retErr error) {
	if err := c.maybeDetectSudoMode(ctx); err != nil {
		return err
	}
	clientConfig, _ := c.configSnapshot()
	if clientConfig.SudoMode == SudoModeRoot {
		return c.RunInteractive(ctx, command)
	}

	// 对于需要提权的场景，打开交互式 shell 后在 shell 内提权再执行命令
	session, err := c.newSessionContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "interactive sudo session")

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	fdIn := int(os.Stdin.Fd())
	fdOut := int(os.Stdout.Fd())
	width, height, err := term.GetSize(fdOut)
	if err != nil {
		width, height = 80, 40
	}
	if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
		return fmt.Errorf("request for pty failed: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("create interactive sudo stdin pipe failed: %w", err)
	}

	sudoCmd, password := c.getSudoParams()
	expect := c.setupInteractiveExpect(session, stdin, password)
	session.Stderr = os.Stderr

	if sudoCmd != "" {
		if err := session.Start(sudoCmd); err != nil {
			return fmt.Errorf("start %s failed: %w", sudoCmd, err)
		}
	} else {
		if err := session.Shell(); err != nil {
			return fmt.Errorf("start shell failed: %w", err)
		}
	}

	oldState, err := term.MakeRaw(fdIn)
	if err != nil {
		return fmt.Errorf("cannot set terminal to raw: %w", err)
	}
	defer func() {
		if restoreErr := term.Restore(fdIn, oldState); restoreErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("restore terminal failed: %w", restoreErr))
		}
	}()

	derivedCtx, cancelResize := context.WithCancel(ctx)
	defer cancelResize()
	startWindowResizeLoop(derivedCtx, session, fdOut, width, height, c.getLogger())

	if expect != nil {
		if err := expect.Wait(ctx, 5*time.Second); err != nil {
			return fmt.Errorf("complete interactive sudo authentication failed: %w", err)
		}

		// 获取被拦截的输出，仅需清理密码行，不再有 sudo 回显
		cleaned := expect.CleanOutput(c.passwordPromptRegex())
		if _, err := io.WriteString(os.Stdout, cleaned); err != nil {
			return fmt.Errorf("write interactive sudo output failed: %w", err)
		}

		// 握手结束后，将后续输出直接透传给终端，并停止无谓的累积
		expect.SetAccumulate(false)
		expect.SetTarget(os.Stdout)
	}

	// 提权完成后，给 Root Shell 留出 1 秒的初始化时间，
	// 防止 sudo 或 su 的 tcflush(清空终端缓冲区) 机制吃掉我们随后立刻发出的指令。
	time.Sleep(1 * time.Second)

	// 提权完成后发送目标命令
	// 使用 exec bash -c 替换掉提权后的 root shell
	wrappedCmd := fmt.Sprintf("exec bash -c '%s'\n", strings.ReplaceAll(command, "'", "'\\''"))
	if _, err := io.WriteString(stdin, wrappedCmd); err != nil {
		return fmt.Errorf("write interactive sudo command failed: %w", err)
	}

	cancelStdin, stdinDone, err := copyStdinTo(os.Stdin, stdin)
	if err != nil {
		return err
	}

	err = ignoreShellExitError(session.Wait())
	cancelErr := cancelStdin()
	stdinErr := <-stdinDone

	return errors.Join(err, cancelErr, stdinErr)
}

func (c *Client) runWithSudo(ctx context.Context, command string, password string, extraStdin io.Reader, config *RunConfig) (output string, retErr error) {
	clientConfig, _ := c.configSnapshot()
	if password == "" && clientConfig.SudoMode == SudoModeSudo {
		return "", fmt.Errorf("sudo password is required but not provided")
	}

	session, err := c.newSessionContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "sudo session")

	if password != "" {
		if extraStdin != nil {
			session.Stdin = io.MultiReader(strings.NewReader(password+"\n"), extraStdin)
		} else {
			session.Stdin = strings.NewReader(password + "\n")
		}
	} else if extraStdin != nil {
		session.Stdin = extraStdin
	}

	fullCmd := fmt.Sprintf("sudo -S -p '' %s", command)
	return c.startWithTimeout(ctx, session, fullCmd, config)
}

func (c *Client) runWithSu(ctx context.Context, command string, password string, config *RunConfig) (output string, retErr error) {
	session, err := c.newSessionContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "su session")

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return "", fmt.Errorf("request for pty failed: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	if config == nil {
		config = DefaultRunConfig()
	}
	syncWriter := newOutputWriter(config)

	expect := NewExpectWithOptions(stdin, []ExpectRule{
		{
			Pattern: c.passwordPromptRegex(),
			Respond: StaticRespond(password),
		},
	}, WithExpectLogger(c.getLogger()))
	expect.SetTarget(syncWriter)
	// 如果模式是全量收集，由于我们要手动处理密码提示过滤，需要让 expect 不自己收集全部
	expect.SetAccumulate(false)
	session.Stdout = expect

	cmd := fmt.Sprintf("export LC_ALL=C; su - root -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))

	if err := session.Start(cmd); err != nil {
		return "", fmt.Errorf("failed to start command: %w", err)
	}

	if err := expect.Wait(ctx, 5*time.Second); err != nil {
		return syncWriter.String(), fmt.Errorf("password handshake failed: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case err = <-done:
	case <-ctx.Done():
		return syncWriter.String(), c.closeCanceledSession(ctx, session, done)
	}

	if err != nil {
		return syncWriter.String(), fmt.Errorf("command execution failed: %w", err)
	}

	output = syncWriter.String()
	// 如果是字符串返回模式，尝试清理密码提示
	if config.OutMode == OutputModeString || config.OutMode == OutputModeRingBuffer {
		if c.passwordPromptRegex() != nil {
			output = c.passwordPromptRegex().ReplaceAllString(output, "")
		}
	}

	return output, nil
}

func (c *Client) preCheckSudoMode(ctx context.Context) (isRoot bool, err error) {
	if err := c.maybeDetectSudoMode(ctx); err != nil {
		return false, err
	}
	clientConfig, _ := c.configSnapshot()
	if clientConfig.SudoMode == SudoModeRoot {
		return true, nil
	}

	// none 模式明确不支持提权
	if clientConfig.SudoMode == SudoModeNone {
		return false, fmt.Errorf("privilege escalation is not supported for this host (sudo_mode=none)")
	}

	// sudo/sudoer 模式：通过 sudo -S -p '' true 预检，可靠且无副作用
	// su 模式不做预检：su -c 会跑 root login shell 初始化脚本，脚本错误会导致误报
	if clientConfig.SudoMode == SudoModeSudo || clientConfig.SudoMode == SudoModeSudoer {
		if _, err := c.runWithSudo(ctx, "true", clientConfig.Password, nil, nil); err != nil {
			return false, fmt.Errorf("sudo access denied: %w", err)
		}
	}
	return false, nil
}

func (c *Client) ShellWithSudo(ctx context.Context) (retErr error) {
	isRoot, err := c.preCheckSudoMode(ctx)
	if err != nil {
		return err
	}
	if isRoot {
		return c.Shell(ctx)
	}

	session, err := c.newSessionContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "sudo shell session")
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	fdIn := int(os.Stdin.Fd())
	fdOut := int(os.Stdout.Fd())
	width, height, err := term.GetSize(fdOut)
	if err != nil {
		width, height = 80, 40
	}
	if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
		return fmt.Errorf("request for pty failed: %w", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("create sudo shell stdin pipe failed: %w", err)
	}

	sudoCmd, password := c.getSudoParams()
	expect := c.setupInteractiveExpect(session, stdin, password)
	session.Stderr = os.Stderr

	if sudoCmd != "" {
		if err := session.Start(sudoCmd); err != nil {
			return fmt.Errorf("start %s failed: %w", sudoCmd, err)
		}
	} else {
		if err := session.Shell(); err != nil {
			return fmt.Errorf("start shell failed: %w", err)
		}
	}

	oldState, err := term.MakeRaw(fdIn)
	if err != nil {
		return fmt.Errorf("cannot set terminal to raw: %w", err)
	}
	defer func() {
		if restoreErr := term.Restore(fdIn, oldState); restoreErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("restore terminal failed: %w", restoreErr))
		}
	}()

	derivedCtx, cancelResize := context.WithCancel(ctx)
	defer cancelResize()
	startWindowResizeLoop(derivedCtx, session, fdOut, width, height, c.getLogger())

	if expect != nil {
		if err := expect.Wait(ctx, 5*time.Second); err != nil {
			return fmt.Errorf("complete sudo shell authentication failed: %w", err)
		}

		// 提取、清洗并打印密码握手前的截留输出
		cleaned := expect.CleanOutput(c.passwordPromptRegex())
		if _, err := io.WriteString(os.Stdout, cleaned); err != nil {
			return fmt.Errorf("write sudo shell output failed: %w", err)
		}

		// 将后续真实的 Shell 输出接入到当前终端
		expect.SetAccumulate(false)
		expect.SetTarget(os.Stdout)
	}

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			if signalErr := session.Signal(ssh.SIGKILL); signalErr != nil {
				c.getLogger().Debugf("signal canceled sudo shell session failed: %v", signalErr)
			}
			debugCloseResource(c.getLogger(), session, "canceled sudo shell session")
		case <-done:
		}
	}()

	cancelStdin, stdinDone, err := copyStdinTo(os.Stdin, stdin)
	if err != nil {
		return err
	}

	err = ignoreShellExitError(session.Wait())
	cancelErr := cancelStdin()
	stdinErr := <-stdinDone

	return errors.Join(err, cancelErr, stdinErr)
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

func (c *Client) getSudoParams() (string, string) {
	clientConfig, _ := c.configSnapshot()
	switch clientConfig.SudoMode {
	case SudoModeSudo:
		return "sudo -i", clientConfig.Password
	case SudoModeSudoer:
		return "sudo -i", ""
	case SudoModeSu:
		return "su -", clientConfig.SuPwd
	case SudoModeRoot, "":
		return "", ""
	default:
		return "", ""
	}
}

func startWindowResizeLoop(ctx context.Context, session *ssh.Session, fdOut, width, height int, l logger.DebugLogger) {
	go func() {
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
}

// setupInteractiveExpect 配置并返回一个用于拦截登录输出的 Expect 状态机。
func (c *Client) setupInteractiveExpect(session *ssh.Session, stdin io.Writer, password string) *Expect {
	if password == "" {
		session.Stdout = os.Stdout
		return nil
	}

	rules := []ExpectRule{{
		Pattern: c.passwordPromptRegex(),
		Respond: StaticRespond(password),
	}}

	expect := NewExpectWithOptions(stdin, rules, WithExpectLogger(c.getLogger()))
	expect.SetAccumulate(true)
	session.Stdout = expect
	return expect
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
	case SudoModeSudo:
		if clientConfig.Password == "" {
			return fmt.Errorf("sudo password is required but not provided")
		}
		var rawCmd string
		if command != "" {
			rawCmd = fmt.Sprintf("sudo -S -p '' bash -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))
		} else {
			rawCmd = "sudo -S -p '' bash"
		}
		return c.runRawCommandWithPayload(ctx, rawCmd, clientConfig.Password+"\n", stdin, stdout, stderr)
	case SudoModeSu:
		return c.runWithSuIO(ctx, command, stdin, stdout, stderr)
	case SudoModeNone:
		return fmt.Errorf("privilege escalation is not supported for this host (sudo_mode=none)")
	default:
		return fmt.Errorf("unknown sudo mode: %s, please check config to set sudo mode", clientConfig.SudoMode)
	}
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

	finishStdin, setupErr := setupStdinPipeline(stdin, stdinPipe, initialPayload)
	if setupErr != nil {
		return setupErr
	}
	defer func() {
		if finishErr := finishStdin(); finishErr != nil {
			retErr = errors.Join(retErr, finishErr)
		}
	}()

	session.Stdout = stdout
	session.Stderr = stderr

	if err := session.Start(rawCmd); err != nil {
		return fmt.Errorf("start session command failed: %w", err)
	}

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

//nolint:gocyclo
func (c *Client) runWithSuIO(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (retErr error) {
	if c == nil || c.sshClient == nil {
		return fmt.Errorf("ssh client is not connected")
	}
	session, err := c.newSessionContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "ssh command session")

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return fmt.Errorf("request for pty failed: %w", err)
	}

	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to open session stdin pipe: %w", err)
	}

	var payload string
	clientConfig, _ := c.configSnapshot()
	if clientConfig.SuPwd != "" {
		payload = clientConfig.SuPwd + "\n"
	}

	finishStdin, setupErr := setupStdinPipeline(stdin, stdinPipe, payload)
	if setupErr != nil {
		return setupErr
	}
	defer func() {
		if finishErr := finishStdin(); finishErr != nil {
			retErr = errors.Join(retErr, finishErr)
		}
	}()

	session.Stdout = stdout
	session.Stderr = stderr

	var cmd string
	if command != "" {
		cmd = fmt.Sprintf("export LC_ALL=C; su - root -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))
	} else {
		cmd = "export LC_ALL=C; su - root"
	}

	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("failed to start su session: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("su session command failed: %w", err)
		}
		return nil
	case <-ctx.Done():
		interruptErr := c.Interrupt()
		finishErr := finishStdin()
		<-done
		return errors.Join(ctx.Err(), interruptErr, finishErr)
	}
}

// pipeCommandStdin pipes stdin to dst in a goroutine and returns a stopAndWait
// function that stops copying and waits for the goroutine to finish.
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
