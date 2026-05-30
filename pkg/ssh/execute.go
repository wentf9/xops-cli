package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func (c *Client) RunWithSudo(ctx context.Context, command string) (string, error) {
	c.maybeDetectSudoMode(ctx)
	wrappedCmd := fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))

	switch c.cfg.SudoMode {
	case SudoModeRoot:
		return c.Run(ctx, command)
	case SudoModeSudo:
		return c.runWithSudo(ctx, wrappedCmd, c.cfg.Password, nil)
	case SudoModeSudoer:
		return c.runWithSudo(ctx, wrappedCmd, "", nil)
	case SudoModeSu:
		return c.runWithSu(ctx, command, c.cfg.SuPwd)
	default:
		return "", fmt.Errorf("unknown sudo mode: %s, please check config to set sudo mode", c.cfg.SudoMode)
	}
}

// RunScriptWithSudo 提权执行脚本
func (c *Client) RunScriptWithSudo(ctx context.Context, scriptContent string) (string, error) {
	c.maybeDetectSudoMode(ctx)
	switch c.cfg.SudoMode {
	case SudoModeRoot:
		return c.RunScript(ctx, scriptContent)
	case SudoModeSudo:
		return c.runWithSudo(ctx, "bash -l -s", c.cfg.Password, strings.NewReader(scriptContent))
	case SudoModeSudoer:
		return c.runWithSudo(ctx, "bash -l -s", "", strings.NewReader(scriptContent))
	case SudoModeSu:
		return c.runWithSu(ctx, fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(scriptContent, "'", "'\\''")), c.cfg.SuPwd)
	default:
		return "", fmt.Errorf("unsupported sudo mode: %s", c.cfg.SudoMode)
	}
}

// RunInteractiveWithSudo 在 PTY 环境下以提权方式执行单条交互式命令
func (c *Client) RunInteractiveWithSudo(ctx context.Context, command string) error {
	c.maybeDetectSudoMode(ctx)
	if c.cfg.SudoMode == SudoModeRoot {
		return c.RunInteractive(ctx, command)
	}

	// 对于需要提权的场景，打开交互式 shell 后在 shell 内提权再执行命令
	session, err := c.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create new session: %w", err)
	}
	defer func() { _ = session.Close() }()

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

	stdin, _ := session.StdinPipe()

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
	defer func() { _ = term.Restore(fdIn, oldState) }()

	derivedCtx, cancelResize := context.WithCancel(ctx)
	defer cancelResize()
	startWindowResizeLoop(derivedCtx, session, fdOut, width, height)

	if expect != nil {
		_ = expect.Wait(ctx, 5*time.Second)

		// 获取被拦截的输出，仅需清理密码行，不再有 sudo 回显
		cleaned := expect.CleanOutput(c.passwordPromptRegex())
		_, _ = os.Stdout.Write([]byte(cleaned))

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
	_, _ = stdin.Write([]byte(wrappedCmd))

	cancelStdin, stdinDone := copyStdinTo(stdin)

	err = ignoreShellExitError(session.Wait())
	_ = term.Restore(fdIn, oldState)
	cancelStdin()
	<-stdinDone

	return err
}

func (c *Client) runWithSudo(ctx context.Context, command string, password string, extraStdin io.Reader) (string, error) {
	if password == "" && c.cfg.SudoMode == SudoModeSudo {
		return "", fmt.Errorf("sudo password is required but not provided")
	}

	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create new session: %w", err)
	}
	defer func() { _ = session.Close() }()

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
	return startWithTimeout(ctx, session, fullCmd)
}

func (c *Client) runWithSu(ctx context.Context, command string, password string) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create new session: %w", err)
	}
	defer func() { _ = session.Close() }()

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

	expect := NewExpect(stdin, ExpectRule{
		Pattern: c.passwordPromptRegex(),
		Respond: StaticRespond(password),
	})
	expect.SetAccumulate(true)
	session.Stdout = expect

	cmd := fmt.Sprintf("export LC_ALL=C; su - root -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))

	if err := session.Start(cmd); err != nil {
		return "", fmt.Errorf("failed to start command: %w", err)
	}

	if err := expect.Wait(ctx, 5*time.Second); err != nil {
		return expect.Output(), fmt.Errorf("password handshake failed: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case err = <-done:
	case <-ctx.Done():
		if killErr := session.Signal(ssh.SIGKILL); killErr != nil {
			return expect.Output(), fmt.Errorf("failed to kill command after context done: %w", killErr)
		}
		return expect.Output(), ctx.Err()
	}

	cleanOutput := expect.CleanOutput(c.passwordPromptRegex())
	if err != nil {
		return cleanOutput, fmt.Errorf("command execution failed: %w", err)
	}

	return cleanOutput, nil
}

func (c *Client) ShellWithSudo(ctx context.Context) error {
	c.maybeDetectSudoMode(ctx)
	if c.cfg.SudoMode == SudoModeRoot {
		return c.Shell(ctx)
	}

	// none 模式明确不支持提权
	if c.cfg.SudoMode == SudoModeNone {
		return fmt.Errorf("privilege escalation is not supported for this host (sudo_mode=none)")
	}

	// sudo/sudoer 模式：通过 sudo -S -p '' true 预检，可靠且无副作用
	// su 模式不做预检：su -c 会跑 root login shell 初始化脚本，脚本错误会导致误报
	if c.cfg.SudoMode == SudoModeSudo || c.cfg.SudoMode == SudoModeSudoer {
		if _, err := c.runWithSudo(ctx, "true", c.cfg.Password, nil); err != nil {
			return fmt.Errorf("sudo access denied: %w", err)
		}
	}

	session, err := c.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create new session: %w", err)
	}
	defer func() { _ = session.Close() }()
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
	stdin, _ := session.StdinPipe()

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
	defer func() { _ = term.Restore(fdIn, oldState) }()

	derivedCtx, cancelResize := context.WithCancel(ctx)
	defer cancelResize()
	startWindowResizeLoop(derivedCtx, session, fdOut, width, height)

	if expect != nil {
		_ = expect.Wait(ctx, 5*time.Second)

		// 提取、清洗并打印密码握手前的截留输出
		cleaned := expect.CleanOutput(c.passwordPromptRegex())
		_, _ = os.Stdout.Write([]byte(cleaned))

		// 将后续真实的 Shell 输出接入到当前终端
		expect.SetAccumulate(false)
		expect.SetTarget(os.Stdout)
	}

	cancelStdin, stdinDone := copyStdinTo(stdin)

	err = ignoreShellExitError(session.Wait())
	_ = term.Restore(fdIn, oldState)
	cancelStdin()
	<-stdinDone

	return err
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
	switch c.cfg.SudoMode {
	case SudoModeSudo:
		return "sudo -i", c.cfg.Password
	case SudoModeSudoer:
		return "sudo -i", ""
	case SudoModeSu:
		return "su -", c.cfg.SuPwd
	case SudoModeRoot, "":
		return "", ""
	default:
		return "", ""
	}
}

func startWindowResizeLoop(ctx context.Context, session *ssh.Session, fdOut, width, height int) {
	go func() {
		lastW, lastH := width, height
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				currW, currH, _ := term.GetSize(fdOut)
				if currW != lastW || currH != lastH {
					_ = session.WindowChange(currH, currW)
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

	expect := NewExpect(stdin, rules...)
	expect.SetAccumulate(true)
	session.Stdout = expect
	return expect
}
