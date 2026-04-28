package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/wentf9/xops-cli/pkg/models"
)

func (c *Client) RunWithSudo(ctx context.Context, command string) (string, error) {
	c.maybeDetectSudoMode(ctx)
	wrappedCmd := fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))

	switch c.node.SudoMode {
	case models.SudoModeRoot:
		return c.Run(ctx, command)
	case models.SudoModeSudo:
		return c.runWithSudo(ctx, wrappedCmd, c.identity.Password, nil)
	case models.SudoModeSudoer:
		return c.runWithSudo(ctx, wrappedCmd, "", nil)
	case models.SudoModeSu:
		return c.runWithSu(command, c.node.SuPwd)
	default:
		return "", fmt.Errorf("unknown sudo mode: %s, please check config to set sudo mode", c.node.SudoMode)
	}
}

// RunScriptWithSudo 提权执行脚本
func (c *Client) RunScriptWithSudo(ctx context.Context, scriptContent string) (string, error) {
	c.maybeDetectSudoMode(ctx)
	switch c.node.SudoMode {
	case models.SudoModeRoot:
		return c.RunScript(ctx, scriptContent)
	case models.SudoModeSudo:
		return c.runWithSudo(ctx, "bash -l -s", c.identity.Password, strings.NewReader(scriptContent))
	case models.SudoModeSudoer:
		return c.runWithSudo(ctx, "bash -l -s", "", strings.NewReader(scriptContent))
	case models.SudoModeSu:
		return c.runWithSu(fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(scriptContent, "'", "'\\''")), c.node.SuPwd)
	default:
		return "", fmt.Errorf("unsupported sudo mode: %s", c.node.SudoMode)
	}
}

// RunInteractiveWithSudo 在 PTY 环境下以提权方式执行单条交互式命令
func (c *Client) RunInteractiveWithSudo(ctx context.Context, command string) error {
	c.maybeDetectSudoMode(ctx)
	if c.node.SudoMode == models.SudoModeRoot {
		return c.RunInteractive(ctx, command)
	}

	// 对于需要提权的场景，打开交互式 shell 后在 shell 内提权再执行命令
	session, err := c.sshClient.NewSession()
	if err != nil {
		return err
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
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	if err := session.Shell(); err != nil {
		return fmt.Errorf("start shell failed: %w", err)
	}

	oldState, err := term.MakeRaw(fdIn)
	if err != nil {
		return fmt.Errorf("can not set term to Raw: %w", err)
	}
	defer func() { _ = term.Restore(fdIn, oldState) }()

	startWindowResizeLoop(session, fdOut, width, height)

	sudoCmd, password := c.getSudoParams()
	// 使用 exec 替换掉普通用户的 shell，使得提权退出后直接关闭 SSH 会话
	if sudoCmd != "" {
		_, _ = stdin.Write([]byte("exec " + sudoCmd + "\n"))
	}

	if password != "" {
		handlePasswordHandshake(stdout, stdin, password)
	}

	// 提权完成后，给 Root Shell 留出 1 秒的初始化时间，
	// 防止 sudo 或 su 的 tcflush(清空终端缓冲区) 机制吃掉我们随后立刻发出的指令。
	time.Sleep(1 * time.Second)

	// 提权完成后发送目标命令
	// 使用 exec bash -c 替换掉提权后的 root shell
	wrappedCmd := fmt.Sprintf("exec bash -c '%s'\n", strings.ReplaceAll(command, "'", "'\\''"))
	_, _ = stdin.Write([]byte(wrappedCmd))

	go func() { _, _ = io.Copy(os.Stdout, stdout) }()
	go func() { _, _ = io.Copy(os.Stderr, stderr) }()

	cancelStdin, stdinDone := copyStdinTo(stdin)

	err = ignoreShellExitError(session.Wait())
	_ = term.Restore(fdIn, oldState)
	cancelStdin()
	<-stdinDone

	return err
}

func (c *Client) runWithSudo(ctx context.Context, command string, password string, extraStdin io.Reader) (string, error) {
	if password == "" && c.node.SudoMode == models.SudoModeSudo {
		return "", fmt.Errorf("sudo password is required but not provided")
	}

	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
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

func (c *Client) runWithSu(command string, password string) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
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
		return "", err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", err
	}

	cmd := fmt.Sprintf("export LC_ALL=C; su - root -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))

	if err := session.Start(cmd); err != nil {
		return "", fmt.Errorf("failed to start command: %w", err)
	}

	var outputBuf bytes.Buffer
	passwordPromptFound := make(chan bool)

	go processSuOutputForPassword(stdout, passwordPromptFound, &outputBuf)

	select {
	case <-passwordPromptFound:
		_, err = stdin.Write([]byte(password + "\n"))
		if err != nil {
			return "", fmt.Errorf("failed to send password: %w", err)
		}
	case <-time.After(5 * time.Second):
		return outputBuf.String(), fmt.Errorf("timeout waiting for password prompt")
	}

	err = session.Wait()
	cleanOutput := cleanSuOutput(outputBuf.String())
	if err != nil {
		return cleanOutput, fmt.Errorf("command execution failed: %w", err)
	}

	return cleanOutput, nil
}

func processSuOutputForPassword(stdout io.Reader, passwordPromptFound chan<- bool, outputBuf *bytes.Buffer) {
	buf := make([]byte, 1024)
	found := false
	for {
		n, err := stdout.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			outputBuf.Write(chunk)
			if !found && (strings.Contains(strings.ToLower(string(chunk)), "assword") || strings.Contains(string(chunk), "密码")) {
				found = true
				passwordPromptFound <- true
			}
		}
		if err != nil {
			if !found {
				close(passwordPromptFound)
			}
			break
		}
	}
}

func (c *Client) ShellWithSudo(ctx context.Context) error {
	c.maybeDetectSudoMode(ctx)
	if c.node.SudoMode == models.SudoModeRoot {
		return c.Shell(ctx)
	}

	// none 模式明确不支持提权
	if c.node.SudoMode == models.SudoModeNone {
		return fmt.Errorf("privilege escalation is not supported for this host (sudo_mode=none)")
	}

	// sudo/sudoer 模式：通过 sudo -S -p '' true 预检，可靠且无副作用
	// su 模式不做预检：su -c 会跑 root login shell 初始化脚本，脚本错误会导致误报
	if c.node.SudoMode == models.SudoModeSudo || c.node.SudoMode == models.SudoModeSudoer {
		if _, err := c.runWithSudo(ctx, "true", c.identity.Password, nil); err != nil {
			return fmt.Errorf("sudo access denied: %w", err)
		}
	}

	session, err := c.sshClient.NewSession()
	if err != nil {
		return err
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
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	if err := session.Shell(); err != nil {
		return fmt.Errorf("start Shell failed: %w", err)
	}

	oldState, err := term.MakeRaw(fdIn)
	if err != nil {
		return fmt.Errorf("can not set term to Raw : %w", err)
	}
	defer func() { _ = term.Restore(fdIn, oldState) }()

	startWindowResizeLoop(session, fdOut, width, height)

	sudoCmd, password := c.getSudoParams()
	_, _ = stdin.Write([]byte(sudoCmd + "\n"))

	if password == "" {
		go func() { _, _ = io.Copy(os.Stdout, stdout) }()
		go func() { _, _ = io.Copy(os.Stderr, stderr) }()

		cancelStdin, stdinDone := copyStdinTo(stdin)

		err = ignoreShellExitError(session.Wait())
		_ = term.Restore(fdIn, oldState)
		cancelStdin()
		<-stdinDone
		return err
	}

	handlePasswordHandshake(stdout, stdin, password)

	go func() { _, _ = io.Copy(os.Stdout, stdout) }()
	go func() { _, _ = io.Copy(os.Stderr, stderr) }()

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
	switch c.node.SudoMode {
	case models.SudoModeSudo:
		return "sudo -i", c.identity.Password
	case models.SudoModeSudoer:
		return "sudo -i", ""
	case models.SudoModeSu:
		return "su -", c.node.SuPwd
	case models.SudoModeRoot, "":
		return "", ""
	default:
		return "", ""
	}
}

func startWindowResizeLoop(session *ssh.Session, fdOut, width, height int) {
	go func() {
		lastW, lastH := width, height
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			currW, currH, _ := term.GetSize(fdOut)
			if currW != lastW || currH != lastH {
				_ = session.WindowChange(currH, currW)
				lastW, lastH = currW, currH
			}
		}
	}()
}

func handlePasswordHandshake(stdout io.Reader, stdin io.Writer, password string) {
	buf := make([]byte, 1024)
	var outputHistory bytes.Buffer
	done := make(chan struct{})

	go func() {
		time.Sleep(5 * time.Second)
		close(done)
	}()

HandshakeLoop:
	for {
		select {
		case <-done:
			break HandshakeLoop
		default:
			n, err := stdout.Read(buf)
			if err != nil {
				break HandshakeLoop
			}
			if n > 0 {
				outputHistory.Write(buf[:n])
				text := outputHistory.String()
				if outputHistory.Len() > 500 {
					outputHistory.Reset()
				}
				if strings.Contains(strings.ToLower(text), "assword") || strings.Contains(text, "密码") {
					_, _ = stdin.Write([]byte(password + "\n"))
					break HandshakeLoop
				}
			}
		}
	}
}

func cleanSuOutput(raw string) string {
	lines := strings.Split(raw, "\n")
	var result []string
	for _, line := range lines {
		trimLine := strings.TrimSpace(line)
		if strings.Contains(trimLine, "assword:") || trimLine == "" || strings.Contains(trimLine, "密码") {
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}
