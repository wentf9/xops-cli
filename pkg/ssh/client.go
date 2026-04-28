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

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Client struct {
	sshClient *ssh.Client
	node      models.Node
	host      models.Host
	identity  models.Identity
	provider  config.ConfigProvider
	nodeName  string
}

func newClient(raw *ssh.Client, node models.Node, host models.Host, identity models.Identity, provider config.ConfigProvider, nodeName string) *Client {
	return &Client{
		sshClient: raw,
		node:      node,
		host:      host,
		identity:  identity,
		provider:  provider,
		nodeName:  nodeName,
	}
}

// Close 关闭连接
func (c *Client) Close() error {
	return c.sshClient.Close()
}

// SSHClient 暴露底层的 ssh.Client (供高级操作使用，如 SCP)
func (c *Client) SSHClient() *ssh.Client {
	return c.sshClient
}

// Node 返回当前连接对应的节点配置
func (c *Client) Node() models.Node {
	return c.node
}

func (c *Client) Run(ctx context.Context, cmd string) (string, error) {
	// 使用 bash -l -c 执行，以加载完整的环境变量 (如 PATH)
	wrappedCmd := fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(cmd, "'", "'\\''"))
	return c.runRaw(ctx, wrappedCmd)
}

// RunWithoutLogin 执行命令并在非登录 Shell 中运行，避免加载 profile 脚本产生干扰输出
func (c *Client) RunWithoutLogin(ctx context.Context, cmd string) (string, error) {
	wrappedCmd := fmt.Sprintf("bash -c '%s'", strings.ReplaceAll(cmd, "'", "'\\''"))
	return c.runRaw(ctx, wrappedCmd)
}

func (c *Client) runRaw(ctx context.Context, wrappedCmd string) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
	}
	defer func() { _ = session.Close() }()
	return startWithTimeout(ctx, session, wrappedCmd)
}

// RunScript 执行 Shell 脚本内容
func (c *Client) RunScript(ctx context.Context, scriptContent string) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
	}
	defer func() { _ = session.Close() }()

	session.Stdin = strings.NewReader(scriptContent)
	// 使用 bash -l -s 从 stdin 读取脚本，以加载环境变量
	return startWithTimeout(ctx, session, "bash -l -s")
}

func (c *Client) Shell(ctx context.Context) error {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()
	// 配置 PTY (终端模式)
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	// 获取当前终端文件描述符
	fdIn := int(os.Stdin.Fd())
	fdOut := int(os.Stdout.Fd())
	width, height, err := term.GetSize(fdOut)
	if err != nil {
		width, height = 80, 40
	}
	if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
		return fmt.Errorf("request for pty failed: %w", err)
	}
	// 获取管道
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	// 启动 Shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("start Shell failed: %w", err)
	}

	// 设置本地终端为 Raw 模式
	oldState, err := term.MakeRaw(fdIn)
	if err != nil {
		return fmt.Errorf("can not set term to Raw : %w", err)
	}
	defer func() { _ = term.Restore(fdIn, oldState) }()
	// ================= Windows 窗口大小自适应 =================
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
	go func() { _, _ = io.Copy(os.Stdout, stdout) }()
	go func() { _, _ = io.Copy(os.Stderr, stderr) }()

	// 启动协程处理用户输入
	cancelStdin, stdinDone := copyStdinTo(stdin)

	err = session.Wait()
	_ = term.Restore(fdIn, oldState)
	cancelStdin()
	<-stdinDone

	// 忽略 ExitError（交互式 shell 的正常退出，退出码可能继承自用户执行的最后一条命令）
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			return nil
		}
	}
	return err
}

// RunInteractive 在 PTY 环境下执行单条命令，支持交互式/流式命令 (如 tail -f, vim, top)
func (c *Client) RunInteractive(ctx context.Context, cmd string) error {
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

	// 使用交互式 Shell 获取完整的终端控制权 (支持基于 TTY 的程序如 top/vim 接收按键信号)
	// 使用 exec 替换当前交互式 Shell，并在完成后自动结束 SSH 会话
	wrappedCmd := fmt.Sprintf("exec bash -c '%s'\n", strings.ReplaceAll(cmd, "'", "'\\''"))
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

// RunInteractiveCmd 在 PTY 环境下直接执行命令（通过 SSH exec 通道，不启动交互式 shell），
// 不会产生登录信息或命令回显，适合在已有 shell 环境内调用 vim/top 等程序。
func (c *Client) RunInteractiveCmd(ctx context.Context, cmd string) error {
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

	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("start command failed: %w", err)
	}

	oldState, err := term.MakeRaw(fdIn)
	if err != nil {
		return fmt.Errorf("can not set term to Raw: %w", err)
	}
	defer func() { _ = term.Restore(fdIn, oldState) }()

	startWindowResizeLoop(session, fdOut, width, height)

	go func() { _, _ = io.Copy(os.Stdout, stdout) }()
	go func() { _, _ = io.Copy(os.Stderr, stderr) }()

	cancelStdin, stdinDone := copyStdinTo(stdin)

	err = ignoreShellExitError(session.Wait())
	_ = term.Restore(fdIn, oldState)
	cancelStdin()
	<-stdinDone

	return err
}

func (c *Client) maybeDetectSudoMode(ctx context.Context) {
	// 如果已经有确定的 SudoMode，且不是 "auto" 或空，则不再探测
	if c.node.SudoMode != "" && c.node.SudoMode != models.SudoModeAuto && c.node.SudoMode != models.SudoModeNone {
		return
	}

	// 1. 探测是否已经是 root
	// 使用 RunWithoutLogin 避免 MOTD 干扰输出
	if out, err := c.RunWithoutLogin(ctx, "id -u"); err == nil {
		// 稳健检查：只要最后一行输出是 0，即认为是 root
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "0" {
			c.updateSudoMode(models.SudoModeRoot)
			return
		}
	}

	// 2. 探测是否有免密 sudo 权限
	if _, err := c.RunWithoutLogin(ctx, "sudo -n true"); err == nil {
		c.updateSudoMode(models.SudoModeSudoer)
		return
	}

	// 3. 测试密码 sudo 是否真正可用（避免用户有密码但不在 sudoers 中时误判）
	if c.identity.Password != "" {
		if _, err := c.runWithSudo(ctx, "true", c.identity.Password, nil); err == nil {
			c.updateSudoMode(models.SudoModeSudo)
			return
		}
	}

	// 4. 检查是否有 su 密码
	if c.node.SuPwd != "" {
		c.updateSudoMode(models.SudoModeSu)
		return
	}

	// 默认兜底
	c.updateSudoMode(models.SudoModeNone)
}

func (c *Client) updateSudoMode(mode models.SudoMode) {
	c.node.SudoMode = mode
	if c.provider != nil && c.nodeName != "" {
		c.provider.AddNode(c.nodeName, c.node)
	}
}

func startWithTimeout(ctx context.Context, session *ssh.Session, command string) (string, error) {
	var b bytes.Buffer
	var mu sync.Mutex
	syncWriter := &synchronizedWriter{mu: &mu, b: &b}
	session.Stdout = syncWriter
	session.Stderr = syncWriter

	if err := session.Start(command); err != nil {
		return "", fmt.Errorf("failed to start command: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case err := <-done:
		output := syncWriter.String()
		if err != nil {
			return output, fmt.Errorf("failed to run command: %w, output: %s", err, output)
		}
		return output, nil
	case <-ctx.Done():
		if killErr := session.Signal(ssh.SIGKILL); killErr != nil {
			return syncWriter.String(), fmt.Errorf("failed to kill command after context done: %w", killErr)
		}
		return syncWriter.String(), ctx.Err()
	}
}

type synchronizedWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (w *synchronizedWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *synchronizedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}
