package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Client struct {
	sshClient        *ssh.Client
	rootConn         net.Conn
	cfg              *ClientConfig
	store            ConfigStore
	connectorPattern string         // Connector 全局级密码提示正则，当节点级为空时回落到此字段
	promptRegex      *regexp.Regexp // 缓存预编译好的正则
	logger           logger.DebugLogger
}

// InteractiveIO supplies the terminal streams used by an interactive SSH
// operation. The caller owns these streams and their lifecycle.
type InteractiveIO struct {
	Stdin  *os.File
	Stdout io.Writer
	Stderr io.Writer
}

func defaultInteractiveIO() InteractiveIO {
	return InteractiveIO{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
}

func validateInteractiveIO(streams InteractiveIO) (int, int, error) {
	if streams.Stdin == nil {
		return 0, 0, fmt.Errorf("interactive stdin is nil")
	}
	if streams.Stdout == nil {
		return 0, 0, fmt.Errorf("interactive stdout is nil")
	}
	if streams.Stderr == nil {
		return 0, 0, fmt.Errorf("interactive stderr is nil")
	}
	fdIn := int(streams.Stdin.Fd())
	fdOut := fdIn
	if outputFile, ok := streams.Stdout.(*os.File); ok {
		fdOut = int(outputFile.Fd())
	}
	return fdIn, fdOut, nil
}

func newClient(raw *ssh.Client, rootConn net.Conn, cfg *ClientConfig, store ConfigStore, connectorPattern string) *Client {
	return newClientWithLogger(raw, rootConn, cfg, store, connectorPattern, logger.NopLogger)
}

func newClientWithLogger(raw *ssh.Client, rootConn net.Conn, cfg *ClientConfig, store ConfigStore, connectorPattern string, l logger.DebugLogger) *Client {
	if l == nil {
		l = logger.NopLogger
	}
	c := &Client{
		sshClient:        raw,
		rootConn:         rootConn,
		cfg:              cfg,
		store:            store,
		connectorPattern: connectorPattern,
		logger:           l,
	}

	pattern := cfg.PasswordPromptPattern
	if pattern == "" {
		pattern = connectorPattern
	}
	if pattern == "" {
		pattern = DefaultPasswordPromptPattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		c.getLogger().Debugf("ssh client: failed to compile password prompt regex %q: %v, falling back to default", pattern, err)
		re = regexp.MustCompile(DefaultPasswordPromptPattern)
	}
	c.promptRegex = re

	return c
}

func (c *Client) getLogger() logger.DebugLogger {
	if c != nil && c.logger != nil {
		return c.logger
	}
	return logger.NopLogger
}

// Interrupt closes the underlying transport forcefully and synchronously.
// It sets an immediate deadline on rootConn and closes the network connection,
// unblocking any concurrent I/O operations without spawning background goroutines.
func (c *Client) Interrupt() error {
	if c == nil {
		return nil
	}
	var errs []error
	if c.rootConn != nil {
		if deadliner, ok := c.rootConn.(interface{ SetDeadline(t time.Time) error }); ok {
			if err := deadliner.SetDeadline(time.Now()); err != nil {
				errs = append(errs, fmt.Errorf("set deadline failed: %w", err))
			}
		}
		if closeErr := c.rootConn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("close root conn failed: %w", closeErr))
		}
	} else if c.sshClient != nil {
		if closeErr := c.sshClient.Close(); closeErr != nil && !errors.Is(closeErr, io.EOF) && !errors.Is(closeErr, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("close ssh client failed: %w", closeErr))
		}
	}

	return errors.Join(errs...)
}

func (c *Client) Close() error {
	return c.sshClient.Close()
}

// SSHClient 暴露底层的 ssh.Client (供高级操作使用，如 SCP)

// Config 返回当前连接对应的节点配置
func (c *Client) Config() *ClientConfig {
	return c.cfg
}

type RunConfig struct {
	LoginShell   bool
	OutMode      OutputMode
	RingMaxBytes int
	StreamPrefix string
	StreamWriter io.Writer
	OutFile      *os.File
}

type RunOption func(*RunConfig)

func WithLoginShell(login bool) RunOption {
	return func(c *RunConfig) {
		c.LoginShell = login
	}
}

func WithOutputMode(mode OutputMode) RunOption {
	return func(c *RunConfig) {
		c.OutMode = mode
	}
}

func WithRingBuffer(maxBytes int) RunOption {
	return func(c *RunConfig) {
		c.OutMode = OutputModeRingBuffer
		c.RingMaxBytes = maxBytes
	}
}

func WithStream(writer io.Writer, prefix string) RunOption {
	return func(c *RunConfig) {
		c.OutMode = OutputModeStream
		c.StreamWriter = writer
		c.StreamPrefix = prefix
	}
}

func WithOutFile(file *os.File) RunOption {
	return func(c *RunConfig) {
		c.OutMode = OutputModeFile
		c.OutFile = file
	}
}

func DefaultRunConfig() *RunConfig {
	return &RunConfig{
		LoginShell: true,
	}
}

func (c *Client) Run(ctx context.Context, cmd string, opts ...RunOption) (string, error) {
	config := DefaultRunConfig()
	for _, opt := range opts {
		opt(config)
	}

	var wrappedCmd string
	if config.LoginShell {
		// 使用 bash -l -c 执行，以加载完整的环境变量 (如 PATH)
		wrappedCmd = fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(cmd, "'", "'\\''"))
	} else {
		wrappedCmd = fmt.Sprintf("bash -c '%s'", strings.ReplaceAll(cmd, "'", "'\\''"))
	}
	return c.runRaw(ctx, wrappedCmd, config)
}

// RunWithoutLogin 执行命令并在非登录 Shell 中运行，避免加载 profile 脚本产生干扰输出
func (c *Client) RunWithoutLogin(ctx context.Context, cmd string) (string, error) {
	wrappedCmd := fmt.Sprintf("bash -c '%s'", strings.ReplaceAll(cmd, "'", "'\\''"))
	return c.runRaw(ctx, wrappedCmd, DefaultRunConfig())
}

func (c *Client) runRaw(ctx context.Context, wrappedCmd string, config *RunConfig) (output string, retErr error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "ssh command session")

	return startWithTimeout(ctx, session, wrappedCmd, config)
}

// RunScript 执行 Shell 脚本内容
func (c *Client) RunScript(ctx context.Context, scriptContent string, opts ...RunOption) (output string, retErr error) {
	config := DefaultRunConfig()
	for _, opt := range opts {
		opt(config)
	}

	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "ssh script session")

	session.Stdin = strings.NewReader(scriptContent)

	cmd := "bash -s"
	if config.LoginShell {
		cmd = "bash -l -s"
	}
	return startWithTimeout(ctx, session, cmd, config)
}

// streamReader 包装 io.ReadCloser 以便在关闭时清理 SSH session
type streamReader struct {
	io.ReadCloser
	session *ssh.Session
	cancel  context.CancelFunc
}

func (s *streamReader) Read(p []byte) (int, error) {
	return s.ReadCloser.Read(p)
}

func (s *streamReader) Close() error {
	s.cancel()
	err := s.ReadCloser.Close()
	closeErr := s.session.Close()
	if errors.Is(closeErr, io.EOF) {
		closeErr = nil
	}
	return errors.Join(err, closeErr)
}

// RunStream 执行命令并返回流式输出
func (c *Client) RunStream(ctx context.Context, cmd string) (io.ReadCloser, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create new session: %w", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("failed to create stdout pipe: %w", err), session.Close())
	}

	wrappedCmd := fmt.Sprintf("bash -c '%s'", strings.ReplaceAll(cmd, "'", "'\\''"))

	if err := session.Start(wrappedCmd); err != nil {
		return nil, errors.Join(fmt.Errorf("failed to start command: %w", err), session.Close())
	}

	derivedCtx, cancel := context.WithCancel(ctx)

	// 监听 Context 自动关闭
	go func() {
		<-derivedCtx.Done()
		debugCloseResource(c.getLogger(), session, "canceled ssh stream session")
	}()

	return &streamReader{ReadCloser: io.NopCloser(stdout), session: session, cancel: cancel}, nil
}

func (c *Client) Shell(ctx context.Context) error {
	return c.ShellWithIO(ctx, defaultInteractiveIO())
}

// ShellWithIO starts an interactive remote shell using caller-provided streams.
func (c *Client) ShellWithIO(ctx context.Context, streams InteractiveIO) (retErr error) {
	fdIn, fdOut, err := validateInteractiveIO(streams)
	if err != nil {
		return err
	}
	session, err := c.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "interactive ssh shell session")
	// 配置 PTY (终端模式)
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	// 获取当前终端文件描述符
	width, height, err := term.GetSize(fdOut)
	if err != nil {
		width, height = 80, 40
	}
	if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
		return fmt.Errorf("request for pty failed: %w", err)
	}
	// 获取管道
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("create SSH stdin pipe failed: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create SSH stdout pipe failed: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("create SSH stderr pipe failed: %w", err)
	}

	// 启动 Shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	// 设置本地终端为 Raw 模式
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
	waitOutput := copySessionOutput(stdout, stderr, streams.Stdout, streams.Stderr)

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			if signalErr := session.Signal(ssh.SIGKILL); signalErr != nil {
				c.getLogger().Debugf("signal canceled interactive SSH shell failed: %v", signalErr)
			}
			debugCloseResource(c.getLogger(), session, "canceled interactive ssh shell session")
		case <-done:
		}
	}()

	// 启动协程处理用户输入
	cancelStdin, stdinDone, err := copyStdinTo(streams.Stdin, stdin)
	if err != nil {
		return err
	}

	err = session.Wait()
	cancelErr := cancelStdin()
	stdinErr := <-stdinDone

	// 忽略 ExitError（交互式 shell 的正常退出，退出码可能继承自用户执行的最后一条命令）
	if err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			err = nil
		}
	}
	return errors.Join(err, cancelErr, stdinErr, waitOutput())
}

// RunInteractive 在 PTY 环境下执行单条命令，支持交互式/流式命令 (如 tail -f, vim, top)
func (c *Client) RunInteractive(ctx context.Context, cmd string) (retErr error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "interactive ssh command session")

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
		return fmt.Errorf("create SSH stdin pipe failed: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create SSH stdout pipe failed: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("create SSH stderr pipe failed: %w", err)
	}

	if err := session.Shell(); err != nil {
		return fmt.Errorf("start shell failed: %w", err)
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

	// 使用交互式 Shell 获取完整的终端控制权 (支持基于 TTY 的程序如 top/vim 接收按键信号)
	// 使用 exec 替换当前交互式 Shell，并在完成后自动结束 SSH 会话
	wrappedCmd := fmt.Sprintf("exec bash -c '%s'\n", strings.ReplaceAll(cmd, "'", "'\\''"))
	if _, err := io.WriteString(stdin, wrappedCmd); err != nil {
		return fmt.Errorf("write interactive SSH command failed: %w", err)
	}

	waitOutput := copySessionOutput(stdout, stderr, os.Stdout, os.Stderr)

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			if signalErr := session.Signal(ssh.SIGKILL); signalErr != nil {
				c.getLogger().Debugf("signal canceled interactive SSH command failed: %v", signalErr)
			}
			debugCloseResource(c.getLogger(), session, "canceled interactive ssh command session")
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

	return errors.Join(err, cancelErr, stdinErr, waitOutput())
}

// RunInteractiveCmd 在 PTY 环境下直接执行命令（通过 SSH exec 通道，不启动交互式 shell），
// 不会产生登录信息或命令回显，适合在已有 shell 环境内调用 vim/top 等程序。
func (c *Client) RunInteractiveCmd(ctx context.Context, cmd string) error {
	return c.RunInteractiveCmdWithIO(ctx, cmd, defaultInteractiveIO())
}

// RunInteractiveCmdWithIO runs one PTY-backed command using caller-provided streams.
func (c *Client) RunInteractiveCmdWithIO(ctx context.Context, cmd string, streams InteractiveIO) (retErr error) {
	fdIn, fdOut, err := validateInteractiveIO(streams)
	if err != nil {
		return err
	}
	session, err := c.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "interactive ssh exec session")

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	width, height, err := term.GetSize(fdOut)
	if err != nil {
		width, height = 80, 40
	}
	if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
		return fmt.Errorf("request for pty failed: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("create SSH stdin pipe failed: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create SSH stdout pipe failed: %w", err)
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("create SSH stderr pipe failed: %w", err)
	}

	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("start command failed: %w", err)
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

	waitOutput := copySessionOutput(stdout, stderr, streams.Stdout, streams.Stderr)

	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			if signalErr := session.Signal(ssh.SIGKILL); signalErr != nil {
				c.getLogger().Debugf("signal canceled interactive SSH exec session failed: %v", signalErr)
			}
			debugCloseResource(c.getLogger(), session, "canceled interactive ssh exec session")
		case <-done:
		}
	}()

	cancelStdin, stdinDone, err := copyStdinTo(streams.Stdin, stdin)
	if err != nil {
		return err
	}

	err = ignoreShellExitError(session.Wait())
	cancelErr := cancelStdin()
	stdinErr := <-stdinDone

	return errors.Join(err, cancelErr, stdinErr, waitOutput())
}

func (c *Client) maybeDetectSudoMode(ctx context.Context) error {
	if c == nil || c.cfg == nil {
		return fmt.Errorf("ssh client or config is nil")
	}
	// 如果已经有确定的 SudoMode，且不是 "auto" 或空，则不再探测
	if c.cfg.SudoMode != "" && c.cfg.SudoMode != SudoModeAuto {
		return nil
	}
	if c.sshClient == nil {
		return fmt.Errorf("ssh client is not connected")
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	// 1. 探测是否已经是 root
	// 使用 RunWithoutLogin 避免 MOTD 干扰输出
	if out, err := c.RunWithoutLogin(ctx, "id -u"); err == nil {
		// 稳健检查：只要最后一行输出是 0，即认为是 root
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "0" {
			return c.updateSudoMode(ctx, SudoModeRoot)
		}
	} else if err := ctx.Err(); err != nil {
		return err
	}

	// 2. 探测是否有免密 sudo 权限
	if _, err := c.RunWithoutLogin(ctx, "sudo -n true"); err == nil {
		return c.updateSudoMode(ctx, SudoModeSudoer)
	} else if err := ctx.Err(); err != nil {
		return err
	}

	// 3. 测试密码 sudo 是否真正可用（避免用户有密码但不在 sudoers 中时误判）
	if c.cfg.Password != "" {
		if _, err := c.runWithSudo(ctx, "true", c.cfg.Password, nil, nil); err == nil {
			return c.updateSudoMode(ctx, SudoModeSudo)
		} else if err := ctx.Err(); err != nil {
			return err
		}
	}

	// 4. 检查是否有 su 密码
	if c.cfg.SuPwd != "" {
		return c.updateSudoMode(ctx, SudoModeSu)
	}

	// 默认兜底
	return c.updateSudoMode(ctx, SudoModeNone)
}

func (c *Client) updateSudoMode(ctx context.Context, mode SudoMode) error {
	c.cfg.SudoMode = mode
	if c.store != nil && c.cfg.NodeID != "" && c.cfg.SudoUpdateToken != "" {
		if err := c.store.UpdateSudo(ctx, c.cfg.NodeID, c.cfg.SudoUpdateToken, mode, c.cfg.SuPwd); err != nil {
			return fmt.Errorf("persist detected sudo mode for node %q failed: %w", c.cfg.NodeID, err)
		}
	}
	return nil
}

func startWithTimeout(ctx context.Context, session *ssh.Session, command string, config *RunConfig) (string, error) {
	if config == nil {
		config = DefaultRunConfig()
	}
	syncWriter := newOutputWriter(config)
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

// passwordPromptRegex 返回当前节点的密码提示正则
func (c *Client) passwordPromptRegex() *regexp.Regexp {
	return c.promptRegex
}

func (c *Client) SSHClient() *ssh.Client {
	return c.sshClient
}
