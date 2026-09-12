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
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Client struct {
	sshClient          *ssh.Client
	rootConn           net.Conn
	cfgMu              sync.RWMutex
	sudoMu             sync.Mutex
	connCfg            ConnectionConfig
	provider           ConnectionProvider
	resolver           SecretResolver
	prompter           SecretPrompter
	recorder           CredentialRecorder
	connectorPattern   string         // Connector 全局级密码提示正则，当节点级为空时回落到此字段
	promptRegex        *regexp.Regexp // 缓存预编译好的正则
	logger             logger.DebugLogger
	handshakeTimeout   time.Duration
	interactionTimeout time.Duration
}

type compatSecretResolver struct {
	password string
	suPwd    string
}

func (r *compatSecretResolver) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	switch req.Kind {
	case SecretKindLoginPassword, SecretKindSudoPassword:
		if r.password != "" {
			return []byte(r.password), nil
		}
	case SecretKindSuPassword:
		if r.suPwd != "" {
			return []byte(r.suPwd), nil
		}
	}
	return nil, ErrInteractionRequired
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

func newClient(raw *ssh.Client, rootConn net.Conn, cfg *ClientConfig, recorder CredentialRecorder, connectorPattern string) *Client {
	return newClientWithLogger(raw, rootConn, cfg, recorder, connectorPattern, logger.NopLogger)
}

func newClientWithLogger(raw *ssh.Client, rootConn net.Conn, cfg *ClientConfig, recorder CredentialRecorder, connectorPattern string, l logger.DebugLogger) *Client {
	return newClientWithComponents(raw, rootConn, cfg, nil, nil, nil, recorder, connectorPattern, 0, 0, l)
}

func newClientWithComponents(
	raw *ssh.Client,
	rootConn net.Conn,
	cfg *ClientConfig,
	provider ConnectionProvider,
	resolver SecretResolver,
	prompter SecretPrompter,
	recorder CredentialRecorder,
	connectorPattern string,
	handshakeTimeout time.Duration,
	interactionTimeout time.Duration,
	l logger.DebugLogger,
) *Client {
	if l == nil {
		l = logger.NopLogger
	}
	var connCfg ConnectionConfig
	if cfg != nil {
		connCfg = cfg.ToConnectionConfig()
	}
	if resolver == nil && cfg != nil && (cfg.Password != "" || cfg.SuPwd != "") {
		resolver = &compatSecretResolver{
			password: cfg.Password,
			suPwd:    cfg.SuPwd,
		}
	}

	c := &Client{
		sshClient:          raw,
		rootConn:           rootConn,
		connCfg:            connCfg,
		provider:           provider,
		resolver:           resolver,
		prompter:           prompter,
		recorder:           recorder,
		connectorPattern:   connectorPattern,
		logger:             l,
		handshakeTimeout:   handshakeTimeout,
		interactionTimeout: interactionTimeout,
	}

	pattern := connCfg.PasswordPromptPattern
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
	}
	if c.sshClient != nil {
		if closeErr := c.sshClient.Close(); closeErr != nil && !errors.Is(closeErr, io.EOF) && !errors.Is(closeErr, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("close ssh client failed: %w", closeErr))
		}
	}

	return errors.Join(errs...)
}

func (c *Client) Close() error {
	return c.sshClient.Close()
}

// Config returns a snapshot of the node configuration. Mutating the returned
// value never changes the live client configuration. The snapshot contains no
// plaintext secrets (Password, Passphrase, SuPwd are always empty).
func (c *Client) Config() *ClientConfig {
	cfg, ok := c.configSnapshot()
	if !ok {
		return nil
	}
	return &cfg
}

func (c *Client) configSnapshot() (ClientConfig, bool) {
	if c == nil {
		return ClientConfig{}, false
	}
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return ClientConfig{
		NodeID:                c.connCfg.NodeID,
		Address:               c.connCfg.Address,
		Port:                  c.connCfg.Port,
		User:                  c.connCfg.User,
		AuthType:              c.connCfg.AuthType,
		KeyPath:               c.connCfg.KeyPath,
		AuthUpdateToken:       c.connCfg.AuthUpdateToken,
		SudoMode:              c.connCfg.SudoMode,
		SudoUpdateToken:       c.connCfg.SudoUpdateToken,
		ProxyJump:             c.connCfg.ProxyJump,
		PasswordPromptPattern: c.connCfg.PasswordPromptPattern,
	}, true
}

// ConnectionConfig returns a copy of the live connection configuration.
func (c *Client) ConnectionConfig() ConnectionConfig {
	if c == nil {
		return ConnectionConfig{}
	}
	c.cfgMu.RLock()
	defer c.cfgMu.RUnlock()
	return c.connCfg
}

// AuthMaterial returns authentication material held by the client.
// Connected and pooled clients retain no AuthMaterial, always returning nil.
func (c *Client) AuthMaterial() *AuthMaterial {
	return nil
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

const sessionShutdownTimeout = time.Second

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
	session, err := c.newSessionContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "ssh command session")

	return c.startWithTimeout(ctx, session, wrappedCmd, config)
}

// RunScript 执行 Shell 脚本内容
func (c *Client) RunScript(ctx context.Context, scriptContent string, opts ...RunOption) (output string, retErr error) {
	config := DefaultRunConfig()
	for _, opt := range opts {
		opt(config)
	}

	session, err := c.newSessionContext(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create new session: %w", err)
	}
	defer joinResourceCloseError(&retErr, session, "ssh script session")

	session.Stdin = strings.NewReader(scriptContent)

	cmd := "bash -s"
	if config.LoginShell {
		cmd = "bash -l -s"
	}
	return c.startWithTimeout(ctx, session, cmd, config)
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
	session, err := c.newSessionContext(ctx)
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
	session, err := c.newSessionContext(ctx)
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
	stopResize := startWindowResizeLoop(derivedCtx, session, fdOut, width, height, c.getLogger(), c.Interrupt)
	defer func() { retErr = errors.Join(retErr, stopResize()) }()
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

// RunInteractive runs one command in a PTY using an SSH exec request.
// A non-interactive login bash loads the login environment without starting a
// prompt or writing the command through the terminal's echoed input stream.
func (c *Client) RunInteractive(ctx context.Context, cmd string) error {
	wrappedCmd := fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(cmd, "'", "'\\''"))
	return c.RunInteractiveCmd(ctx, wrappedCmd)
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
	session, err := c.newSessionContext(ctx)
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
	stopResize := startWindowResizeLoop(derivedCtx, session, fdOut, width, height, c.getLogger(), c.Interrupt)
	defer func() { retErr = errors.Join(retErr, stopResize()) }()

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

func withTimeoutOrDefault(ctx context.Context, timeout, defaultTimeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if ctx != nil {
		return context.WithTimeout(ctx, timeout)
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (c *Client) recordPrivilegeSecret(ctx context.Context, kind SecretKind, connCfg ConnectionConfig, pwd string) error {
	if c.recorder == nil {
		return nil
	}
	switch kind {
	case SecretKindLoginPassword:
		oldToken := connCfg.AuthUpdateToken
		if oldToken != "" {
			committedToken, recErr := c.recorder.UpdateAuth(ctx, connCfg.NodeID, oldToken, pwd, connCfg.KeyPath, "")
			if recErr != nil {
				return fmt.Errorf("record login password failed: %w", recErr)
			}
			if err := c.refreshConnectionTokens(tokenRefreshKindAuth, committedToken); err != nil {
				return err
			}
		}
	case SecretKindSuPassword, SecretKindSudoPassword:
		oldToken := connCfg.SudoUpdateToken
		if oldToken != "" {
			committedToken, recErr := c.recorder.UpdateSudo(ctx, connCfg.NodeID, oldToken, connCfg.SudoMode, pwd)
			if recErr != nil {
				return fmt.Errorf("record su password failed: %w", recErr)
			}
			if err := c.refreshConnectionTokens(tokenRefreshKindSudo, committedToken); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *Client) resolvePrivilegeMaterial(ctx context.Context, kind SecretKind, forcePrompt ...bool) (*PrivilegeMaterial, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	connCfg := c.ConnectionConfig()

	// [P1] 根据机密种类选择对应的版本令牌：登录密码校验 AuthUpdateToken，提权密码校验 SudoUpdateToken
	var versionToken string
	switch kind {
	case SecretKindLoginPassword, SecretKindPrivateKeyPassphrase:
		versionToken = connCfg.AuthUpdateToken
	case SecretKindSuPassword, SecretKindSudoPassword:
		versionToken = connCfg.SudoUpdateToken
	}

	req := SecretRequest{
		Kind:         kind,
		NodeID:       connCfg.NodeID,
		User:         connCfg.User,
		Host:         connCfg.Address,
		Port:         connCfg.Port,
		KeyPath:      connCfg.KeyPath,
		VersionToken: versionToken,
	}

	// [P2] 施加有界解析超时，同时保留调用方 Context 的取消信号
	resolveCtx, cancelResolve := withTimeoutOrDefault(ctx, c.handshakeTimeout, defaultSSHHandshakeTimeout)
	defer cancelResolve()

	// 1. 优先尝试 SecretResolver 解析
	promptOnly := len(forcePrompt) > 0 && forcePrompt[0]
	if c.resolver != nil && !promptOnly {
		secretBytes, err := c.resolvePrivilegeCandidate(resolveCtx, req, connCfg.AuthUpdateToken)
		if len(secretBytes) > 0 {
			// [P2] 立即安排原始切片在函数退出时清零，覆盖成功、错误与交互回退等所有路径
			defer zeroBytes(secretBytes)
		}
		if err == nil && len(secretBytes) > 0 {
			matBytes := make([]byte, len(secretBytes))
			copy(matBytes, secretBytes)
			return &PrivilegeMaterial{Password: matBytes}, nil
		}
		if err != nil && !errors.Is(err, ErrInteractionRequired) && !reportCredentialFailure(ctx, c.prompter, "read", err) {
			// [P1] 后端故障直接终止并保留错误链
			return nil, fmt.Errorf("resolve privilege secret failed: %w", err)
		}
	}

	// 2. resolver 缺失或返回 ErrInteractionRequired 时，降级到 prompter 交互提示
	if c.prompter == nil {
		return nil, ErrInteractionRequired
	}

	// [P2] 施加有界交互超时，同时保留调用方 Context 的取消信号
	promptCtx, cancelPrompt := withTimeoutOrDefault(ctx, c.interactionTimeout, DefaultInteractionTimeout)
	defer cancelPrompt()

	pwd, err := c.prompter.PromptSecret(promptCtx, req)
	if err != nil {
		return nil, fmt.Errorf("prompt privilege secret failed: %w", err)
	}

	if kind == SecretKindSudoPassword {
		connCfg.SudoMode = SudoModeSudo
	}
	if kind == SecretKindSuPassword {
		connCfg.SudoMode = SudoModeSu
	}
	material := &PrivilegeMaterial{Password: []byte(pwd)}
	material.confirmedSave = func(work context.Context, value []byte) error {
		return c.recordPrivilegeSecret(work, kind, connCfg, string(value))
	}
	return material, nil
}

func (c *Client) maybeDetectSudoMode(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("sudo detection context is nil")
	}
	if c == nil {
		return fmt.Errorf("ssh client or config is nil")
	}
	c.sudoMu.Lock()
	defer c.sudoMu.Unlock()
	connCfg := c.ConnectionConfig()
	// 如果已经有确定的 SudoMode，且不是 "auto" 或空，则不再探测
	if connCfg.SudoMode != "" && connCfg.SudoMode != SudoModeAuto {
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

	// 3. 测试密码 sudo 是否真正可用（按命令解析登录密码，使用完毕立即清零）
	priv, err := c.resolvePrivilegeMaterial(ctx, SecretKindSudoPassword)
	if err == nil {
		defer priv.Zero()
		priv.deferSave = true
		if _, testErr := c.runWithSudo(ctx, "true", priv.Password, nil, nil, priv); testErr == nil {
			return c.confirmDetectedSudo(ctx, priv)
		} else if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
	} else {
		// [P1] 只有当明确需要交互时（未预置密码），探测才跳过；非取消类的后端故障必须终止并保留错误链
		if !errors.Is(err, ErrInteractionRequired) {
			return fmt.Errorf("resolve login password for sudo probe failed: %w", err)
		}
	}

	if credentialRecoveryPrompter(c.prompter) != nil {
		// Do not prompt for a su candidate merely to detect its presence and
		// discard it. The actual operation obtains and verifies it once. This
		// unverified mode choice stays local to the connection.
		c.cfgMu.Lock()
		c.connCfg.SudoMode = SudoModeSu
		c.cfgMu.Unlock()
		return nil
	}

	// 4. 检查是否有 su 密码（按命令解析 su 密码，使用完毕立即清零）
	privSu, errSu := c.resolvePrivilegeMaterial(ctx, SecretKindSuPassword)
	if errSu == nil {
		privSu.Zero()
		return c.updateSudoMode(ctx, SudoModeSu)
	} else {
		// [P1] 同样，只有当明确需要交互时才跳过；后端故障必须终止并保留错误链
		if !errors.Is(errSu, ErrInteractionRequired) {
			return fmt.Errorf("resolve su password for probe failed: %w", errSu)
		}
	}

	// 默认兜底
	return c.updateSudoMode(ctx, SudoModeNone)
}

func (c *Client) updateSudoMode(ctx context.Context, mode SudoMode) error {
	if c == nil {
		return fmt.Errorf("ssh client is nil")
	}
	c.cfgMu.Lock()
	c.connCfg.SudoMode = mode
	nodeID := c.connCfg.NodeID
	updateToken := c.connCfg.SudoUpdateToken
	c.cfgMu.Unlock()
	if c.recorder != nil && nodeID != "" && updateToken != "" {
		committedToken, err := c.recorder.UpdateSudo(ctx, nodeID, updateToken, mode, "")
		if err != nil {
			return fmt.Errorf("persist detected sudo mode for node %q failed: %w", nodeID, err)
		}
		// [P1] 成功持久化提权模式后，刷新连接快照中的最新版本令牌并校验兼容性
		if err := c.refreshConnectionTokens(tokenRefreshKindSudo, committedToken); err != nil {
			return err
		}
	}
	return nil
}

// refreshConnectionTokens 从底层 ConnectionProvider 刷新最新的版本令牌并校验目标与版本兼容性
func (c *Client) refreshConnectionTokens(kind tokenRefreshKind, committedToken string) error {
	if c == nil || c.provider == nil {
		return nil
	}
	c.cfgMu.RLock()
	curCfg := c.connCfg
	nodeID := curCfg.NodeID
	c.cfgMu.RUnlock()
	if nodeID == "" {
		return nil
	}

	newCfg, err := c.provider.GetConfig(nodeID)
	if err != nil {
		return fmt.Errorf("reload config for node %q failed: %w", nodeID, err)
	}
	if newCfg == nil {
		return fmt.Errorf("%w: config not found for node %q", ErrSnapshotMismatch, nodeID)
	}

	// [P1] 校验完整连接目标（Address, Port, User, KeyPath, ProxyJump）是否仍然与当前已建立的连接一致
	if err := validateTargetCompatibility(curCfg, newCfg); err != nil {
		return fmt.Errorf("incompatible target update for node %q: %w", nodeID, err)
	}

	// [P1] 校验刷新版本与本次写回的对应关系：必须严格等于本次事务实际提交的版本，拒绝采纳后续无关更新，且允许幂等未变
	switch kind {
	case tokenRefreshKindAuth:
		if committedToken != "" && newCfg.AuthUpdateToken != committedToken {
			return fmt.Errorf("%w: auth version mismatch after update for node %q (expected %q, got %q)",
				ErrSnapshotMismatch, nodeID, committedToken, newCfg.AuthUpdateToken)
		}
	case tokenRefreshKindSudo:
		if committedToken != "" && newCfg.SudoUpdateToken != committedToken {
			return fmt.Errorf("%w: sudo version mismatch after update for node %q (expected %q, got %q)",
				ErrSnapshotMismatch, nodeID, committedToken, newCfg.SudoUpdateToken)
		}
	}

	c.cfgMu.Lock()
	switch kind {
	case tokenRefreshKindAuth:
		c.connCfg.AuthUpdateToken = newCfg.AuthUpdateToken
	case tokenRefreshKindSudo:
		c.connCfg.SudoUpdateToken = newCfg.SudoUpdateToken
		// A no-save recorder returns the unchanged token. Do not overwrite
		// verified session-local discovery with the repository's old mode.
		if shouldRefreshSudoMode(curCfg, newCfg) {
			c.connCfg.SudoMode = newCfg.SudoMode
		}
	}
	if newCfg.HasOriginalProxyJump {
		c.connCfg.OriginalProxyJump = newCfg.OriginalProxyJump
		c.connCfg.HasOriginalProxyJump = true
	} else if newCfg.OriginalProxyJump != "" {
		c.connCfg.OriginalProxyJump = newCfg.OriginalProxyJump
	}
	c.cfgMu.Unlock()
	return nil
}

func (c *Client) startWithTimeout(ctx context.Context, session *ssh.Session, command string, config *RunConfig, stderrWrappers ...func(io.Writer) io.Writer) (string, error) {
	if config == nil {
		config = DefaultRunConfig()
	}
	syncWriter := newOutputWriter(config)
	session.Stdout = syncWriter
	session.Stderr = syncWriter
	for _, wrap := range stderrWrappers {
		session.Stderr = wrap(session.Stderr)
	}

	if err := session.Start(command); err != nil {
		return "", fmt.Errorf("failed to start command: %w", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case err := <-done:
		err = errors.Join(err, flushPrivilegePrompt(session.Stderr))
		output := syncWriter.String()
		if err != nil {
			return output, fmt.Errorf("failed to run command: %w, output: %s", err, output)
		}
		return output, nil
	case <-ctx.Done():
		closeErr := c.closeCanceledSession(ctx, session, done)
		flushErr := flushPrivilegePrompt(session.Stderr)
		return syncWriter.String(), errors.Join(closeErr, flushErr)
	}
}

// closeCanceledSession closes an individual SSH channel and joins its Wait
// goroutine. If a broken transport leaves channel shutdown blocked, closing the
// owned transport is the bounded fallback that guarantees both goroutines exit.
func (c *Client) closeCanceledSession(ctx context.Context, session *ssh.Session, waitDone <-chan error) error {
	shutdownDone := make(chan error, 1)
	go func() {
		closeErr := closeResource(session, "canceled SSH command session")
		waitErr := <-waitDone
		if waitErr != nil {
			waitErr = fmt.Errorf("wait for canceled SSH command failed: %w", waitErr)
		}
		shutdownDone <- errors.Join(closeErr, waitErr)
	}()

	timer := time.NewTimer(sessionShutdownTimeout)
	defer timer.Stop()
	select {
	case shutdownErr := <-shutdownDone:
		return errors.Join(ctx.Err(), shutdownErr)
	case <-timer.C:
		interruptErr := c.Interrupt()
		shutdownErr := <-shutdownDone
		return errors.Join(
			ctx.Err(),
			fmt.Errorf("ssh command session shutdown timed out after %s", sessionShutdownTimeout),
			interruptErr,
			shutdownErr,
		)
	}
}

// passwordPromptRegex 返回当前节点的密码提示正则
func (c *Client) passwordPromptRegex() *regexp.Regexp {
	return c.promptRegex
}

func (c *Client) SSHClient() *ssh.Client {
	return c.sshClient
}

// Keep verified session-local discovery when a recorder intentionally does not
// advance the credential version (for example, remember=never).
func shouldRefreshSudoMode(current ConnectionConfig, next *ClientConfig) bool {
	return next.SudoMode != "" && (next.SudoUpdateToken != current.SudoUpdateToken || current.SudoMode == "" || current.SudoMode == SudoModeAuto)
}
