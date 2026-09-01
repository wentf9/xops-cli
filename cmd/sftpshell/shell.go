package sftpshell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/chzyer/readline"
	pkgsftp "github.com/pkg/sftp"
	"github.com/schollz/progressbar/v3"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"golang.org/x/term"
)

// Shell 定义交互式 SFTP 环境
type Shell struct {
	clientMu        sync.RWMutex
	client          *sftp.Client
	clientUses      map[*sftp.Client]*clientUse
	clientChange    *clientChange
	closed          bool
	closeErr        error
	sshClient       *ssh.Client
	lifecycleMu     sync.Mutex
	state           shellState
	runCancel       context.CancelFunc
	runDone         chan struct{}
	closeDone       chan struct{}
	lifecycleErr    error
	cwd             string
	localCwd        string
	stdin           io.Reader
	lineMu          sync.Mutex
	line            *lineEditor
	displayMu       sync.Mutex
	displayErr      error
	historyFile     string // readline 历史记录文件
	stdout          io.Writer
	stderr          io.Writer
	askConfirmHook  func(prompt string) bool
	logger          logger.DebugLogger
	noOverwrite     bool
	transferConfig  sftp.TransferConfig
	newClientFn     clientFactory
	newLineEditorFn lineEditorFactory
}

// shellState is a terminal, single-use lifecycle. A Shell can make exactly
// one transition from created to running, then to stopped or closed.
type shellState uint8

const (
	shellCreated shellState = iota
	shellRunning
	shellStopped
	shellClosed
)

// clientUse tracks an in-flight operation without holding clientMu across I/O.
// done is closed when the last lease is released.
type clientUse struct {
	count int
	done  chan struct{}
}

// clientChange serializes subsystem refresh and shutdown without holding a
// mutex while network I/O runs or active client leases drain.
type clientChange struct {
	done    chan struct{}
	err     error
	closing bool
}

// clientFactory 定义创建 SFTP 客户端的工厂函数类型（便于单元测试注入）
type clientFactory func(context.Context, *ssh.Client, ...sftp.Option) (*sftp.Client, error)

type lineEditorFactory func(context.Context, io.Reader, io.Writer, io.Writer, string, *Shell) (*lineEditor, error)

const shellNetworkOperationTimeout = 10 * time.Second

func (s *Shell) ensureClient(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("sftp shell context is nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("ensure SFTP client canceled: %w", err)
	}

	for {
		s.clientMu.Lock()
		if s.closed {
			s.clientMu.Unlock()
			return fmt.Errorf("sftp shell is closed")
		}
		if change := s.clientChange; change != nil {
			s.clientMu.Unlock()
			if err := waitClientChange(ctx, change); err != nil {
				return fmt.Errorf("wait for SFTP client refresh failed: %w", err)
			}
			if change.closing {
				continue
			}
			return change.err
		}

		change := &clientChange{done: make(chan struct{})}
		s.clientChange = change
		oldClient := s.client
		sshCli := s.sshClient
		createFn := s.newClientFn
		cfg := s.transferConfig
		s.clientMu.Unlock()

		err := s.refreshClient(ctx, oldClient, sshCli, createFn, cfg)
		s.clientMu.RLock()
		closed := s.closed
		s.clientMu.RUnlock()
		if err == nil && closed {
			err = fmt.Errorf("sftp shell is closed")
		}
		s.finishClientChange(change, err)
		return err
	}
}

func (s *Shell) refreshClient(
	ctx context.Context,
	oldClient *sftp.Client,
	sshCli *ssh.Client,
	createFn clientFactory,
	cfg sftp.TransferConfig,
) error {

	if oldClient != nil {
		// clientChange blocks new leases. Drain existing leases before probing,
		// because cancellation of Client.Do interrupts the whole subsystem.
		s.clientMu.RLock()
		var idle <-chan struct{}
		if use := s.clientUses[oldClient]; use != nil {
			idle = use.done
		}
		s.clientMu.RUnlock()
		if idle != nil {
			select {
			case <-idle:
			case <-ctx.Done():
				return fmt.Errorf("wait for active SFTP operations canceled: %w", ctx.Err())
			}
		}

		probeCtx, cancelProbe := context.WithTimeout(ctx, shellNetworkOperationTimeout)
		err := oldClient.Do(probeCtx, func(c *pkgsftp.Client) error {
			_, e := c.Getwd()
			return e
		})
		cancelProbe()
		if err == nil {
			return nil
		}

		cfg = oldClient.Config()
		s.clientMu.Lock()
		s.transferConfig = cfg
		if s.client == oldClient {
			s.client = nil
		}
		s.clientMu.Unlock()

		if closeErr := oldClient.Close(); closeErr != nil {
			return fmt.Errorf("close old SFTP client after failed health probe: %w", closeErr)
		}
	}

	if sshCli == nil {
		return fmt.Errorf("sftp shell SSH client is nil")
	}

	if createFn == nil {
		createFn = sftp.NewClient
	}

	newCli, err := createFn(ctx, sshCli,
		sftp.WithForce(cfg.Force),
		sftp.WithConcurrentFiles(cfg.ConcurrentFiles),
		sftp.WithThreadsPerFile(cfg.ThreadsPerFile),
		sftp.WithChunkSize(int(cfg.ChunkSize)),
		sftp.WithResume(cfg.EnableResume),
		sftp.WithResumeMinSize(cfg.ResumeMinSize),
	)
	if err != nil {
		return fmt.Errorf("reconnect sftp subsystem failed: %w", err)
	}
	if newCli == nil {
		return fmt.Errorf("reconnect sftp subsystem returned a nil client")
	}

	s.clientMu.Lock()
	if s.closed {
		s.clientMu.Unlock()
		if closeErr := newCli.Close(); closeErr != nil {
			return errors.Join(
				fmt.Errorf("sftp shell was closed while reconnecting"),
				fmt.Errorf("close reconnected SFTP client failed: %w", closeErr),
			)
		}
		return fmt.Errorf("sftp shell was closed while reconnecting")
	}
	s.client = newCli
	s.transferConfig = newCli.Config()
	s.clientMu.Unlock()
	return nil
}

func waitClientChange(ctx context.Context, change *clientChange) error {
	select {
	case <-change.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Shell) finishClientChange(change *clientChange, err error) {
	s.clientMu.Lock()
	change.err = err
	if s.clientChange == change {
		s.clientChange = nil
	}
	close(change.done)
	s.clientMu.Unlock()
}

// acquireClient returns a reference-counted client lease. State locks are
// held only while selecting a client and updating its lease count.
func (s *Shell) acquireClient(ctx context.Context) (*sftp.Client, func(), error) {
	if ctx == nil {
		return nil, nil, fmt.Errorf("acquire SFTP client context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("acquire SFTP client canceled: %w", err)
	}

	for {
		s.clientMu.Lock()
		if s.closed {
			s.clientMu.Unlock()
			return nil, nil, fmt.Errorf("sftp shell is closed")
		}
		if change := s.clientChange; change != nil {
			s.clientMu.Unlock()
			if err := waitClientChange(ctx, change); err != nil {
				return nil, nil, fmt.Errorf("wait to acquire SFTP client failed: %w", err)
			}
			if !change.closing && change.err != nil {
				return nil, nil, change.err
			}

			s.clientMu.Lock()
			if !s.closed && s.clientChange == nil && s.client != nil {
				cli, release := s.registerClientLeaseLocked()
				s.clientMu.Unlock()
				return cli, release, nil
			}
			s.clientMu.Unlock()
			continue
		}
		if s.client != nil {
			cli, release := s.registerClientLeaseLocked()
			s.clientMu.Unlock()
			return cli, release, nil
		}

		change := &clientChange{done: make(chan struct{})}
		s.clientChange = change
		oldClient := s.client
		sshCli := s.sshClient
		createFn := s.newClientFn
		cfg := s.transferConfig
		s.clientMu.Unlock()

		err := s.refreshClient(ctx, oldClient, sshCli, createFn, cfg)
		s.clientMu.Lock()
		var cli *sftp.Client
		var release func()
		if s.closed {
			err = fmt.Errorf("sftp shell is closed")
		} else if err == nil {
			cli, release = s.registerClientLeaseLocked()
			if cli == nil {
				err = fmt.Errorf("sftp client is not connected")
			}
		}
		change.err = err
		if s.clientChange == change {
			s.clientChange = nil
		}
		close(change.done)
		s.clientMu.Unlock()
		if err != nil {
			return nil, nil, err
		}
		return cli, release, nil
	}
}

func (s *Shell) registerClientLeaseLocked() (*sftp.Client, func()) {
	cli := s.client
	if cli == nil {
		return nil, nil
	}
	if s.clientUses == nil {
		s.clientUses = make(map[*sftp.Client]*clientUse)
	}
	use := s.clientUses[cli]
	if use == nil {
		use = &clientUse{done: make(chan struct{})}
		s.clientUses[cli] = use
	}
	use.count++

	release := sync.OnceFunc(func() {
		s.clientMu.Lock()
		defer s.clientMu.Unlock()
		active := s.clientUses[cli]
		if active == nil {
			return
		}
		active.count--
		if active.count == 0 {
			delete(s.clientUses, cli)
			close(active.done)
		}
	})
	return cli, release
}

// clientConfig 获取当前客户端配置（并发安全）
func (s *Shell) clientConfig() sftp.TransferConfig {
	s.clientMu.RLock()
	defer s.clientMu.RUnlock()
	if s.client != nil {
		return s.client.Config()
	}
	return s.transferConfig
}

// Close makes the shell terminal, cancels an active Run, and waits for it to
// stop before closing the prompt and SFTP subsystem. Concurrent callers wait
// for the first close operation and observe the same result.
func (s *Shell) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if ctx == nil {
		return fmt.Errorf("close SFTP shell context is nil")
	}
	owner, runDone, runCancel, closeDone := s.beginClose()
	if !owner {
		select {
		case <-closeDone:
			s.lifecycleMu.Lock()
			err := s.lifecycleErr
			s.lifecycleMu.Unlock()
			return err
		case <-ctx.Done():
			return fmt.Errorf("wait for concurrent SFTP shell close failed: %w", ctx.Err())
		}
	}

	var closeErr error
	defer func() {
		s.finishClose(closeErr)
	}()
	if runCancel != nil {
		runCancel()
	}
	if err := s.interruptLineEditor(); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("interrupt SFTP prompt during close failed: %w", err))
	}
	if runDone != nil {
		select {
		case <-runDone:
		case <-ctx.Done():
			closeErr = errors.Join(closeErr, fmt.Errorf("wait for SFTP shell run during close failed: %w", ctx.Err()))
		}
	}
	if err := s.closeLineEditor(); err != nil {
		closeErr = errors.Join(closeErr, fmt.Errorf("close SFTP line editor failed: %w", err))
	}
	if err := s.closeClientSubsystem(ctx); err != nil {
		closeErr = errors.Join(closeErr, err)
	}
	return closeErr
}

func (s *Shell) beginClose() (bool, <-chan struct{}, context.CancelFunc, <-chan struct{}) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.state == shellClosed {
		return false, nil, nil, s.closeDone
	}
	s.state = shellClosed
	s.closeDone = make(chan struct{})
	return true, s.runDone, s.runCancel, s.closeDone
}

func (s *Shell) finishClose(err error) {
	s.lifecycleMu.Lock()
	s.lifecycleErr = err
	close(s.closeDone)
	s.lifecycleMu.Unlock()
}

// closeClientSubsystem waits for active SFTP operations and closes the current
// subsystem. The Shell lifecycle has already been made terminal by Close.
func (s *Shell) closeClientSubsystem(ctx context.Context) error {
	for {
		s.clientMu.Lock()
		if s.closed {
			err := s.closeErr
			s.clientMu.Unlock()
			return err
		}
		if change := s.clientChange; change != nil {
			s.clientMu.Unlock()
			if err := waitClientChange(ctx, change); err != nil {
				return s.forceCloseClient(fmt.Errorf("wait for SFTP client transition during close failed: %w", err))
			}
			continue
		}

		change := &clientChange{done: make(chan struct{}), closing: true}
		s.clientChange = change
		cli := s.client
		var idle <-chan struct{}
		if use := s.clientUses[cli]; use != nil {
			idle = use.done
		}
		s.clientMu.Unlock()

		if idle != nil {
			select {
			case <-idle:
			case <-ctx.Done():
				err := s.forceCloseClient(fmt.Errorf("wait for active SFTP operations during close failed: %w", ctx.Err()))
				s.finishClientChange(change, err)
				return err
			}
		}

		s.clientMu.Lock()
		s.client = nil
		s.closed = true
		s.clientMu.Unlock()

		err := closeSFTPClient(cli)
		s.clientMu.Lock()
		s.closeErr = err
		s.clientMu.Unlock()
		s.finishClientChange(change, err)
		return err
	}
}

// forceCloseClient prevents a concurrent reconnect from publishing a new
// client after the client-close context has expired.
func (s *Shell) forceCloseClient(reason error) error {
	s.clientMu.Lock()
	if s.closed {
		err := s.closeErr
		s.clientMu.Unlock()
		return err
	}
	cli := s.client
	s.client = nil
	s.closed = true
	s.closeErr = reason
	s.clientMu.Unlock()

	err := errors.Join(reason, closeSFTPClient(cli))
	s.clientMu.Lock()
	s.closeErr = err
	s.clientMu.Unlock()
	return err
}

func closeSFTPClient(cli *sftp.Client) error {
	if cli == nil {
		return nil
	}
	if err := cli.Close(); err != nil {
		return fmt.Errorf("close SFTP shell client failed: %w", err)
	}
	return nil
}

func (s *Shell) getLogger() logger.DebugLogger {
	if s != nil && s.logger != nil {
		return s.logger
	}
	return logger.NopLogger
}

// Option configures the interactive SFTP presentation layer.
type Option func(*Shell)

// WithLogger injects the concurrent-safe debug logger used for secondary UI diagnostics.
func WithLogger(l logger.DebugLogger) Option {
	return func(s *Shell) {
		if l != nil {
			s.logger = l
		} else {
			s.logger = logger.NopLogger
		}
	}
}

// WithNoOverwrite makes transfer commands skip existing destinations without
// prompting. This policy belongs to the interactive presentation layer.
func WithNoOverwrite(noOverwrite bool) Option {
	return func(s *Shell) {
		s.noOverwrite = noOverwrite
	}
}

// New creates a new interactive SFTP presentation layer. The line editor is
// created lazily by Run immediately before its first prompt, so Close never
// has to tear down an editor that has not begun reading.
// stdin 为 *os.File 时会复制文件描述符，使断线取消能够只关闭 Shell 自己的输入副本，
// 不影响进程级标准输入或其他终端使用者；其他输入必须实现 io.ReadCloser，且其生命周期
// 由 Shell 接管，以确保取消能够唤醒阻塞读取。
func New(ctx context.Context, client *sftp.Client, sshClient *ssh.Client, stdin io.Reader, stdout, stderr io.Writer, opts ...Option) (*Shell, error) {
	if ctx == nil {
		return nil, fmt.Errorf("sftp shell context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("create SFTP shell canceled: %w", err)
	}
	if client == nil {
		return nil, fmt.Errorf("sftp shell client is nil")
	}
	if sshClient == nil {
		return nil, fmt.Errorf("sftp shell SSH client is nil")
	}
	if stdin == nil {
		return nil, fmt.Errorf("sftp shell stdin is nil")
	}
	if stdout == nil {
		return nil, fmt.Errorf("sftp shell stdout is nil")
	}
	if stderr == nil {
		return nil, fmt.Errorf("sftp shell stderr is nil")
	}
	shell := &Shell{
		client:         client,
		sshClient:      sshClient,
		stdin:          stdin,
		stdout:         stdout,
		stderr:         stderr,
		logger:         logger.NopLogger,
		transferConfig: client.Config(),
		state:          shellCreated,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(shell)
		}
	}
	setupCtx, cancelSetup := context.WithTimeout(ctx, shellNetworkOperationTimeout)
	defer cancelSetup()
	cwd, err := client.Cwd(setupCtx)
	if err != nil {
		if isContextError(err) {
			return nil, fmt.Errorf("resolve initial SFTP working directory failed: %w", err)
		}
		shell.getLogger().Debugf("resolve initial SFTP working directory failed: %v", err)
		cwd = "."
	}
	localCwd, err := os.Getwd()
	if err != nil {
		shell.getLogger().Debugf("resolve initial local working directory failed: %v", err)
		localCwd = "."
	}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		shell.getLogger().Debugf("resolve SFTP history directory failed: %v", err)
	}
	historyFile := ""
	if homeDir != "" {
		historyFile = filepath.Join(homeDir, ".xops_sftp_history")
	}
	shell.cwd = cwd
	shell.localCwd = localCwd
	shell.historyFile = historyFile
	return shell, nil
}

// Run 启动交互式循环 (REPL)
//
//nolint:gocyclo
func (s *Shell) Run(ctx context.Context) (runErr error) {
	if ctx == nil {
		return fmt.Errorf("run SFTP shell context is nil")
	}
	runCtx, err := s.beginRun(ctx)
	if err != nil {
		return err
	}
	defer s.endRun()
	defer func() {
		if closeErr := s.closeLineEditor(); closeErr != nil {
			runErr = combineShellErrors(runErr, fmt.Errorf("close SFTP line editor failed: %w", closeErr))
		}
	}()

	for {
		if err := runCtx.Err(); err != nil {
			return err
		}
		prompt := fmt.Sprintf("sftp:%s> ", s.cwd)
		input, err := s.prompt(runCtx, prompt)
		if err != nil {
			if runCtx.Err() != nil {
				return runCtx.Err()
			}
			if errors.Is(err, readline.ErrInterrupt) {
				// Ctrl+C 拦截：若连接已断开则直接退出，否则继续等待输入
				continue
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read SFTP prompt failed: %w", err)
		}

		// 连接已断开（keepalive 失败或服务端关闭）时不再执行命令，直接退出，
		// 避免 dispatchCommand 触发必然失败的远程操作并刷出误导性错误
		if runCtx.Err() != nil {
			return runCtx.Err()
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		if err := s.appendHistory(input); err != nil {
			s.getLogger().Debugf("save SFTP shell history failed: %v", err)
		}

		// ! 前缀：本地执行快捷方式（如 `!ls` 或 `! ls -la`）
		if strings.HasPrefix(input, "!") {
			localCmd := strings.TrimSpace(input[1:])
			if localCmd != "" {
				s.handleLexec(runCtx, localCmd)
			}
			if displayErr := s.takeDisplayError(); displayErr != nil {
				return displayErr
			}
			continue
		}

		args := strings.Fields(input)
		cmd := args[0]
		params := args[1:]

		// Pure-local and lifecycle commands do not need the remote SFTP client;
		// skip the health-check probe to avoid blocking exit/local ops on a
		// broken network. For remote-bound commands, a failed reconnect skips
		// execution to avoid misleading errors from a broken client.
		if requiresRemote(cmd) {
			if err := s.ensureClient(runCtx); err != nil {
				s.fprintfStderr("restore sftp client failed: %v\n", err)
				continue
			}
		}

		exit, err := s.dispatchCommand(runCtx, cmd, params)
		if err != nil {
			return err
		}
		if exit {
			return nil
		}

		if runCtx.Err() != nil {
			return runCtx.Err()
		}
	}
}

func (s *Shell) beginRun(ctx context.Context) (context.Context, error) {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	switch s.state {
	case shellCreated:
		runCtx, cancel := context.WithCancel(ctx)
		s.state = shellRunning
		s.runCancel = cancel
		s.runDone = make(chan struct{})
		return runCtx, nil
	case shellRunning:
		return nil, fmt.Errorf("sftp shell is already running")
	case shellStopped:
		return nil, fmt.Errorf("sftp shell can only run once")
	case shellClosed:
		return nil, fmt.Errorf("sftp shell is closed")
	default:
		return nil, fmt.Errorf("sftp shell has an invalid lifecycle state")
	}
}

func (s *Shell) endRun() {
	s.lifecycleMu.Lock()
	if s.state == shellRunning {
		s.state = shellStopped
	}
	s.runCancel = nil
	close(s.runDone)
	s.lifecycleMu.Unlock()
}

func combineShellErrors(primary, secondary error) error {
	if primary == nil {
		return secondary
	}
	return fmt.Errorf("%w; %w", primary, secondary)
}

func (s *Shell) dispatchCommand(ctx context.Context, cmd string, params []string) (bool, error) {
	switch cmd {
	case "exit", "quit", "bye":
		return true, nil
	case "help", "?":
		s.printHelp()
	case "pwd", "lpwd":
		s.handlePwd(cmd)
	case "ls", "ll", "lls", "lll":
		s.handleLsGroup(ctx, cmd, params)
	case "cd", "lcd":
		s.handleCdGroup(ctx, cmd, params)
	case "mkdir", "lmkdir":
		s.handleMkdirGroup(ctx, cmd, params)
	case "rm", "lrm":
		s.handleRmGroup(ctx, cmd, params)
	default:
		s.dispatchTransferCmd(ctx, cmd, params)
	}
	return false, s.takeDisplayError()
}

func (s *Shell) recordDisplayError(err error) {
	if err == nil {
		return
	}
	s.displayMu.Lock()
	s.displayErr = errors.Join(s.displayErr, err)
	s.displayMu.Unlock()
}

func (s *Shell) takeDisplayError() error {
	s.displayMu.Lock()
	defer s.displayMu.Unlock()
	err := s.displayErr
	s.displayErr = nil
	return err
}

func (s *Shell) fprintfStdout(format string, args ...any) {
	if _, err := fmt.Fprintf(s.stdout, format, args...); err != nil {
		s.recordDisplayError(fmt.Errorf("write SFTP shell output failed: %w", err))
	}
}

func (s *Shell) fprintStdout(args ...any) {
	if _, err := fmt.Fprint(s.stdout, args...); err != nil {
		s.recordDisplayError(fmt.Errorf("write SFTP shell output failed: %w", err))
	}
}

func (s *Shell) fprintlnStdout(args ...any) {
	if _, err := fmt.Fprintln(s.stdout, args...); err != nil {
		s.recordDisplayError(fmt.Errorf("write SFTP shell output failed: %w", err))
	}
}

func (s *Shell) fprintfStderr(format string, args ...any) {
	if _, err := fmt.Fprintf(s.stderr, format, args...); err != nil {
		s.recordDisplayError(fmt.Errorf("write SFTP shell diagnostic failed: %w", err))
	}
}

func (s *Shell) fprintlnStderr(args ...any) {
	if _, err := fmt.Fprintln(s.stderr, args...); err != nil {
		s.recordDisplayError(fmt.Errorf("write SFTP shell diagnostic failed: %w", err))
	}
}

// isPureLocalCmd reports whether cmd operates only on the local filesystem or
// terminates the shell. These commands must never be gated behind a remote
// health-check so that users can still exit or work locally even when the
// network is broken.
func isPureLocalCmd(cmd string) bool {
	switch cmd {
	case "exit", "quit", "bye",
		"help", "?",
		"pwd", "lpwd",
		"lls", "lll",
		"lcd",
		"lmkdir",
		"lrm",
		"lcp",
		"lmv",
		"lshell",
		"lexec":
		return true
	}
	return false
}

// requiresRemote reports whether cmd needs a healthy remote SFTP client. Pure
// local commands and exit/help do not require one.
func requiresRemote(cmd string) bool {
	return !isPureLocalCmd(cmd)
}

func (s *Shell) dispatchTransferCmd(ctx context.Context, cmd string, params []string) {
	switch cmd {
	case "cp", "lcp":
		s.handleCpGroup(ctx, cmd, params)
	case "mv", "lmv":
		s.handleMvGroup(ctx, cmd, params)
	case "shell":
		s.handleShell(ctx)
	case "lshell":
		s.handleLshell(ctx)
	case "exec":
		s.handleExec(ctx, params)
	case "lexec":
		s.handleLexec(ctx, strings.Join(params, " "))
	case "get":
		s.handleGet(ctx, params)
	case "put":
		s.handlePut(ctx, params)
	default:
		s.fprintfStderr("%s\n", i18n.Tf("sftp_shell_unknown_cmd", map[string]any{"Cmd": cmd}))
	}
}

func (s *Shell) handlePwd(cmd string) {
	if cmd == "pwd" {
		s.fprintlnStdout(s.cwd)
	} else {
		s.fprintlnStdout(s.localCwd)
	}
}

func (s *Shell) handleLsGroup(ctx context.Context, cmd string, params []string) {
	switch cmd {
	case "ls":
		s.handleLs(ctx, params, false)
	case "ll":
		s.handleLs(ctx, params, true)
	case "lls":
		s.handleLocalLs(params, false)
	case "lll":
		s.handleLocalLs(params, true)
	}
}

func (s *Shell) handleCdGroup(ctx context.Context, cmd string, params []string) {
	if cmd == "cd" {
		s.handleCd(ctx, params)
	} else {
		s.handleLocalCd(params)
	}
}

func (s *Shell) handleMkdirGroup(ctx context.Context, cmd string, params []string) {
	if cmd == "mkdir" {
		s.handleMkdir(ctx, params)
	} else {
		s.handleLocalMkdir(params)
	}
}

func (s *Shell) handleRmGroup(ctx context.Context, cmd string, params []string) {
	if cmd == "rm" {
		s.handleRm(ctx, params)
	} else {
		s.handleLocalRm(ctx, params)
	}
}

func (s *Shell) handleCpGroup(ctx context.Context, cmd string, params []string) {
	if cmd == "cp" {
		s.handleCp(ctx, params)
	} else {
		s.handleLocalCp(ctx, params)
	}
}

func (s *Shell) handleMvGroup(ctx context.Context, cmd string, params []string) {
	if cmd == "mv" {
		s.handleMv(ctx, params)
	} else {
		s.handleLocalMv(ctx, params)
	}
}

// ================= 命令处理逻辑 =================

func (s *Shell) resolvePath(p string) string {
	// SFTP 协议强制使用 / 作为路径分隔符
	// 使用 strings.HasPrefix 判断绝对路径，而非 filepath.IsAbs
	// 因为 filepath.IsAbs 依赖本地操作系统规则（Windows 会认为 /home 是相对路径）
	if strings.HasPrefix(p, "/") {
		return p
	}
	s.clientMu.RLock()
	defer s.clientMu.RUnlock()
	if s.client != nil {
		return s.client.JoinPath(s.cwd, p)
	}
	return path.Join(s.cwd, p)
}

func (s *Shell) resolveLocalPath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(s.localCwd, p)
}

func (s *Shell) handleCd(ctx context.Context, args []string) {
	if len(args) == 0 {
		return
	}
	var target string
	if hasWildcard(args[0]) {
		matches, err := s.expandRemote(ctx, args[0])
		if err != nil {
			s.fprintfStderr("cd: %v\n", err)
			return
		}
		single, err := classifyGlobResult(args[0], matches, true)
		if err != nil {
			s.fprintfStderr("cd: %v\n", err)
			return
		}
		target = single[0]
	} else {
		target = s.resolvePath(args[0])
	}

	// 检查目录是否存在
	info, exists, err := s.remoteStat(ctx, target, true)
	if err != nil || !exists {
		s.fprintfStderr("cd: %v\n", err)
		return
	}
	if !info.IsDir() {
		s.fprintfStderr("%s\n", i18n.Tf("sftp_shell_cd_not_dir", map[string]any{"Path": args[0]}))
		return
	}
	s.cwd = target
}

func (s *Shell) handleLocalCd(args []string) {
	if len(args) == 0 {
		return
	}
	var target string
	if hasWildcard(args[0]) {
		matches, err := s.expandLocal(args[0])
		if err != nil {
			s.fprintfStderr("lcd: %v\n", err)
			return
		}
		single, err := classifyGlobResult(args[0], matches, true)
		if err != nil {
			s.fprintfStderr("lcd: %v\n", err)
			return
		}
		target = single[0]
	} else {
		target = s.resolveLocalPath(args[0])
	}
	if err := os.Chdir(target); err != nil {
		s.fprintfStderr("lcd: %v\n", err)
		return
	}
	// 更新本地当前目录
	localCwd, err := os.Getwd()
	if err != nil {
		s.fprintfStderr("lcd: resolve current directory failed: %v\n", err)
		return
	}
	s.localCwd = localCwd
}

func (s *Shell) handleLs(ctx context.Context, args []string, long bool) {
	if len(args) > 0 && hasWildcard(args[0]) {
		matches, err := s.expandRemote(ctx, args[0])
		if err != nil {
			s.fprintfStderr("ls: %v\n", err)
			return
		}
		multi := len(matches) > 1
		for _, m := range matches {
			if multi {
				s.fprintfStdout("\n%s:\n", m)
			}
			s.listRemoteOne(ctx, m, long)
		}
		return
	}
	path := s.cwd
	if len(args) > 0 {
		path = s.resolvePath(args[0])
	}
	s.listRemoteOne(ctx, path, long)
}

// listRemoteOne 列出单个远程路径的内容
// path 为文件时直接显示该文件信息，为目录时列出其内容（与 bash ls 行为一致）
func (s *Shell) listRemoteOne(ctx context.Context, path string, long bool) {
	info, exists, err := s.remoteStat(ctx, path, true)
	if err != nil || !exists {
		s.fprintfStderr("ls: %v\n", err)
		return
	}
	var files []os.FileInfo
	if info.IsDir() {
		cli, release, err := s.acquireClient(ctx)
		if err != nil {
			s.fprintfStderr("ls: %v\n", err)
			return
		}
		defer release()

		err = cli.Do(ctx, func(client *pkgsftp.Client) error {
			var readErr error
			files, readErr = client.ReadDir(path)
			return readErr
		})
		if err != nil {
			s.fprintfStderr("ls: %v\n", err)
			return
		}
	} else {
		// path 是文件，直接显示该文件自身
		files = []os.FileInfo{info}
	}

	if long {
		// 详细列表模式 (类似 ls -l)
		w := tabwriter.NewWriter(s.stdout, 0, 0, 1, ' ', 0)
		for _, f := range files {
			modTime := f.ModTime().Format("Jan 02 15:04")
			size := formatBytes(f.Size())
			name := f.Name()
			if f.IsDir() {
				name += "/"
			}
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Mode(), size, modTime, name); err != nil {
				s.recordDisplayError(fmt.Errorf("write remote listing failed: %w", err))
				break
			}
		}
		if err := w.Flush(); err != nil {
			s.recordDisplayError(fmt.Errorf("flush remote listing failed: %w", err))
		}
	} else {
		// 简单列表模式 (多列输出)
		names := make([]string, 0, len(files))
		for _, f := range files {
			name := f.Name()
			if f.IsDir() {
				name += "/"
			}
			names = append(names, name)
		}
		s.printColumns(names)
	}
}

func (s *Shell) handleLocalLs(args []string, long bool) {
	if len(args) > 0 && hasWildcard(args[0]) {
		matches, err := s.expandLocal(args[0])
		if err != nil {
			s.fprintfStderr("lls: %v\n", err)
			return
		}
		multi := len(matches) > 1
		for _, m := range matches {
			if multi {
				s.fprintfStdout("\n%s:\n", m)
			}
			s.listLocalOne(m, long)
		}
		return
	}
	path := s.localCwd
	if len(args) > 0 {
		path = s.resolveLocalPath(args[0])
	}
	s.listLocalOne(path, long)
}

// listLocalOne 列出单个本地路径的内容
// path 为文件时直接显示该文件信息，为目录时列出其内容（与 bash ls 行为一致）
func (s *Shell) listLocalOne(path string, long bool) {
	info, err := os.Stat(path)
	if err != nil {
		s.fprintfStderr("lls: %v\n", err)
		return
	}
	var infos []os.FileInfo
	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			s.fprintfStderr("lls: %v\n", err)
			return
		}
		infos, err = localDirectoryInfos(path, entries)
		if err != nil {
			s.fprintfStderr("lls: %v\n", err)
			return
		}
	} else {
		// path 是文件，直接显示该文件自身
		infos = []os.FileInfo{info}
	}

	if long {
		// 详细列表模式
		w := tabwriter.NewWriter(s.stdout, 0, 0, 1, ' ', 0)
		for _, fi := range infos {
			modTime := fi.ModTime().Format("Jan 02 15:04")
			size := formatBytes(fi.Size())
			name := fi.Name()
			if fi.IsDir() {
				name += string(filepath.Separator)
			}
			if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", fi.Mode(), size, modTime, name); err != nil {
				s.recordDisplayError(fmt.Errorf("write local listing failed: %w", err))
				break
			}
		}
		if err := w.Flush(); err != nil {
			s.recordDisplayError(fmt.Errorf("flush local listing failed: %w", err))
		}
	} else {
		// 简单列表模式 (多列输出)
		names := make([]string, 0, len(infos))
		for _, fi := range infos {
			name := fi.Name()
			if fi.IsDir() {
				name += string(filepath.Separator)
			}
			names = append(names, name)
		}
		s.printColumns(names)
	}
}

func localDirectoryInfos(directory string, entries []os.DirEntry) ([]os.FileInfo, error) {
	infos := make([]os.FileInfo, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect local directory entry %q failed: %w", filepath.Join(directory, entry.Name()), err)
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func (s *Shell) handleGet(ctx context.Context, args []string) {
	if len(args) < 1 {
		s.fprintlnStderr(i18n.T("sftp_shell_get_usage"))
		return
	}
	remotes, err := s.expandRemote(ctx, args[0])
	if err != nil {
		s.fprintfStderr("get: %v\n", err)
		return
	}

	// 多源时：本地 dst 必须是已存在的目录或省略
	if len(remotes) > 1 {
		var localDir string
		if len(args) > 1 {
			localDir = s.resolveLocalPath(args[1])
			info, exists, statErr := inspectPath(os.Stat, localDir)
			if statErr != nil {
				s.fprintfStderr("get: %v\n", statErr)
				return
			}
			if !exists || !info.IsDir() {
				s.fprintlnStderr(i18n.T("sftp_shell_dest_must_be_dir"))
				return
			}
		} else {
			localDir = s.localCwd
		}
		for _, remote := range remotes {
			localTarget := filepath.Join(localDir, filepath.Base(remote))
			s.getSingle(ctx, remote, localTarget)
		}
		return
	}

	// 单源：保持原行为
	remote := remotes[0]
	local := filepath.Base(remote)
	if len(args) > 1 {
		local = s.resolveLocalPath(args[1])
	}
	s.getSingle(ctx, remote, local)
}

// getSingle 下载单个远程文件/目录到本地，含覆盖确认与进度条
func (s *Shell) getSingle(ctx context.Context, remote, local string) {
	cli, release, err := s.acquireClient(ctx)
	if err != nil {
		s.fprintfStderr("get: %v\n", err)
		return
	}
	defer release()

	clientToUse := cli
	info, exists, statErr := s.remoteStat(ctx, remote, true)
	if statErr != nil {
		s.fprintfStderr("get: %v\n", statErr)
		return
	}
	if !exists {
		s.fprintfStderr("get: remote source %q does not exist\n", remote)
		return
	}

	// 检查目标文件是否已存在
	localDest, destinationExists, statErr := resolveLocalDownloadDestination(local, remote)
	if statErr != nil {
		s.fprintfStderr("get: %v\n", statErr)
		return
	}
	if destinationExists {
		if s.noOverwrite {
			return
		}
		if !cli.Config().Force {
			confirmed, confirmErr := s.askConfirmation(ctx, i18n.Tf("prompt_overwrite", map[string]any{"Path": localDest}))
			if confirmErr != nil {
				s.recordDisplayError(confirmErr)
				return
			}
			if !confirmed {
				return
			}
			clientToUse = cli.WithForce(true)
		}
	}

	s.fprintlnStdout(i18n.Tf("sftp_shell_downloading", map[string]any{"Remote": remote, "Local": localDest}))

	// 计算远程文件/目录总大小以显示准确的进度条
	var totalSize int64
	description := "Downloading"
	if info.IsDir() {
		description = "Downloading (Dir)"
		walkErr := cli.Do(ctx, func(client *pkgsftp.Client) error {
			walker := client.Walk(remote)
			for walker.Step() {
				if err := walker.Err(); err != nil {
					return err
				}
				if fi := walker.Stat(); !fi.IsDir() {
					totalSize += fi.Size()
				}
			}
			return walker.Err()
		})
		if walkErr != nil {
			s.fprintfStderr("get: walk remote source failed: %v\n", walkErr)
			return
		}
	} else {
		totalSize = info.Size()
	}

	bar := progressbar.NewOptions64(
		totalSize,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(s.stdout),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionOnCompletion(func() {
			s.fprintStdout("\n")
		}),
	)
	callback := func(n int64) {
		if err := bar.Add64(n); err != nil {
			s.recordDisplayError(fmt.Errorf("update download progress failed: %w", err))
		}
	}

	var dlErr error
	if info.IsDir() {
		dlErr = clientToUse.DownloadDirectory(ctx, remote, localDest, callback)
	} else {
		dlErr = clientToUse.DownloadFile(ctx, remote, localDest, info.Size(), info.Mode(), callback)
	}
	if finishErr := bar.Finish(); finishErr != nil {
		s.recordDisplayError(fmt.Errorf("finish download progress failed: %w", finishErr))
	}
	if dlErr != nil {
		s.fprintfStderr("%s\n", i18n.Tf("sftp_shell_download_failed", map[string]any{"Error": dlErr}))
	} else {
		s.fprintlnStdout(i18n.T("sftp_shell_download_done"))
	}
}

func resolveLocalDownloadDestination(localPath, remotePath string) (string, bool, error) {
	localInfo, localExists, err := inspectPath(os.Stat, localPath)
	if err != nil {
		return "", false, err
	}
	localDestination := localPath
	if localExists && localInfo.IsDir() {
		localDestination = filepath.Join(localPath, filepath.Base(remotePath))
	}
	_, destinationExists, err := inspectPath(os.Lstat, localDestination)
	if err != nil {
		return "", false, err
	}
	return localDestination, destinationExists, nil
}

func (s *Shell) handlePut(ctx context.Context, args []string) {
	if len(args) < 1 {
		s.fprintlnStderr(i18n.T("sftp_shell_put_usage"))
		return
	}
	locals, err := s.expandLocal(args[0])
	if err != nil {
		s.fprintfStderr("put: %v\n", err)
		return
	}

	// 检查本地文件/目录是否存在（expandLocal 已展开，但单源无通配符时短路返回原路径，
	// 此处保留 os.Stat 检查以维持原错误信息）
	if _, err := os.Stat(locals[0]); err != nil {
		errMsg := i18n.Tf("sftp_shell_upload_failed", map[string]any{"Error": err})
		s.fprintfStderr("%s\n", strings.TrimPrefix(errMsg, "\n"))
		return
	}

	// 多源时：远程 dst 必须是已存在的目录或省略
	if len(locals) > 1 {
		var remoteDir string
		if len(args) > 1 {
			remoteDir = s.resolvePath(args[1])
			info, exists, statErr := s.remoteStat(ctx, remoteDir, true)
			if statErr != nil {
				s.fprintfStderr("put: %v\n", statErr)
				return
			}
			if !exists || !info.IsDir() {
				s.fprintlnStderr(i18n.T("sftp_shell_dest_must_be_dir"))
				return
			}
		} else {
			remoteDir = s.cwd
		}
		for _, local := range locals {
			remoteTarget := s.resolvePath(path.Join(remoteDir, filepath.Base(local)))
			s.putSingle(ctx, local, remoteTarget)
		}
		return
	}

	// 单源：保持原行为
	local := locals[0]
	var remote string
	if len(args) > 1 {
		remote = s.resolvePath(args[1])
	} else {
		remote = s.resolvePath(filepath.Base(local))
	}
	s.putSingle(ctx, local, remote)
}

// putSingle 上传单个本地文件/目录到远程，含覆盖确认与进度条
func (s *Shell) putSingle(ctx context.Context, local, remote string) {
	cli, release, err := s.acquireClient(ctx)
	if err != nil {
		s.fprintfStderr("put: %v\n", err)
		return
	}
	defer release()

	clientToUse := cli
	// 检查目标文件是否已存在
	remoteStat, remoteExists, statErr := s.remoteStat(ctx, remote, true)
	if statErr != nil {
		s.fprintfStderr("put: %v\n", statErr)
		return
	}
	if remoteExists && remoteStat.IsDir() {
		remote = cli.JoinPath(remote, filepath.Base(local))
	}
	_, destinationExists, statErr := s.remoteStat(ctx, remote, false)
	if statErr != nil {
		s.fprintfStderr("put: %v\n", statErr)
		return
	}
	if destinationExists {
		if s.noOverwrite {
			return
		}
		if !cli.Config().Force {
			confirmed, confirmErr := s.askConfirmation(ctx, i18n.Tf("prompt_overwrite", map[string]any{"Path": remote}))
			if confirmErr != nil {
				s.recordDisplayError(confirmErr)
				return
			}
			if !confirmed {
				return
			}
			clientToUse = cli.WithForce(true)
		}
	}

	s.fprintlnStdout(i18n.Tf("sftp_shell_uploading", map[string]any{"Local": local, "Remote": remote}))

	// 计算本地文件大小以显示准确的进度条
	var totalSize int64
	walkErr := filepath.Walk(local, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info != nil && !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	if walkErr != nil {
		s.fprintfStderr("%s\n", i18n.Tf("sftp_shell_upload_failed", map[string]any{"Error": walkErr}))
		return
	}

	bar := progressbar.NewOptions64(
		totalSize,
		progressbar.OptionSetDescription("Uploading"),
		progressbar.OptionSetWriter(s.stdout), // 关键：使用 readline 的 stdout
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionOnCompletion(func() {
			s.fprintStdout("\n")
		}),
	)
	callback := func(n int64) {
		if err := bar.Add64(n); err != nil {
			s.recordDisplayError(fmt.Errorf("update upload progress failed: %w", err))
		}
	}

	uploadErr := clientToUse.Upload(ctx, local, remote, callback)
	if finishErr := bar.Finish(); finishErr != nil {
		s.recordDisplayError(fmt.Errorf("finish upload progress failed: %w", finishErr))
	}
	if uploadErr != nil {
		s.fprintfStderr("%s\n", i18n.Tf("sftp_shell_upload_failed", map[string]any{"Error": uploadErr}))
	} else {
		s.fprintlnStdout(i18n.T("sftp_shell_upload_done"))
	}
}

func (s *Shell) handleMkdir(ctx context.Context, args []string) {
	if len(args) < 1 {
		s.fprintlnStderr(i18n.T("sftp_shell_mkdir_usage"))
		return
	}
	path := s.resolvePath(args[0])
	cli, release, err := s.acquireClient(ctx)
	if err != nil {
		s.fprintfStderr("mkdir: %v\n", err)
		return
	}
	defer release()

	if err := cli.Do(ctx, func(client *pkgsftp.Client) error {
		return client.Mkdir(path)
	}); err != nil {
		s.fprintfStderr("mkdir: %v\n", err)
	}
}

func (s *Shell) handleLocalMkdir(args []string) {
	if len(args) < 1 {
		s.fprintlnStderr(i18n.T("sftp_shell_lmkdir_usage"))
		return
	}
	path := s.resolveLocalPath(args[0])
	if err := os.Mkdir(path, 0755); err != nil {
		s.fprintfStderr("lmkdir: %v\n", err)
	}
}

func (s *Shell) handleRm(ctx context.Context, args []string) {
	args, localForce := parseForceFlag(args)
	force := s.clientConfig().Force || localForce

	if len(args) < 1 {
		s.fprintlnStderr(i18n.T("sftp_shell_rm_usage"))
		return
	}
	paths, err := s.expandRemote(ctx, args[0])
	if err != nil {
		s.fprintfStderr("rm: %v\n", err)
		return
	}
	for _, p := range paths {
		if !force {
			confirmed, confirmErr := s.askConfirmation(ctx, fmt.Sprintf("rm: remove remote '%s'?", p))
			if confirmErr != nil {
				s.recordDisplayError(confirmErr)
				return
			}
			if !confirmed {
				continue
			}
		}
		s.removeOne(ctx, p)
	}
}

// removeOne 删除单个远程路径
func (s *Shell) removeOne(ctx context.Context, p string) {
	cli, release, err := s.acquireClient(ctx)
	if err != nil {
		s.fprintfStderr("rm: %v\n", err)
		return
	}
	defer release()

	if err := cli.RemoveAll(ctx, p); err != nil {
		s.fprintfStderr("rm: %v\n", err)
	}
}

func (s *Shell) handleLocalRm(ctx context.Context, args []string) {
	args, localForce := parseForceFlag(args)
	force := s.clientConfig().Force || localForce

	if len(args) < 1 {
		s.fprintlnStderr(i18n.T("sftp_shell_lrm_usage"))
		return
	}
	paths, err := s.expandLocal(args[0])
	if err != nil {
		s.fprintfStderr("lrm: %v\n", err)
		return
	}
	for _, p := range paths {
		if !force {
			confirmed, confirmErr := s.askConfirmation(ctx, fmt.Sprintf("lrm: remove local '%s'?", p))
			if confirmErr != nil {
				s.recordDisplayError(confirmErr)
				return
			}
			if !confirmed {
				continue
			}
		}
		// 为了方便，lrm 直接支持递归删除
		if err := os.RemoveAll(p); err != nil {
			s.fprintfStderr("lrm: %v\n", err)
		}
	}
}

//nolint:gocyclo
func (s *Shell) handleCp(ctx context.Context, args []string) {
	args, localForce := parseForceFlag(args)
	force := s.clientConfig().Force || localForce

	if len(args) < 2 {
		s.fprintlnStderr(i18n.T("sftp_shell_cp_usage"))
		return
	}
	srcs, err := s.expandRemote(ctx, args[0])
	if err != nil {
		s.fprintfStderr("cp: %v\n", err)
		return
	}
	dst := s.resolvePath(args[1])

	// 提前计算目标地址并进行交互式确认
	dstIsDir, statErr := s.remotePathIsDirectory(ctx, dst)
	if statErr != nil {
		s.fprintfStderr("cp: %v\n", statErr)
		return
	}
	finalDsts, err := resolveMultiSrc(srcs, dst, dstIsDir)
	if err != nil {
		s.fprintfStderr("cp: %v\n", err)
		return
	}

	for i, src := range srcs {
		finalDst := finalDsts[i]
		if !force {
			skip, confirmErr := s.shouldSkipRemoteOverwrite(ctx, "cp", finalDst)
			if confirmErr != nil {
				s.recordDisplayError(confirmErr)
				return
			}
			if skip {
				continue
			}
		}

		if err := s.remoteCopySFTP(ctx, src, finalDst); err != nil {
			s.fprintfStderr("cp: %v\n", err)
		}
	}
}

func (s *Shell) remoteCopySFTP(ctx context.Context, src, dst string) error {
	cli, release, err := s.acquireClient(ctx)
	if err != nil {
		return err
	}
	defer release()
	return cli.RemoteCopy(ctx, src, dst)
}

func (s *Shell) handleMv(ctx context.Context, args []string) {
	args, localForce := parseForceFlag(args)
	force := s.clientConfig().Force || localForce

	if len(args) < 2 {
		s.fprintlnStderr(i18n.T("sftp_shell_mv_usage"))
		return
	}
	srcs, err := s.expandRemote(ctx, args[0])
	if err != nil {
		s.fprintfStderr("mv: %v\n", err)
		return
	}
	dst := s.resolvePath(args[1])

	dstIsDir, statErr := s.remotePathIsDirectory(ctx, dst)
	if statErr != nil {
		s.fprintfStderr("mv: %v\n", statErr)
		return
	}
	finalDsts, err := resolveMultiSrc(srcs, dst, dstIsDir)
	if err != nil {
		s.fprintfStderr("mv: %v\n", err)
		return
	}

	for i, src := range srcs {
		finalDst := finalDsts[i]
		if !force {
			skip, confirmErr := s.shouldSkipRemoteOverwrite(ctx, "mv", finalDst)
			if confirmErr != nil {
				s.recordDisplayError(confirmErr)
				return
			}
			if skip {
				continue
			}
		}

		cli, release, acquireErr := s.acquireClient(ctx)
		if acquireErr != nil {
			s.fprintfStderr("mv: %v\n", acquireErr)
			return
		}
		renameErr := cli.Rename(ctx, src, finalDst)
		release()
		if renameErr != nil {
			s.fprintfStderr("mv: %v\n", renameErr)
		}
	}
}

func (s *Shell) handleLocalCp(ctx context.Context, args []string) {
	args, localForce := parseForceFlag(args)
	force := s.clientConfig().Force || localForce

	if len(args) < 2 {
		s.fprintlnStderr(i18n.T("sftp_shell_lcp_usage"))
		return
	}
	srcs, err := s.expandLocal(args[0])
	if err != nil {
		s.fprintfStderr("lcp: %v\n", err)
		return
	}
	dst := s.resolveLocalPath(args[1])

	// 检查目标是否是目录
	dstInfo, dstExists, statErr := inspectPath(os.Stat, dst)
	if statErr != nil {
		s.fprintfStderr("lcp: %v\n", statErr)
		return
	}
	dstIsDir := dstExists && dstInfo.IsDir()
	finalDsts, err := resolveMultiSrcLocal(srcs, dst, dstIsDir)
	if err != nil {
		s.fprintfStderr("lcp: %v\n", err)
		return
	}
	for i, src := range srcs {
		finalDst := finalDsts[i]
		if !force {
			_, exists, statErr := inspectPath(os.Lstat, finalDst)
			if statErr != nil {
				s.fprintfStderr("lcp: %v\n", statErr)
				return
			}
			if exists {
				if s.noOverwrite {
					continue
				}
				confirmed, confirmErr := s.askConfirmation(ctx, fmt.Sprintf("lcp: overwrite local '%s'?", finalDst))
				if confirmErr != nil {
					s.recordDisplayError(confirmErr)
					return
				}
				if !confirmed {
					continue
				}
			}
		}
		if err := copyLocal(src, finalDst); err != nil {
			s.fprintfStderr("lcp: %v\n", err)
		}
	}
}

func copyLocal(src, dst string) error {
	srcInfo, err := os.Lstat(src)
	if err != nil {
		return fmt.Errorf("lstat local source %q failed: %w", src, err)
	}
	if srcInfo.Mode()&os.ModeSymlink != 0 {
		return copyLocalLink(src, dst)
	}
	if srcInfo.IsDir() {
		return copyLocalDir(src, dst)
	}
	return copyLocalFile(src, dst)
}

func copyLocalDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(dst, relPath)
		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode())
		}
		return copyLocal(path, targetPath)
	})
}

func copyLocalLink(src, dst string) error {
	target, err := os.Readlink(src)
	if err != nil {
		return fmt.Errorf("read local symbolic link %q failed: %w", src, err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("create local symbolic link parent failed: %w", err)
	}
	if _, err := os.Lstat(dst); err == nil {
		if err := os.Remove(dst); err != nil {
			return fmt.Errorf("remove local symbolic link destination %q failed: %w", dst, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("lstat local symbolic link destination %q failed: %w", dst, err)
	}
	if err := os.Symlink(target, dst); err != nil {
		return fmt.Errorf("create local symbolic link %q failed: %w", dst, err)
	}
	return nil
}

func copyLocalFile(src, dst string) (retErr error) {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open local source file %q failed: %w", src, err)
	}
	defer func() {
		if closeErr := srcFile.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close local source file %q failed: %w", src, closeErr))
		}
	}()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat local source file %q failed: %w", src, err)
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("open local destination file %q failed: %w", dst, err)
	}
	defer func() {
		if closeErr := dstFile.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close local destination file %q failed: %w", dst, closeErr))
		}
	}()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("copy local file %q to %q failed: %w", src, dst, err)
	}
	if err := os.Chmod(dst, srcInfo.Mode()); err != nil {
		return fmt.Errorf("set local destination mode failed: %w", err)
	}
	return nil
}

func (s *Shell) handleLocalMv(ctx context.Context, args []string) {
	args, localForce := parseForceFlag(args)
	force := s.clientConfig().Force || localForce

	if len(args) < 2 {
		s.fprintlnStderr(i18n.T("sftp_shell_lmv_usage"))
		return
	}
	srcs, err := s.expandLocal(args[0])
	if err != nil {
		s.fprintfStderr("lmv: %v\n", err)
		return
	}
	dst := s.resolveLocalPath(args[1])

	// 检查目标是否是目录
	dstInfo, dstExists, statErr := inspectPath(os.Stat, dst)
	if statErr != nil {
		s.fprintfStderr("lmv: %v\n", statErr)
		return
	}
	dstIsDir := dstExists && dstInfo.IsDir()
	finalDsts, err := resolveMultiSrcLocal(srcs, dst, dstIsDir)
	if err != nil {
		s.fprintfStderr("lmv: %v\n", err)
		return
	}
	for i, src := range srcs {
		finalDst := finalDsts[i]
		if !force {
			_, exists, statErr := inspectPath(os.Lstat, finalDst)
			if statErr != nil {
				s.fprintfStderr("lmv: %v\n", statErr)
				return
			}
			if exists {
				if s.noOverwrite {
					continue
				}
				confirmed, confirmErr := s.askConfirmation(ctx, fmt.Sprintf("lmv: overwrite local '%s'?", finalDst))
				if confirmErr != nil {
					s.recordDisplayError(confirmErr)
					return
				}
				if !confirmed {
					continue
				}
			}
		}
		if err := os.Rename(src, finalDst); err != nil {
			s.fprintfStderr("lmv: %v\n", err)
		}
	}
}

type pathStatFunc func(string) (os.FileInfo, error)

func (s *Shell) remotePathIsDirectory(ctx context.Context, target string) (bool, error) {
	info, exists, err := s.remoteStat(ctx, target, true)
	if err != nil {
		return false, err
	}
	return exists && info.IsDir(), nil
}

func (s *Shell) shouldSkipRemoteOverwrite(ctx context.Context, command, target string) (bool, error) {
	stat := func(path string) (os.FileInfo, error) {
		info, exists, err := s.remoteStat(ctx, path, false)
		if err == nil && !exists {
			return nil, os.ErrNotExist
		}
		return info, err
	}
	return shouldSkipPathOverwrite(ctx, command, target, stat, s.noOverwrite, s.askConfirmation)
}

func (s *Shell) remoteStat(ctx context.Context, target string, followFinalLink bool) (os.FileInfo, bool, error) {
	cli, release, err := s.acquireClient(ctx)
	if err != nil {
		return nil, false, err
	}
	defer release()

	var info os.FileInfo
	err = cli.Do(ctx, func(client *pkgsftp.Client) error {
		var statErr error
		if followFinalLink {
			info, statErr = client.Stat(target)
		} else {
			info, statErr = client.Lstat(target)
		}
		return statErr
	})
	if err == nil {
		return info, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("stat remote path %q failed: %w", target, err)
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func shouldSkipPathOverwrite(
	ctx context.Context,
	command string,
	target string,
	stat pathStatFunc,
	noOverwrite bool,
	confirm func(context.Context, string) (bool, error),
) (bool, error) {
	_, exists, err := inspectPath(stat, target)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	if noOverwrite {
		return true, nil
	}
	confirmed, err := confirm(ctx, fmt.Sprintf("%s: overwrite remote '%s'?", command, target))
	if err != nil {
		return false, err
	}
	return !confirmed, nil
}

func inspectPath(stat pathStatFunc, target string) (os.FileInfo, bool, error) {
	info, err := stat(target)
	if err == nil {
		return info, true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("stat path %q failed: %w", target, err)
}

func parseForceFlag(args []string) ([]string, bool) {
	force := false
	filtered := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "-f" {
			force = true
		} else {
			filtered = append(filtered, arg)
		}
	}
	return filtered, force
}

func (s *Shell) printHelp() {
	s.fprintlnStdout(i18n.T("sftp_shell_help"))
}

func (s *Shell) askConfirmation(ctx context.Context, prompt string) (bool, error) {
	if s.askConfirmHook != nil {
		return s.askConfirmHook(prompt), nil
	}
	if s.currentLineEditor() == nil {
		return false, fmt.Errorf("sftp line editor is not initialized")
	}
	s.fprintStdout("\n")
	input, err := s.promptExisting(ctx, fmt.Sprintf("%s [y/N]: ", prompt))
	if err != nil {
		return false, fmt.Errorf("read SFTP confirmation failed: %w", err)
	}
	response := strings.ToLower(strings.TrimSpace(input))
	return response == "y" || response == "yes", nil
}

// handleShell 进入远程交互式 shell（SSH PTY）
func (s *Shell) handleShell(ctx context.Context) {
	if err := s.closeLineEditor(); err != nil {
		s.recordDisplayError(fmt.Errorf("close SFTP line editor before remote shell failed: %w", err))
		return
	}
	streams, err := s.interactiveIO()
	if err != nil {
		s.recordDisplayError(err)
		return
	}
	if err := s.sshClient.ShellWithIO(ctx, streams); err != nil {
		s.fprintfStderr("shell: %v\n", err)
	}
	s.fprintlnStdout("")
}

// handleLshell 进入本地交互式 shell
func (s *Shell) handleLshell(ctx context.Context) {
	if err := s.closeLineEditor(); err != nil {
		s.recordDisplayError(fmt.Errorf("close SFTP line editor before local shell failed: %w", err))
		return
	}
	shellBin := os.Getenv("SHELL")
	if shellBin == "" {
		shellBin = "sh"
	}
	if runtime.GOOS == "windows" {
		shellBin = "powershell.exe"
	}
	c := exec.CommandContext(ctx, shellBin)
	c.Stdin = s.stdin
	c.Stdout = s.stdout
	c.Stderr = s.stderr
	c.Dir = s.localCwd
	if err := c.Run(); err != nil {
		s.fprintfStderr("lshell: %v\n", err)
	}
	s.fprintlnStdout("")
}

// handleExec 在远程主机上执行命令，分配 PTY 以支持 vim/top 等交互式程序
func (s *Shell) handleExec(ctx context.Context, args []string) {
	if len(args) == 0 {
		s.fprintlnStderr(i18n.T("sftp_shell_exec_usage"))
		return
	}
	escapedCwd := strings.ReplaceAll(s.cwd, "'", "'\\''")
	cmdStr := fmt.Sprintf("cd '%s' && %s", escapedCwd, strings.Join(args, " "))
	if err := s.closeLineEditor(); err != nil {
		s.recordDisplayError(fmt.Errorf("close SFTP line editor before remote command failed: %w", err))
		return
	}
	streams, err := s.interactiveIO()
	if err != nil {
		s.recordDisplayError(err)
		return
	}
	if err := s.sshClient.RunInteractiveCmdWithIO(ctx, cmdStr, streams); err != nil {
		s.fprintfStderr("exec: %v\n", err)
	}
	s.fprintlnStdout("")
}

// handleLexec 在本地执行命令，接管终端 I/O 以支持 vim 等交互式程序
func (s *Shell) handleLexec(ctx context.Context, cmdStr string) {
	if cmdStr == "" {
		s.fprintlnStderr(i18n.T("sftp_shell_lexec_usage"))
		return
	}
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-Command", cmdStr)
	} else {
		c = exec.CommandContext(ctx, "sh", "-c", cmdStr)
	}
	// 直接绑定终端，确保 vim/less 等交互式程序能正常读写
	c.Stdin = s.stdin
	c.Stdout = s.stdout
	c.Stderr = s.stderr
	c.Dir = s.localCwd

	// line editor 持有终端原始状态，运行前先将终端还原为普通模式，
	// 退出后重新接管，避免 vim 退出后终端状态混乱
	if err := s.closeLineEditor(); err != nil {
		s.recordDisplayError(fmt.Errorf("close SFTP line editor before local command failed: %w", err))
		return
	}
	err := c.Run()
	if err != nil {
		s.fprintfStderr("lexec: %v\n", err)
	}
}

func (s *Shell) interactiveIO() (ssh.InteractiveIO, error) {
	stdin, ok := s.stdin.(*os.File)
	if !ok {
		return ssh.InteractiveIO{}, fmt.Errorf("interactive SFTP shell stdin must be an *os.File")
	}
	return ssh.InteractiveIO{Stdin: stdin, Stdout: s.stdout, Stderr: s.stderr}, nil
}

func (s *Shell) currentLineEditor() *lineEditor {
	s.lineMu.Lock()
	defer s.lineMu.Unlock()
	return s.line
}

func (s *Shell) prompt(ctx context.Context, prompt string) (string, error) {
	if s.currentLineEditor() == nil {
		if err := s.resetLineEditor(ctx); err != nil {
			return "", err
		}
	}
	return s.promptExisting(ctx, prompt)
}

func (s *Shell) promptExisting(ctx context.Context, prompt string) (string, error) {
	editor := s.currentLineEditor()
	if editor == nil {
		return "", fmt.Errorf("sftp line editor is not initialized")
	}
	return editor.Prompt(ctx, prompt)
}

func (s *Shell) appendHistory(input string) error {
	editor := s.currentLineEditor()
	if editor == nil {
		return fmt.Errorf("sftp line editor is not initialized")
	}
	if err := editor.AppendHistory(input); err != nil {
		return fmt.Errorf("append SFTP shell history failed: %w", err)
	}
	return nil
}

func (s *Shell) interruptLineEditor() error {
	editor := s.currentLineEditor()
	if editor == nil {
		return nil
	}
	return editor.Interrupt()
}

func (s *Shell) closeLineEditor() error {
	s.lineMu.Lock()
	editor := s.line
	s.line = nil
	s.lineMu.Unlock()
	if editor == nil {
		return nil
	}
	return editor.Close()
}

func (s *Shell) resetLineEditor(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("reset SFTP line editor context is nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("reset SFTP line editor canceled: %w", err)
	}
	newEditor := s.newLineEditorFn
	if newEditor == nil {
		newEditor = newLineEditor
	}
	editor, err := newEditor(ctx, s.stdin, s.stdout, s.stderr, s.historyFile, s)
	if err != nil {
		return fmt.Errorf("initialize SFTP line editor failed: %w", err)
	}
	s.lifecycleMu.Lock()
	if s.state != shellRunning || ctx.Err() != nil {
		s.lifecycleMu.Unlock()
		if closeErr := editor.Close(); closeErr != nil {
			return errors.Join(
				fmt.Errorf("sftp shell is closed while initializing line editor"),
				fmt.Errorf("close unpublished SFTP line editor failed: %w", closeErr),
			)
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("reset SFTP line editor canceled: %w", err)
		}
		return fmt.Errorf("sftp shell is closed while initializing line editor")
	}
	s.lineMu.Lock()
	oldEditor := s.line
	s.line = editor
	s.lineMu.Unlock()
	s.lifecycleMu.Unlock()
	if oldEditor != nil {
		if err := oldEditor.Close(); err != nil {
			return fmt.Errorf("close replaced SFTP line editor failed: %w", err)
		}
	}
	return nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// printColumns 多列格式输出，类似 Linux ls 命令
func (s *Shell) printColumns(names []string) {
	if len(names) == 0 {
		return
	}

	// 获取终端宽度
	width := 80 // 默认宽度
	if fd := int(os.Stdout.Fd()); term.IsTerminal(fd) {
		if w, _, err := term.GetSize(fd); err == nil && w > 0 {
			width = w
		}
	}

	// 找出最长名称
	maxLen := 0
	for _, name := range names {
		if len(name) > maxLen {
			maxLen = len(name)
		}
	}

	// 每列宽度 = 最大名称 + 2 (间距)
	colWidth := maxLen + 2
	if colWidth < 4 {
		colWidth = 4
	}

	// 计算列数
	cols := width / colWidth
	if cols < 1 {
		cols = 1
	}

	// 计算行数
	rows := (len(names) + cols - 1) / cols

	// 按列优先顺序输出
	for row := range rows {
		for col := 0; col < cols; col++ {
			idx := col*rows + row
			if idx >= len(names) {
				break
			}
			name := names[idx]
			// 使用固定宽度格式化，左对齐
			s.fprintfStdout("%-*s", colWidth, name)
		}
		s.fprintlnStdout()
	}
}
