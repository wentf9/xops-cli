package sftpshell

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
)

// Shell 维护交互式 SFTP 会话的远端/本机工作目录状态与受控命令执行循环；零值恒未初始化并失败关闭。
//
//xops:opaque
//xops:failclosed
type Shell struct {
	eng              TransferClient
	preTarget        engine.ResolvedTarget
	resolvedTarget   engine.ResolvedTarget
	targetSpec       string
	cliOptions       option.OptionLayer
	stdin            io.Reader
	stdout           io.Writer
	stderr           io.Writer
	prompt           string
	initialRemoteDir algebraic.Option[pathalg.RemotePath]
	homeRemoteDir    pathalg.RemotePath
	remoteDir        pathalg.RemotePath
	localDir         pathalg.LocalDir
	localFS          LocalFS
	scopedLocalOnly  bool
	symlinkPolicy    pathalg.SymlinkPolicy
	interruptCh      <-chan struct{}
	commandTimeout   algebraic.Option[algebraic.Duration]
	streamBuffer     int
	showProgress     bool
	valid            bool
}

// NewShell 校验依赖配置并构造交互式 SFTP Shell 实例（零网络 I/O，真正初始化在 Run 中进行）。
func NewShell(cfg Config) (*Shell, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	localDir, ok := cfg.InitialLocalDir.Get()
	if !ok {
		var err error
		if localDir, err = pathalg.ParseLocalDir("."); err != nil {
			return nil, fmt.Errorf("%w: 初始化默认本地目录失败: %w", ErrInvalidConfig, err)
		}
	}
	stdin := cfg.Stdin
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	prompt := cfg.Prompt
	if prompt == "" {
		prompt = defaultPrompt
	}
	buf := cfg.StreamBuffer
	if buf <= 0 {
		buf = defaultStreamBuffer
	}
	return &Shell{
		eng:              cfg.Engine,
		preTarget:        cfg.Target,
		targetSpec:       strings.TrimSpace(cfg.TargetSpec),
		cliOptions:       cfg.CLIOptions,
		stdin:            stdin,
		stdout:           cfg.Stdout,
		stderr:           cfg.Stderr,
		prompt:           prompt,
		initialRemoteDir: cfg.InitialRemoteDir,
		localDir:         localDir,
		localFS:          cfg.LocalFS,
		scopedLocalOnly:  cfg.ScopedLocalOnly,
		symlinkPolicy:    cfg.SymlinkPolicy,
		interruptCh:      cfg.InterruptCh,
		commandTimeout:   cfg.CommandTimeout,
		streamBuffer:     buf,
		showProgress:     cfg.ShowProgress,
		valid:            true,
	}, nil
}

// RemoteDir 返回当前远端工作目录（未初始化时返回无效零值）。
func (s *Shell) RemoteDir() pathalg.RemotePath {
	if s == nil || !s.valid {
		return zeroVal[pathalg.RemotePath]()
	}
	return s.remoteDir
}

// LocalDir 返回当前本机工作目录（未初始化时返回无效零值）。
func (s *Shell) LocalDir() pathalg.LocalDir {
	if s == nil || !s.valid {
		return zeroVal[pathalg.LocalDir]()
	}
	return s.localDir
}

// Run 初始化远端目标与起始目录，随后进入交互命令循环；
// 单条命令取消后安全恢复至提示符，外层会话 ctx 取消或安全门控 Halted 时立即失败关闭退出。
func (s *Shell) Run(ctx context.Context) error {
	if s == nil || !s.valid {
		return ErrNotInitialized
	}
	if ctx == nil {
		return ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.initSession(ctx); err != nil {
		return err
	}
	return s.readEvalLoop(ctx)
}

func (s *Shell) initSession(ctx context.Context) error {
	if !s.preTarget.IsZero() {
		s.resolvedTarget = s.preTarget
	} else {
		res, err := s.eng.ResolveTarget(ctx, engine.ResolveTargetRequest{
			Target:     s.targetSpec,
			CLIOptions: s.cliOptions,
		})
		if err != nil {
			return err
		}
		s.resolvedTarget = res
	}
	startPath, hasInitial := s.initialRemoteDir.Get()
	if !hasInitial {
		var err error
		if startPath, err = pathalg.ParseRemotePath("."); err != nil {
			return err
		}
	}
	realPath, err := s.eng.RealPathRemote(ctx, engine.RemotePathOpRequest{
		RemoteCall: s.remoteCall(nil),
		Path:       startPath,
	})
	if err != nil {
		return err
	}
	s.homeRemoteDir = realPath
	s.remoteDir = realPath
	return nil
}

func (s *Shell) readEvalLoop(ctx context.Context) error {
	reader := bufio.NewReaderSize(s.stdin, 4096)
	for {
		line, eof, err := s.readPromptLine(ctx, reader)
		if err != nil {
			return err
		}
		if eof && strings.TrimSpace(line) == "" {
			return nil
		}
		quit, fatalErr := s.handleInputLine(ctx, line)
		if fatalErr != nil {
			return fatalErr
		}
		if quit || eof {
			return nil
		}
	}
}

func (s *Shell) readPromptLine(ctx context.Context, reader *bufio.Reader) (string, bool, error) {
	if err := ctx.Err(); err != nil {
		return "", false, err
	}
	_, _ = io.WriteString(s.stdout, s.prompt)
	line, eof, err := readBoundedLine(reader)
	if err == nil {
		return line, eof, nil
	}
	if ctx.Err() != nil {
		return "", false, ctx.Err()
	}
	return "", false, err
}

func readBoundedLine(r *bufio.Reader) (string, bool, error) {
	var b strings.Builder
	for {
		chunk, isPrefix, err := r.ReadLine()
		if len(chunk) > 0 {
			if b.Len()+len(chunk) > maxLineBytes {
				return "", false, fmt.Errorf("%w: 单行命令超过最大长度 %d 字节", ErrSyntax, maxLineBytes)
			}
			b.Write(chunk)
		}
		if errors.Is(err, io.EOF) {
			return b.String(), true, nil
		}
		if err != nil {
			return "", false, err
		}
		if !isPrefix {
			return b.String(), false, nil
		}
	}
}

func (s *Shell) handleInputLine(ctx context.Context, line string) (quit bool, fatalErr error) {
	tokens, err := ParseLine(line)
	if err != nil {
		s.writeCommandErr(err)
		return false, nil
	}
	if len(tokens) == 0 {
		return false, nil
	}
	cmd := strings.ToLower(tokens[0])
	if cmd == "exit" || cmd == "quit" || cmd == "bye" {
		return true, nil
	}
	cmdErr := s.executeCommandSupervised(ctx, cmd, tokens[1:])
	if cmdErr == nil {
		return false, nil
	}
	return false, s.handleCommandError(ctx, cmdErr)
}

// executeCommandSupervised 为单条交互命令建立独立可取消子上下文并经 core/conc.RunScoped 监督中断监听，
// 保证中断通道触发时仅取消当前在途命令并在返回提示符前 100% 排空监听协程。
func (s *Shell) executeCommandSupervised(sessionCtx context.Context, cmd string, args []string) error {
	cmdCtx, cancelCause := context.WithCancelCause(sessionCtx)
	defer cancelCause(nil)

	if timeout, ok := s.commandTimeout.Get(); ok {
		var cancelTimeout context.CancelFunc
		cmdCtx, cancelTimeout = context.WithTimeout(cmdCtx, timeout.Std())
		defer cancelTimeout()
	}

	err := conc.RunScoped(cmdCtx, func(runCtx context.Context, nursery *conc.Nursery) error {
		if s.interruptCh != nil {
			if gErr := nursery.Go(func(wCtx context.Context) error {
				select {
				case <-s.interruptCh:
					cancelCause(ErrCommandCanceled)
				case <-wCtx.Done():
				}
				return nil
			}); gErr != nil {
				return gErr
			}
		}
		return s.dispatchCommand(runCtx, cmd, args)
	})
	if errors.Is(context.Cause(cmdCtx), ErrCommandCanceled) && sessionCtx.Err() == nil {
		return ErrCommandCanceled
	}
	return err
}

func (s *Shell) dispatchCommand(ctx context.Context, cmd string, args []string) error {
	switch cmd {
	case "pwd":
		return s.cmdPWD(args)
	case "cd":
		return s.cmdCD(ctx, args)
	case "ls":
		return s.cmdLS(ctx, args)
	case "lpwd":
		return s.cmdLPWD(args)
	case "lcd":
		return s.cmdLCD(ctx, args)
	case "lls":
		return s.cmdLLS(ctx, args)
	case "put":
		return s.cmdPut(ctx, args)
	case "get":
		return s.cmdGet(ctx, args)
	case "cat":
		return s.cmdCat(ctx, args)
	case "write":
		return s.cmdWrite(ctx, args)
	case "mv", "rename":
		return s.cmdRename(ctx, args)
	case "mkdir":
		return s.cmdMkdir(ctx, args)
	case "rm":
		return s.cmdRemove(ctx, args)
	case "rmdir":
		return s.cmdRemoveDir(ctx, args)
	case "chmod":
		return s.cmdChmod(ctx, args)
	case "chtimes":
		return s.cmdChtimes(ctx, args)
	case "stat":
		return s.cmdStat(ctx, args, true)
	case "lstat":
		return s.cmdStat(ctx, args, false)
	case "realpath":
		return s.cmdRealPath(ctx, args)
	case "readlink":
		return s.cmdReadLink(ctx, args)
	case "help", "?":
		return s.cmdHelp(args)
	default:
		return fmt.Errorf("%w: 未知命令 %q（输入 'help' 查看支持命令）", ErrSyntax, cmd)
	}
}

func (s *Shell) handleCommandError(sessionCtx context.Context, err error) error {
	if sessionCtx.Err() != nil {
		return sessionCtx.Err()
	}
	if errors.Is(err, engine.ErrEngineHalted) || errors.Is(err, engine.ErrEngineClosed) {
		s.writeCommandErr(err)
		return err
	}
	s.writeCommandErr(err)
	return nil
}

func (s *Shell) writeCommandErr(err error) {
	_, _ = fmt.Fprintf(s.stderr, "sftp: %s\n", formatCommandError(err))
}

func formatCommandError(err error) string {
	switch {
	case errors.Is(err, ErrCommandCanceled):
		return "command canceled (returned to prompt)"
	case errors.Is(err, context.DeadlineExceeded):
		return "command timed out (returned to prompt)"
	case errors.Is(err, engine.ErrRemoteIsDir):
		return fmt.Sprintf("%v (hint: use 'rmdir' for empty directories)", err)
	case errors.Is(err, engine.ErrOutcomeUnknown):
		return fmt.Sprintf("CRITICAL OutcomeUnknown — DO NOT retry blindly: %v", err)
	case errors.Is(err, engine.ErrApprovalRequired):
		if ch, ok := engine.ExtractApprovalChallenge(err); ok {
			return fmt.Sprintf("approval required (%s, digest=%s)", ch.Reason(), ch.EnvelopeDigest().String())
		}
		return err.Error()
	default:
		return err.Error()
	}
}

func (s *Shell) remoteCall(stream *events.OperationStream) engine.RemoteCall {
	if s.resolvedTarget.IsValid() {
		return engine.RemoteCall{
			TargetInput: engine.TargetInput{Target: s.resolvedTarget},
			CallOptions: engine.CallOptions{OperationStream: stream},
		}
	}
	return engine.RemoteCall{
		TargetInput: engine.TargetInput{TargetSpec: s.targetSpec, CLIOptions: s.cliOptions},
		CallOptions: engine.CallOptions{OperationStream: stream},
	}
}
