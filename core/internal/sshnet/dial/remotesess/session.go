package remotesess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/ports"
)

// Session 封装单条 *ssh.Session，实现 ports.RemoteSession；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type Session struct {
	lifeNursery *conc.Nursery
	isAlive     func() bool
	sshSess     *ssh.Session
	stdinPipe   io.WriteCloser
	stdoutPipe  io.Reader
	stderrPipe  io.Reader

	mu              sync.Mutex
	stdinPipeTaken  bool
	stdoutPipeTaken bool
	stderrPipeTaken bool
	starting        bool

	outMu         sync.Mutex
	discardOutput bool
	ioErrMu       sync.Mutex
	ioErr         error
	pumpsDone     chan struct{}
	stdinCancel   context.CancelFunc

	started   atomic.Bool
	truncated atomic.Bool
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	valid     bool
}

// New 预绑定 StdinPipe / StdoutPipe / StderrPipe 并构造受 lifeNursery 监督的 Session。
func New(lifeNursery *conc.Nursery, isAlive func() bool, sshSess *ssh.Session) (*Session, error) {
	if lifeNursery == nil || isAlive == nil || sshSess == nil {
		if sshSess != nil {
			_ = sshSess.Close()
		}
		return nil, ports.ErrClosed
	}
	inPipe, err := sshSess.StdinPipe()
	if err != nil {
		_ = sshSess.Close()
		return nil, err
	}
	outPipe, err := sshSess.StdoutPipe()
	if err != nil {
		_ = sshSess.Close()
		return nil, err
	}
	errPipe, err := sshSess.StderrPipe()
	if err != nil {
		_ = sshSess.Close()
		return nil, err
	}
	done := make(chan struct{})
	close(done)
	return &Session{
		lifeNursery: lifeNursery,
		isAlive:     isAlive,
		sshSess:     sshSess,
		stdinPipe:   &idempotentStdinPipe{w: inPipe},
		stdoutPipe:  outPipe,
		stderrPipe:  errPipe,
		pumpsDone:   done,
		valid:       true,
	}, nil
}

// StdinPipe 在 Start/StartShell 前借出远端标准输入写入管道（与非空 ExecStreams.Stdin 及 PlanKindScript 互斥）。
func (s *Session) StdinPipe() (io.WriteCloser, error) {
	if err := s.claimPipe(&s.stdinPipeTaken); err != nil {
		return nil, err
	}
	return s.stdinPipe, nil
}

// StdoutPipe 在 Start/StartShell 前借出远端标准输出读取管道（与非空 ExecStreams.Stdout 互斥）。
func (s *Session) StdoutPipe() (io.Reader, error) {
	if err := s.claimPipe(&s.stdoutPipeTaken); err != nil {
		return nil, err
	}
	return s.stdoutPipe, nil
}

// StderrPipe 在 Start/StartShell 前借出远端标准错误读取管道（与非空 ExecStreams.Stderr 互斥）。
func (s *Session) StderrPipe() (io.Reader, error) {
	if err := s.claimPipe(&s.stderrPipeTaken); err != nil {
		return nil, err
	}
	return s.stderrPipe, nil
}

func (s *Session) claimPipe(taken *bool) error {
	if s == nil || !s.valid {
		return ports.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return ports.ErrClosed
	}
	if s.starting || s.started.Load() || *taken {
		return ports.ErrInvalidArgument
	}
	*taken = true
	return nil
}

// Start 在远端会话通道上渲染并启动不可变 CommandPlan（含可选 PTY、环境变量、脚本 stdin 投递与输出上限截断）。
func (s *Session) Start(ctx context.Context, cmd execution.CommandPlan, streams ports.ExecStreams) error {
	if err := checkSessionStartArgs(ctx, streams); err != nil {
		return err
	}
	if !cmd.IsValid() {
		return ports.ErrInvalidArgument
	}
	rendered, err := cmd.RenderCommand()
	if err != nil {
		return fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err)
	}
	stdinSrc := buildCommandStdinReader(cmd, streams.Stdin)
	return s.launchSession(ctx, streams, cmd.MaxOutputBytes(), stdinSrc, true, func() error {
		return s.sshSess.Start(rendered)
	})
}

// StartShell 在远端会话通道上启动交互式 Shell（可选 PTY 与环境变量统一由 streams 承载）。
func (s *Session) StartShell(ctx context.Context, streams ports.ExecStreams) error {
	if err := checkSessionStartArgs(ctx, streams); err != nil {
		return err
	}
	return s.launchSession(ctx, streams, 0, streams.Stdin, false, func() error {
		return s.sshSess.Shell()
	})
}

func checkSessionStartArgs(ctx context.Context, streams ports.ExecStreams) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if ptyReq, ok := streams.PTY.Get(); ok && !ptyReq.IsValid() {
		return ports.ErrInvalidArgument
	}
	return nil
}

func (s *Session) launchSession(
	ctx context.Context,
	streams ports.ExecStreams,
	maxOutputBytes uint64,
	stdinSrc io.Reader,
	closeEmptyStdin bool,
	startOp func() error,
) error {
	inTaken, outTaken, errTaken, err := s.beginStart(streams, stdinSrc != nil)
	if err != nil {
		return err
	}
	_, startErr := chanconn.RunMultiplexedOp(ctx, s.lifeNursery, func() (struct{}, error) {
		if eErr := s.applyEnvAndPTY(ctx, streams); eErr != nil {
			return struct{}{}, eErr
		}
		return struct{}{}, startOp()
	}, func(struct{}) {
		_ = s.sshSess.Close()
	})
	if startErr != nil {
		_ = s.Close()
		return startErr
	}
	s.started.Store(true)
	if err := s.startIOPumps(streams, maxOutputBytes, stdinSrc, closeEmptyStdin, inTaken, outTaken, errTaken); err != nil {
		_ = s.Close()
		return err
	}
	return nil
}

func (s *Session) beginStart(streams ports.ExecStreams, hasStdinSrc bool) (inTaken, outTaken, errTaken bool, err error) {
	if s == nil || !s.valid {
		return false, false, false, ports.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() || !s.isAlive() {
		return false, false, false, ports.ErrClosed
	}
	if s.starting || s.started.Load() {
		return false, false, false, ports.ErrInvalidArgument
	}
	if (s.stdinPipeTaken && hasStdinSrc) || (s.stdoutPipeTaken && streams.Stdout != nil) || (s.stderrPipeTaken && streams.Stderr != nil) {
		return false, false, false, ports.ErrInvalidArgument
	}
	s.starting = true
	return s.stdinPipeTaken, s.stdoutPipeTaken, s.stderrPipeTaken, nil
}

type setenvPayload struct {
	Name  string
	Value string
}

func (s *Session) applyEnvAndPTY(ctx context.Context, streams ports.ExecStreams) error {
	if len(streams.Env) > 0 {
		for _, k := range slices.Sorted(maps.Keys(streams.Env)) {
			if err := ctx.Err(); err != nil {
				return err
			}
			// 按 OpenSSH SendEnv 惯例：服务端 AcceptEnv 拒绝（ok==false）不中断启动，仅透传传输级错误。
			if _, err := s.sshSess.SendRequest("env", true, ssh.Marshal(&setenvPayload{Name: k, Value: streams.Env[k]})); err != nil {
				return err
			}
		}
	}
	if ptyReq, ok := streams.PTY.Get(); ok {
		sz := ptyReq.Size()
		if err := s.sshSess.RequestPty(ptyReq.Term(), int(sz.Rows()), int(sz.Cols()), defaultPTYModes()); err != nil {
			return err
		}
	}
	return nil
}

func defaultPTYModes() ssh.TerminalModes {
	return ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
}

// ResizePTY 向远端会话发送 RFC 4254 window-change 窗口尺寸更新请求。
func (s *Session) ResizePTY(ctx context.Context, size ports.TerminalSize) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.valid || s.closed.Load() {
		return ports.ErrClosed
	}
	if !size.IsValid() {
		return ports.ErrInvalidTTYSize
	}
	return s.sshSess.WindowChange(int(size.Rows()), int(size.Cols()))
}

// Signal 向远端进程发送规范化 POSIX 信号（如 "INT"、"TERM"、"KILL"，兼容可选 "SIG" 前缀）。
func (s *Session) Signal(ctx context.Context, signal string) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.valid || s.closed.Load() {
		return ports.ErrClosed
	}
	norm := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(signal)), "SIG")
	if norm == "" {
		return ports.ErrInvalidArgument
	}
	return s.sshSess.Signal(ssh.Signal(norm))
}

// Wait 在上游连接 lifeNursery 监督下等待远端进程退出、排空输出泵并映射为封闭 execution.ExecutionOutcome。
// 对端进入半开黑洞且 ctx 取消/超时时立即返回 OutcomeUnknown 与 ctx.Err()，绝不永久挂起。
func (s *Session) Wait(ctx context.Context) (execution.ExecutionOutcome, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if s == nil || !s.valid || s.closed.Load() {
		return nil, ports.ErrClosed
	}
	if !s.started.Load() {
		return nil, ports.ErrInvalidArgument
	}
	if err := ctx.Err(); err != nil {
		s.abortWaitOnCancel()
		return s.buildWaitOutcome(ctx, err, nil)
	}
	_, waitErr := chanconn.RunMultiplexedOp(ctx, s.lifeNursery, func() (struct{}, error) {
		return struct{}{}, s.sshSess.Wait()
	}, nil)
	if ctx.Err() != nil {
		s.abortWaitOnCancel()
		return s.buildWaitOutcome(ctx, ctx.Err(), nil)
	}
	select {
	case <-s.currentPumpsDone():
	case <-ctx.Done():
		s.abortWaitOnCancel()
		return s.buildWaitOutcome(ctx, ctx.Err(), nil)
	}
	s.cancelStdin()
	return s.buildWaitOutcome(ctx, waitErr, s.firstIOErr())
}

func (s *Session) abortWaitOnCancel() {
	s.markDiscardOutput()
	s.cancelStdin()
	_ = s.sshSess.Close()
}

func (s *Session) buildWaitOutcome(ctx context.Context, waitErr, ioErr error) (execution.ExecutionOutcome, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		phase := execution.ExecPhaseCanceled
		if errors.Is(ctxErr, context.DeadlineExceeded) {
			phase = execution.ExecPhaseTimedOut
		}
		out, _ := execution.NewOutcomeUnknown(phase, "wait_canceled", ctxErr.Error())
		return out, ctxErr
	}
	trunc := s.truncated.Load()
	if waitErr == nil {
		out, err := execution.NewOutcomeCompleted(execution.NewExitCode(0), trunc)
		if err == nil && ioErr != nil {
			return out, ioErr
		}
		return out, err
	}
	var exitErr *ssh.ExitError
	if errors.As(waitErr, &exitErr) {
		out, err := buildExitErrorOutcome(exitErr, trunc)
		if err == nil && ioErr != nil {
			return out, ioErr
		}
		return out, err
	}
	var missingErr *ssh.ExitMissingError
	if errors.As(waitErr, &missingErr) {
		out, err := execution.NewOutcomeCompleted(execution.NewExitUnknown(missingErr.Error()), trunc)
		if err == nil && ioErr != nil {
			return out, ioErr
		}
		return out, err
	}
	out, _ := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "transport_lost", waitErr.Error())
	return out, waitErr
}

func buildExitErrorOutcome(exitErr *ssh.ExitError, truncated bool) (execution.ExecutionOutcome, error) {
	if sigName := exitErr.Signal(); sigName != "" {
		sig, err := execution.NewExitSignal(sigName, false, exitErr.Msg())
		if err != nil {
			return execution.NewOutcomeCompleted(execution.NewExitUnknown(exitErr.Error()), truncated)
		}
		return execution.NewOutcomeCompleted(sig, truncated)
	}
	return execution.NewOutcomeCompleted(execution.NewExitCode(int32(exitErr.ExitStatus())), truncated)
}

// Close 幂等关闭远端会话通道、停用本地输出写入并在有界宽限内收敛输出排空（零泄漏）。
func (s *Session) Close() error {
	if s == nil || !s.valid {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.markDiscardOutput()
		s.cancelStdin()
		sessErr := s.sshSess.Close()
		if errors.Is(sessErr, io.EOF) || errors.Is(sessErr, net.ErrClosed) {
			sessErr = nil
		}
		chanconn.WaitBounded(s.currentPumpsDone(), chanconn.CloseGraceTimeout)
		s.closeErr = sessErr
	})
	return s.closeErr
}
