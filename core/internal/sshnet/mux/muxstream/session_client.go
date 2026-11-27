package muxstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/internal/sshnet/dial/chanconn"
	"github.com/wentf9/xops-cli/core/ports"
)

// RemoteSession 通过独立帧流实现 ports.RemoteSession，严格保持管道互斥、缓冲解耦与零泄漏语义；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type RemoteSession struct {
	lifeNursery *conc.Nursery
	isAlive     func() bool
	conn        io.ReadWriteCloser
	fw          *SyncFrameWriter

	mu             sync.Mutex
	stdinTaken     bool
	stdoutTaken    bool
	stderrTaken    bool
	starting       bool
	stdinPipeW     *io.PipeWriter
	stdinPipeR     *io.PipeReader
	stdoutPipe     *bufferedPipe
	stderrPipe     *bufferedPipe
	stdoutDst      io.Writer
	stderrDst      io.Writer
	maxOutputBytes uint64
	outputUsed     atomic.Uint64
	truncated      atomic.Bool

	outMu         sync.Mutex
	discardOutput bool
	ioErrMu       sync.Mutex
	ioErr         error

	ctrlMu      sync.Mutex
	nextCtrlID  atomic.Uint32
	pendingCtrl map[uint32]chan error

	outcomeCh     chan sessionWaitResult
	readerDone    chan struct{}
	stdinPumpDone chan struct{}
	started       atomic.Bool
	closed        atomic.Bool
	closeOnce     sync.Once
	closeErr      error
	valid         bool
}

type sessionWaitResult struct {
	outcome execution.ExecutionOutcome
	err     error
}

// NewRemoteSession 在已通过 xopsCOpenSession 握手的连接上构造客户端 RemoteSession。
func NewRemoteSession(lifeNursery *conc.Nursery, isAlive func() bool, conn io.ReadWriteCloser) (*RemoteSession, error) {
	if lifeNursery == nil || isAlive == nil || conn == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, ports.ErrClosed
	}
	done := make(chan struct{})
	close(done)
	return &RemoteSession{
		lifeNursery:   lifeNursery,
		isAlive:       isAlive,
		conn:          conn,
		fw:            NewSyncFrameWriter(conn),
		pendingCtrl:   make(map[uint32]chan error),
		outcomeCh:     make(chan sessionWaitResult, 1),
		readerDone:    done,
		stdinPumpDone: done,
		valid:         true,
	}, nil
}

// StdinPipe 在 Start/StartShell 前借出远端标准输入写入管道（与 ExecStreams.Stdin 互斥）。
func (s *RemoteSession) StdinPipe() (io.WriteCloser, error) {
	if s == nil || !s.valid {
		return nil, ports.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return nil, ports.ErrClosed
	}
	if s.starting || s.started.Load() || s.stdinTaken {
		return nil, ports.ErrInvalidArgument
	}
	pr, pw := io.Pipe()
	s.stdinTaken = true
	s.stdinPipeR = pr
	s.stdinPipeW = pw
	return &idempotentPipeWriter{pw: pw}, nil
}

// StdoutPipe 在 Start/StartShell 前借出带独立缓冲的远端标准输出读取管道（与 ExecStreams.Stdout 互斥）。
func (s *RemoteSession) StdoutPipe() (io.Reader, error) {
	return s.claimOutputPipe(&s.stdoutTaken, &s.stdoutPipe)
}

// StderrPipe 在 Start/StartShell 前借出带独立缓冲的远端标准错误读取管道（与 ExecStreams.Stderr 互斥）。
func (s *RemoteSession) StderrPipe() (io.Reader, error) {
	return s.claimOutputPipe(&s.stderrTaken, &s.stderrPipe)
}

func (s *RemoteSession) claimOutputPipe(taken *bool, dstPipe **bufferedPipe) (io.Reader, error) {
	if s == nil || !s.valid {
		return nil, ports.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return nil, ports.ErrClosed
	}
	if s.starting || s.started.Load() || *taken {
		return nil, ports.ErrInvalidArgument
	}
	bp := newBufferedPipe()
	*taken = true
	*dstPipe = bp
	return bp, nil
}

// Start 通过 ControlMaster 启动远端不可变 CommandPlan 执行。
func (s *RemoteSession) Start(ctx context.Context, cmd execution.CommandPlan, streams ports.ExecStreams) error {
	if err := checkSessionCtxAndPTY(ctx, streams); err != nil {
		return err
	}
	if !cmd.IsValid() {
		return ports.ErrInvalidArgument
	}
	cmdJSON, err := EncodeCommandPlan(cmd)
	if err != nil {
		return err
	}
	body := EncodePTYAndEnv(AppendBytes(nil, cmdJSON), streams.PTY, streams.Env)
	_, hasScript := cmd.StdinPayload()
	return s.launch(ctx, SessMsgStartExec, body, streams, cmd.MaxOutputBytes(), streams.Stdin, hasScript, true)
}

// StartShell 通过 ControlMaster 启动远端交互式 Shell。
func (s *RemoteSession) StartShell(ctx context.Context, streams ports.ExecStreams) error {
	if err := checkSessionCtxAndPTY(ctx, streams); err != nil {
		return err
	}
	body := EncodePTYAndEnv(nil, streams.PTY, streams.Env)
	return s.launch(ctx, SessMsgStartShell, body, streams, 0, streams.Stdin, false, false)
}

func checkSessionCtxAndPTY(ctx context.Context, streams ports.ExecStreams) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if pty, ok := streams.PTY.Get(); ok && !pty.IsValid() {
		return ports.ErrInvalidArgument
	}
	return nil
}

func (s *RemoteSession) launch(ctx context.Context, msgType uint32, body []byte, streams ports.ExecStreams, maxBytes uint64, stdinSrc io.Reader, hasScript, closeEmptyStdin bool) error {
	if err := s.beginStart(streams, maxBytes, stdinSrc != nil || hasScript); err != nil {
		return err
	}
	// 启动握手受 chanconn.RunWithAbortWatchdog 监督，确保对端黑洞时 ctx 取消立即 O(1) 解阻。
	if err := chanconn.RunWithAbortWatchdog(ctx, func() { _ = s.conn.Close() }, func() error {
		if err := s.fw.Write(msgType, body); err != nil {
			return err
		}
		respType, respBody, err := ReadPacket(s.conn)
		if err != nil {
			return err
		}
		return checkStartedReply(respType, respBody)
	}); err != nil {
		_ = s.Close()
		return err
	}
	if err := s.startBackgroundPumps(stdinSrc, closeEmptyStdin); err != nil {
		_ = s.Close()
		return err
	}
	s.started.Store(true)
	if ctxErr := ctx.Err(); ctxErr != nil {
		_ = s.Close()
		return ctxErr
	}
	return nil
}

func (s *RemoteSession) beginStart(streams ports.ExecStreams, maxBytes uint64, hasStdinSrc bool) error {
	if s == nil || !s.valid {
		return ports.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() || !s.isAlive() {
		return ports.ErrClosed
	}
	if s.starting || s.started.Load() {
		return ports.ErrInvalidArgument
	}
	if (s.stdinTaken && hasStdinSrc) || (s.stdoutTaken && streams.Stdout != nil) || (s.stderrTaken && streams.Stderr != nil) {
		return ports.ErrInvalidArgument
	}
	s.starting = true
	s.stdoutDst = streams.Stdout
	s.stderrDst = streams.Stderr
	s.maxOutputBytes = maxBytes
	return nil
}

func checkStartedReply(respType uint32, respBody []byte) error {
	if respType != SessMsgStarted {
		return domi18n.EF(ports.ErrCorruptData, domi18n.KeyMuxUnexpectedFrame, domi18n.Str("actual", fmt.Sprintf("%#x", respType)), domi18n.Str("expected", "SessMsgStarted"))
	}
	rd := NewReader(respBody)
	okFlag, e1 := rd.ReadUint32()
	msg, e2 := rd.ReadString()
	if err := FirstErr(e1, e2); err != nil {
		return err
	}
	if okFlag == 0 {
		return domi18n.WrapSentinel(ports.ErrInvalidArgument, domi18n.E(domi18n.KeyMuxRemoteError, domi18n.BoundStr("detail", msg)))
	}
	return nil
}

// ResizePTY 向已启动的复用会话发送带关联 reqID 的窗口尺寸更新请求。
func (s *RemoteSession) ResizePTY(ctx context.Context, size ports.TerminalSize) error {
	if err := s.checkControlActive(ctx); err != nil {
		return err
	}
	if !size.IsValid() {
		return ports.ErrInvalidTTYSize
	}
	reqID := s.nextCtrlID.Add(1)
	body := AppendU32(AppendU32(AppendU32(nil, reqID), uint32(size.Cols())), uint32(size.Rows()))
	return s.sendSessionControl(ctx, reqID, SessMsgResizePTY, body)
}

// Signal 向已启动的复用会话发送带关联 reqID 的规范化 POSIX 信号。
func (s *RemoteSession) Signal(ctx context.Context, signal string) error {
	if err := s.checkControlActive(ctx); err != nil {
		return err
	}
	norm := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(signal)), "SIG")
	if norm == "" {
		return ports.ErrInvalidArgument
	}
	reqID := s.nextCtrlID.Add(1)
	return s.sendSessionControl(ctx, reqID, SessMsgSignal, AppendStr(AppendU32(nil, reqID), norm))
}

func (s *RemoteSession) checkControlActive(ctx context.Context) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || !s.valid || s.closed.Load() || !s.isAlive() {
		return ports.ErrClosed
	}
	if !s.started.Load() {
		return ports.ErrInvalidArgument
	}
	return nil
}

func (s *RemoteSession) sendSessionControl(ctx context.Context, reqID, msgType uint32, body []byte) error {
	ch, err := s.registerCtrlPending(reqID)
	if err != nil {
		return err
	}
	defer s.unregisterCtrlPending(reqID)

	if err := s.fw.Write(msgType, body); err != nil {
		return err
	}
	select {
	case repErr := <-ch:
		return repErr
	case <-s.currentReaderDone():
		return ports.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Wait 等待远端复用会话退出并返回完整封闭 execution.ExecutionOutcome。
// 当 ctx 取消或超时时立即停用本地输出写入、关闭管道与底层连接，O(1) 返回 (OutcomeUnknown, ctx.Err())，
// 绝不因调用方阻塞态 ExecStreams.Stdin 挂死。
func (s *RemoteSession) Wait(ctx context.Context) (execution.ExecutionOutcome, error) {
	if ctx == nil {
		return nil, ports.ErrNilContext
	}
	if s == nil || !s.valid || s.closed.Load() {
		return nil, ports.ErrClosed
	}
	if !s.started.Load() {
		return nil, ports.ErrInvalidArgument
	}
	select {
	case res := <-s.outcomeCh:
		if res.err == nil {
			if ioErr := s.firstIOErr(); ioErr != nil {
				return res.outcome, ioErr
			}
		}
		return res.outcome, res.err
	case <-ctx.Done():
		s.abortWaitOnCancel()
		phase := execution.ExecPhaseCanceled
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			phase = execution.ExecPhaseTimedOut
		}
		out, _ := execution.NewOutcomeUnknown(phase, "mux_wait_canceled", ctx.Err().Error())
		return out, ctx.Err()
	}
}

type writeDeadliner interface {
	SetWriteDeadline(time.Time) error
}

// sendBestEffortCloseFrame 仅在会话已启动后以极短写截止时间尽力发送 SessMsgClose，
// 防止对端黑洞、未读管道或满发送缓冲导致 abortWaitOnCancel / Close 阻塞。
func (s *RemoteSession) sendBestEffortCloseFrame() {
	if !s.started.Load() {
		return
	}
	if wd, ok := s.conn.(writeDeadliner); ok {
		_ = wd.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	}
	_ = s.fw.Write(SessMsgClose, nil)
}

// abortWaitOnCancel 对齐 dial/remotesess：取消 Wait 时立即停用输出缓冲与管道并断开底层帧流，
// 绝不在外部调用方拥有的 ExecStreams.Stdin 读泵上无界等待。
func (s *RemoteSession) abortWaitOnCancel() {
	s.markDiscardOutput()
	s.failAllCtrlPending(ports.ErrClosed)
	s.mu.Lock()
	inW, inR := s.stdinPipeW, s.stdinPipeR
	s.mu.Unlock()
	if inW != nil {
		_ = inW.Close()
	}
	if inR != nil {
		_ = inR.Close()
	}
	s.closeOutputPipesAbort()
	s.sendBestEffortCloseFrame()
	_ = s.conn.Close()
}

// Close 幂等关闭复用会话管道与底层连接并在有界宽限内收敛后台读泵（零泄漏、对阻塞态外部 Stdin 有界解阻）。
func (s *RemoteSession) Close() error {
	if s == nil || !s.valid {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed.Store(true)
		inTaken := s.stdinTaken
		inW, inR := s.stdinPipeW, s.stdinPipeR
		rDone, inDone := s.readerDone, s.stdinPumpDone
		s.mu.Unlock()

		s.markDiscardOutput()
		s.failAllCtrlPending(ports.ErrClosed)
		s.sendBestEffortCloseFrame()
		if inW != nil {
			_ = inW.Close()
		}
		if inR != nil {
			_ = inR.Close()
		}
		s.closeOutputPipesAbort()
		cErr := s.conn.Close()
		if IsBenignIOErr(cErr) {
			cErr = nil
		}
		<-rDone
		if inTaken {
			<-inDone
		} else {
			chanconn.WaitBounded(inDone, chanconn.CloseGraceTimeout)
		}
		s.closeErr = cErr
	})
	return s.closeErr
}
