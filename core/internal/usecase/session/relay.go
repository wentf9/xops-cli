package session

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
)

type ttyDecision struct{ requestPTY, useRawTerminal bool }

// resolveTTYDecision 按 OpenSSH RequestTTY（auto/yes/no/force）与本机终端交互能力决定
// 是否分配远端 PTY 以及是否接管本机原始终端 Relay：
// RequestTTYUnset 下若 CommandPlan.PTY()==true 则始终分配远端 PTY（本机非交互时走流式而非原始终端）。
func resolveTTYDecision(mode RequestTTYMode, isShell, cmdPTY, localInteractive bool) ttyDecision {
	switch mode {
	case RequestTTYYes:
		return ttyDecision{requestPTY: localInteractive, useRawTerminal: localInteractive}
	case RequestTTYForce:
		return ttyDecision{requestPTY: true, useRawTerminal: localInteractive}
	case RequestTTYAuto:
		ok := (isShell || cmdPTY) && localInteractive
		return ttyDecision{requestPTY: ok, useRawTerminal: ok}
	case RequestTTYUnset:
		return ttyDecision{requestPTY: cmdPTY || (isShell && localInteractive), useRawTerminal: (cmdPTY || isShell) && localInteractive}
	case RequestTTYNo:
	}
	return ttyDecision{}
}

func resolvePTYTerm(explicit string, env ports.EnvPort) string {
	if explicit != "" {
		return explicit
	}
	if env != nil {
		if v, ok := env.LookupEnv("TERM"); ok && v != "" {
			return v
		}
	}
	return defaultTTYTerm
}
func buildPTYRequest(termName string, sz ports.TerminalSize) (ports.PTYRequest, error) {
	if !sz.IsValid() {
		var err error
		if sz, err = ports.NewTerminalSize(defaultTTYCols, defaultTTYRows); err != nil {
			return zeroVal[ports.PTYRequest](), err
		}
	}
	if req, err := ports.NewPTYRequest(termName, sz); err == nil {
		return req, nil
	}
	return ports.NewPTYRequest(defaultTTYTerm, sz)
}

type sessionStarter func(ctx context.Context, streams ports.ExecStreams) error

// runRawTerminalSession 在 TerminalPort.WithRawTerminal 同步作用域内绑定 RemoteSession 三管道，
// 启动远端命令或 Shell，并经 TerminalHandle.Relay 双向中继输入/输出与窗口缩放事件（0 linearlease、0 goleak）。
// 仅在 starter 成功启动远端进程后才标记 started=true；此前（含 WithRawTerminal 进入失败）一律返回 OutcomeNotStarted。
func runRawTerminalSession(
	ctx context.Context, sess ports.RemoteSession, termPort ports.TerminalPort, starter sessionStarter,
	termName string, sendEnv map[string]string, stderrDst io.Writer, emitter *operationEmitter, wantPTY bool,
) (execution.ExecutionOutcome, error) {
	started, startPhase, startCode := false, execution.StartPhaseSessionOpen, "raw_terminal_failed"
	relayErr := termPort.WithRawTerminal(ctx, func(term ports.TerminalHandle) error {
		remoteIn, remoteOut, remoteErr, pErr := claimSessionPipes(sess)
		if pErr != nil {
			startPhase, startCode = execution.StartPhaseSessionOpen, "session_pipes_failed"
			return pErr
		}
		var sz ports.TerminalSize
		if wantPTY {
			sz, _ = term.Size()
		}
		ptyOpt, ptyErr := prepareOptionalPTY(wantPTY, termName, sz)
		if ptyErr != nil {
			startPhase, startCode = execution.StartPhaseValidate, "invalid_pty"
			return ptyErr
		}
		if sErr := starter(ctx, ports.ExecStreams{PTY: ptyOpt, Env: sendEnv}); sErr != nil {
			startPhase, startCode = execution.StartPhaseRequestRejected, "session_start_failed"
			return sErr
		}
		started = true
		return relayPipesThroughTerminal(ctx, sess, term, remoteIn, remoteOut, remoteErr, stderrDst, emitter, wantPTY)
	})
	if !started {
		err := firstNonNilErr(relayErr, ctx.Err(), ports.ErrClosed)
		return notStartedSessionOutcome(startPhase, startCode, err), err
	}
	if relayErr != nil || ctx.Err() != nil {
		_ = sess.Close()
		err := firstNonNilErr(relayErr, ctx.Err(), nil)
		return outcomeForAbortedRun(ctx, err), err
	}
	return sess.Wait(ctx)
}

func firstNonNilErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
func claimSessionPipes(sess ports.RemoteSession) (io.WriteCloser, io.Reader, io.Reader, error) {
	inPipe, err := sess.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	outPipe, err := sess.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	errPipe, err := sess.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	return inPipe, outPipe, errPipe, nil
}
func prepareOptionalPTY(wantPTY bool, termName string, sz ports.TerminalSize) (algebraic.Option[ports.PTYRequest], error) {
	if !wantPTY {
		return algebraic.None[ports.PTYRequest](), nil
	}
	req, err := buildPTYRequest(termName, sz)
	if err != nil {
		return algebraic.None[ports.PTYRequest](), err
	}
	return algebraic.Some(req), nil
}

// relayPipesThroughTerminal 经无缓冲 io.Pipe 将 remoteOut（及无独立 stderrDst 时的 remoteErr）
// 汇流至 term.Relay，避免将借用句柄 term 传入任何后台协程；通过先置同步 AfterFunc 熔断、
// 管道写错双向打断与 gracefulStdinWriter 消除取消死锁与远端并发退出误报。
func relayPipesThroughTerminal(
	ctx context.Context, sess ports.RemoteSession, term ports.TerminalHandle,
	remoteIn io.WriteCloser, remoteOut, remoteErr io.Reader, stderrDst io.Writer, emitter *operationEmitter, wantPTY bool,
) error {
	pr, pw := io.Pipe()
	defer func() { _ = pr.Close() }()
	var abortOnce sync.Once
	abort := func() { abortOnce.Do(func() { _ = closeClosers(pr, pw, sess) }) }
	onResize := buildResizeCallback(sess, wantPTY)
	var relayErr, pumpErr error
	runErr := conc.RunWait(ctx, func(wCtx context.Context, n *conc.Nursery) error {
		defer registerSyncAbort(wCtx, abort)()
		if err := n.Go(func(pCtx context.Context) error {
			pumpErr = pumpRemotePipesToRelay(pCtx, pw, remoteOut, remoteErr, stderrDst, emitter, abort)
			return pumpErr
		}); err != nil {
			abort()
			return err
		}
		relayErr = term.Relay(wCtx, &gracefulStdinWriter{ctx: wCtx, w: remoteIn}, pr, onResize)
		if relayErr != nil || wCtx.Err() != nil {
			abort()
		}
		return relayErr
	})
	return firstNonNilErr(pumpErr, relayErr, runErr)
}

func buildResizeCallback(sess ports.RemoteSession, wantPTY bool) func(context.Context, ports.TerminalSize) error {
	if !wantPTY {
		return nil
	}
	return func(rCtx context.Context, sz ports.TerminalSize) error {
		if err := sess.ResizePTY(rCtx, sz); err != nil && !errors.Is(err, ports.ErrClosed) && rCtx.Err() == nil {
			return err
		}
		return nil
	}
}

// pumpRemotePipesToRelay 并发排空 remoteOut 与 remoteErr 并在二者全部到达 EOF 后关闭 pw；
// 若任一侧遭遇真实非关闭错误（如 stderrDst 写失败），立即触发 abort 唤醒另一侧与 term.Relay 防止死锁。
func pumpRemotePipesToRelay(ctx context.Context, pw *io.PipeWriter, remoteOut, remoteErr io.Reader, stderrDst io.Writer, emitter *operationEmitter, abort func()) error {
	defer func() { _ = pw.Close() }()
	lockedPW := &syncWriter{w: pw}
	outWriter := wrapOutputWriter(ctx, lockedPW, emitter, events.OutputStreamStdout)
	errDst := io.Writer(lockedPW)
	if stderrDst != nil {
		errDst = stderrDst
	}
	errWriter := wrapOutputWriter(ctx, errDst, emitter, events.OutputStreamStderr)
	copyAndAbort := func(dst io.Writer, src io.Reader) error {
		err := copyPipeBestEffort(dst, src)
		if err != nil {
			abort()
		}
		return err
	}
	return conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if err := n.Go(func(context.Context) error { return copyAndAbort(outWriter, remoteOut) }); err != nil {
			abort()
			return err
		}
		return copyAndAbort(errWriter, remoteErr)
	})
}
func copyPipeBestEffort(dst io.Writer, src io.Reader) error {
	if src != nil {
		if _, err := io.Copy(dst, src); err != nil && !isRemotePipeClosedErr(err) {
			return err
		}
	}
	return nil
}
func isRemotePipeClosedErr(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.Is(err, ports.ErrClosed)
}

// gracefulStdinWriter 包装远端 StdinPipe：当会话未被取消而远端先退出关闭 stdin 时，
// 宽容吸收并发在途按键写入，等待 remoteOut/remoteErr 完整排空并由 sess.Wait 产出精确 OutcomeCompleted。
type gracefulStdinWriter struct {
	ctx    context.Context
	w      io.WriteCloser
	closed atomic.Bool
}

func (g *gracefulStdinWriter) Write(p []byte) (int, error) {
	if g.closed.Load() {
		if g.ctx.Err() != nil {
			return 0, g.ctx.Err()
		}
		return len(p), nil
	}
	n, err := g.w.Write(p)
	if err != nil && g.ctx.Err() == nil && isRemotePipeClosedErr(err) {
		g.closed.Store(true)
		return len(p), nil
	}
	return n, err
}

func (g *gracefulStdinWriter) Close() error {
	g.closed.Store(true)
	if err := g.w.Close(); err != nil && !isRemotePipeClosedErr(err) {
		return err
	}
	return nil
}

// syncWriter 为多源并发写入同一 io.PipeWriter 提供互斥串行化。
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// runStreamSession 执行非原始终端模式（无 PTY 或非交互强分配 PTY -tt）的会话流接线与退出等待。
func runStreamSession(
	ctx context.Context, sess ports.RemoteSession, starter sessionStarter, termName string,
	sendEnv map[string]string, stdin io.Reader, stdout, stderr io.Writer, emitter *operationEmitter, wantPTY bool,
) (execution.ExecutionOutcome, error) {
	ptyOpt, err := prepareOptionalPTY(wantPTY, termName, zeroVal[ports.TerminalSize]())
	if err != nil {
		return notStartedSessionOutcome(execution.StartPhaseValidate, "invalid_pty", err), err
	}
	streams := ports.ExecStreams{Stdin: stdin, Stdout: wrapOutputWriter(ctx, stdout, emitter, events.OutputStreamStdout), Stderr: wrapOutputWriter(ctx, stderr, emitter, events.OutputStreamStderr), PTY: ptyOpt, Env: sendEnv}
	if err := starter(ctx, streams); err != nil {
		return notStartedSessionOutcome(execution.StartPhaseRequestRejected, "session_start_failed", err), err
	}
	return sess.Wait(ctx)
}

func outcomeForAbortedRun(ctx context.Context, err error) execution.ExecutionOutcome {
	phase, code, msg := execution.ExecPhaseTransportLost, "session_aborted", "session aborted"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		phase, code = execution.ExecPhaseTimedOut, "timed_out"
	} else if ctx.Err() != nil {
		phase, code = execution.ExecPhaseCanceled, "canceled"
	}
	if err != nil {
		msg = err.Error()
	}
	out, _ := execution.NewOutcomeUnknown(phase, code, msg)
	return out
}
