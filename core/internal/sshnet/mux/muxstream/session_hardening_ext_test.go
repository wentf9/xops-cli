package muxstream_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/internal/sshnet/mux/muxstream"
	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/core/ports/tck"
)

// scriptedRemoteSession 用于在 muxstream 桥接测试中精确编排 stdout/stderr 乱序、快退不读 stdin、
// 阻塞退出与控制信号并发关联等边界行为。
type scriptedRemoteSession struct {
	onStart   func(ctx context.Context, cmd execution.CommandPlan, streams ports.ExecStreams, outW, errW *io.PipeWriter) (execution.ExecutionOutcome, error)
	onCtrl    func(kind string) error
	blockWait bool

	mu      sync.Mutex
	outR    *io.PipeReader
	outW    *io.PipeWriter
	errR    *io.PipeReader
	errW    *io.PipeWriter
	doneCh  chan struct{}
	waitRes execution.ExecutionOutcome
	waitErr error
	closed  chan struct{}
	once    sync.Once
}

func newScriptedSession(
	onStart func(ctx context.Context, cmd execution.CommandPlan, streams ports.ExecStreams, outW, errW *io.PipeWriter) (execution.ExecutionOutcome, error),
	onCtrl func(kind string) error,
) *scriptedRemoteSession {
	oR, oW := io.Pipe()
	eR, eW := io.Pipe()
	return &scriptedRemoteSession{
		onStart: onStart,
		onCtrl:  onCtrl,
		outR:    oR,
		outW:    oW,
		errR:    eR,
		errW:    eW,
		doneCh:  make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (s *scriptedRemoteSession) StdinPipe() (io.WriteCloser, error) { return nil, ports.ErrUnsupported }
func (s *scriptedRemoteSession) StdoutPipe() (io.Reader, error)     { return s.outR, nil }
func (s *scriptedRemoteSession) StderrPipe() (io.Reader, error)     { return s.errR, nil }

func (s *scriptedRemoteSession) Start(ctx context.Context, cmd execution.CommandPlan, streams ports.ExecStreams) error {
	out, err := s.onStart(ctx, cmd, streams, s.outW, s.errW)
	s.mu.Lock()
	s.waitRes, s.waitErr = out, err
	s.mu.Unlock()
	if !s.blockWait {
		close(s.doneCh)
	}
	return nil
}

func (s *scriptedRemoteSession) StartShell(ctx context.Context, streams ports.ExecStreams) error {
	return s.Start(ctx, muxstream.ZeroVal[execution.CommandPlan](), streams)
}

func (s *scriptedRemoteSession) ResizePTY(_ context.Context, _ ports.TerminalSize) error {
	if s.onCtrl != nil {
		return s.onCtrl("resize")
	}
	return nil
}

func (s *scriptedRemoteSession) Signal(_ context.Context, sig string) error {
	if s.onCtrl != nil {
		return s.onCtrl("signal:" + sig)
	}
	return nil
}

func (s *scriptedRemoteSession) Wait(ctx context.Context) (execution.ExecutionOutcome, error) {
	select {
	case <-s.doneCh:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.waitRes, s.waitErr
	case <-s.closed:
		return nil, ports.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *scriptedRemoteSession) Close() error {
	s.once.Do(func() {
		close(s.closed)
		_ = s.outW.Close()
		_ = s.errW.Close()
		_ = s.outR.Close()
		_ = s.errR.Close()
	})
	return nil
}

// TestMuxStream_WaitCancelWithBlockedExternalStdinO1 验证 Blocker 修复：
// 调用方通过 ExecStreams.Stdin 传入阻塞态 io.PipeReader 时，Wait(ctx) 取消与 Close() 必须 O(1) 返回且零死锁。
func TestMuxStream_WaitCancelWithBlockedExternalStdinO1(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srvSess := newScriptedSession(func(_ context.Context, _ execution.CommandPlan, _ ports.ExecStreams, outW, errW *io.PipeWriter) (execution.ExecutionOutcome, error) {
		return nil, nil
	}, nil)
	srvSess.blockWait = true

	cliPipe, srvPipe := net.Pipe()
	inR, inW := io.Pipe()
	defer func() { _ = inW.Close(); _ = inR.Close() }()

	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			muxstream.ServeSessionBridge(c, srvPipe, srvSess)
			return nil
		}); gErr != nil {
			return gErr
		}
		rs, rErr := muxstream.NewRemoteSession(n, func() bool { return true }, cliPipe)
		if rErr != nil {
			return rErr
		}
		cmd := tck.MustCommandPlan(t, "sleep 60")
		if sErr := rs.Start(ctx, cmd, ports.ExecStreams{Stdin: inR}); sErr != nil {
			_ = rs.Close()
			return sErr
		}
		waitCtx, wCancel := context.WithTimeout(ctx, 40*time.Millisecond)
		defer wCancel()
		start := time.Now()
		out, wErr := rs.Wait(waitCtx)
		elapsed := time.Since(start)
		if !errors.Is(wErr, context.DeadlineExceeded) || out == nil || out.Kind() != execution.OutcomeKindUnknown {
			_ = inW.Close()
			_ = rs.Close()
			return errors.New("Wait 取消未返回预期 OutcomeUnknown + DeadlineExceeded")
		}
		if elapsed > 300*time.Millisecond {
			_ = inW.Close()
			_ = rs.Close()
			return errors.New("阻塞外部 Stdin 下 Wait 取消耗时过长")
		}
		// 即使外部 inW 尚未关闭，Close() 也在有界宽限内返回而非永久死锁。
		cStart := time.Now()
		_ = rs.Close()
		if time.Since(cStart) > 2*time.Second {
			_ = inW.Close()
			return errors.New("阻塞外部 Stdin 下 Close 超过有界宽限")
		}
		_ = inW.Close()
		return nil
	})
	if err != nil {
		t.Fatalf("阻塞外部 Stdin Wait 取消验证失败: %v", err)
	}
}

// TestMuxStream_ServerInRUnblocksWhenFastCommandIgnoresStdin 验证 #123 M1 修复：
// 远端快速命令完全不读 stdin 而客户端持续写入大量 stdin 时，服务端关闭 inR 解除阻塞，零死锁零泄漏。
func TestMuxStream_ServerInRUnblocksWhenFastCommandIgnoresStdin(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	srvSess := newScriptedSession(func(_ context.Context, _ execution.CommandPlan, _ ports.ExecStreams, outW, errW *io.PipeWriter) (execution.ExecutionOutcome, error) {
		_ = outW.Close()
		_ = errW.Close()
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}, nil)

	cliPipe, srvPipe := net.Pipe()
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			muxstream.ServeSessionBridge(c, srvPipe, srvSess)
			return nil
		}); gErr != nil {
			return gErr
		}
		rs, rErr := muxstream.NewRemoteSession(n, func() bool { return true }, cliPipe)
		if rErr != nil {
			return rErr
		}
		defer func() { _ = rs.Close() }()
		inW, pErr := rs.StdinPipe()
		if pErr != nil {
			return pErr
		}
		cmd := tck.MustCommandPlan(t, "true")
		if sErr := rs.Start(ctx, cmd, ports.ExecStreams{}); sErr != nil {
			return sErr
		}
		_ = n.Go(func(context.Context) error {
			_, _ = inW.Write(bytes.Repeat([]byte("X"), 128*1024))
			_ = inW.Close()
			return nil
		})
		out, wErr := rs.Wait(ctx)
		if wErr != nil {
			return wErr
		}
		if comp, ok := out.(*execution.OutcomeCompleted); !ok || !comp.Succeeded() {
			return errors.New("期望 OutcomeCompleted(0)")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("快速退出不读 stdin 回归测试失败: %v", err)
	}
}

// TestMuxStream_BufferedPipesTruncatedAndDstWriteError 验证 #123 M2 与 #124 M1 修复：
//  1. 远端先写 stderr 后关 stdout，调用方严格顺序 ReadAll(stdoutR) 再 ReadAll(stderrR) 绝不死锁；
//  2. CommandPlan.MaxOutputBytes 截断状态准确回填至 OutcomeCompleted.Truncated()==true；
//  3. ExecStreams.Stdout 写失败时持续排空并在 Wait 暴露 firstIOErr。
func TestMuxStream_BufferedPipesTruncatedAndDstWriteError(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	t.Run("SequentialStdoutThenStderrNoDeadlock", func(t *testing.T) {
		verifySequentialPipeDrain(t, ctx)
	})
	t.Run("MaxOutputBytesSetsTruncatedFlag", func(t *testing.T) {
		verifyTruncatedOutcomeFlag(t, ctx)
	})
	t.Run("StdoutWriteErrorSurfacedByWait", func(t *testing.T) {
		verifyDstWriteErrorSurfaced(t, ctx)
	})
}

func verifySequentialPipeDrain(t *testing.T, ctx context.Context) {
	t.Helper()
	srvSess := newScriptedSession(func(_ context.Context, _ execution.CommandPlan, _ ports.ExecStreams, outW, errW *io.PipeWriter) (execution.ExecutionOutcome, error) {
		// 先写大量 stderr 再写 stdout，验证单读循环经缓冲管道绝不互锁。
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}, nil)
	cliPipe, srvPipe := net.Pipe()
	cmd := tck.MustCommandPlan(t, "both")
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			muxstream.ServeSessionBridge(c, srvPipe, srvSess)
			return nil
		}); gErr != nil {
			return gErr
		}
		return runSequentialPipeDrainClient(ctx, n, cliPipe, srvSess, cmd)
	})
	if err != nil {
		t.Fatalf("顺序 stdout/stderr 排空失败: %v", err)
	}
}

func runSequentialPipeDrainClient(
	ctx context.Context,
	n *conc.Nursery,
	cliPipe net.Conn,
	srvSess *scriptedRemoteSession,
	cmd execution.CommandPlan,
) error {
	rs, rErr := muxstream.NewRemoteSession(n, func() bool { return true }, cliPipe)
	if rErr != nil {
		return rErr
	}
	defer func() { _ = rs.Close() }()
	stdoutR, e1 := rs.StdoutPipe()
	stderrR, e2 := rs.StderrPipe()
	if err := muxstream.FirstErr(e1, e2); err != nil {
		return err
	}
	if err := rs.Start(ctx, cmd, ports.ExecStreams{}); err != nil {
		return err
	}
	if gErr := n.Go(func(context.Context) error {
		_, _ = srvSess.errW.Write([]byte("stderr-first-payload"))
		_ = srvSess.errW.Close()
		_, _ = srvSess.outW.Write([]byte("stdout-second-payload"))
		_ = srvSess.outW.Close()
		return nil
	}); gErr != nil {
		return gErr
	}
	gotOut, eOut := io.ReadAll(stdoutR)
	gotErr, eErr := io.ReadAll(stderrR)
	if err := muxstream.FirstErr(eOut, eErr); err != nil {
		return err
	}
	if string(gotOut) != "stdout-second-payload" || string(gotErr) != "stderr-first-payload" {
		return errors.New("顺序排空 stdout/stderr 数据不匹配")
	}
	_, err := rs.Wait(ctx)
	return err
}

func verifyTruncatedOutcomeFlag(t *testing.T, ctx context.Context) {
	t.Helper()
	cmd, cErr := execution.NewCommandPlan(execution.CommandPlanSpec{
		Kind:           execution.PlanKindCommand,
		Profile:        execution.DefaultServerLaunchProfile(),
		Command:        "emit-64",
		MaxOutputBytes: algebraic.Some(uint64(8)),
	})
	if cErr != nil {
		t.Fatalf("NewCommandPlan: %v", cErr)
	}
	srvSess := newScriptedSession(func(_ context.Context, _ execution.CommandPlan, _ ports.ExecStreams, outW, errW *io.PipeWriter) (execution.ExecutionOutcome, error) {
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}, nil)
	cliPipe, srvPipe := net.Pipe()
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			muxstream.ServeSessionBridge(c, srvPipe, srvSess)
			return nil
		}); gErr != nil {
			return gErr
		}
		return runTruncatedOutcomeClient(ctx, n, cliPipe, srvSess, cmd)
	})
	if err != nil {
		t.Fatalf("MaxOutputBytes 截断回归测试失败: %v", err)
	}
}

func runTruncatedOutcomeClient(
	ctx context.Context,
	n *conc.Nursery,
	cliPipe net.Conn,
	srvSess *scriptedRemoteSession,
	cmd execution.CommandPlan,
) error {
	rs, rErr := muxstream.NewRemoteSession(n, func() bool { return true }, cliPipe)
	if rErr != nil {
		return rErr
	}
	defer func() { _ = rs.Close() }()
	var outBuf bytes.Buffer
	if err := rs.Start(ctx, cmd, ports.ExecStreams{Stdout: &outBuf}); err != nil {
		return err
	}
	if gErr := n.Go(func(context.Context) error {
		_, _ = srvSess.outW.Write(bytes.Repeat([]byte("A"), 64))
		_ = srvSess.outW.Close()
		_ = srvSess.errW.Close()
		return nil
	}); gErr != nil {
		return gErr
	}
	out, wErr := rs.Wait(ctx)
	if wErr != nil {
		return wErr
	}
	comp, ok := out.(*execution.OutcomeCompleted)
	if !ok || !comp.Truncated() || outBuf.Len() != 8 {
		return errors.New("MaxOutputBytes 截断状态未准确回填至 OutcomeCompleted.Truncated()")
	}
	return nil
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func verifyDstWriteErrorSurfaced(t *testing.T, ctx context.Context) {
	t.Helper()
	wantErr := errors.New("disk full")
	srvSess := newScriptedSession(func(_ context.Context, _ execution.CommandPlan, _ ports.ExecStreams, outW, errW *io.PipeWriter) (execution.ExecutionOutcome, error) {
		return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	}, nil)
	cliPipe, srvPipe := net.Pipe()
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(c context.Context) error {
			muxstream.ServeSessionBridge(c, srvPipe, srvSess)
			return nil
		}); gErr != nil {
			return gErr
		}
		rs, rErr := muxstream.NewRemoteSession(n, func() bool { return true }, cliPipe)
		if rErr != nil {
			return rErr
		}
		defer func() { _ = rs.Close() }()
		if err := rs.Start(ctx, tck.MustCommandPlan(t, "emit"), ports.ExecStreams{Stdout: failingWriter{err: wantErr}}); err != nil {
			return err
		}
		if gErr := n.Go(func(context.Context) error {
			_, _ = srvSess.outW.Write([]byte("trigger-write-err"))
			_ = srvSess.outW.Close()
			_ = srvSess.errW.Close()
			return nil
		}); gErr != nil {
			return gErr
		}
		_, wErr := rs.Wait(ctx)
		if !errors.Is(wErr, wantErr) {
			return errors.New("Wait 未暴露 Stdout.Write 失败错误")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Stdout 写错误暴露测试失败: %v", err)
	}
}

// TestMuxStream_ControlGuardsBoundsAndStrictSplice 验证 #123 M3/M4/M6/m7 修复：
//   - Start 前调用 ResizePTY/Signal 失败关闭（不破坏线缆）；
//   - 线缆端口与 PTY 尺寸拒绝 uint32->uint16 静默截断；
//   - SpliceStreamsStrict 在无 CloseWrite 对端关闭时立即关闭双端（无僵尸隧道）；
//   - RemoteListener 的已接受连接本地 Close 后 Read 返回 net.ErrClosed。
func TestMuxStream_ControlGuardsBoundsAndStrictSplice(t *testing.T) {
	defer goleak.VerifyNone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. 线缆端口与 PTY 越界校验。
	badFwd := muxstream.AppendU32(nil, 1)
	badFwd = muxstream.AppendU32(badFwd, muxstream.FwdLocal)
	badFwd = muxstream.AppendStr(badFwd, "127.0.0.1")
	badFwd = muxstream.AppendU32(badFwd, 65616) // 0x10050 -> 绝不可静默截断为 80
	badFwd = muxstream.AppendStr(badFwd, "10.0.0.1")
	badFwd = muxstream.AppendU32(badFwd, 80)
	if _, _, err := muxstream.DecodeForwardWire(badFwd); !errors.Is(err, ports.ErrInvalidArgument) {
		t.Fatalf("越界转发端口 DecodeForwardWire = %v, 期望 ErrInvalidArgument", err)
	}
	badPTY := muxstream.AppendU32(nil, 1)
	badPTY = muxstream.AppendStr(badPTY, "xterm")
	badPTY = muxstream.AppendU32(badPTY, 70000)
	badPTY = muxstream.AppendU32(badPTY, 24)
	badPTY = muxstream.AppendU32(badPTY, 0)
	rd := muxstream.NewReader(badPTY)
	if _, _, err := muxstream.DecodePTYAndEnv(&rd); !errors.Is(err, ports.ErrInvalidTTYSize) {
		t.Fatalf("越界 PTY 尺寸 DecodePTYAndEnv = %v, 期望 ErrInvalidTTYSize", err)
	}

	// 2. Start 前调用 ResizePTY/Signal 必须直接返回 ErrInvalidArgument 且不污染连接。
	verifyPreStartControlGuard(t, ctx)

	// 3. SpliceStreamsStrict 在无 CloseWrite 管道单侧关闭时立即退出（无僵尸隧道）。
	l1, l2 := net.Pipe()
	r1, r2 := net.Pipe()
	defer func() { _ = l2.Close(); _ = r2.Close() }()
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		if gErr := n.Go(func(context.Context) error {
			return r2.Close()
		}); gErr != nil {
			return gErr
		}
		return muxstream.SpliceStreamsStrict(ctx, l1, r1)
	})
	if err != nil {
		t.Fatalf("SpliceStreamsStrict 未在单侧关闭时及时收敛: %v", err)
	}
}

func verifyPreStartControlGuard(t *testing.T, ctx context.Context) {
	t.Helper()
	cliPipe, srvPipe := net.Pipe()
	defer func() { _ = srvPipe.Close() }()
	err := conc.RunWait(ctx, func(_ context.Context, n *conc.Nursery) error {
		rs, rErr := muxstream.NewRemoteSession(n, func() bool { return true }, cliPipe)
		if rErr != nil {
			return rErr
		}
		defer func() { _ = rs.Close() }()
		sz, _ := ports.NewTerminalSize(80, 24)
		if cErr := rs.ResizePTY(ctx, sz); !errors.Is(cErr, ports.ErrInvalidArgument) {
			return errors.New("Start 前 ResizePTY 必须返回 ErrInvalidArgument")
		}
		if cErr := rs.Signal(ctx, "TERM"); !errors.Is(cErr, ports.ErrInvalidArgument) {
			return errors.New("Start 前 Signal 必须返回 ErrInvalidArgument")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Start 前控制护栏失败: %v", err)
	}
}
