package remotesess

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/ports"
)

// idempotentStdinPipe 封装 x/crypto/ssh.Session.StdinPipe：
// 当快速远端命令在调用方半关闭标准输入前已退出并关闭通道时，底层 CloseWrite 可能返回 io.EOF 或 net.ErrClosed，
// 本封装保证 Close 幂等且对已关闭/已 EOF 通道平滑返回 nil。
type idempotentStdinPipe struct {
	w         io.WriteCloser
	closeOnce sync.Once
	closeErr  error
}

func (p *idempotentStdinPipe) Write(b []byte) (int, error) {
	return p.w.Write(b)
}

func (p *idempotentStdinPipe) Close() error {
	p.closeOnce.Do(func() {
		err := p.w.Close()
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		p.closeErr = err
	})
	return p.closeErr
}

func buildCommandStdinReader(cmd execution.CommandPlan, userStdin io.Reader) io.Reader {
	scriptBody, hasScript := cmd.StdinPayload()
	if !hasScript {
		return userStdin
	}
	if userStdin == nil {
		return strings.NewReader(scriptBody)
	}
	return io.MultiReader(strings.NewReader(scriptBody), userStdin)
}

type outputPumpTarget struct {
	dst io.Writer
	src io.Reader
}

func (s *Session) startIOPumps(
	streams ports.ExecStreams,
	maxOutputBytes uint64,
	stdinSrc io.Reader,
	closeEmptyStdin, inTaken, outTaken, errTaken bool,
) error {
	targets := s.collectOutputPumpTargets(streams, outTaken, errTaken)
	if err := s.startOutputPumps(targets, maxOutputBytes); err != nil {
		return err
	}
	if err := s.startClaimedOutputBridges(outTaken, errTaken); err != nil {
		return err
	}
	return s.startStdinPump(stdinSrc, closeEmptyStdin, inTaken)
}

type pipeBridgeTarget struct {
	pw  *io.PipeWriter
	src io.Reader
}

// startClaimedOutputBridges 为调用方通过 StdoutPipe()/StderrPipe() 借出的输出流分别启动独立桥接协程：
// 任一流读到 EOF 即刻关闭各自 io.PipeWriter（互不耦合，亦不计入外层 MaxOutputBytes），
// 若 Session.Close 提前关闭写端则切换为丢弃排空直至上游传输终止，避免半开黑洞永久阻塞调用方读取。
func (s *Session) startClaimedOutputBridges(outTaken, errTaken bool) error {
	bridges := s.collectClaimedBridges(outTaken, errTaken)
	if len(bridges) == 0 {
		return nil
	}
	done := make(chan struct{})
	s.mu.Lock()
	s.bridgesDone = done
	s.mu.Unlock()
	var rem atomic.Int32
	rem.Store(int32(len(bridges)))
	doneOne := func() {
		if rem.Add(-1) == 0 {
			close(done)
		}
	}
	for i, b := range bridges {
		bridge := b
		if err := s.lifeNursery.Go(func(context.Context) error {
			defer doneOne()
			s.pumpClaimedBridge(bridge.pw, bridge.src)
			return nil
		}); err != nil {
			for j := i; j < len(bridges); j++ {
				_ = bridges[j].pw.Close()
				doneOne()
			}
			return ports.ErrClosed
		}
	}
	return nil
}

func (s *Session) collectClaimedBridges(outTaken, errTaken bool) []pipeBridgeTarget {
	s.mu.Lock()
	outW, errW := s.outBridgeW, s.errBridgeW
	s.mu.Unlock()
	var bridges []pipeBridgeTarget
	if outTaken && outW != nil {
		bridges = append(bridges, pipeBridgeTarget{pw: outW, src: s.stdoutPipe})
	}
	if errTaken && errW != nil {
		bridges = append(bridges, pipeBridgeTarget{pw: errW, src: s.stderrPipe})
	}
	return bridges
}

func (s *Session) pumpClaimedBridge(pw *io.PipeWriter, src io.Reader) {
	defer func() { _ = pw.Close() }()
	buf := make([]byte, sessionCopyBufferBytes)
	dropping := false
	for {
		n, rErr := src.Read(buf)
		if n > 0 && !dropping {
			dropping = s.writeBridgeChunk(pw, buf[:n]) != nil
		}
		if rErr != nil {
			if !errors.Is(rErr, io.EOF) && !dropping {
				_ = pw.CloseWithError(rErr)
			}
			return
		}
	}
}

func (s *Session) writeBridgeChunk(pw *io.PipeWriter, chunk []byte) error {
	if s.closed.Load() {
		return ports.ErrClosed
	}
	_, err := pw.Write(chunk)
	return err
}

func (s *Session) closeBridgeWriters() {
	s.mu.Lock()
	outW, errW := s.outBridgeW, s.errBridgeW
	s.mu.Unlock()
	if outW != nil {
		_ = outW.Close()
	}
	if errW != nil {
		_ = errW.Close()
	}
}

func (s *Session) currentBridgesDone() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bridgesDone
}

func (s *Session) collectOutputPumpTargets(streams ports.ExecStreams, outTaken, errTaken bool) []outputPumpTarget {
	var targets []outputPumpTarget
	if !outTaken {
		targets = append(targets, outputPumpTarget{dst: streams.Stdout, src: s.stdoutPipe})
	}
	if !errTaken {
		targets = append(targets, outputPumpTarget{dst: streams.Stderr, src: s.stderrPipe})
	}
	return targets
}

func (s *Session) startOutputPumps(targets []outputPumpTarget, maxOutputBytes uint64) error {
	if len(targets) == 0 {
		return nil
	}
	var budget atomic.Uint64
	done := make(chan struct{})
	s.mu.Lock()
	s.pumpsDone = done
	s.mu.Unlock()
	var rem atomic.Int32
	rem.Store(int32(len(targets)))
	finishOne := func(pErr error) {
		s.recordIOErr(pErr)
		if rem.Add(-1) == 0 {
			close(done)
		}
	}
	for i, tgt := range targets {
		if err := s.spawnOutputPump(tgt.dst, tgt.src, maxOutputBytes, &budget, finishOne); err != nil {
			// 为当前及后续尚未启动的输出泵补齐计数递减，确保 pumpsDone 立即关闭，避免 Close() 无谓空等。
			for j := i; j < len(targets); j++ {
				finishOne(ports.ErrClosed)
			}
			return ports.ErrClosed
		}
	}
	return nil
}

func (s *Session) spawnOutputPump(
	dst io.Writer,
	src io.Reader,
	maxBytes uint64,
	budget *atomic.Uint64,
	finishOne func(error),
) error {
	if dst == nil {
		dst = io.Discard
	}
	if err := s.lifeNursery.Go(func(context.Context) error {
		err := copyBoundedOutput(dst, src, maxBytes, budget, &s.truncated, &s.outMu, &s.discardOutput)
		finishOne(err)
		return nil
	}); err != nil {
		return ports.ErrClosed
	}
	return nil
}

func (s *Session) startStdinPump(stdinSrc io.Reader, closeEmptyStdin, inTaken bool) error {
	if inTaken {
		return nil
	}
	if stdinSrc == nil {
		if closeEmptyStdin {
			_ = s.stdinPipe.Close()
		}
		return nil
	}
	inCtx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.stdinCancel = cancel
	s.mu.Unlock()
	if err := s.lifeNursery.Go(func(context.Context) error {
		defer cancel()
		return copyStdinToPipe(inCtx, s.stdinPipe, stdinSrc)
	}); err != nil {
		cancel()
		return ports.ErrClosed
	}
	return nil
}

func (s *Session) recordIOErr(err error) {
	if err == nil {
		return
	}
	s.ioErrMu.Lock()
	if s.ioErr == nil {
		s.ioErr = err
	}
	s.ioErrMu.Unlock()
}

func (s *Session) firstIOErr() error {
	s.ioErrMu.Lock()
	defer s.ioErrMu.Unlock()
	return s.ioErr
}

func (s *Session) markDiscardOutput() {
	s.outMu.Lock()
	s.discardOutput = true
	s.outMu.Unlock()
}

func (s *Session) cancelStdin() {
	s.mu.Lock()
	cancel := s.stdinCancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Session) currentPumpsDone() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pumpsDone
}

// copyBoundedOutput 排空远端输出流至 EOF：
//   - 若超过 CommandPlan.MaxOutputBytes 上限，置位 truncated 并继续排空，避免 SSH 流控窗口耗尽死锁；
//   - 若 dst.Write 首次返回错误，记录 firstWriteErr 并立即切换至 io.Discard 排空到底，
//     防止流控反压卡死远端进程的同时向 Wait 暴露本地写失败；
//   - 每次写入受 outMu 与 discard 标志门控，确保 Wait 取消或 Close 返回后绝不触碰调用方缓冲。
func copyBoundedOutput(
	dst io.Writer,
	src io.Reader,
	maxBytes uint64,
	used *atomic.Uint64,
	truncated *atomic.Bool,
	outMu *sync.Mutex,
	discard *bool,
) error {
	var firstWriteErr error
	buf := make([]byte, sessionCopyBufferBytes)
	for {
		n, rErr := src.Read(buf)
		if n > 0 && dst != nil && firstWriteErr == nil {
			if chunk := sliceWithinOutputBudget(buf[:n], maxBytes, used, truncated); len(chunk) > 0 {
				dst, firstWriteErr = writeGuardedChunk(dst, chunk, outMu, discard)
			}
		}
		if rErr != nil {
			if firstWriteErr != nil {
				return firstWriteErr
			}
			if errors.Is(rErr, io.EOF) {
				return nil
			}
			return rErr
		}
	}
}

func writeGuardedChunk(dst io.Writer, chunk []byte, outMu *sync.Mutex, discard *bool) (io.Writer, error) {
	outMu.Lock()
	defer outMu.Unlock()
	if *discard {
		return io.Discard, nil
	}
	if _, err := dst.Write(chunk); err != nil {
		return io.Discard, err
	}
	return dst, nil
}

func sliceWithinOutputBudget(data []byte, maxBytes uint64, used *atomic.Uint64, truncated *atomic.Bool) []byte {
	if maxBytes == 0 {
		return data
	}
	for {
		cur := used.Load()
		if cur >= maxBytes {
			truncated.Store(true)
			return nil
		}
		rem := maxBytes - cur
		take := min(uint64(len(data)), rem)
		if used.CompareAndSwap(cur, cur+take) {
			if take < uint64(len(data)) {
				truncated.Store(true)
			}
			return data[:take]
		}
	}
}

func copyStdinToPipe(ctx context.Context, dst io.WriteCloser, src io.Reader) error {
	defer func() { _ = dst.Close() }()
	buf := make([]byte, sessionCopyBufferBytes)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, rErr := src.Read(buf)
		if n > 0 {
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return nil
			}
		}
		if rErr != nil {
			return nil
		}
	}
}
