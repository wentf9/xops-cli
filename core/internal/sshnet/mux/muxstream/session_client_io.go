package muxstream

import (
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/ports"
)

func (s *RemoteSession) startBackgroundPumps(stdinSrc io.Reader, closeEmptyStdin bool) error {
	rDone := make(chan struct{})
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		close(rDone)
		return ports.ErrClosed
	}
	s.readerDone = rDone
	stdinR := s.stdinPipeR
	stdinTaken := s.stdinTaken
	s.mu.Unlock()

	if err := s.lifeNursery.Go(func(context.Context) error {
		defer close(rDone)
		s.readServerLoop()
		return nil
	}); err != nil {
		close(rDone)
		return ports.ErrClosed
	}
	if stdinTaken {
		return s.spawnStdinPump(stdinR)
	}
	if stdinSrc != nil {
		return s.spawnStdinPump(stdinSrc)
	}
	if closeEmptyStdin {
		_ = s.fw.Write(SessMsgStdinEOF, nil)
	}
	return nil
}

func (s *RemoteSession) spawnStdinPump(src io.Reader) error {
	done := make(chan struct{})
	s.mu.Lock()
	if s.closed.Load() {
		s.mu.Unlock()
		close(done)
		return ports.ErrClosed
	}
	s.stdinPumpDone = done
	s.mu.Unlock()

	if err := s.lifeNursery.Go(func(context.Context) error {
		defer close(done)
		s.pumpStdinLoop(src)
		return nil
	}); err != nil {
		close(done)
		return ports.ErrClosed
	}
	return nil
}

func (s *RemoteSession) pumpStdinLoop(src io.Reader) {
	buf := make([]byte, CopyChunkBytes)
	for !s.closed.Load() {
		n, err := src.Read(buf)
		if s.closed.Load() {
			return
		}
		if n > 0 {
			if wErr := s.fw.Write(SessMsgStdinData, AppendBytes(nil, buf[:n])); wErr != nil {
				return
			}
		}
		if err != nil {
			_ = s.fw.Write(SessMsgStdinEOF, nil)
			return
		}
	}
}

func (s *RemoteSession) readServerLoop() {
	defer s.closeOutputPipesEOF()
	defer s.failAllCtrlPending(ports.ErrClosed)
	for {
		msgType, body, err := ReadPacket(s.conn)
		if err != nil {
			s.deliverTransportLost(err)
			return
		}
		if done, _ := s.handleServerFrame(msgType, body); done {
			return
		}
	}
}

func (s *RemoteSession) handleServerFrame(msgType uint32, body []byte) (bool, error) {
	rd := NewReader(body)
	switch msgType {
	case SessMsgStdoutData:
		if data, err := rd.ReadBytes(); err != nil {
			return false, err
		} else {
			s.writeOutput(true, data)
		}
	case SessMsgStdoutEOF:
		s.closeSingleOutputPipe(true, false)
	case SessMsgStderrData:
		if data, err := rd.ReadBytes(); err != nil {
			return false, err
		} else {
			s.writeOutput(false, data)
		}
	case SessMsgStderrEOF:
		s.closeSingleOutputPipe(false, false)
	case SessMsgCtrlReply:
		s.deliverCtrlReply(&rd)
	case SessMsgOutcome:
		return true, s.deliverOutcomeFrame(body)
	}
	return false, nil
}

func (s *RemoteSession) registerCtrlPending(reqID uint32) (chan error, error) {
	s.ctrlMu.Lock()
	defer s.ctrlMu.Unlock()
	if s.pendingCtrl == nil || s.closed.Load() {
		return nil, ports.ErrClosed
	}
	ch := make(chan error, 1)
	s.pendingCtrl[reqID] = ch
	return ch, nil
}

func (s *RemoteSession) unregisterCtrlPending(reqID uint32) {
	s.ctrlMu.Lock()
	if s.pendingCtrl != nil {
		delete(s.pendingCtrl, reqID)
	}
	s.ctrlMu.Unlock()
}

func (s *RemoteSession) failAllCtrlPending(err error) {
	s.ctrlMu.Lock()
	pend := s.pendingCtrl
	s.pendingCtrl = nil
	s.ctrlMu.Unlock()
	for _, ch := range pend {
		ch <- err
	}
}

func (s *RemoteSession) deliverCtrlReply(rd *Reader) {
	reqID, e0 := rd.ReadUint32()
	okFlag, e1 := rd.ReadUint32()
	msg, e2 := rd.ReadString()
	var cErr error
	if err := FirstErr(e0, e1, e2); err != nil {
		cErr = err
	} else if okFlag == 0 {
		cErr = domi18n.E(domi18n.KeyCommonDetail, domi18n.BoundStr("detail", msg))
	}
	s.ctrlMu.Lock()
	ch := s.pendingCtrl[reqID]
	delete(s.pendingCtrl, reqID)
	s.ctrlMu.Unlock()
	if ch != nil {
		ch <- cErr
	}
}

func (s *RemoteSession) deliverOutcomeFrame(body []byte) error {
	out, wErr, decErr := DecodeOutcomePayload(body)
	if decErr != nil {
		s.deliverTransportLost(decErr)
		return decErr
	}
	// 将客户端本地 MaxOutputBytes 截断状态准确回填至 OutcomeCompleted.Truncated()。
	if comp, ok := out.(*execution.OutcomeCompleted); ok && comp.IsValid() && s.truncated.Load() && !comp.Truncated() {
		if rebuilt, err := execution.NewOutcomeCompleted(comp.Status(), true); err == nil {
			out = rebuilt
		}
	}
	select {
	case s.outcomeCh <- sessionWaitResult{outcome: out, err: wErr}:
	default:
	}
	return nil
}

func (s *RemoteSession) deliverTransportLost(err error) {
	out, _ := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "mux_transport_lost", err.Error())
	select {
	case s.outcomeCh <- sessionWaitResult{outcome: out, err: err}:
	default:
	}
}

func (s *RemoteSession) writeOutput(isStdout bool, data []byte) {
	if len(data) == 0 || s.closed.Load() {
		return
	}
	s.mu.Lock()
	var bp *bufferedPipe
	var dst io.Writer
	if isStdout {
		bp, dst = s.stdoutPipe, s.stdoutDst
	} else {
		bp, dst = s.stderrPipe, s.stderrDst
	}
	maxBytes := s.maxOutputBytes
	s.mu.Unlock()

	if bp != nil {
		bp.writeChunk(data)
		return
	}
	if dst == nil {
		return
	}
	chunk := sliceOutputBudget(data, maxBytes, &s.outputUsed, &s.truncated)
	if len(chunk) == 0 {
		return
	}
	s.writeGuardedDst(isStdout, dst, chunk)
}

func (s *RemoteSession) writeGuardedDst(isStdout bool, dst io.Writer, chunk []byte) {
	s.outMu.Lock()
	defer s.outMu.Unlock()
	if s.discardOutput {
		return
	}
	if _, err := dst.Write(chunk); err != nil {
		s.recordIOErr(err)
		// 首次写入失败后静默丢弃后续数据块以继续排空帧流，并由 Wait 暴露错误。
		s.mu.Lock()
		if isStdout {
			s.stdoutDst = io.Discard
		} else {
			s.stderrDst = io.Discard
		}
		s.mu.Unlock()
	}
}

func (s *RemoteSession) markDiscardOutput() {
	s.outMu.Lock()
	s.discardOutput = true
	s.outMu.Unlock()
}

func (s *RemoteSession) recordIOErr(err error) {
	if err == nil {
		return
	}
	s.ioErrMu.Lock()
	if s.ioErr == nil {
		s.ioErr = err
	}
	s.ioErrMu.Unlock()
}

func (s *RemoteSession) firstIOErr() error {
	s.ioErrMu.Lock()
	defer s.ioErrMu.Unlock()
	return s.ioErr
}

func sliceOutputBudget(data []byte, maxBytes uint64, used *atomic.Uint64, truncated *atomic.Bool) []byte {
	if maxBytes == 0 {
		return data
	}
	for {
		cur := used.Load()
		if cur >= maxBytes {
			truncated.Store(true)
			return nil
		}
		take := min(uint64(len(data)), maxBytes-cur)
		if used.CompareAndSwap(cur, cur+take) {
			if take < uint64(len(data)) {
				truncated.Store(true)
			}
			return data[:take]
		}
	}
}

func (s *RemoteSession) closeSingleOutputPipe(isStdout, abort bool) {
	s.mu.Lock()
	var bp *bufferedPipe
	if isStdout {
		bp, s.stdoutPipe = s.stdoutPipe, nil
	} else {
		bp, s.stderrPipe = s.stderrPipe, nil
	}
	s.mu.Unlock()
	if bp == nil {
		return
	}
	if abort {
		bp.closeAbort()
		return
	}
	bp.closeEOF()
}

func (s *RemoteSession) closeOutputPipesEOF() {
	s.closeSingleOutputPipe(true, false)
	s.closeSingleOutputPipe(false, false)
}

func (s *RemoteSession) closeOutputPipesAbort() {
	s.closeSingleOutputPipe(true, true)
	s.closeSingleOutputPipe(false, true)
}

func (s *RemoteSession) currentReaderDone() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readerDone
}

type idempotentPipeWriter struct {
	pw   *io.PipeWriter
	once sync.Once
}

func (w *idempotentPipeWriter) Write(p []byte) (int, error) { return w.pw.Write(p) }

func (w *idempotentPipeWriter) Close() error {
	w.once.Do(func() { _ = w.pw.Close() })
	return nil
}
