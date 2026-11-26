package muxstream

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/ports"
)

func (s *RemoteSession) startBackgroundPumps(stdinSrc io.Reader, closeEmptyStdin bool) error {
	rDone := make(chan struct{})
	s.mu.Lock()
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
	s.stdinPumpDone = done
	s.mu.Unlock()
	if err := s.lifeNursery.Go(func(context.Context) error {
		defer close(done)
		buf := make([]byte, CopyChunkBytes)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if wErr := s.fw.Write(SessMsgStdinData, AppendBytes(nil, buf[:n])); wErr != nil {
					return nil
				}
			}
			if err != nil {
				_ = s.fw.Write(SessMsgStdinEOF, nil)
				return nil
			}
		}
	}); err != nil {
		close(done)
		return ports.ErrClosed
	}
	return nil
}

func (s *RemoteSession) readServerLoop() {
	defer s.closeOutputPipes()
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
		s.closeSingleOutputPipe(true)
	case SessMsgStderrData:
		if data, err := rd.ReadBytes(); err != nil {
			return false, err
		} else {
			s.writeOutput(false, data)
		}
	case SessMsgStderrEOF:
		s.closeSingleOutputPipe(false)
	case SessMsgCtrlReply:
		s.deliverCtrlReply(&rd)
	case SessMsgOutcome:
		return true, s.deliverOutcomeFrame(body)
	}
	return false, nil
}

func (s *RemoteSession) deliverCtrlReply(rd *Reader) {
	okFlag, e1 := rd.ReadUint32()
	msg, e2 := rd.ReadString()
	var cErr error
	if err := FirstErr(e1, e2); err != nil {
		cErr = err
	} else if okFlag == 0 {
		cErr = errors.New(msg)
	}
	select {
	case s.ctrlCh <- cErr:
	default:
	}
}

func (s *RemoteSession) deliverOutcomeFrame(body []byte) error {
	out, wErr, decErr := DecodeOutcomePayload(body)
	if decErr != nil {
		s.deliverTransportLost(decErr)
		return decErr
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
	var pw *io.PipeWriter
	var dst io.Writer
	if isStdout {
		pw, dst = s.stdoutPipeW, s.stdoutDst
	} else {
		pw, dst = s.stderrPipeW, s.stderrDst
	}
	maxBytes := s.maxOutputBytes
	s.mu.Unlock()

	if pw != nil {
		_, _ = pw.Write(data)
		return
	}
	if dst == nil {
		return
	}
	chunk := sliceOutputBudget(data, maxBytes, &s.outputUsed, &s.truncated)
	if len(chunk) > 0 {
		_, _ = dst.Write(chunk)
	}
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

func (s *RemoteSession) closeSingleOutputPipe(isStdout bool) {
	s.mu.Lock()
	var pw *io.PipeWriter
	if isStdout {
		pw, s.stdoutPipeW = s.stdoutPipeW, nil
	} else {
		pw, s.stderrPipeW = s.stderrPipeW, nil
	}
	s.mu.Unlock()
	if pw != nil {
		_ = pw.Close()
	}
}

func (s *RemoteSession) closeOutputPipes() {
	s.closeSingleOutputPipe(true)
	s.closeSingleOutputPipe(false)
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
