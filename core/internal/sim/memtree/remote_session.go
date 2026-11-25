package memtree

import (
	"cmp"
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/ports"
)

// SessionFaultConfig 封装 RemoteSession 的仿真输出与错误注入参数。
type SessionFaultConfig struct {
	Output   string
	Outcome  execution.ExecutionOutcome
	StartErr error
	WaitErr  error
}

// RemoteSession 实现 ports.RemoteSession，支持前置管道获取及与 ExecStreams 互斥校验。
//
//xops:opaque
//xops:failclosed
type RemoteSession struct {
	mu                                sync.Mutex
	aliveFn                           func() bool
	cfg                               SessionFaultConfig
	initialized                       bool
	started, closed                   atomic.Bool
	stdinPipe, stdoutPipe, stderrPipe *StreamPipe
}

// NewRemoteSession 构造绑定至底层连接探活回调与故障配置的纯内存远端会话。
func NewRemoteSession(aliveFn func() bool, cfg SessionFaultConfig) *RemoteSession {
	return &RemoteSession{aliveFn: aliveFn, cfg: cfg, initialized: true}
}

func (s *RemoteSession) checkOpen(ctx context.Context, needConn bool) error {
	if ctx == nil {
		return ports.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !s.initialized || s.closed.Load() || (needConn && (s.aliveFn == nil || !s.aliveFn())) {
		return ports.ErrClosed
	}
	return nil
}

func (s *RemoteSession) allocPipe(slot **StreamPipe) (*StreamPipe, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.initialized || s.closed.Load() {
		return nil, ports.ErrClosed
	}
	if s.started.Load() || *slot != nil {
		return nil, ports.ErrInvalidArgument
	}
	*slot = NewStreamPipe()
	return *slot, nil
}

func (s *RemoteSession) StdinPipe() (io.WriteCloser, error) { return s.allocPipe(&s.stdinPipe) }
func (s *RemoteSession) StdoutPipe() (io.Reader, error)     { return s.allocPipe(&s.stdoutPipe) }
func (s *RemoteSession) StderrPipe() (io.Reader, error)     { return s.allocPipe(&s.stderrPipe) }

// BeginStartLocked 在持锁复核会话未关闭、未重复启动且流管道无冲突后标记已启动（仅供包内外白盒复核）。
func (s *RemoteSession) BeginStartLocked(streams ports.ExecStreams) error {
	if !s.initialized || s.closed.Load() {
		return ports.ErrClosed
	}
	if s.started.Load() || (s.stdinPipe != nil && streams.Stdin != nil) || (s.stdoutPipe != nil && streams.Stdout != nil) || (s.stderrPipe != nil && streams.Stderr != nil) {
		return ports.ErrInvalidArgument
	}
	s.started.Store(true)
	return nil
}

func (s *RemoteSession) Start(ctx context.Context, cmd execution.CommandPlan, streams ports.ExecStreams) error {
	if err := s.checkOpen(ctx, true); err != nil {
		return err
	}
	if s.cfg.StartErr != nil {
		return s.cfg.StartErr
	}
	if !cmd.IsValid() {
		return ports.ErrInvalidArgument
	}
	s.mu.Lock()
	err := s.BeginStartLocked(streams)
	outPipe, errPipe := s.stdoutPipe, s.stderrPipe
	s.mu.Unlock()
	if err != nil {
		return err
	}
	payload := cmp.Or(s.cfg.Output, "tck-ok\n")
	if outPipe != nil {
		_, _ = io.WriteString(outPipe, payload)
		_ = outPipe.Close()
	} else if streams.Stdout != nil {
		_, _ = io.WriteString(streams.Stdout, payload)
	}
	if errPipe != nil {
		_ = errPipe.Close()
	}
	return nil
}

func (s *RemoteSession) StartShell(ctx context.Context, streams ports.ExecStreams) error {
	if err := s.checkOpen(ctx, true); err != nil {
		return err
	}
	if ptyReq, ok := streams.PTY.Get(); ok && !ptyReq.IsValid() {
		return ports.ErrInvalidArgument
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.BeginStartLocked(streams)
}

func (s *RemoteSession) ResizePTY(ctx context.Context, size ports.TerminalSize) error {
	if err := s.checkOpen(ctx, false); err != nil {
		return err
	}
	if !size.IsValid() {
		return ports.ErrInvalidTTYSize
	}
	return nil
}

func (s *RemoteSession) Signal(ctx context.Context, sig string) error {
	if err := s.checkOpen(ctx, false); err != nil {
		return err
	}
	if sig == "" {
		return ports.ErrInvalidArgument
	}
	return nil
}

func (s *RemoteSession) Wait(ctx context.Context) (execution.ExecutionOutcome, error) {
	if err := s.checkOpen(ctx, false); err != nil {
		return nil, err
	}
	if s.cfg.WaitErr != nil {
		return nil, s.cfg.WaitErr
	}
	if !s.started.Load() {
		return nil, ports.ErrInvalidArgument
	}
	if s.cfg.Outcome != nil && s.cfg.Outcome.IsValid() {
		return s.cfg.Outcome, nil
	}
	return execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
}

func (s *RemoteSession) Close() error {
	s.closed.Store(true)
	s.mu.Lock()
	pipes := [3]*StreamPipe{s.stdinPipe, s.stdoutPipe, s.stderrPipe}
	s.mu.Unlock()
	for _, p := range pipes {
		if p != nil {
			_ = p.Close()
		}
	}
	return nil
}
