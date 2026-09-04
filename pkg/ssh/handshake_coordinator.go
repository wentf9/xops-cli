package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ErrHandshakeClosed 表示握手协调器已关闭或已被 fail-closed 中断。
var ErrHandshakeClosed = errors.New("handshake coordinator is closed")

// handshakeCoordinator coordinates the network handshake timeout with user interaction pauses.
// When an interactive callback (e.g. host key confirmation, password prompt, passphrase) is invoked,
// the coordinator pauses the network deadline and underlying socket timeout so that user typing time
// is governed solely by the interaction timeout without causing the SSH network transport to time out.
type handshakeCoordinator struct {
	parentCtx context.Context
	timeout   time.Duration

	mu     sync.Mutex
	conn   net.Conn
	timer  *time.Timer
	ctx    context.Context
	cancel context.CancelCauseFunc
	paused bool
	closed bool
}

func newHandshakeCoordinator(parentCtx context.Context, timeout time.Duration) *handshakeCoordinator {
	ctx, cancel := context.WithCancelCause(parentCtx)
	hc := &handshakeCoordinator{
		parentCtx: parentCtx,
		timeout:   timeout,
		ctx:       ctx,
		cancel:    cancel,
	}
	if timeout > 0 {
		hc.mu.Lock()
		hc.timer = time.AfterFunc(timeout, func() {
			hc.mu.Lock()
			defer hc.mu.Unlock()
			if !hc.paused && !hc.closed {
				hc.failClosed(context.DeadlineExceeded)
			}
		})
		hc.mu.Unlock()
	}
	return hc
}

func (hc *handshakeCoordinator) Context() context.Context {
	return hc.ctx
}

func (hc *handshakeCoordinator) Err() error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if err := context.Cause(hc.ctx); err != nil {
		return err
	}
	if err := hc.ctx.Err(); err != nil {
		return err
	}
	if hc.closed {
		return ErrHandshakeClosed
	}
	return nil
}

func isIgnorableDeadlineError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "deadline not supported") ||
		strings.Contains(errStr, "use of closed network connection")
}

func (hc *handshakeCoordinator) failClosed(cause error) {
	hc.closed = true
	hc.paused = false
	if hc.timer != nil {
		hc.timer.Stop()
	}
	if cause == nil {
		cause = ErrHandshakeClosed
	} else if !errors.Is(cause, ErrHandshakeClosed) {
		cause = errors.Join(ErrHandshakeClosed, cause)
	}
	hc.cancel(cause)
}

func (hc *handshakeCoordinator) FailClosed(cause error) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.failClosed(cause)
}

func (hc *handshakeCoordinator) SetConn(conn net.Conn) error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if err := hc.ctx.Err(); err != nil {
		cause := context.Cause(hc.ctx)
		if cause == nil {
			cause = err
		}
		hc.failClosed(cause)
		return cause
	}
	if hc.closed {
		return ErrHandshakeClosed
	}
	hc.conn = conn
	if !hc.paused && conn != nil && hc.timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(hc.timeout)); err != nil {
			if !isIgnorableDeadlineError(err) {
				hc.failClosed(err)
				return fmt.Errorf("set initial handshake deadline failed: %w", err)
			}
		}
	}
	return nil
}

func (hc *handshakeCoordinator) Pause() error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if err := hc.ctx.Err(); err != nil {
		cause := context.Cause(hc.ctx)
		if cause == nil {
			cause = err
		}
		hc.failClosed(cause)
		return cause
	}
	if hc.closed {
		if cause := context.Cause(hc.ctx); cause != nil && !errors.Is(cause, hc.parentCtx.Err()) {
			return cause
		}
		return ErrHandshakeClosed
	}
	if hc.paused {
		return nil
	}
	if hc.conn != nil {
		if err := hc.conn.SetDeadline(time.Time{}); err != nil {
			if !isIgnorableDeadlineError(err) {
				hc.failClosed(err)
				return fmt.Errorf("clear handshake deadline on pause failed: %w", err)
			}
		}
	}
	hc.paused = true
	if hc.timer != nil {
		hc.timer.Stop()
	}
	return nil
}

func (hc *handshakeCoordinator) Resume() error {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if err := hc.ctx.Err(); err != nil {
		cause := context.Cause(hc.ctx)
		if cause == nil {
			cause = err
		}
		hc.failClosed(cause)
		return cause
	}
	if hc.closed {
		if cause := context.Cause(hc.ctx); cause != nil && !errors.Is(cause, hc.parentCtx.Err()) {
			return cause
		}
		return ErrHandshakeClosed
	}
	if !hc.paused {
		return nil
	}
	if hc.conn != nil && hc.timeout > 0 {
		if err := hc.conn.SetDeadline(time.Now().Add(hc.timeout)); err != nil {
			if !isIgnorableDeadlineError(err) {
				hc.failClosed(err)
				return fmt.Errorf("restore handshake deadline on resume failed: %w", err)
			}
		}
	}
	hc.paused = false
	if hc.timer != nil && hc.timeout > 0 {
		hc.timer.Reset(hc.timeout)
	}
	return nil
}

func (hc *handshakeCoordinator) Close() {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	if hc.closed {
		return
	}
	hc.failClosed(ErrHandshakeClosed)
}

type coordinatingPrompter struct {
	prompter    SecretPrompter
	coordinator *handshakeCoordinator
}

func (p *coordinatingPrompter) PromptSecret(ctx context.Context, req SecretRequest) (secretResult string, retErr error) {
	if p.coordinator != nil {
		if err := p.coordinator.Pause(); err != nil {
			return "", err
		}
		defer func() {
			if resumeErr := p.coordinator.Resume(); resumeErr != nil {
				retErr = errors.Join(retErr, resumeErr)
				secretResult = ""
			}
		}()
	}
	return p.prompter.PromptSecret(ctx, req)
}
