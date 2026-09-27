package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type shutdownTestListener struct {
	entered  chan struct{}
	wake     chan struct{}
	wakeOnce sync.Once
	closes   atomic.Int32
	closeErr error
}

func newShutdownTestListener() *shutdownTestListener {
	return &shutdownTestListener{entered: make(chan struct{}), wake: make(chan struct{})}
}

func (l *shutdownTestListener) Accept() (net.Conn, error) {
	close(l.entered)
	<-l.wake
	return nil, io.EOF
}
func (l *shutdownTestListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (l *shutdownTestListener) unblock() { l.wakeOnce.Do(func() { close(l.wake) }) }
func (l *shutdownTestListener) Close() error {
	n := l.closes.Add(1)
	l.unblock()
	if n > 1 {
		return errors.New("listener closed more than once")
	}
	return l.closeErr
}

func waitShutdownTestSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatal("forward shutdown did not progress")
	}
}

func TestForwardListenerClosesOnce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		closeErr error
	}{
		{name: "success"}, {name: "close failure", closeErr: errors.New("listener cleanup failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			listener := newShutdownTestListener()
			listener.closeErr = tc.closeErr
			forward := runForwardListener(ctx, listener, forwardOptions{}, nil)
			waitShutdownTestSignal(t, listener.entered)
			cancel()
			waitShutdownTestSignal(t, forward.Done())
			if err := forward.Wait(); !errors.Is(err, tc.closeErr) {
				t.Errorf("Wait = %v, want %v", err, tc.closeErr)
			}
			if got := listener.closes.Load(); got != 1 {
				t.Errorf("listener Close called %d times, want 1", got)
			}
		})
	}
}

// Hold child notification after the parent is canceled, modelling the window
// where an SSH monitor closes the transport before listener cancellation runs.
type delayedForwardCancellation struct {
	context.Context
	observed   chan struct{}
	release    chan struct{}
	propagated chan struct{}
}

func (c *delayedForwardCancellation) Value(any) any { return nil }
func (c *delayedForwardCancellation) AfterFunc(fn func()) func() bool {
	return context.AfterFunc(c.Context, func() {
		close(c.observed)
		<-c.release
		fn()
		close(c.propagated)
	})
}

func TestForwardListenerParentCancellationPrecedesNotification(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	ctx := &delayedForwardCancellation{Context: parent, observed: make(chan struct{}), release: make(chan struct{}), propagated: make(chan struct{})}
	defer func() { cancel(); close(ctx.release); waitShutdownTestSignal(t, ctx.propagated) }()
	listener := newShutdownTestListener()
	forward := runForwardListener(ctx, listener, forwardOptions{}, nil)
	waitShutdownTestSignal(t, listener.entered)
	cancel()
	waitShutdownTestSignal(t, ctx.observed)
	listener.unblock() // SSH shutdown makes the remote Accept return EOF.
	waitShutdownTestSignal(t, forward.Done())
	if err := forward.Wait(); err != nil {
		t.Fatalf("normal cancellation reported as failure: %v", err)
	}
}

func TestForwardListenerPreservesUnexpectedEOF(t *testing.T) {
	listener := newShutdownTestListener()
	forward := runForwardListener(t.Context(), listener, forwardOptions{}, nil)
	waitShutdownTestSignal(t, listener.entered)
	listener.unblock()
	waitShutdownTestSignal(t, forward.Done())
	if err := forward.Wait(); !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected listener failure was hidden: %v", err)
	}
}
