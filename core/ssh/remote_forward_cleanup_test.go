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

	cryptoSSH "golang.org/x/crypto/ssh"
)

// A failed SSH channel acceptance does not mean the remote listener queue is
// closed. A later queued channel can hold x/crypto/ssh's forward-list mutex,
// preventing listener Close until another Accept drains that queue.
type queuedRemoteCleanupListener struct {
	ctx          context.Context
	closeStarted chan struct{}
	queueDrained chan struct{}
	closed       chan struct{}
	accepts      atomic.Int32
	closes       atomic.Int32
	drainOnce    sync.Once
	closeOnce    sync.Once
	closeErr     error
	queuedConn   net.Conn
}

func (l *queuedRemoteCleanupListener) Accept() (net.Conn, error) {
	switch l.accepts.Add(1) {
	case 1:
		select {
		case <-l.closeStarted:
			return nil, io.EOF // The first queued NewChannel.Accept failed.
		case <-l.ctx.Done():
			return nil, l.ctx.Err()
		}
	case 2:
		l.drainOnce.Do(func() { close(l.queueDrained) })
		return l.queuedConn, nil
	}
	select {
	case <-l.closed:
		return nil, io.EOF
	case <-l.ctx.Done():
		return nil, l.ctx.Err()
	}
}

func (l *queuedRemoteCleanupListener) Close() error {
	if l.closes.Add(1) == 1 {
		close(l.closeStarted)
	}
	defer l.closeOnce.Do(func() { close(l.closed) })
	select {
	case <-l.queueDrained:
		return l.closeErr
	case <-l.ctx.Done():
		return l.ctx.Err()
	}
}

func (l *queuedRemoteCleanupListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 43210}
}

func TestRemoteForwardUnpublishedCleanupDrainsAfterAcceptFailure(t *testing.T) {
	closeFailure := errors.New("remote listener cleanup failed")
	for _, tc := range []struct {
		name     string
		closeErr error
	}{
		{name: "success"},
		{name: "close error", closeErr: closeFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			queuedConn, queuedPeer := net.Pipe()
			t.Cleanup(func() {
				if err := errors.Join(closeResource(queuedConn, "queued test connection"), closeResource(queuedPeer, "queued test peer")); err != nil {
					t.Error(err)
				}
			})
			if err := queuedPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			listener := &queuedRemoteCleanupListener{
				ctx: ctx, closeStarted: make(chan struct{}), queueDrained: make(chan struct{}),
				closed: make(chan struct{}), closeErr: tc.closeErr, queuedConn: queuedConn,
			}
			bounded := &remoteForwardListener{Listener: listener, client: &Client{}, timeout: time.Second}
			result := make(chan error, 1)
			done := make(chan struct{})
			go func() {
				defer close(done)
				result <- bounded.closeUnpublished()
			}()
			// Cancel releases the fixture's blocked Accept and Close paths even
			// if a regression makes cleanup stop after the first failed Accept.
			t.Cleanup(func() { cancel(); <-done })
			select {
			case err := <-result:
				if !errors.Is(err, tc.closeErr) {
					t.Fatalf("unpublished listener cleanup = %v, want %v", err, tc.closeErr)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("unpublished listener cleanup stopped draining after an Accept failure")
			}
			if got := listener.accepts.Load(); got < 2 {
				t.Fatalf("Accept called %d times, want the queued channel drained after EOF", got)
			}
			if err := bounded.Close(); !errors.Is(err, tc.closeErr) {
				t.Fatalf("repeated listener close = %v, want %v", err, tc.closeErr)
			}
			if got := listener.closes.Load(); got != 1 {
				t.Fatalf("underlying listener Close called %d times, want 1", got)
			}
			var data [1]byte
			if _, err := queuedPeer.Read(data[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("queued forwarded connection remains open after cleanup: %v", err)
			}
		})
	}
}

type lateRemoteForwardConn struct {
	cryptoSSH.Conn
	cancelForward context.CancelFunc
	closeStarted  chan struct{}
	releaseClose  chan struct{}
	closed        chan struct{}
	channels      chan cryptoSSH.NewChannel
	requests      chan *cryptoSSH.Request
	closeOnce     sync.Once
	closeReturned atomic.Bool
	cancels       atomic.Int32
}

func (c *lateRemoteForwardConn) SendRequest(name string, _ bool, _ []byte) (bool, []byte, error) {
	if name == "tcpip-forward" {
		c.cancelForward()
		<-c.closeStarted
		// The reply was already decoded when cancellation interrupted SSH.
		// Listen still registers its listener while the interrupt is finishing.
		return true, nil, nil
	}
	if name == "cancel-tcpip-forward" {
		c.cancels.Add(1)
	}
	return false, nil, io.EOF
}

func (c *lateRemoteForwardConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeStarted)
		<-c.releaseClose
		close(c.closed)
		close(c.channels)
		close(c.requests)
		c.closeReturned.Store(true)
	})
	return nil
}

func (c *lateRemoteForwardConn) Wait() error {
	<-c.closed
	return io.EOF
}

func TestRemoteForwardCanceledLateSuccessClosesListenerAndJoinsInterrupt(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	conn := &lateRemoteForwardConn{
		cancelForward: cancel, closeStarted: make(chan struct{}), releaseClose: make(chan struct{}),
		closed: make(chan struct{}), channels: make(chan cryptoSSH.NewChannel), requests: make(chan *cryptoSSH.Request),
	}
	client := &Client{sshClient: cryptoSSH.NewClient(conn, conn.channels, conn.requests)}
	result := make(chan remoteForwardResult, 1)
	done := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(conn.releaseClose) }) }
	go func() {
		defer close(done)
		forward, err := client.RemoteForward(ctx, "127.0.0.1:43210", "127.0.0.1:43211")
		result <- remoteForwardResult{forward: forward, err: err}
	}()
	// Releasing the interrupt barrier and canceling the context ensure both
	// fixture Close and the forwarding call exit on assertion failures too.
	t.Cleanup(func() {
		release()
		cancel()
		if err := client.Close(); err != nil {
			t.Error(err)
		}
		<-done
	})
	select {
	case <-conn.closeStarted:
	case <-time.After(time.Second):
		t.Fatal("forward cancellation did not interrupt SSH")
	}
	select {
	case got := <-result:
		t.Fatalf("forward returned before its interrupt callback finished: %v", got.err)
	case <-time.After(25 * time.Millisecond):
	}
	release()
	select {
	case got := <-result:
		if got.forward != nil || !errors.Is(got.err, context.Canceled) {
			t.Fatalf("late canceled forward = %v, %v; want nil, canceled", got.forward, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("late remote listener was not cleaned after cancellation")
	}
	if !conn.closeReturned.Load() {
		t.Fatal("forward returned without joining the interrupt callback")
	}
	if got := conn.cancels.Load(); got != 1 {
		t.Fatalf("late listener cancel-tcpip-forward requests = %d, want 1", got)
	}
}
