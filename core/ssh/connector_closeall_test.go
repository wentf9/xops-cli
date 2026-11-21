package ssh

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

type closeResultConn struct {
	ssh.Conn
	err   error
	calls atomic.Int32
}

func (c *closeResultConn) Close() error {
	c.calls.Add(1)
	return c.err
}

func TestConnector_CloseAll_CloseResults(t *testing.T) {
	closeFailure := errors.New("transport close failed")
	for _, tt := range []struct {
		name string
		err  error
		want error
	}{
		{name: "success"},
		{name: "EOF", err: io.EOF},
		{name: "wrapped EOF", err: fmt.Errorf("channel closed: %w", io.EOF)},
		{name: "already closed", err: net.ErrClosed},
		{name: "wrapped already closed", err: fmt.Errorf("transport closed: %w", net.ErrClosed)},
		{name: "unexpected EOF", err: io.ErrUnexpectedEOF, want: io.ErrUnexpectedEOF},
		{name: "close failure", err: closeFailure, want: closeFailure},
	} {
		t.Run(tt.name, func(t *testing.T) {
			connector := newTestConnector(&mockConfigStore{})
			conn := &closeResultConn{err: tt.err}
			other := &closeResultConn{}
			targetKey := DigestClientConfig(&ClientConfig{NodeID: "target"}, ZeroHopDigest)
			otherKey := DigestClientConfig(&ClientConfig{NodeID: "other"}, ZeroHopDigest)
			if _, err := connector.pool.Publish(targetKey, &PooledClient{SSHClient: &ssh.Client{Conn: conn}}, nil, nil); err != nil {
				t.Fatalf("publish target failed: %v", err)
			}
			if _, err := connector.pool.Publish(otherKey, &PooledClient{SSHClient: &ssh.Client{Conn: other}}, nil, nil); err != nil {
				t.Fatalf("publish other failed: %v", err)
			}

			var wg sync.WaitGroup
			for range 10 {
				wg.Go(func() {
					if err := connector.CloseAll(); !errors.Is(err, tt.want) {
						t.Errorf("CloseAll() = %v, want %v", err, tt.want)
					}
				})
			}
			wg.Wait()
			if conn.calls.Load() != 1 || other.calls.Load() != 1 {
				t.Errorf("close calls = (%d, %d), want (1, 1)", conn.calls.Load(), other.calls.Load())
			}
			if connector.pool.Count() != 0 {
				t.Fatal("client pool was not cleared")
			}
		})
	}
}

func TestConnector_CloseAll_Idempotent(t *testing.T) {
	c := &Connector{
		pool:      newConnPool(),
		closeDone: make(chan struct{}),
	}
	c.closeErr = fmt.Errorf("initial close error")
	c.closed = true
	close(c.closeDone)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := c.CloseAll()
			if err == nil || err.Error() != "initial close error" {
				t.Errorf("expected 'initial close error', got %v", err)
			}
		}()
	}
	wg.Wait()
}
