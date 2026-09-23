package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type monitoredTestConn struct {
	ssh.Conn
	closed    chan struct{}
	probeSeen chan struct{}
	closeOnce sync.Once
	probeOnce sync.Once
	blackhole bool
}

func (c *monitoredTestConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *monitoredTestConn) Wait() error {
	<-c.closed
	return io.EOF
}

func (c *monitoredTestConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	c.probeOnce.Do(func() { close(c.probeSeen) })
	if c.blackhole {
		<-c.closed
		return false, nil, io.EOF
	}
	return false, nil, nil // An unsupported keepalive reply still proves liveness.
}

func TestClientWait(t *testing.T) {
	for _, mode := range []string{"disconnect", "blackhole", "cancel idle", "cancel probe", "healthy"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			conn := &monitoredTestConn{
				closed: make(chan struct{}), probeSeen: make(chan struct{}),
				blackhole: mode == "blackhole" || mode == "cancel probe",
			}
			client := &Client{sshClient: &ssh.Client{Conn: conn}}
			done := make(chan error, 1)
			interval, timeout := 5*time.Millisecond, time.Second
			if mode == "blackhole" {
				timeout = 20 * time.Millisecond
			}
			if mode == "cancel idle" || mode == "disconnect" {
				interval = time.Hour
			}
			go func() { done <- client.wait(ctx, interval, timeout) }()
			switch mode {
			case "disconnect":
				closeTestResource(t, conn)
			case "cancel idle":
				cancel()
			case "cancel probe", "healthy":
				select {
				case <-conn.probeSeen:
				case <-time.After(time.Second):
					t.Fatal("keepalive request was not sent")
				}
				select {
				case err := <-done:
					t.Fatalf("monitor exited before cancellation: %v", err)
				default:
				}
				cancel()
			}
			select {
			case err := <-done:
				var want error
				switch mode {
				case "disconnect":
					want = io.EOF
				case "blackhole":
					want = errKeepaliveTimeout
				}
				if !errors.Is(err, want) {
					t.Fatalf("Wait() = %v, want %v", err, want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("connection monitor did not stop")
			}
			select {
			case <-conn.closed:
			default:
				t.Fatal("monitor left the transport open")
			}
		})
	}
}

func TestClientCloseAlreadyClosed(t *testing.T) {
	failure := errors.New("close failure")
	for _, tt := range []struct{ err, want error }{
		{}, {io.EOF, nil}, {net.ErrClosed, nil},
		{fmt.Errorf("close tcp: %w", net.ErrClosed), nil},
		{io.ErrUnexpectedEOF, io.ErrUnexpectedEOF}, {failure, failure},
	} {
		client := &Client{sshClient: &ssh.Client{Conn: &closeResultConn{err: tt.err}}}
		if err := client.Close(); !errors.Is(err, tt.want) {
			t.Errorf("Close() with %v = %v, want %v", tt.err, err, tt.want)
		}
	}
}
