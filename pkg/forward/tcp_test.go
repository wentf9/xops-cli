package forward

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

type shortTCPWriteConn struct {
	bytes.Buffer
	maxWrite    int
	deadlineErr error
}

func (c *shortTCPWriteConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *shortTCPWriteConn) Close() error                     { return nil }
func (c *shortTCPWriteConn) LocalAddr() net.Addr              { return nil }
func (c *shortTCPWriteConn) RemoteAddr() net.Addr             { return nil }
func (c *shortTCPWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *shortTCPWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *shortTCPWriteConn) SetWriteDeadline(time.Time) error { return c.deadlineErr }
func (c *shortTCPWriteConn) Write(p []byte) (int, error) {
	if c.maxWrite == 0 {
		return 0, nil
	}
	if len(p) > c.maxWrite {
		p = p[:c.maxWrite]
	}
	return c.Buffer.Write(p)
}

func TestWriteTCPBytes(t *testing.T) {
	t.Run("continues after short writes", func(t *testing.T) {
		conn := &shortTCPWriteConn{maxWrite: 2}
		if err := writeTCPBytes(conn, []byte("abcdef")); err != nil {
			t.Fatalf("writeTCPBytes failed: %v", err)
		}
		if got := conn.String(); got != "abcdef" {
			t.Fatalf("got %q, want %q", got, "abcdef")
		}
	})

	t.Run("rejects zero progress", func(t *testing.T) {
		if err := writeTCPBytes(&shortTCPWriteConn{}, []byte("x")); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("got %v, want io.ErrShortWrite", err)
		}
	})

	t.Run("propagates deadline error", func(t *testing.T) {
		wantErr := errors.New("deadline unavailable")
		err := writeTCPBytes(&shortTCPWriteConn{maxWrite: 1, deadlineErr: wantErr}, []byte("x"))
		if !errors.Is(err, wantErr) {
			t.Fatalf("got %v, want wrapped deadline error", err)
		}
	})
}

// startEchoServer starts a TCP echo server and returns its address.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() {
					if err := c.Close(); err != nil {
						t.Logf("Close failed: %v", err)
					}
				}()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func TestTCPForwarder_ForwardsData(t *testing.T) {
	echoAddr := startEchoServer(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-alloc listen: %v", err)
	}
	forwardAddr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Logf("Close failed: %v", err)
	}

	f := NewTCPForwarder(forwardAddr, echoAddr)
	errCh := make(chan error, 1)
	go func() { errCh <- f.Run(t.Context()) }()

	// wait for forwarder to start
	var conn net.Conn
	for range 20 {
		conn, err = net.DialTimeout("tcp", forwardAddr, 50*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect to forwarder: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	}()

	msg := []byte("hello forwarder")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("expected %q, got %q", msg, buf)
	}
}

func TestTCPForwarder_CtxCancel(t *testing.T) {
	echoAddr := startEchoServer(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-alloc listen: %v", err)
	}
	forwardAddr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Logf("Close failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	f := NewTCPForwarder(forwardAddr, echoAddr)
	errCh := make(chan error, 1)
	go func() { errCh <- f.Run(ctx) }()

	// let the forwarder start
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned non-nil error after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after ctx cancel")
	}
}

func TestTCPForwarder_ConnCleanupOnCancel(t *testing.T) {
	echoAddr := startEchoServer(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pre-alloc listen: %v", err)
	}
	forwardAddr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Logf("Close failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	f := NewTCPForwarder(forwardAddr, echoAddr)
	errCh := make(chan error, 1)
	go func() { errCh <- f.Run(ctx) }()

	// wait for forwarder to start
	var conn net.Conn
	for range 20 {
		conn, err = net.DialTimeout("tcp", forwardAddr, 50*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect to forwarder: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	}()

	// Cancel context
	cancel()

	// Wait for connection to be closed by forwarder
	errReadCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		_, err := conn.Read(buf)
		errReadCh <- err
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Run returned non-nil error after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after ctx cancel")
	}

	select {
	case err := <-errReadCh:
		if err == nil {
			t.Error("expected connection to be closed, but Read returned nil error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("connection was not closed by forwarder after cancel")
	}
}

func TestTCPForwarder_BlackholeTargetTimeout(t *testing.T) {
	blackholeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blackhole listen failed: %v", err)
	}
	defer func() {
		_ = blackholeLn.Close()
	}()

	forwardLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("forward listen failed: %v", err)
	}
	forwardAddr := forwardLn.Addr().String()
	_ = forwardLn.Close()

	reportErrCh := make(chan error, 10)
	f := NewTCPForwarder(
		forwardAddr,
		blackholeLn.Addr().String(),
		WithErrorHandler(func(e error) {
			reportErrCh <- e
		}),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- f.Run(ctx) }()

	var conn net.Conn
	for range 20 {
		conn, err = net.DialTimeout("tcp", forwardAddr, 50*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("connect to forwarder failed: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	cancel()

	select {
	case err := <-runErrCh:
		if err != nil {
			t.Errorf("Run failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit in time after cancel on blackhole forwarder")
	}
}
