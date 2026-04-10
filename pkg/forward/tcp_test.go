package forward

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// startEchoServer starts a TCP echo server and returns its address.
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
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
	_ = ln.Close()

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
	defer func() { _ = conn.Close() }()

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
	_ = ln.Close()

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
