package forward

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockDebugLogger struct {
	mu       sync.Mutex
	messages []string
}

func (m *mockDebugLogger) Debug(msg string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, fmt.Sprintf(msg, args...))
}

func (m *mockDebugLogger) Debugf(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, fmt.Sprintf(format, args...))
}

func TestTCPForwarder_ErrorHandler(t *testing.T) {
	listenListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	listenAddr := listenListener.Addr().String()
	if err := listenListener.Close(); err != nil {
		t.Logf("Close failed: %v", err)
	} // 释放端口供 Forwarder 使用

	var (
		errMu       sync.Mutex
		receivedErr error
		errWG       sync.WaitGroup
	)
	errWG.Add(1)

	errHandler := func(err error) {
		errMu.Lock()
		if receivedErr == nil {
			receivedErr = err
			errWG.Done()
		}
		errMu.Unlock()
	}

	targetAddr := "127.0.0.1:59999"
	f := NewTCPForwarder(listenAddr, targetAddr,
		WithErrorHandler(errHandler),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- f.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("tcp", listenAddr)
	if err == nil {
		if err := conn.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	}

	done := make(chan struct{})
	go func() {
		errWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		errMu.Lock()
		defer errMu.Unlock()
		if receivedErr == nil {
			t.Fatal("expected non-nil error reported to ErrorHandler")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for TCP ErrorHandler to be triggered")
	}
}

func TestUDPForwarder_ErrorHandler(t *testing.T) {
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet failed: %v", err)
	}
	listenAddr := l.LocalAddr().String()
	if err := l.Close(); err != nil {
		t.Logf("Close failed: %v", err)
	}

	var (
		errMu       sync.Mutex
		receivedErr error
		errWG       sync.WaitGroup
	)
	errWG.Add(1)

	errHandler := func(err error) {
		errMu.Lock()
		if receivedErr == nil {
			receivedErr = err
			errWG.Done()
		}
		errMu.Unlock()
	}

	// 目标为 0.0.0.0:0（端口 0 在 UDP Write 时必触发系统错误）
	targetAddr := "0.0.0.0:0"
	f := NewUDPForwarder(listenAddr, targetAddr,
		WithErrorHandler(errHandler),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- f.Run(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	clientConn, err := net.Dial("udp", listenAddr)
	if err != nil {
		t.Fatalf("dial forwarder failed: %v", err)
	}
	defer func() {
		if err := clientConn.Close(); err != nil {
			t.Logf("Close failed: %v", err)
		}
	}()

	_, writeErr := clientConn.Write([]byte("test data"))
	if writeErr != nil {
		t.Fatalf("client write failed: %v", writeErr)
	}

	done := make(chan struct{})
	go func() {
		errWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		errMu.Lock()
		defer errMu.Unlock()
		if receivedErr == nil {
			t.Fatal("expected non-nil error reported to ErrorHandler")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for UDP ErrorHandler to be triggered")
	}
}

func TestForwarder_DefaultErrorHandler_FallsBackToLogger(t *testing.T) {
	listenListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	listenAddr := listenListener.Addr().String()
	if err := listenListener.Close(); err != nil {
		t.Fatalf("close reserved listen address failed: %v", err)
	}

	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve target address failed: %v", err)
	}
	targetAddr := targetListener.Addr().String()
	if err := targetListener.Close(); err != nil {
		t.Fatalf("close reserved target address failed: %v", err)
	}

	mockLogger := &mockDebugLogger{}
	f := NewTCPForwarder(listenAddr, targetAddr,
		WithLogger(mockLogger),
		// 不设置 ErrorHandler，测试是否正确 fallback 到 logger 而不是被静默吞掉
	)

	ctx, cancel := context.WithCancel(t.Context())
	runErrCh := make(chan error, 1)

	go func() {
		runErrCh <- f.Run(ctx)
	}()

	var conn net.Conn
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("tcp", listenAddr, 50*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("connect to forwarder failed: %v", err)
	}
	if err := conn.Close(); err != nil {
		cancel()
		t.Fatalf("close test connection failed: %v", err)
	}

	found := false
	for time.Now().Before(deadline) {
		mockLogger.mu.Lock()
		for _, msg := range mockLogger.messages {
			if strings.Contains(msg, "dial target "+targetAddr+" failed") {
				found = true
				break
			}
		}
		mockLogger.mu.Unlock()
		if found {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		cancel()
		t.Fatal("expected error to fallback to debug logger when ErrorHandler is nil")
	}

	cancel()
	select {
	case runErr := <-runErrCh:
		if runErr != nil {
			t.Fatalf("forwarder returned error after cancellation: %v", runErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("forwarder did not stop after cancellation")
	}
}
