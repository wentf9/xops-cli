package ssh

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type mockInterruptConn struct {
	net.Conn
	deadlineCalled atomic.Bool
	closedCalled   atomic.Bool
	closeErr       error
}

func (m *mockInterruptConn) SetDeadline(t time.Time) error {
	m.deadlineCalled.Store(true)
	return nil
}

func (m *mockInterruptConn) Close() error {
	m.closedCalled.Store(true)
	return m.closeErr
}

// TestClient_Interrupt_SynchronousAndSafe verifies that Interrupt calls SetDeadline and Close synchronously without spawning detached goroutines.
func TestClient_Interrupt_SynchronousAndSafe(t *testing.T) {
	conn := &mockInterruptConn{}
	cli := &Client{rootConn: conn}

	err := cli.Interrupt()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !conn.deadlineCalled.Load() {
		t.Error("expected SetDeadline to be called")
	}
	if !conn.closedCalled.Load() {
		t.Error("expected Close to be called")
	}
}

// TestClient_Interrupt_ErrorCombination verifies that Close errors are propagated.
func TestClient_Interrupt_ErrorCombination(t *testing.T) {
	expectedErr := errors.New("underlying network close failure")
	conn := &mockInterruptConn{closeErr: expectedErr}
	cli := &Client{rootConn: conn}

	err := cli.Interrupt()
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v in combined error, got: %v", expectedErr, err)
	}
}

// TestClient_Interrupt_NetPipe verifies that Interrupt cleanly closes real net.Pipe connections and unblocks concurrent operations.
func TestClient_Interrupt_NetPipe(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = serverConn.Close() }()

	cli := &Client{rootConn: clientConn}

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 10)
		_, rErr := clientConn.Read(buf)
		readDone <- rErr
	}()

	// Interrupt should synchronously close clientConn, unblocking the Read
	if err := cli.Interrupt(); err != nil {
		t.Errorf("unexpected error on interrupt: %v", err)
	}

	select {
	case rErr := <-readDone:
		if rErr == nil {
			t.Error("expected Read to unblock with error on Interrupt")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Read did not unblock within 1s after Interrupt")
	}
}

// TestClient_Interrupt_NilConn verifies that Interrupt handles nil connections gracefully without panicking.
func TestClient_Interrupt_NilConn(t *testing.T) {
	var cli *Client
	if err := cli.Interrupt(); err != nil {
		t.Errorf("expected nil error for nil client, got %v", err)
	}

	emptyCli := &Client{}
	if err := emptyCli.Interrupt(); err != nil {
		t.Errorf("expected nil error for empty client, got %v", err)
	}
}
