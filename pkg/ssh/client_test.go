package ssh

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClient_ConfigReturnsConcurrentSnapshot(t *testing.T) {
	original := &ClientConfig{NodeID: "node-1", SudoMode: SudoModeAuto}
	cli := newClient(nil, nil, original, nil, "")
	original.SudoMode = SudoModeRoot
	if got := cli.Config().SudoMode; got != SudoModeAuto {
		t.Fatalf("Config().SudoMode = %q, want independent snapshot %q", got, SudoModeAuto)
	}

	var wg sync.WaitGroup
	for index := range 100 {
		wg.Go(func() {
			mode := SudoModeSudo
			if index%2 == 0 {
				mode = SudoModeSudoer
			}
			if err := cli.updateSudoMode(context.Background(), mode); err != nil {
				t.Errorf("updateSudoMode() error = %v", err)
			}
		})
		wg.Go(func() {
			snapshot := cli.Config()
			if snapshot == nil {
				t.Error("Config() returned nil")
				return
			}
			snapshot.SudoMode = SudoModeNone
		})
	}
	wg.Wait()
	if got := cli.Config().SudoMode; got != SudoModeSudo && got != SudoModeSudoer {
		t.Fatalf("live SudoMode = %q, want a concurrently stored mode", got)
	}
}

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

func TestDetectedSudoModeSurvivesNoSaveRecorder(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		provider := &trackingProvider{cfg: &ClientConfig{
			NodeID: "test", Address: "127.0.0.1", Port: 22, User: "test",
			SudoMode: SudoModeAuto, SudoUpdateToken: "sudo-old",
		}}
		recorder := &testRecorder{sudoCommittedToken: "sudo-old"}
		if conflict {
			recorder.onUpdateSudo = func() {
				provider.mu.Lock()
				defer provider.mu.Unlock()
				provider.cfg.SudoUpdateToken = "concurrent-change"
			}
		}
		client := newClientWithComponents(nil, nil, provider.cfg, provider, nil, nil, recorder, "", time.Second, time.Second, nil)
		err := client.updateSudoMode(t.Context(), SudoModeSudo)
		if conflict {
			if !errors.Is(err, ErrSnapshotMismatch) {
				t.Fatalf("no-save discovery bypassed version conflict: %v", err)
			}
			continue
		}
		if err != nil || client.ConnectionConfig().SudoMode != SudoModeSudo {
			t.Fatalf("verified local sudo mode was discarded: %v", err)
		}
		if err := client.recordPrivilegeSecret(t.Context(), SecretKindSudoPassword, client.ConnectionConfig(), "verified-test-password"); err != nil || client.ConnectionConfig().SudoMode != SudoModeSudo {
			t.Fatalf("no-save password confirmation discarded local discovery: %v", err)
		}
		if provider.cfg.SudoMode != SudoModeAuto || client.ConnectionConfig().SudoUpdateToken != "sudo-old" {
			t.Fatal("no-save discovery changed persistent mode or token")
		}
	}
}
