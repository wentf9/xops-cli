package ssh

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestP7W17a_C17L1_NilSSHClientConnAndKeepAliveGuards(t *testing.T) {
	t.Run("execute_and_session_methods_reject_nil_conn_without_panicking", testP7W17aC17L1NilConnSessionMethods)
	t.Run("pooled_client_startKeepAlive_ignores_nil_conn", testP7W17aC17L1PooledKeepAliveNilConn)
	t.Run("keepalive_guards_nil_ctx_nil_client_and_nil_conn", testP7W17aC17L1KeepAliveGuards)
}

func testP7W17aC17L1NilConnSessionMethods(t *testing.T) {
	ctx := t.Context()
	unconnected := &Client{
		connCfg:   ConnectionConfig{NodeID: "unconnected", Address: "127.0.0.1", Port: 22, User: "tester"},
		sshClient: &cryptoSSH.Client{}, // non-nil *ssh.Client with nil Conn
	}
	plan, err := PlanCommand("echo hi", CommandOptions{Interpreter: InterpreterServer})
	if err != nil {
		t.Fatalf("PlanCommand: %v", err)
	}

	cases := []struct {
		name string
		fn   func() error
	}{
		{"newSessionContext", func() error { _, err := unconnected.newSessionContext(ctx); return err }},
		{"runSessionWithInput", func() error {
			return unconnected.runSessionWithInput(ctx, "exec", func(*cryptoSSH.Session) error { return nil }, "", nil, &bytes.Buffer{}, &bytes.Buffer{})
		}},
		{"validateCommandExecution", func() error { return validateCommandExecution(ctx, unconnected, plan) }},
		{"RunCommandPlanWithIO", func() error {
			return unconnected.RunCommandPlanWithIO(ctx, plan, nil, &bytes.Buffer{}, &bytes.Buffer{})
		}},
		{"RunCommandPlanWithRemotePTY", func() error {
			return unconnected.RunCommandPlanWithRemotePTY(ctx, plan, nil, &bytes.Buffer{}, &bytes.Buffer{})
		}},
		{"validateSubsystemArgs", func() error { return validateSubsystemArgs(ctx, unconnected, "sftp", nil) }},
		{"RunSubsystemWithIO", func() error {
			return unconnected.RunSubsystemWithIO(ctx, "sftp", nil, &bytes.Buffer{}, &bytes.Buffer{}, false)
		}},
		{"RunShellWithoutPTY", func() error { return unconnected.RunShellWithoutPTY(ctx, nil, &bytes.Buffer{}, &bytes.Buffer{}) }},
		{"RunShellWithIO", func() error { return unconnected.RunShellWithIO(ctx, nil, &bytes.Buffer{}, &bytes.Buffer{}) }},
		{"RunShellWithRemotePTY", func() error { return unconnected.RunShellWithRemotePTY(ctx, nil, &bytes.Buffer{}, &bytes.Buffer{}) }},
		{"RunCommandWithRemotePTY", func() error {
			return unconnected.RunCommandWithRemotePTY(ctx, "echo hi", nil, &bytes.Buffer{}, &bytes.Buffer{})
		}},
		{"maybeDetectSudoMode", func() error { return unconnected.maybeDetectSudoMode(ctx, &RunConfig{Interpreter: InterpreterBash}) }},
	}
	for _, tc := range cases {
		if err := tc.fn(); err == nil {
			t.Errorf("%s returned nil error for nil sshClient.Conn", tc.name)
		}
	}
	if res := unconnected.ExecuteCommand(ctx, plan); res.Err() == nil || res.Outcome != ExecutionNotStarted {
		t.Fatalf("ExecuteCommand = (%+v, err=%v), want ExecutionNotStarted error", res, res.Err())
	}
	if _, err := unconnected.ProbeExecutionConfig(ctx); !errors.Is(err, ErrExecutionProbe) {
		t.Fatalf("ProbeExecutionConfig = %v, want ErrExecutionProbe", err)
	}
	if ch := unconnected.watchTransport(); ch != nil {
		t.Fatalf("watchTransport returned non-nil channel %v for nil sshClient.Conn", ch)
	}
}

func testP7W17aC17L1PooledKeepAliveNilConn(t *testing.T) {
	ctx := t.Context()
	var wg sync.WaitGroup
	pooled := &PooledClient{SSHClient: &cryptoSSH.Client{}}
	pooled.startKeepAlive(ctx, ctx, 5*time.Millisecond, 5*time.Millisecond, false, nil, &wg)
	if active, _ := pooled.keepAliveState(); active {
		t.Fatal("PooledClient.startKeepAlive started keepalive on nil SSHClient.Conn")
	}
	wg.Wait()
}

func testP7W17aC17L1KeepAliveGuards(t *testing.T) {
	ctx := t.Context()
	assertClosed := func(name string, ch <-chan struct{}) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatalf("%s did not return an immediately closed channel", name)
		}
	}

	//nolint:staticcheck // intentionally testing nil context guard
	assertClosed("StartKeepAlive(nil, &Client{})", StartKeepAlive(nil, &cryptoSSH.Client{}, 5*time.Millisecond, 5*time.Millisecond, nil))
	assertClosed("StartKeepAlive(ctx, nil)", StartKeepAlive(ctx, nil, 5*time.Millisecond, 5*time.Millisecond, nil))
	assertClosed("StartKeepAlive(ctx, &Client{})", StartKeepAlive(ctx, &cryptoSSH.Client{}, 5*time.Millisecond, 5*time.Millisecond, nil))

	conn := &monitoredTestConn{closed: make(chan struct{}), probeSeen: make(chan struct{})}
	//nolint:staticcheck // intentionally testing nil context guard on connected client
	assertClosed("StartKeepAlive(nil, connected)", StartKeepAlive(nil, &cryptoSSH.Client{Conn: conn}, 5*time.Millisecond, 5*time.Millisecond, nil))

	var wg sync.WaitGroup
	wg.Add(1)
	//nolint:staticcheck // intentionally testing nil stopCtx/abortCtx guard
	assertClosed("startKeepAliveWithContexts(nil, nil)", startKeepAliveWithContexts(nil, nil, &cryptoSSH.Client{Conn: conn}, 5*time.Millisecond, 5*time.Millisecond, nil, nil, nil, false, &wg))
	wg.Wait()

	wg.Add(1)
	assertClosed("startKeepAliveWithContexts(nil conn)", startKeepAliveWithContexts(ctx, ctx, &cryptoSSH.Client{}, 5*time.Millisecond, 5*time.Millisecond, nil, nil, nil, false, &wg))
	wg.Wait()

	if err := probeWithContexts(ctx, ctx, &cryptoSSH.Client{}, 5*time.Millisecond, nil, nil, nil, false, nil); err == nil {
		t.Fatal("probeWithContexts returned nil error for nil sshClient.Conn")
	}
}
