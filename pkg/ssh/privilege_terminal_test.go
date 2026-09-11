package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestPrivilegeTerminalHandoffAfterAuthentication(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudo, SudoModeSu} {
		t.Run(string(mode), func(t *testing.T) {
			setTestHome(t)
			addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: mode, password: "valid", status: 7})
			ui := &recoveryTestUI{values: []string{"wrong", "valid"}}
			recorder := &testRecorder{}
			client := exchangeTestClient(t, addr, mode, ui, recorder)
			var activated, restored atomic.Int32
			terminal := &privilegeTerminal{width: 100, height: 30, ignoreExit: true, activate: func(ctx context.Context, session *cryptoSSH.Session) (func() error, error) {
				if evidence.attempts.Load() != 2 || session == nil {
					return nil, errors.New("terminal activated before authentication")
				}
				activated.Add(1)
				return func() error { restored.Add(1); return nil }, nil
			}}
			var output bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := client.runPrivilegeOperation(ctx, mode, "command", bytes.NewReader([]byte("first-input")), &output, &output, terminal); err != nil {
				t.Fatal(err)
			}
			if activated.Load() != 1 || restored.Load() != 1 || !evidence.ptyEchoOff.Load() {
				t.Fatal("incorrect terminal lifecycle or password echo enabled")
			}
			if got := <-evidence.input; got != "first-input" {
				t.Fatalf("first input changed: %q", got)
			}
			if recorder.sudoCalls != 1 || evidence.commands.Load() != 1 {
				t.Fatal("command replayed or verified password not saved")
			}
		})
	}
}

func TestPrivilegeTerminalWaitsForRemoteEchoBeforeInput(t *testing.T) {
	setTestHome(t)
	addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid", withholdTerminal: true})
	client := exchangeTestClient(t, addr, SudoModeSudo, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	client.handshakeTimeout = 200 * time.Millisecond
	var restored atomic.Int32
	terminal := &privilegeTerminal{width: 80, height: 40, activate: func(context.Context, *cryptoSSH.Session) (func() error, error) {
		return func() error { restored.Add(1); return nil }, nil
	}}
	input := bytes.NewReader([]byte("untouched"))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := client.runPrivilegeOperation(ctx, SudoModeSudo, "command", input, io.Discard, io.Discard, terminal)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("missing terminal handoff timeout: %v", err)
	}
	if input.Len() != len("untouched") || restored.Load() != 1 || evidence.commands.Load() != 0 {
		t.Fatal("input consumed before remote terminal readiness or terminal not restored")
	}
}

func TestPrivilegeTerminalRestoreFailureIsNotHiddenByExitStatus(t *testing.T) {
	setTestHome(t)
	addr, _ := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSu, password: "valid", status: 7})
	client := exchangeTestClient(t, addr, SudoModeSu, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	restoreErr := errors.New("terminal restore failed")
	terminal := &privilegeTerminal{width: 80, height: 40, ignoreExit: true, activate: func(context.Context, *cryptoSSH.Session) (func() error, error) {
		return func() error { return restoreErr }, nil
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := client.runPrivilegeOperation(ctx, SudoModeSu, "command", nil, io.Discard, io.Discard, terminal); !errors.Is(err, restoreErr) {
		t.Fatalf("restore error hidden: %v", err)
	}
}

func TestPrivilegeTerminalCancellationRestoresBeforeReturn(t *testing.T) {
	setTestHome(t)
	addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSu, password: "valid"})
	recorder := &testRecorder{}
	client := exchangeTestClient(t, addr, SudoModeSu, &recoveryTestUI{values: []string{"valid"}}, recorder)
	entered := make(chan struct{})
	var restored atomic.Int32
	terminal := &privilegeTerminal{width: 80, height: 40, activate: func(ctx context.Context, _ *cryptoSSH.Session) (func() error, error) {
		close(entered)
		<-ctx.Done()
		return func() error { restored.Add(1); return nil }, nil
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	done := make(chan error, 1)
	go func() {
		done <- client.runPrivilegeOperation(ctx, SudoModeSu, "command", nil, io.Discard, io.Discard, terminal)
	}()
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("terminal did not activate")
	}
	cancel()
	err := <-done
	joined = true
	if !errors.Is(err, context.Canceled) || restored.Load() != 1 || evidence.commands.Load() != 0 || recorder.sudoCalls != 0 {
		t.Fatalf("incomplete cancellation cleanup: %v", err)
	}
}
