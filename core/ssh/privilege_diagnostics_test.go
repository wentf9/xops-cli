package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	corelog "github.com/wentf9/xops-cli/core/log"
	cryptossh "golang.org/x/crypto/ssh"
)

func privilegePhases(recorder *diagnosticRecorder) []string {
	var phases []string
	for _, event := range recorder.snapshot() {
		if event.Kind == corelog.PrivilegeLifecycle {
			phases = append(phases, event.Outcome)
		}
	}
	return phases
}
func requirePrivilegePhase(t *testing.T, recorder *diagnosticRecorder, phase string, want bool) {
	t.Helper()
	found := false
	for _, got := range privilegePhases(recorder) {
		if got == phase {
			found = true
		}
	}
	if found != want {
		t.Fatalf("phase %q presence=%v want=%v: %v", phase, found, want, privilegePhases(recorder))
	}
}

func TestPrivilegeDiagnosticsRetriesAndPrivacy(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudo, SudoModeSu} {
		t.Run(string(mode), func(t *testing.T) {
			setTestHome(t)
			const password = "private-password-marker"
			address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: mode, password: password, status: 7})
			client := exchangeTestClient(t, address, mode, &recoveryTestUI{values: []string{"private-wrong-marker", password}}, &testRecorder{})
			recorder := &diagnosticRecorder{}
			client.diagnostics = recorder
			var restored bool
			terminal := &privilegeTerminal{width: 80, height: 40, activate: func(context.Context, *cryptossh.Session) (func() error, error) {
				return func() error { restored = true; return nil }, nil
			}}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err := client.runPrivilegeOperation(ctx, mode, "private-command-marker", strings.NewReader("private-input-marker"), io.Discard, io.Discard, terminal)
			var exit *cryptossh.ExitError
			if !errors.As(err, &exit) || exit.ExitStatus() != 7 || evidence.commands.Load() != 1 || evidence.attempts.Load() != 2 || !restored {
				t.Fatalf("execution/retry policy changed: %v", err)
			}
			for _, phase := range []string{"attempt_started", "password_prompt", "interactive_prompt", "password_response_sent", "elevated_shell_ready", "terminal_activated", "terminal_handoff_confirmed", "input_forwarding", "terminal_restored", "operation_failed"} {
				requirePrivilegePhase(t, recorder, phase, true)
			}
			retry := "password_retry"
			if mode == SudoModeSu {
				retry = "exchange_retry"
				requirePrivilegePhase(t, recorder, "authentication_rejected", true)
			}
			requirePrivilegePhase(t, recorder, retry, true)
			phases := privilegePhases(recorder)
			previous := -1
			for _, phase := range []string{"elevated_shell_ready", "terminal_activated", "terminal_handoff_confirmed", "input_forwarding", "terminal_restored", "operation_failed"} {
				found := -1
				for i, got := range phases {
					if got == phase {
						found = i
						break
					}
				}
				if found <= previous {
					t.Fatalf("incorrect handoff/cleanup order: %v", phases)
				}
				previous = found
			}
			text := fmt.Sprint(recorder.snapshot())
			for _, private := range []string{password, "private-wrong-marker", "private-command-marker", "private-input-marker", "xops-ready-", "xops-password-", "xops-continue-", "xops-terminal-"} {
				if strings.Contains(text, private) {
					t.Fatalf("privilege diagnostic leaked %q", private)
				}
			}
		})
	}
}

func TestPrivilegeDiagnosticsBannerIsNotAnAuthenticationResult(t *testing.T) {
	setTestHome(t)
	address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSu, noPrompt: true, banner: "su: Authentication failure\n"})
	client := exchangeTestClient(t, address, SudoModeSu, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	recorder := &diagnosticRecorder{}
	client.diagnostics = recorder
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := client.runPrivilegeOperation(ctx, SudoModeSu, "command", nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	requirePrivilegePhase(t, recorder, "elevated_shell_ready", true)
	requirePrivilegePhase(t, recorder, "authentication_rejected", false)
	requirePrivilegePhase(t, recorder, "operation_completed", true)
	if evidence.commands.Load() != 1 {
		t.Fatal("banner replayed user command")
	}
}

func TestPrivilegeDiagnosticsRejectedWithoutReadiness(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudo, SudoModeSu} {
		t.Run(string(mode), func(t *testing.T) {
			setTestHome(t)
			address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: mode, password: "valid"})
			client := exchangeTestClient(t, address, mode, &recoveryTestUI{values: []string{"wrong1", "wrong2", "wrong3"}}, &testRecorder{})
			recorder := &diagnosticRecorder{}
			client.diagnostics = recorder
			input := bytes.NewReader([]byte("untouched"))
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := client.runPrivilegeOperation(ctx, mode, "must-not-start", input, io.Discard, io.Discard); err == nil {
				t.Fatal("rejection succeeded")
			}
			requirePrivilegePhase(t, recorder, "elevated_shell_ready", false)
			requirePrivilegePhase(t, recorder, "elevation_not_confirmed", true)
			requirePrivilegePhase(t, recorder, "operation_failed", true)
			if input.Len() != len("untouched") || evidence.commands.Load() != 0 || evidence.attempts.Load() != 3 {
				t.Fatal("rejected escalation consumed input or retried user work")
			}
		})
	}
}

func TestPrivilegeDiagnosticsPasswordlessAndModeSelection(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeRoot, SudoModeSudoer, SudoModeAuto} {
		t.Run(string(mode), func(t *testing.T) {
			client := commandTestClient(t, &commandFixture{output: "not-root"})
			client.connCfg.SudoMode = mode
			recorder := &diagnosticRecorder{}
			client.diagnostics = recorder
			if _, err := client.RunWithSudo(t.Context(), "private-command-marker"); err != nil {
				t.Fatal(err)
			}
			requirePrivilegePhase(t, recorder, "mode_selected", true)
			requirePrivilegePhase(t, recorder, "elevated_shell_ready", false) // No authenticated control frame on the legacy path.
			requirePrivilegePhase(t, recorder, "password_prompt", false)
			if mode == SudoModeRoot {
				requirePrivilegePhase(t, recorder, "escalation_not_required", true)
				requirePrivilegePhase(t, recorder, "command_prepared", false)
			} else {
				requirePrivilegePhase(t, recorder, "command_prepared", true)
				requirePrivilegePhase(t, recorder, "attempt_started", true)
				requirePrivilegePhase(t, recorder, "operation_completed", true)
			}
			if mode == SudoModeAuto {
				for _, phase := range []string{"detection_started", "root_probe", "passwordless_probe", "passwordless_available"} {
					requirePrivilegePhase(t, recorder, phase, true)
				}
			}
		})
	}
}

func TestPrivilegeDiagnosticsCancellationDuringPrompt(t *testing.T) {
	setTestHome(t)
	address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSu, password: "valid"})
	ui := &blockingPrivilegeUI{entered: make(chan struct{})}
	client := exchangeTestClient(t, address, SudoModeSu, ui, &testRecorder{})
	recorder := &diagnosticRecorder{}
	client.diagnostics = recorder
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.runPrivilegeOperation(ctx, SudoModeSu, "never-start", nil, io.Discard, io.Discard)
	}()
	select {
	case <-ui.entered:
	case <-ctx.Done():
		<-done
		t.Fatal("prompt not reached")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	requirePrivilegePhase(t, recorder, "operation_canceled", true)
	requirePrivilegePhase(t, recorder, "elevated_shell_ready", false)
	if evidence.commands.Load() != 0 {
		t.Fatal("canceled authentication started user code")
	}
}

func TestPrivilegeDiagnosticsCredentialLookupDoesNotClaimAuthentication(t *testing.T) {
	const secret = "private-stored-password-marker"
	client := newClient(nil, nil, &ClientConfig{Password: secret, SudoMode: SudoModeSudo}, nil, "")
	recorder := &diagnosticRecorder{}
	client.diagnostics = recorder
	material, err := client.resolvePrivilegeMaterial(t.Context(), SecretKindSudoPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Zero()
	requirePrivilegePhase(t, recorder, "credential_lookup", true)
	requirePrivilegePhase(t, recorder, "credential_available", true)
	requirePrivilegePhase(t, recorder, "interactive_prompt", false)
	requirePrivilegePhase(t, recorder, "elevated_shell_ready", false)
	if strings.Contains(fmt.Sprint(recorder.snapshot()), secret) {
		t.Fatal("stored credential leaked")
	}
}

func TestPrivilegeDiagnosticsRestoreError(t *testing.T) {
	setTestHome(t)
	address, _ := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid", status: 7})
	client := exchangeTestClient(t, address, SudoModeSudo, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	recorder := &diagnosticRecorder{}
	client.diagnostics = recorder
	restoreErr := errors.New("private-terminal-error-marker")
	terminal := &privilegeTerminal{width: 80, height: 40, ignoreExit: true, activate: func(context.Context, *cryptossh.Session) (func() error, error) {
		return func() error { return restoreErr }, nil
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := client.runPrivilegeOperation(ctx, SudoModeSudo, "command", nil, io.Discard, io.Discard, terminal); !errors.Is(err, restoreErr) {
		t.Fatalf("restoration error lost: %v", err)
	}
	requirePrivilegePhase(t, recorder, "terminal_restore_failed", true)
	requirePrivilegePhase(t, recorder, "terminal_restored", false)
	requirePrivilegePhase(t, recorder, "operation_failed", true)
	if strings.Contains(fmt.Sprint(recorder.snapshot()), restoreErr.Error()) {
		t.Fatal("raw restoration error entered diagnostics")
	}
}

func TestPrivilegeDiagnosticsHandoffTimeout(t *testing.T) {
	setTestHome(t)
	address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid", withholdTerminal: true})
	client := exchangeTestClient(t, address, SudoModeSudo, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	recorder := &diagnosticRecorder{}
	client.diagnostics = recorder
	client.handshakeTimeout = 100 * time.Millisecond
	terminal := &privilegeTerminal{width: 80, height: 40, activate: func(context.Context, *cryptossh.Session) (func() error, error) {
		return func() error { return nil }, nil
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err := client.runPrivilegeOperation(ctx, SudoModeSudo, "never-start", nil, io.Discard, io.Discard, terminal)
	if !errors.Is(err, context.DeadlineExceeded) || evidence.commands.Load() != 0 {
		t.Fatalf("handoff timeout lost or user code dispatched: %v", err)
	}
	requirePrivilegePhase(t, recorder, "elevated_shell_ready", true)
	requirePrivilegePhase(t, recorder, "terminal_handoff_confirmed", false)
	requirePrivilegePhase(t, recorder, "terminal_restored", true)
	requirePrivilegePhase(t, recorder, "operation_timed_out", true)
}
