//go:build linux

package ssh

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestExplicitInteractiveSudoHandoffTimeoutRestoresTerminal(t *testing.T) {
	setTestHome(t)
	_, slave := openPrivilegeTestPTY(t)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid", withholdTerminal: true})
	client := exchangeTestClient(t, addr, SudoModeSudo, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
	client.handshakeTimeout = 200 * time.Millisecond
	var output bytes.Buffer
	client.environment.InteractiveIO = InteractiveIO{Stdin: slave, Stdout: &output, Stderr: &output}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	err = client.RunInteractiveWithSudoExecution(ctx, "must-not-run", &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("handoff timeout lost: %v", err)
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || *before != *after {
		t.Fatalf("terminal not restored after timeout: %v", err)
	}
	if evidence.commands.Load() != 0 || evidence.attempts.Load() != 1 {
		t.Fatal("command started before terminal handoff or authentication missing")
	}
}

func assertBorrowedPrivilegeLog(t *testing.T, file *os.File) {
	t.Helper()
	data, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "command output: su: Authentication failure\n" {
		t.Fatalf("output lost or password/protocol leaked: %q", data)
	}
	if _, err := file.Stat(); err != nil {
		t.Fatalf("borrowed privilege output closed: %v", err)
	}
}

func TestExplicitInteractiveSudoAuthenticatesAndRestoresTerminal(t *testing.T) {
	for _, test := range []struct {
		name        string
		interpreter Interpreter
		login       bool
	}{
		{"bash non-login", InterpreterBash, false},
		{"bash login", InterpreterBash, true},
		{"sh", InterpreterSh, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			setTestHome(t)
			master, slave := openPrivilegeTestPTY(t)
			before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			addr, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: SudoModeSudo, password: "valid", status: 7, inputBytes: 1})
			ui := &canonicalPrivilegeUI{recoveryTestUI: recoveryTestUI{values: []string{"wrong", "valid"}}, terminal: slave}
			recorder := &testRecorder{}
			client := exchangeTestClient(t, addr, SudoModeSudo, ui, recorder)
			output, err := os.CreateTemp(t.TempDir(), "privilege-output-*")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = output.Close() })
			client.environment.InteractiveIO = InteractiveIO{Stdin: slave, Stdout: output, Stderr: output}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := master.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			sent := make(chan error, 1)
			go func() {
				select {
				case <-evidence.terminalSignaled:
				case <-ctx.Done():
					sent <- ctx.Err()
					return
				}
				_, err := master.Write([]byte("Z"))
				sent <- err
			}()
			runErr := client.RunInteractiveWithSudoExecution(ctx, "chosen", &ExecutionConfig{
				Interpreter: test.interpreter, LaunchDialect: LaunchPOSIX, Login: &test.login,
			})
			cancel()
			if err := <-sent; err != nil {
				t.Fatal(err)
			}
			assertTerminalExit(t, runErr, 7, false, false, false)
			after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil || *before != *after {
				t.Fatalf("terminal not restored: %v", err)
			}
			if got := <-evidence.input; got != "Z" {
				t.Fatalf("first input lost: %q", got)
			}
			if recorder.sudoCalls != 1 || evidence.commands.Load() != 1 || evidence.attempts.Load() != 2 {
				t.Fatalf("authentication or single dispatch failed: prompts=%d commands=%d saves=%d", evidence.attempts.Load(), evidence.commands.Load(), recorder.sudoCalls)
			}
			assertBorrowedPrivilegeLog(t, output)
			if client.Execution() != nil {
				t.Fatal("explicit execution changed shared defaults")
			}
		})
	}
}
