package ssh

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestLegacyExecRequestsAreBounded(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for name, run := range map[string]func(*Client) error{
		"Run":             func(c *Client) error { _, err := c.Run(context.Background(), "command"); return err },
		"RunWithoutLogin": func(c *Client) error { _, err := c.RunWithoutLogin(context.Background(), "command"); return err },
		"RunScript":       func(c *Client) error { _, err := c.RunScript(context.Background(), "command"); return err },
		"RunCommandWithIO": func(c *Client) error {
			return c.RunCommandWithIO(context.Background(), "command", false, nil, io.Discard, io.Discard)
		},
		"RunStream": func(c *Client) error {
			stream, err := c.RunStream(context.Background(), "command")
			if stream != nil {
				err = errors.Join(err, stream.Close())
			}
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			scenario := &commandFixture{hangRequest: true}
			client := commandTestClient(t, scenario)
			client.handshakeTimeout = 30 * time.Millisecond
			start := time.Now()
			if err := run(client); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("missing exec request deadline: %v", err)
			}
			if time.Since(start) > 3*time.Second || scenario.attempts.Load() != 1 {
				t.Fatal("request hung or command replayed")
			}
		})
	}
}

func TestLegacySessionCreationHasDefaultDeadline(t *testing.T) {
	scenario := &commandFixture{stallOpen: true}
	client := commandTestClient(t, scenario)
	client.handshakeTimeout = 30 * time.Millisecond
	session, err := client.newSessionContext(context.Background())
	if session != nil {
		if err := session.Close(); err != nil {
			t.Error(err)
		}
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("session creation unbounded: %v", err)
	}
}

func TestLegacyBashEntryPointPayloads(t *testing.T) {
	for _, test := range []struct {
		name, payload, input string
		run                  func(*Client) (string, error)
	}{
		{"login", "bash -l -c 'echo '\\''quoted'\\'''", "", func(c *Client) (string, error) { return c.Run(t.Context(), "echo 'quoted'") }},
		{"non-login", "bash -c 'echo '\\''quoted'\\'''", "", func(c *Client) (string, error) { return c.RunWithoutLogin(t.Context(), "echo 'quoted'") }},
		{"script login", "bash -l -s", "#!/bin/sh\necho script\n", func(c *Client) (string, error) { return c.RunScript(t.Context(), "#!/bin/sh\necho script\n") }},
		{"script non-login", "bash -s", "echo script\n", func(c *Client) (string, error) {
			return c.RunScript(t.Context(), "echo script\n", WithLoginShell(false))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			scenario := &commandFixture{commands: make(chan string, 1), inputs: make(chan string, 1), output: "output"}
			client := commandTestClient(t, scenario)
			output, err := test.run(client)
			if err != nil || !strings.Contains(output, "output") {
				t.Fatalf("legacy execution failed: %q, %v", output, err)
			}
			if got := <-scenario.commands; got != test.payload {
				t.Fatalf("payload %q, want %q", got, test.payload)
			}
			if got := <-scenario.inputs; got != test.input {
				t.Fatalf("stdin %q, want %q", got, test.input)
			}
		})
	}
}

func TestShellExitPolicyPreservesAdditionalErrors(t *testing.T) {
	exit := &cryptoSSH.ExitError{}
	cleanup := errors.New("cleanup failed")
	err := ignoreShellExitError(errors.Join(exit, context.Canceled, cleanup))
	if !errors.Is(err, context.Canceled) || !errors.Is(err, cleanup) {
		t.Fatalf("shell exit policy hid additional errors: %v", err)
	}
	var retained *cryptoSSH.ExitError
	if errors.As(err, &retained) {
		t.Fatal("full login shell exit was not ignored")
	}
}

func TestPTYRequestTimeoutBeforeCommandStart(t *testing.T) {
	scenario := &commandFixture{hangPTY: true}
	client := commandTestClient(t, scenario)
	client.handshakeTimeout = 30 * time.Millisecond
	session, err := client.newSessionContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.closeSessionBounded(session); err != nil {
			t.Error(err)
		}
	}()
	err = client.sessionRequest(t.Context(), session, "pty", func() error { return session.RequestPty("xterm", 40, 80, nil) })
	if !errors.Is(err, context.DeadlineExceeded) || scenario.attempts.Load() != 0 {
		t.Fatalf("PTY timeout dispatched command: %v", err)
	}
}

func TestTerminalPreflightRejectsNonTerminalBeforeDispatch(t *testing.T) {
	client := commandTestClient(t, &commandFixture{})
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stdin.Close(); err != nil {
			t.Error(err)
		}
	}()
	err = client.RunInteractiveCmdWithIO(t.Context(), "command", InteractiveIO{Stdin: stdin, Stdout: io.Discard, Stderr: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "local terminal") {
		t.Fatalf("non-terminal input accepted: %v", err)
	}
}

func TestPrivilegePTYRequestDeadlineBeforeAuthentication(t *testing.T) {
	for _, mode := range []SudoMode{SudoModeSudo, SudoModeSu} {
		t.Run(string(mode), func(t *testing.T) {
			setTestHome(t)
			address, evidence := startPrivilegeExchangeServer(t, privilegeServerOptions{mode: mode, password: "valid", blockPtyReply: true})
			client := exchangeTestClient(t, address, mode, &recoveryTestUI{values: []string{"valid"}}, &testRecorder{})
			client.handshakeTimeout = 30 * time.Millisecond
			terminal := &privilegeTerminal{width: 80, height: 40, activate: func(context.Context, *cryptoSSH.Session) (func() error, error) {
				return func() error { return nil }, nil
			}}
			err := client.runPrivilegeOperation(context.Background(), mode, "command", nil, io.Discard, io.Discard, terminal)
			if !errors.Is(err, context.DeadlineExceeded) || evidence.execRequests.Load() != 0 || evidence.attempts.Load() != 0 {
				t.Fatalf("privilege PTY request hung or consumed input: %v", err)
			}
		})
	}
}

func TestRunStreamCloseJoinsAndIsIdempotent(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	client := commandTestClient(t, &commandFixture{terminal: true, output: "stream output"})
	stream, err := client.RunStream(t.Context(), "command")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stream.Close(); err != nil {
			t.Error(err)
		}
	}()
	output, err := io.ReadAll(stream)
	if err != nil || string(output) != "stream output" {
		t.Fatalf("stream output %q: %v", output, err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInteractivePlanRejectsUnsafeOutputBeforeDispatch(t *testing.T) {
	scenario := &commandFixture{}
	client := commandTestClient(t, scenario)
	plan, err := PlanCommand("command", CommandOptions{})
	if err != nil {
		t.Fatal(err)
	}
	unknown := &unknownTerminalWriter{}
	err = client.RunInteractivePlanWithIO(t.Context(), plan, InteractiveIO{Stdout: unknown, Stderr: io.Discard})
	if err == nil || !strings.Contains(err.Error(), "ContextWriter") || unknown.calls.Load() != 0 || scenario.attempts.Load() != 0 {
		t.Fatalf("unsafe output reached execution: %v", err)
	}
	plan, err = PlanCommand("command", CommandOptions{Stdin: []byte("conflicting input")})
	if err != nil {
		t.Fatal(err)
	}
	err = client.RunInteractivePlanWithIO(t.Context(), plan, InteractiveIO{})
	if err == nil || !strings.Contains(err.Error(), "terminal streams") || scenario.attempts.Load() != 0 {
		t.Fatalf("ambiguous PTY stdin accepted: %v", err)
	}
}
