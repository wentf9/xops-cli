package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestRunCommandPlanWithIO_Validations(t *testing.T) {
	plan, err := PlanCommand("echo hello", CommandOptions{})
	if err != nil {
		t.Fatal(err)
	}

	client := &Client{}
	// Nil client / unconnected
	if err := client.RunCommandPlanWithIO(t.Context(), plan, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("expected error on unconnected client")
	}

	// Plan with input must be rejected
	planWithInput, err := PlanCommand("cat", CommandOptions{Stdin: []byte("input")})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RunCommandPlanWithIO(t.Context(), planWithInput, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("expected error on plan with finite input")
	}

	// Uncancelable output must be rejected
	scenario := &commandFixture{output: "test"}
	client = commandTestClient(t, scenario)
	unknown := &unknownTerminalWriter{}
	if err := client.RunCommandPlanWithIO(t.Context(), plan, nil, unknown, io.Discard); err == nil {
		t.Fatal("expected error with uncancelable stdout")
	}
	if err := client.RunCommandPlanWithIO(t.Context(), plan, nil, io.Discard, unknown); err == nil {
		t.Fatal("expected error with uncancelable stderr")
	}
}

func TestRunCommandPlanWithIO_ExecutionAndExitStatus(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	for _, tc := range []struct {
		name       string
		status     uint32
		signal     bool
		missing    bool
		wantExit   bool
		wantSignal bool
	}{
		{name: "success", status: 0},
		{name: "nonzero exit", status: 42, wantExit: true},
		{name: "signal termination", signal: true, wantSignal: true},
		{name: "missing exit status", missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scenario := &commandFixture{
				commands:     make(chan string, 1),
				inputs:       make(chan string, 1),
				requestTypes: make(chan string, 1),
				output:       "streamed output",
				status:       tc.status,
				signal:       tc.signal,
				missing:      tc.missing,
			}
			client := commandTestClient(t, scenario)

			plan, err := PlanCommand("mycmd", CommandOptions{})
			if err != nil {
				t.Fatal(err)
			}

			var stdout, stderr bytes.Buffer
			stdinContent := "streaming input payload\n"
			err = client.RunCommandPlanWithIO(t.Context(), plan, strings.NewReader(stdinContent), &stdout, &stderr)

			if tc.wantExit {
				var exitErr *cryptoSSH.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitStatus() != int(tc.status) {
					t.Fatalf("expected exit status %d, got: %v", tc.status, err)
				}
			} else if tc.wantSignal {
				var exitErr *cryptoSSH.ExitError
				if !errors.As(err, &exitErr) || exitErr.Signal() != "TERM" {
					t.Fatalf("expected signal TERM, got: %v", err)
				}
			} else if tc.missing {
				var missingErr *cryptoSSH.ExitMissingError
				if !errors.As(err, &missingErr) {
					t.Fatalf("expected ExitMissingError, got: %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotReq := <-scenario.requestTypes; gotReq != "exec" {
				t.Fatalf("request type: %q, want exec", gotReq)
			}
			if gotCmd := <-scenario.commands; gotCmd != "mycmd" {
				t.Fatalf("command: %q, want mycmd", gotCmd)
			}
			if gotIn := <-scenario.inputs; gotIn != stdinContent {
				t.Fatalf("stdin: %q, want %q", gotIn, stdinContent)
			}
			if stdout.String() != "streamed output" {
				t.Fatalf("stdout: %q, want streamed output", stdout.String())
			}
			if stderr.String() != "stderr" {
				t.Fatalf("stderr: %q, want stderr", stderr.String())
			}
		})
	}
}

func TestRunShellWithoutPTY_Execution(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	for _, tc := range []struct {
		name     string
		status   uint32
		wantExit bool
	}{
		{name: "success", status: 0},
		{name: "nonzero exit", status: 15, wantExit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scenario := &commandFixture{
				inputs:       make(chan string, 1),
				requestTypes: make(chan string, 1),
				output:       "shell stdout",
				status:       tc.status,
			}
			client := commandTestClient(t, scenario)

			var stdout, stderr bytes.Buffer
			stdinContent := "echo shell\n"
			err := client.RunShellWithoutPTY(t.Context(), strings.NewReader(stdinContent), &stdout, &stderr)

			if tc.wantExit {
				var exitErr *cryptoSSH.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitStatus() != int(tc.status) {
					t.Fatalf("expected exit status %d, got: %v", tc.status, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if gotReq := <-scenario.requestTypes; gotReq != "shell" {
				t.Fatalf("request type: %q, want shell", gotReq)
			}
			if gotIn := <-scenario.inputs; gotIn != stdinContent {
				t.Fatalf("stdin: %q, want %q", gotIn, stdinContent)
			}
			if stdout.String() != "shell stdout" {
				t.Fatalf("stdout: %q, want shell stdout", stdout.String())
			}
		})
	}
}

func TestRunShellWithoutPTY_Cancellation(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })

	scenario := &commandFixture{
		hangCommand:  true,
		requestTypes: make(chan string, 1),
	}
	client := commandTestClient(t, scenario)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err := client.RunShellWithoutPTY(ctx, strings.NewReader(""), &stdout, &stderr)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got: %v", err)
	}
}

type failedOutputWriter struct{ err error }

func (w failedOutputWriter) WriteContext(context.Context, []byte) (int, error) { return 0, w.err }
func (w failedOutputWriter) Write([]byte) (int, error)                         { return 0, w.err }

func awaitCommandStreamRegression(t *testing.T, client *Client, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		if err := client.Interrupt(); err != nil {
			t.Error(err)
		}
		err := <-done
		t.Fatalf("streaming cleanup waited for the command timeout: %v", err)
		return err
	}
}

func TestRunCommandPlanWithIO_OutputFailureInterruptsCommand(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, sinkErr := range []error{io.ErrClosedPipe, context.DeadlineExceeded} {
		t.Run(sinkErr.Error(), func(t *testing.T) {
			scenario := &commandFixture{output: strings.Repeat("x", 4<<20)}
			client := commandTestClient(t, scenario)
			plan, err := PlanCommand("side-effect", CommandOptions{Timeout: 30 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				done <- client.RunCommandPlanWithIO(t.Context(), plan, nil, failedOutputWriter{sinkErr}, io.Discard)
			}()
			err = awaitCommandStreamRegression(t, client, done)
			if !errors.Is(err, sinkErr) || scenario.attempts.Load() != 1 {
				t.Fatalf("output error lost or replay: %v", err)
			}
		})
	}
}

func TestRunCommandPlanWithIO_BrokenPipeDoesNotWaitForRemoteExit(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native pipe output bridges are only validated on Linux")
	}
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	closeReader := sync.OnceValue(reader.Close)
	t.Cleanup(func() {
		if err := closeReader(); err != nil {
			t.Error(err)
		}
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	})
	scenario := &commandFixture{commands: make(chan string, 1), output: strings.Repeat("x", 4<<20)}
	client := commandTestClient(t, scenario)
	plan, err := PlanCommand("side-effect", CommandOptions{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- client.RunCommandPlanWithIO(t.Context(), plan, nil, writer, io.Discard)
	}()
	select {
	case <-scenario.commands:
	case <-time.After(3 * time.Second):
		t.Fatal("command not dispatched")
	}
	if err := closeReader(); err != nil {
		t.Fatal(err)
	}
	err = awaitCommandStreamRegression(t, client, done)
	if !errors.Is(err, syscall.EPIPE) || scenario.attempts.Load() != 1 {
		t.Fatalf("broken pipe not preserved or replayed: %v", err)
	}
}

func TestRunShellWithoutPTY_OutputFailureInterruptsSession(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	scenario := &commandFixture{output: strings.Repeat("x", 4<<20)}
	client := commandTestClient(t, scenario)
	done := make(chan error, 1)
	go func() {
		done <- client.RunShellWithoutPTY(t.Context(), strings.NewReader(""), failedOutputWriter{io.ErrClosedPipe}, io.Discard)
	}()
	err := awaitCommandStreamRegression(t, client, done)
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output error lost: %v", err)
	}
}

func TestRunShellWithoutPTY_BrokenPipeDoesNotHang(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native pipe output bridges are only validated on Linux")
	}
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	closeReader := sync.OnceValue(reader.Close)
	t.Cleanup(func() {
		if err := closeReader(); err != nil {
			t.Error(err)
		}
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	})
	scenario := &commandFixture{requestTypes: make(chan string, 1), output: strings.Repeat("x", 4<<20)}
	client := commandTestClient(t, scenario)
	done := make(chan error, 1)
	go func() {
		done <- client.RunShellWithoutPTY(t.Context(), strings.NewReader(""), writer, io.Discard)
	}()
	select {
	case <-scenario.requestTypes:
	case <-time.After(3 * time.Second):
		t.Fatal("shell request not dispatched")
	}
	if err := closeReader(); err != nil {
		t.Fatal(err)
	}
	err = awaitCommandStreamRegression(t, client, done)
	if !errors.Is(err, syscall.EPIPE) {
		t.Fatalf("broken pipe not preserved: %v", err)
	}
}

type stallingContextWriter struct {
	started  chan struct{}
	canceled chan struct{}
}

func (w *stallingContextWriter) WriteContext(ctx context.Context, _ []byte) (int, error) {
	if w.started != nil {
		select {
		case w.started <- struct{}{}:
		default:
		}
	}
	<-ctx.Done()
	if w.canceled != nil {
		select {
		case w.canceled <- struct{}{}:
		default:
		}
	}
	return 0, ctx.Err()
}

func (w *stallingContextWriter) Write([]byte) (int, error) {
	return 0, errors.New("unexpected non-context write")
}

func TestRunCommandPlanWithIO_DrainTimeoutUnblocksStalledOutput(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	scenario := &commandFixture{output: "finished remote command", status: 0}
	client := commandTestClient(t, scenario)
	plan, err := PlanCommand("slow-drain", CommandOptions{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	writer := &stallingContextWriter{started: make(chan struct{}, 1), canceled: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() {
		done <- client.RunCommandPlanWithIO(t.Context(), plan, nil, writer, io.Discard)
	}()
	select {
	case <-writer.started:
	case <-time.After(3 * time.Second):
		t.Fatal("output write never started")
	}
	err = awaitCommandStreamRegression(t, client, done)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded on drain timeout, got: %v", err)
	}
	select {
	case <-writer.canceled:
	default:
		t.Fatal("expected writer to be canceled by drain timeout")
	}
}

func TestRunShellWithoutPTY_DrainTimeoutUnblocksStalledOutput(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	scenario := &commandFixture{output: "finished shell output", status: 0}
	client := commandTestClient(t, scenario)
	writer := &stallingContextWriter{started: make(chan struct{}, 1), canceled: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() {
		done <- client.RunShellWithoutPTY(context.Background(), strings.NewReader(""), writer, io.Discard)
	}()
	select {
	case <-writer.started:
	case <-time.After(3 * time.Second):
		t.Fatal("output write never started")
	}
	err := awaitCommandStreamRegression(t, client, done)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded on drain timeout, got: %v", err)
	}
	select {
	case <-writer.canceled:
	default:
		t.Fatal("expected writer to be canceled by drain timeout")
	}
}

func TestRunCommandPlanWithIO_DrainTimeoutUnblocksStalledPipe(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native pipe output bridges are only validated on Linux")
	}
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	scenario := &commandFixture{commands: make(chan string, 1), output: strings.Repeat("x", 1<<20), status: 0}
	client := commandTestClient(t, scenario)
	plan, err := PlanCommand("side-effect", CommandOptions{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- client.RunCommandPlanWithIO(t.Context(), plan, nil, writer, io.Discard)
	}()
	select {
	case <-scenario.commands:
	case <-time.After(3 * time.Second):
		t.Fatal("command not dispatched")
	}
	err = awaitCommandStreamRegression(t, client, done)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded on drain timeout, got: %v", err)
	}
}

func TestRunShellWithoutPTY_DrainTimeoutUnblocksStalledPipe(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native pipe output bridges are only validated on Linux")
	}
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})
	scenario := &commandFixture{requestTypes: make(chan string, 1), output: strings.Repeat("x", 1<<20), status: 0}
	client := commandTestClient(t, scenario)
	done := make(chan error, 1)
	go func() {
		done <- client.RunShellWithoutPTY(context.Background(), strings.NewReader(""), writer, io.Discard)
	}()
	select {
	case <-scenario.requestTypes:
	case <-time.After(3 * time.Second):
		t.Fatal("shell request not dispatched")
	}
	err = awaitCommandStreamRegression(t, client, done)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded on drain timeout, got: %v", err)
	}
}
