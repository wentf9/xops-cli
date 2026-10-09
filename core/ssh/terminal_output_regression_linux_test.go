//go:build linux

package ssh

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/sys/unix"
)

type failedTerminalInputBridge struct{ err error }

func (b failedTerminalInputBridge) Start(context.Context, InteractiveIO, io.Writer) (InputCopy, error) {
	return nil, b.err
}

type failedTerminalOutput struct{ err error }

func (w failedTerminalOutput) Write([]byte) (int, error)                         { return 0, w.err }
func (w failedTerminalOutput) WriteContext(context.Context, []byte) (int, error) { return 0, w.err }

// The watchdog interrupts and joins even the regressed implementation, so a
// test failure never leaves a command goroutine or a blocked output pump behind.
func terminalRegressionResult(t *testing.T, client *Client, run func() error) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	joined := make(chan struct{})
	go func() { defer close(joined); done <- run() }()
	t.Cleanup(func() {
		if err := client.Interrupt(); err != nil {
			t.Error(err)
		}
		<-joined
	})
	return done
}

func awaitTerminalRegression(t *testing.T, client *Client, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		if err := client.Interrupt(); err != nil {
			t.Error(err)
		}
		err := <-done
		t.Fatalf("terminal cleanup waited for the command timeout: %v", err)
		return err
	}
}

func TestTerminalInputFailureJoinsOutputWithoutCloseAcknowledgment(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "explicit"}[explicit], func(t *testing.T) {
			_, stdin := openPrivilegeTestPTY(t)
			before, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			scenario := &commandFixture{terminal: true, hangCommand: true, blockClose: true}
			client := commandTestClient(t, scenario)
			inputErr := errors.New("input initialization failed")
			client.environment.InputBridge = failedTerminalInputBridge{inputErr}
			streams := InteractiveIO{Stdin: stdin, Stdout: io.Discard, Stderr: io.Discard}
			plan, err := PlanCommand("side-effect", CommandOptions{})
			if err != nil {
				t.Fatal(err)
			}
			done := terminalRegressionResult(t, client, func() error {
				if explicit {
					return client.RunInteractivePlanWithIO(t.Context(), plan, streams)
				}
				return client.RunInteractiveCmdWithIO(t.Context(), "side-effect", streams)
			})
			err = awaitTerminalRegression(t, client, done)
			if !errors.Is(err, inputErr) || scenario.attempts.Load() != 1 {
				t.Fatalf("input error lost or command replayed: %v", err)
			}
			after, err := unix.IoctlGetTermios(int(stdin.Fd()), unix.TCGETS)
			if err != nil || *before != *after {
				t.Fatalf("terminal not restored: %v", err)
			}
		})
	}
}

func TestTerminalOutputFailureInterruptsRunningCommand(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, sinkErr := range []error{io.ErrClosedPipe, context.DeadlineExceeded} {
		t.Run(sinkErr.Error(), func(t *testing.T) {
			_, stdin := openPrivilegeTestPTY(t)
			scenario := &commandFixture{terminal: true, blockClose: true, output: strings.Repeat("x", 4<<20)}
			client := commandTestClient(t, scenario)
			plan, err := PlanCommand("side-effect", CommandOptions{Timeout: 30 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			done := terminalRegressionResult(t, client, func() error {
				return client.RunInteractivePlanWithIO(t.Context(), plan, InteractiveIO{Stdin: stdin, Stdout: failedTerminalOutput{sinkErr}, Stderr: io.Discard})
			})
			err = awaitTerminalRegression(t, client, done)
			if !errors.Is(err, sinkErr) || scenario.attempts.Load() != 1 {
				t.Fatalf("output error lost or replay: %v", err)
			}
		})
	}
}

func TestTerminalBrokenPipeDoesNotWaitForRemoteExit(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	_, stdin := openPrivilegeTestPTY(t)
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
	scenario := &commandFixture{terminal: true, commands: make(chan string, 1), output: strings.Repeat("x", 4<<20)}
	client := commandTestClient(t, scenario)
	plan, err := PlanCommand("side-effect", CommandOptions{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	done := terminalRegressionResult(t, client, func() error {
		return client.RunInteractivePlanWithIO(t.Context(), plan, InteractiveIO{Stdin: stdin, Stdout: writer, Stderr: io.Discard})
	})
	select {
	case <-scenario.commands:
	case <-time.After(3 * time.Second):
		t.Fatal("command not dispatched")
	}
	if err := closeReader(); err != nil {
		t.Fatal(err)
	}
	err = awaitTerminalRegression(t, client, done)
	if !errors.Is(err, syscall.EPIPE) || scenario.attempts.Load() != 1 {
		t.Fatalf("broken pipe not preserved or replayed: %v", err)
	}
	if _, err := writer.Stat(); err != nil {
		t.Fatalf("borrowed output closed: %v", err)
	}
}
