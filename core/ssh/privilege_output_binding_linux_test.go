//go:build linux

package ssh

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestExplicitPrivilegedPTYBindsContextOutput(t *testing.T) {
	_, input := openPrivilegeTestPTY(t)
	before, err := unix.IoctlGetTermios(int(input.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	scenario := &commandFixture{terminal: true, output: "chosen"}
	client := commandTestClient(t, scenario)
	client.connCfg.SudoMode = SudoModeRoot
	sink := &privilegeContextSink{entered: make(chan struct{}), block: true}
	client.environment.InteractiveIO = InteractiveIO{Stdin: input, Stdout: sink, Stderr: io.Discard}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done, joined := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(joined)
		done <- client.RunInteractiveWithSudoExecution(ctx, "chosen", &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX})
	}()
	defer func() { cancel(); <-joined }()
	select {
	case <-sink.entered:
	case err := <-done:
		t.Fatalf("PTY output ended without binding: %v", err)
	case <-ctx.Done():
		t.Fatal("PTY output did not start")
	}
	cancel()
	err = <-done
	var outputErr *OutputError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &outputErr) || outputErr.Target != sink {
		t.Fatalf("PTY output cancellation lost: %v", err)
	}
	if sink.raw.Load() != 0 || scenario.attempts.Load() != 1 {
		t.Fatal("unbound output or command replay")
	}
	after, err := unix.IoctlGetTermios(int(input.Fd()), unix.TCGETS)
	if err != nil || *before != *after {
		t.Fatalf("terminal not restored: %v", err)
	}
	if _, err := input.Stat(); err != nil {
		t.Fatalf("borrowed terminal closed: %v", err)
	}
}
