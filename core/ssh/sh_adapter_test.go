package ssh

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestShAdapter_PlanCommand(t *testing.T) {
	t.Run("sh command with posix dialect", func(t *testing.T) {
		plan, err := PlanCommand("echo 'hello'", CommandOptions{
			Interpreter:   InterpreterSh,
			LaunchDialect: LaunchPOSIX,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if plan.Payload() != "sh -c 'echo '\\''hello'\\'''" {
			t.Errorf("unexpected payload: %s", plan.Payload())
		}
		if plan.LoginMode() != LoginDisabled {
			t.Errorf("expected login disabled, got %v", plan.LoginMode())
		}
	})

	t.Run("sh command rejects login shell", func(t *testing.T) {
		_, err := PlanCommand("echo hi", CommandOptions{
			Interpreter:   InterpreterSh,
			LaunchDialect: LaunchPOSIX,
			Login:         LoginEnabled,
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("sh command rejects non-posix dialect", func(t *testing.T) {
		_, err := PlanCommand("echo hi", CommandOptions{
			Interpreter:   InterpreterSh,
			LaunchDialect: LaunchCmd,
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestShAdapter_BOMRejectionInRunScript(t *testing.T) {
	bomContent := "\xef\xbb\xbf#!/bin/sh\necho hi\n"
	client := &Client{}

	_, err := client.RunScript(context.Background(), bomContent)
	if err == nil {
		t.Fatal("expected BOM error in RunScript, got nil")
	}
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation, got: %v", err)
	}

	_, err = client.RunScriptWithExecution(context.Background(), bomContent, nil)
	if err == nil {
		t.Fatal("expected BOM error in RunScriptWithExecution, got nil")
	}
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation, got: %v", err)
	}

	_, err = client.RunScriptWithSudo(context.Background(), bomContent)
	if err == nil {
		t.Fatal("expected BOM error in RunScriptWithSudo, got nil")
	}
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation, got: %v", err)
	}

	_, err = client.RunScriptWithSudoExecution(context.Background(), bomContent, nil)
	if err == nil {
		t.Fatal("expected BOM error in RunScriptWithSudoExecution, got nil")
	}
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation, got: %v", err)
	}
}

func TestMetricsCollector_RejectsIncompatibleExecution(t *testing.T) {
	cfg := &ClientConfig{
		Execution: &ExecutionConfig{
			Interpreter:   InterpreterPowerShell,
			LaunchDialect: LaunchPowerShell,
		},
	}
	client := newClient(nil, nil, cfg, nil, "")
	mc := NewMetricsCollector(client)

	err := mc.Start(context.Background())
	if err == nil {
		t.Fatal("expected error starting metrics collector on Windows config, got nil")
	}
	if !strings.Contains(err.Error(), "Linux/POSIX") {
		t.Errorf("error %q does not mention Linux/POSIX requirement", err.Error())
	}
}

func TestMaybeDetectSudoMode_SkipsOnNonPOSIX(t *testing.T) {
	cfg := &ClientConfig{
		Execution: &ExecutionConfig{
			Interpreter:   InterpreterCmd,
			LaunchDialect: LaunchCmd,
		},
	}
	client := newClient(nil, nil, cfg, nil, "")

	// Without connection, maybeDetectSudoMode would normally return "ssh client is not connected"
	// if it tried to probe, but for non-POSIX configs it returns nil immediately without probing.
	err := client.maybeDetectSudoMode(context.Background())
	if err != nil {
		t.Fatalf("expected nil for non-POSIX config, got: %v", err)
	}
}

type dummyWriteCloser struct {
	closed bool
}

func (d *dummyWriteCloser) Write(p []byte) (n int, err error) { return len(p), nil }
func (d *dummyWriteCloser) Close() error                      { d.closed = true; return nil }

func TestSetupStdinPipeline_RejectsConflictingScriptAndRuntimeStdin(t *testing.T) {
	pipe := &dummyWriteCloser{}
	stdin := strings.NewReader("runtime-stdin")
	initialPayload := "echo script\n"

	_, err := setupStdinPipeline(stdin, pipe, initialPayload)
	if err == nil {
		t.Fatal("expected error when both initialPayload and stdin are provided, got nil")
	}
	if !errors.Is(err, ErrExecutionValidation) {
		t.Fatalf("expected ErrExecutionValidation, got: %v", err)
	}
	if !pipe.closed {
		t.Error("expected pipe to be closed on conflict error")
	}
}
