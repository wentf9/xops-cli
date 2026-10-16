package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd"
	"github.com/wentf9/xops-cli/core/ssh"
)

func TestReportErrorSkipsFailedSCPOutput(t *testing.T) {
	for _, stream := range []string{"stderr", "stdout", "command"} {
		t.Run(stream, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stderr")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			previous := os.Stderr
			os.Stderr = file
			defer func() { os.Stderr = previous }()
			var outputErr error = &cmd.SCPOutputError{Stream: stream, Err: os.ErrClosed}
			if stream == "command" {
				outputErr = &ssh.OutputError{Target: os.Stderr, Err: os.ErrClosed}
			}
			reportError(errors.Join(errors.New("operation failed"), fmt.Errorf("cleanup: %w", outputErr)))
			data, err := os.ReadFile(path)
			if err != nil || len(data) != 0 {
				t.Fatalf("failed stderr was written again: %q %v", data, err)
			}
		})
	}
}

func TestReportErrorPreservesOrdinaryFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stderr")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	previous := os.Stderr
	os.Stderr = file
	defer func() { os.Stderr = previous }()
	reportError(errors.New("ordinary transfer failure"))
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "ordinary transfer failure") {
		t.Fatalf("ordinary error lost: %q %v", data, err)
	}
}

func TestReportErrorPreservesIndependentLogFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "command.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Open(path) // A read-only log deterministically fails writes.
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	bound, release, _, err := ssh.BindOutput(t.Context(), log)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := bound.Write([]byte("remote output"))
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if writeErr == nil {
		t.Fatal("read-only log accepted a write")
	}
	stderrPath := filepath.Join(t.TempDir(), "stderr")
	stderr, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = stderr
	defer func() { os.Stderr = previous; _ = stderr.Close() }()
	reportError(errors.Join(errors.New("execution failed"), writeErr, errors.New("cleanup failed")))
	data, err := os.ReadFile(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"execution failed", path, "cleanup failed"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("lost %q in stderr: %s", want, data)
		}
	}
}
