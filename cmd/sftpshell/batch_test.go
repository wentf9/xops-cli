package sftpshell

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBatchStopsAtFirstFailure(t *testing.T) {
	for _, batch := range []bool{true} {
		t.Run(map[bool]string{true: "batch", false: "interactive"}[batch], func(t *testing.T) {
			dir := t.TempDir()
			var output, diagnostics bytes.Buffer
			s := &Shell{batch: batch, stdin: batchInput(t, "lcd missing-directory\nlmkdir after-failure\nexit\n"), stdout: &output, stderr: &diagnostics, cwd: "/", localCwd: dir, historyFile: filepath.Join(dir, "history")}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			err := s.Run(ctx)
			if batch && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected missing-directory error, got %v", err)
			}
			if (err != nil) != batch {
				t.Fatalf("batch=%v error=%v", batch, err)
			}
			_, statErr := os.Stat(filepath.Join(dir, "after-failure"))
			if batch && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("subsequent command executed: %v", statErr)
			}
			if !batch && statErr != nil {
				t.Fatal(statErr)
			}
			if batch {
				if _, err := os.Stat(s.historyFile); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("batch wrote history: %v", err)
				}
			}
		})
	}
}

func TestInteractiveCommandErrorAllowsContinuation(t *testing.T) {
	var diagnostics bytes.Buffer
	s := &Shell{stdout: &bytes.Buffer{}, stderr: &diagnostics, localCwd: t.TempDir()}
	_, commandErr := s.dispatchCommand(t.Context(), "lcd", []string{"missing-directory"})
	if commandErr == nil {
		t.Fatal("missing command error")
	}
	if err := s.reportCommandError(commandErr); err != nil {
		t.Fatalf("interactive error became fatal: %v", err)
	}
	if !strings.Contains(diagnostics.String(), "missing-directory") {
		t.Fatal("missing diagnostic")
	}
	if _, err := s.dispatchCommand(t.Context(), "lmkdir", []string{"after-error"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.localCwd, "after-error")); err != nil {
		t.Fatal(err)
	}
}

func TestBatchCancellationClosesReader(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, reader)
	defer closeTestResource(t, writer)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	s := &Shell{batch: true, stdin: reader, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, localCwd: t.TempDir()}
	if err := s.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation=%v", err)
	}
}

func TestBatchLexecDoesNotConsumeCommands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX cat")
	}
	dir := t.TempDir()
	var output, diagnostics bytes.Buffer
	s := &Shell{batch: true, stdin: batchInput(t, "lexec cat\nlmkdir survived\nexit\n"), stdout: &output, stderr: &diagnostics, cwd: "/", localCwd: dir}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "survived")); err != nil {
		t.Fatal(err)
	}
}

func TestBatchRejectsInteraction(t *testing.T) {
	s := &Shell{batch: true}
	if _, err := s.askConfirmation(t.Context(), "confirm"); err == nil {
		t.Fatal("confirmation accepted")
	}
	for _, command := range []string{"shell", "lshell"} {
		if _, err := s.dispatchCommand(t.Context(), command, nil); err == nil {
			t.Fatalf("%s accepted", command)
		}
	}
}

func batchInput(t *testing.T, commands string) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "commands")
	if err := os.WriteFile(path, []byte(commands), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	return f
}
