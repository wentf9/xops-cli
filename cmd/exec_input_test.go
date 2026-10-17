package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/ssh"
)

func TestExecStdinScriptCancellationPreservesBorrowedInput(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	old := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = old })
	o := NewExecOptions()
	command := newCmdExecWithOptions(o)
	if err := command.Flags().Parse([]string{"--host", "fixture", "--interpreter", "sh", "--launch-dialect", "posix"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	command.SetContext(ctx)
	done := make(chan error, 1)
	go func() { done <- o.Complete(command, nil) }()
	// The producer remains open: only context cancellation may end the read.
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		_ = writer.Close()
		<-done
		t.Fatal("script input did not cancel")
	}
	if _, err := reader.Stat(); err != nil {
		t.Fatalf("borrowed stdin closed: %v", err)
	}
	if _, err := writer.Write([]byte("caller")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len("caller"))
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "caller" {
		t.Fatalf("canceled reader stole later input: %q %v", data, err)
	}
}

func TestExecScriptInputReadLimitAndOwnership(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	if _, err := io.WriteString(writer, strings.Repeat("x", 64)); err != nil {
		_ = writer.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = readExecScriptInput(t.Context(), reader, 32)
	if err == nil || !strings.Contains(err.Error(), "script exceeds 32 bytes") {
		t.Fatalf("read limit not enforced: %v", err)
	}
	remainder, err := io.ReadAll(reader)
	if err != nil || len(remainder) != 31 {
		t.Fatalf("input closed or read beyond limit+1: remaining=%d error=%v", len(remainder), err)
	}
}

func TestExecScriptFileBoundedRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "check.sh")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(ssh.MaxCommandInputBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readExecScriptFile(t.Context(), path, ssh.MaxCommandInputBytes); err == nil || !strings.Contains(err.Error(), "script exceeds") {
		t.Fatalf("oversized file accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte("echo exact"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := readExecScriptFile(t.Context(), path, int64(len("echo exact")))
	if err != nil || string(data) != "echo exact" {
		t.Fatalf("exact-size file rejected/changed: %q %v", data, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readExecScriptFile(ctx, path, ssh.MaxCommandInputBytes); !errors.Is(err, context.Canceled) {
		t.Fatalf("file read ignored cancellation: %v", err)
	}
	if _, err := readExecScriptFile(t.Context(), t.TempDir(), ssh.MaxCommandInputBytes); err == nil {
		t.Fatal("non-regular script path accepted")
	}
}

func TestExecScriptRejectsCredentialStdinConflictBeforeRead(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	if _, err := io.WriteString(writer, "untouched"); err != nil {
		t.Fatal(err)
	}
	old := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = old })
	o := NewExecOptions()
	command := newCmdExecWithOptions(o)
	if err := command.Flags().Parse([]string{"--host", "fixture", "--interpreter", "sh", "--launch-dialect", "posix", "--password-stdin"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Complete(command, nil); err == nil || !strings.Contains(err.Error(), "stdin cannot supply both") {
		t.Fatalf("stdin ownership conflict accepted: %v", err)
	}
	data := make([]byte, len("untouched"))
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "untouched" {
		t.Fatalf("credential input consumed on rejected invocation: %q %v", data, err)
	}
}
