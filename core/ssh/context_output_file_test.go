package ssh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestContextOutputRegularFileOwnershipAndCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output.log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.WriteString("before/"); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	writer, release, err := prepareContextOutput(ctx, file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("bound/")); err != nil {
		t.Fatal(err)
	}
	cancel()
	_, err = writer.Write([]byte("must-not-appear"))
	var outputErr *OutputError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &outputErr) || !outputErr.TargetsFile(file) {
		t.Fatalf("file cancellation or sink identity lost: %v", err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("caller"); err != nil {
		t.Fatalf("borrowed file closed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "before/bound/caller" {
		t.Fatalf("append flag changed or canceled output written: %q", data)
	}
}

func TestContextOutputRegularFileErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "readonly.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	writer, release, err := prepareContextOutput(t.Context(), file)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	_, writeErr := writer.Write([]byte("rejected"))
	var outputErr *OutputError
	var pathErr *os.PathError
	if !errors.As(writeErr, &outputErr) || !outputErr.TargetsFile(file) || !errors.As(writeErr, &pathErr) {
		t.Errorf("write error or sink identity lost: %v", writeErr)
	}
	if err := release(); err != nil {
		t.Error(err)
	}
	if _, err := file.Stat(); err != nil {
		t.Errorf("borrowed failed sink closed: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareContextOutput(t.Context(), file); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed output accepted or cause lost: %v", err)
	}
}

func TestInteractivePlanClosedFileRejectedBeforeCommand(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "closed-output-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	scenario := &commandFixture{}
	client := commandTestClient(t, scenario)
	plan, err := PlanCommand("must-not-start", CommandOptions{})
	if err != nil {
		t.Fatal(err)
	}
	err = client.RunInteractivePlanWithIO(t.Context(), plan, InteractiveIO{Stdout: file, Stderr: file})
	if !errors.Is(err, os.ErrClosed) || scenario.attempts.Load() != 0 {
		t.Fatalf("closed output reached execution or cause lost: %v", err)
	}
}

// A controlled waiter models an in-flight file write that the OS cannot cancel.
// Cancellation may signal it, but must never abandon the output worker.
func TestTerminalOutputCancellationJoinsInFlightFileWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release, canceled, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- waitTerminalOutput(ctx, func() error { close(entered); <-release; return nil }, func() { close(canceled) })
	}()
	<-entered
	cancel()
	<-canceled
	select {
	case err := <-done:
		close(release)
		t.Fatalf("abandoned in-flight output: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
