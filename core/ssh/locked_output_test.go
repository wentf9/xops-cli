package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

type shortContextOutput struct{}

func (shortContextOutput) Write([]byte) (int, error)                         { panic("unbound writer") }
func (shortContextOutput) WriteContext(context.Context, []byte) (int, error) { return 0, nil }

func TestBoundOutputShortWriteIsClassified(t *testing.T) {
	bound, release, supported, err := BindOutput(t.Context(), shortContextOutput{})
	if err != nil || !supported {
		t.Fatalf("binding: %v %v", supported, err)
	}
	defer func() {
		if err := release(); err != nil {
			t.Error(err)
		}
	}()
	_, err = bound.Write([]byte("data"))
	var outputErr *OutputError
	if !errors.Is(err, io.ErrShortWrite) || !errors.As(err, &outputErr) {
		t.Fatalf("short write lost: %v", err)
	}
}

func TestBindLockedOutputWaitCancels(t *testing.T) {
	var mu sync.Mutex
	var buffer bytes.Buffer
	mu.Lock()
	defer mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	bound, release, supported, err := BindOutput(ctx, NewLockedWriter(&mu, &buffer))
	if err != nil || !supported {
		t.Fatalf("binding: %v %v", supported, err)
	}
	defer func() {
		if err := release(); err != nil {
			t.Error(err)
		}
	}()
	done := make(chan error, 1)
	go func() { _, err := bound.Write([]byte("blocked")); done <- err }()
	select {
	case err := <-done:
		var outputErr *OutputError
		if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &outputErr) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for output lock ignored cancellation")
	}
	if buffer.Len() != 0 {
		t.Fatal("canceled writer wrote data")
	}
}

func TestBindLockedOutputUnknownCapability(t *testing.T) {
	var mu sync.Mutex
	unknown := &unknownTerminalWriter{}
	target := NewLockedWriter(&mu, unknown)
	bound, release, supported, err := BindOutput(t.Context(), target)
	if err != nil || supported || bound != target || unknown.calls.Load() != 0 {
		t.Fatalf("unknown capability changed: %v %v", supported, err)
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
}

func TestBindLockedOutputNativePipeCancellation(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close(); _ = writer.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	var mu sync.Mutex
	bound, release, supported, err := BindOutput(ctx, NewLockedWriter(&mu, writer))
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		_ = release()
		t.Skip("native pipe binding unavailable")
	}
	done := make(chan error, 1)
	go func() { _, err := bound.Write(bytes.Repeat([]byte("x"), 2<<20)); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		_ = reader.Close()
		<-done
		_ = release()
		t.Fatal("locked native pipe ignored cancellation")
	}
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Stat(); err != nil {
		t.Fatalf("borrowed stream closed: %v", err)
	}
}
