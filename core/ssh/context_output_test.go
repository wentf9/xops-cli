package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type unknownTerminalWriter struct{ calls atomic.Int32 }

func (w *unknownTerminalWriter) Write(data []byte) (int, error) {
	w.calls.Add(1)
	return len(data), nil
}

type cancelableTerminalWriter struct{}

func (cancelableTerminalWriter) Write([]byte) (int, error) {
	return 0, errors.New("unbounded Write must not be used")
}
func (cancelableTerminalWriter) WriteContext(ctx context.Context, _ []byte) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestContextOutputCapabilities(t *testing.T) {
	unknown := &unknownTerminalWriter{}
	if _, _, err := prepareContextOutput(t.Context(), unknown); err == nil || unknown.calls.Load() != 0 {
		t.Fatal("unknown writer invoked or accepted")
	}
	var typedNil *bytes.Buffer
	if _, _, err := prepareContextOutput(t.Context(), typedNil); err == nil {
		t.Fatal("nil output accepted")
	}
	for _, dst := range []io.Writer{&bytes.Buffer{}, io.Discard} {
		writer, close, err := prepareContextOutput(t.Context(), dst)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte("data")); err != nil {
			t.Fatal(err)
		}
		if err := close(); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	writer, close, err := prepareContextOutput(ctx, cancelableTerminalWriter{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := writer.Write([]byte("data")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("output cancellation lost: %v", err)
	}
}
