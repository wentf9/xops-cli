package ssh

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A destination whose Close (SSH CloseWrite in production) is not allowed to
// overlap Write. The session owner, represented by release, unblocks the write.
type closeOrderStdinWriter struct {
	entered, release, closed chan struct{}
	writing, overlap         atomic.Bool
	closes                   atomic.Int32
	writeErr, closeErr       error
}

func (w *closeOrderStdinWriter) Write(p []byte) (int, error) {
	w.writing.Store(true)
	close(w.entered)
	<-w.release
	w.writing.Store(false)
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	return len(p), nil
}
func (w *closeOrderStdinWriter) Close() error {
	if w.writing.Load() {
		w.overlap.Store(true)
	}
	if w.closes.Add(1) == 1 {
		close(w.closed)
	}
	return w.closeErr
}

type closeOrderInputBridge struct{}

func (closeOrderInputBridge) Start(ctx context.Context, _ InteractiveIO, dst io.Writer) (InputCopy, error) {
	done := make(chan error, 1)
	go func() { _, err := io.WriteString(dst, "input"); done <- err }()
	return NewInputCopy(ctx, func() error { return nil }, done)
}

func TestPipeCommandStdinJoinsWriteBeforeClose(t *testing.T) {
	for _, mode := range []string{"memory", "file"} {
		for _, fail := range []bool{false, true} {
			t.Run(mode+"/failure="+map[bool]string{false: "false", true: "true"}[fail], func(t *testing.T) {
				writer := &closeOrderStdinWriter{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
				release := sync.OnceFunc(func() { close(writer.release) })
				defer release()
				if fail {
					writer.writeErr, writer.closeErr = errors.New("write failed"), errors.New("close failed")
				}
				var input io.Reader = strings.NewReader("input")
				if mode == "file" {
					file, err := os.CreateTemp(t.TempDir(), "stdin")
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = file.Close() }()
					input = file
				}
				stop, err := pipeCommandStdin(input, writer, inputPipelineOptions{ctx: t.Context(), bridge: closeOrderInputBridge{}})
				if err != nil {
					t.Fatal(err)
				}
				<-writer.entered
				stopped := make(chan error, 1)
				started := make(chan struct{})
				go func() { close(started); stopped <- stop() }()
				<-started
				select {
				case <-writer.closed:
					t.Error("stdin Close overlapped its active Write")
				case <-time.After(30 * time.Millisecond):
				}
				release() // Session/transport shutdown ends the in-flight write.
				select {
				case err := <-stopped:
					if !errors.Is(err, writer.writeErr) || !errors.Is(err, writer.closeErr) {
						t.Fatalf("stdin error lost: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("input copy was not joined")
				}
				if writer.overlap.Load() || writer.closes.Load() != 1 {
					t.Fatalf("Close overlapped or repeated: overlap=%v closes=%d", writer.overlap.Load(), writer.closes.Load())
				}
				if err := stop(); !errors.Is(err, writer.writeErr) || !errors.Is(err, writer.closeErr) {
					t.Fatalf("idempotent finish lost error: %v", err)
				}
			})
		}
	}
}
