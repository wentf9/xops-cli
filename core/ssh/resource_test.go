package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type closeErrorResource struct {
	err error
}

type readErrorSource struct {
	err error
}

func (r readErrorSource) Read([]byte) (int, error) {
	return 0, r.err
}

func (r closeErrorResource) Close() error {
	return r.err
}

func TestCloseResourceReturnsCloseFailure(t *testing.T) {
	wantErr := errors.New("disk failure")
	err := closeResource(closeErrorResource{err: wantErr}, "test resource")
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "close test resource failed") {
		t.Fatalf("closeResource() error = %v, want wrapped close failure", err)
	}
}

func TestCopySessionOutputReturnsCopyError(t *testing.T) {
	wantErr := errors.New("output unavailable")
	wait := copySessionOutput(readErrorSource{err: wantErr}, bytes.NewReader(nil), io.Discard, io.Discard)

	if err := wait(); !errors.Is(err, wantErr) {
		t.Fatalf("copySessionOutput error = %v, want wrapped output error", err)
	}
}

func TestSessionOutputReportsFailureBeforeOtherStreamEOF(t *testing.T) {
	reader, writer := io.Pipe()
	wantErr := errors.New("stdout copy failed")
	output := startSessionOutput(readErrorSource{err: wantErr}, reader, io.Discard, io.Discard)
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
		if err := output.wait(); !errors.Is(err, wantErr) {
			t.Errorf("output error lost: %v", err)
		}
	})
	select {
	case err := <-output.failed:
		if !errors.Is(err, wantErr) {
			t.Fatalf("unexpected failure: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("output error waited for other stream EOF")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := output.wait(); !errors.Is(err, wantErr) {
			t.Fatalf("joined error lost: %v", err)
		}
	}
}

func TestSessionOutputOrdersBlockedWriteFailureBeforeWaitingStream(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sink := &privilegeContextSink{entered: make(chan struct{}), block: true}
	stdoutWriter, stderrWriter, closeOutput, err := bindStrictOutputs(ctx, sink, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeOutput(); err != nil {
			t.Error(err)
		}
	}()
	stderrReader, stderrPipe := io.Pipe()
	defer func() {
		_ = stderrReader.Close()
		_ = stderrPipe.Close()
	}()
	output := startSessionOutput(strings.NewReader("stdout"), stderrReader, stdoutWriter, stderrWriter)
	<-sink.entered
	if _, err := io.WriteString(stderrPipe, "stderr"); err != nil {
		t.Fatal(err)
	}
	if err := stderrPipe.Close(); err != nil {
		t.Fatal(err)
	}
	// Increase the chance that the stderr pump is waiting on outputMu when
	// cancellation fires; ordering is guaranteed regardless because the stdout
	// pump records its write error before releasing outputMu.
	time.Sleep(time.Millisecond)
	cancel()
	for _, got := range []error{<-output.failed, output.wait()} {
		var outputErr *OutputError
		if !errors.Is(got, context.Canceled) || !errors.As(got, &outputErr) || outputErr.Target != sink {
			t.Fatalf("blocked stream sink identity lost: %v", got)
		}
	}
}
