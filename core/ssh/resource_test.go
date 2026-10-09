package ssh

import (
	"bytes"
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
