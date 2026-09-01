package ssh

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
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
