package cmd

import (
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRunBase64DecodeReturnsAllInputErrors(t *testing.T) {
	err := runBase64(io.Discard, []string{"%%%", "***"}, true, base64.StdEncoding)
	if err == nil {
		t.Fatal("expected invalid base64 input error")
	}
	if !strings.Contains(err.Error(), "argument 1") || !strings.Contains(err.Error(), "argument 2") {
		t.Fatalf("expected both decode failures, got %v", err)
	}
}

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestRunBase64ReturnsOutputError(t *testing.T) {
	wantErr := errors.New("output unavailable")
	err := runBase64(failingWriter{err: wantErr}, []string{"data"}, false, base64.StdEncoding)
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected output error, got %v", err)
	}
}
