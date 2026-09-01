package cmd

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

type interactionFailingWriter struct {
	err error
}

func (w interactionFailingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestCLIInteractionHandlerConfirmHostKey(t *testing.T) {
	stdin, err := os.CreateTemp(t.TempDir(), "host-key-input-*")
	if err != nil {
		t.Fatalf("create host key input: %v", err)
	}
	t.Cleanup(func() {
		if err := stdin.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Errorf("close host key input: %v", err)
		}
	})
	if _, err := stdin.WriteString("yes\n"); err != nil {
		t.Fatalf("write host key input: %v", err)
	}
	if _, err := stdin.Seek(0, 0); err != nil {
		t.Fatalf("rewind host key input: %v", err)
	}

	var output bytes.Buffer
	handler := &cliInteractionHandler{stdin: stdin, stdout: &output}
	confirmed, err := handler.ConfirmHostKey("host.example", "SHA256:test")
	if err != nil {
		t.Fatalf("ConfirmHostKey() error = %v", err)
	}
	if !confirmed {
		t.Fatal("ConfirmHostKey() confirmed = false, want true")
	}
	if got := output.String(); !strings.Contains(got, "host.example") || !strings.Contains(got, "SHA256:test") {
		t.Fatalf("ConfirmHostKey() output = %q, want host and fingerprint", got)
	}
}

func TestCLIInteractionHandlerReturnsOutputError(t *testing.T) {
	wantErr := errors.New("output unavailable")
	handler := &cliInteractionHandler{stdin: os.Stdin, stdout: interactionFailingWriter{err: wantErr}}
	_, err := handler.ConfirmHostKey("host.example", "SHA256:test")
	if !errors.Is(err, wantErr) {
		t.Fatalf("ConfirmHostKey() error = %v, want wrapped %v", err, wantErr)
	}
}
