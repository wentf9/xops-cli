package sftp

import (
	"bytes"
	"os"
	"testing"
	"time"
)

func TestLineEditorCloseBeforePromptDoesNotBlock(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create input pipe failed: %v", err)
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()

	shell := &Shell{cwd: "/", localCwd: t.TempDir()}
	editor, err := newLineEditor(reader, &bytes.Buffer{}, &bytes.Buffer{}, "", shell)
	if err != nil {
		t.Fatalf("create line editor failed: %v", err)
	}
	closed := make(chan error, 1)
	go func() {
		closed <- editor.Close()
	}()
	select {
	case closeErr := <-closed:
		if closeErr != nil {
			t.Errorf("close line editor failed: %v", closeErr)
		}
	case <-time.After(time.Second):
		t.Fatal("closing an unused line editor blocked")
	}
}
