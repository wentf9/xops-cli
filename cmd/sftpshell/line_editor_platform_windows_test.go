//go:build windows

package sftpshell

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestWindowsLineEditorDoesNotReadBeforePrompt(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, reader)
	defer closeTestResource(t, writer)
	editor, err := newLineEditor(context.Background(), reader, &bytes.Buffer{}, &bytes.Buffer{}, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, editor)
	if editor.isReading() {
		t.Fatal("editor started reading before Prompt")
	}
}
