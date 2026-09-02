package sftpshell

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestLineEditorCloseInterruptsActivePrompt(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create input pipe failed: %v", err)
	}
	defer closeTestResource(t, reader)
	defer closeTestResource(t, writer)

	shell := &Shell{cwd: "/", localCwd: t.TempDir()}
	editor, err := newLineEditor(context.Background(), reader, &bytes.Buffer{}, &bytes.Buffer{}, "", shell)
	if err != nil {
		t.Fatalf("create line editor failed: %v", err)
	}
	promptDone := make(chan error, 1)
	go func() {
		_, promptErr := editor.Prompt(t.Context(), "sftp> ")
		promptDone <- promptErr
	}()
	deadline := time.Now().Add(time.Second)
	for !editor.instance.Terminal.IsReading() {
		if time.Now().After(deadline) {
			t.Fatal("line editor did not enter a prompt read")
		}
		time.Sleep(time.Millisecond)
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
		t.Fatal("closing an active line editor blocked")
	}
	select {
	case promptErr := <-promptDone:
		if promptErr != nil && !errors.Is(promptErr, io.EOF) {
			t.Errorf("prompt error = %v, want EOF or nil", promptErr)
		}
	case <-time.After(time.Second):
		t.Fatal("active prompt did not return after closing the line editor")
	}
}

func TestLineEditorCloseBeforePrompt(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create input pipe failed: %v", err)
	}
	defer closeTestResource(t, reader)
	defer closeTestResource(t, writer)

	shell := &Shell{cwd: "/", localCwd: t.TempDir()}
	editor, err := newLineEditor(context.Background(), reader, &bytes.Buffer{}, &bytes.Buffer{}, "", shell)
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
		t.Fatal("closing a line editor before Prompt blocked")
	}
	if err := editor.Close(); err != nil {
		t.Fatalf("second close line editor failed: %v", err)
	}
}
