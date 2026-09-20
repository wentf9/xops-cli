package sftpshell

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	for !editor.isReading() {
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
		if promptErr != nil && !errors.Is(promptErr, io.EOF) && !errors.Is(promptErr, ErrLineEditorClosed) {
			t.Errorf("prompt error = %v, want EOF, ErrLineEditorClosed or nil", promptErr)
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

func TestLineEditorEOFAndRepeatedPrompts(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, reader)
	editor, err := newLineEditor(t.Context(), reader, io.Discard, io.Discard, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, editor)
	closeTestResource(t, writer)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := editor.Prompt(ctx, "EOF> "); !errors.Is(err, io.EOF) {
		t.Fatalf("EOF = %v", err)
	}
}

func TestPromptCleanupErrorsTakePrecedence(t *testing.T) {
	failure := errors.New("restore failed")
	for _, normal := range []error{nil, io.EOF, ErrPromptInterrupted, context.Canceled} {
		result := normal
		joinPromptCleanup(&result, failure)
		var cleanup *promptCleanupError
		if !errors.As(result, &cleanup) || !errors.Is(result, failure) {
			t.Fatalf("cleanup failure lost: %v", result)
		}
	}
}

func TestLineEditorConcurrentPromptAndClose(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, reader)
	defer closeTestResource(t, writer)
	editor, err := newLineEditor(t.Context(), reader, io.Discard, io.Discard, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, editor)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := editor.Prompt(ctx, "FIRST> "); done <- err }()
	for !editor.isReading() {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := editor.Prompt(ctx, "SECOND> "); err == nil {
		t.Fatal("concurrent prompt accepted")
	}
	if err := editor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrLineEditorClosed) {
		t.Fatalf("closed prompt = %v", err)
	}
	if _, err := editor.Prompt(ctx, "AFTER> "); !errors.Is(err, ErrLineEditorClosed) {
		t.Fatalf("closed editor restarted: %v", err)
	}
}

func TestLineEditorHistoryFailureFallsBackToSession(t *testing.T) {
	dir := t.TempDir()
	historyPath := filepath.Join(dir, "history")
	writeTestFile(t, historyPath, []byte("previous\n"))
	// An unusable sidecar gives a deterministic storage error on all platforms.
	if err := os.Mkdir(historyPath+".lock", 0o700); err != nil {
		t.Fatal(err)
	}
	var warnings bytes.Buffer
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, reader)
	defer closeTestResource(t, writer)
	editor, err := newLineEditor(t.Context(), reader, io.Discard, &warnings, historyPath, &Shell{})
	if err != nil {
		t.Fatalf("optional history prevented startup: %v", err)
	}
	defer closeTestResource(t, editor)
	if warnings.Len() == 0 {
		t.Fatal("history failure was not reported")
	}
	if got := editor.history.Lines(); len(got) != 1 || got[0] != "previous" {
		t.Fatalf("readable history not retained: %v", got)
	}
	if err := editor.AppendHistory("session command"); err != nil {
		t.Fatal(err)
	}
	if got := editor.history.Lines(); len(got) != 2 || got[1] != "session command" {
		t.Fatalf("session history=%v", got)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		line, err := editor.Prompt(ctx, "HISTORY> ")
		if err == nil && line != "lpwd" {
			err = fmt.Errorf("line=%q", line)
		}
		done <- err
	}()
	if _, err := writer.WriteString("lpwd\r"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLineEditorTypeAheadAcrossBuffersAndRecreation(t *testing.T) {
	defer verifyNoShellGoroutineLeak(t)()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, reader)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	commands := make([]string, 80)
	var input strings.Builder
	for i := range commands {
		commands[i] = fmt.Sprintf("command-%02d-%s", i, strings.Repeat("x", 70))
		input.WriteString(commands[i] + "\r")
	}
	written := make(chan error, 1)
	go func() { _, err := writer.WriteString(input.String()); written <- errors.Join(err, writer.Close()) }()
	defer func() {
		closeTestResource(t, writer)
		if err := <-written; err != nil {
			t.Error(err)
		}
	}()
	shell := &Shell{}
	editor, err := newLineEditor(ctx, reader, io.Discard, io.Discard, "", shell)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closeTestResource(t, editor) }()
	for i, want := range commands {
		if i == 40 {
			if err := editor.Close(); err != nil {
				t.Fatal(err)
			}
			editor, err = newLineEditor(ctx, reader, io.Discard, io.Discard, "", shell)
			if err != nil {
				t.Fatal(err)
			}
			if len(editor.history.Lines()) != 40 {
				t.Fatal("session history did not survive editor recreation")
			}
		}
		line, err := editor.Prompt(ctx, "MACRO> ")
		if err != nil || line != want {
			t.Fatalf("prompt %d=%q err=%v", i, line, err)
		}
		if err := editor.AppendHistory(line); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := editor.Prompt(ctx, "EOF> "); !errors.Is(err, io.EOF) {
		t.Fatalf("macro EOF=%v", err)
	}
}

type finalChunkReader struct{ data []byte }

func (r *finalChunkReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, io.EOF
}
func (*finalChunkReader) Close() error { return nil }

func TestLineEditorPreservesDataReturnedWithEOF(t *testing.T) {
	editor, err := newLineEditor(t.Context(), &finalChunkReader{data: []byte("pwd\rhelp\r")}, io.Discard, io.Discard, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, editor)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	for _, want := range []string{"pwd", "help"} {
		line, err := editor.Prompt(ctx, "EOF> ")
		if err != nil || line != want {
			t.Fatalf("line=%q err=%v, want %q", line, err, want)
		}
	}
	if _, err := editor.Prompt(ctx, "EOF> "); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestLineEditorReportsHistoryWarningFailure(t *testing.T) {
	failure := errors.New("warning output failed")
	_, err := newLineEditor(t.Context(), nil, io.Discard, shellFailingWriter{err: failure}, t.TempDir(), &Shell{})
	if !errors.Is(err, failure) {
		t.Fatalf("warning failure lost: %v", err)
	}
}

func TestLineEditorCloseReleasesSession(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, reader)
	defer closeTestResource(t, writer)
	shell := &Shell{}
	editor, err := newLineEditor(t.Context(), reader, io.Discard, io.Discard, "", shell)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, editor)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := editor.Prompt(ctx, "CLOSE> "); done <- err }()
	for !editor.isReading() {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(time.Millisecond)
	}
	if err := editor.Close(); err != nil {
		t.Fatal(err)
	}
	if !editor.session.prompt.TryLock() {
		t.Fatal("Close returned with the session still locked")
	}
	editor.session.prompt.Unlock()
	if err := <-done; !errors.Is(err, ErrLineEditorClosed) {
		t.Fatal(err)
	}
}
