//go:build !windows

package sftpshell

import (
	"context"
	"fmt"
	"github.com/creack/pty"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestLineEditorPTYPartialTypeAhead(t *testing.T) {
	cases := []struct{ name, first, rest, want string }{
		{"paste body", "\x1b[200~get first", "\nrm second\x1b[201~", "get first rm second"},
		{"paste opener", "\x1b[20", "0~get first\nrm second\x1b[201~", "get first rm second"},
		{"paste closer", "\x1b[200~get first\nrm second\x1b[20", "1~", "get first rm second"},
		{"UTF-8", "get \xe7", "\x95\x8c", "get 界"},
		{"escape sequence", "ab\x1b[", "Dc", "acb"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			baseline := goleak.IgnoreCurrent()
			t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
			h := newEditorPTY(t)
			shell := &Shell{}
			editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", shell)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeTestResource(t, editor) })
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			type result struct {
				line string
				err  error
			}
			done := make(chan result, 1)
			go func() { line, err := editor.Prompt(ctx, "FIRST> "); done <- result{line, err} }()
			h.wait(t, "FIRST>")
			h.write(t, "pwd\r"+tt.first)
			got := <-done
			if got.line != "pwd" || got.err != nil {
				t.Fatalf("first prompt: %+v", got)
			}
			// Recreating the editor and spending longer than the escape timeout outside
			// a prompt must not flush partial input or leave a terminal reader running.
			closeTestResource(t, editor)
			time.Sleep(75 * time.Millisecond)
			editor, err = newLineEditor(ctx, h.slave, h.slave, h.slave, "", shell)
			if err != nil {
				t.Fatal(err)
			}
			go func() { line, err := editor.Prompt(ctx, "SECOND> "); done <- result{line, err} }()
			h.wait(t, "SECOND>")
			h.write(t, tt.rest)
			h.wait(t, tt.want)
			select {
			case got := <-done:
				t.Fatalf("submitted without Enter: %+v", got)
			default:
			}
			h.write(t, "\r")
			got = <-done
			if got.line != tt.want || got.err != nil {
				t.Fatalf("second prompt: %+v, want %q", got, tt.want)
			}
		})
	}
}

// Observe the pipe output using the same terminal-screen assertions as a PTY,
// without replacing process-global stdin/stdout.
type editorScreenWriter struct{ screen *editorPTY }

func (w editorScreenWriter) Write(p []byte) (int, error) {
	w.screen.mu.Lock()
	defer w.screen.mu.Unlock()
	return w.screen.raw.Write(p)
}

func TestLineEditorPTYPipedOutput(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	h := newEditorPTY(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	screen := &editorPTY{}
	copied := make(chan error, 1)
	go func() { _, err := io.Copy(editorScreenWriter{screen}, reader); copied <- err }()
	t.Cleanup(func() {
		closeTestResource(t, writer)
		if err := <-copied; err != nil {
			t.Error(err)
		}
		closeTestResource(t, reader)
	})
	editor, err := newLineEditor(t.Context(), h.slave, writer, io.Discard, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for i, options := range []promptOptions{{text: "PIPE> "}, {text: "Overwrite? [y/N]: ", confirmation: true}} {
		done := make(chan error, 1)
		go func() {
			line, err := editor.prompt(ctx, options)
			if err == nil && line != "yes" {
				err = fmt.Errorf("answer = %q", line)
			}
			done <- err
		}()
		screen.wait(t, strings.TrimSpace(options.text))
		h.write(t, "yes")
		screen.wait(t, options.text+"yes")
		h.write(t, "\r")
		if err := <-done; err != nil {
			t.Fatalf("prompt %d: %v", i, err)
		}
	}
}

func TestLineEditorPTYRedirectedResize(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	h := newEditorPTY(t)
	// A writer without Fd behaves like tee output from Bubble Tea's perspective.
	// Capture it directly so no process-global output replacement is needed.
	screen := &editorPTY{}
	editor, err := newLineEditor(t.Context(), h.slave, editorScreenWriter{screen}, io.Discard, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		line, err := editor.Prompt(ctx, "RESIZE> ")
		if err == nil && line != strings.Repeat("x", 60) {
			err = fmt.Errorf("input after resize = %q", line)
		}
		done <- err
	}()
	screen.wait(t, "RESIZE>")
	h.write(t, strings.Repeat("x", 60))
	screen.wait(t, "RESIZE> "+strings.Repeat("x", 60))
	for _, cols := range []uint16{30, 100} {
		if err := pty.Setsize(h.slave, &pty.Winsize{Rows: 24, Cols: cols}); err != nil {
			t.Fatal(err)
		}
		// This standalone PTY has no foreground process group to receive SIGWINCH.
		if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
			t.Fatal(err)
		}
		wantColumn := min(68, int(cols)-1)
		for {
			screen.mu.Lock()
			raw := screen.raw.String()
			screen.mu.Unlock()
			cursor, err := terminalCursor(raw, 100, 24)
			if err != nil {
				t.Fatal(err)
			}
			if cursor.X == wantColumn && cursor.Y == 0 {
				break
			}
			if ctx.Err() != nil {
				t.Fatalf("resize to %d: cursor=%+v, want (%d,0)", cols, cursor, wantColumn)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	h.write(t, "\r")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLineEditorPTYUnicodeModeReport(t *testing.T) {
	h := newEditorPTY(t)
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		line, err := editor.Prompt(ctx, "UNICODE> ")
		if err == nil && line != "❤️" {
			err = fmt.Errorf("Unicode input = %q", line)
		}
		done <- err
	}()
	h.wait(t, "UNICODE>")
	// A terminal that supports mode 2027 reports that it is currently reset.
	h.write(t, "\x1b[?2027;2$y❤️")
	for {
		h.mu.Lock()
		raw := h.raw.String()
		h.mu.Unlock()
		cursor, err := terminalCursor(raw, 100, 24)
		if err != nil {
			t.Fatal(err)
		}
		negotiated := strings.Contains(raw, "\x1b[?2027h")
		if negotiated && strings.Contains(raw, "❤️") && cursor.X == 11 && cursor.Y == 0 {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("Unicode mode negotiated=%v, cursor=%+v; want (11,0), raw=%q", negotiated, cursor, raw)
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.write(t, "\r")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLineEditorPTYTranscriptBeyondScreen(t *testing.T) {
	h := newEditorPTY(t)
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	command := "BEGIN_MARKER_" + strings.Repeat("x", 2500) + "_END_MARKER"
	done := make(chan error, 1)
	go func() {
		line, err := editor.Prompt(ctx, "LONG> ")
		if err == nil && line != command {
			err = fmt.Errorf("submitted command was truncated")
		}
		done <- err
	}()
	h.wait(t, "LONG>")
	h.write(t, "\x1b[200~"+command+"\x1b[201~\r")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(h.slave, "AFTER_ECHO"); err != nil {
		t.Fatal(err)
	}
	h.wait(t, "\nAFTER_ECHO")
	h.mu.Lock()
	raw := h.raw.String()
	h.mu.Unlock()
	// Raw output includes scrollback that a screen-sized snapshot cannot show.
	transcript := strings.ReplaceAll(raw, "\r\n", "\n")
	if count := strings.Count(transcript, "LONG> "+command+"\n"); count != 1 {
		t.Fatalf("complete command echo count=%d, want 1 (head present=%v)", count, strings.Contains(raw, "BEGIN_MARKER_"))
	}
}
