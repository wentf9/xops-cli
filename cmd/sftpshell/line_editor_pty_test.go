//go:build !windows

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
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/wentf9/xops-cli/internal/terminal"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"go.uber.org/goleak"
	"golang.org/x/term"
)

type editorPTY struct {
	master, slave *os.File
	mu            sync.Mutex
	raw           strings.Builder
}

func newEditorPTY(t *testing.T) *editorPTY {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, slave); closeTestResource(t, master) })
	if err := pty.Setsize(slave, &pty.Winsize{Rows: 24, Cols: 100}); err != nil {
		t.Fatal(err)
	}
	h := &editorPTY{master: master, slave: slave}
	input, err := terminal.DuplicatePromptInput(master)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	stop := context.AfterFunc(ctx, func() {
		if err := input.Interrupt(); err != nil {
			t.Error(err)
		}
	})
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := input.Read(buf)
			if n > 0 {
				h.mu.Lock()
				h.raw.Write(buf[:n])
				_, parseErr := terminalScreen(h.raw.String(), 100, 24)
				h.mu.Unlock()
				if parseErr != nil {
					done <- parseErr
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					err = nil
				}
				done <- err
				return
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		if err := input.Interrupt(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
		stop()
		if err := input.Close(); err != nil {
			t.Error(err)
		}
	})
	return h
}
func (h *editorPTY) text() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	screen, err := terminalScreen(h.raw.String(), 100, 24)
	if err != nil {
		return err.Error()
	}
	return screen
}
func (h *editorPTY) wait(t *testing.T, text string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(h.text(), text) {
		if time.Now().After(deadline) {
			h.mu.Lock()
			raw := h.raw.String()
			h.mu.Unlock()
			t.Fatalf("waiting for %q, screen:\n%s\nraw:%q", text, h.text(), raw)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func (h *editorPTY) write(t *testing.T, text string) {
	t.Helper()
	if _, err := h.master.WriteString(text); err != nil {
		t.Fatal(err)
	}
}
func TestLineEditorPTY(t *testing.T) {
	// Run cleanup before leak verification, retaining the original goroutine set.
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	h := newEditorPTY(t)
	original, err := term.GetState(int(h.slave.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{localCwd: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	cases := []struct {
		keys, want string
		err        error
	}{
		{"\x1b[3~pwd\r", "pwd", nil},
		{"abc\x01\x1b[3~\r", "bc", nil},
		{"abc\x04\r", "abc", nil},
		{"e\u0301界\x01\x1b[3~\r", "界", nil},
		{"\x1b[200~ls\nexit\x1b[201~\r", "ls exit", nil},
		{"\x03", "", ErrPromptInterrupted},
		{"\x04", "", io.EOF},
		{"lpwd\r", "lpwd", nil},
	}
	for i, tt := range cases {
		prompt := fmt.Sprintf("ROUND%d> ", i)
		type result struct {
			line string
			err  error
		}
		resultc := make(chan result, 1)
		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		go func() { line, err := editor.Prompt(ctx, prompt); resultc <- result{line, err} }()
		h.wait(t, strings.TrimSpace(prompt))
		h.write(t, tt.keys)
		got := <-resultc
		cancel()
		if got.line != tt.want || !errors.Is(got.err, tt.err) {
			t.Fatalf("round %d: line=%q err=%v", i, got.line, got.err)
		}
		if tt.err == nil {
			h.wait(t, prompt+tt.want)
			marker := fmt.Sprintf("AFTER_%d", i)
			if _, err := fmt.Fprintln(h.slave, marker); err != nil {
				t.Fatal(err)
			}
			h.wait(t, "\n"+marker)
		}
		state, err := term.GetState(int(h.slave.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		if *state != *original {
			t.Fatalf("terminal mode not restored after round %d", i)
		}
	}
	// A canonical reader must get the first input after the editor yields.
	h.write(t, "handoff\n")
	buf := make([]byte, 64)
	n, err := h.slave.Read(buf)
	if err != nil || string(buf[:n]) != "handoff\n" {
		t.Fatalf("handoff read=%q err=%v", buf[:n], err)
	}
}
func TestLineEditorPTYCancelAndOutputFailure(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	h := newEditorPTY(t)
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, editor)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := editor.Prompt(ctx, "CANCEL> "); done <- err }()
	h.wait(t, "CANCEL>")
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	failure := errors.New("output rejected")
	broken, err := newLineEditor(t.Context(), h.slave, shellFailingWriter{failure}, io.Discard, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestResource(t, broken)
	timeout, stop := context.WithTimeout(t.Context(), 2*time.Second)
	defer stop()
	if _, err := broken.Prompt(timeout, "BROKEN> "); !errors.Is(err, failure) {
		t.Fatalf("output failure lost: %v", err)
	}
}

func TestLineEditorPTYCompletionCancellation(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	h := newEditorPTY(t)
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	started, finished := make(chan struct{}), make(chan struct{})
	editor.complete = func(ctx context.Context, _ string, _ int) completionResult {
		close(started)
		<-ctx.Done()
		close(finished)
		return completionResult{err: ctx.Err()}
	}
	result := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	go func() {
		line, err := editor.Prompt(ctx, "ASYNC> ")
		if line != "get x" && err == nil {
			err = fmt.Errorf("line = %q", line)
		}
		result <- err
	}()
	h.wait(t, "ASYNC>")
	h.write(t, "get \t")
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	h.write(t, "x\r")
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("completion still running after prompt returned")
	}
}

func TestLineEditorPTYLongPrompt(t *testing.T) {
	h := newEditorPTY(t)
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	result := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	go func() {
		line, err := editor.prompt(ctx, promptOptions{text: strings.Repeat("长路径/", 30) + " [y/N]: ", confirmation: true})
		if err == nil && line != "n" {
			err = fmt.Errorf("answer = %q", line)
		}
		result <- err
	}()
	h.wait(t, "[y/N]")
	h.write(t, "n\r")
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestLineEditorPTYBurstShutdown(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	h := newEditorPTY(t)
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := editor.Prompt(ctx, "BURST> "); done <- err }()
	h.wait(t, "BURST>")
	h.write(t, "pwd\r"+strings.Repeat("x", 200))
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLineEditorPTYLongCommandTranscript(t *testing.T) {
	h := newEditorPTY(t)
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	command := strings.Repeat("a", 120) + "TAIL_MARKER"
	go func() {
		line, err := editor.Prompt(ctx, "LONG> ")
		if err == nil && line != command {
			err = fmt.Errorf("long input was truncated")
		}
		done <- err
	}()
	h.wait(t, "LONG>")
	h.write(t, command+"\r")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	h.wait(t, "TAIL_MARKER")
	h.wait(t, "LONG> aaaa")
}

func TestLineEditorPTYDirectoryCompletion(t *testing.T) {
	h := newEditorPTY(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "bin", "lib"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "bin", "lib", "tool.txt"), []byte("test"))
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{localCwd: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		line, err := editor.Prompt(ctx, "DIRECTORY> ")
		if err == nil && line != "put bin/lib/tool.txt" {
			err = fmt.Errorf("completed input = %q", line)
		}
		done <- err
	}()
	h.wait(t, "DIRECTORY>")
	h.write(t, "put bin\t")
	h.wait(t, "DIRECTORY> put bin/")
	h.write(t, "\t")
	h.wait(t, "DIRECTORY> put bin/lib/")
	h.write(t, "\t")
	h.wait(t, "DIRECTORY> put bin/lib/tool.txt")
	h.write(t, "\r")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLineEditorPTYConfirmCompletionBeforeSubmit(t *testing.T) {
	h := newEditorPTY(t)
	dir := t.TempDir()
	for _, name := range []string{"bina", "binb"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(dir, "binb", "tool.txt"), []byte("test"))
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{localCwd: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		line, err := editor.Prompt(ctx, "CHOOSE> ")
		if err == nil && line != "put binb/tool.txt" {
			err = fmt.Errorf("submitted input=%q", line)
		}
		done <- err
	}()
	h.wait(t, "CHOOSE>")
	h.write(t, "put bin\t")
	h.wait(t, "bina/")
	h.wait(t, "binb/")
	h.write(t, "\t")
	h.wait(t, "CHOOSE> put bina/")
	h.write(t, "\t")
	h.wait(t, "CHOOSE> put binb/")
	// Enter must accept binb/, leaving this same prompt available for Tab.
	h.write(t, "\r\t")
	h.wait(t, "CHOOSE> put binb/tool.txt")
	select {
	case err := <-done:
		t.Fatalf("prompt returned before submission: %v", err)
	default:
	}
	h.write(t, "\r")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLineEditorPTYCompletionHighlight(t *testing.T) {
	previousColor := logger.ColorEnabled()
	t.Cleanup(func() {
		if previousColor {
			logger.SetColorMode("always")
		} else {
			logger.SetColorMode("never")
		}
	})
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	for _, mode := range []string{"always", "never"} {
		t.Run(mode, func(t *testing.T) {
			logger.SetColorMode(mode)
			h := newEditorPTY(t)
			dir := t.TempDir()
			for _, name := range []string{"bina", "binb"} {
				if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{localCwd: dir})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { closeTestResource(t, editor) })
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				line, err := editor.Prompt(ctx, "HIGHLIGHT> ")
				if err == nil && line != "put binb/" {
					err = fmt.Errorf("selected input = %q", line)
				}
				done <- err
			}()
			h.wait(t, "HIGHLIGHT>")
			h.write(t, "put bin\t")
			h.wait(t, "bina/")
			h.wait(t, "binb/")
			for selected, name := range []string{"bina/", "binb/"} {
				h.write(t, "\t")
				h.wait(t, "> "+name)
				if mode == "always" {
					h.mu.Lock()
					raw := h.raw.String()
					h.mu.Unlock()
					screen, err := parseTerminalScreen(raw, 100, 24)
					if err != nil {
						t.Fatal(err)
					}
					menu := strings.Split(screen.String(), "\n")[1]
					for i, label := range []string{"bina/", "binb/"} {
						column := strings.Index(menu, label)
						if column < 0 {
							t.Fatalf("candidate %q missing from %q", label, menu)
						}
						if styled := screen.Cell(column, 1).Mode != 0; styled != (i == selected) {
							t.Fatalf("candidate %q styled=%v, selected=%v", label, styled, i == selected)
						}
					}
				}
			}
			h.write(t, "\r\r")
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLineEditorPTYPagedCompletion(t *testing.T) {
	initTestI18n(t)
	// vt10x counts wide characters as single cells; use an ASCII footer when
	// checking incremental terminal cursor updates, with locale coverage below.
	i18n.SetLang("en")
	t.Cleanup(func() { i18n.SetLang("zh") })
	h := newEditorPTY(t)
	dir := t.TempDir()
	for i := range 120 {
		if err := os.Mkdir(filepath.Join(dir, fmt.Sprintf("bin%03d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(dir, "bin054", "tool.txt"), []byte("test"))
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{localCwd: dir})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		line, err := editor.Prompt(ctx, "PAGES> ")
		if err == nil && line != "put bin054/tool.txt" {
			err = fmt.Errorf("paged completion submitted %q", line)
		}
		done <- err
	}()
	h.wait(t, "PAGES>")
	h.write(t, "put bin\t")
	// A 100-column terminal fits nine columns and six rows, or 54 items.
	h.wait(t, "1/3")
	h.wait(t, "bin053/")
	if strings.Contains(h.text(), "bin054/") {
		t.Fatal("second page was displayed on the first page")
	}
	for _, step := range []struct{ keys, page, selected string }{
		{"\x1b[6~", "2/3", "bin054/"},
		{"\x1b[6~", "3/3", "bin108/"},
		{"\x1b[5~", "2/3", "bin054/"},
		{"\x1b[Z", "1/3", "bin053/"},
		{"\t", "2/3", "bin054/"},
	} {
		h.write(t, step.keys)
		h.wait(t, "PAGES> put "+step.selected)
		h.wait(t, step.page)
		h.wait(t, "> "+step.selected)
	}
	h.write(t, "\r\t")
	h.wait(t, "PAGES> put bin054/tool.txt")
	select {
	case err := <-done:
		t.Fatalf("selection submitted early: %v", err)
	default:
	}
	h.write(t, "\r")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConfirmationInterruptStopsLocalCommand(t *testing.T) {
	initTestI18n(t)
	for _, command := range []string{"lcp", "lmv", "lrm"} {
		t.Run(command, func(t *testing.T) {
			h := newEditorPTY(t)
			dir := t.TempDir()
			for _, sub := range []string{"src", "dst"} {
				if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			writeTestFile(t, filepath.Join(dir, "src", "a"), []byte("a"))
			writeTestFile(t, filepath.Join(dir, "src", "b"), []byte("b"))
			writeTestFile(t, filepath.Join(dir, "dst", "a"), []byte("original"))
			shell := &Shell{cwd: "/", localCwd: dir, stdin: h.slave, stdout: h.slave, stderr: h.slave}
			editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", shell)
			if err != nil {
				t.Fatal(err)
			}
			shell.line = editor
			t.Cleanup(func() { closeTestResource(t, editor) })
			args := []string{"src/*", "dst"}
			if command == "lrm" {
				args = args[:1]
			}
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := shell.dispatchCommand(ctx, command, args); done <- err }()
			confirmation := command + ": overwrite local"
			if command == "lrm" {
				confirmation = "lrm: remove local"
			}
			h.wait(t, confirmation)
			h.write(t, "\x03")
			commandErr := <-done
			if !errors.Is(commandErr, ErrPromptInterrupted) {
				t.Fatalf("confirmation interruption=%v", commandErr)
			}
			if err := shell.reportCommandError(commandErr); err != nil {
				t.Fatalf("interruption terminated REPL: %v", err)
			}
			for _, name := range []string{"a", "b"} {
				if _, err := os.Stat(filepath.Join(dir, "src", name)); err != nil {
					t.Fatalf("source changed after cancellation: %v", err)
				}
			}
			if got := string(readTestFile(t, filepath.Join(dir, "dst", "a"))); got != "original" {
				t.Fatal("overwrite occurred")
			}
			if _, err := os.Stat(filepath.Join(dir, "dst", "b")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("later file processed: %v", err)
			}
			next := make(chan error, 1)
			go func() {
				line, err := editor.Prompt(t.Context(), "RECOVERED> ")
				if err == nil && line != "lpwd" {
					err = fmt.Errorf("next command=%q", line)
				}
				next <- err
			}()
			h.wait(t, "RECOVERED>")
			h.write(t, "lpwd\r")
			if err := <-next; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLineEditorPTYHistorySearchPaste(t *testing.T) {
	h := newEditorPTY(t)
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	for _, line := range []string{"get needle", "rm other"} {
		if err := editor.AppendHistory(line); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		line, err := editor.Prompt(ctx, "SEARCH> ")
		if err == nil && line != "get needle" {
			err = fmt.Errorf("search result=%q", line)
		}
		done <- err
	}()
	h.wait(t, "SEARCH>")
	h.write(t, "\x12\x1b[200~needle\x1b[201~")
	h.wait(t, "SEARCH> get needle")
	h.wait(t, "history search: needle")
	h.write(t, "\r\r")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestShellRunContinuesAfterConfirmationInterrupt(t *testing.T) {
	initTestI18n(t)
	h := newEditorPTY(t)
	dir := t.TempDir()
	for _, name := range []string{"src", "dst"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestFile(t, filepath.Join(dir, "src", "a"), []byte("a"))
	writeTestFile(t, filepath.Join(dir, "src", "b"), []byte("b"))
	writeTestFile(t, filepath.Join(dir, "dst", "a"), []byte("old"))
	shell := &Shell{cwd: "/", localCwd: dir, stdin: h.slave, stdout: h.slave, stderr: h.slave}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- shell.Run(ctx) }()
	h.wait(t, "sftp:/>")
	h.write(t, "lcp src/* dst\r")
	h.wait(t, "lcp: overwrite local")
	h.write(t, "\x03")
	for !strings.HasSuffix(strings.TrimSpace(h.text()), "sftp:/>") {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(dir, "dst", "b")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second file was copied: %v", err)
	}
	h.write(t, "lpwd\r")
	h.wait(t, "sftp:/> lpwd")
	for !strings.HasSuffix(strings.TrimSpace(h.text()), "sftp:/>") {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.write(t, "exit\r")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLineEditorPTYTypeAhead(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
	h := newEditorPTY(t)
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		for i, want := range []string{"pwd", "help", "exit"} {
			line, err := editor.Prompt(ctx, fmt.Sprintf("AHEAD%d> ", i))
			if err != nil {
				done <- err
				return
			}
			if line != want {
				done <- fmt.Errorf("prompt %d=%q, want %q", i, line, want)
				return
			}
		}
		done <- nil
	}()
	h.wait(t, "AHEAD0>")
	h.write(t, "pwd\rhelp\rexit\r")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestShellStartsWithReadOnlyHistoryDirectory(t *testing.T) {
	initTestI18n(t)
	h := newEditorPTY(t)
	dir := t.TempDir()
	historyPath := filepath.Join(dir, "history")
	writeTestFile(t, historyPath, []byte("previous\n"))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Error(err)
		}
	})
	probe, err := os.Create(filepath.Join(dir, "probe"))
	if err == nil {
		closeTestResource(t, probe)
		t.Skip("current user bypasses directory write permissions")
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	var warnings bytes.Buffer
	shell := &Shell{cwd: "/", localCwd: dir, stdin: h.slave, stdout: h.slave, stderr: &warnings, historyFile: historyPath}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- shell.Run(ctx) }()
	h.wait(t, "sftp:/>")
	h.write(t, "lpwd\rexit\r")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warnings.String(), "session history") {
		t.Fatalf("missing fallback warning: %q", warnings.String())
	}
	if got := string(readTestFile(t, historyPath)); got != "previous\n" {
		t.Fatalf("read-only history changed: %q", got)
	}
	if got := shell.editorState.history.Lines(); len(got) != 3 {
		t.Fatalf("session history not usable: %v", got)
	}
}

func TestLineEditorPTYCursorCellsAndScrolling(t *testing.T) {
	h := newEditorPTY(t)
	editor, err := newLineEditor(t.Context(), h.slave, h.slave, h.slave, "", &Shell{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestResource(t, editor) })
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		line, err := editor.Prompt(ctx, "CURSOR> ")
		if err == nil && line != strings.Repeat("a", 120) {
			err = fmt.Errorf("final input=%q", line)
		}
		done <- err
	}()
	h.wait(t, "CURSOR>")
	for _, step := range []struct {
		keys   string
		column int
	}{
		{"界", 10}, {"\x1b[D", 8}, {"a", 9}, {"\x05", 11}, {"\x7f", 9},
		{"\x15e\u0301", 9}, {"\x01\x0b👩‍💻", 10}, {"\x01\x1b[3~", 8},
		{strings.Repeat("a", 120), 99}, {strings.Repeat("\x1b[D", 6), 93},
	} {
		h.write(t, step.keys)
		for {
			h.mu.Lock()
			raw := h.raw.String()
			h.mu.Unlock()
			cursor, err := terminalCursor(raw, 100, 24)
			if err != nil {
				t.Fatal(err)
			}
			if cursor.X == step.column && cursor.Y == 0 {
				break
			}
			if ctx.Err() != nil {
				t.Fatalf("cursor=%+v, want column %d after %q", cursor, step.column, step.keys)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	h.write(t, "\r")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
