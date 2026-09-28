//go:build linux

package tui

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/term"
	pty "github.com/wentf9/xops-cli/internal/testpty"
	"go.uber.org/goleak"
	"golang.org/x/sys/unix"
)

type programReadyWriter struct {
	ready chan struct{}
	once  sync.Once
}

func (w *programReadyWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.ready) })
	return len(p), nil
}

func TestProgramQuitJoinsBurstDecoder(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  string
		cancel bool
		filter string
	}{
		{"ctrl-c burst", "\x03" + strings.Repeat("x", 1024), false, ""},
		{"quit burst", "q" + strings.Repeat("x", 1024), false, ""},
		{"cancel partial sequence", "\x1b[", true, ""},
		{"paste then quit", "/\x1b[200~user\x1b[201~\x03", false, "user"},
	} {
		t.Run(tc.name, func(t *testing.T) { testProgramShutdown(t, tc.input, tc.cancel, tc.filter) })
	}
}

func testProgramShutdown(t *testing.T, input string, cancelProgram bool, filter string) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { assertProgramNoLeaks(t, baseline) })
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTUITestResource(t, master)
	defer closeTUITestResource(t, slave)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	model := newV2TestModel(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	output := &programReadyWriter{ready: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, model, slave, output)
	}()
	select {
	case <-output.ready:
	case <-ctx.Done():
		t.Fatal("program did not render")
	}
	if _, err := io.WriteString(master, input); err != nil {
		t.Fatal(err)
	}
	if cancelProgram {
		cancel()
	}
	select {
	case err := <-done:
		if cancelProgram {
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled program returned %v", err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("program did not shut down")
	}
	if model.list.FilterValue() != filter {
		t.Fatalf("filter = %q, want %q", model.list.FilterValue(), filter)
	}
	after, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || *before != *after {
		t.Fatalf("terminal was not restored: %v", err)
	}
}

func TestProgramUnlockReleasesAndRestartsInput(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { assertProgramNoLeaks(t, baseline) })
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTUITestResource(t, master)
	defer closeTUITestResource(t, slave)
	before, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	model := newV2TestModel(t)
	restored := make(chan error, 1)
	model.vaultControl = func(ctx context.Context, unlock bool) error {
		state, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err == nil && (!unlock || *state != *before) {
			err = errors.New("unlock did not receive the restored terminal")
		}
		restored <- err
		return err
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	output := &programReadyWriter{ready: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, model, slave, output) }()
	select {
	case <-output.ready:
	case <-ctx.Done():
		t.Fatal("program did not render")
	}
	if _, err := io.WriteString(master, "\x15"+strings.Repeat("x", 1024)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-restored:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("unlock did not run")
	}
	if _, err := io.WriteString(master, "\x03"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("input did not resume after unlock")
	}
}

// Bubbles may finish an already-scheduled cursor blink after Run returns.
// Allow that bounded timer, but never ignore a decoder or command goroutine.
func assertProgramNoLeaks(t *testing.T, baseline goleak.Option) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := goleak.Find(baseline)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Exercise the query and terminal reply through the real input decoder, rather
// than injecting a BackgroundColorMsg directly into Model.Update.
func TestProgramRequestsAndDecodesBackground(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { assertProgramNoLeaks(t, baseline) })
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTUITestResource(t, master)
	defer closeTUITestResource(t, slave)
	model := newV2TestModel(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	output := &backgroundQueryWriter{queried: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, model, slave, output) }()
	select {
	case <-output.queried:
	case <-ctx.Done():
		<-done
		t.Fatal("startup did not request the terminal background color")
	}
	if _, err := io.WriteString(master, "\x1b]11;rgb:ffff/ffff/ffff\x1b\\\x03"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("program did not quit after the background reply")
	}
	if model.backgroundColor == nil || model.hasDarkBackground() {
		t.Fatal("terminal background reply did not select the light palette")
	}
	if model.list.Styles.StatusBarActiveFilter.GetForeground() != lipgloss.Color("#1a1a1a") {
		t.Fatal("terminal background discovery did not update the node list")
	}
}

type backgroundQueryWriter struct {
	mu      sync.Mutex
	buffer  strings.Builder
	queried chan struct{}
	once    sync.Once
}

func (w *backgroundQueryWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buffer.Write(p)
	if strings.Contains(w.buffer.String(), "\x1b]11;?") {
		w.once.Do(func() { close(w.queried) })
	}
	return n, err
}

// Run the same polling implementation used on Windows against a real PTY.
// Changing the terminal size requires no keypress or terminal handoff.
func TestProgramSizeWatcherReadsTerminalResize(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	defer goleak.VerifyNone(t, baseline)
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTUITestResource(t, master)
	defer closeTUITestResource(t, slave)
	if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	events := make(chan tea.Msg, 4)
	stop := pollProgramSize(ctx, func() (int, int, error) { return term.GetSize(slave.Fd()) }, func(msg tea.Msg) {
		select {
		case events <- msg:
		case <-ctx.Done():
		}
	})
	defer stop()
	for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 24}, {Width: 120, Height: 40}, {Width: 60, Height: 20}} {
		if err := pty.Setsize(master, &pty.Winsize{Cols: uint16(size.Width), Rows: uint16(size.Height)}); err != nil {
			t.Fatal(err)
		}
		select {
		case msg := <-events:
			if msg != size {
				t.Fatalf("resize = %#v, want %#v", msg, size)
			}
		case <-ctx.Done():
			t.Fatal("terminal resize did not reach the watcher")
		}
	}
}
