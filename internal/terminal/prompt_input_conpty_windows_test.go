//go:build windows && integration

package terminal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/conpty"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

const vtHelperEnv = "XOPS_VT_INPUT_HELPER"

func TestWindowsInteractiveInputConPTY(t *testing.T) {
	if marker := os.Getenv(vtHelperEnv); marker != "" {
		runVTHelper(t, marker)
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	console, output := newVTConsole(t)

	marker := filepath.Join(t.TempDir(), "progress")
	pid, handle, err := console.Spawn(os.Args[0],
		[]string{os.Args[0], "-test.run=^TestWindowsInteractiveInputConPTY$", "-test.timeout=15s"},
		&syscall.ProcAttr{Env: append(os.Environ(), vtHelperEnv+"="+marker)})
	if err != nil {
		t.Fatal(err)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(errors.Join(err, windows.TerminateProcess(windows.Handle(handle), 1), windows.CloseHandle(windows.Handle(handle))))
	}
	if err := windows.CloseHandle(windows.Handle(handle)); err != nil {
		t.Error(err)
	}
	type result struct {
		state *os.ProcessState
		err   error
	}
	done := make(chan result, 1)
	go func() {
		state, err := process.Wait()
		done <- result{state, err}
	}()
	finished := false
	defer func() {
		if !finished {
			select {
			case <-done:
				return
			default:
			}
			if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error(err)
			}
			<-done
		}
	}()

	for phase, sequence := range vtInputSequences {
		waitVTStage(t, ctx, marker, strconv.Itoa(phase), output)
		if _, err := io.WriteString(console, sequence); err != nil {
			t.Fatal(err)
		}
	}
	waitVTStage(t, ctx, marker, strconv.Itoa(len(vtInputSequences)), output)
	if _, err := io.WriteString(console, "z"); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		finished = true
		if result.err != nil || !result.state.Success() {
			t.Fatalf("ConPTY child failed: %v: %s", result.err, output.text())
		}
	case <-ctx.Done():
		t.Fatalf("ConPTY child did not exit: %s", output.text())
	}
}

// Exercise VT sequences from an actual ConPTY, not synthesized navigation keys.
// Each Read corresponds to one Write in the SSH stdin forwarding loop.
var vtInputSequences = []string{"\x1b[A", "\x1b[B", "\x1b[30;1R", "\x1b[O", "\x1b[I", "\x1b[200~paste\x1b[201~", "界", "😀", "\x00", "\x1b[1;5D", "\x1b[Z", "\x1b", strings.Repeat("x", windowsConsoleInputBatchSize-1) + "😀\x1b[A"}

func runVTHelper(t *testing.T, marker string) {
	state, err := term.GetState(int(os.Stdin.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := term.Restore(int(os.Stdin.Fd()), state); err != nil {
			t.Error(err)
		}
	}()
	enableVTFocusReporting(t)
	input, err := DuplicateInteractiveInput(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := input.Close(); err != nil {
			t.Error(err)
		}
	}()
	// Exercise the SFTP lifecycle too: construct the reader before switching
	// the borrowed console to VT mode. Mode selection must happen at read time.
	if _, err := term.MakeRaw(int(os.Stdin.Fd())); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	defer cancelVTHelperInput(t, ctx, input)()
	readVTHelperSequences(t, marker, input)
	checkVTHelperHandoff(t, ctx, marker, input)
}

func cancelVTHelperInput(t *testing.T, ctx context.Context, input PromptInput) func() {
	t.Helper()
	interruptDone := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { interruptDone <- input.Interrupt() })
	return func() {
		if !stop() {
			if err := <-interruptDone; err != nil {
				t.Error(err)
			}
		}
	}
}

func readVTHelperSequences(t *testing.T, marker string, input PromptInput) {
	t.Helper()
	buffer := make([]byte, 4096)
	for phase, sequence := range vtInputSequences {
		if err := os.WriteFile(marker, []byte(strconv.Itoa(phase)), 0600); err != nil {
			t.Fatal(err)
		}
		var n int
		var err error
		if len(sequence) > windowsConsoleInputBatchSize {
			// Large bursts may span multiple reads; assert stream integrity.
			n, err = io.ReadFull(input, buffer[:len(sequence)])
		} else {
			n, err = input.Read(buffer)
		}
		if err != nil || string(buffer[:n]) != sequence {
			t.Fatalf("phase %d: read %q, err=%v, want %q", phase, buffer[:n], err, sequence)
		}
	}
}

func checkVTHelperHandoff(t *testing.T, ctx context.Context, marker string, input PromptInput) {
	t.Helper()
	buffer := make([]byte, 4096)
	// Closing must also cancel a blocked console read and release the handle.
	readDone := make(chan error, 1)
	go func() { _, err := input.Read(buffer); readDone <- err }()
	if err := input.Interrupt(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("canceled read: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("console read did not stop")
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := DuplicateInteractiveInput(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := next.Close(); err != nil {
			t.Error(err)
		}
	}()
	defer cancelVTHelperInput(t, ctx, next)()
	if err := os.WriteFile(marker, []byte(strconv.Itoa(len(vtInputSequences))), 0600); err != nil {
		t.Fatal(err)
	}
	n, err := next.Read(buffer)
	if err != nil || string(buffer[:n]) != "z" {
		t.Fatalf("reader after handoff: read %q, err=%v, want z", buffer[:n], err)
	}
}

func enableVTFocusReporting(t *testing.T) {
	t.Helper()
	handle := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		t.Fatalf("read console output mode: %v", err)
	}
	if err := windows.SetConsoleMode(handle, mode|windows.ENABLE_PROCESSED_OUTPUT|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		t.Fatalf("enable console VT output: %v", err)
	}
	t.Cleanup(func() {
		if err := windows.SetConsoleMode(handle, mode); err != nil {
			t.Errorf("restore console output mode: %v", err)
		}
	})
	// ConPTY can consume focus notifications instead of forwarding their VT
	// input unless the child requests focus reporting. This fixture owns a fresh
	// console, where reporting starts disabled. Disable it again before restoring
	// the output mode, including when a later assertion fails.
	t.Cleanup(func() {
		if _, err := io.WriteString(os.Stdout, "\x1b[?1004l"); err != nil {
			t.Errorf("disable console focus reporting: %v", err)
		}
	})
	if _, err := io.WriteString(os.Stdout, "\x1b[?1004h"); err != nil {
		t.Fatalf("enable console focus reporting: %v", err)
	}
}

type vtOutput struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (o *vtOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buffer.Write(p)
}

func (o *vtOutput) text() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buffer.String()
}

func newVTConsole(t *testing.T) (*conpty.ConPty, *vtOutput) {
	t.Helper()
	console, err := conpty.New(100, 30, 0)
	if err != nil {
		t.Fatal(err)
	}
	output := &vtOutput{}
	readDone := make(chan error, 1)
	// Closing the owned ConPTY after the child exits unblocks this reader.
	go func() {
		_, err := io.Copy(output, console)
		readDone <- err
	}()
	t.Cleanup(func() {
		if err := console.Close(); err != nil {
			t.Error(err)
		}
		select {
		case err := <-readDone:
			if !isVTOutputCloseError(err) {
				t.Errorf("read ConPTY output: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("ConPTY output reader did not exit")
		}
	})

	return console, output
}

// Only use this after closing the owned ConPTY. Its reader calls ReadFile
// directly, so a read racing with CloseHandle can return ERROR_INVALID_HANDLE
// instead of os.ErrClosed or ERROR_BROKEN_PIPE.
func isVTOutputCloseError(err error) bool {
	return err == nil || errors.Is(err, os.ErrClosed) ||
		errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_INVALID_HANDLE)
}

func TestWindowsConPTYOutputClosedHandle(t *testing.T) {
	console, err := conpty.New(100, 30, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := console.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := console.Close(); err != nil {
		t.Fatal(err)
	}
	// Force the next iteration of the output-copy loop to run after Close,
	// without depending on the scheduler to reproduce the cleanup race.
	_, err = io.Copy(io.Discard, console)
	if !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		t.Fatalf("read closed ConPTY: got %v, want ERROR_INVALID_HANDLE", err)
	}
	if !isVTOutputCloseError(err) {
		t.Fatalf("closed ConPTY output was treated as a failure: %v", err)
	}
	if isVTOutputCloseError(windows.ERROR_ACCESS_DENIED) {
		t.Fatal("unexpected output read errors must remain failures")
	}
}

func waitVTStage(t *testing.T, ctx context.Context, marker, want string, output *vtOutput) {
	t.Helper()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(marker)
		if err == nil && string(data) == want {
			return
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("waiting for stage %s: %s", want, output.text())
		case <-ticker.C:
		}
	}
}
