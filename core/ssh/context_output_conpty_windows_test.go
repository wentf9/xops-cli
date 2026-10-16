//go:build windows && integration

package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/conpty"
	"golang.org/x/sys/windows"
)

const (
	relayConPTYMarker = "XOPS_TEST_BLOCKED_CONSOLE_OUTPUT"
	relayConPTYMode   = "XOPS_TEST_CONSOLE_OUTPUT_MODE"
)

// Neither subtest drains ConPTY output until the relay process is confirmed
// exited. The parent-death case kills the owner without running any Go defers.
func TestWindowsOutputConPTYFallback(t *testing.T) {
	if marker := os.Getenv(relayConPTYMarker); marker != "" {
		runBlockedConsoleChild(t, marker, os.Getenv(relayConPTYMode))
		return
	}
	for _, mode := range []string{"cancel", "parent-death"} {
		t.Run(mode, func(t *testing.T) { testBlockedConsoleRelay(t, mode) })
	}
}

func runBlockedConsoleChild(t *testing.T, marker, mode string) {
	t.Helper()
	output, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = output.Close() }()
	var before uint32
	if err := windows.GetConsoleMode(windows.Handle(output.Fd()), &before); err != nil {
		t.Fatal(err)
	}
	writeCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := marker + ".entered-console-write"
	writeCtx = testConsoleRelayContext(t, writeCtx, started)
	bound, closeFn, supported, err := BindOutput(writeCtx, output)
	if err != nil || !supported {
		t.Fatalf("console binding failed: %v %v", supported, err)
	}
	defer func() { cancel(); _ = closeFn() }()
	relay := bound.(contextOutput).target.(*windowsConsoleOutput)
	if err := relay.ensureRelay(); err != nil {
		t.Fatal(err)
	}
	var process windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), relay.relayProcess, windows.CurrentProcess(), &process, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(process) }()
	pid, err := windows.GetProcessId(process)
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() { _, err := bound.Write(bytes.Repeat([]byte("x"), 4<<20)); writeDone <- err }()
	waitForBlockedConsoleWrite(t, started, writeDone)
	if mode == "parent-death" {
		publishConsoleMarker(t, marker, strconv.FormatUint(uint64(pid), 10))
		// The supervising test now opens the relay wait handle and kills this
		// process. No binding/scope Close runs: only OS Job ownership can reap it.
		select {
		case err := <-writeDone:
			t.Fatalf("write unexpectedly completed before parent death: %v", err)
		case <-time.After(12 * time.Second):
			t.Fatal("supervisor did not terminate relay owner")
		}
	}
	cancel()
	select {
	case err := <-writeDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("console cancellation lost: %v", err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("blocked console write did not join")
	}
	if status, err := windows.WaitForSingleObject(process, 0); err != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatalf("relay is still alive before ConPTY drain: wait=%d err=%v", status, err)
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	if err := closeFn(); err != nil {
		t.Fatal(err)
	}
	// Cancellation, relay exit and both binding releases must finish while
	// ConPTY is unread. Only now may the parent resume draining: even a
	// GetConsoleMode query can block behind ConPTY output backpressure.
	publishConsoleMarker(t, marker, "ready-to-drain")
	var after uint32
	if err := windows.GetConsoleMode(windows.Handle(output.Fd()), &after); err != nil || before != after {
		t.Fatalf("borrowed console mode changed: %v", err)
	}
	// The parent still requires this process to exit successfully, so the
	// readiness marker cannot hide a failed borrowed-handle/mode assertion.
}

func waitForBlockedConsoleWrite(t *testing.T, started string, writeDone <-chan error) {
	t.Helper()
	startup := time.NewTimer(8 * time.Second)
	defer startup.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(started); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case err := <-writeDone:
			t.Fatalf("write returned before entering console output: %v", err)
		case <-startup.C:
			t.Fatal("relay never entered console output")
		case <-tick.C:
		}
	}
	select {
	case err := <-writeDone:
		t.Fatalf("unread ConPTY did not block the write: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
}

func publishConsoleMarker(t *testing.T, marker, result string) {
	t.Helper()
	if err := os.WriteFile(marker+".tmp", []byte(result), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(marker+".tmp", marker); err != nil {
		t.Fatal(err)
	}
}

func testBlockedConsoleRelay(t *testing.T, mode string) {
	t.Helper()
	console, err := conpty.New(80, 25, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	marker := filepath.Join(t.TempDir(), "output-result")
	pid, handle, err := console.Spawn(os.Args[0], []string{os.Args[0], "-test.run=^TestWindowsOutputConPTYFallback$", "-test.timeout=24s"}, &syscall.ProcAttr{Env: append(os.Environ(), relayConPTYMarker+"="+marker, relayConPTYMode+"="+mode)})
	if err != nil {
		_ = console.Close()
		t.Fatal(err)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		_ = windows.TerminateProcess(windows.Handle(handle), 1)
		_ = windows.CloseHandle(windows.Handle(handle))
		_ = console.Close()
		t.Fatal(err)
	}
	_ = windows.CloseHandle(windows.Handle(handle))
	done := make(chan error, 1)
	go func() {
		state, err := process.Wait()
		if err == nil && !state.Success() {
			err = fmt.Errorf("console child exited: %s", state)
		}
		done <- err
	}()
	var drain sync.Once
	drained := make(chan struct{})
	startDrain := func() { drain.Do(func() { go func() { _, _ = io.Copy(io.Discard, console); close(drained) }() }) }
	joined := false
	defer func() {
		startDrain()
		if !joined {
			_ = process.Kill()
			<-done
		}
		if err := console.Close(); err != nil {
			t.Error(err)
		}
		select {
		case <-drained:
		case <-time.After(2 * time.Second):
			t.Error("ConPTY reader did not join")
		}
	}()
	result := waitForConsoleMarker(t, ctx, marker, done, &joined)
	if mode == "parent-death" {
		killConsoleOwnerAndWaitRelay(t, ctx, process, done, &joined, result)
		return
	}
	if result != "ready-to-drain" {
		t.Fatalf("native console: %s", result)
	}
	startDrain()
	select {
	case err := <-done:
		joined = true
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("console child did not exit")
	}
}

func waitForConsoleMarker(t *testing.T, ctx context.Context, marker string, done <-chan error, joined *bool) string {
	t.Helper()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		data, err := os.ReadFile(marker)
		if err == nil {
			return string(data)
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			*joined = true
			t.Fatalf("owner exited before blocked-write marker: %v", err)
		case <-ctx.Done():
			t.Fatal("console test did not finish before output was drained")
		case <-tick.C:
		}
	}
}

func killConsoleOwnerAndWaitRelay(t *testing.T, ctx context.Context, process *os.Process, done <-chan error, joined *bool, result string) {
	t.Helper()
	relayPID, err := strconv.ParseUint(result, 10, 32)
	if err != nil {
		t.Fatalf("invalid relay PID %q: %v", result, err)
	}
	relay, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(relayPID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(relay) }()
	if err := process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		*joined = true
	case <-ctx.Done():
		t.Fatal("owner did not exit")
	}
	if status, err := windows.WaitForSingleObject(relay, 5000); err != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatalf("orphan relay survived parent death before ConPTY drain: wait=%d err=%v", status, err)
	}
}
