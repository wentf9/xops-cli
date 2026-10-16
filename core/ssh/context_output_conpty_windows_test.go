//go:build windows && integration

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/conpty"
	"golang.org/x/sys/windows"
)

// The child must reject a console binding while ConPTY output is unread.
// Only after the fallback is acknowledged does the parent drain test output.
func TestWindowsOutputConPTYFallback(t *testing.T) {
	const helper = "XOPS_TEST_BLOCKED_CONSOLE_OUTPUT"
	if marker := os.Getenv(helper); marker != "" {
		output, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
		if err != nil {
			_ = os.WriteFile(marker, []byte(err.Error()), 0o600)
			return
		}
		defer func() { _ = output.Close() }()
		bound, closeFn, supported, err := BindOutput(t.Context(), output)
		result := "ok"
		if err != nil || supported || bound != io.Writer(output) {
			result = fmt.Sprintf("console fallback changed: %v %v", supported, err)
		}
		if err := closeFn(); err != nil {
			result = fmt.Sprintf("release binding: %v", err)
		}
		var mode uint32
		if err := windows.GetConsoleMode(windows.Handle(output.Fd()), &mode); err != nil {
			result = fmt.Sprintf("borrowed console closed: %v", err)
		}
		if err := os.WriteFile(marker+".tmp", []byte(result), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(marker+".tmp", marker); err != nil {
			t.Fatal(err)
		}
		return
	}
	console, err := conpty.New(80, 25, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	marker := filepath.Join(t.TempDir(), "output-result")
	pid, handle, err := console.Spawn(os.Args[0], []string{os.Args[0], "-test.run=^TestWindowsOutputConPTYFallback$", "-test.timeout=15s"}, &syscall.ProcAttr{Env: append(os.Environ(), helper+"="+marker)})
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
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		result, err := os.ReadFile(marker)
		if err == nil {
			if string(result) != "ok" {
				t.Fatalf("native console: %s", result)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("console fallback did not finish before output was drained")
		case <-tick.C:
		}
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
