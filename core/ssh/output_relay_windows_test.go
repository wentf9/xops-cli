//go:build windows

package ssh

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func testConsoleRelayContext(t *testing.T, ctx context.Context, started string) context.Context {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	work, cleanup := WithConsoleOutputRelay(ctx, ConsoleOutputRelay{
		Executable: exe,
		Args:       []string{"-test.run=^TestWindowsOutputRelayHelper$", "--"},
		Env:        append(os.Environ(), "XOPS_TEST_RELAY_STARTED="+started),
	})
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Errorf("relay scope cleanup: %v", err)
		}
	})
	return work
}

// Explicit test-binary dispatch replaces the former production package init.
func TestWindowsOutputRelayHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--" {
		return
	}
	spec := os.Args[len(os.Args)-1]
	if marker := os.Getenv("XOPS_TEST_RELAY_STARTED"); marker != "" {
		req, ack, console, err := parseWindowsConsoleRelaySpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(console), "test relay console")
		defer func() { _ = file.Close() }()
		if code := serveWindowsConsoleOutput(req, ack, notifyingConsoleWriter{file, marker}); code != 0 {
			t.Fatalf("relay exit code %d", code)
		}
		return
	}
	if code := ServeConsoleOutputRelay(spec); code != 0 {
		t.Fatalf("relay exit code %d", code)
	}
}

type notifyingConsoleWriter struct {
	console io.Writer
	marker  string
}

func (w notifyingConsoleWriter) Write(data []byte) (int, error) {
	if err := os.WriteFile(w.marker, []byte("writing"), 0o600); err != nil {
		return 0, err
	}
	return w.console.Write(data)
}

func TestWindowsOutputIgnoresRelayEnvironment(t *testing.T) {
	if os.Getenv("XOPS_TEST_IGNORES_RELAY_ENV") == "1" {
		return // Reaching the test proves importing core did not exit the process.
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, exe, "-test.run=^TestWindowsOutputIgnoresRelayEnvironment$")
	child.Env = append(os.Environ(), "XOPS_TEST_IGNORES_RELAY_ENV=1", "XOPS_WINDOWS_CONSOLE_OUTPUT_RELAY=invalid")
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("importing core dispatched environment: %v\n%s", err, output)
	}
}

func TestWindowsOutputRelayStopRetainsOwnershipOnFailure(t *testing.T) {
	// An unsignaled event is waitable but cannot be terminated as a process.
	// This deterministically exercises termination failure without a live orphan.
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		_ = windows.CloseHandle(event)
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	var ack windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(r.Fd()), windows.CurrentProcess(), &ack, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		_ = windows.CloseHandle(event)
		t.Fatal(err)
	}
	ctx, cleanup := WithConsoleOutputRelay(t.Context(), ConsoleOutputRelay{})
	owner := ctx.Value(consoleOutputRelayKey{}).(*consoleRelayScope)
	output := &windowsConsoleOutput{relayProcess: event, ackReader: ack, owner: owner}
	if err := owner.add(output); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cleanup() }()
	if err := output.close(); err == nil {
		t.Fatal("unconfirmed process termination reported success")
	}
	if output.relayProcess != event || output.ackReader != ack || !output.closed {
		t.Fatal("failed stop discarded ownership or allowed further writes")
	}
	if err := windows.SetEvent(event); err != nil {
		t.Fatal(err)
	}
	if len(owner.owned) != 1 {
		t.Fatal("failed binding was not retained by command scope")
	}
	// Only the command scope retains this binding after a local defer fails.
	// Retrying the returned owner cleanup must reap it, not require the caller
	// to obtain the private binding from RunCommandPlanWithIO.
	if err := cleanup(); err != nil {
		t.Fatalf("scope retry cleanup: %v", err)
	}
	if output.relayProcess != 0 || output.ackReader != 0 || len(owner.owned) != 0 {
		t.Fatal("confirmed exit did not release owned handles")
	}
	if err := output.close(); err != nil {
		t.Fatalf("repeat cleanup: %v", err)
	}
}

func TestWindowsOutputRelayInvalidSpec(t *testing.T) {
	for _, spec := range []string{"", "1,2", "0,2,3", "1,2,18446744073709551615"} {
		if code := ServeConsoleOutputRelay(spec); code == 0 {
			t.Fatalf("accepted invalid spec %q", spec)
		}
	}
}

func TestWindowsOutputRelayStartupFailure(t *testing.T) {
	output := &windowsConsoleOutput{relay: ConsoleOutputRelay{Executable: filepath.Join(t.TempDir(), "missing-relay.exe")}}
	// Duplicate a valid handle so failure occurs at process creation, not setup.
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()
	if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(null.Fd()), windows.CurrentProcess(), &output.handle, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = output.close() }()
	if _, err := output.WriteContext(t.Context(), []byte("x")); err == nil {
		t.Fatal("missing helper executable reported success")
	}
	if output.relayProcess != 0 || output.reqWriter != 0 || output.ackReader != 0 {
		t.Fatal("startup failure retained pipe/process ownership")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := output.WriteContext(ctx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled write: %v", err)
	}
}
