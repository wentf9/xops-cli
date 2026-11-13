//go:build !windows

package sshenv

import (
	"errors"
	"io"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestProcessStdioConn_ReapsTrappedProcessGroupAndGrandchildren(t *testing.T) {
	baselineFDs := countLinuxOpenFDs(t)
	baselineGoroutines := runtime.NumGoroutine()

	// Child traps SIGTERM and spawns a background grandchild holding pipes open,
	// exercising the full 200ms EOF grace -> SIGTERM -> 100ms grace -> -pgid SIGKILL path.
	rawConn, err := DialProxyCommandWithStderr(
		t.Context(),
		`trap '' TERM; (sleep 60) & printf 'R'; sleep 60`,
		io.Discard,
	)
	if err != nil {
		t.Fatalf("DialProxyCommandWithStderr failed: %v", err)
	}
	pConn, ok := rawConn.(*ProcessStdioConn)
	if !ok {
		_ = rawConn.Close()
		t.Fatalf("expected *ProcessStdioConn, got %T", rawConn)
	}
	pgid := pConn.proc.pgid
	if pgid <= 0 {
		_ = pConn.Close()
		t.Fatalf("invalid child pgid %d", pgid)
	}

	ready := make([]byte, 1)
	if _, err := io.ReadFull(pConn, ready); err != nil {
		_ = pConn.Close()
		t.Fatalf("read readiness byte failed: %v", err)
	}

	start := time.Now()
	if err := pConn.Close(); err != nil {
		t.Fatalf("pConn.Close() failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("pConn.Close() took %v, expected bounded reap", elapsed)
	}

	// Verify the entire process group (-pgid), including the backgrounded sleep 60 grandchild, is dead and reaped.
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		killErr := syscall.Kill(-pgid, 0)
		if errors.Is(killErr, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("process group %d still alive after Close(): err=%v", pgid, killErr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Also test background grandchild cleanup when the direct shell exits immediately after spawning a child.
	rawQuick, err := DialProxyCommandWithStderr(
		t.Context(),
		`(sleep 60) & printf 'Q'; exit 0`,
		io.Discard,
	)
	if err != nil {
		t.Fatalf("DialProxyCommandWithStderr(quick parent + orphan grandchild) failed: %v", err)
	}
	quickConn := rawQuick.(*ProcessStdioConn)
	quickPGID := quickConn.proc.pgid
	if _, err := io.ReadFull(quickConn, ready); err != nil {
		_ = quickConn.Close()
		t.Fatalf("read readiness byte failed: %v", err)
	}
	if err := quickConn.Close(); err != nil {
		t.Fatalf("quickConn.Close() failed: %v", err)
	}
	deadline = time.Now().Add(500 * time.Millisecond)
	for !errors.Is(syscall.Kill(-quickPGID, 0), syscall.ESRCH) {
		if time.Now().After(deadline) {
			t.Fatalf("orphan grandchild in pgid %d survived Close()", quickPGID)
		}
		time.Sleep(10 * time.Millisecond)
	}

	assertGoroutinesSettled(t, baselineGoroutines)
	if baselineFDs > 0 {
		afterFDs := countLinuxOpenFDs(t)
		if afterFDs > baselineFDs+2 {
			t.Fatalf("open file descriptors leaked: before=%d after=%d", baselineFDs, afterFDs)
		}
	}
}

func TestResolveUserShellFallback(t *testing.T) {
	for _, bad := range []string{"", "   ", "relative/sh", "/nonexistent/shell-path", t.TempDir()} {
		if got := resolveUserShell(bad); got != fallbackPosixShell {
			t.Fatalf("resolveUserShell(%q) = %q, want %q", bad, got, fallbackPosixShell)
		}
	}
	if got := resolveUserShell("/bin/sh"); got != "/bin/sh" {
		t.Fatalf("resolveUserShell(/bin/sh) = %q, want /bin/sh", got)
	}
}

func countLinuxOpenFDs(t *testing.T) int {
	t.Helper()
	if runtime.GOOS != "linux" {
		return 0
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return len(entries)
}
