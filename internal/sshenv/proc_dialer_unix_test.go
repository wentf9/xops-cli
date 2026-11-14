//go:build !windows

package sshenv

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/internal/testpty"
	"golang.org/x/term"
)

func forceHeadlessModeForTest(t *testing.T) {
	t.Helper()
	orig := probeControllingTTY
	probeControllingTTY = func() bool { return false }
	t.Cleanup(func() { probeControllingTTY = orig })
}

func forceForegroundTTYModeForTest(t *testing.T) {
	t.Helper()
	orig := probeControllingTTY
	probeControllingTTY = func() bool { return true }
	t.Cleanup(func() { probeControllingTTY = orig })
}

func TestHelperUnixSubprocess(t *testing.T) {
	switch os.Getenv("XOPS_SSHENV_UNIX_HELPER") {
	case "":
		return
	case "setsid-hang":
		_, _ = syscall.Setsid()
		signal.Ignore(syscall.SIGTERM)
		_, _ = os.Stdout.Write([]byte("S"))
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "pty-leader":
		runPTYLeaderSubprocessHelper()
	case "devtty-proxy":
		runDevTTYProxySubprocessHelper()
	case "detached-inherited-pty":
		runDetachedInheritedPTYSubprocessHelper()
	}
}

func runPTYLeaderSubprocessHelper() {
	if !defaultHasControllingTTY() {
		_, _ = fmt.Fprintln(os.Stderr, "expected defaultHasControllingTTY() == true in PTY session leader")
		os.Exit(3)
	}
	exe, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "os.Executable: %v\n", err)
		os.Exit(4)
	}
	proxyCmd := fmt.Sprintf(`XOPS_SSHENV_UNIX_HELPER=devtty-proxy "%s" -test.run=^TestHelperUnixSubprocess$`, exe)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := DialProxyCommandWithStderr(ctx, proxyCmd, io.Discard)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "DialProxyCommandWithStderr: %v\n", err)
		os.Exit(5)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	_ = conn.Close()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "read proxy stdout: %v\n", err)
		os.Exit(6)
	}
	if strings.TrimSpace(line) != "PROXY-OK:654321" {
		_, _ = fmt.Fprintf(os.Stderr, "unexpected proxy stdout %q\n", line)
		os.Exit(7)
	}
	os.Exit(0)
}

func runDevTTYProxySubprocessHelper() {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "open /dev/tty: %v\n", err)
		os.Exit(11)
	}
	defer func() { _ = tty.Close() }()

	// Exercise both tcgetattr and tcsetattr (MakeRaw + Restore); a background
	// process group receives SIGTTOU immediately on tcsetattr!
	origState, err := term.MakeRaw(int(tty.Fd()))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "term.MakeRaw(/dev/tty): %v\n", err)
		os.Exit(12)
	}
	if err := term.Restore(int(tty.Fd()), origState); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "term.Restore(/dev/tty): %v\n", err)
		os.Exit(13)
	}

	if _, err := io.WriteString(tty, "OTP-PROMPT:"); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "write /dev/tty prompt: %v\n", err)
		os.Exit(14)
	}
	// Reading /dev/tty from a background process group triggers SIGTTIN!
	code, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "read /dev/tty answer: %v\n", err)
		os.Exit(15)
	}
	_, _ = fmt.Fprintf(os.Stdout, "PROXY-OK:%s\n", strings.TrimSpace(code))
	_, _ = io.Copy(os.Stdout, os.Stdin)
	os.Exit(0)
}

func runDetachedInheritedPTYSubprocessHelper() {
	// Regression helper for M11: called after Setsid: true WITHOUT Setctty,
	// with stdin and stderr attached to a non-controlling PTY slave.
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stderr.Fd())) {
		_, _ = fmt.Fprintln(os.Stderr, "expected stdin/stderr to be PTY slave FDs")
		os.Exit(21)
	}
	if isForegroundTerminalFD(int(os.Stdin.Fd())) || isForegroundTerminalFD(int(os.Stderr.Fd())) {
		_, _ = fmt.Fprintln(os.Stderr, "isForegroundTerminalFD returned true on non-controlling PTY")
		os.Exit(22)
	}
	if defaultHasControllingTTY() {
		_, _ = fmt.Fprintln(os.Stderr, "defaultHasControllingTTY returned true in detached setsid process")
		os.Exit(23)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rawConn, err := DialProxyCommandWithStderr(ctx, `trap '' TERM; (sleep 60) & printf 'D'; sleep 60`, io.Discard)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "DialProxyCommandWithStderr: %v\n", err)
		os.Exit(24)
	}
	pConn := rawConn.(*ProcessStdioConn)
	if pConn.proc.foregroundTTY || pConn.proc.pgid <= 0 {
		_ = pConn.Close()
		_, _ = fmt.Fprintf(os.Stderr, "expected isolated process group, got foregroundTTY=%v pgid=%d\n", pConn.proc.foregroundTTY, pConn.proc.pgid)
		os.Exit(25)
	}
	pgid := pConn.proc.pgid
	ready := make([]byte, 1)
	if _, err := io.ReadFull(pConn, ready); err != nil {
		_ = pConn.Close()
		_, _ = fmt.Fprintf(os.Stderr, "read readiness byte: %v\n", err)
		os.Exit(26)
	}
	if err := pConn.Close(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Close: %v\n", err)
		os.Exit(27)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for !errors.Is(syscall.Kill(-pgid, 0), syscall.ESRCH) {
		if time.Now().After(deadline) {
			_, _ = fmt.Fprintf(os.Stderr, "process group %d survived Close()\n", pgid)
			os.Exit(28)
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, _ = fmt.Fprintln(os.Stdout, "DETACHED-PTY-ISOLATED-OK")
	os.Exit(0)
}

func TestProcessStdioConn_ReapsTrappedProcessGroupAndGrandchildren(t *testing.T) {
	forceHeadlessModeForTest(t)
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

func TestProcessStdioConn_HeadlessFallbackKillsSetsidChild(t *testing.T) {
	forceHeadlessModeForTest(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	setsidCmd := fmt.Sprintf(`exec env XOPS_SSHENV_UNIX_HELPER=setsid-hang "%s" -test.run=^TestHelperUnixSubprocess$`, exe)
	setsidConn, err := DialProxyCommandWithStderr(t.Context(), setsidCmd, io.Discard)
	if err != nil {
		t.Fatalf("DialProxyCommandWithStderr(setsid-hang) failed: %v", err)
	}
	ready := make([]byte, 1)
	if _, err := io.ReadFull(setsidConn, ready); err != nil {
		_ = setsidConn.Close()
		t.Fatalf("read setsid readiness byte failed: %v", err)
	}
	startSetsidClose := time.Now()
	if err := setsidConn.Close(); err != nil {
		t.Fatalf("setsidConn.Close() failed: %v", err)
	}
	if elapsed := time.Since(startSetsidClose); elapsed > 2*time.Second {
		t.Fatalf("setsidConn.Close() hung for %v without fallback cmd.Process.Kill()", elapsed)
	}
}

func TestDialProxyCommand_ForegroundPTYAllowsDevTTYPromptWithoutSIGTTINOrSIGTTOU(t *testing.T) {
	master, slave, err := testpty.Open()
	if err != nil {
		t.Fatalf("testpty.Open failed: %v", err)
	}
	defer func() { _ = master.Close() }()
	defer func() { _ = slave.Close() }()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	var leaderOut, leaderErr syncBuffer
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestHelperUnixSubprocess$")
	cmd.Env = append(os.Environ(), "XOPS_SSHENV_UNIX_HELPER=pty-leader")
	cmd.Stdin = slave
	cmd.Stdout = &leaderOut
	cmd.Stderr = &leaderErr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start PTY session leader failed: %v", err)
	}
	_ = slave.Close()

	promptFound := make(chan error, 1)
	go func() {
		var seen bytes.Buffer
		buf := make([]byte, 128)
		for {
			n, readErr := master.Read(buf)
			if n > 0 {
				seen.Write(buf[:n])
				if strings.Contains(seen.String(), "OTP-PROMPT:") {
					_, writeErr := io.WriteString(master, "654321\n")
					promptFound <- writeErr
					// Drain any echoed bytes until master closes.
					_, _ = io.Copy(io.Discard, master)
					return
				}
			}
			if readErr != nil {
				promptFound <- fmt.Errorf("read PTY master before prompt (saw %q): %w", seen.String(), readErr)
				return
			}
		}
	}()

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cmd.Wait()
	}()

	select {
	case promptErr := <-promptFound:
		if promptErr != nil {
			t.Fatalf("PTY prompt interaction failed: %v (stderr=%q)", promptErr, leaderErr.String())
		}
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		t.Fatalf("timed out waiting for ProxyCommand /dev/tty prompt (stopped on SIGTTIN/SIGTTOU?): stderr=%q", leaderErr.String())
	}

	select {
	case waitErr := <-waitDone:
		if waitErr != nil {
			t.Fatalf("PTY session leader failed: %v (stdout=%q stderr=%q)", waitErr, leaderOut.String(), leaderErr.String())
		}
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		t.Fatalf("timed out waiting for PTY session leader exit: stderr=%q", leaderErr.String())
	}
}

func TestForegroundTTYMode_TerminatesDirectChildAndPreservesLocalCommandBackgroundJobs(t *testing.T) {
	forceForegroundTTYModeForTest(t)

	// 1. Foreground ProxyCommand stays in caller group (pgid == 0) and terminates cleanly via direct process signals.
	rawConn, err := DialProxyCommandWithStderr(
		t.Context(),
		`trap '' HUP TERM; printf 'F'; sleep 60`,
		io.Discard,
	)
	if err != nil {
		t.Fatalf("DialProxyCommandWithStderr failed: %v", err)
	}
	pConn := rawConn.(*ProcessStdioConn)
	if !pConn.proc.foregroundTTY || pConn.proc.pgid != 0 {
		_ = pConn.Close()
		t.Fatalf("expected foregroundTTY=true pgid=0, got foregroundTTY=%v pgid=%d", pConn.proc.foregroundTTY, pConn.proc.pgid)
	}
	ready := make([]byte, 1)
	if _, err := io.ReadFull(pConn, ready); err != nil {
		_ = pConn.Close()
		t.Fatalf("read readiness byte: %v", err)
	}
	childPID := pConn.proc.process.Pid
	if err := pConn.Close(); err != nil {
		t.Fatalf("foreground pConn.Close() failed: %v", err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for !errors.Is(syscall.Kill(childPID, 0), syscall.ESRCH) {
		if time.Now().After(deadline) {
			t.Fatalf("foreground ProxyCommand child %d still alive after Close()", childPID)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 2. LocalCommand exiting normally in foreground mode must NOT kill intentional background jobs (L3).
	var stdoutBuf syncBuffer
	err = RunLocalCommandWithIO(
		t.Context(),
		`sleep 30 </dev/null >/dev/null 2>&1 & echo $!`,
		&stdoutBuf,
		io.Discard,
	)
	if err != nil {
		t.Fatalf("RunLocalCommandWithIO background spawn failed: %v", err)
	}
	bgPID, err := strconv.Atoi(strings.TrimSpace(stdoutBuf.String()))
	if err != nil || bgPID <= 0 {
		t.Fatalf("failed to parse background PID from %q: %v", stdoutBuf.String(), err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(bgPID, syscall.SIGKILL)
	})
	if killErr := syscall.Kill(bgPID, 0); killErr != nil {
		t.Fatalf("expected LocalCommand background job PID %d to survive normal exit, got %v", bgPID, killErr)
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

func TestDetachedSetsidInheritingNonControllingPTY_IsolatesAndReapsProcessGroup(t *testing.T) {
	master, slave, err := testpty.Open()
	if err != nil {
		t.Fatalf("testpty.Open failed: %v", err)
	}
	defer func() { _ = master.Close() }()
	defer func() { _ = slave.Close() }()

	// Drain master so any diagnostic writes to stderr never block.
	go func() {
		_, _ = io.Copy(io.Discard, master)
	}()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	var stdoutBuf syncBuffer
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestHelperUnixSubprocess$")
	cmd.Env = append(os.Environ(), "XOPS_SSHENV_UNIX_HELPER=detached-inherited-pty")
	cmd.Stdin = slave
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = slave
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // Detached session without Setctty -> TIOCGPGRP returns ENOTTY!
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start detached helper failed: %v", err)
	}
	_ = slave.Close()

	if err := cmd.Wait(); err != nil {
		t.Fatalf("detached inherited-PTY helper failed: %v (stdout=%q)", err, stdoutBuf.String())
	}
	if !strings.Contains(stdoutBuf.String(), "DETACHED-PTY-ISOLATED-OK") {
		t.Fatalf("missing success marker in helper stdout %q", stdoutBuf.String())
	}
}

func TestProcessStdioConn_SpontaneousExitBeforeCloseSkipsDelayedGroupReap(t *testing.T) {
	forceHeadlessModeForTest(t)

	var reapCalls atomic.Int32
	origHook := onUnixReapRemainingGroup
	onUnixReapRemainingGroup = func(int) {
		reapCalls.Add(1)
	}
	t.Cleanup(func() {
		onUnixReapRemainingGroup = origHook
	})

	rawConn, err := DialProxyCommandWithStderr(t.Context(), `printf 'E'; exit 0`, io.Discard)
	if err != nil {
		t.Fatalf("DialProxyCommandWithStderr failed: %v", err)
	}
	pConn := rawConn.(*ProcessStdioConn)

	buf := make([]byte, 8)
	n, err := pConn.Read(buf)
	if n != 1 || buf[0] != 'E' {
		_ = pConn.Close()
		t.Fatalf("Read = (%d, %v), want ('E')", n, err)
	}

	// Wait until both cmd.Wait() (waitDone) and stderr EOF (stderrDone) have naturally completed.
	select {
	case <-pConn.waitDone:
	case <-time.After(2 * time.Second):
		_ = pConn.Close()
		t.Fatal("timed out waiting for spontaneous waitDone")
	}
	select {
	case <-pConn.stderrDone:
	case <-time.After(2 * time.Second):
		_ = pConn.Close()
		t.Fatal("timed out waiting for spontaneous stderrDone")
	}

	if !pConn.spontaneousExit.Load() {
		t.Fatal("expected spontaneousExit=true after natural exit prior to Close()")
	}
	if err := pConn.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if got := reapCalls.Load(); got != 0 {
		t.Fatalf("expected reapRemainingGroup to be skipped when waitDone and stderrDone already closed prior to Close(), got %d calls", got)
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
