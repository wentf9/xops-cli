//go:build !windows

package sshenv

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestP6_WaitProcessGroupExit_ReturnsImmediatelyWhenPipesCloseEvenForLivePGID(t *testing.T) {
	t.Parallel()

	// Use our own live process group so syscall.Kill(-livePGID, 0) ALWAYS succeeds.
	// waitProcessGroupExit must return true immediately once stderrDone and
	// sentinelDone are closed rather than polling until termGrace and risking a
	// SIGKILL against a recycled PGID.
	livePGID := syscall.Getpgrp()
	if err := syscall.Kill(-livePGID, 0); err != nil {
		t.Fatalf("expected current process group %d to be live: %v", livePGID, err)
	}

	t.Run("already_closed_pipes", func(t *testing.T) {
		stderrDone := make(chan struct{})
		sentinelDone := make(chan struct{})
		close(stderrDone)
		close(sentinelDone)

		start := time.Now()
		exited := waitProcessGroupExit(livePGID, 5*time.Second, stderrDone, sentinelDone)
		elapsed := time.Since(start)
		if !exited {
			t.Fatal("waitProcessGroupExit = false when both pipes are closed, want true")
		}
		if elapsed > 200*time.Millisecond {
			t.Fatalf("waitProcessGroupExit waited %v instead of returning immediately on closed pipes", elapsed)
		}
	})

	t.Run("pipes_close_during_grace", func(t *testing.T) {
		stderrDone := make(chan struct{})
		sentinelDone := make(chan struct{})
		go func() {
			time.Sleep(15 * time.Millisecond)
			close(stderrDone)
			time.Sleep(15 * time.Millisecond)
			close(sentinelDone)
		}()

		start := time.Now()
		exited := waitProcessGroupExit(livePGID, 5*time.Second, stderrDone, sentinelDone)
		elapsed := time.Since(start)
		if !exited {
			t.Fatal("waitProcessGroupExit = false after both pipes closed, want true")
		}
		if elapsed > 500*time.Millisecond {
			t.Fatalf("waitProcessGroupExit took %v (waited out termGrace instead of waking on pipe closure)", elapsed)
		}
	})

	t.Run("sentinel_open_still_waits_full_grace", func(t *testing.T) {
		stderrDone := make(chan struct{})
		sentinelDone := make(chan struct{})
		close(stderrDone)

		start := time.Now()
		exited := waitProcessGroupExit(livePGID, 40*time.Millisecond, stderrDone, sentinelDone)
		elapsed := time.Since(start)
		if exited {
			t.Fatal("waitProcessGroupExit = true while sentinelDone remained open on live PGID, want false")
		}
		if elapsed < 25*time.Millisecond {
			t.Fatalf("waitProcessGroupExit returned too early (%v) while sentinelDone remained open", elapsed)
		}
	})
}

func startTermIgnoringDummyPGID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", `trap '' TERM; printf R; exec sleep 30`)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start dummy child: %v", err)
	}
	pgid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		_ = cmd.Wait()
	})

	ready := make([]byte, 1)
	if _, err := stdout.Read(ready); err != nil || ready[0] != 'R' {
		t.Fatalf("dummy child failed to signal readiness: %q, %v", ready, err)
	}
	return pgid
}

func TestP6_ReapRemainingGroup_SkipsSIGKILLWhenPipesCloseBeforeEscalation(t *testing.T) {
	t.Run("pipes_close_during_grace", func(t *testing.T) {
		dummyPGID := startTermIgnoringDummyPGID(t)
		stderrDone := make(chan struct{})
		sentinelDone := make(chan struct{})

		origHook := onUnixReapRemainingGroup
		onUnixReapRemainingGroup = func(int) {
			go func() {
				time.Sleep(15 * time.Millisecond)
				close(stderrDone)
				close(sentinelDone)
			}()
		}
		t.Cleanup(func() { onUnixReapRemainingGroup = origHook })

		p := &platformProc{pgid: dummyPGID}
		start := time.Now()
		p.reapRemainingGroup(2*time.Second, stderrDone, sentinelDone, false)
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("reapRemainingGroup took %v, expected immediate return when pipes closed", elapsed)
		}
		if err := syscall.Kill(-dummyPGID, 0); err != nil {
			t.Fatalf("reapRemainingGroup SIGKILLed unrelated live PGID %d after pipes closed: %v", dummyPGID, err)
		}
	})

	t.Run("zero_grace_rechecks_pipes_before_sigkill", func(t *testing.T) {
		dummyPGID := startTermIgnoringDummyPGID(t)
		stderrDone := make(chan struct{})
		sentinelDone := make(chan struct{})

		origHook := onUnixReapRemainingGroup
		onUnixReapRemainingGroup = func(int) {
			close(stderrDone)
			close(sentinelDone)
		}
		t.Cleanup(func() { onUnixReapRemainingGroup = origHook })

		p := &platformProc{pgid: dummyPGID}
		p.reapRemainingGroup(0, stderrDone, sentinelDone, false)
		if err := syscall.Kill(-dummyPGID, 0); err != nil {
			t.Fatalf("reapRemainingGroup(termGrace=0) sent SIGKILL after pipes closed: %v", err)
		}
	})
}

func TestP6_TerminateTree_GuardsPGIDAgainstReapAndClosedSentinel(t *testing.T) {
	t.Run("markReaped_blocks_pgid_signal", func(t *testing.T) {
		dummyPGID := startTermIgnoringDummyPGID(t)
		p := &platformProc{pgid: dummyPGID}
		p.markReaped()

		openDone := make(chan struct{})
		p.terminateTree(20*time.Millisecond, openDone)
		if err := syscall.Kill(-dummyPGID, 0); err != nil {
			t.Fatalf("terminateTree signaled PGID %d after markReaped(): %v", dummyPGID, err)
		}
	})

	t.Run("closed_sentinelDone_skips_pgid_signal", func(t *testing.T) {
		dummyPGID := startTermIgnoringDummyPGID(t)
		closedSentinel := make(chan struct{})
		close(closedSentinel)
		p := &platformProc{pgid: dummyPGID}
		p.bindSentinelObserver(nil, closedSentinel)

		openDone := make(chan struct{})
		p.terminateTree(20*time.Millisecond, openDone)
		if err := syscall.Kill(-dummyPGID, 0); err != nil {
			t.Fatalf("terminateTree signaled PGID %d despite closed sentinelDone: %v", dummyPGID, err)
		}
	})

	t.Run("closed_sentinel_pipe_writer_skips_pgid_signal", func(t *testing.T) {
		dummyPGID := startTermIgnoringDummyPGID(t)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		_ = w.Close()

		openSentinel := make(chan struct{})
		openDone := make(chan struct{})
		p := &platformProc{pgid: dummyPGID}
		p.bindSentinelObserver(r, openSentinel)
		p.terminateTree(20*time.Millisecond, openDone)
		p.clearSentinelObserver()

		if err := syscall.Kill(-dummyPGID, 0); err != nil {
			t.Fatalf("terminateTree signaled PGID %d despite closed sentinel pipe writer: %v", dummyPGID, err)
		}
	})

	t.Run("concurrent_reap_and_terminateTree_race_free", func(t *testing.T) {
		for range 20 {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			sentinelDone := make(chan struct{})
			p := &platformProc{pgid: 0, foregroundTTY: true}
			p.bindSentinelObserver(r, sentinelDone)

			var wg sync.WaitGroup
			wg.Go(func() {
				p.terminateTree(5*time.Millisecond, done)
			})
			wg.Go(func() {
				p.markReaped()
				close(done)
				_ = w.Close()
				close(sentinelDone)
			})
			wg.Wait()
			p.clearSentinelObserver()
			_ = r.Close()
		}
	})
}

func TestP6_EvaluateSuspendProcessGroup_Matrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		pid          int
		ppid         int
		pgrp         int
		sid          int
		sidErr       error
		parentSID    int
		parentSIDErr error
		wantErr      error
	}{
		{
			name:      "normal_job_control_child",
			pid:       200,
			ppid:      100,
			pgrp:      200,
			sid:       100,
			parentSID: 100,
			wantErr:   nil,
		},
		{
			name:      "child_in_non_leader_job_group",
			pid:       201,
			ppid:      200,
			pgrp:      200,
			sid:       100,
			parentSID: 100,
			wantErr:   nil,
		},
		{
			name:         "cross_uid_parent_eperm_not_falsely_orphaned",
			pid:          200,
			ppid:         100,
			pgrp:         200,
			sid:          100,
			parentSIDErr: syscall.EPERM,
			wantErr:      nil,
		},
		{
			name:      "init_reparented_ppid_1",
			pid:       200,
			ppid:      1,
			pgrp:      200,
			sid:       100,
			parentSID: 1,
			wantErr:   errSuspendOrphanedProcessGroup,
		},
		{
			name:      "session_leader_pid_eq_sid",
			pid:       200,
			ppid:      100,
			pgrp:      200,
			sid:       200,
			parentSID: 100,
			wantErr:   errSuspendOrphanedProcessGroup,
		},
		{
			name:      "member_of_session_leader_pgrp",
			pid:       201,
			ppid:      200,
			pgrp:      200,
			sid:       200,
			parentSID: 200,
			wantErr:   errSuspendOrphanedProcessGroup,
		},
		{
			name:      "parent_in_different_session_subreaper",
			pid:       200,
			ppid:      50,
			pgrp:      200,
			sid:       100,
			parentSID: 50,
			wantErr:   errSuspendOrphanedProcessGroup,
		},
		{
			name:    "invalid_pgrp",
			pid:     200,
			ppid:    100,
			pgrp:    0,
			sid:     100,
			wantErr: errSuspendOrphanedProcessGroup,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := evaluateSuspendProcessGroup(tc.pid, tc.ppid, tc.pgrp, tc.sid, tc.sidErr, tc.parentSID, tc.parentSIDErr)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("evaluateSuspendProcessGroup() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestHelperSuspendUnixSubprocess(t *testing.T) {
	mode := os.Getenv("XOPS_SSHENV_P6_SUSPEND_HELPER")
	if mode == "" {
		return
	}
	suspendFn := platformSuspendProcess()
	if suspendFn == nil {
		_, _ = fmt.Fprintln(os.Stderr, "platformSuspendProcess returned nil on Unix")
		os.Exit(10)
	}
	switch mode {
	case "suspend-resume":
		_, _ = fmt.Fprintln(os.Stdout, "READY")
		if err := suspendFn(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "suspendFn failed: %v\n", err)
			os.Exit(11)
		}
		_, _ = fmt.Fprintln(os.Stdout, "RESUMED")
		os.Exit(0)
	case "orphaned-setsid":
		err := suspendFn()
		if !errors.Is(err, errSuspendOrphanedProcessGroup) {
			_, _ = fmt.Fprintf(os.Stderr, "orphaned suspendFn = %v, want errSuspendOrphanedProcessGroup\n", err)
			os.Exit(12)
		}
		_, _ = fmt.Fprintln(os.Stdout, "ORPHAN-FAILFAST-OK")
		os.Exit(0)
	case "ignored-sigtstp":
		signal.Ignore(syscall.SIGTSTP)
		if err := suspendFn(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "ignored-sigtstp suspendFn = %v, want nil\n", err)
			os.Exit(13)
		}
		_, _ = fmt.Fprintln(os.Stdout, "IGNORED-OK")
		os.Exit(0)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unknown helper mode %q\n", mode)
		os.Exit(14)
	}
}

func TestP6_PlatformSuspendProcess_RealUnixStopAndSIGCONTResume(t *testing.T) {
	if os.Getpid() <= 1 {
		t.Skip("cannot create non-init-parented child when test process is PID 1")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestHelperSuspendUnixSubprocess$")
	cmd.Env = append(os.Environ(), "XOPS_SSHENV_P6_SUSPEND_HELPER=suspend-resume")
	// Setpgid puts the child in its own process group within our session so its
	// parent (this test process) is in the same session and a different PGID ->
	// guaranteed non-orphaned even under headless CI runners.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		t.Fatalf("start suspend helper: %v", err)
	}
	childPID := cmd.Process.Pid
	t.Cleanup(func() {
		_ = syscall.Kill(-childPID, syscall.SIGCONT)
		_ = syscall.Kill(-childPID, syscall.SIGKILL)
	})

	reader := bufio.NewReader(stdoutPipe)
	readyLine, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(readyLine) != "READY" {
		t.Fatalf("read READY line = (%q, %v), stderr=%q", readyLine, err, stderrBuf.String())
	}

	type waitStopResult struct {
		ws  syscall.WaitStatus
		err error
	}
	stopCh := make(chan waitStopResult, 1)
	go func() {
		var ws syscall.WaitStatus
		for {
			_, wErr := syscall.Wait4(childPID, &ws, syscall.WUNTRACED, nil)
			if errors.Is(wErr, syscall.EINTR) {
				continue
			}
			stopCh <- waitStopResult{ws: ws, err: wErr}
			return
		}
	}()

	select {
	case res := <-stopCh:
		if res.err != nil {
			t.Fatalf("Wait4(WUNTRACED) failed: %v (stderr=%q)", res.err, stderrBuf.String())
		}
		if !res.ws.Stopped() {
			t.Fatalf("child did not enter WIFSTOPPED state: status=%#x (exited=%v exit=%d stderr=%q)",
				res.ws, res.ws.Exited(), res.ws.ExitStatus(), stderrBuf.String())
		}
		if res.ws.StopSignal() != syscall.SIGTSTP {
			t.Fatalf("child stop signal = %v, want SIGTSTP", res.ws.StopSignal())
		}
	case <-ctx.Done():
		t.Fatalf("timed out waiting for child process %d to stop on SIGTSTP (stderr=%q)", childPID, stderrBuf.String())
	}

	if err := syscall.Kill(-childPID, syscall.SIGCONT); err != nil {
		t.Fatalf("send SIGCONT to child group %d: %v", childPID, err)
	}

	resumedLine, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(resumedLine) != "RESUMED" {
		t.Fatalf("read RESUMED line after SIGCONT = (%q, %v), stderr=%q", resumedLine, err, stderrBuf.String())
	}

	if err := cmd.Wait(); err != nil {
		t.Fatalf("suspend helper exit after SIGCONT failed: %v (stderr=%q)", err, stderrBuf.String())
	}
}

func TestP6_PlatformSuspendProcess_OrphanedSessionLeaderAndIgnoredSIGTSTPDoNotDeadlock(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	t.Run("orphaned_setsid_session_leader_fails_fast", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestHelperSuspendUnixSubprocess$")
		cmd.Env = append(os.Environ(), "XOPS_SSHENV_P6_SUSPEND_HELPER=orphaned-setsid")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("orphaned setsid helper failed (deadlock or wrong error): %v, out=%q", err, string(out))
		}
		if !strings.Contains(string(out), "ORPHAN-FAILFAST-OK") {
			t.Fatalf("missing ORPHAN-FAILFAST-OK in output %q", string(out))
		}
	})

	t.Run("ignored_sigtstp_returns_immediately", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestHelperSuspendUnixSubprocess$")
		cmd.Env = append(os.Environ(), "XOPS_SSHENV_P6_SUSPEND_HELPER=ignored-sigtstp")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("ignored SIGTSTP helper failed: %v, out=%q", err, string(out))
		}
		if !strings.Contains(string(out), "IGNORED-OK") {
			t.Fatalf("missing IGNORED-OK in output %q", string(out))
		}
	})
}
