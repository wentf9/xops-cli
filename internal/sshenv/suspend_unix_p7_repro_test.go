//go:build !windows

package sshenv

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/verdict"
	"golang.org/x/sys/unix"
)

// TestP7Repro_MED10_EvaluateSuspendProcessGroup_FailClosedOnErrors verifies MED-10 part 1:
// evaluateSuspendProcessGroup fails closed (returns verdict.Deny + error) when Getsid(0),
// Getsid(ppid), or Getpgid(ppid) fails or returns a non-positive ID.
func TestP7Repro_MED10_EvaluateSuspendProcessGroup_FailClosedOnErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		snap suspendProcessSnapshot
	}{
		{
			name: "getsid_self_eperm",
			snap: suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sidErr: syscall.EPERM, parentSID: 100, parentPGRP: 100},
		},
		{
			name: "getsid_self_enosys",
			snap: suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sidErr: syscall.ENOSYS, parentSID: 100, parentPGRP: 100},
		},
		{
			name: "getsid_self_nonpositive",
			snap: suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sid: 0, parentSID: 100, parentPGRP: 100},
		},
		{
			name: "getsid_parent_eperm",
			snap: suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sid: 100, parentSIDErr: syscall.EPERM, parentPGRP: 100},
		},
		{
			name: "getsid_parent_esrch",
			snap: suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sid: 100, parentSIDErr: syscall.ESRCH, parentPGRP: 100},
		},
		{
			name: "getsid_parent_nonpositive",
			snap: suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sid: 100, parentSID: 0, parentPGRP: 100},
		},
		{
			name: "getpgid_parent_eperm",
			snap: suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sid: 100, parentSID: 100, parentPGRPErr: syscall.EPERM},
		},
		{
			name: "getpgid_parent_nonpositive",
			snap: suspendProcessSnapshot{pid: 200, ppid: 100, pgrp: 200, sid: 100, parentSID: 100, parentPGRP: 0},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := evaluateSuspendProcessGroup(tc.snap)
			if v != verdict.Deny || err == nil {
				t.Fatalf("evaluateSuspendProcessGroup(%+v) = (%v, %v), want (Deny, non-nil error)", tc.snap, v, err)
			}
		})
	}
}

const (
	p7MED10RoleEnv   = "XOPS_SSHENV_P7_MED10_ROLE"
	p7MED10ResultEnv = "XOPS_SSHENV_P7_MED10_RESULT"
	p7MED10ReadyEnv  = "XOPS_SSHENV_P7_MED10_READY"
	p7MED10GoEnv     = "XOPS_SSHENV_P7_MED10_GO"
)

type p7MED10ChildReport struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	PGRP       int    `json:"pgrp"`
	ParentPGRP int    `json:"parent_pgrp"`
	SID        int    `json:"sid"`
	ParentSID  int    `json:"parent_sid"`
	Verdict    string `json:"verdict"`
	CheckErr   string `json:"check_err"`
}

func TestHelperP7_MED10_SuspendOrphan(t *testing.T) {
	role := os.Getenv(p7MED10RoleEnv)
	if role == "" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "os.Executable: %v\n", err)
		os.Exit(20)
	}
	resultPath := os.Getenv(p7MED10ResultEnv)
	readyPath := os.Getenv(p7MED10ReadyEnv)
	goPath := os.Getenv(p7MED10GoEnv)

	switch role {
	case "session_leader":
		cmd := exec.Command(exe, "-test.run=^TestHelperP7_MED10_SuspendOrphan$")
		cmd.Env = append(os.Environ(), p7MED10RoleEnv+"=pgrp_leader")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "start pgrp_leader: %v\n", err)
			os.Exit(21)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if _, statErr := os.Stat(readyPath); statErr == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Exit(0)

	case "pgrp_leader":
		cmd := exec.Command(exe, "-test.run=^TestHelperP7_MED10_SuspendOrphan$")
		cmd.Env = append(os.Environ(), p7MED10RoleEnv+"=child")
		if err := cmd.Start(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "start child: %v\n", err)
			os.Exit(22)
		}
		_ = cmd.Wait()
		os.Exit(0)

	case "child":
		if err := os.WriteFile(readyPath, []byte("ready"), 0o600); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "write ready: %v\n", err)
			os.Exit(23)
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if _, statErr := os.Stat(goPath); statErr == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}

		pid := os.Getpid()
		ppid := os.Getppid()
		pgrp := unix.Getpgrp()
		parentPGRP, _ := unix.Getpgid(ppid)
		sid, _ := unix.Getsid(0)
		parentSID, _ := unix.Getsid(ppid)
		v, checkErr := checkSuspendableProcessGroup()

		rep := p7MED10ChildReport{
			PID:        pid,
			PPID:       ppid,
			PGRP:       pgrp,
			ParentPGRP: parentPGRP,
			SID:        sid,
			ParentSID:  parentSID,
			Verdict:    v.String(),
		}
		if checkErr != nil {
			rep.CheckErr = checkErr.Error()
		}
		data, _ := json.Marshal(rep)
		tmp := resultPath + ".tmp"
		_ = os.WriteFile(tmp, data, 0o600)
		_ = os.Rename(tmp, resultPath)
		os.Exit(0)
	}
}

// TestP7Repro_MED10_CheckSuspendableProcessGroup_OrphanedSamePGRPAsParent verifies MED-10 part 2:
// A real POSIX orphaned process group member whose parent is in the same session AND the same
// process group (parentPGRP == pgrp) must be denied suspend (verdict.Deny + error).
func TestP7Repro_MED10_CheckSuspendableProcessGroup_OrphanedSamePGRPAsParent(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready")
	goPath := filepath.Join(dir, "go")
	resultPath := filepath.Join(dir, "result.json")

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestHelperP7_MED10_SuspendOrphan$")
	cmd.Env = append(os.Environ(),
		p7MED10RoleEnv+"=session_leader",
		p7MED10ReadyEnv+"="+readyPath,
		p7MED10GoEnv+"="+goPath,
		p7MED10ResultEnv+"="+resultPath,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("session_leader failed: %v (output=%s)", err, string(out))
	}

	if err := os.WriteFile(goPath, []byte("go"), 0o600); err != nil {
		t.Fatalf("write go signal: %v", err)
	}

	var data []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var readErr error
		data, readErr = os.ReadFile(resultPath)
		if readErr == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(data) == 0 {
		t.Fatal("timed out waiting for orphaned child report")
	}

	var rep p7MED10ChildReport
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal child report %q: %v", string(data), err)
	}
	if rep.PPID <= 1 || rep.PID == rep.SID || rep.PGRP == rep.SID || rep.ParentSID != rep.SID || rep.ParentPGRP != rep.PGRP {
		t.Fatalf("precondition mismatch for orphaned same-pgrp child topology: %+v", rep)
	}
	if rep.Verdict != verdict.Deny.String() || rep.CheckErr == "" {
		t.Fatalf("checkSuspendableProcessGroup did not fail closed for orphaned same-pgrp member: %+v", rep)
	}
}

// TestP7_LOW5_PostReapPGID_RequiresLiveMemberProof verifies LOW-5(pgid):
// after the group leader has been reaped, neither reapRemainingGroup nor
// cleanupAfterWait signals -pgid unless an inherited live-member sentinel proof
// is active (fail closed: skip signal).
func TestP7_LOW5_PostReapPGID_RequiresLiveMemberProof(t *testing.T) {
	t.Run("reapRemainingGroup_nil_sentinel_skips_signal", func(t *testing.T) {
		dummyPGID := startTermIgnoringDummyPGID(t)
		stderrDone := make(chan struct{}) // open stderr alone is NOT a sentinel proof
		var hookCalled bool
		origHook := onUnixReapRemainingGroup
		onUnixReapRemainingGroup = func(int) { hookCalled = true }
		t.Cleanup(func() { onUnixReapRemainingGroup = origHook })

		p := &platformProc{pgid: dummyPGID}
		p.markReaped()
		p.reapRemainingGroup(20*time.Millisecond, stderrDone, nil, false)
		if hookCalled {
			t.Fatal("reapRemainingGroup ran without live-member sentinel proof")
		}
		if err := syscall.Kill(-dummyPGID, 0); err != nil {
			t.Fatalf("reapRemainingGroup signaled unrelated live PGID %d without sentinel proof: %v", dummyPGID, err)
		}
	})

	t.Run("reapRemainingGroup_closed_sentinel_pipe_fd_skips_signal", func(t *testing.T) {
		dummyPGID := startTermIgnoringDummyPGID(t)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		_ = w.Close()

		stderrDone := make(chan struct{})
		openSentinelDone := make(chan struct{}) // channel lagging behind kernel EOF
		var hookCalled bool
		origHook := onUnixReapRemainingGroup
		onUnixReapRemainingGroup = func(int) { hookCalled = true }
		t.Cleanup(func() { onUnixReapRemainingGroup = origHook })

		p := &platformProc{pgid: dummyPGID}
		p.bindSentinelObserver(r, openSentinelDone)
		p.markReaped()
		p.reapRemainingGroup(20*time.Millisecond, stderrDone, openSentinelDone, false)
		p.clearSentinelObserver()
		if hookCalled {
			t.Fatal("reapRemainingGroup ran despite sentinel pipe writer being closed")
		}
		if err := syscall.Kill(-dummyPGID, 0); err != nil {
			t.Fatalf("reapRemainingGroup signaled live PGID %d after sentinel writer closed: %v", dummyPGID, err)
		}
	})

	t.Run("cleanupAfterWait_nil_sentinel_skips_signal", func(t *testing.T) {
		dummyPGID := startTermIgnoringDummyPGID(t)
		var hookCalled bool
		origHook := onUnixReapRemainingGroup
		onUnixReapRemainingGroup = func(int) { hookCalled = true }
		t.Cleanup(func() { onUnixReapRemainingGroup = origHook })

		p := &platformProc{pgid: dummyPGID}
		p.markReaped()
		p.cleanupAfterWait(true)
		if hookCalled {
			t.Fatal("cleanupAfterWait signaled -pgid with nil sentinel pipe")
		}
		if err := syscall.Kill(-dummyPGID, 0); err != nil {
			t.Fatalf("cleanupAfterWait signaled unrelated live PGID %d with nil sentinel: %v", dummyPGID, err)
		}
	})
}
