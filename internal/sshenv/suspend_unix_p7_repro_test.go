//go:build p7repro && !windows

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

	"golang.org/x/sys/unix"
)

// TestP7Repro_MED10_EvaluateSuspendProcessGroup_FailClosedOnErrors reproduces MED-10 part 1:
// evaluateSuspendProcessGroup fails open (returns nil) when Getsid(0) or Getsid(ppid) fails
// or returns a non-positive session ID.
func TestP7Repro_MED10_EvaluateSuspendProcessGroup_FailClosedOnErrors(t *testing.T) {
	cases := []struct {
		name         string
		pid          int
		ppid         int
		pgrp         int
		sid          int
		sidErr       error
		parentSID    int
		parentSIDErr error
	}{
		{
			name:   "getsid_self_eperm",
			pid:    200,
			ppid:   100,
			pgrp:   200,
			sid:    0,
			sidErr: syscall.EPERM,
		},
		{
			name:   "getsid_self_enosys",
			pid:    200,
			ppid:   100,
			pgrp:   200,
			sid:    0,
			sidErr: syscall.ENOSYS,
		},
		{
			name: "getsid_self_nonpositive",
			pid:  200,
			ppid: 100,
			pgrp: 200,
			sid:  0,
		},
		{
			name:         "getsid_parent_eperm",
			pid:          200,
			ppid:         100,
			pgrp:         200,
			sid:          100,
			parentSID:    0,
			parentSIDErr: syscall.EPERM,
		},
		{
			name:         "getsid_parent_esrch",
			pid:          200,
			ppid:         100,
			pgrp:         200,
			sid:          100,
			parentSID:    0,
			parentSIDErr: syscall.ESRCH,
		},
		{
			name:      "getsid_parent_nonpositive",
			pid:       200,
			ppid:      100,
			pgrp:      200,
			sid:       100,
			parentSID: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := evaluateSuspendProcessGroup(tc.pid, tc.ppid, tc.pgrp, tc.sid, tc.sidErr, tc.parentSID, tc.parentSIDErr)
			if err == nil {
				t.Fatalf("MED-10 reproduced: evaluateSuspendProcessGroup(%d,%d,%d,%d,%v,%d,%v) failed open (returned nil), want error",
					tc.pid, tc.ppid, tc.pgrp, tc.sid, tc.sidErr, tc.parentSID, tc.parentSIDErr)
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
		// Session leader (Setsid=true) spawns pgrp_leader in a new process group (Setpgid=true),
		// waits for child to be alive inside that process group, and then exits so the process
		// group becomes POSIX-orphaned while pgrp_leader stays alive as child's parent.
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
		// Exit session_leader without killing pgrp_leader/child; test signals goPath once we exit.
		os.Exit(0)

	case "pgrp_leader":
		// Spawn child in the SAME process group (no Setpgid) and wait for it to complete.
		cmd := exec.Command(exe, "-test.run=^TestHelperP7_MED10_SuspendOrphan$")
		cmd.Env = append(os.Environ(), p7MED10RoleEnv+"=child")
		if err := cmd.Start(); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "start child: %v\n", err)
			os.Exit(22)
		}
		_ = cmd.Wait()
		os.Exit(0)

	case "child":
		// Signal session_leader that we are running inside pgrp_leader's process group.
		if err := os.WriteFile(readyPath, []byte("ready"), 0o600); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "write ready: %v\n", err)
			os.Exit(23)
		}
		// Wait until test confirms session_leader has exited (so our process group is now orphaned).
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
		checkErr := checkSuspendableProcessGroup()

		rep := p7MED10ChildReport{
			PID:        pid,
			PPID:       ppid,
			PGRP:       pgrp,
			ParentPGRP: parentPGRP,
			SID:        sid,
			ParentSID:  parentSID,
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

// TestP7Repro_MED10_CheckSuspendableProcessGroup_OrphanedSamePGRPAsParent reproduces MED-10 part 2:
// Under POSIX, a process whose parent is in the same session AND the SAME process group
// (parentPGRP == pgrp) cannot keep its process group non-orphaned. In a real orphaned process group
// {pgrp_leader, child} (after the session leader exits), child has ppid == pgrp_leader > 1,
// pid != sid, pgrp != sid, parentSID == sid, and parentPGRP == pgrp. Because
// checkSuspendableProcessGroup / evaluateSuspendProcessGroup does not check parentPGRP == pgrp,
// it erroneously allows suspend (returning nil).
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
	// Start session_leader in its own session so it can exit cleanly and orphan {pgrp_leader, child}.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("session_leader failed: %v (output=%s)", err, string(out))
	}

	// session_leader has exited and been reaped; {pgrp_leader, child} is now a POSIX orphaned process group.
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
	// Sanity-check that we genuinely created the exact POSIX orphaned process group topology.
	if rep.PPID <= 1 || rep.PID == rep.SID || rep.PGRP == rep.SID || rep.ParentSID != rep.SID || rep.ParentPGRP != rep.PGRP {
		t.Fatalf("precondition mismatch for orphaned same-pgrp child topology: %+v", rep)
	}
	if rep.CheckErr == "" {
		t.Fatalf("MED-10 reproduced: checkSuspendableProcessGroup returned nil for orphaned process group member with parentPGRP==pgrp (%+v)", rep)
	}
}
