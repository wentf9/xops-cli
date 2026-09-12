//go:build integration && linux && amd64

package kdfhelper

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The isolated supervisor adopts and reaps the orphan; it does not change the
// subreaper policy of the main integration-test process.
func TestKDFParentDeathProcess(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	if mode == "death-parent" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestKDFProcessWorker$", "--", "worker-stall")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
		if err := cmd.Start(); err != nil {
			os.Exit(1)
		}
		if _, err := fmt.Fprintln(os.Stdout, cmd.Process.Pid); err != nil {
			os.Exit(1)
		}
		os.Exit(77)
	}
	if mode != "death-supervisor" {
		return
	}
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestKDFParentDeathProcess$", "--", "death-parent")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 77 {
		t.Fatalf("parent did not exit: %v %s", err, out)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		var status unix.WaitStatus
		got, err := unix.Wait4(pid, &status, unix.WNOHANG, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got == pid {
			if !status.Signaled() || status.Signal() != unix.SIGKILL {
				t.Fatalf("unexpected orphan status %v", status)
			}
			return
		}
		if time.Now().After(deadline) {
			killErr := unix.Kill(pid, unix.SIGKILL)
			_, waitErr := unix.Wait4(pid, &status, 0, nil)
			t.Fatalf("orphan remained alive; cleanup: %v", errors.Join(killErr, waitErr))
		}
		time.Sleep(time.Millisecond)
	}
}

func TestKDFParentDeathKillsWorker(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestKDFParentDeathProcess$", "--", "death-supervisor")
	cmd.WaitDelay = time.Second
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("parent-death verification: %v\n%s", err, out)
	}
}
