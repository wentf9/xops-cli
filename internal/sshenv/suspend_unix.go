//go:build !windows

package sshenv

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/wentf9/xops-cli/core/verdict"
	"golang.org/x/sys/unix"
)

var errSuspendOrphanedProcessGroup = errors.New("cannot suspend orphaned or session-leader process group")

type suspendProcessSnapshot struct {
	pid           int
	ppid          int
	pgrp          int
	sid           int
	sidErr        error
	parentSID     int
	parentSIDErr  error
	parentPGRP    int
	parentPGRPErr error
}

// checkSuspendableProcessGroup evaluates whether the current process belongs to
// a non-orphaned POSIX process group that can safely receive SIGTSTP.
// Any Getsid/Getpgid error or non-positive ID fails closed with verdict.Deny.
func checkSuspendableProcessGroup() (verdict.Verdict, error) {
	pid := os.Getpid()
	ppid := os.Getppid()
	pgrp := unix.Getpgrp()
	sid, sidErr := unix.Getsid(0)
	var (
		parentSID     int
		parentSIDErr  error
		parentPGRP    int
		parentPGRPErr error
	)
	if ppid > 1 {
		parentSID, parentSIDErr = unix.Getsid(ppid)
		parentPGRP, parentPGRPErr = unix.Getpgid(ppid)
	}
	return evaluateSuspendProcessGroup(suspendProcessSnapshot{
		pid:           pid,
		ppid:          ppid,
		pgrp:          pgrp,
		sid:           sid,
		sidErr:        sidErr,
		parentSID:     parentSID,
		parentSIDErr:  parentSIDErr,
		parentPGRP:    parentPGRP,
		parentPGRPErr: parentPGRPErr,
	})
}

func evaluateSuspendProcessGroup(s suspendProcessSnapshot) (verdict.Verdict, error) {
	if s.pid <= 0 || s.ppid <= 1 || s.pgrp <= 0 {
		return verdict.Deny, errSuspendOrphanedProcessGroup
	}
	if s.sidErr != nil {
		return verdict.Deny, fmt.Errorf("%w: getsid(0): %w", errSuspendOrphanedProcessGroup, s.sidErr)
	}
	if s.sid <= 0 || s.pid == s.sid || s.pgrp == s.sid {
		return verdict.Deny, errSuspendOrphanedProcessGroup
	}
	if s.parentSIDErr != nil {
		return verdict.Deny, fmt.Errorf("%w: getsid(ppid): %w", errSuspendOrphanedProcessGroup, s.parentSIDErr)
	}
	if s.parentSID <= 0 || s.parentSID != s.sid {
		return verdict.Deny, errSuspendOrphanedProcessGroup
	}
	if s.parentPGRPErr != nil {
		return verdict.Deny, fmt.Errorf("%w: getpgid(ppid): %w", errSuspendOrphanedProcessGroup, s.parentPGRPErr)
	}
	// Full POSIX orphaned process group predicate: parent must belong to the
	// same session AND a different process group to prevent the group from
	// being orphaned.
	if s.parentPGRP <= 0 || s.parentPGRP == s.pgrp {
		return verdict.Deny, errSuspendOrphanedProcessGroup
	}
	return verdict.Allow, nil
}

func platformSuspendProcess() func() error {
	return func() error {
		if signal.Ignored(syscall.SIGTSTP) {
			return nil
		}
		// POSIX silently discards default-action SIGTSTP in orphaned process
		// groups (e.g. session leaders, processes in the session leader's group,
		// init-reparented processes, or processes whose parent is in another
		// session or the same process group). Fail closed so callers never
		// deadlock waiting on SIGCONT.
		var checkErr error
		v := verdict.Decide(func() (verdict.Verdict, error) {
			res, err := checkSuspendableProcessGroup()
			checkErr = err
			return res, err
		})
		if v.Denied() {
			if checkErr != nil {
				return checkErr
			}
			return errSuspendOrphanedProcessGroup
		}
		// Register SIGCONT notification before sending SIGTSTP so that in a
		// multi-threaded Go runtime suspendFn only returns after the process
		// actually stops and resumes (fg), preventing callers from re-entering
		// terminal raw mode before the kernel stop lands.
		sigContCh := make(chan os.Signal, 1)
		signal.Notify(sigContCh, syscall.SIGCONT)
		defer signal.Stop(sigContCh)

		// Send SIGTSTP to the foreground process group (matching OpenSSH kill(0, SIGTSTP)),
		// falling back to the current process PID if group signaling is disallowed.
		if err := syscall.Kill(0, syscall.SIGTSTP); err != nil {
			if pidErr := syscall.Kill(os.Getpid(), syscall.SIGTSTP); pidErr != nil {
				return pidErr
			}
		}
		<-sigContCh
		return nil
	}
}
