//go:build !windows

package sshenv

import (
	"errors"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

var errSuspendOrphanedProcessGroup = errors.New("cannot suspend orphaned or session-leader process group")

func checkSuspendableProcessGroup() error {
	pid := os.Getpid()
	ppid := os.Getppid()
	pgrp := unix.Getpgrp()
	sid, sidErr := unix.Getsid(0)
	var (
		parentSID    int
		parentSIDErr error
	)
	if ppid > 1 {
		parentSID, parentSIDErr = unix.Getsid(ppid)
	}
	return evaluateSuspendProcessGroup(pid, ppid, pgrp, sid, sidErr, parentSID, parentSIDErr)
}

func evaluateSuspendProcessGroup(pid, ppid, pgrp, sid int, sidErr error, parentSID int, parentSIDErr error) error {
	if ppid <= 1 || pgrp <= 0 {
		return errSuspendOrphanedProcessGroup
	}
	if sidErr == nil && sid > 0 {
		if pid == sid || pgrp == sid {
			return errSuspendOrphanedProcessGroup
		}
		if parentSIDErr == nil && parentSID > 0 && parentSID != sid {
			return errSuspendOrphanedProcessGroup
		}
	}
	return nil
}

func platformSuspendProcess() func() error {
	return func() error {
		if signal.Ignored(syscall.SIGTSTP) {
			return nil
		}
		// POSIX silently discards default-action SIGTSTP in orphaned process
		// groups (e.g. session leaders, processes in the session leader's group,
		// init-reparented processes, or processes whose parent is in another
		// session). Fail fast so callers never deadlock forever waiting on SIGCONT.
		if err := checkSuspendableProcessGroup(); err != nil {
			return err
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
