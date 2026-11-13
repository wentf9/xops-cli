//go:build !windows

package sshenv

import (
	"os"
	"syscall"
)

func platformSuspendProcess() func() error {
	return func() error {
		// Send SIGTSTP to the foreground process group (matching OpenSSH kill(0, SIGTSTP)),
		// falling back to the current process PID if group signaling is disallowed.
		if err := syscall.Kill(0, syscall.SIGTSTP); err != nil {
			return syscall.Kill(os.Getpid(), syscall.SIGTSTP)
		}
		return nil
	}
}
