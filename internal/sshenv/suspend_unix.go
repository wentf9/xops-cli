//go:build !windows

package sshenv

import (
	"os"
	"os/signal"
	"syscall"
)

func platformSuspendProcess() func() error {
	return func() error {
		if signal.Ignored(syscall.SIGTSTP) {
			return nil
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
