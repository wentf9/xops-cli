//go:build windows

package credential

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func tryLockFile(file *os.File) error {
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY | windows.LOCKFILE_EXCLUSIVE_LOCK)
	return windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &windows.Overlapped{})
}

func unlockFile(file *os.File) error {
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}

func isLockContended(err error) bool {
	return errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

