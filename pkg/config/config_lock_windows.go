//go:build windows

package config

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

const lockfileExclusiveLock = 0x00000002

func tryLockConfigFile(file *os.File) error {
	return windows.LockFileEx(windows.Handle(file.Fd()), lockfileExclusiveLock, 0, 1, 0, &windows.Overlapped{})
}

func unlockConfigFile(file *os.File) error {
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}

func isConfigLockContended(err error) bool {
	return errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
