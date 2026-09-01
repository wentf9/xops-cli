//go:build !windows

package config

import (
	"errors"
	"os"
	"syscall"
)

func tryLockConfigFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockConfigFile(file *os.File) error {
	return syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
}

func isConfigLockContended(err error) bool {
	return errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN)
}
