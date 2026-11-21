//go:build unix

package ssh

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func holdSocketDirLockForTest(targetPath string, fn func() error) error {
	dirFile, err := os.Open(filepath.Dir(targetPath))
	if err != nil {
		return err
	}
	defer func() { _ = dirFile.Close() }()

	fd := int(dirFile.Fd())
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX)
		if err == nil {
			break
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return err
	}
	defer func() {
		for {
			if uErr := syscall.Flock(fd, syscall.LOCK_UN); uErr == nil || !errors.Is(uErr, syscall.EINTR) {
				break
			}
		}
	}()
	return fn()
}
