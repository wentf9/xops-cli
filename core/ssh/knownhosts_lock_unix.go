//go:build unix

package ssh

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// openKnownHostsFileNoFollow opens path without following a trailing symlink
// (O_NOFOLLOW) and without blocking on FIFOs (O_NONBLOCK). Callers must still
// verify f.Stat().Mode().IsRegular() on the open file handle before reading or
// writing.
func openKnownHostsFileNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, perm)
}

// openKnownHostsReadOnlyFollow opens a read-only known_hosts file (such as a
// global /etc/ssh/ssh_known_hosts that may be symlinked on Linux/NixOS) with
// O_NONBLOCK so a raced FIFO cannot hang open(). Callers must verify
// f.Stat().Mode().IsRegular() on the open handle before reading.
func openKnownHostsReadOnlyFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func lockKnownHostsFile(f *os.File, exclusive bool) error {
	if f == nil {
		return errors.New("known_hosts file is nil")
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	fd := int(f.Fd())
	for {
		err := syscall.Flock(fd, how)
		if err == nil {
			return nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return err
	}
}

func unlockKnownHostsFile(f *os.File) error {
	if f == nil {
		return nil
	}
	fd := int(f.Fd())
	for {
		err := syscall.Flock(fd, syscall.LOCK_UN)
		if err == nil {
			return nil
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return err
	}
}

func hardenNewKnownHostsFile(string) error {
	return nil
}

// withControlSocketDirLock acquires an exclusive advisory flock(2) on the
// parent directory of targetPath for the duration of fn. Locking the directory
// creates zero extra files, does not affect MaxControlPathLength, serializes
// stale-socket inspection/removal/link across processes and goroutines, and is
// automatically released by the kernel on close or process crash.
func withControlSocketDirLock(targetPath string, fn func() error) error {
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
