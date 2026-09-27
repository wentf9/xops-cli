//go:build !windows

package transfer

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func privateJournalMode(mode os.FileMode) bool { return mode.Perm()&0077 == 0 }

func lockJournal(file *os.File) error {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return ErrStoreLocked
	}
	return err
}

func replaceJournalFile(root *os.Root, source, destination string) error {
	if err := root.Rename(source, destination); err != nil {
		return fmt.Errorf("replace transfer metadata: %w", err)
	}
	return nil
}

func syncJournalDirectory(path string) (retErr error) {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open transfer metadata directory for sync: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, closeJournalResource(file, "directory")) }()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync transfer metadata directory: %w", err)
	}
	return nil
}
