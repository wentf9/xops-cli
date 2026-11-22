//go:build !windows

package transfer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wentf9/xops-cli/core/fsx"
)

func privateJournalMode(mode os.FileMode) bool { return mode.Perm()&0077 == 0 }

func createJournalDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err == nil {
		if !info.IsDir() || !privateJournalMode(info.Mode()) {
			return errors.New("transfer metadata directory must be a private directory, not a symbolic link")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect transfer metadata directory: %w", err)
	}
	parent := filepath.Dir(directory)
	if parent != directory {
		if _, err := os.Stat(parent); errors.Is(err, os.ErrNotExist) {
			if err := createJournalDirectory(parent); err != nil {
				return err
			}
		} else if err != nil {
			return fmt.Errorf("inspect transfer metadata parent: %w", err)
		}
	}
	if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create transfer metadata directory: %w", err)
	}
	if err := fsx.SyncDir(parent); err != nil {
		return err
	}
	return createJournalDirectory(directory)
}

func verifyJournalRoot(*os.Root) error { return nil }

func openJournalLockFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
}

func createJournalTempFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}

func checkJournalFilePrivacy(_ *os.File, mode os.FileMode) error {
	if !privateJournalMode(mode) {
		return errors.New("transfer metadata must be a private regular file")
	}
	return nil
}

func replaceJournalFile(root *os.Root, source, destination string) error {
	if err := root.Rename(source, destination); err != nil {
		return fmt.Errorf("replace transfer metadata: %w", err)
	}
	return nil
}
