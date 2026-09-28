package sftp

import (
	"errors"
	"fmt"
	"os"
)

// replaceLocalFile first attempts an atomic replacement. Some filesystems reject
// renaming over an existing file; in that case, retain the old regular file in a
// backup until promotion succeeds. This fallback is not atomic.
func replaceLocalFile(tempPath, localPath string, rename func(string, string) error) error {
	renameErr := rename(tempPath, localPath)
	if renameErr == nil {
		return nil
	}
	if !errors.Is(renameErr, os.ErrExist) {
		return fmt.Errorf("rename local temporary file failed: %w", renameErr)
	}
	info, err := os.Lstat(localPath)
	if err != nil {
		return errors.Join(fmt.Errorf("rename local temporary file failed: %w", renameErr),
			fmt.Errorf("lstat local destination before replacement failed: %w", err))
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cannot replace non-regular local destination %q: %w", localPath, renameErr)
	}

	// tempPath already contains the random suffix assigned at finalization.
	backupPath := tempPath + ".backup"
	if _, err := os.Lstat(backupPath); err == nil {
		return fmt.Errorf("prepare local destination backup failed: backup %q already exists", backupPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("lstat local destination backup failed: %w", err)
	}
	if err := rename(localPath, backupPath); err != nil {
		return fmt.Errorf("backup local destination failed: %w", err)
	}
	if err := rename(tempPath, localPath); err != nil {
		promotionErr := fmt.Errorf("rename local temporary file failed: %w", err)
		// Do not overwrite a destination created by another writer while the
		// original was backed up. Leave its backup available for recovery.
		if _, statErr := os.Lstat(localPath); !errors.Is(statErr, os.ErrNotExist) {
			return errors.Join(promotionErr, fmt.Errorf("local destination changed; original retained at %q", backupPath), statErr)
		}
		if rollbackErr := rename(backupPath, localPath); rollbackErr != nil {
			return errors.Join(promotionErr, fmt.Errorf("restore local destination failed; original retained at %q: %w", backupPath, rollbackErr))
		}
		return promotionErr
	}
	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("remove local destination backup %q failed: %w", backupPath, err)
	}
	return nil
}
