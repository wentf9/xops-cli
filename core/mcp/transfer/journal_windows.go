//go:build windows

package transfer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Windows metadata privacy relies on the user-profile directory ACL. POSIX
// group/other bits synthesized by os.Stat do not describe Windows ACLs.
func privateJournalMode(os.FileMode) bool { return true }

func lockJournal(file *os.File) error {
	err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_FAIL_IMMEDIATELY|windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &windows.Overlapped{})
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return ErrStoreLocked
	}
	return err
}

func replaceJournalFile(root *os.Root, source, destination string) error {
	from, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), source))
	if err != nil {
		return fmt.Errorf("encode temporary transfer metadata path: %w", err)
	}
	to, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), destination))
	if err != nil {
		return fmt.Errorf("encode transfer metadata path: %w", err)
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("replace transfer metadata: %w", err)
	}
	return nil
}

func syncJournalDirectory(path string) (retErr error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode transfer directory: %w", err)
	}
	handle, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fmt.Errorf("open transfer metadata directory for sync: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, windows.CloseHandle(handle)) }()
	if err := windows.FlushFileBuffers(handle); err != nil {
		return fmt.Errorf("sync transfer metadata directory: %w", err)
	}
	return nil
}
