//go:build windows

package transfer

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Windows metadata privacy relies on the user-profile directory ACL. POSIX
// group/other bits synthesized by os.Stat do not describe Windows ACLs.
func privateJournalMode(os.FileMode) bool { return true }

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
