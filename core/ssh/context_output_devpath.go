//go:build linux || darwin || freebsd

package ssh

import (
	"fmt"
	"os"
	"path/filepath"
)

// findCharDevicePathByInfo locates the filesystem device node matching info
// across dirs without following symlinks (such as /dev/stdout -> /dev/fd/1),
// ensuring os.OpenFile opens an independent kernel file description rather
// than duplicating a borrowed descriptor.
func findCharDevicePathByInfo(info os.FileInfo, dirs []string) (string, error) {
	if info == nil {
		return "", fmt.Errorf("terminal file info is nil")
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			entryInfo, infoErr := entry.Info()
			if infoErr != nil {
				continue
			}
			if entryInfo.Mode()&os.ModeCharDevice == 0 {
				continue
			}
			if os.SameFile(info, entryInfo) {
				return filepath.Join(dir, entry.Name()), nil
			}
		}
	}
	return "", fmt.Errorf("resolve terminal output device path: no matching character device found")
}
