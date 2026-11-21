//go:build !windows

package transfer

import (
	"fmt"
	"os"
)

func privateJournalMode(mode os.FileMode) bool { return mode.Perm()&0077 == 0 }

func replaceJournalFile(root *os.Root, source, destination string) error {
	if err := root.Rename(source, destination); err != nil {
		return fmt.Errorf("replace transfer metadata: %w", err)
	}
	return nil
}
