//go:build !windows

package file

import (
	"os"
	"testing"
)

func assertRequestedFileMode(t *testing.T, info os.FileInfo, want os.FileMode) {
	t.Helper()
	if got := info.Mode().Perm(); got != want {
		t.Errorf("permissions = %o, want %o", got, want)
	}
}
