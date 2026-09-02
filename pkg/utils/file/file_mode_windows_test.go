//go:build windows

package file

import (
	"os"
	"testing"
)

func assertRequestedFileMode(t *testing.T, info os.FileInfo, _ os.FileMode) {
	t.Helper()
	if !info.Mode().IsRegular() {
		t.Errorf("created path mode = %v, want a regular file", info.Mode())
	}
}
