//go:build linux || darwin || freebsd

package ssh

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/creack/pty"
)

func TestFindCharDevicePathByInfo_MatchesTerminalAndSkipsSymlinks(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("pty.Open unavailable in environment: %v", err)
	}
	defer func() {
		_ = master.Close()
		_ = slave.Close()
	}()

	info, err := slave.Stat()
	if err != nil {
		t.Fatal(err)
	}

	symlinkDir := t.TempDir()
	symlinkPath := filepath.Join(symlinkDir, "stdout-link")
	if err := os.Symlink(slave.Name(), symlinkPath); err != nil {
		t.Fatal(err)
	}

	// Even when symlinkDir precedes real /dev directories, symlinks must never be returned.
	got, err := findCharDevicePathByInfo(info, []string{symlinkDir, "/dev/pts", "/dev"})
	if err != nil {
		t.Fatalf("findCharDevicePathByInfo failed: %v", err)
	}
	if got == symlinkPath {
		t.Fatalf("findCharDevicePathByInfo returned symlink %q instead of character device node", got)
	}
	gotInfo, err := os.Lstat(got)
	if err != nil {
		t.Fatalf("Lstat(%q) failed: %v", got, err)
	}
	if gotInfo.Mode()&os.ModeSymlink != 0 || gotInfo.Mode()&os.ModeCharDevice == 0 {
		t.Fatalf("matched path %q mode = %v, want real ModeCharDevice", got, gotInfo.Mode())
	}
	if !os.SameFile(info, gotInfo) {
		t.Fatalf("matched path %q does not refer to the same device as slave %q", got, slave.Name())
	}
}
