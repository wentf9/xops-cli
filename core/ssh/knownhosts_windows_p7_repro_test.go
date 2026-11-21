//go:build p7repro && windows

package ssh

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

func p7WinFileIdentity(t *testing.T, path string) windows.ByHandleFileInformation {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %q for identity: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		t.Fatalf("GetFileInformationByHandle(%q): %v", path, err)
	}
	return info
}

func p7SameWinFile(a, b windows.ByHandleFileInformation) bool {
	return a.VolumeSerialNumber == b.VolumeSerialNumber &&
		a.FileIndexHigh == b.FileIndexHigh &&
		a.FileIndexLow == b.FileIndexLow
}

// TestP7Repro_H7_WindowsOpenKnownHostsNoFollow_ReparsePoint reproduces H7 on Windows:
// openKnownHostsFileNoFollow performs a path-based GetFileAttributesNoFollow check followed by
// os.OpenFile (which omits FILE_FLAG_OPEN_REPARSE_POINT). If a symlink/reparse point is swapped
// into place between the two calls (or when the pre-check misses), os.OpenFile follows the reparse
// point and returns a handle to the victim file; GetFileInformationByHandle then inspects the
// victim's attributes (no FILE_ATTRIBUTE_REPARSE_POINT) and permits the open.
// Additionally, hardenNewKnownHostsFile calls SetNamedSecurityInfo by path, following symlinks.
func TestP7Repro_H7_WindowsOpenKnownHostsNoFollow_ReparsePoint(t *testing.T) {
	dir := t.TempDir()
	victimPath := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victimPath, []byte("victim-data\n"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	probeLink := filepath.Join(dir, "probe.link")
	if err := os.Symlink(victimPath, probeLink); err != nil {
		t.Skipf("Windows symlink creation unavailable (requires Developer Mode or SeCreateSymbolicLinkPrivilege): %v", err)
	}
	_ = os.Remove(probeLink)

	victimInfo := p7WinFileIdentity(t, victimPath)

	t.Run("swapped_leaf_symlink_never_opens_victim", func(t *testing.T) {
		targetPath := filepath.Join(dir, "known_hosts_race")
		if err := os.WriteFile(targetPath, []byte("legit\n"), 0o600); err != nil {
			t.Fatalf("seed targetPath: %v", err)
		}

		stopFlip := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopFlip:
					return
				default:
				}
				_ = os.Remove(targetPath)
				_ = os.Symlink(victimPath, targetPath)
				_ = os.Remove(targetPath)
				_ = os.WriteFile(targetPath, []byte("legit\n"), 0o600)
			}
		}()
		defer func() {
			close(stopFlip)
			wg.Wait()
		}()

		const attempts = 500
		for i := range attempts {
			f, err := openKnownHostsFileNoFollow(targetPath, os.O_RDONLY, 0)
			if err != nil {
				continue
			}
			var got windows.ByHandleFileInformation
			infoErr := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &got)
			_ = f.Close()
			if infoErr != nil {
				continue
			}
			if p7SameWinFile(got, victimInfo) {
				t.Fatalf("H7 reproduced on attempt %d: openKnownHostsFileNoFollow followed swapped symlink and returned a handle to victim %q", i+1, victimPath)
			}
		}
	})

	t.Run("hardenNewKnownHostsFile_follows_symlink", func(t *testing.T) {
		linkPath := filepath.Join(dir, "known_hosts_harden_link")
		if err := os.Symlink(victimPath, linkPath); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		if err := hardenNewKnownHostsFile(linkPath); err == nil {
			t.Fatalf("H7 reproduced: hardenNewKnownHostsFile(%q) followed symlink and mutated target DACL without error", linkPath)
		}
	})
}
