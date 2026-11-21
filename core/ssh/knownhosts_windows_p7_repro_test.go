//go:build windows

package ssh

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/core/winsec"
)

// TestP7Repro_H7_WindowsOpenKnownHostsNoFollow_ReparsePoint verifies H7 is fixed on Windows:
//   - known_hosts opening now uses fsx.OpenLocked / fsx.OpenRegular (CreateFile with
//     FILE_FLAG_OPEN_REPARSE_POINT + handle attribute inspection) so a swapped leaf
//     symlink/reparse point can never open or return the victim file.
//   - New known_hosts files are created via fsx.CreateExclusive with an owner-only
//     SECURITY_DESCRIPTOR at creation time (rejecting symlinks with os.ErrExist), and
//     winsec.HardenFileOwnerOnly rejects symlinks via handle-based SetSecurityInfo.
func TestP7Repro_H7_WindowsOpenKnownHostsNoFollow_ReparsePoint(t *testing.T) {
	dir := t.TempDir()
	victimData := []byte("victim-data\n")
	victimPath := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victimPath, victimData, 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	probeLink := filepath.Join(dir, "probe.link")
	if err := os.Symlink(victimPath, probeLink); err != nil {
		t.Skipf("Windows symlink creation unavailable (requires Developer Mode or SeCreateSymbolicLinkPrivilege): %v", err)
	}
	_ = os.Remove(probeLink)

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
			lf, err := fsx.OpenLocked(targetPath, fsx.LockShared, false, 0)
			if err != nil {
				continue
			}
			got, readErr := io.ReadAll(lf)
			_ = lf.Close()
			if readErr != nil {
				continue
			}
			if bytes.Equal(got, victimData) {
				t.Fatalf("H7 reproduced on attempt %d: fsx.OpenLocked followed swapped symlink and read victim %q", i+1, victimPath)
			}
		}
	})

	t.Run("create_and_harden_reject_symlink", func(t *testing.T) {
		linkPath := filepath.Join(dir, "known_hosts_harden_link")
		if err := os.Symlink(victimPath, linkPath); err != nil {
			t.Fatalf("create symlink: %v", err)
		}
		if f, err := fsx.CreateExclusive(linkPath, fsx.OwnerOnlyPerm); !errors.Is(err, os.ErrExist) {
			if f != nil {
				_ = f.Close()
			}
			t.Fatalf("H7 reproduced: fsx.CreateExclusive(%q) = %v, want os.ErrExist", linkPath, err)
		}
		if err := winsec.HardenFileOwnerOnly(linkPath); err == nil {
			t.Fatalf("H7 reproduced: winsec.HardenFileOwnerOnly(%q) followed symlink and mutated target DACL without error", linkPath)
		}
	})
}
