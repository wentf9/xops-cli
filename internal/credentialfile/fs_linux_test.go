//go:build linux && amd64

package credentialfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
	"golang.org/x/sys/unix"
)

func TestVaultRootDoesNotRequireFilesystemAllowlist(t *testing.T) {
	// /dev/shm is deliberately outside the ext4/XFS/Btrfs validation matrix.
	// Acceptance here is a policy regression test, not a durability claim.
	path, err := os.MkdirTemp("/dev/shm", "xops-filesystem-policy-")
	if err != nil {
		t.Skipf("shared-memory test directory unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(path); err != nil {
			t.Error(err)
		}
	})
	root, err := createVaultRoot(t.Context(), filepath.Join(path, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.file.Close(); err != nil {
			t.Error(err)
		}
	}()
	reopened, err := openRoot(t.Context(), filepath.Join(path, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := reopened.file.Close(); err != nil {
			t.Error(err)
		}
	}()
	if root.mount != reopened.mount || root.id != reopened.id {
		t.Fatal("unstable directory identity")
	}
}

func TestChildStillRequiresSameDeviceAndMount(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := openRoot(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.file.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, changeDevice := range []bool{false, true} {
		parent := *root
		if changeDevice {
			parent.id.dev++
		} else {
			parent.mount++
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		child, err := newDirectory(file, &parent)
		if child != nil {
			if closeErr := child.file.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("cross-mount directory accepted: %v", err)
		}
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("rejected handle leaked: %v", err)
		}
	}
}

func TestPrivateFileValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  uint32
		links uint64
		dir   bool
		valid bool
	}{
		{"file", unix.S_IFREG | 0600, 1, false, true},
		{"public", unix.S_IFREG | 0644, 1, false, false},
		{"hardlink", unix.S_IFREG | 0600, 2, false, false},
		{"fifo", unix.S_IFIFO | 0600, 1, false, false},
		{"directory", unix.S_IFDIR | 0700, 2, true, true},
		{"group_directory", unix.S_IFDIR | 0770, 2, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := unix.Stat_t{Mode: tc.mode, Uid: uint32(unix.Geteuid()), Nlink: tc.links}
			err := validatePrivate(st, tc.dir)
			if (err == nil) != tc.valid {
				t.Fatalf("permission validation: %v", err)
			}
			if !tc.valid && !errors.Is(err, credential.ErrCredentialAccessDenied) {
				t.Fatal(err)
			}
		})
	}
}
