//go:build linux && amd64

package credentialfile

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
	"golang.org/x/sys/unix"
)

func TestMountIdentityRequiresExt4AndDeviceMatch(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		valid      bool
	}{
		{"ext4", "82 67 8:32 / / rw - ext4 /dev/sdc rw\n", true},
		{"ext3", "82 67 8:32 / / rw - ext3 /dev/sdc rw\n", false},
		{"wrong_device", "82 67 8:33 / / rw - ext4 /dev/sdc rw\n", false},
		{"wrong_mount", "83 67 8:32 / / rw - ext4 /dev/sdc rw\n", false},
		{"missing_type", "82 67 8:32 / / rw -\n", false},
		{"overlay", "82 67 8:32 / / rw - overlay overlay rw\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := matchMount(strings.NewReader(tc.line), 82, unix.Mkdev(8, 32))
			if (err == nil) != tc.valid {
				t.Fatalf("mount validation: %v", err)
			}
			if !tc.valid && !errors.Is(err, ErrUnsupported) {
				t.Fatal(err)
			}
		})
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
