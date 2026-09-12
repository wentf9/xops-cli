//go:build linux && amd64

package credentialfile

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMountIDOldKernelFallback(t *testing.T) {
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	expected, err := mountID(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		failure error
	}{
		{"no statx", unix.ENOSYS}, {"unsupported mask", unix.EINVAL},
		{"unsupported operation", unix.EOPNOTSUPP}, {"missing returned mask", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			id, err := mountIDWithStatx(file, func(int, string, int, int, *unix.Statx_t) error { return tt.failure })
			if err != nil || id != expected {
				t.Fatalf("mount identity mismatch: %d vs %d, %v", id, expected, err)
			}
		})
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("borrowed handle closed", err)
	}
}

func TestMountIDDoesNotBypassAccessDenial(t *testing.T) {
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	_, err = mountIDWithStatx(file, func(int, string, int, int, *unix.Statx_t) error { return unix.EACCES })
	if !errors.Is(err, unix.EACCES) || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("access error hidden: %v", err)
	}
}

func TestParseFDInfoMountID(t *testing.T) {
	for _, tt := range []struct {
		name, input string
		want        uint64
	}{
		{"old kernel", "pos:\t0\nflags:\t0100000\nmnt_id:\t46\n", 46},
		{"new kernel", "pos:\t0\nmnt_id:\t101\nino:\t2345\n", 101},
		{"missing", "pos:\t0\n", 0}, {"empty", "mnt_id:\n", 0},
		{"zero", "mnt_id:\t0\n", 0}, {"negative", "mnt_id:\t-1\n", 0},
		{"overflow", "mnt_id:\t18446744073709551616\n", 0},
		{"duplicate", "mnt_id:\t1\nmnt_id:\t2\n", 0},
		{"trailing text", "mnt_id:\t46 garbage\n", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFDInfoMountID(tt.input)
			if tt.want == 0 {
				if err == nil {
					t.Fatal("invalid fdinfo accepted")
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("got %d, %v", got, err)
			}
		})
	}
}
