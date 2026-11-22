//go:build unix

package fsx

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenRegularAndOpenLocked_FIFODoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "stall.fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo failed: %v", err)
	}

	cases := []struct {
		name string
		fn   func() error
	}{
		{
			name: "OpenRegular",
			fn: func() error {
				rf, err := OpenRegular(fifoPath, Limits{MaxBytes: 1024})
				if rf != nil {
					_ = rf.Close()
				}
				return err
			},
		},
		{
			name: "ReadAllBounded",
			fn: func() error {
				_, err := ReadAllBounded(fifoPath, Limits{MaxBytes: 1024})
				return err
			},
		},
		{
			name: "OpenRegular_AllowDevNull",
			fn: func() error {
				rf, err := OpenRegular(fifoPath, Limits{MaxBytes: 1024}, AllowDevNull())
				if rf != nil {
					_ = rf.Close()
				}
				return err
			},
		},
		{
			name: "OpenLocked_Shared",
			fn: func() error {
				lf, err := OpenLocked(fifoPath, LockShared, false, 0)
				if lf != nil {
					_ = lf.Close()
				}
				return err
			},
		},
		{
			name: "OpenLocked_Exclusive",
			fn: func() error {
				lf, err := OpenLocked(fifoPath, LockExclusive, false, OwnerOnlyPerm)
				if lf != nil {
					_ = lf.Close()
				}
				return err
			},
		},
		{
			name: "OpenRegularUnbounded",
			fn: func() error {
				f, _, err := OpenRegularUnbounded(fifoPath)
				if f != nil {
					_ = f.Close()
				}
				return err
			},
		},
		{
			name: "OpenRegularUnbounded_FollowSymlinks",
			fn: func() error {
				f, _, err := OpenRegularUnbounded(fifoPath, FollowSymlinks())
				if f != nil {
					_ = f.Close()
				}
				return err
			},
		},
		{
			name: "OpenStagingFile",
			fn: func() error {
				f, _, _, err := OpenStagingFile(fifoPath, OwnerOnlyPerm)
				if f != nil {
					_ = f.Close()
				}
				return err
			},
		},
		{
			name: "OpenAppendRegular",
			fn: func() error {
				f, err := OpenAppendRegular(fifoPath, OwnerOnlyPerm)
				if f != nil {
					_ = f.Close()
				}
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- tc.fn() }()
			select {
			case err := <-done:
				if !errors.Is(err, ErrNonRegular) {
					t.Fatalf("%s on FIFO = %v, want ErrNonRegular", tc.name, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("%s blocked on FIFO instead of failing closed", tc.name)
			}
		})
	}
}

func TestOpenRegular_UnixDevicesAndSockets(t *testing.T) {
	t.Run("dev_zero_rejected_even_with_AllowDevNull", func(t *testing.T) {
		if _, err := os.Stat("/dev/zero"); err != nil {
			t.Skip("/dev/zero not available")
		}
		done := make(chan error, 1)
		go func() {
			_, err := ReadAllBounded("/dev/zero", Limits{MaxBytes: 64}, AllowDevNull())
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ErrNonRegular) {
				t.Fatalf("ReadAllBounded(/dev/zero, AllowDevNull()) = %v, want ErrNonRegular", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("ReadAllBounded(/dev/zero) blocked")
		}
	})

	t.Run("symlink_to_dev_null_requires_both_options", func(t *testing.T) {
		dir := t.TempDir()
		nullLink := filepath.Join(dir, "null-link")
		if err := os.Symlink(os.DevNull, nullLink); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenRegular(nullLink, Limits{MaxBytes: 64}, AllowDevNull()); !errors.Is(err, ErrSymlink) {
			t.Fatalf("OpenRegular(symlink->/dev/null, AllowDevNull) = %v, want ErrSymlink", err)
		}
		rf, err := OpenRegular(nullLink, Limits{MaxBytes: 64}, AllowDevNull(), FollowSymlinks())
		if err != nil {
			t.Fatalf("OpenRegular(symlink->/dev/null, AllowDevNull, FollowSymlinks) failed: %v", err)
		}
		defer func() { _ = rf.Close() }()
		if !rf.IsDevNull() {
			t.Fatal("expected IsDevNull() == true")
		}
	})

	t.Run("unix_socket_rejected", func(t *testing.T) {
		dir := shortSocketTempDir(t)
		sockPath := filepath.Join(dir, "s.sock")
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ln.Close() }()

		if _, err := OpenRegular(sockPath, Limits{MaxBytes: 64}); !errors.Is(err, ErrNonRegular) {
			t.Fatalf("OpenRegular(unix socket) = %v, want ErrNonRegular", err)
		}
	})
}

func TestOpenRegularAndCreateExclusive_UnixDescriptorFlags(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "flags.txt")
	f, err := CreateExclusive(p, OwnerOnlyPerm)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	fdFlags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD failed: %v", err)
	}
	if fdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("CreateExclusive fd missing FD_CLOEXEC (flags=%#x)", fdFlags)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != OwnerOnlyPerm {
		t.Fatalf("CreateExclusive perm = %04o, want %04o", st.Mode().Perm(), OwnerOnlyPerm)
	}

	rf, err := OpenRegular(p, Limits{MaxBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rf.Close() }()
	flFlags, err := unix.FcntlInt(rf.file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatalf("F_GETFL failed: %v", err)
	}
	if flFlags&unix.O_NONBLOCK != 0 {
		t.Fatalf("OpenRegular failed to clear O_NONBLOCK (flags=%#x)", flFlags)
	}
	rfdFlags, err := unix.FcntlInt(rf.file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD failed: %v", err)
	}
	if rfdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("OpenRegular fd missing FD_CLOEXEC (flags=%#x)", rfdFlags)
	}

	af, err := OpenAppendRegular(p, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("OpenAppendRegular failed: %v", err)
	}
	defer func() { _ = af.Close() }()
	aflFlags, err := unix.FcntlInt(af.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatalf("OpenAppendRegular F_GETFL failed: %v", err)
	}
	if aflFlags&unix.O_NONBLOCK != 0 {
		t.Fatalf("OpenAppendRegular failed to clear O_NONBLOCK (flags=%#x)", aflFlags)
	}
	if aflFlags&unix.O_APPEND == 0 {
		t.Fatalf("OpenAppendRegular missing O_APPEND (flags=%#x)", aflFlags)
	}
	afdFlags, err := unix.FcntlInt(af.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("OpenAppendRegular F_GETFD failed: %v", err)
	}
	if afdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("OpenAppendRegular missing FD_CLOEXEC (flags=%#x)", afdFlags)
	}
}

func TestSocketSlot_UnixPermissionsAndDirectBindFallback(t *testing.T) {
	dir := shortSocketTempDir(t)
	sockPath := filepath.Join(dir, "ctrl.sock")
	slot, err := BindSocketSlot(sockPath, nil)
	if err != nil {
		t.Fatalf("BindSocketSlot failed: %v", err)
	}
	defer func() { _ = slot.Release() }()

	fi, err := os.Lstat(sockPath)
	if err != nil {
		t.Fatalf("Lstat(%q) failed: %v", sockPath, err)
	}
	if fi.Mode().Perm() != OwnerOnlyPerm {
		t.Fatalf("socket perm = %04o, want %04o", fi.Mode().Perm(), OwnerOnlyPerm)
	}

	// Ensure no leftover .mXXXX.t temp files remain in the socket directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "ctrl.sock" {
		t.Fatalf("unexpected entries in socket dir: %d", len(entries))
	}

	// Direct-bind fallback when sun_path budget cannot hold an 8-byte temp suffix.
	maxLen := maxUnixSocketPathLen()
	deepDir := dir
	for len(deepDir)+2 < maxLen-4 {
		next := filepath.Join(deepDir, "abcdefgh")
		if len(next)+3 > maxLen {
			break
		}
		deepDir = next
	}
	if err := os.MkdirAll(deepDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Make directory path long enough that dirBudget < 8 as well.
	padLen := maxLen - len(deepDir) - 1 - 3 // leaves 3 chars for filename ("a.s")
	if padLen > 0 {
		padDir := filepath.Join(deepDir, string(makePadding('d', padLen-1)))
		if len(padDir)+4 <= maxLen {
			if err := os.MkdirAll(padDir, 0o700); err != nil {
				t.Fatal(err)
			}
			deepDir = padDir
		}
	}
	tightPath := filepath.Join(deepDir, "a.s")
	if len(tightPath) <= maxLen {
		tightSlot, err := BindSocketSlot(tightPath, nil)
		if err != nil {
			t.Fatalf("BindSocketSlot(tightPath len=%d/%d) failed: %v", len(tightPath), maxLen, err)
		}
		if err := tightSlot.Release(); err != nil {
			t.Fatalf("Release(tightSlot) failed: %v", err)
		}
		if _, statErr := os.Lstat(tightPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("tightPath still exists after Release: %v", statErr)
		}
	}
}

func makePadding(ch byte, n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = ch
	}
	return b
}
