//go:build windows

package fsx

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/winsec"
	"golang.org/x/sys/windows"
)

func TestCreateExclusive_WindowsOwnerOnlySDAtCreation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")

	f, err := CreateExclusive(path, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("CreateExclusive failed: %v", err)
	}
	defer func() { _ = f.Close() }()

	sd, err := winsec.GetSecurityInfoByHandle(windows.Handle(f.Fd()))
	if err != nil {
		t.Fatalf("GetSecurityInfoByHandle failed: %v", err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatalf("sd.Control failed: %v", err)
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("expected SE_DACL_PROTECTED on CreateExclusive file, got control=%#x", ctrl)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("sd.DACL failed: %v", err)
	}
	if dacl.AceCount != 2 {
		t.Fatalf("expected 2 owner-only ACEs (CurrentUser + SYSTEM), got %d", dacl.AceCount)
	}
}

func TestSocketSlot_WindowsRealDirLockAndHandleACL(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "mux")
	if err := winsec.EnsureOwnerOnlyDirectory(dir); err != nil {
		t.Fatalf("EnsureOwnerOnlyDirectory failed: %v", err)
	}

	// Verify withDirLockOS actually serializes concurrent lockers (not a no-op).
	entered := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- withDirLockOS(dir, func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	secondAcquired := make(chan error, 1)
	go func() {
		secondAcquired <- withDirLockOS(dir, func() error { return nil })
	}()

	select {
	case err := <-secondAcquired:
		close(release)
		<-holderDone
		t.Fatalf("second Windows dir lock acquired while first was still held (err=%v)", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	if err := <-holderDone; err != nil {
		t.Fatalf("first dir lock failed: %v", err)
	}
	select {
	case err := <-secondAcquired:
		if err != nil {
			t.Fatalf("second dir lock failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("second Windows dir lock did not unblock after first released")
	}

	// Verify SocketSlot bind, handle-based socket ACL verification, dial, and Release.
	sockPath := filepath.Join(dir, "ctrl.sock")
	slot, err := BindSocketSlot(sockPath, nil)
	if err != nil {
		t.Fatalf("BindSocketSlot failed: %v", err)
	}
	if err := winsec.VerifyOwnerOnlySocketByHandle(sockPath); err != nil {
		_ = slot.Release()
		t.Fatalf("VerifyOwnerOnlySocketByHandle failed: %v", err)
	}

	acceptDone := make(chan struct{})
	go func(ln net.Listener) {
		defer close(acceptDone)
		if c, aErr := ln.Accept(); aErr == nil {
			_ = c.Close()
		}
	}(slot.Listener())

	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	if err != nil {
		_ = slot.Release()
		<-acceptDone
		t.Fatalf("dial Windows AF_UNIX socket failed: %v", err)
	}
	_ = conn.Close()
	if err := slot.Release(); err != nil {
		<-acceptDone
		t.Fatalf("Release failed: %v", err)
	}
	<-acceptDone

	if _, err := os.Lstat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket still exists after Release: %v", err)
	}
}

func TestWindowsOpenAppendRegular_OwnerOnlySDAndDevNullSentinel(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")

	f, err := OpenAppendRegular(auditPath, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("OpenAppendRegular failed: %v", err)
	}
	defer func() { _ = f.Close() }()

	sd, err := winsec.GetSecurityInfoByHandle(windows.Handle(f.Fd()))
	if err != nil {
		t.Fatalf("GetSecurityInfoByHandle failed: %v", err)
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		t.Fatalf("sd.Control failed: %v", err)
	}
	if ctrl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("expected SE_DACL_PROTECTED on OpenAppendRegular(0600), got control=%#x", ctrl)
	}

	// OpenRegular with AllowDevNull recognizes "/dev/null", "NUL", and "\\\\.\\NUL" on Windows.
	for _, p := range []string{"/dev/null", "NUL", "nul", `\\.\NUL`, `\\.\nul`} {
		rf, openErr := OpenRegular(p, Limits{MaxBytes: 64}, AllowDevNull())
		if openErr != nil {
			t.Fatalf("OpenRegular(%q, AllowDevNull()) failed: %v", p, openErr)
		}
		if !rf.IsDevNull() {
			_ = rf.Close()
			t.Fatalf("OpenRegular(%q, AllowDevNull()).IsDevNull() = false, want true", p)
		}
		_ = rf.Close()
	}
}

func TestWindowsDirLock_PostLockSameFileRetryAndExhaustion(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "mux-retry")
	if err := winsec.EnsureOwnerOnlyDirectory(dir); err != nil {
		t.Fatalf("EnsureOwnerOnlyDirectory failed: %v", err)
	}

	// 1. Single concurrent replacement triggers bounded retry and succeeds on attempt 2.
	attempts := 0
	prevHook := windowsDirLockPostAcquireHook
	windowsDirLockPostAcquireHook = func(lockPath string, attempt int) {
		attempts++
		if attempt == 0 {
			tmp := filepath.Join(dir, "lock-swap.tmp")
			_ = os.WriteFile(tmp, []byte("new"), 0o600)
			_ = replaceFileOS(tmp, lockPath)
		}
	}
	t.Cleanup(func() { windowsDirLockPostAcquireHook = prevHook })

	if err := withDirLockOS(dir, func() error { return nil }); err != nil {
		t.Fatalf("withDirLockOS after single replacement failed: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("observed %d attempts, want 2", attempts)
	}

	// 2. Continuous replacement across all attempts returns ErrRetryExhausted.
	attempts = 0
	windowsDirLockPostAcquireHook = func(lockPath string, _ int) {
		attempts++
		tmp := filepath.Join(dir, "lock-churn.tmp")
		_ = os.WriteFile(tmp, []byte("churn"), 0o600)
		_ = replaceFileOS(tmp, lockPath)
	}
	if err := withDirLockOS(dir, func() error { return nil }); !errors.Is(err, ErrRetryExhausted) {
		t.Fatalf("withDirLockOS under continuous replacement = %v, want ErrRetryExhausted", err)
	}
	if attempts != DefaultLockRetries {
		t.Fatalf("observed %d attempts, want %d", attempts, DefaultLockRetries)
	}
}

func TestWindowsSyncDir_HardenedFlagsAndTypeValidation(t *testing.T) {
	wantRequired := uint32(
		windows.FILE_FLAG_BACKUP_SEMANTICS |
			windows.SECURITY_SQOS_PRESENT |
			windows.SECURITY_ANONYMOUS,
	)
	if windowsSyncDirFlags&wantRequired != wantRequired {
		t.Fatalf("windowsSyncDirFlags = %#x, missing required backup/anonymous SQOS flags %#x", windowsSyncDirFlags, wantRequired)
	}
	if windowsSyncDirFlags&windows.FILE_FLAG_OPEN_REPARSE_POINT != 0 {
		t.Fatalf("windowsSyncDirFlags = %#x must omit FILE_FLAG_OPEN_REPARSE_POINT so SyncDir works on valid directory symlinks/mount points", windowsSyncDirFlags)
	}

	dir := t.TempDir()
	if err := SyncDir(dir); err != nil {
		t.Fatalf("SyncDir(%q): %v", dir, err)
	}

	regularFile := filepath.Join(dir, "not-a-dir.txt")
	if err := os.WriteFile(regularFile, []byte("hello"), OwnerOnlyPerm); err != nil {
		t.Fatalf("WriteFile(%q): %v", regularFile, err)
	}
	if err := SyncDir(regularFile); !errors.Is(err, ErrNonRegular) {
		t.Fatalf("SyncDir(regular file) = %v, want ErrNonRegular", err)
	}

	for _, dev := range []string{"NUL", `\\.\NUL`} {
		if err := SyncDir(dev); !errors.Is(err, ErrNonRegular) {
			t.Fatalf("SyncDir(%q) = %v, want ErrNonRegular", dev, err)
		}
	}
}
