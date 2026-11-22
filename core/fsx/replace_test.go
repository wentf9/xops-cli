package fsx

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestTryOpenLocked_ContendedAndShared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.lock")

	ex, err := TryOpenLocked(path, LockExclusive, true, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("TryOpenLocked(exclusive): %v", err)
	}
	if !ex.Created() {
		t.Fatalf("expected Created()=true on first open")
	}

	// Second exclusive attempt must fail immediately with ErrWouldBlock.
	if _, err := TryOpenLocked(path, LockExclusive, true, OwnerOnlyPerm); !errors.Is(err, ErrWouldBlock) {
		t.Fatalf("contended TryOpenLocked(exclusive) = %v, want ErrWouldBlock", err)
	}
	// Shared attempt while exclusive held must also fail with ErrWouldBlock.
	if _, err := TryOpenLocked(path, LockShared, false, OwnerOnlyPerm); !errors.Is(err, ErrWouldBlock) {
		t.Fatalf("contended TryOpenLocked(shared) = %v, want ErrWouldBlock", err)
	}

	if err := ex.Close(); err != nil {
		t.Fatalf("ex.Close: %v", err)
	}

	// Multiple shared locks may coexist, while exclusive fails with ErrWouldBlock.
	sh1, err := TryOpenLocked(path, LockShared, false, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("TryOpenLocked(shared 1): %v", err)
	}
	defer func() { _ = sh1.Close() }()

	sh2, err := TryOpenLocked(path, LockShared, false, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("TryOpenLocked(shared 2): %v", err)
	}
	defer func() { _ = sh2.Close() }()

	if _, err := TryOpenLocked(path, LockExclusive, false, OwnerOnlyPerm); !errors.Is(err, ErrWouldBlock) {
		t.Fatalf("TryOpenLocked(exclusive) while shared held = %v, want ErrWouldBlock", err)
	}
}

func TestOpenLockedContext_CancelAndAcquireOnRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctx.lock")

	// Nil context, empty path, invalid mode fail closed.
	var nilCtx context.Context
	if _, err := OpenLockedContext(nilCtx, path, LockExclusive, true, OwnerOnlyPerm); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("nil ctx = %v, want os.ErrInvalid", err)
	}
	if _, err := OpenLockedContext(t.Context(), "", LockExclusive, true, OwnerOnlyPerm); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("empty path = %v, want ErrEmptyPath", err)
	}
	if _, err := OpenLockedContext(t.Context(), path, LockMode(0), true, OwnerOnlyPerm); !errors.Is(err, ErrInvalidLockMode) {
		t.Fatalf("zero LockMode = %v, want ErrInvalidLockMode", err)
	}

	holder, err := TryOpenLocked(path, LockExclusive, true, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("holder TryOpenLocked: %v", err)
	}
	defer func() { _ = holder.Close() }()

	// Contended acquisition must honor deadline promptly.
	waitCtx, cancel := context.WithTimeout(t.Context(), 45*time.Millisecond)
	defer cancel()
	if _, err := OpenLockedContext(waitCtx, path, LockExclusive, true, OwnerOnlyPerm); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended OpenLockedContext = %v, want DeadlineExceeded", err)
	}

	// Releasing holder allows waiter to succeed promptly.
	acqCtx, acqCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer acqCancel()
	go func() {
		time.Sleep(35 * time.Millisecond)
		_ = holder.Close()
	}()
	acquired, err := OpenLockedContext(acqCtx, path, LockExclusive, true, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("OpenLockedContext after release: %v", err)
	}
	if err := acquired.Close(); err != nil {
		t.Fatalf("acquired.Close: %v", err)
	}
}

func TestTryLockFile_PinnedHandle(t *testing.T) {
	if err := TryLockFile(nil, LockExclusive); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("TryLockFile(nil) = %v, want os.ErrInvalid", err)
	}

	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("os.OpenRoot: %v", err)
	}
	defer func() { _ = root.Close() }()

	f1, err := root.OpenFile("service.lock", os.O_CREATE|os.O_RDWR, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("root.OpenFile 1: %v", err)
	}
	defer func() { _ = f1.Close() }()

	if err := TryLockFile(f1, LockMode(0)); !errors.Is(err, ErrInvalidLockMode) {
		t.Fatalf("TryLockFile(invalid mode) = %v, want ErrInvalidLockMode", err)
	}
	if err := TryLockFile(f1, LockExclusive); err != nil {
		t.Fatalf("TryLockFile(f1): %v", err)
	}

	f2, err := root.OpenFile("service.lock", os.O_RDWR, OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("root.OpenFile 2: %v", err)
	}
	defer func() { _ = f2.Close() }()

	if err := TryLockFile(f2, LockExclusive); !errors.Is(err, ErrWouldBlock) {
		t.Fatalf("contended TryLockFile(f2) = %v, want ErrWouldBlock", err)
	}

	_ = f1.Close()
	if err := TryLockFile(f2, LockExclusive); err != nil {
		t.Fatalf("TryLockFile(f2) after f1 close: %v", err)
	}
}

func TestAtomicReplace_CreateReplaceAndOptions(t *testing.T) {
	if _, err := AtomicReplace("", []byte("x"), OwnerOnlyPerm); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("empty path = %v, want ErrEmptyPath", err)
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "config.yaml")

	res, err := AtomicReplace(target, []byte("v1\n"), OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("AtomicReplace create: %v", err)
	}
	if !res.Applied || !res.Durable {
		t.Fatalf("create result = %+v, want Applied=true Durable=true", res)
	}
	got, err := ReadAllBounded(target, Limits{MaxBytes: 1024})
	if err != nil || !bytes.Equal(got, []byte("v1\n")) {
		t.Fatalf("read v1 = (%q, %v)", got, err)
	}
	if runtime.GOOS != "windows" {
		fi, statErr := os.Stat(target)
		if statErr != nil || fi.Mode().Perm() != OwnerOnlyPerm {
			t.Fatalf("mode = %v (err=%v), want %v", fi.Mode().Perm(), statErr, OwnerOnlyPerm)
		}
	}

	res2, err := AtomicReplace(target, []byte("v2-updated\n"), 0o644, WithoutDirSync())
	if err != nil {
		t.Fatalf("AtomicReplace overwrite: %v", err)
	}
	if !res2.Applied || res2.Durable {
		t.Fatalf("WithoutDirSync result = %+v, want Applied=true Durable=false", res2)
	}
	got2, err := ReadAllBounded(target, Limits{MaxBytes: 1024})
	if err != nil || !bytes.Equal(got2, []byte("v2-updated\n")) {
		t.Fatalf("read v2 = (%q, %v)", got2, err)
	}

	// Ensure no leftover temp files remain in dir.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "config.yaml" {
		t.Fatalf("unexpected entries after AtomicReplace: %v", entries)
	}
}

func TestAtomicReplace_ErrorCleanupRespectsSameFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	sentinel := errors.New("injected write hook error")

	// Case 1: normal error path removes our own temp file cleanly.
	var createdTemp string
	replaceTempWriteHook = func(tempPath string) error {
		createdTemp = tempPath
		return sentinel
	}
	t.Cleanup(func() {
		replaceTempWriteHook = nil
		replaceBeforeCleanupHook = nil
	})

	res, err := AtomicReplace(target, []byte("payload"), OwnerOnlyPerm)
	if !errors.Is(err, sentinel) || res.Applied || res.Durable {
		t.Fatalf("injected failure = (%+v, %v), want sentinel & Applied=false", res, err)
	}
	if createdTemp == "" {
		t.Fatal("temp path not observed")
	}
	if _, statErr := os.Lstat(createdTemp); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("own temp file %q was not cleaned up: %v", createdTemp, statErr)
	}

	// Case 2: if tempPath is replaced by a different inode before cleanup,
	// SameFile mismatch prevents deleting the foreign file.
	var swappedPath string
	replaceBeforeCleanupHook = func(tempPath string) {
		swappedPath = tempPath
		other := filepath.Join(dir, "foreign.txt")
		if wErr := os.WriteFile(other, []byte("keep-me"), 0o600); wErr != nil {
			t.Errorf("write foreign file: %v", wErr)
			return
		}
		if rErr := os.Rename(other, tempPath); rErr != nil {
			t.Errorf("swap temp path: %v", rErr)
		}
	}

	res2, err2 := AtomicReplace(target, []byte("payload2"), OwnerOnlyPerm)
	if !errors.Is(err2, sentinel) || res2.Applied {
		t.Fatalf("swapped cleanup = (%+v, %v), want sentinel", res2, err2)
	}
	kept, readErr := ReadAllBounded(swappedPath, Limits{MaxBytes: 1024})
	if readErr != nil || string(kept) != "keep-me" {
		t.Fatalf("foreign file at swapped temp path was unlinked or modified: (%q, %v)", kept, readErr)
	}
}

func TestSyncDir(t *testing.T) {
	if err := SyncDir(""); !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("SyncDir(empty) = %v, want ErrEmptyPath", err)
	}
	dir := t.TempDir()
	if err := SyncDir(dir); err != nil {
		t.Fatalf("SyncDir(%q): %v", dir, err)
	}
	if err := SyncDir(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Fatal("SyncDir on missing directory succeeded")
	}

	regularFile := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(regularFile, []byte("data"), OwnerOnlyPerm); err != nil {
		t.Fatalf("WriteFile(%q): %v", regularFile, err)
	}
	if err := SyncDir(regularFile); err == nil {
		t.Fatal("SyncDir on regular file succeeded, want error")
	}

	// SyncDir and AtomicReplace must continue working when the parent directory
	// itself is accessed through a valid directory symlink (e.g. macOS /var ->
	// /private/var or a symlinked config/temp directory).
	realSub := filepath.Join(dir, "real-dir")
	if err := os.MkdirAll(realSub, 0o700); err != nil {
		t.Fatalf("MkdirAll(%q): %v", realSub, err)
	}
	linkDir := filepath.Join(dir, "link-dir")
	if err := os.Symlink(realSub, linkDir); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on Windows: %v", err)
		}
		t.Fatalf("Symlink(%q -> %q): %v", linkDir, realSub, err)
	}
	if err := SyncDir(linkDir); err != nil {
		t.Fatalf("SyncDir on directory symlink %q failed: %v", linkDir, err)
	}
	target := filepath.Join(linkDir, "config.yaml")
	res, err := AtomicReplace(target, []byte("synced\n"), OwnerOnlyPerm)
	if err != nil {
		t.Fatalf("AtomicReplace inside symlinked directory failed: %v", err)
	}
	if !res.Applied || !res.Durable {
		t.Fatalf("AtomicReplace inside symlinked directory = %+v, want Applied=true Durable=true", res)
	}
}
