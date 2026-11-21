package fsx

import (
	"errors"
	"fmt"
	"os"
	"sync"
)

// LockMode specifies the advisory lock mode and access rights for OpenLocked.
//
// Zero value fails closed: callers must pass LockShared or LockExclusive.
type LockMode uint8

const (
	lockModeInvalid LockMode = iota
	// LockShared acquires a shared (read) advisory lock on a read-only handle.
	LockShared
	// LockExclusive acquires an exclusive (read-write) advisory lock on a read-write handle.
	LockExclusive
)

// String returns a human-readable lock mode name.
func (m LockMode) String() string {
	switch m {
	case LockShared:
		return "shared"
	case LockExclusive:
		return "exclusive"
	default:
		return "invalid"
	}
}

// CreateExclusive atomically creates a new regular file at path without
// following symlinks or reparse points, failing with an error matching
// os.ErrExist if any entry already exists at path.
//
// On Unix, the file is created with O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC
// and perm.Perm().
// On Windows, the file is created with CREATE_NEW and a protected owner-only
// SECURITY_DESCRIPTOR (via winsec.NewOwnerOnlySecurityDescriptor) supplied
// directly to CreateFile so there is no post-create ACL hardening window.
//
// Ownership: the caller owns the returned *os.File and must call Close.
func CreateExclusive(path string, perm os.FileMode) (*os.File, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}
	return createExclusiveOS(path, perm)
}

// LockedFile represents an owned, open regular-file handle protected by an OS
// advisory lock (flock on Unix, LockFileEx on Windows) that has been verified
// against os.SameFile(fstat, lstat(path)) while holding the lock.
//
// All I/O must occur through LockedFile's methods so callers never bypass the
// locked handle.
//
// Ownership: the caller owns *LockedFile and must call Close when done. Close
// is idempotent and releases both the OS advisory lock and the underlying file
// handle.
type LockedFile struct {
	mu      sync.RWMutex
	file    *os.File
	path    string
	mode    LockMode
	created bool
	closed  bool
}

// lockedPostAcquireHook is a package-private test hook invoked immediately
// after acquiring the OS lock and before SameFile verification. Nil in
// production.
var lockedPostAcquireHook func(path string, attempt int)

// OpenLocked opens path without following symlinks/reparse points, validates
// that the opened handle is a regular disk file, acquires the requested OS
// advisory lock (LockShared or LockExclusive), and verifies
// os.SameFile(fstat, lstat(path)) while holding the lock.
//
// If the path was replaced concurrently before the lock was acquired (SameFile
// mismatch or unlinked while waiting), OpenLocked unlocks, closes the stale
// handle, and retries up to DefaultLockRetries times before returning
// ErrRetryExhausted.
//
// When create is true and path does not exist, the file is created atomically
// via CreateExclusive(path, perm) (owner-only SD on Windows at creation time).
//
// Ownership: on success the caller owns *LockedFile and must call Close.
func OpenLocked(path string, mode LockMode, create bool, perm os.FileMode) (*LockedFile, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}
	if mode != LockShared && mode != LockExclusive {
		return nil, fmt.Errorf("%w: %d", ErrInvalidLockMode, mode)
	}
	return openLockedWithRetries(path, mode, create, perm, DefaultLockRetries)
}

func openLockedWithRetries(path string, mode LockMode, create bool, perm os.FileMode, maxRetries int) (*LockedFile, error) {
	if maxRetries <= 0 {
		maxRetries = DefaultLockRetries
	}
	for attempt := 0; attempt < maxRetries; attempt++ {
		f, created, retry, err := openForLockAttempt(path, mode, create, perm)
		if err != nil {
			return nil, err
		}
		if retry {
			continue
		}

		if lockErr := lockFileOS(f, mode == LockExclusive); lockErr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("fsx: lock %q (%s): %w", path, mode, lockErr)
		}

		if hook := lockedPostAcquireHook; hook != nil {
			hook(path, attempt)
		}

		matched, verifyErr := verifyLockedFileIdentity(f, path)
		if verifyErr != nil {
			_ = unlockFileOS(f)
			_ = f.Close()
			return nil, verifyErr
		}
		if matched {
			return &LockedFile{
				file:    f,
				path:    path,
				mode:    mode,
				created: created,
			}, nil
		}

		// Path was unlinked or replaced with a different inode while acquiring
		// the lock: release lock, close stale handle, and retry.
		_ = unlockFileOS(f)
		_ = f.Close()
	}
	return nil, fmt.Errorf("%w: %q replaced across %d attempts", ErrRetryExhausted, path, maxRetries)
}

func openForLockAttempt(path string, mode LockMode, create bool, perm os.FileMode) (*os.File, bool, bool, error) {
	f, err := openExistingRegularForLockOS(path, mode == LockExclusive)
	if err == nil {
		return f, false, false, nil
	}
	if !create || !errors.Is(err, os.ErrNotExist) {
		return nil, false, false, err
	}

	cf, createErr := createExclusiveOS(path, perm)
	if createErr != nil {
		if errors.Is(createErr, os.ErrExist) {
			// Another writer created path concurrently; retry opening it.
			return nil, false, true, nil
		}
		return nil, false, false, createErr
	}
	if mode == LockExclusive {
		return cf, true, false, nil
	}

	// LockShared requires a read-only handle: close the newly created handle
	// and immediately reopen read-only (with no-follow).
	_ = cf.Close()
	ro, roErr := openExistingRegularForLockOS(path, false)
	if roErr != nil {
		if errors.Is(roErr, os.ErrNotExist) {
			return nil, false, true, nil
		}
		return nil, false, false, roErr
	}
	return ro, true, false, nil
}

func verifyLockedFileIdentity(f *os.File, path string) (bool, error) {
	fInfo, fErr := f.Stat()
	if fErr != nil {
		return false, fmt.Errorf("fsx: fstat locked %q: %w", path, fErr)
	}
	if !fInfo.Mode().IsRegular() {
		return false, fmt.Errorf("%w: %q", ErrNonRegular, path)
	}
	pInfo, pErr := os.Lstat(path)
	if pErr != nil {
		if errors.Is(pErr, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("fsx: lstat %q: %w", path, pErr)
	}
	if pInfo.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%w: %q replaced with symlink", ErrSymlink, path)
	}
	if !pInfo.Mode().IsRegular() {
		return false, fmt.Errorf("%w: %q replaced with non-regular entry", ErrNonRegular, path)
	}
	if !os.SameFile(fInfo, pInfo) {
		return false, nil
	}
	return true, nil
}

// Close unlocks the advisory file lock and closes the underlying file handle.
// Close is idempotent; subsequent calls return nil.
func (l *LockedFile) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	f := l.file
	l.file = nil
	if f == nil {
		return nil
	}
	unlockErr := unlockFileOS(f)
	closeErr := f.Close()
	if errors.Is(closeErr, os.ErrClosed) {
		closeErr = nil
	}
	return errors.Join(unlockErr, closeErr)
}

// Read reads from the locked file handle.
func (l *LockedFile) Read(p []byte) (int, error) {
	if l == nil {
		return 0, os.ErrInvalid
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed || l.file == nil {
		return 0, os.ErrClosed
	}
	return l.file.Read(p)
}

// ReadAt reads len(p) bytes from the locked file handle starting at offset off.
func (l *LockedFile) ReadAt(p []byte, off int64) (int, error) {
	if l == nil {
		return 0, os.ErrInvalid
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed || l.file == nil {
		return 0, os.ErrClosed
	}
	return l.file.ReadAt(p, off)
}

// Write writes len(p) bytes to the locked file handle (requires LockExclusive).
func (l *LockedFile) Write(p []byte) (int, error) {
	if l == nil {
		return 0, os.ErrInvalid
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed || l.file == nil {
		return 0, os.ErrClosed
	}
	if l.mode != LockExclusive {
		return 0, os.ErrPermission
	}
	return l.file.Write(p)
}

// WriteAt writes len(p) bytes to the locked file handle at offset off (requires LockExclusive).
func (l *LockedFile) WriteAt(p []byte, off int64) (int, error) {
	if l == nil {
		return 0, os.ErrInvalid
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed || l.file == nil {
		return 0, os.ErrClosed
	}
	if l.mode != LockExclusive {
		return 0, os.ErrPermission
	}
	return l.file.WriteAt(p, off)
}

// Seek sets the offset for the next Read or Write on the locked file handle.
func (l *LockedFile) Seek(offset int64, whence int) (int64, error) {
	if l == nil {
		return 0, os.ErrInvalid
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed || l.file == nil {
		return 0, os.ErrClosed
	}
	return l.file.Seek(offset, whence)
}

// Stat returns file metadata from the locked file handle.
func (l *LockedFile) Stat() (os.FileInfo, error) {
	if l == nil {
		return nil, os.ErrInvalid
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed || l.file == nil {
		return nil, os.ErrClosed
	}
	return l.file.Stat()
}

// Truncate changes the size of the locked file handle (requires LockExclusive).
func (l *LockedFile) Truncate(size int64) error {
	if l == nil {
		return os.ErrInvalid
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed || l.file == nil {
		return os.ErrClosed
	}
	if l.mode != LockExclusive {
		return os.ErrPermission
	}
	return l.file.Truncate(size)
}

// Sync commits the current contents of the locked file handle to stable storage.
func (l *LockedFile) Sync() error {
	if l == nil {
		return os.ErrInvalid
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed || l.file == nil {
		return os.ErrClosed
	}
	return l.file.Sync()
}

// Path returns the path passed to OpenLocked.
func (l *LockedFile) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Mode returns the LockMode held by l.
func (l *LockedFile) Mode() LockMode {
	if l == nil {
		return lockModeInvalid
	}
	return l.mode
}

// Created reports whether OpenLocked created the file on disk.
func (l *LockedFile) Created() bool {
	return l != nil && l.created
}
