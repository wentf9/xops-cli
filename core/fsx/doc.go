// Package fsx provides handle-based filesystem security primitives for XOps.
//
// All file and socket lifecycle operations in this package operate on open OS
// handles rather than path-based Stat-then-Open or Lstat-then-Remove sequences:
//
//   - OpenRegular / ReadAllBounded open regular files without blocking on FIFOs
//     or following symlinks/reparse points, verify file type and size limits on
//     the open handle, and enforce MaxBytes across reads.
//   - CreateExclusive creates a brand new file without following symlinks and,
//     on Windows, applies a protected owner-only SECURITY_DESCRIPTOR atomically
//     at creation time.
//   - OpenLocked / TryOpenLocked / OpenLockedContext acquire a shared or
//     exclusive OS advisory lock on an open no-follow regular file handle and
//     verify os.SameFile(fstat, lstat(path)) under the lock, retrying up to
//     DefaultLockRetries times on concurrent replacement. TryLockFile locks an
//     already-pinned handle (for example from os.Root or dirfd openat).
//   - AtomicReplace writes via an exclusive no-follow temporary file in the
//     destination directory (with owner-only SD on Windows for 0o077-masked
//     modes), syncs the file, atomically replaces the destination, and syncs
//     the parent directory (via SyncDir) unless WithoutDirSync is passed.
//   - SocketSlot is the sole owner of a control socket path, serializing bind,
//     stale replacement, and release under a real directory lock on both Unix
//     and Windows. Release strictly unlinks (after SameFile verification under
//     the directory lock) BEFORE closing the listener.
//   - ValidateLocalComponent is the single cross-platform authority for
//     validating local single-segment filename components.
//
// Resource ownership:
//   - *RegularFile owns its underlying OS file handle; callers must invoke
//     Close (idempotent).
//   - CreateExclusive returns an owned *os.File; callers must invoke Close.
//   - *LockedFile owns its underlying OS file handle and OS advisory lock;
//     callers must invoke Close (idempotent), which unlocks and closes the handle.
//   - *SocketSlot owns its bound net.Listener and socket directory entry;
//     callers must invoke Release (idempotent). Do not call Close directly on
//     slot.Listener() prior to Release, or the unlink-before-close invariant is
//     violated.
package fsx

import (
	"errors"
	"os"
)

const (
	// OwnerOnlyPerm is the standard POSIX permission mode for owner-only files.
	OwnerOnlyPerm os.FileMode = 0o600

	// DefaultLockRetries is the bounded retry budget for OpenLocked when the
	// target path is concurrently replaced before the advisory lock is acquired.
	DefaultLockRetries = 8
)

var (
	// ErrEmptyPath indicates an empty or whitespace-only filesystem path.
	ErrEmptyPath = errors.New("fsx: path is empty")

	// ErrInvalidLimit indicates Limits.MaxBytes is <= 0 (zero value fails closed).
	ErrInvalidLimit = errors.New("fsx: invalid size limit")

	// ErrInvalidLockMode indicates an unrecognized or zero-value LockMode.
	ErrInvalidLockMode = errors.New("fsx: invalid lock mode")

	// ErrSymlink indicates a trailing symlink or Windows reparse point was rejected.
	ErrSymlink = errors.New("fsx: refusing symlink or reparse point")

	// ErrNonRegular indicates the opened handle is not a regular disk file
	// (for example a FIFO, directory, socket, pipe, or character/block device).
	ErrNonRegular = errors.New("fsx: refusing non-regular file")

	// ErrTooLarge indicates the file exceeds Limits.MaxBytes either at open time
	// or while streaming reads.
	ErrTooLarge = errors.New("fsx: file exceeds maximum size limit")

	// ErrRetryExhausted indicates OpenLocked observed concurrent path replacement
	// across all bounded retry attempts.
	ErrRetryExhausted = errors.New("fsx: file lock retry budget exhausted due to concurrent replacement")

	// ErrWouldBlock indicates a non-blocking lock attempt (TryOpenLocked or
	// TryLockFile) encountered a conflicting lock held by another caller.
	ErrWouldBlock = errors.New("fsx: file lock is held by another caller")

	// ErrSlotOccupied indicates a control socket path is already occupied by a
	// live or unverified entry.
	ErrSlotOccupied = errors.New("fsx: socket slot already occupied")

	// ErrSlotClosed indicates an operation was attempted on a released SocketSlot.
	ErrSlotClosed = errors.New("fsx: socket slot already released")

	// ErrInvalidProbe indicates ReplaceStaleSocketSlot or PruneStaleSocket was
	// called with a nil stale-probe callback.
	ErrInvalidProbe = errors.New("fsx: stale socket probe callback is nil")

	// ErrInvalidComponent indicates a filename component violates cross-platform
	// local path safety rules.
	ErrInvalidComponent = errors.New("fsx: invalid local filename component")

	// ErrUnsupported indicates the operation is not safely supported on the
	// current operating system.
	ErrUnsupported = errors.New("fsx: operation unsupported on this platform")
)
