//go:build windows

package fsx

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/wentf9/xops-cli/core/winsec"
	"golang.org/x/sys/windows"
)

const (
	// windowsUnixPathMax mirrors Windows SDK <afunix.h> UNIX_PATH_MAX - 1.
	windowsUnixPathMax = 107

	// windowsDirLockFileName is the fixed lock file inside an owner-only socket
	// directory used by LockFileEx to serialize SocketSlot bind, stale replace,
	// and release across goroutines and processes on Windows.
	windowsDirLockFileName = ".xops-socket-slot.lock"
)

func openRegularOS(path string, l Limits, cfg openConfig) (*RegularFile, error) {
	if cfg.allowDevNull && IsDevNullSentinel(path) {
		return newDevNullRegularFile(path, l.MaxBytes, nil), nil
	}

	f, st, size, err := openWindowsRegularReadHandle(path, cfg)
	if err != nil {
		return nil, err
	}
	if size < 0 || size > l.MaxBytes || st.Size() > l.MaxBytes {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %q (%d > %d bytes)", ErrTooLarge, path, st.Size(), l.MaxBytes)
	}

	return &RegularFile{
		file:     f,
		info:     st,
		path:     path,
		maxBytes: l.MaxBytes,
	}, nil
}

func openRegularUnboundedOS(path string, cfg openConfig) (*os.File, os.FileInfo, error) {
	f, st, _, err := openWindowsRegularReadHandle(path, cfg)
	if err != nil {
		return nil, nil, err
	}
	return f, st, nil
}

func openWindowsRegularReadHandle(path string, cfg openConfig) (*os.File, os.FileInfo, int64, error) {
	safePath := fixLongPathWindows(path)
	pathPtr, err := windows.UTF16PtrFromString(safePath)
	if err != nil {
		return nil, nil, 0, &os.PathError{Op: "open", Path: path, Err: err}
	}

	flags := uint32(
		windows.FILE_FLAG_BACKUP_SEMANTICS |
			windows.SECURITY_SQOS_PRESENT |
			windows.SECURITY_ANONYMOUS,
	)
	if !cfg.followSymlinks {
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	const share = uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)

	handle, err := windows.CreateFile(pathPtr, windows.GENERIC_READ, share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, nil, 0, classifyWindowsOpenError(path, err)
	}

	info, err := validateWindowsRegularHandle(handle, path)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, nil, 0, err
	}
	size := (int64(info.FileSizeHigh) << 32) | int64(info.FileSizeLow)

	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		_ = windows.CloseHandle(handle)
		return nil, nil, 0, fmt.Errorf("fsx: os.NewFile returned nil for %q", path)
	}

	st, statErr := f.Stat()
	if statErr != nil {
		_ = f.Close()
		return nil, nil, 0, statErr
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, 0, fmt.Errorf("%w: %q", ErrNonRegular, path)
	}
	return f, st, size, nil
}

func createExclusiveOS(path string, _ os.FileMode) (*os.File, error) {
	currSID, err := winsec.CurrentProcessUserSID()
	if err != nil {
		return nil, fmt.Errorf("fsx: query current Windows user SID: %w", err)
	}
	sd, err := winsec.NewOwnerOnlySecurityDescriptor(currSID, windows.NO_INHERITANCE)
	if err != nil {
		return nil, fmt.Errorf("fsx: build owner-only security descriptor: %w", err)
	}

	safePath := fixLongPathWindows(path)
	pathPtr, err := windows.UTF16PtrFromString(safePath)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	const share = uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	const flags = uint32(
		windows.FILE_ATTRIBUTE_NORMAL |
			windows.FILE_FLAG_OPEN_REPARSE_POINT |
			windows.SECURITY_SQOS_PRESENT |
			windows.SECURITY_ANONYMOUS,
	)

	handle, createErr := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		share,
		sa,
		windows.CREATE_NEW,
		flags,
		0,
	)
	runtime.KeepAlive(sd)
	runtime.KeepAlive(sa)
	if createErr != nil {
		return nil, classifyWindowsOpenError(path, createErr)
	}

	return wrapValidatedWindowsHandle(handle, path)
}

func createReplaceTempOS(path string, perm os.FileMode) (*os.File, error) {
	if perm.Perm()&0o077 == 0 {
		return createExclusiveOS(path, perm)
	}

	safePath := fixLongPathWindows(path)
	pathPtr, err := windows.UTF16PtrFromString(safePath)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	const share = uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	const flags = uint32(
		windows.FILE_ATTRIBUTE_NORMAL |
			windows.FILE_FLAG_OPEN_REPARSE_POINT |
			windows.SECURITY_SQOS_PRESENT |
			windows.SECURITY_ANONYMOUS,
	)

	handle, createErr := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		share,
		nil,
		windows.CREATE_NEW,
		flags,
		0,
	)
	if createErr != nil {
		return nil, classifyWindowsOpenError(path, createErr)
	}

	return wrapValidatedWindowsHandle(handle, path)
}

func wrapValidatedWindowsHandle(handle windows.Handle, path string) (*os.File, error) {
	if _, valErr := validateWindowsRegularHandle(handle, path); valErr != nil {
		_ = windows.CloseHandle(handle)
		return nil, valErr
	}

	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("fsx: os.NewFile returned nil for %q", path)
	}
	return f, nil
}

func openExistingRegularOS(path string, writable bool) (*os.File, error) {
	return openExistingRegularForLockOS(path, writable)
}

func openExistingRegularForLockOS(path string, exclusive bool) (*os.File, error) {
	safePath := fixLongPathWindows(path)
	pathPtr, err := windows.UTF16PtrFromString(safePath)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	access := uint32(windows.GENERIC_READ)
	if exclusive {
		access |= windows.GENERIC_WRITE
	}
	const share = uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	const flags = uint32(
		windows.FILE_FLAG_BACKUP_SEMANTICS |
			windows.FILE_FLAG_OPEN_REPARSE_POINT |
			windows.SECURITY_SQOS_PRESENT |
			windows.SECURITY_ANONYMOUS,
	)

	handle, err := windows.CreateFile(pathPtr, access, share, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, classifyWindowsOpenError(path, err)
	}

	if _, valErr := validateWindowsRegularHandle(handle, path); valErr != nil {
		_ = windows.CloseHandle(handle)
		return nil, valErr
	}

	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("fsx: os.NewFile returned nil for %q", path)
	}
	return f, nil
}

func openAppendRegularOS(path string, perm os.FileMode) (*os.File, error) {
	safePath := fixLongPathWindows(path)
	pathPtr, err := windows.UTF16PtrFromString(safePath)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	const (
		appendAccess = uint32(
			windows.FILE_APPEND_DATA |
				windows.FILE_READ_ATTRIBUTES |
				windows.FILE_WRITE_ATTRIBUTES |
				windows.FILE_WRITE_EA |
				windows.STANDARD_RIGHTS_WRITE |
				windows.SYNCHRONIZE,
		)
		share         = uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
		existingFlags = uint32(
			windows.FILE_FLAG_BACKUP_SEMANTICS |
				windows.FILE_FLAG_OPEN_REPARSE_POINT |
				windows.SECURITY_SQOS_PRESENT |
				windows.SECURITY_ANONYMOUS,
		)
		createFlags = uint32(
			windows.FILE_ATTRIBUTE_NORMAL |
				windows.FILE_FLAG_OPEN_REPARSE_POINT |
				windows.SECURITY_SQOS_PRESENT |
				windows.SECURITY_ANONYMOUS,
		)
	)

	for attempt := 0; attempt < DefaultLockRetries; attempt++ {
		handle, openErr := windows.CreateFile(pathPtr, appendAccess, share, nil, windows.OPEN_EXISTING, existingFlags, 0)
		if openErr == nil {
			return wrapValidatedWindowsHandle(handle, path)
		}
		if !errors.Is(openErr, windows.ERROR_FILE_NOT_FOUND) && !errors.Is(openErr, os.ErrNotExist) {
			return nil, classifyWindowsOpenError(path, openErr)
		}

		f, createErr := createWindowsExclusiveWithAccess(path, pathPtr, appendAccess, createFlags, perm.Perm()&0o077 == 0)
		if createErr == nil {
			return f, nil
		}
		if !errors.Is(createErr, os.ErrExist) {
			return nil, createErr
		}
	}
	return nil, fmt.Errorf("%w: open append file %q", ErrRetryExhausted, path)
}

func createWindowsExclusiveWithAccess(path string, pathPtr *uint16, access, flags uint32, ownerOnly bool) (*os.File, error) {
	var (
		sd *windows.SECURITY_DESCRIPTOR
		sa *windows.SecurityAttributes
	)
	if ownerOnly {
		currSID, err := winsec.CurrentProcessUserSID()
		if err != nil {
			return nil, fmt.Errorf("fsx: query current Windows user SID: %w", err)
		}
		sd, err = winsec.NewOwnerOnlySecurityDescriptor(currSID, windows.NO_INHERITANCE)
		if err != nil {
			return nil, fmt.Errorf("fsx: build owner-only security descriptor: %w", err)
		}
		sa = &windows.SecurityAttributes{
			Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
			SecurityDescriptor: sd,
		}
	}
	const share = uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	handle, createErr := windows.CreateFile(pathPtr, access, share, sa, windows.CREATE_NEW, flags, 0)
	runtime.KeepAlive(sd)
	runtime.KeepAlive(sa)
	if createErr != nil {
		return nil, classifyWindowsOpenError(path, createErr)
	}
	return wrapValidatedWindowsHandle(handle, path)
}

func validateWindowsRegularHandle(handle windows.Handle, path string) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	fileType, typeErr := windows.GetFileType(handle)
	if typeErr != nil {
		return info, &os.PathError{Op: "getfiletype", Path: path, Err: typeErr}
	}
	if fileType != windows.FILE_TYPE_DISK {
		return info, fmt.Errorf("%w: %q (type=%d)", ErrNonRegular, path, fileType)
	}
	if infoErr := windows.GetFileInformationByHandle(handle, &info); infoErr != nil {
		return info, &os.PathError{Op: "stat", Path: path, Err: infoErr}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return info, fmt.Errorf("%w: %q", ErrSymlink, path)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return info, fmt.Errorf("%w: %q", ErrNonRegular, path)
	}
	return info, nil
}

func classifyWindowsOpenError(path string, err error) error {
	pathErr := &os.PathError{Op: "open", Path: path, Err: err}
	if errors.Is(err, windows.ERROR_PIPE_BUSY) || errors.Is(err, windows.ERROR_CANT_ACCESS_FILE) {
		return fmt.Errorf("%w: %w", ErrNonRegular, pathErr)
	}
	return pathErr
}

func lockFileOS(f *os.File, exclusive bool) error {
	if f == nil {
		return os.ErrInvalid
	}
	var flags uint32
	if exclusive {
		flags = windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	var ol windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, ^uint32(0), ^uint32(0), &ol)
	runtime.KeepAlive(f)
	return err
}

func tryLockFileOS(f *os.File, exclusive bool) error {
	if f == nil {
		return os.ErrInvalid
	}
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	var ol windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, ^uint32(0), ^uint32(0), &ol)
	runtime.KeepAlive(f)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return fmt.Errorf("%w: %w", ErrWouldBlock, err)
	}
	return err
}

func replaceFileOS(source, destination string) error {
	srcPtr, err := windows.UTF16PtrFromString(fixLongPathWindows(source))
	if err != nil {
		return fmt.Errorf("encode temp path %q: %w", source, err)
	}
	dstPtr, err := windows.UTF16PtrFromString(fixLongPathWindows(destination))
	if err != nil {
		return fmt.Errorf("encode destination path %q: %w", destination, err)
	}
	if err := windows.MoveFileEx(srcPtr, dstPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	return nil
}

// windowsSyncDirFlags opens an existing directory handle for FlushFileBuffers
// while blocking named-pipe impersonation (SECURITY_SQOS_PRESENT |
// SECURITY_ANONYMOUS). FILE_FLAG_OPEN_REPARSE_POINT is intentionally omitted so
// SyncDir(filepath.Dir(target)) continues to work when dir itself is a valid
// directory symlink, junction, or volume mount point (matching Unix
// O_RDONLY|O_DIRECTORY without O_NOFOLLOW); validateWindowsDirectoryHandle then
// verifies FILE_TYPE_DISK and FILE_ATTRIBUTE_DIRECTORY on the open handle
// before calling FlushFileBuffers.
const windowsSyncDirFlags = uint32(
	windows.FILE_FLAG_BACKUP_SEMANTICS |
		windows.SECURITY_SQOS_PRESENT |
		windows.SECURITY_ANONYMOUS,
)

func validateWindowsDirectoryHandle(handle windows.Handle, dir string) error {
	fileType, typeErr := windows.GetFileType(handle)
	if typeErr != nil {
		return &os.PathError{Op: "getfiletype", Path: dir, Err: typeErr}
	}
	if fileType != windows.FILE_TYPE_DISK {
		return fmt.Errorf("%w: %q (type=%d)", ErrNonRegular, dir, fileType)
	}
	var info windows.ByHandleFileInformation
	if infoErr := windows.GetFileInformationByHandle(handle, &info); infoErr != nil {
		return &os.PathError{Op: "stat", Path: dir, Err: infoErr}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DEVICE != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%w: %q is not a directory", ErrNonRegular, dir)
	}
	return nil
}

func syncDirOS(dir string) (retErr error) {
	dirPtr, err := windows.UTF16PtrFromString(fixLongPathWindows(dir))
	if err != nil {
		return fmt.Errorf("fsx: encode directory path %q: %w", dir, err)
	}
	handle, err := windows.CreateFile(
		dirPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windowsSyncDirFlags,
		0,
	)
	if err != nil {
		return fmt.Errorf("fsx: open directory handle %q: %w", dir, classifyWindowsOpenError(dir, err))
	}
	defer func() {
		if closeErr := windows.CloseHandle(handle); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("fsx: close directory handle %q: %w", dir, closeErr))
		}
	}()
	if valErr := validateWindowsDirectoryHandle(handle, dir); valErr != nil {
		return valErr
	}
	if flushErr := windows.FlushFileBuffers(handle); flushErr != nil {
		return fmt.Errorf("fsx: flush directory buffers %q: %w", dir, flushErr)
	}
	return nil
}

func unlockFileOS(f *os.File) error {
	if f == nil {
		return nil
	}
	var ol windows.Overlapped
	err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, ^uint32(0), ^uint32(0), &ol)
	runtime.KeepAlive(f)
	return err
}

// windowsDirLockPostAcquireHook is a package-private test hook invoked
// immediately after acquiring the Windows directory lock file and before
// verifyLockedFileIdentity. Nil in production.
var windowsDirLockPostAcquireHook func(lockPath string, attempt int)

// withDirLockOS implements a real cross-goroutine and cross-process directory
// lock on Windows by locking a fixed regular file inside the verified
// owner-only directory using LockFileEx(LOCKFILE_EXCLUSIVE_LOCK), verifying
// post-lock file identity via verifyLockedFileIdentity with bounded retry.
func withDirLockOS(dir string, fn func() error) error {
	currSID, err := winsec.CurrentProcessUserSID()
	if err != nil {
		return fmt.Errorf("fsx: query current Windows user SID: %w", err)
	}
	if err := winsec.VerifyOwnerOnlyDirectoryByHandle(dir, currSID); err != nil {
		return fmt.Errorf("fsx: verify owner-only socket directory %q: %w", dir, err)
	}

	lockPath := filepath.Join(dir, windowsDirLockFileName)
	f, err := acquireWindowsDirLockFile(lockPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = unlockFileOS(f)
		_ = f.Close()
	}()

	return fn()
}

func acquireWindowsDirLockFile(lockPath string) (*os.File, error) {
	for attempt := 0; attempt < DefaultLockRetries; attempt++ {
		f, err := openOrCreateWindowsDirLockFile(lockPath)
		if err != nil {
			return nil, err
		}
		if lockErr := lockFileOS(f, true); lockErr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("fsx: lock socket directory lock %q: %w", lockPath, lockErr)
		}
		if hook := windowsDirLockPostAcquireHook; hook != nil {
			hook(lockPath, attempt)
		}
		matched, verifyErr := verifyLockedFileIdentity(f, lockPath)
		if verifyErr != nil {
			_ = unlockFileOS(f)
			_ = f.Close()
			return nil, verifyErr
		}
		if matched {
			return f, nil
		}
		// Lock file was unlinked or replaced with a different file while
		// waiting on LockFileEx: unlock, close stale handle, and retry.
		_ = unlockFileOS(f)
		_ = f.Close()
	}
	return nil, fmt.Errorf("%w: socket directory lock %q replaced across %d attempts", ErrRetryExhausted, lockPath, DefaultLockRetries)
}

func openOrCreateWindowsDirLockFile(lockPath string) (*os.File, error) {
	for attempt := 0; attempt < 4; attempt++ {
		f, err := openExistingRegularForLockOS(lockPath, true)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("fsx: open socket directory lock %q: %w", lockPath, err)
		}
		cf, createErr := createExclusiveOS(lockPath, OwnerOnlyPerm)
		if createErr == nil {
			return cf, nil
		}
		if !errors.Is(createErr, os.ErrExist) {
			return nil, fmt.Errorf("fsx: create socket directory lock %q: %w", lockPath, createErr)
		}
	}
	return nil, fmt.Errorf("%w: open socket directory lock %q", ErrRetryExhausted, lockPath)
}

func ensureWindowsSocketSlotFree(targetPath string, allowReplace bool, isStale func() bool) error {
	if _, statErr := os.Lstat(targetPath); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		return statErr
	}
	if !allowReplace {
		return fmt.Errorf("%w: %s", ErrSlotOccupied, targetPath)
	}
	outcome, pruneErr := pruneLockedSocketEntry(targetPath, nil, isStale)
	if pruneErr != nil {
		return pruneErr
	}
	if outcome != StaleSocketRemoved && outcome != StaleSocketAlreadyGone {
		return fmt.Errorf("%w: %s", ErrSlotOccupied, targetPath)
	}
	return nil
}

func bindSocketSlotOS(targetPath string, listenFn ListenFunc, allowReplace bool, isStale func() bool) (*SocketSlot, error) {
	if len(targetPath) > windowsUnixPathMax {
		return nil, fmt.Errorf("fsx: socket path %q exceeds maximum Unix socket path length (%d bytes)", targetPath, windowsUnixPathMax)
	}
	dir := filepath.Dir(targetPath)
	if err := winsec.EnsureOwnerOnlyDirectory(dir); err != nil {
		return nil, fmt.Errorf("fsx: prepare owner-only socket directory %q: %w", dir, err)
	}

	var (
		ln     net.Listener
		origFi os.FileInfo
	)
	err := withDirLockOS(dir, func() error {
		if freeErr := ensureWindowsSocketSlotFree(targetPath, allowReplace, isStale); freeErr != nil {
			return freeErr
		}

		// Windows AF_UNIX does not support NTFS hard-linking of socket reparse
		// points. Bind directly inside the verified owner-only directory while
		// holding the directory lock, then harden and verify via handle APIs.
		var listenErr error
		ln, listenErr = listenFn(targetPath)
		if listenErr != nil {
			occupied, checkErr := isWindowsAddrInUse(listenErr, targetPath)
			if checkErr != nil {
				return errors.Join(fmt.Errorf("fsx: listen on socket %q: %w", targetPath, listenErr), checkErr)
			}
			if occupied {
				return fmt.Errorf("%w: %s", ErrSlotOccupied, targetPath)
			}
			return fmt.Errorf("fsx: listen on socket %q: %w", targetPath, listenErr)
		}
		disableAutoUnlink(ln)

		fi, secErr := hardenAndVerifyWindowsSocket(targetPath)
		if secErr != nil {
			_ = os.Remove(targetPath)
			_ = ln.Close()
			return secErr
		}
		origFi = fi
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &SocketSlot{
		path:     targetPath,
		listener: ln,
		origFi:   origFi,
	}, nil
}

func hardenAndVerifyWindowsSocket(targetPath string) (os.FileInfo, error) {
	if hardenErr := winsec.HardenSocketOwnerOnlyByHandle(targetPath); hardenErr != nil {
		return nil, fmt.Errorf("fsx: harden socket DACL %q: %w", targetPath, hardenErr)
	}
	origFi, lstatErr := os.Lstat(targetPath)
	if lstatErr != nil {
		return nil, fmt.Errorf("fsx: stat socket %q: %w", targetPath, lstatErr)
	}
	if verifyErr := winsec.VerifyOwnerOnlySocketByHandle(targetPath); verifyErr != nil {
		return nil, fmt.Errorf("fsx: verify socket security %q: %w", targetPath, verifyErr)
	}
	return origFi, nil
}

func pruneStaleSocketOS(targetPath string, expected os.FileInfo, isStale func() bool) (StaleSocketOutcome, error) {
	dir := filepath.Dir(targetPath)
	var outcome StaleSocketOutcome
	err := withDirLockOS(dir, func() error {
		var pErr error
		outcome, pErr = pruneLockedSocketEntry(targetPath, expected, isStale)
		return pErr
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return StaleSocketAlreadyGone, nil
		}
		return StaleSocketLive, err
	}
	return outcome, nil
}

func removeOwnedWindowsSocketLocked(targetPath string, origFi os.FileInfo, ln net.Listener) (listenerClosed bool, err error) {
	currFi, statErr := os.Lstat(targetPath)
	if statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return false, nil
		}
		return false, statErr
	}
	if !os.SameFile(origFi, currFi) {
		return false, nil
	}
	rmErr := os.Remove(targetPath)
	if rmErr == nil || errors.Is(rmErr, os.ErrNotExist) {
		return false, nil
	}
	if !isWindowsSharingViolation(rmErr) || ln == nil {
		return false, rmErr
	}
	// Defensive Windows fallback: if a filesystem filter holds a sharing lock
	// on the socket reparse point until the listener closes, close while still
	// holding the directory lock, re-verify SameFile, then unlink.
	_ = ln.Close()
	return true, removeWindowsSocketIfSameFile(targetPath, origFi)
}

func removeWindowsSocketIfSameFile(targetPath string, origFi os.FileInfo) error {
	againFi, againErr := os.Lstat(targetPath)
	if againErr != nil {
		if errors.Is(againErr, os.ErrNotExist) {
			return nil
		}
		return againErr
	}
	if !os.SameFile(origFi, againFi) {
		return nil
	}
	if retryRm := os.Remove(targetPath); retryRm != nil && !errors.Is(retryRm, os.ErrNotExist) {
		return retryRm
	}
	return nil
}

func releaseSocketSlotOS(targetPath string, origFi os.FileInfo, ln net.Listener) error {
	var (
		unlinkErr      error
		listenerClosed bool
	)
	if targetPath != "" && origFi != nil {
		dir := filepath.Dir(targetPath)
		lockErr := withDirLockOS(dir, func() error {
			var rmErr error
			listenerClosed, rmErr = removeOwnedWindowsSocketLocked(targetPath, origFi, ln)
			return rmErr
		})
		if lockErr != nil && !errors.Is(lockErr, os.ErrNotExist) {
			unlinkErr = lockErr
		}
	}

	var closeErr error
	if ln != nil && !listenerClosed {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = err
		}
	}
	return errors.Join(unlinkErr, closeErr)
}

func isWindowsSharingViolation(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

func isWindowsAddrInUse(err error, targetPath string) (bool, error) {
	if err == nil {
		return false, nil
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) && (sysErr == syscall.EADDRINUSE || sysErr == syscall.EEXIST || sysErr == windows.WSAEADDRINUSE) {
		return true, nil
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "address already in use") ||
		strings.Contains(lower, "only one usage of each socket address") ||
		strings.Contains(lower, "file exists") {
		return true, nil
	}
	if strings.Contains(lower, "access is denied") {
		if _, statErr := os.Lstat(targetPath); statErr == nil {
			return true, nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return false, fmt.Errorf("fsx: lstat socket %q after access-denied bind: %w", targetPath, statErr)
		}
	}
	return false, nil
}

func isConnRefusedOS(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, windows.WSAECONNREFUSED)
}

func isExtendedOrDeviceWindowsPath(path string) bool {
	if len(path) < 4 {
		return false
	}
	isSlash := func(b byte) bool { return b == '\\' || b == '/' }
	p0, p1, p2, p3 := path[0], path[1], path[2], path[3]
	if p0 == '\\' && p1 == '?' && p2 == '?' && p3 == '\\' {
		return true
	}
	return isSlash(p0) && isSlash(p1) && (p2 == '?' || p2 == '.') && isSlash(p3)
}

func isDriveRelativeWindowsPath(path string) bool {
	if len(path) < 2 || path[1] != ':' {
		return false
	}
	c := path[0]
	isDriveLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	if !isDriveLetter {
		return false
	}
	return len(path) == 2 || (path[2] != '\\' && path[2] != '/')
}

func fixLongPathWindows(path string) string {
	if path == "" || isExtendedOrDeviceWindowsPath(path) {
		return path
	}
	var precomputedFull string
	effectiveLen := len(path)
	if isDriveRelativeWindowsPath(path) {
		full, err := windows.FullPath(path)
		if err != nil || full == "" {
			return path
		}
		precomputedFull = full
		effectiveLen = len(full)
	} else if !filepath.IsAbs(path) {
		if wd, err := os.Getwd(); err == nil {
			effectiveLen += len(wd) + 1
		}
	}
	if effectiveLen < 248 {
		return path
	}
	full := precomputedFull
	if full == "" {
		var err error
		full, err = windows.FullPath(path)
		if err != nil || full == "" {
			return path
		}
	}
	if isExtendedOrDeviceWindowsPath(full) {
		return full
	}
	if strings.HasPrefix(full, `\\`) && !strings.HasPrefix(full, `\\?\`) {
		return `\\?\UNC\` + full[2:]
	}
	return `\\?\` + full
}
