//go:build windows

package osfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/windows"
)

const winAppendAccess uint32 = (windows.FILE_GENERIC_WRITE &^ windows.FILE_WRITE_DATA) |
	windows.STANDARD_RIGHTS_READ | windows.FILE_READ_ATTRIBUTES | windows.FILE_READ_EA

func winNativePath(kind pathalg.LocalPathKind, raw string) (string, error) {
	if kind == pathalg.LocalPathPOSIXAbs {
		return "", fmt.Errorf("%w: Windows 不支持裸 POSIX 绝对路径 %q", ports.ErrInvalidArgument, raw)
	}
	return NormalizeWin32LongPath(filepath.FromSlash(raw)), nil
}

func localDirToNativePath(dir pathalg.LocalDir) (string, error) {
	return winNativePath(dir.Kind(), dir.String())
}
func localSourceToNativePath(src pathalg.LocalSourcePath) (string, error) {
	return winNativePath(src.Kind(), src.String())
}

// ntCreateAtHandle 相对已打开目录句柄 dirHandle 原子打开/创建单个分量，主路径启用 OBJ_DONT_REPARSE
// 阻断一切重解析点穿越；对不支持 OBJ_DONT_REPARSE 的旧版内核以单分量 FILE_OPEN_REPARSE_POINT 回退校验。
func ntCreateAtHandle(dirHandle windows.Handle, leaf string, access, disposition, options, fileAttrs uint32, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	if dirHandle == 0 || dirHandle == windows.InvalidHandle || leaf == "" || leaf == ".." || strings.ContainsAny(leaf, `\/:`) {
		return windows.InvalidHandle, fmt.Errorf("%w: 非法相对目录分量 %q", ports.ErrInvalidArgument, leaf)
	}
	ntName, err := windows.NewNTUnicodeString(leaf)
	if err != nil {
		return windows.InvalidHandle, mapOSError(err)
	}
	sqos := windows.SECURITY_QUALITY_OF_SERVICE{
		Length: uint32(unsafe.Sizeof(windows.SECURITY_QUALITY_OF_SERVICE{})), ImpersonationLevel: windows.SecurityAnonymous,
		ContextTrackingMode: windows.SECURITY_STATIC_TRACKING,
	}
	oa := windows.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: dirHandle, ObjectName: ntName,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: sd, SecurityQoS: &sqos,
	}
	fullOpts := options | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_FOR_BACKUP_INTENT
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access, &oa, &iosb, nil, fileAttrs, winShareAll, disposition, fullOpts, 0, 0)
	if errors.Is(err, windows.STATUS_INVALID_PARAMETER) {
		oa.Attributes &^= windows.OBJ_DONT_REPARSE
		err = windows.NtCreateFile(&h, access, &oa, &iosb, nil, fileAttrs, winShareAll, disposition, fullOpts|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	}
	runtime.KeepAlive(ntName)
	runtime.KeepAlive(sd)
	runtime.KeepAlive(&sqos)
	runtime.KeepAlive(&oa)
	if err != nil {
		return windows.InvalidHandle, mapNTStatusError(leaf, err)
	}
	return h, nil
}

// withParentDirHandleWin 从 *os.Root 锚定根目录句柄逐段无重解析步进至父目录句柄并执行同步回调。
//
//xops:syncclosure
func withParentDirHandleWin(root *os.Root, parentSegs []string, fn func(parentH windows.Handle) error) error {
	rootF, err := root.Open(".")
	if err != nil {
		return mapWindowsOpenError(".", err)
	}
	defer func() { _ = rootF.Close() }()
	curH, ownedH := windows.Handle(rootF.Fd()), windows.InvalidHandle
	defer func() {
		if ownedH != windows.InvalidHandle {
			_ = windows.CloseHandle(ownedH)
		}
	}()
	for _, seg := range parentSegs {
		nextH, openErr := ntCreateAtHandle(curH, seg, windows.FILE_LIST_DIRECTORY|windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES,
			windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, windows.FILE_ATTRIBUTE_NORMAL, nil)
		if openErr != nil {
			return openErr
		}
		if _, vErr := validateWindowsHandle(nextH, seg, true, true); vErr != nil {
			_ = windows.CloseHandle(nextH)
			return vErr
		}
		if ownedH != windows.InvalidHandle {
			_ = windows.CloseHandle(ownedH)
		}
		curH, ownedH = nextH, nextH
	}
	err = fn(curH)
	runtime.KeepAlive(rootF)
	return err
}

func ntCreateInRootWin(root *os.Root, parentSegs []string, leaf string, access, disp, opts, attrs uint32, ownerOnly bool, inh uint32) (windows.Handle, error) {
	var sd *windows.SECURITY_DESCRIPTOR
	if ownerOnly {
		var err error
		if sd, _, err = currentOwnerOnlySD(inh); err != nil {
			return windows.InvalidHandle, err
		}
	}
	h := windows.InvalidHandle
	err := withParentDirHandleWin(root, parentSegs, func(parentH windows.Handle) error {
		var cErr error
		h, cErr = ntCreateAtHandle(parentH, leaf, access, disp, opts, attrs, sd)
		return cErr
	})
	return h, err
}

func openLeafInRootWin(root *os.Root, dest pathalg.LocalRootedDest, access, disposition uint32, ownerOnly bool) (*os.File, error) {
	segs := dest.Segments()
	h, err := ntCreateInRootWin(root, segs[:len(segs)-1], dest.Base(), access, disposition, windows.FILE_NON_DIRECTORY_FILE, windows.FILE_ATTRIBUTE_NORMAL, ownerOnly, windows.NO_INHERITANCE)
	if err != nil {
		return nil, err
	}
	f, _, err := wrapValidatedWindowsFile(h, dest.String(), true)
	if err != nil && disposition == windows.FILE_CREATE {
		_ = root.Remove(dest.String())
	}
	return f, err
}

func openRegularFDInRootOS(root *os.Root, dest pathalg.LocalRootedDest) (*os.File, error) {
	return openLeafInRootWin(root, dest, windows.FILE_GENERIC_READ, windows.FILE_OPEN, false)
}
func createExclusiveInRootOS(root *os.Root, dest pathalg.LocalRootedDest, mode fs.FileMode) (*os.File, error) {
	return openLeafInRootWin(root, dest, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE, windows.FILE_CREATE, mode.Perm()&0o077 == 0)
}
func openForAppendInRootOS(root *os.Root, dest pathalg.LocalRootedDest, mode fs.FileMode) (*os.File, error) {
	return openLeafInRootWin(root, dest, winAppendAccess, windows.FILE_OPEN_IF, mode.Perm()&0o077 == 0)
}
func openForLockInRootOS(root *os.Root, dest pathalg.LocalRootedDest, mode ports.LockMode, create bool, perm fs.FileMode) (*os.File, error) {
	access, disp, ownerOnly := uint32(windows.FILE_GENERIC_READ), uint32(windows.FILE_OPEN), false
	if mode == ports.LockExclusive || create {
		access |= windows.FILE_GENERIC_WRITE
	}
	if create {
		disp, ownerOnly = windows.FILE_OPEN_IF, sanitizeFilePerm(perm, defaultFilePerm)&0o077 == 0
	}
	return openLeafInRootWin(root, dest, access, disp, ownerOnly)
}

func mkdirSegmentInRootOS(root *os.Root, parentSegs []string, leaf string, mode fs.FileMode) error {
	h, err := ntCreateInRootWin(root, parentSegs, leaf, windows.FILE_LIST_DIRECTORY|windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE, windows.FILE_ATTRIBUTE_DIRECTORY, mode.Perm()&0o077 == 0, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	if err != nil {
		return err
	}
	return mapOSError(windows.CloseHandle(h))
}

// openOperatorReadOS 按 SymlinkPolicy 在 Windows 上打开跨盘符/长路径操作员只读常规文件。
func openOperatorReadOS(nativePath string, policy pathalg.SymlinkPolicy) (*os.File, int64, error) {
	flags, rejectReparse := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_ANONYMOUS), false
	switch policy {
	case pathalg.SymlinkReject, pathalg.SymlinkContainedRelative:
		flags, rejectReparse = flags|windows.FILE_FLAG_OPEN_REPARSE_POINT, true
	case pathalg.SymlinkFollowOperatorSource:
	default:
		return nil, 0, fmt.Errorf("%w: 不支持的软链接策略 %v", ports.ErrInvalidArgument, policy)
	}
	pathPtr, err := windows.UTF16PtrFromString(nativePath)
	if err != nil {
		return nil, 0, mapOSError(err)
	}
	handle, err := windows.CreateFile(pathPtr, windows.GENERIC_READ, winShareAll, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return nil, 0, mapWindowsOpenError(nativePath, err)
	}
	return wrapValidatedWindowsFile(handle, nativePath, rejectReparse)
}

func wrapValidatedWindowsFile(handle windows.Handle, path string, rejectReparse bool) (*os.File, int64, error) {
	info, err := validateWindowsHandle(handle, path, false, rejectReparse)
	if err == nil {
		if f := os.NewFile(uintptr(handle), path); f != nil {
			return f, (int64(info.FileSizeHigh) << 32) | int64(info.FileSizeLow), nil
		}
		err = fmt.Errorf("%w: os.NewFile 返回空句柄", ports.ErrInvalidArgument)
	}
	_ = windows.CloseHandle(handle)
	return nil, 0, err
}

func validateWindowsHandle(handle windows.Handle, path string, expectDir, rejectReparse bool) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if ft, err := windows.GetFileType(handle); err != nil {
		return info, mapOSError(err)
	} else if ft != windows.FILE_TYPE_DISK {
		return info, fmt.Errorf("%w: %q 不是磁盘对象", ports.ErrNotRegularFile, path)
	}
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return info, mapOSError(err)
	}
	if rejectReparse && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return info, fmt.Errorf("%w: %q 为重解析点/符号链接", ports.ErrSymlinkRejected, path)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DEVICE != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != expectDir {
		return info, fmt.Errorf("%w: %q 对象类型不符合预期", ports.ErrNotRegularFile, path)
	}
	return info, nil
}

func mapNTStatusError(path string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windows.STATUS_REPARSE_POINT_ENCOUNTERED), errors.Is(err, windows.STATUS_STOPPED_ON_SYMLINK):
		return fmt.Errorf("%w: %s: %w", ports.ErrSymlinkRejected, path, err)
	case errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION):
		return fmt.Errorf("%w: %s: %w", ports.ErrAlreadyExists, path, err)
	case errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND), errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND):
		return fmt.Errorf("%w: %s: %w", ports.ErrNotFound, path, err)
	case errors.Is(err, windows.STATUS_FILE_IS_A_DIRECTORY), errors.Is(err, windows.STATUS_NOT_A_DIRECTORY), errors.Is(err, windows.STATUS_OBJECT_TYPE_MISMATCH):
		return fmt.Errorf("%w: %s: %w", ports.ErrNotRegularFile, path, err)
	}
	if nt, ok := errors.AsType[windows.NTStatus](err); ok {
		return mapWindowsOpenError(path, nt.Errno())
	}
	return mapWindowsOpenError(path, err)
}

func mapWindowsOpenError(path string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return fmt.Errorf("%w: %s: %w", ports.ErrNotFound, path, err)
	case errors.Is(err, windows.ERROR_FILE_EXISTS), errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		return fmt.Errorf("%w: %s: %w", ports.ErrAlreadyExists, path, err)
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return fmt.Errorf("%w: %s: %w", ports.ErrPermissionDenied, path, err)
	case errors.Is(err, windows.ERROR_PIPE_BUSY), errors.Is(err, windows.ERROR_CANT_ACCESS_FILE):
		return fmt.Errorf("%w: %s: %w", ports.ErrNotRegularFile, path, err)
	default:
		return mapOSError(err)
	}
}

func tryLockFileOS(f *os.File, exclusive bool) error {
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if exclusive {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	var ol windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, ^uint32(0), ^uint32(0), &ol)
	runtime.KeepAlive(f)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		return fmt.Errorf("%w: %w", ports.ErrLockBusy, err)
	}
	return err
}

func unlockFileOS(f *os.File) error {
	var ol windows.Overlapped
	err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, ^uint32(0), ^uint32(0), &ol)
	runtime.KeepAlive(f)
	return err
}

func syncRootParentDirOS(_ *os.Root, _ pathalg.LocalRootedDest) error { return nil }
