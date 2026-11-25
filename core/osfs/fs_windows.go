//go:build windows

package osfs

import (
	"errors"
	"fmt"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/windows"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"
)

const winAppendAccess uint32 = (windows.FILE_GENERIC_WRITE &^ windows.FILE_WRITE_DATA) |
	windows.STANDARD_RIGHTS_READ | windows.FILE_READ_ATTRIBUTES | windows.FILE_READ_EA

func localPathToNativeOS(kind pathalg.LocalPathKind, raw string) (string, error) {
	if kind == pathalg.LocalPathPOSIXAbs {
		return "", fmt.Errorf("%w: Windows 不支持裸 POSIX 绝对路径 %q", ports.ErrInvalidArgument, raw)
	}
	return NormalizeWin32LongPath(filepath.FromSlash(raw)), nil
}

// ntCreateAtHandle 相对已打开目录句柄原子打开/创建单个分量，主路径启用 OBJ_DONT_REPARSE，旧内核以 FILE_OPEN_REPARSE_POINT 回退。
func ntCreateAtHandle(dirHandle windows.Handle, leaf string, access, disposition, options, fileAttrs uint32, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	if dirHandle == 0 || dirHandle == windows.InvalidHandle || leaf == "" || leaf == ".." || strings.ContainsAny(leaf, `\/:`) {
		return windows.InvalidHandle, fmt.Errorf("%w: 非法相对目录分量 %q", ports.ErrInvalidArgument, leaf)
	}
	ntName, err := windows.NewNTUnicodeString(leaf)
	if err != nil {
		return windows.InvalidHandle, mapOSError(err)
	}
	sqos := windows.SECURITY_QUALITY_OF_SERVICE{Length: uint32(unsafe.Sizeof(windows.SECURITY_QUALITY_OF_SERVICE{})), ImpersonationLevel: windows.SecurityAnonymous, ContextTrackingMode: windows.SECURITY_STATIC_TRACKING}
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: dirHandle, ObjectName: ntName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: sd, SecurityQoS: &sqos}
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
		nextH, openErr := ntCreateAtHandle(curH, seg, windows.FILE_LIST_DIRECTORY|windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, windows.FILE_ATTRIBUTE_NORMAL, nil)
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
	err := withParentDirHandleWin(root, parentSegs, func(parentH windows.Handle) (cErr error) {
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
func openLeafInRootOS(r *os.Root, d pathalg.LocalRootedDest, op rootLeafOp, perm fs.FileMode) (*os.File, error) {
	const ro, rw = windows.FILE_GENERIC_READ, windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE
	specs := [7]struct {
		acc, disp uint32
		mayCreate bool
	}{
		{ro, windows.FILE_OPEN, false}, {rw, windows.FILE_CREATE, true}, {winAppendAccess, windows.FILE_OPEN_IF, true},
		{rw, windows.FILE_OPEN_IF, true}, {ro, windows.FILE_OPEN, false}, {rw, windows.FILE_OPEN, false}, {rw, windows.FILE_OPEN_IF, true},
	}
	return openLeafInRootWin(r, d, specs[op].acc, specs[op].disp, specs[op].mayCreate && perm.Perm()&0o077 == 0)
}
func mkdirSegmentInRootOS(root *os.Root, parentSegs []string, leaf string, mode fs.FileMode) error {
	h, err := ntCreateInRootWin(root, parentSegs, leaf, windows.FILE_LIST_DIRECTORY|windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES, windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE, windows.FILE_ATTRIBUTE_DIRECTORY, mode.Perm()&0o077 == 0, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	if err != nil {
		return err
	}
	return mapOSError(windows.CloseHandle(h))
}
func ensureDirOS(nativeDir string, mode fs.FileMode) error {
	if mode.Perm()&0o077 == 0 {
		return EnsureOwnerOnlyDirectory(nativeDir)
	}
	_, toCreate, err := collectMissingDirs(nativeDir)
	if err != nil {
		return err
	}
	return createMissingDirsWin(toCreate, nil, nil, nil)
}
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

type winErrMap struct{ src, out error }

func mapWinErrTable(path string, err error, tbl []winErrMap) error {
	for _, m := range tbl {
		if errors.Is(err, m.src) {
			return fmt.Errorf("%w: %s: %w", m.out, path, err)
		}
	}
	return nil
}
func mapNTStatusError(path string, err error) error {
	if err == nil {
		return nil
	}
	if mapped := mapWinErrTable(path, err, []winErrMap{
		{windows.STATUS_REPARSE_POINT_ENCOUNTERED, ports.ErrSymlinkRejected}, {windows.STATUS_STOPPED_ON_SYMLINK, ports.ErrSymlinkRejected},
		{windows.STATUS_OBJECT_NAME_COLLISION, ports.ErrAlreadyExists}, {windows.STATUS_OBJECT_NAME_NOT_FOUND, ports.ErrNotFound},
		{windows.STATUS_OBJECT_PATH_NOT_FOUND, ports.ErrNotFound}, {windows.STATUS_FILE_IS_A_DIRECTORY, ports.ErrNotRegularFile},
		{windows.STATUS_NOT_A_DIRECTORY, ports.ErrNotRegularFile}, {windows.STATUS_OBJECT_TYPE_MISMATCH, ports.ErrNotRegularFile},
	}); mapped != nil {
		return mapped
	}
	if nt, ok := errors.AsType[windows.NTStatus](err); ok {
		return mapWindowsOpenError(path, nt.Errno())
	}
	return mapWindowsOpenError(path, err)
}
func mapWindowsOpenError(path string, err error) error {
	if err == nil {
		return nil
	}
	if mapped := mapWinErrTable(path, err, []winErrMap{
		{windows.ERROR_FILE_NOT_FOUND, ports.ErrNotFound}, {windows.ERROR_PATH_NOT_FOUND, ports.ErrNotFound},
		{windows.ERROR_FILE_EXISTS, ports.ErrAlreadyExists}, {windows.ERROR_ALREADY_EXISTS, ports.ErrAlreadyExists},
		{windows.ERROR_ACCESS_DENIED, ports.ErrPermissionDenied}, {windows.ERROR_PIPE_BUSY, ports.ErrNotRegularFile},
		{windows.ERROR_CANT_ACCESS_FILE, ports.ErrNotRegularFile},
	}); mapped != nil {
		return mapped
	}
	return mapOSError(err)
}
func tryLockFileOS(f *os.File, exclusive bool) error {
	flags := pickIf(exclusive, uint32(windows.LOCKFILE_FAIL_IMMEDIATELY|windows.LOCKFILE_EXCLUSIVE_LOCK), uint32(windows.LOCKFILE_FAIL_IMMEDIATELY))
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
