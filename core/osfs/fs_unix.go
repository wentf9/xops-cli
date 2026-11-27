//go:build unix

package osfs

import (
	"errors"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/unix"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
)

func localPathToNativeOS(kind pathalg.LocalPathKind, raw string) (string, error) {
	if kind == pathalg.LocalPathWindowsDrive {
		return "", domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyOSFSPathPlatformMismatch, domi18n.BoundStr("path", raw))
	}
	return raw, nil
}
func unlockFileOS(f *os.File) error { return flockFileUnix(f, unix.LOCK_UN) }
func openLeafInRootOS(root *os.Root, dest pathalg.LocalRootedDest, op rootLeafOp, perm fs.FileMode) (*os.File, error) {
	flags := [7]int{
		unix.O_RDONLY | unix.O_NONBLOCK, unix.O_RDWR | unix.O_CREAT | unix.O_EXCL,
		unix.O_WRONLY | unix.O_CREAT | unix.O_APPEND | unix.O_NONBLOCK,
		unix.O_RDWR | unix.O_CREAT | unix.O_NONBLOCK, unix.O_RDONLY | unix.O_NONBLOCK,
		unix.O_RDWR | unix.O_NONBLOCK, unix.O_RDWR | unix.O_CREAT | unix.O_NONBLOCK,
	}
	return openLeafInRootUnix(root, dest, flags[op], perm)
}
func openatNoFollow(dirFD int, name string, flags int, mode uint32) (int, error) {
	for {
		fd, err := unix.Openat(dirFD, name, flags, mode)
		if !errors.Is(err, syscall.EINTR) {
			return fd, err
		}
	}
}

// stepDirChainUnix 从基准目录句柄逐段以 O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC 步进；createMode!=0 时按序 Mkdirat。
//
//xops:syncclosure
func stepDirChainUnix(baseF *os.File, segs []string, createMode fs.FileMode, fn func(leafFD int) error) error {
	curFD, ownedFD := int(baseF.Fd()), -1
	defer func() {
		if ownedFD >= 0 {
			_ = unix.Close(ownedFD)
		}
	}()
	for _, seg := range segs {
		if createMode != 0 {
			if mkErr := unix.Mkdirat(curFD, seg, uint32(createMode.Perm())); mkErr != nil && !errors.Is(mkErr, unix.EEXIST) {
				return mapUnixOpenError(mkErr)
			}
		}
		nextFD, oErr := openatNoFollow(curFD, seg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if oErr != nil {
			return mapUnixDirOpenError(curFD, seg, oErr)
		}
		if ownedFD >= 0 {
			_ = unix.Close(ownedFD)
		}
		curFD, ownedFD = nextFD, nextFD
	}
	var err error
	if fn != nil {
		err = fn(curFD)
	}
	runtime.KeepAlive(baseF)
	return err
}
func ensureDirOS(nativeDir string, mode fs.FileMode) error { return ensureDirRawUnix(nativeDir, mode) }

// ensureDirRawUnix 在 Unix 上逐段以 Mkdirat + O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC 安全创建目录，
// 容忍 OS 级祖先软链（如 macOS /tmp -> /private/tmp），同时严格拒绝末段或新建路径中的符号链接。
func ensureDirRawUnix(nativeDir string, mode fs.FileMode) error {
	if nativeDir == "" {
		return domi18n.EF(ports.ErrInvalidArgument, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "dir"))
	}
	target := filepath.Clean(nativeDir)
	base, missing, err := walkExistingAncestorUnix(target)
	if err != nil {
		return err
	}
	if len(missing) == 0 {
		fd, oErr := openatNoFollow(unix.AT_FDCWD, target, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if oErr != nil {
			return mapUnixDirOpenError(unix.AT_FDCWD, target, oErr)
		}
		return mapOSError(unix.Close(fd))
	}
	baseF, err := os.OpenFile(base, os.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return mapUnixOpenError(err)
	}
	defer func() { _ = baseF.Close() }()
	slices.Reverse(missing)
	return stepDirChainUnix(baseF, missing, mode, nil)
}
func walkExistingAncestorUnix(target string) (string, []string, error) {
	var missing []string
	for cur := target; ; {
		if st, err := os.Stat(cur); err == nil {
			if !st.IsDir() {
				return "", nil, domi18n.EF(ports.ErrNotRegularFile, domi18n.KeyOSFSNotDirectory, domi18n.BoundStr("path", cur))
			}
			return cur, missing, nil
		} else if parent := filepath.Dir(cur); !errors.Is(err, os.ErrNotExist) || parent == cur {
			return "", nil, mapOSError(err)
		} else {
			missing, cur = append(missing, filepath.Base(cur)), parent
		}
	}
}

//xops:syncclosure
func withParentDirFDUnix(root *os.Root, parentSegs []string, fn func(parentFD int) error) error {
	rootF, err := root.Open(".")
	if err != nil {
		return mapUnixOpenError(err)
	}
	defer func() { _ = rootF.Close() }()
	return stepDirChainUnix(rootF, parentSegs, 0, fn)
}
func openLeafInRootUnix(root *os.Root, dest pathalg.LocalRootedDest, flags int, mode fs.FileMode) (*os.File, error) {
	segs, fd := dest.Segments(), -1
	if err := withParentDirFDUnix(root, segs[:len(segs)-1], func(parentFD int) (oErr error) {
		fd, oErr = openatNoFollow(parentFD, dest.Base(), flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
		return mapUnixOpenError(oErr)
	}); err != nil {
		return nil, err
	}
	if err := verifyRegularFDUnix(fd, dest.String(), flags&unix.O_NONBLOCK != 0); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), dest.String()), nil
}
func verifyRegularFDUnix(fd int, rel string, clearNonblock bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return mapOSError(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return domi18n.EF(ports.ErrNotRegularFile, domi18n.KeyOSFSNotRegularFile, domi18n.BoundStr("path", rel))
	}
	if clearNonblock {
		return mapOSError(unix.SetNonblock(fd, false))
	}
	return nil
}
func mkdirSegmentInRootOS(root *os.Root, parentSegs []string, leaf string, mode fs.FileMode) error {
	return withParentDirFDUnix(root, parentSegs, func(parentFD int) error { return mapUnixOpenError(unix.Mkdirat(parentFD, leaf, uint32(mode.Perm()))) })
}
func openOperatorReadOS(nativePath string, policy pathalg.SymlinkPolicy) (*os.File, int64, error) {
	flags := os.O_RDONLY | unix.O_NONBLOCK
	switch policy {
	case pathalg.SymlinkReject, pathalg.SymlinkContainedRelative:
		flags |= unix.O_NOFOLLOW
	case pathalg.SymlinkFollowOperatorSource:
	default:
		return nil, 0, errField(ports.ErrInvalidArgument, "symlink_policy")
	}
	f, err := os.OpenFile(nativePath, flags, 0)
	if err != nil {
		return nil, 0, mapUnixOpenError(err)
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, 0, pickIf[error](err != nil, mapOSError(err), domi18n.EF(ports.ErrNotRegularFile, domi18n.KeyOSFSNotRegularFile, domi18n.BoundStr("path", nativePath)))
	}
	return f, st.Size(), nil
}
func mapUnixDirOpenError(dirFD int, name string, err error) error {
	var st unix.Stat_t
	if errors.Is(err, unix.ENOTDIR) && unix.Fstatat(dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return wrapS(ports.ErrSymlinkRejected, err)
	}
	return mapUnixOpenError(err)
}
func mapUnixOpenError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EMLINK), isBSDFileTypeErr(err):
		return wrapS(ports.ErrSymlinkRejected, err)
	case errors.Is(err, unix.EISDIR), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ENXIO):
		return wrapS(ports.ErrNotRegularFile, err)
	default:
		return mapOSError(err)
	}
}
func flockFileUnix(f *os.File, how int) error {
	rawConn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if ctrlErr := rawConn.Control(func(fd uintptr) {
		for {
			if lockErr = unix.Flock(int(fd), how); !errors.Is(lockErr, syscall.EINTR) {
				return
			}
		}
	}); ctrlErr != nil {
		return ctrlErr
	}
	return lockErr
}
func tryLockFileOS(f *os.File, exclusive bool) error {
	err := flockFileUnix(f, pickIf(exclusive, unix.LOCK_EX|unix.LOCK_NB, unix.LOCK_SH|unix.LOCK_NB))
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return wrapS(ports.ErrLockBusy, err)
	}
	return mapOSError(err)
}
func syncRootParentDirOS(root *os.Root, dest pathalg.LocalRootedDest) error {
	parentRel := "."
	if parent, ok := dest.Parent(); ok {
		parentRel = parent.String()
	}
	dirFile, err := root.Open(parentRel)
	if err != nil {
		return mapOSError(err)
	}
	syncErr := dirFile.Sync()
	if errors.Is(syncErr, unix.EINVAL) || errors.Is(syncErr, unix.EROFS) || errors.Is(syncErr, unix.EBADF) || errors.Is(syncErr, unix.EOPNOTSUPP) {
		syncErr = nil
	}
	return mapOSError(errors.Join(syncErr, dirFile.Close()))
}
