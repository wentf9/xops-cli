//go:build unix

package osfs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"syscall"

	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/unix"
)

func unixNativePath(kind pathalg.LocalPathKind, raw string) (string, error) {
	if kind == pathalg.LocalPathWindowsDrive {
		return "", fmt.Errorf("%w: Unix 不支持 Windows 盘符路径 %q", ports.ErrInvalidArgument, raw)
	}
	return raw, nil
}
func localDirToNativePath(dir pathalg.LocalDir) (string, error) {
	return unixNativePath(dir.Kind(), dir.String())
}
func localSourceToNativePath(src pathalg.LocalSourcePath) (string, error) {
	return unixNativePath(src.Kind(), src.String())
}

func openatNoFollow(dirFD int, name string, flags int, mode uint32) (int, error) {
	for {
		fd, err := unix.Openat(dirFD, name, flags, mode)
		if !errors.Is(err, syscall.EINTR) {
			return fd, err
		}
	}
}

// withParentDirFDUnix 从 *os.Root 锚定根目录句柄逐段以 O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC 步进至父目录 FD 并执行同步回调。
//
//xops:syncclosure
func withParentDirFDUnix(root *os.Root, parentSegs []string, fn func(parentFD int) error) error {
	rootF, err := root.Open(".")
	if err != nil {
		return mapUnixOpenError(err)
	}
	defer func() { _ = rootF.Close() }()
	curFD, ownedFD := int(rootF.Fd()), -1
	defer func() {
		if ownedFD >= 0 {
			_ = unix.Close(ownedFD)
		}
	}()
	for _, seg := range parentSegs {
		nextFD, openErr := openatNoFollow(curFD, seg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			return mapUnixOpenError(openErr)
		}
		if ownedFD >= 0 {
			_ = unix.Close(ownedFD)
		}
		curFD, ownedFD = nextFD, nextFD
	}
	err = fn(curFD)
	runtime.KeepAlive(rootF)
	return err
}

func openLeafInRootUnix(root *os.Root, dest pathalg.LocalRootedDest, flags int, mode fs.FileMode) (*os.File, error) {
	segs, fd := dest.Segments(), -1
	if err := withParentDirFDUnix(root, segs[:len(segs)-1], func(parentFD int) error {
		var openErr error
		fd, openErr = openatNoFollow(parentFD, dest.Base(), flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
		return mapUnixOpenError(openErr)
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
		return fmt.Errorf("%w: 目标 %q 不是常规文件", ports.ErrNotRegularFile, rel)
	}
	if clearNonblock {
		return mapOSError(unix.SetNonblock(fd, false))
	}
	return nil
}

func openRegularFDInRootOS(root *os.Root, dest pathalg.LocalRootedDest) (*os.File, error) {
	return openLeafInRootUnix(root, dest, unix.O_RDONLY|unix.O_NONBLOCK, 0)
}
func createExclusiveInRootOS(root *os.Root, dest pathalg.LocalRootedDest, mode fs.FileMode) (*os.File, error) {
	return openLeafInRootUnix(root, dest, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, mode)
}
func openForAppendInRootOS(root *os.Root, dest pathalg.LocalRootedDest, mode fs.FileMode) (*os.File, error) {
	return openLeafInRootUnix(root, dest, unix.O_WRONLY|unix.O_CREAT|unix.O_APPEND|unix.O_NONBLOCK, mode)
}

func openForLockInRootOS(root *os.Root, dest pathalg.LocalRootedDest, mode ports.LockMode, create bool, perm fs.FileMode) (*os.File, error) {
	flags, createPerm := unix.O_RDONLY|unix.O_NONBLOCK, fs.FileMode(0)
	if mode == ports.LockExclusive || create {
		flags = unix.O_RDWR | unix.O_NONBLOCK
	}
	if create {
		flags, createPerm = flags|unix.O_CREAT, sanitizeFilePerm(perm, defaultFilePerm)
	}
	return openLeafInRootUnix(root, dest, flags, createPerm)
}

func mkdirSegmentInRootOS(root *os.Root, parentSegs []string, leaf string, mode fs.FileMode) error {
	return withParentDirFDUnix(root, parentSegs, func(parentFD int) error {
		return mapUnixOpenError(unix.Mkdirat(parentFD, leaf, uint32(mode.Perm())))
	})
}

// openOperatorReadOS 按 SymlinkPolicy 在 Unix 上打开人工指定的只读常规源文件。
func openOperatorReadOS(nativePath string, policy pathalg.SymlinkPolicy) (*os.File, int64, error) {
	flags := os.O_RDONLY | unix.O_NONBLOCK
	switch policy {
	case pathalg.SymlinkReject, pathalg.SymlinkContainedRelative:
		flags |= unix.O_NOFOLLOW
	case pathalg.SymlinkFollowOperatorSource:
	default:
		return nil, 0, fmt.Errorf("%w: 不支持的软链接策略 %v", ports.ErrInvalidArgument, policy)
	}
	f, err := os.OpenFile(nativePath, flags, 0)
	if err != nil {
		return nil, 0, mapUnixOpenError(err)
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		if err != nil {
			return nil, 0, mapOSError(err)
		}
		return nil, 0, fmt.Errorf("%w: 源路径 %q 不是常规文件", ports.ErrNotRegularFile, nativePath)
	}
	return f, st.Size(), nil
}

func mapUnixOpenError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.EMLINK), isBSDFileTypeErr(err):
		return fmt.Errorf("%w: %w", ports.ErrSymlinkRejected, err)
	case errors.Is(err, unix.EISDIR), errors.Is(err, unix.ENOTDIR), errors.Is(err, unix.ENXIO):
		return fmt.Errorf("%w: %w", ports.ErrNotRegularFile, err)
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
	how := unix.LOCK_SH | unix.LOCK_NB
	if exclusive {
		how = unix.LOCK_EX | unix.LOCK_NB
	}
	err := flockFileUnix(f, how)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return fmt.Errorf("%w: %w", ports.ErrLockBusy, err)
	}
	return mapOSError(err)
}
func unlockFileOS(f *os.File) error { return flockFileUnix(f, unix.LOCK_UN) }

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
