//go:build unix

package fsx

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

var slotTempSeq atomic.Uint64

func nextSlotTempToken() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint32(b[:]) & 0xffff
	}
	seq := slotTempSeq.Add(1)
	return (uint32(os.Getpid())&0xff)<<8 | uint32(seq&0xff)
}

func openRegularOS(path string, l Limits, cfg openConfig) (*RegularFile, error) {
	openFlags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOCTTY
	if !cfg.followSymlinks {
		openFlags |= unix.O_NOFOLLOW
	}
	fd, err := unixOpenNoIntr(path, openFlags, 0)
	if err != nil {
		return nil, classifyUnixOpenError(path, err)
	}

	var st unix.Stat_t
	if fstatErr := unix.Fstat(fd, &st); fstatErr != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "fstat", Path: path, Err: fstatErr}
	}

	if (st.Mode & unix.S_IFMT) != unix.S_IFREG {
		if cfg.allowDevNull {
			if isNull, nullErr := isUnixDevNullStat(&st); nullErr == nil && isNull {
				_ = unix.Close(fd)
				return newDevNullRegularFile(path, l.MaxBytes, nil), nil
			}
		}
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: %q", ErrNonRegular, path)
	}

	if st.Size > l.MaxBytes {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: %q (%d > %d bytes)", ErrTooLarge, path, st.Size, l.MaxBytes)
	}

	if clearErr := clearUnixNonBlock(fd, path); clearErr != nil {
		_ = unix.Close(fd)
		return nil, clearErr
	}

	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("fsx: os.NewFile returned nil for %q", path)
	}

	info, statErr := f.Stat()
	if statErr != nil {
		_ = f.Close()
		return nil, statErr
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %q", ErrNonRegular, path)
	}
	if info.Size() > l.MaxBytes {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %q (%d > %d bytes)", ErrTooLarge, path, info.Size(), l.MaxBytes)
	}

	return &RegularFile{
		file:     f,
		info:     info,
		path:     path,
		maxBytes: l.MaxBytes,
	}, nil
}

func isUnixDevNullStat(st *unix.Stat_t) (bool, error) {
	if st == nil || (st.Mode&unix.S_IFMT) != unix.S_IFCHR {
		return false, nil
	}
	var nullSt unix.Stat_t
	if err := unix.Stat(os.DevNull, &nullSt); err != nil {
		return false, err
	}
	return (nullSt.Mode&unix.S_IFMT) == unix.S_IFCHR &&
		st.Dev == nullSt.Dev &&
		st.Rdev == nullSt.Rdev, nil
}

func createExclusiveOS(path string, perm os.FileMode) (*os.File, error) {
	flags := unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unixOpenNoIntr(path, flags, uint32(perm.Perm()))
	if err != nil {
		return nil, classifyUnixOpenError(path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("fsx: os.NewFile returned nil for %q", path)
	}
	return f, nil
}

func openExistingRegularForLockOS(path string, exclusive bool) (*os.File, error) {
	flags := unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOCTTY
	if exclusive {
		flags |= unix.O_RDWR
	} else {
		flags |= unix.O_RDONLY
	}
	fd, err := unixOpenNoIntr(path, flags, 0)
	if err != nil {
		return nil, classifyUnixOpenError(path, err)
	}

	var st unix.Stat_t
	if fstatErr := unix.Fstat(fd, &st); fstatErr != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "fstat", Path: path, Err: fstatErr}
	}
	if (st.Mode & unix.S_IFMT) != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w: %q", ErrNonRegular, path)
	}
	if clearErr := clearUnixNonBlock(fd, path); clearErr != nil {
		_ = unix.Close(fd)
		return nil, clearErr
	}

	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("fsx: os.NewFile returned nil for %q", path)
	}
	return f, nil
}

func lockFileOS(f *os.File, exclusive bool) error {
	if f == nil {
		return os.ErrInvalid
	}
	how := unix.LOCK_SH
	if exclusive {
		how = unix.LOCK_EX
	}
	return unixFlockFile(f, how)
}

func tryLockFileOS(f *os.File, exclusive bool) error {
	if f == nil {
		return os.ErrInvalid
	}
	how := unix.LOCK_SH | unix.LOCK_NB
	if exclusive {
		how = unix.LOCK_EX | unix.LOCK_NB
	}
	err := unixFlockFile(f, how)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return fmt.Errorf("%w: %w", ErrWouldBlock, err)
	}
	return err
}

func createReplaceTempOS(path string, perm os.FileMode) (*os.File, error) {
	f, err := createExclusiveOS(path, perm)
	if err != nil {
		return nil, err
	}
	if chmodErr := f.Chmod(perm.Perm()); chmodErr != nil {
		origInfo, _ := f.Stat()
		_ = f.Close()
		_ = removeTempIfSameFile(path, origInfo)
		return nil, fmt.Errorf("fsx: chmod temp file %q: %w", path, chmodErr)
	}
	return f, nil
}

func replaceFileOS(source, destination string) error {
	return os.Rename(source, destination)
}

func syncDirOS(dir string) (retErr error) {
	fd, err := unixOpenNoIntr(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	f := os.NewFile(uintptr(fd), dir)
	if f == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("fsx: os.NewFile returned nil for directory %q", dir)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("fsx: close directory %q: %w", dir, closeErr))
		}
	}()
	if syncErr := f.Sync(); syncErr != nil {
		return fmt.Errorf("fsx: sync directory %q: %w", dir, syncErr)
	}
	return nil
}

func unlockFileOS(f *os.File) error {
	if f == nil {
		return nil
	}
	return unixFlockFile(f, unix.LOCK_UN)
}

func unixFlockFile(f *os.File, how int) error {
	rawConn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var flockErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		for {
			flockErr = unix.Flock(int(fd), how)
			if !errors.Is(flockErr, unix.EINTR) {
				return
			}
		}
	})
	if ctrlErr != nil {
		return ctrlErr
	}
	return flockErr
}

func unixOpenNoIntr(path string, flags int, mode uint32) (int, error) {
	for {
		fd, err := unix.Open(path, flags, mode)
		if !errors.Is(err, unix.EINTR) {
			return fd, err
		}
	}
}

func clearUnixNonBlock(fd int, path string) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return &os.PathError{Op: "fcntl", Path: path, Err: err}
	}
	if flags&unix.O_NONBLOCK != 0 {
		if _, setErr := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK); setErr != nil {
			return &os.PathError{Op: "fcntl", Path: path, Err: setErr}
		}
	}
	return nil
}

func classifyUnixOpenError(path string, err error) error {
	pathErr := &os.PathError{Op: "open", Path: path, Err: err}
	if errors.Is(err, unix.ELOOP) || (runtime.GOOS == "freebsd" && errors.Is(err, unix.EMLINK)) {
		return fmt.Errorf("%w: %w", ErrSymlink, pathErr)
	}
	if errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENXIO) || errors.Is(err, unix.EOPNOTSUPP) {
		return fmt.Errorf("%w: %w", ErrNonRegular, pathErr)
	}
	return pathErr
}

func maxUnixSocketPathLen() int {
	return len(unix.RawSockaddrUnix{}.Path) - 1
}

func withDirLockOS(dir string, fn func() error) error {
	fd, err := unixOpenNoIntr(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	dirFile := os.NewFile(uintptr(fd), dir)
	if dirFile == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("fsx: os.NewFile returned nil for directory %q", dir)
	}
	defer func() { _ = dirFile.Close() }()

	if lockErr := unixFlockFile(dirFile, unix.LOCK_EX); lockErr != nil {
		return fmt.Errorf("fsx: lock socket directory %q: %w", dir, lockErr)
	}
	defer func() { _ = unixFlockFile(dirFile, unix.LOCK_UN) }()

	return fn()
}

func bindSocketSlotOS(targetPath string, listenFn ListenFunc, allowReplace bool, isStale func() bool) (*SocketSlot, error) {
	maxPathLen := maxUnixSocketPathLen()
	if len(targetPath) > maxPathLen {
		return nil, fmt.Errorf("fsx: socket path %q exceeds maximum Unix socket path length (%d bytes)", targetPath, maxPathLen)
	}
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("fsx: create socket directory %q: %w", dir, err)
	}

	suffixBudget := maxPathLen - len(targetPath)
	dirBudget := maxPathLen - (len(dir) + 1)
	useSuffixTemp := suffixBudget >= 8
	useDirTemp := !useSuffixTemp && dirBudget >= 8

	if !useSuffixTemp && !useDirTemp {
		return bindDirectUnixSocketSlot(targetPath, dir, listenFn, allowReplace, isStale)
	}
	return bindTempLinkUnixSocketSlot(targetPath, dir, useSuffixTemp, listenFn, allowReplace, isStale)
}

func bindTempLinkUnixSocketSlot(
	targetPath, dir string,
	useSuffixTemp bool,
	listenFn ListenFunc,
	allowReplace bool,
	isStale func() bool,
) (*SocketSlot, error) {
	ln, tempPath, err := listenTempUnixSocket(targetPath, dir, useSuffixTemp, listenFn)
	if err != nil {
		return nil, err
	}
	disableAutoUnlink(ln)
	defer func() { _ = os.Remove(tempPath) }()

	if err := os.Chmod(tempPath, OwnerOnlyPerm); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("fsx: chmod temp socket %q: %w", tempPath, err)
	}
	origFi, err := os.Lstat(tempPath)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("fsx: stat temp socket %q: %w", tempPath, err)
	}

	pubErr := withDirLockOS(dir, func() error {
		return publishLinkedUnixSocket(tempPath, targetPath, allowReplace, isStale)
	})
	if pubErr != nil {
		_ = ln.Close()
		return nil, pubErr
	}
	return &SocketSlot{
		path:     targetPath,
		listener: ln,
		origFi:   origFi,
	}, nil
}

func listenTempUnixSocket(targetPath, dir string, useSuffixTemp bool, listenFn ListenFunc) (net.Listener, string, error) {
	var (
		ln       net.Listener
		tempPath string
		err      error
	)
	for attempt := 0; attempt < 4; attempt++ {
		tok := nextSlotTempToken()
		if useSuffixTemp {
			tempPath = fmt.Sprintf("%s.m%04x.t", targetPath, tok)
		} else {
			tempPath = filepath.Join(dir, fmt.Sprintf(".m%04x.t", tok))
		}
		ln, err = listenFn(tempPath)
		if err == nil {
			return ln, tempPath, nil
		}
		if !isUnixAddrInUse(err) {
			return nil, "", fmt.Errorf("fsx: listen on temp socket %q: %w", tempPath, err)
		}
	}
	return nil, "", fmt.Errorf("fsx: listen on temp socket failed: %w", err)
}

func publishLinkedUnixSocket(tempPath, targetPath string, allowReplace bool, isStale func() bool) error {
	linkErr := os.Link(tempPath, targetPath)
	if linkErr == nil {
		return nil
	}
	if !errors.Is(linkErr, os.ErrExist) && !errors.Is(linkErr, syscall.EEXIST) {
		return fmt.Errorf("fsx: link socket %q -> %q: %w", tempPath, targetPath, linkErr)
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
	if retryErr := os.Link(tempPath, targetPath); retryErr != nil {
		if errors.Is(retryErr, os.ErrExist) || errors.Is(retryErr, syscall.EEXIST) {
			return fmt.Errorf("%w: %s", ErrSlotOccupied, targetPath)
		}
		return fmt.Errorf("fsx: link replacement socket %q -> %q: %w", tempPath, targetPath, retryErr)
	}
	return nil
}

func bindDirectUnixSocketSlot(
	targetPath, dir string,
	listenFn ListenFunc,
	allowReplace bool,
	isStale func() bool,
) (*SocketSlot, error) {
	var (
		ln     net.Listener
		origFi os.FileInfo
	)
	err := withDirLockOS(dir, func() error {
		if _, statErr := os.Lstat(targetPath); statErr == nil {
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
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}

		var listenErr error
		ln, listenErr = listenFn(targetPath)
		if listenErr != nil {
			if isUnixAddrInUse(listenErr) {
				return fmt.Errorf("%w: %s", ErrSlotOccupied, targetPath)
			}
			return fmt.Errorf("fsx: listen on socket %q: %w", targetPath, listenErr)
		}
		disableAutoUnlink(ln)

		if chmodErr := os.Chmod(targetPath, OwnerOnlyPerm); chmodErr != nil {
			_ = os.Remove(targetPath)
			_ = ln.Close()
			return fmt.Errorf("fsx: chmod socket %q: %w", targetPath, chmodErr)
		}
		var lstatErr error
		origFi, lstatErr = os.Lstat(targetPath)
		if lstatErr != nil {
			_ = os.Remove(targetPath)
			_ = ln.Close()
			return fmt.Errorf("fsx: stat socket %q: %w", targetPath, lstatErr)
		}
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

func releaseSocketSlotOS(targetPath string, origFi os.FileInfo, ln net.Listener) error {
	var unlinkErr error
	if targetPath != "" && origFi != nil {
		dir := filepath.Dir(targetPath)
		lockErr := withDirLockOS(dir, func() error {
			currFi, err := os.Lstat(targetPath)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return nil
				}
				return err
			}
			if !os.SameFile(origFi, currFi) {
				return nil
			}
			if rmErr := os.Remove(targetPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				return rmErr
			}
			return nil
		})
		if lockErr != nil && !errors.Is(lockErr, os.ErrNotExist) {
			unlinkErr = lockErr
		}
	}

	var closeErr error
	if ln != nil {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = err
		}
	}
	return errors.Join(unlinkErr, closeErr)
}

func isUnixAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) && (sysErr == syscall.EADDRINUSE || sysErr == syscall.EEXIST) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "address already in use") || strings.Contains(lower, "file exists")
}

func isConnRefusedOS(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}
