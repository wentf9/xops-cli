//go:build darwin

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func prepareFileOutput(ctx context.Context, source *os.File, perWrite time.Duration) (io.Writer, func() error, error) {
	info, err := source.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("inspect native output: %w", err)
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		owned, openErr := reopenNonBlockingWriteFile(source)
		if openErr != nil {
			return nil, nil, openErr
		}
		return bindOwnedFileOutput(ctx, owned, source, perWrite)
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, nil, fmt.Errorf("access native output: %w", err)
	}
	var owned *os.File
	var prepareErr error
	err = raw.Control(func(fd uintptr) {
		flags, flagErr := unix.FcntlInt(fd, unix.F_GETFL, 0)
		if flagErr != nil {
			prepareErr = flagErr
			return
		}
		// Darwin /dev/fd also duplicates the shared file description. Never set
		// O_NONBLOCK on a borrowed blocking pipe, even temporarily.
		if flags&unix.O_NONBLOCK == 0 {
			prepareErr = fmt.Errorf("blocking macOS pipes require a ContextWriter")
			return
		}
		duplicate, dupErr := unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0)
		if dupErr != nil {
			prepareErr = dupErr
			return
		}
		owned = os.NewFile(uintptr(duplicate), "owned nonblocking output")
	})
	if err != nil || prepareErr != nil {
		if owned != nil {
			prepareErr = errors.Join(prepareErr, closeResource(owned, "owned native output"))
		}
		return nil, nil, errors.Join(err, prepareErr)
	}
	openedInfo, err := owned.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return nil, nil, errors.Join(fmt.Errorf("native output identity changed while opening"), err, closeResource(owned, "owned native output"))
	}
	return bindOwnedFileOutput(ctx, owned, source, perWrite)
}

func reopenNonBlockingWriteFile(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, fmt.Errorf("terminal output is nil")
	}
	info, err := source.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect native output: %w", err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return nil, fmt.Errorf("output is not a terminal")
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("access native output: %w", err)
	}
	var owned *os.File
	var openErr error
	err = raw.Control(func(fd uintptr) {
		if _, termErr := unix.IoctlGetTermios(int(fd), unix.TIOCGETA); termErr != nil {
			openErr = fmt.Errorf("output is not a terminal: %w", termErr)
			return
		}
		name, pathErr := darwinOutputPath(fd)
		if pathErr != nil {
			openErr = pathErr
			return
		}
		owned, openErr = os.OpenFile(name, os.O_WRONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0) //nolint:forbidigo // reopen verified TTY char device with independent non-blocking file description
	})
	if err != nil || openErr != nil {
		if owned != nil {
			openErr = errors.Join(openErr, closeResource(owned, "owned native output"))
		}
		return nil, errors.Join(err, openErr)
	}
	openedInfo, statErr := owned.Stat()
	if statErr != nil || !os.SameFile(info, openedInfo) {
		return nil, errors.Join(fmt.Errorf("native output identity changed while opening"), statErr, closeResource(owned, "owned native output"))
	}
	return owned, nil
}

func darwinOutputPath(fd uintptr) (string, error) {
	var path [unix.PathMax]byte
	// FcntlInt's variadic argument also carries pointer-valued commands. Pin
	// the buffer so stack movement cannot invalidate it across the libc call.
	var pin runtime.Pinner
	pin.Pin(&path[0])
	defer pin.Unpin()
	if _, err := unix.FcntlInt(fd, unix.F_GETPATH, int(uintptr(unsafe.Pointer(&path[0])))); err != nil {
		return "", fmt.Errorf("resolve terminal output path: %w", err)
	}
	for n, b := range path {
		if b == 0 {
			return string(path[:n]), nil
		}
	}
	return "", fmt.Errorf("terminal output path is not terminated")
}
