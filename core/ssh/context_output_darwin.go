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
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, nil, fmt.Errorf("access native output: %w", err)
	}
	var owned *os.File
	var prepareErr error
	err = raw.Control(func(fd uintptr) {
		if info.Mode()&os.ModeNamedPipe != 0 {
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
			return
		}
		if _, termErr := unix.IoctlGetTermios(int(fd), unix.TIOCGETA); termErr != nil {
			prepareErr = fmt.Errorf("output is not a terminal: %w", termErr)
			return
		}
		name, pathErr := darwinOutputPath(fd)
		if pathErr != nil {
			prepareErr = pathErr
			return
		}
		owned, prepareErr = os.OpenFile(name, os.O_WRONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
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
