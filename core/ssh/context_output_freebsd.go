//go:build freebsd

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

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
			// FreeBSD /dev/fd duplicates the shared file description. Never set
			// O_NONBLOCK on a borrowed blocking pipe, even temporarily.
			if flags&unix.O_NONBLOCK == 0 {
				prepareErr = fmt.Errorf("blocking FreeBSD pipes require a ContextWriter")
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
		if info.Mode()&os.ModeCharDevice == 0 {
			prepareErr = fmt.Errorf("output is not a terminal or named pipe")
			return
		}
		if _, termErr := unix.IoctlGetTermios(int(fd), unix.TIOCGETA); termErr != nil {
			prepareErr = fmt.Errorf("output is not a terminal: %w", termErr)
			return
		}
		devPath, pathErr := findCharDevicePathByInfo(info, []string{"/dev/pts", "/dev"})
		if pathErr != nil {
			prepareErr = pathErr
			return
		}
		owned, prepareErr = os.OpenFile(devPath, os.O_WRONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
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
