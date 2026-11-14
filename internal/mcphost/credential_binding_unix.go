//go:build !windows

package mcphost

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openRegularCertFile(certPath string) (*os.File, os.FileInfo, bool, error) {
	var (
		fd  int
		err error
	)
	for {
		fd, err = unix.Open(certPath, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		if info, statErr := os.Stat(certPath); statErr == nil && !info.Mode().IsRegular() {
			return nil, nil, true, err
		}
		return nil, nil, false, err
	}

	var st unix.Stat_t
	if fstatErr := unix.Fstat(fd, &st); fstatErr != nil || (st.Mode&unix.S_IFMT) != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, nil, true, nil
	}
	if flags, flErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); flErr == nil && flags&unix.O_NONBLOCK != 0 {
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK)
	}
	f := os.NewFile(uintptr(fd), certPath)
	if f == nil {
		_ = unix.Close(fd)
		return nil, nil, false, errors.New("os.NewFile returned nil for certificate fd")
	}
	fInfo, statErr := f.Stat()
	if statErr != nil || !fInfo.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, true, nil
	}
	return f, fInfo, false, nil
}
