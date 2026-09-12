//go:build (linux || darwin) && (amd64 || arm64)

package kdfhelper

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"time"
)

func pollablePipe(f *os.File) (*os.File, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeNamedPipe == 0 {
		return nil, ErrProtocol
	}
	fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, errors.Join(err, unix.Close(fd))
	}
	return os.NewFile(uintptr(fd), "private-kdf-pipe"), nil
}

func setWorkerDeadlines(input, output *os.File, deadline time.Time) error {
	if err := input.SetReadDeadline(deadline); err != nil {
		return err
	}
	return output.SetWriteDeadline(deadline)
}
