//go:build linux

// Package testpty provides PTY pairs for terminal integration fixtures.
package testpty

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Open returns a PTY pair. The caller owns both files.
// Pointer-aware ioctl helpers keep kernel output valid across Go stack moves.
func Open() (master, slave *os.File, retErr error) {
	opened, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open PTY master: %w", err)
	}
	defer func() {
		if retErr != nil {
			if err := opened.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close PTY master after allocation failure: %w", err))
			}
		}
	}()
	if err := unix.IoctlSetPointerInt(int(opened.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		return nil, nil, fmt.Errorf("unlock PTY slave: %w", err)
	}
	number, err := unix.IoctlGetInt(int(opened.Fd()), unix.TIOCGPTN)
	if err != nil {
		return nil, nil, fmt.Errorf("read PTY slave number: %w", err)
	}
	slave, err = os.OpenFile("/dev/pts/"+strconv.Itoa(number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open PTY slave: %w", err)
	}
	return opened, slave, nil
}
