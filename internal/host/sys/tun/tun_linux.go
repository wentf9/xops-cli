//go:build linux

package tun

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/unix"
)

func openLocalTUNOS(_ context.Context, spec ports.TUNSpec) (io.ReadWriteCloser, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", mapLinuxTUNErr(err)
	}
	ifName, flags, err := linuxIfreqSpec(spec)
	if err != nil {
		_ = unix.Close(fd)
		return nil, "", err
	}
	ifr, err := unix.NewIfreq(ifName)
	if err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("%w: %w", ports.ErrInvalidArgument, err)
	}
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, "", mapLinuxTUNErr(err)
	}
	conn, err := newUnixTUNConn(fd, false)
	if err != nil {
		return nil, "", err
	}
	return conn, ifr.Name(), nil
}

func linuxIfreqSpec(spec ports.TUNSpec) (string, uint16, error) {
	switch spec.Mode() {
	case ports.TUNModePointToPoint:
		flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if spec.LocalUnit() == ports.TUNUnitAny {
			return "tun%d", flags, nil
		}
		return fmt.Sprintf("tun%d", spec.LocalUnit()), flags, nil
	case ports.TUNModeEthernet:
		flags := uint16(unix.IFF_TAP | unix.IFF_NO_PI)
		if spec.LocalUnit() == ports.TUNUnitAny {
			return "tap%d", flags, nil
		}
		return fmt.Sprintf("tap%d", spec.LocalUnit()), flags, nil
	default:
		return "", 0, fmt.Errorf("%w: 不支持的 TUNMode", ports.ErrInvalidArgument)
	}
}

func mapLinuxTUNErr(err error) error {
	switch {
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return fmt.Errorf("%w: %w", ports.ErrPermissionDenied, err)
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENODEV), errors.Is(err, unix.ENXIO):
		return fmt.Errorf("%w: %w", ports.ErrUnsupported, err)
	default:
		return err
	}
}
