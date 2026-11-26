//go:build darwin

package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/unix"
)

const (
	darwinSysProtoControl = 2
	darwinUtunOptIfname   = 2
	darwinUtunControlName = "com.apple.net.utun_control"
)

func openLocalTUNOS(_ context.Context, spec ports.TUNSpec) (io.ReadWriteCloser, string, error) {
	if spec.Mode() != ports.TUNModePointToPoint {
		return nil, "", fmt.Errorf("%w: macOS 原生 utun 仅支持 L3 点对点隧道", ports.ErrUnsupported)
	}
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, darwinSysProtoControl)
	if err != nil {
		return nil, "", mapDarwinTUNErr(err)
	}
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, "", err
	}
	var ctl unix.CtlInfo
	copy(ctl.Name[:], darwinUtunControlName)
	if err := unix.IoctlCtlInfo(fd, &ctl); err != nil {
		_ = unix.Close(fd)
		return nil, "", mapDarwinTUNErr(err)
	}
	unit := uint32(0)
	if spec.LocalUnit() != ports.TUNUnitAny {
		// Darwin utun SockaddrCtl.Unit 采用 1 起始编号（unit=1 对应 utun0）。
		unit = spec.LocalUnit() + 1
	}
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: ctl.Id, Unit: unit}); err != nil {
		_ = unix.Close(fd)
		return nil, "", mapDarwinTUNErr(err)
	}
	ifName, err := unix.GetsockoptString(fd, darwinSysProtoControl, darwinUtunOptIfname)
	if err != nil {
		_ = unix.Close(fd)
		return nil, "", err
	}
	conn, err := newUnixTUNConn(fd, true)
	if err != nil {
		return nil, "", err
	}
	return conn, strings.TrimRight(ifName, "\x00"), nil
}

func mapDarwinTUNErr(err error) error {
	switch {
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return fmt.Errorf("%w: %w", ports.ErrPermissionDenied, err)
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.EAFNOSUPPORT), errors.Is(err, unix.EPROTONOSUPPORT):
		return fmt.Errorf("%w: %w", ports.ErrUnsupported, err)
	default:
		return err
	}
}
