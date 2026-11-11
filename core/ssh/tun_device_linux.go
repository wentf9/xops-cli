//go:build linux

package ssh

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type linuxTunnelDevice struct {
	name  string
	mode  TunnelMode
	file  *os.File
	close func() error
}

func (d *linuxTunnelDevice) Name() string     { return d.name }
func (d *linuxTunnelDevice) Mode() TunnelMode { return d.mode }

func (d *linuxTunnelDevice) ReadPacket(buf []byte) ([]byte, error) {
	n, err := d.file.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (d *linuxTunnelDevice) WritePacket(pkt []byte) error {
	_, err := d.file.Write(pkt)
	return err
}

func (d *linuxTunnelDevice) Close() error {
	return d.close()
}

func openPlatformTunnelDevice(mode TunnelMode, localUnit int) (TunnelDevice, error) {
	if localUnit < 0 || localUnit > TunnelIDAny {
		return nil, fmt.Errorf("invalid local tunnel unit %d", localUnit)
	}

	var flags uint16
	var ifrName string
	deviceMode := mode

	switch mode {
	case TunnelModePointToPoint, TunnelModeYes:
		deviceMode = TunnelModePointToPoint
		flags = uint16(unix.IFF_TUN | unix.IFF_NO_PI)
		if localUnit == TunnelIDAny {
			ifrName = "tun%d"
		} else {
			ifrName = fmt.Sprintf("tun%d", localUnit)
		}
	case TunnelModeEthernet:
		flags = uint16(unix.IFF_TAP | unix.IFF_NO_PI)
		if localUnit == TunnelIDAny {
			ifrName = "tap%d"
		} else {
			ifrName = fmt.Sprintf("tap%d", localUnit)
		}
	default:
		return nil, fmt.Errorf("%w: unsupported tunnel mode %q", ErrTunnelDeviceUnsupported, mode)
	}

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun failed: %w", err)
	}

	ifr, err := unix.NewIfreq(ifrName)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create ifreq for %q failed: %w", ifrName, err)
	}
	ifr.SetUint16(flags)

	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF on %q failed: %w", ifrName, err)
	}

	name := ifr.Name()
	file := os.NewFile(uintptr(fd), name)

	dev := &linuxTunnelDevice{
		name: name,
		mode: deviceMode,
		file: file,
	}
	dev.close = sync.OnceValue(dev.file.Close)
	return dev, nil
}
