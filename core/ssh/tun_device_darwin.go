//go:build darwin

package ssh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	sysprotoControl = 2 // unix.AF_SYS_CONTROL / SYSPROTO_CONTROL
	utunOptIfname   = 2 // UTUN_OPT_IFNAME
)

type darwinTunnelDevice struct {
	name      string
	mode      TunnelMode
	fd        int
	wakeRead  int
	wakeWrite int

	readMu   sync.Mutex
	readBuf  []byte
	writeMu  sync.Mutex
	writeBuf []byte

	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup
}

func (d *darwinTunnelDevice) Name() string     { return d.name }
func (d *darwinTunnelDevice) Mode() TunnelMode { return d.mode }

func (d *darwinTunnelDevice) ReadPacket(buf []byte) ([]byte, error) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, os.ErrClosed
	}
	d.wg.Add(1)
	d.mu.Unlock()
	defer d.wg.Done()

	d.readMu.Lock()
	defer d.readMu.Unlock()

	need := len(buf) + 4
	if cap(d.readBuf) < need {
		d.readBuf = make([]byte, need)
	}
	rawBuf := d.readBuf[:need]
	for {
		d.mu.Lock()
		closed := d.closed
		d.mu.Unlock()
		if closed {
			return nil, os.ErrClosed
		}

		fds := []unix.PollFd{
			{Fd: int32(d.fd), Events: unix.POLLIN},
			{Fd: int32(d.wakeRead), Events: unix.POLLIN},
		}
		_, err := unix.Poll(fds, -1)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}

		d.mu.Lock()
		closed = d.closed
		d.mu.Unlock()
		if closed || (fds[1].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0) {
			return nil, os.ErrClosed
		}
		if fds[0].Revents&unix.POLLNVAL != 0 {
			return nil, os.ErrClosed
		}

		if fds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
			n, err := unix.Read(d.fd, rawBuf)
			if err != nil {
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
					continue
				}
				return nil, err
			}
			if n == 0 {
				return nil, io.EOF
			}
			if n <= 4 {
				continue
			}
			if n-4 > len(buf) {
				return nil, io.ErrShortBuffer
			}
			copied := copy(buf, rawBuf[4:n])
			return buf[:copied], nil
		}
	}
}

func (d *darwinTunnelDevice) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	var af uint32
	switch pkt[0] >> 4 {
	case 4:
		af = uint32(unix.AF_INET)
	case 6:
		af = uint32(unix.AF_INET6)
	default:
		return fmt.Errorf("unsupported IP version %d on darwin utun", pkt[0]>>4)
	}

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return os.ErrClosed
	}
	d.wg.Add(1)
	d.mu.Unlock()
	defer d.wg.Done()

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	need := 4 + len(pkt)
	if cap(d.writeBuf) < need {
		d.writeBuf = make([]byte, need)
	}
	raw := d.writeBuf[:need]
	binary.BigEndian.PutUint32(raw[0:4], af)
	copy(raw[4:], pkt)

	for {
		d.mu.Lock()
		closed := d.closed
		d.mu.Unlock()
		if closed {
			return os.ErrClosed
		}

		_, err := unix.Write(d.fd, raw)
		if err == nil {
			return nil
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}

		fds := []unix.PollFd{
			{Fd: int32(d.fd), Events: unix.POLLOUT},
			{Fd: int32(d.wakeRead), Events: unix.POLLIN},
		}
		_, err = unix.Poll(fds, -1)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}

		d.mu.Lock()
		closed = d.closed
		d.mu.Unlock()
		if closed || (fds[1].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0) {
			return os.ErrClosed
		}
		if fds[0].Revents&unix.POLLNVAL != 0 {
			return os.ErrClosed
		}
	}
}

func (d *darwinTunnelDevice) Close() error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		_, _ = unix.Write(d.wakeWrite, []byte{1})
		_ = unix.Close(d.wakeWrite)
		d.mu.Unlock()

		d.wg.Wait()

		var errs []error
		if err := unix.Close(d.fd); err != nil {
			errs = append(errs, err)
		}
		if err := unix.Close(d.wakeRead); err != nil {
			errs = append(errs, err)
		}
		d.closeErr = errors.Join(errs...)
	})
	return d.closeErr
}

func openPlatformTunnelDevice(mode TunnelMode, localUnit int) (TunnelDevice, error) {
	if mode == TunnelModeEthernet {
		return nil, fmt.Errorf("%w: ethernet (tap) mode is not supported on macOS", ErrTunnelDeviceUnsupported)
	}
	if mode != TunnelModePointToPoint && mode != TunnelModeYes {
		return nil, fmt.Errorf("%w: unsupported tunnel mode %q", ErrTunnelDeviceUnsupported, mode)
	}
	if localUnit < 0 || localUnit > TunnelIDAny {
		return nil, fmt.Errorf("invalid local tunnel unit %d", localUnit)
	}

	syscall.ForkLock.RLock()
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		syscall.ForkLock.RUnlock()
		return nil, fmt.Errorf("open utun control socket failed: %w", err)
	}
	unix.CloseOnExec(fd)
	syscall.ForkLock.RUnlock()
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set utun socket non-blocking failed: %w", err)
	}

	var ctlInfo unix.CtlInfo
	copy(ctlInfo.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, &ctlInfo); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("ioctl CTLIOCGINFO for utun_control failed: %w", err)
	}

	var unit uint32
	if localUnit != TunnelIDAny {
		unit = uint32(localUnit + 1)
	}

	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: ctlInfo.Id, Unit: unit}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("connect utun control socket (unit=%d) failed: %w", unit, err)
	}

	ifName, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil || ifName == "" {
		if localUnit != TunnelIDAny {
			ifName = fmt.Sprintf("utun%d", localUnit)
		} else {
			ifName = "utun"
		}
	} else {
		ifName = strings.TrimRight(ifName, "\x00")
	}

	var wake [2]int
	syscall.ForkLock.RLock()
	if err := unix.Pipe(wake[:]); err != nil {
		syscall.ForkLock.RUnlock()
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create utun wake pipe failed: %w", err)
	}
	unix.CloseOnExec(wake[0])
	unix.CloseOnExec(wake[1])
	syscall.ForkLock.RUnlock()
	_ = unix.SetNonblock(wake[0], true)
	_ = unix.SetNonblock(wake[1], true)

	return &darwinTunnelDevice{
		name:      ifName,
		mode:      TunnelModePointToPoint,
		fd:        fd,
		wakeRead:  wake[0],
		wakeWrite: wake[1],
	}, nil
}
