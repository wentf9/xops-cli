//go:build linux || darwin

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/unix"
)

const darwinAFHeaderBytes = 4

// unixTUNConn 基于 raw fd + self-pipe + unix.Poll 提供可安全并发关闭的 TUN/TAP 帧读写流，
// 全程不调用 os.NewFile 与 unix.Fstat，并以读写锁隔离 Close 对 fd 的释放，杜绝 fd 复用竞态。
type unixTUNConn struct {
	fd            int
	wakeR         *os.File
	wakeW         *os.File
	stripAFHeader bool
	closed        atomic.Bool
	ioMu          sync.RWMutex
	closeOnce     sync.Once
	closeErr      error
}

func newUnixTUNConn(fd int, stripAFHeader bool) (*unixTUNConn, error) {
	wakeR, wakeW, err := os.Pipe()
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("创建 TUN 唤醒管道失败: %w", err)
	}
	return &unixTUNConn{
		fd:            fd,
		wakeR:         wakeR,
		wakeW:         wakeW,
		stripAFHeader: stripAFHeader,
	}, nil
}

func (c *unixTUNConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.ioMu.RLock()
	defer c.ioMu.RUnlock()
	for {
		if c.closed.Load() {
			return 0, ports.ErrClosed
		}
		if err := c.waitReady(unix.POLLIN); err != nil {
			return 0, err
		}
		n, retry, err := c.readOnce(p)
		if retry {
			continue
		}
		return n, err
	}
}

func (c *unixTUNConn) readOnce(p []byte) (int, bool, error) {
	if c.stripAFHeader {
		buf := make([]byte, len(p)+darwinAFHeaderBytes)
		n, err := readNonBlockFD(c.fd, buf)
		if isUnixWouldBlock(err) {
			return 0, true, nil
		}
		if err != nil {
			return 0, false, err
		}
		if n <= darwinAFHeaderBytes {
			// 丢弃仅有 AF 头的残缺帧并继续等待下一有效帧，避免返回 (0, nil) 违反 io.Reader 契约。
			return 0, true, nil
		}
		return copy(p, buf[darwinAFHeaderBytes:n]), false, nil
	}
	n, err := readNonBlockFD(c.fd, p)
	if isUnixWouldBlock(err) {
		return 0, true, nil
	}
	return n, false, err
}

func (c *unixTUNConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.ioMu.RLock()
	defer c.ioMu.RUnlock()
	payload, err := c.prepareWritePayload(p)
	if err != nil {
		return 0, err
	}
	for {
		if c.closed.Load() {
			return 0, ports.ErrClosed
		}
		if err := c.waitReady(unix.POLLOUT); err != nil {
			return 0, err
		}
		n, retry, err := c.writeOnce(payload)
		if retry {
			continue
		}
		return n, err
	}
}

func (c *unixTUNConn) prepareWritePayload(p []byte) ([]byte, error) {
	if !c.stripAFHeader {
		return p, nil
	}
	return prependDarwinAFHeader(p)
}

func (c *unixTUNConn) writeOnce(payload []byte) (int, bool, error) {
	n, err := writeNonBlockFD(c.fd, payload)
	if isUnixWouldBlock(err) {
		return 0, true, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !c.stripAFHeader {
		return n, false, nil
	}
	if n <= darwinAFHeaderBytes {
		return 0, false, io.ErrShortWrite
	}
	return n - darwinAFHeaderBytes, false, nil
}

func isUnixWouldBlock(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK)
}

func (c *unixTUNConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		wErr := c.wakeW.Close()
		c.ioMu.Lock()
		fdErr := unix.Close(c.fd)
		rErr := c.wakeR.Close()
		c.fd = -1
		c.ioMu.Unlock()
		c.closeErr = errors.Join(wErr, fdErr, rErr)
	})
	return c.closeErr
}

func (c *unixTUNConn) waitReady(events int16) error {
	fds := []unix.PollFd{
		{Fd: int32(c.fd), Events: events},
		{Fd: int32(c.wakeR.Fd()), Events: unix.POLLIN},
	}
	for {
		if c.closed.Load() {
			return ports.ErrClosed
		}
		_, err := unix.Poll(fds, -1)
		runtime.KeepAlive(c.wakeR)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if fds[1].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLNVAL) != 0 || c.closed.Load() {
			return ports.ErrClosed
		}
		if fds[0].Revents&(events|unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return nil
		}
	}
}

func readNonBlockFD(fd int, buf []byte) (int, error) {
	for {
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}
}

func writeNonBlockFD(fd int, buf []byte) (int, error) {
	for {
		n, err := unix.Write(fd, buf)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return n, err
	}
}

func prependDarwinAFHeader(pkt []byte) ([]byte, error) {
	var af uint32
	switch pkt[0] >> 4 {
	case 4:
		af = uint32(unix.AF_INET)
	case 6:
		af = uint32(unix.AF_INET6)
	default:
		return nil, fmt.Errorf("%w: utun L3 帧首字节版本无效 (0x%02x)", ports.ErrInvalidArgument, pkt[0])
	}
	out := make([]byte, darwinAFHeaderBytes+len(pkt))
	binary.BigEndian.PutUint32(out[:darwinAFHeaderBytes], af)
	copy(out[darwinAFHeaderBytes:], pkt)
	return out, nil
}
