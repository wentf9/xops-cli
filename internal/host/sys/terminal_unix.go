//go:build unix

package sys

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"sync"

	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/unix"
)

func probeFileInteractive(in, out *os.File) (bool, error) {
	if in == nil || out == nil {
		return false, nil
	}
	_, inErr := unix.IoctlGetTermios(int(in.Fd()), ioctlReadTermios)
	runtime.KeepAlive(in)
	if inErr != nil {
		return false, nil
	}
	_, outErr := unix.IoctlGetTermios(int(out.Fd()), ioctlReadTermios)
	runtime.KeepAlive(out)
	return outErr == nil, nil
}

func queryFileSize(in, out *os.File) (ports.TerminalSize, error) {
	ws, err := unix.IoctlGetWinsize(int(out.Fd()), unix.TIOCGWINSZ)
	runtime.KeepAlive(out)
	if err != nil {
		ws, err = unix.IoctlGetWinsize(int(in.Fd()), unix.TIOCGWINSZ)
		runtime.KeepAlive(in)
		if err != nil {
			return zeroVal[ports.TerminalSize](), fmt.Errorf("查询 Unix 终端窗口尺寸失败: %w", err)
		}
	}
	return ports.NewTerminalSize(ws.Col, ws.Row)
}

func enterRawFileOS(in, _ *os.File) (func() error, error) {
	fd := int(in.Fd())
	orig, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	runtime.KeepAlive(in)
	if err != nil {
		return nil, fmt.Errorf("读取原始 termios 状态失败: %w", err)
	}
	saved := *orig
	raw := *orig
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, &raw); err != nil {
		runtime.KeepAlive(in)
		return nil, fmt.Errorf("切换 Unix 终端至原始模式失败: %w", err)
	}
	runtime.KeepAlive(in)

	var restoreOnce sync.Once
	var restoreErr error
	return func() error {
		restoreOnce.Do(func() {
			restoreErr = unix.IoctlSetTermios(int(in.Fd()), ioctlWriteTermios, &saved)
			runtime.KeepAlive(in)
		})
		return restoreErr
	}, nil
}

func watchResizeOS(ctx context.Context, in, out *os.File, dst chan ports.TerminalSize) error {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, unix.SIGWINCH)
	defer signal.Stop(sigCh)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sigCh:
			if sz, err := queryFileSize(in, out); err == nil {
				pushLatestResize(dst, sz)
			}
		}
	}
}

// unixCancelableFileReader 基于 self-pipe + unix.Poll 实现可立即唤醒的终端输入读取，
// 消除传统阻塞 os.Stdin.Read 导致远端退出后孤儿读协程泄漏问题。
type unixCancelableFileReader struct {
	in        *os.File
	wakeR     *os.File
	wakeW     *os.File
	unblockDo sync.Once
	closeDo   sync.Once
}

func newCancelableFileReaderOS(in *os.File) (io.Reader, func(), func(), error) {
	wakeR, wakeW, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("创建终端输入唤醒管道失败: %w", err)
	}
	r := &unixCancelableFileReader{in: in, wakeR: wakeR, wakeW: wakeW}
	return r, r.unblock, r.close, nil
}

func (r *unixCancelableFileReader) unblock() {
	r.unblockDo.Do(func() { _ = r.wakeW.Close() })
}

func (r *unixCancelableFileReader) close() {
	r.unblock()
	r.closeDo.Do(func() { _ = r.wakeR.Close() })
}

func (r *unixCancelableFileReader) Read(p []byte) (int, error) {
	inFD, wakeFD := int32(r.in.Fd()), int32(r.wakeR.Fd())
	fds := []unix.PollFd{
		{Fd: inFD, Events: unix.POLLIN},
		{Fd: wakeFD, Events: unix.POLLIN},
	}
	for {
		_, err := unix.Poll(fds, -1)
		runtime.KeepAlive(r.in)
		runtime.KeepAlive(r.wakeR)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, err
		}
		// 优先响应取消唤醒管道，确保远端退出或上下文取消后即使本地输入有缓冲字节也能确定性立即收敛。
		if fds[1].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return 0, errInputCanceled
		}
		// 显式包含 unix.POLLNVAL，避免 inFD 失效/关闭时 unix.Poll 立即返回却无人消费引发 100% CPU 空转。
		if fds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			n, rErr := readFDUnix(r.in, p)
			if errors.Is(rErr, unix.EAGAIN) || errors.Is(rErr, unix.EWOULDBLOCK) {
				continue
			}
			return n, rErr
		}
	}
}

func readFDUnix(f *os.File, p []byte) (int, error) {
	for {
		n, err := unix.Read(int(f.Fd()), p)
		runtime.KeepAlive(f)
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
