//go:build !windows

package ssh

import (
	"errors"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// copyStdinTo 使用 poll(2) 将 os.Stdin 复制到 dst，返回取消函数和完成通道。
// 调用 cancel 后 goroutine 会立即退出，不会残留读取 stdin 的 goroutine 偷走后续输入。
//
// 实现原理：同时 poll stdin fd 和一个 cancel pipe fd，关闭 cancel pipe 写端即可
// 立即唤醒 poll 并退出，完全避免了 os.File.SetReadDeadline 在终端 fd 上不生效的问题。
func copyStdinTo(dst io.Writer) (cancel func(), done <-chan struct{}) {
	cancelR, cancelW, err := os.Pipe()
	if err != nil {
		return fallbackCopyStdinTo(dst)
	}

	ch := make(chan struct{})
	go func() {
		defer close(ch)
		defer func() { _ = cancelR.Close() }()

		stdinFd := int(os.Stdin.Fd())
		cancelFd := int(cancelR.Fd())
		buf := make([]byte, 32*1024)

		fds := []unix.PollFd{
			{Fd: int32(stdinFd), Events: unix.POLLIN},
			{Fd: int32(cancelFd), Events: unix.POLLIN},
		}

		for {
			_, err := unix.Poll(fds, -1)
			if err != nil {
				if errors.Is(err, syscall.EINTR) {
					continue
				}
				return
			}
			if fds[1].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
				return
			}
			if fds[0].Revents&unix.POLLIN != 0 {
				n, err := unix.Read(stdinFd, buf)
				if n > 0 {
					if _, werr := dst.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}
	}()

	return func() { _ = cancelW.Close() }, ch
}
