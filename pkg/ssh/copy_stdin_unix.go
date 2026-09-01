//go:build !windows

package ssh

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// copyStdinTo 使用 poll(2) 将 src 复制到 dst，返回取消函数和完成通道。
// 调用 cancel 后 goroutine 会立即退出，不会残留读取 stdin 的 goroutine 偷走后续输入。
//
// 实现原理：同时 poll stdin fd 和一个 cancel pipe fd，关闭 cancel pipe 写端即可
// 立即唤醒 poll 并退出，完全避免了 os.File.SetReadDeadline 在终端 fd 上不生效的问题。
func copyStdinTo(src *os.File, dst io.Writer) (cancel func() error, done <-chan error, err error) {
	if src == nil {
		return nil, nil, fmt.Errorf("interactive stdin is nil")
	}
	cancelR, cancelW, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("create stdin cancellation pipe failed: %w", err)
	}

	ch := make(chan error, 1)
	go func() {
		var copyErr error
		defer func() {
			if closeErr := cancelR.Close(); closeErr != nil {
				copyErr = errors.Join(copyErr, fmt.Errorf("close stdin cancellation reader failed: %w", closeErr))
			}
			ch <- copyErr
			close(ch)
		}()

		stdinFd := int(src.Fd())
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
				copyErr = fmt.Errorf("poll stdin failed: %w", err)
				return
			}
			if fds[1].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
				return
			}
			if fds[0].Revents&unix.POLLIN != 0 {
				n, err := unix.Read(stdinFd, buf)
				if n > 0 {
					if _, werr := dst.Write(buf[:n]); werr != nil {
						copyErr = fmt.Errorf("copy stdin to SSH session failed: %w", werr)
						return
					}
				}
				if err != nil {
					copyErr = fmt.Errorf("read stdin failed: %w", err)
					return
				}
				if n == 0 {
					return
				}
			}
		}
	}()

	var (
		cancelOnce sync.Once
		cancelErr  error
	)
	return func() error {
		cancelOnce.Do(func() {
			if closeErr := cancelW.Close(); closeErr != nil {
				cancelErr = fmt.Errorf("close stdin cancellation writer failed: %w", closeErr)
			}
		})
		return cancelErr
	}, ch, nil
}
