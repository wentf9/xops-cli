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

// copyStdinTo 使用 SyscallConn + poll(2) 将 src 复制到 dst，返回取消函数和完成通道。
// 不调用 src.Fd() 以免篡改借用文件描述符的非阻塞标志，对 EAGAIN/EINTR 干净重试。
func copyStdinTo(src *os.File, dst io.Writer) (cancel func() error, done <-chan error, err error) {
	if src == nil {
		return nil, nil, fmt.Errorf("interactive stdin is nil")
	}
	rawSrc, err := src.SyscallConn()
	if err != nil {
		return nil, nil, fmt.Errorf("access interactive stdin descriptor: %w", err)
	}
	cancelR, cancelW, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("create stdin cancellation pipe failed: %w", err)
	}
	rawCancel, err := cancelR.SyscallConn()
	if err != nil {
		_ = cancelR.Close()
		_ = cancelW.Close()
		return nil, nil, fmt.Errorf("access stdin cancellation pipe failed: %w", err)
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

		buf := make([]byte, 32*1024)
		for {
			n, canceled, readErr := readStdinPollStep(rawSrc, rawCancel, buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					copyErr = fmt.Errorf("copy stdin to SSH session failed: %w", werr)
					return
				}
			}
			if canceled {
				return
			}
			if readErr != nil {
				copyErr = readErr
				return
			}
			if n == 0 {
				return
			}
		}
	}()

	var (
		cancelOnce sync.Once
		cancelErr  error
	)
	return func() error {
		cancelOnce.Do(func() {
			_, _ = cancelW.Write([]byte{1})
			if closeErr := cancelW.Close(); closeErr != nil {
				cancelErr = fmt.Errorf("close stdin cancellation writer failed: %w", closeErr)
			}
		})
		return cancelErr
	}, ch, nil
}

func readStdinPollStep(rawSrc, rawCancel syscall.RawConn, buf []byte) (n int, canceled bool, readErr error) {
	ctrlErr := rawSrc.Control(func(sfd uintptr) {
		wErr := rawCancel.Control(func(cfd uintptr) {
			fds := []unix.PollFd{
				{Fd: int32(sfd), Events: unix.POLLIN},
				{Fd: int32(cfd), Events: unix.POLLIN},
			}
			for {
				fds[0].Revents = 0
				fds[1].Revents = 0
				_, pErr := unix.Poll(fds, -1)
				if pErr != nil {
					if errors.Is(pErr, syscall.EINTR) {
						continue
					}
					readErr = fmt.Errorf("poll stdin failed: %w", pErr)
					return
				}
				if fds[1].Revents != 0 {
					canceled = true
					return
				}
				if fds[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
					readErr = fmt.Errorf("stdin poll reported invalid or failed descriptor")
					return
				}
				if fds[0].Revents&unix.POLLHUP != 0 && fds[0].Revents&unix.POLLIN == 0 {
					return
				}
				if fds[0].Revents&unix.POLLIN != 0 {
					rn, rErr := unix.Read(int(sfd), buf)
					if rErr != nil {
						if errors.Is(rErr, syscall.EINTR) || errors.Is(rErr, syscall.EAGAIN) || errors.Is(rErr, syscall.EWOULDBLOCK) {
							continue
						}
						if rn > 0 {
							n = rn
						}
						readErr = fmt.Errorf("read stdin failed: %w", rErr)
						return
					}
					n = rn
					return
				}
			}
		})
		if wErr != nil && readErr == nil && !canceled {
			readErr = wErr
		}
	})
	if ctrlErr != nil && readErr == nil && !canceled {
		readErr = ctrlErr
	}
	return n, canceled, readErr
}
