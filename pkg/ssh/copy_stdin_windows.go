//go:build windows

package ssh

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// copyStdinTo 在 Windows 上通过非阻塞轮询控制台输入事件数实现。
// 仅在事件数 > 0 时才去真正调用 os.Stdin.Read，避免发生永久阻塞。
// 这样在退出交互式环境时，通过 cancel 信号能瞬间干净地退出，
// 绝不会因为悬挂读取导致后续第一个字符被吞。
func copyStdinTo(src *os.File, dst io.Writer) (cancel func() error, done <-chan error, err error) {
	if src == nil {
		return nil, nil, fmt.Errorf("interactive stdin is nil")
	}
	cancelCh := make(chan struct{})
	doneCh := make(chan error, 1)
	once := &sync.Once{}
	var cancelErr error
	cancelCopy := func() error {
		once.Do(func() {
			close(cancelCh)
			// 取消控制台句柄上所有当前挂起的 I/O 操作（打断任何可能被挂起的 os.Stdin.Read）
			handle := windows.Handle(src.Fd())
			if err := windows.CancelIoEx(handle, nil); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) {
				cancelErr = fmt.Errorf("cancel stdin read failed: %w", err)
			}
		})
		return cancelErr
	}

	go func() {
		var copyErr error
		defer func() {
			doneCh <- copyErr
			close(doneCh)
		}()

		handle := windows.Handle(src.Fd())
		buf := make([]byte, 1024)

		for {
			select {
			case <-cancelCh:
				return
			default:
			}

			var numEvents uint32
			err := windows.GetNumberOfConsoleInputEvents(handle, &numEvents)
			if err != nil {
				// Fallback to standard blocking copy if stdin is not a console handle
				_, copyErr = io.Copy(dst, src)
				select {
				case <-cancelCh:
					copyErr = nil
				default:
					if copyErr != nil {
						copyErr = fmt.Errorf("copy stdin to SSH session failed: %w", copyErr)
					}
				}
				return
			}

			if numEvents > 0 {
				n, err := src.Read(buf)
				if n > 0 {
					// 写入前双重检测是否已取消，避免把退出后抢读到的字符写入已关闭的目标
					select {
					case <-cancelCh:
						return
					default:
					}
					if _, werr := dst.Write(buf[:n]); werr != nil {
						copyErr = fmt.Errorf("copy stdin to SSH session failed: %w", werr)
						return
					}
				}
				if err != nil {
					copyErr = fmt.Errorf("read stdin failed: %w", err)
					return
				}
			} else {
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()

	return cancelCopy, doneCh, nil
}
