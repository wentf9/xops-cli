//go:build windows

package ssh

import (
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
func copyStdinTo(dst io.Writer) (cancel func(), done <-chan struct{}) {
	ch := make(chan struct{})
	once := &sync.Once{}
	closeCh := func() {
		once.Do(func() {
			close(ch)
			// 取消控制台句柄上所有当前挂起的 I/O 操作（打断任何可能被挂起的 os.Stdin.Read）
			handle := windows.Handle(os.Stdin.Fd())
			_ = windows.CancelIoEx(handle, nil)
		})
	}

	go func() {
		defer closeCh()

		handle := windows.Handle(os.Stdin.Fd())
		buf := make([]byte, 1024)

		for {
			select {
			case <-ch:
				return
			default:
			}

			var numEvents uint32
			err := windows.GetNumberOfConsoleInputEvents(handle, &numEvents)
			if err != nil {
				// Fallback to standard blocking copy if stdin is not a console handle
				_, _ = io.Copy(dst, os.Stdin)
				return
			}

			if numEvents > 0 {
				n, err := os.Stdin.Read(buf)
				if n > 0 {
					// 写入前双重检测是否已取消，避免把退出后抢读到的字符写入已关闭的目标
					select {
					case <-ch:
						return
					default:
					}
					if _, werr := dst.Write(buf[:n]); werr != nil {
						return
					}
				}
				if err != nil {
					return
				}
			} else {
				time.Sleep(20 * time.Millisecond)
			}
		}
	}()

	return closeCh, ch
}
