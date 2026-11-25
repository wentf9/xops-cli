//go:build windows

package sys

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/ports"
	"golang.org/x/sys/windows"
)

const windowsResizePollInterval = 100 * time.Millisecond

func probeFileInteractive(in, out *os.File) (bool, error) {
	if in == nil || out == nil {
		return false, nil
	}
	var inMode, outMode uint32
	inErr := windows.GetConsoleMode(windows.Handle(in.Fd()), &inMode)
	runtime.KeepAlive(in)
	if inErr != nil {
		return false, nil
	}
	outErr := windows.GetConsoleMode(windows.Handle(out.Fd()), &outMode)
	runtime.KeepAlive(out)
	return outErr == nil, nil
}

func queryFileSize(_, out *os.File) (ports.TerminalSize, error) {
	var info windows.ConsoleScreenBufferInfo
	err := windows.GetConsoleScreenBufferInfo(windows.Handle(out.Fd()), &info)
	runtime.KeepAlive(out)
	if err != nil {
		return zeroVal[ports.TerminalSize](), fmt.Errorf("查询 Windows 控制台窗口尺寸失败: %w", err)
	}
	cols := int(info.Window.Right - info.Window.Left + 1)
	rows := int(info.Window.Bottom - info.Window.Top + 1)
	if cols <= 0 || rows <= 0 {
		return zeroVal[ports.TerminalSize](), fmt.Errorf("%w: Windows 控制台返回非正尺寸 %dx%d", ports.ErrInvalidTTYSize, cols, rows)
	}
	return ports.NewTerminalSize(uint16(cols), uint16(rows))
}

func enterRawFileOS(in, out *os.File) (func() error, error) {
	inH, outH := windows.Handle(in.Fd()), windows.Handle(out.Fd())
	var origIn, origOut uint32
	if err := windows.GetConsoleMode(inH, &origIn); err != nil {
		runtime.KeepAlive(in)
		return nil, fmt.Errorf("读取 Windows 控制台输入模式失败: %w", err)
	}
	if err := windows.GetConsoleMode(outH, &origOut); err != nil {
		runtime.KeepAlive(out)
		return nil, fmt.Errorf("读取 Windows 控制台输出模式失败: %w", err)
	}

	// 窗口缩放由 watchResizeOS 经 GetConsoleScreenBufferInfo 独立监测，显式屏蔽 WINDOW/MOUSE 事件，
	// 防止非字符事件虚假唤醒 WaitForMultipleObjects 导致随后的 ReadFile 意外阻塞。
	rawIn := (origIn &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_PROCESSED_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_WINDOW_INPUT | windows.ENABLE_MOUSE_INPUT)) |
		windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	if err := windows.SetConsoleMode(inH, rawIn); err != nil {
		runtime.KeepAlive(in)
		return nil, fmt.Errorf("切换 Windows 控制台至原始 VT 输入模式失败: %w", err)
	}
	// 启用 VT 输出处理以兼容 ConPTY ANSI 序列；旧版控制台不支持时回退保留原输出模式。
	rawOut := origOut | windows.ENABLE_PROCESSED_OUTPUT | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	outChanged := windows.SetConsoleMode(outH, rawOut) == nil
	runtime.KeepAlive(in)
	runtime.KeepAlive(out)

	var restoreOnce sync.Once
	var restoreErr error
	return func() error {
		restoreOnce.Do(func() {
			inErr := windows.SetConsoleMode(windows.Handle(in.Fd()), origIn)
			var outErr error
			if outChanged {
				outErr = windows.SetConsoleMode(windows.Handle(out.Fd()), origOut)
			}
			runtime.KeepAlive(in)
			runtime.KeepAlive(out)
			restoreErr = errors.Join(inErr, outErr)
		})
		return restoreErr
	}, nil
}

func watchResizeOS(ctx context.Context, in, out *os.File, dst chan ports.TerminalSize) error {
	last, _ := queryFileSize(in, out)
	ticker := time.NewTicker(windowsResizePollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			sz, err := queryFileSize(in, out)
			if err == nil && sz.IsValid() && !sz.Equal(last) {
				last = sz
				pushLatestResize(dst, sz)
			}
		}
	}
}

type windowsCancelableFileReader struct {
	in        *os.File
	stopEv    windows.Handle
	isConsole bool
	canceled  atomic.Bool
	reading   atomic.Bool
	unblockDo sync.Once
	closeDo   sync.Once
}

func newCancelableFileReaderOS(in *os.File) (io.Reader, func(), func(), error) {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("创建 Windows 终端取消事件失败: %w", err)
	}
	var mode uint32
	isConsole := windows.GetConsoleMode(windows.Handle(in.Fd()), &mode) == nil
	runtime.KeepAlive(in)
	r := &windowsCancelableFileReader{in: in, stopEv: ev, isConsole: isConsole}
	return r, r.unblock, r.close, nil
}

func (r *windowsCancelableFileReader) unblock() {
	r.unblockDo.Do(func() {
		r.canceled.Store(true)
		_ = windows.SetEvent(r.stopEv)
		r.cancelPendingRead()
	})
}

// cancelPendingRead 通过 Dekker 原子屏障（canceled 与 reading）闭合 unblock 与 ReadFile 之间的 TOCTOU 竞态，
// 当 Read 已越过检查正进入内核同步读取时重发 CancelIoEx 直至其退出，避免遗漏取消导致永久阻塞。
func (r *windowsCancelableFileReader) cancelPendingRead() {
	inH := windows.Handle(r.in.Fd())
	defer runtime.KeepAlive(r.in)
	for {
		err := windows.CancelIoEx(inH, nil)
		if !r.reading.Load() || errors.Is(err, windows.ERROR_INVALID_HANDLE) {
			return
		}
		if err == nil {
			runtime.Gosched()
			continue
		}
		timer := time.NewTimer(time.Millisecond)
		<-timer.C
	}
}

func (r *windowsCancelableFileReader) close() {
	r.unblock()
	r.closeDo.Do(func() { _ = windows.CloseHandle(r.stopEv) })
}

func (r *windowsCancelableFileReader) Read(p []byte) (int, error) {
	r.reading.Store(true)
	defer r.reading.Store(false)
	if r.canceled.Load() {
		return 0, errInputCanceled
	}
	inH := windows.Handle(r.in.Fd())
	if err := r.waitConsoleReady(inH); err != nil {
		return 0, err
	}
	if r.canceled.Load() {
		return 0, errInputCanceled
	}
	var done uint32
	err := windows.ReadFile(inH, p, &done, nil)
	runtime.KeepAlive(r.in)
	return r.mapReadResult(done, err)
}

func (r *windowsCancelableFileReader) waitConsoleReady(inH windows.Handle) error {
	if !r.isConsole {
		return nil
	}
	// 将 stopEv 置于索引 0，保证在取消与输入同时就绪时优先确定性退出。
	ev, err := windows.WaitForMultipleObjects([]windows.Handle{r.stopEv, inH}, false, windows.INFINITE)
	runtime.KeepAlive(r.in)
	if err != nil {
		return err
	}
	if ev == windows.WAIT_OBJECT_0 || r.canceled.Load() {
		return errInputCanceled
	}
	return nil
}

func (r *windowsCancelableFileReader) mapReadResult(done uint32, err error) (int, error) {
	if err != nil {
		if errors.Is(err, windows.ERROR_OPERATION_ABORTED) || r.canceled.Load() {
			return 0, errInputCanceled
		}
		if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return 0, io.EOF
		}
		return 0, err
	}
	if done == 0 {
		return 0, io.EOF
	}
	return int(done), nil
}
