//go:build windows

package interact

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/ports"
	"github.com/wentf9/xops-cli/internal/i18n"
	"golang.org/x/sys/windows"
)

func probeFileTTYOS(in, out *os.File) (bool, error) {
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

// Windows 不支持回退 /dev/tty，管道化标准输入必须严格失败关闭返回 ports.ErrInteractionUnavailable。
func probeControllingTTYOS() (bool, error) { return false, nil }

func promptTTYLineOS(ctx context.Context, in, out *os.File, _ bool, prompt string, noEcho bool) ([]byte, error) {
	if isTTY, _ := probeFileTTYOS(in, out); !isTTY {
		return nil, ports.ErrInteractionUnavailable
	}
	if _, err := io.WriteString(out, prompt); err != nil {
		return nil, err
	}
	if noEcho {
		restore, err := disableEchoWindowsConsole(in)
		if err != nil {
			return nil, err
		}
		defer func() {
			_ = restore()
			_, _ = io.WriteString(out, "\r\n")
		}()
	}
	return readCancelableLineWindows(ctx, in)
}

func disableEchoWindowsConsole(in *os.File) (func() error, error) {
	inH := windows.Handle(in.Fd())
	var orig uint32
	if err := windows.GetConsoleMode(inH, &orig); err != nil {
		runtime.KeepAlive(in)
		return nil, i18n.Wrap(err, i18n.KeyInteractWinReadConsole)
	}
	muted := orig &^ windows.ENABLE_ECHO_INPUT
	if err := windows.SetConsoleMode(inH, muted); err != nil {
		runtime.KeepAlive(in)
		return nil, i18n.Wrap(err, i18n.KeyInteractWinDisableEcho)
	}
	runtime.KeepAlive(in)
	return func() error {
		err := windows.SetConsoleMode(windows.Handle(in.Fd()), orig)
		runtime.KeepAlive(in)
		return err
	}, nil
}

// readCancelableLineWindows 借助 AfterFunc 退出屏障与 Dekker (canceled/reading) CancelIoEx 循环读取控制台单行，
// 防止关闭 stopEv 时发生 Win32 句柄释放后使用竞态，并杜绝取消落入 WaitForMultipleObjects->ReadFile 间隙导致挂死。
func readCancelableLineWindows(ctx context.Context, in *os.File) ([]byte, error) {
	stopEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, i18n.Wrap(err, i18n.KeyInteractWinCancelEvent)
	}
	inH := windows.Handle(in.Fd())
	var canceled, reading atomic.Bool
	afterDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(afterDone)
		canceled.Store(true)
		_ = windows.SetEvent(stopEv)
		cancelPendingConsoleRead(in, &reading)
	})
	defer func() {
		if !stop() {
			<-afterDone
		}
		_ = windows.CloseHandle(stopEv)
		runtime.KeepAlive(in)
	}()

	return scanWindowsConsoleLine(ctx, inH, stopEv, &canceled, &reading)
}

func scanWindowsConsoleLine(ctx context.Context, inH, stopEv windows.Handle, canceled, reading *atomic.Bool) ([]byte, error) {
	var out []byte
	var one [1]byte
	for {
		n, err := readSingleWindowsByte(ctx, inH, stopEv, canceled, reading, one[:])
		if err != nil {
			clear(out)
			return nil, err
		}
		if n == 0 {
			if len(out) > 0 {
				return out, nil
			}
			return nil, ports.ErrInteractionCanceled
		}
		if one[0] == '\n' {
			return out, nil
		}
		if len(out) >= maxPromptLineBytes {
			clear(out)
			drainWindowsConsoleToNewline(ctx, inH, stopEv, canceled, reading)
			return nil, i18n.EF(ports.ErrLimitExceeded, i18n.KeyInteractLineTooLong, i18n.Int("max", maxPromptLineBytes))
		}
		out = append(out, one[0])
	}
}

func readSingleWindowsByte(ctx context.Context, inH, stopEv windows.Handle, canceled, reading *atomic.Bool, one []byte) (int, error) {
	if err := waitConsoleOrCancelWindows(ctx, stopEv, inH, canceled); err != nil {
		return 0, err
	}
	reading.Store(true)
	defer reading.Store(false)
	if canceled.Load() {
		return 0, mapWindowsCancelErr(ctx)
	}
	var done uint32
	if err := windows.ReadFile(inH, one, &done, nil); err != nil {
		return 0, mapWindowsReadErr(ctx, err, canceled)
	}
	return int(done), nil
}

func drainWindowsConsoleToNewline(ctx context.Context, inH, stopEv windows.Handle, canceled, reading *atomic.Bool) {
	var one [1]byte
	for {
		n, err := readSingleWindowsByte(ctx, inH, stopEv, canceled, reading, one[:])
		if err != nil || n == 0 || one[0] == '\n' {
			return
		}
	}
}

func cancelPendingConsoleRead(in *os.File, reading *atomic.Bool) {
	inH := windows.Handle(in.Fd())
	defer runtime.KeepAlive(in)
	for {
		err := windows.CancelIoEx(inH, nil)
		if !reading.Load() || errors.Is(err, windows.ERROR_INVALID_HANDLE) {
			return
		}
		if err == nil {
			runtime.Gosched()
			continue
		}
		tm := time.NewTimer(time.Millisecond)
		<-tm.C
	}
}

func waitConsoleOrCancelWindows(ctx context.Context, stopEv, inH windows.Handle, canceled *atomic.Bool) error {
	if canceled.Load() {
		return mapWindowsCancelErr(ctx)
	}
	ev, err := windows.WaitForMultipleObjects([]windows.Handle{stopEv, inH}, false, windows.INFINITE)
	if err != nil {
		return err
	}
	if ev == windows.WAIT_OBJECT_0 || canceled.Load() {
		return mapWindowsCancelErr(ctx)
	}
	return nil
}

func mapWindowsCancelErr(ctx context.Context) error {
	if cErr := ctx.Err(); cErr != nil {
		return cErr
	}
	return ports.ErrInteractionCanceled
}

func mapWindowsReadErr(ctx context.Context, err error, canceled *atomic.Bool) error {
	if errors.Is(err, windows.ERROR_OPERATION_ABORTED) || canceled.Load() {
		return mapWindowsCancelErr(ctx)
	}
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_HANDLE_EOF) {
		return ports.ErrInteractionCanceled
	}
	return err
}
