//go:build windows

package interact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/ports"
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
		return nil, fmt.Errorf("读取 Windows 控制台输入模式失败: %w", err)
	}
	muted := orig &^ windows.ENABLE_ECHO_INPUT
	if err := windows.SetConsoleMode(inH, muted); err != nil {
		runtime.KeepAlive(in)
		return nil, fmt.Errorf("禁用 Windows 控制台回显失败: %w", err)
	}
	runtime.KeepAlive(in)
	return func() error {
		err := windows.SetConsoleMode(windows.Handle(in.Fd()), orig)
		runtime.KeepAlive(in)
		return err
	}, nil
}

func readCancelableLineWindows(ctx context.Context, in *os.File) ([]byte, error) {
	stopEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("创建 Windows 取消事件失败: %w", err)
	}
	defer func() { _ = windows.CloseHandle(stopEv) }()

	inH := windows.Handle(in.Fd())
	var canceled atomic.Bool
	stop := context.AfterFunc(ctx, func() {
		canceled.Store(true)
		_ = windows.SetEvent(stopEv)
		_ = windows.CancelIoEx(inH, nil)
	})
	defer stop()
	defer runtime.KeepAlive(in)

	var out []byte
	var one [1]byte
	for len(out) < maxPromptLineBytes {
		if err := waitConsoleOrCancelWindows(ctx, stopEv, inH, &canceled); err != nil {
			clear(out)
			return nil, err
		}
		var done uint32
		rErr := windows.ReadFile(inH, one[:], &done, nil)
		if rErr != nil {
			clear(out)
			return nil, mapWindowsReadErr(ctx, rErr, &canceled)
		}
		if done == 0 {
			if len(out) > 0 {
				return out, nil
			}
			return nil, ports.ErrInteractionCanceled
		}
		if one[0] == '\n' {
			return out, nil
		}
		out = append(out, one[0])
	}
	return out, nil
}

func waitConsoleOrCancelWindows(ctx context.Context, stopEv, inH windows.Handle, canceled *atomic.Bool) error {
	if canceled.Load() {
		return ctx.Err()
	}
	ev, err := windows.WaitForMultipleObjects([]windows.Handle{stopEv, inH}, false, windows.INFINITE)
	if err != nil {
		return err
	}
	if ev == windows.WAIT_OBJECT_0 || canceled.Load() {
		if cErr := ctx.Err(); cErr != nil {
			return cErr
		}
		return ports.ErrInteractionCanceled
	}
	return nil
}

func mapWindowsReadErr(ctx context.Context, err error, canceled *atomic.Bool) error {
	if errors.Is(err, windows.ERROR_OPERATION_ABORTED) || canceled.Load() {
		if cErr := ctx.Err(); cErr != nil {
			return cErr
		}
		return ports.ErrInteractionCanceled
	}
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_HANDLE_EOF) {
		return ports.ErrInteractionCanceled
	}
	return err
}
