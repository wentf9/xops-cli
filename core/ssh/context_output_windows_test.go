//go:build windows

package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/sys/windows"
)

func windowsOutputPipe(t *testing.T, overlapped bool) (*os.File, *os.File) {
	t.Helper()
	if !overlapped {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		return reader, writer
	}
	name, err := windows.UTF16PtrFromString(fmt.Sprintf(`\\.\pipe\xops-output-%d-%d`, os.Getpid(), time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	server, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_OUTBOUND|windows.FILE_FLAG_OVERLAPPED, windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT, 1, 4096, 4096, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(server)
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(event) }()
	request := &windows.Overlapped{HEvent: event}
	// No IOCP is attached until os.NewFile below. Keep this request and its
	// backing memory alive through connection completion before reusing them.
	var pin runtime.Pinner
	pin.Pin(request)
	defer pin.Unpin()
	err = windows.ConnectNamedPipe(server, request)
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		_ = windows.CloseHandle(server)
		t.Fatal(err)
	}
	client, err := windows.CreateFile(name, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		_ = windows.CloseHandle(server)
		t.Fatal(err)
	}
	var transferred uint32
	if err := windows.GetOverlappedResult(server, request, &transferred, true); err != nil {
		_ = windows.CloseHandle(client)
		_ = windows.CloseHandle(server)
		t.Fatal(err)
	}
	return os.NewFile(uintptr(client), "owned test pipe reader"), os.NewFile(uintptr(server), "owned overlapped test pipe writer")
}

func TestWindowsOutputPipeCancellation(t *testing.T) {
	for _, mode := range []string{"synchronous", "overlapped"} {
		t.Run(mode, func(t *testing.T) {
			baseline := goleak.IgnoreCurrent()
			t.Cleanup(func() { goleak.VerifyNone(t, baseline) })
			reader, writer := windowsOutputPipe(t, mode == "overlapped")
			defer func() { _ = reader.Close(); _ = writer.Close() }()
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			bound, closeFn, supported, err := BindOutput(ctx, writer)
			if err != nil || !supported {
				t.Fatalf("pipe not bound: %v %v", supported, err)
			}
			done := make(chan error, 1)
			go func() { _, err := bound.Write(bytes.Repeat([]byte("x"), 1<<20)); done <- err }()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("pipe cancellation lost: %v", err)
				}
			case <-time.After(2 * time.Second):
				_ = reader.Close()
				<-done
				_ = closeFn()
				t.Fatal("pipe cancellation did not join")
			}
			if err := closeFn(); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Stat(); err != nil {
				t.Fatalf("borrowed handle closed: %v", err)
			}
		})
	}
}

func TestWindowsOutputPipeBorrowedHandleAndBytes(t *testing.T) {
	for _, overlapped := range []bool{false, true} {
		t.Run(fmt.Sprint(overlapped), func(t *testing.T) {
			reader, writer := windowsOutputPipe(t, overlapped)
			defer func() { _ = reader.Close(); _ = writer.Close() }()
			bound, closeFn, supported, err := BindOutput(t.Context(), writer)
			if err != nil || !supported {
				t.Fatalf("pipe not bound: %v %v", supported, err)
			}
			payload := []byte("原生 output")
			if n, err := bound.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("write: %d %v", n, err)
			}
			if err := closeFn(); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte("!")); err != nil {
				t.Fatalf("borrowed handle unusable: %v", err)
			}
			data := make([]byte, len(payload)+1)
			if _, err := io.ReadFull(reader, data); err != nil || string(data) != string(payload)+"!" {
				t.Fatalf("pipe bytes changed: %q %v", data, err)
			}
		})
	}
}

func TestWindowsOutputConsoleFallback(t *testing.T) {
	if os.Getenv("XOPS_TEST_OUTPUT_CONSOLE") == "1" {
		kernel := windows.NewLazySystemDLL("kernel32.dll")
		create := kernel.NewProc("CreateConsoleScreenBuffer")
		handle, _, callErr := create.Call(windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, 0, 1, 0)
		if windows.Handle(handle) == windows.InvalidHandle {
			t.Fatal(callErr)
		}
		file := os.NewFile(handle, "test console screen")
		defer func() { _ = file.Close() }()
		var before uint32
		if err := windows.GetConsoleMode(windows.Handle(handle), &before); err != nil {
			t.Fatal(err)
		}
		fallback, release, supported, err := BindOutput(t.Context(), file)
		if err != nil || supported || fallback != io.Writer(file) {
			t.Fatalf("console without host injection must remain unsupported: %v %v", supported, err)
		}
		if err := release(); err != nil {
			t.Fatal(err)
		}
		ctx := testConsoleRelayContext(t, t.Context(), "")
		bound, closeFn, supported, err := BindOutput(ctx, file)
		if err != nil || !supported || bound == io.Writer(file) {
			t.Fatalf("console binding failed: %v %v", supported, err)
		}
		payload := []byte("原生 console")
		if n, err := bound.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("console relay write: %d %v", n, err)
		}
		if err := closeFn(); err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("!")); err != nil {
			t.Fatalf("borrowed console unusable: %v", err)
		}
		var after uint32
		if err := windows.GetConsoleMode(windows.Handle(handle), &after); err != nil || before != after {
			t.Fatalf("console mode changed: %v", err)
		}
		if err := ctx.Value(consoleOutputRelayKey{}).(*consoleRelayScope).close(); err != nil {
			t.Fatal(err)
		}
		_, releaseClosed, supported, err := BindOutput(ctx, file)
		if err == nil || supported {
			t.Fatalf("closed scope silently fell back to direct output: %v %v", supported, err)
		}
		if err := releaseClosed(); err != nil {
			t.Fatal(err)
		}
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, exe, "-test.run=^TestWindowsOutputConsoleFallback$")
	child.Env = append(os.Environ(), "XOPS_TEST_OUTPUT_CONSOLE=1")
	child.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE}
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("native console helper: %v\n%s", err, output)
	}
}
