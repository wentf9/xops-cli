//go:build windows

package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var cancelSynchronousOutput = windows.NewLazySystemDLL("kernel32.dll").NewProc("CancelSynchronousIo")

// windowsFileOutput owns a duplicate, never the caller's handle. The mutex
// serializes writes and binding release.
// Each native call pins its OS thread until its cancellation worker joins.
type windowsFileOutput struct {
	mu       sync.Mutex
	handle   windows.Handle
	perWrite time.Duration
	closed   bool
	closeErr error
}

func prepareFileOutput(ctx context.Context, source *os.File, perWrite time.Duration) (io.Writer, func() error, error) {
	if err := cancelSynchronousOutput.Find(); err != nil {
		return nil, nil, fmt.Errorf("load native output cancellation: %w", err)
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, nil, fmt.Errorf("access native output: %w", err)
	}
	var duplicate windows.Handle
	var isNull bool
	var prepareErr error
	err = raw.Control(func(fd uintptr) {
		handle := windows.Handle(fd)
		kind, kindErr := windows.GetFileType(handle)
		if kindErr != nil {
			prepareErr = kindErr
			return
		}
		if kind == windows.FILE_TYPE_CHAR {
			isNull = windowsNullOutput(handle)
			if isNull {
				return
			}
		}
		// ConPTY backpressure can block WriteConsoleW despite repeated
		// CancelSynchronousIo calls (verified on Windows 11). Never advertise
		// console cancellation or fall back to an unbounded auxiliary write.
		if kind != windows.FILE_TYPE_PIPE {
			prepareErr = fmt.Errorf("native cancelable output requires a pipe")
			return
		}
		process := windows.CurrentProcess()
		prepareErr = windows.DuplicateHandle(process, handle, process, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS)
	})
	if err != nil || prepareErr != nil {
		if duplicate != 0 {
			prepareErr = errors.Join(prepareErr, windows.CloseHandle(duplicate))
		}
		return nil, nil, errors.Join(err, prepareErr)
	}
	if isNull {
		return contextOutput{ctx, regularFileOutput{source}, source}, func() error { return nil }, nil
	}
	output := &windowsFileOutput{handle: duplicate, perWrite: perWrite}
	return contextOutput{ctx, output, source}, output.close, nil
}

func (w *windowsFileOutput) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		w.closed = true
		w.closeErr = windows.CloseHandle(w.handle)
	}
	return w.closeErr
}

func (w *windowsFileOutput) WriteContext(ctx context.Context, data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	if w.perWrite > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, w.perWrite)
		defer cancel()
	}
	total := 0
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		chunk := data[:min(len(data), 1<<20)]
		n, err := w.writeNative(ctx, chunk)
		total += n
		if err != nil {
			return total, err
		}
		if n != len(chunk) {
			return total, io.ErrShortWrite
		}
		data = data[n:]
	}
	return total, nil
}

func (w *windowsFileOutput) writeNative(ctx context.Context, data []byte) (n int, retErr error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	thread, err := windows.OpenThread(windows.THREAD_TERMINATE, false, windows.GetCurrentThreadId())
	if err != nil {
		return 0, fmt.Errorf("open output thread: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, windows.CloseHandle(thread)) }()
	var pin runtime.Pinner
	defer pin.Unpin()
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, fmt.Errorf("create output event: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, windows.CloseHandle(event)) }()
	// The low bit suppresses IOCP delivery, including when the borrowed pipe
	// was already associated with Go's completion port. Only this request is
	// canceled; never use CancelIoEx(handle, nil) on a shared file object.
	overlapped := &windows.Overlapped{HEvent: event | 1}
	pin.Pin(overlapped)
	pin.Pin(&data[0])
	finished := make(chan struct{})
	canceled := make(chan error, 1)
	go func() { canceled <- cancelWindowsOutput(ctx, finished, thread, w.handle, overlapped) }()
	if err := ctx.Err(); err != nil {
		retErr = err
	} else {
		var written uint32
		retErr = windows.WriteFile(w.handle, data, &written, overlapped)
		if errors.Is(retErr, windows.ERROR_IO_PENDING) {
			retErr = windows.GetOverlappedResult(w.handle, overlapped, &written, true)
		}
		n = int(written)
	}
	close(finished)
	// Join before returning, unpinning the request/data, releasing its event,
	// closing the thread handle, or letting this thread run unrelated code.
	retErr = errors.Join(ctx.Err(), retErr, <-canceled)
	return n, retErr
}

func cancelWindowsOutput(ctx context.Context, finished <-chan struct{}, thread, handle windows.Handle, request *windows.Overlapped) error {
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
	}
	retry := time.NewTicker(time.Millisecond)
	defer retry.Stop()
	var cancelErr error
	for {
		select {
		case <-finished:
			return cancelErr
		default:
		}
		result, _, err := cancelSynchronousOutput.Call(uintptr(thread))
		if result == 0 && !errors.Is(err, windows.ERROR_NOT_FOUND) && cancelErr == nil {
			cancelErr = err
		}
		if request != nil {
			if err := windows.CancelIoEx(handle, request); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) && cancelErr == nil {
				cancelErr = err
			}
		}
		// ERROR_NOT_FOUND may mean cancellation beat entry into WriteFile. Keep
		// retrying until the issuing thread acknowledges completion, not just once.
		select {
		case <-finished:
			return cancelErr
		case <-retry.C:
		}
	}
}

// File IDs cannot distinguish Windows consoles, pipes and NUL. Query only
// character handles; never query a pipe with another pending I/O.
func windowsNullOutput(handle windows.Handle) bool {
	var buffer [512]uintptr
	var returned uint32
	var pin runtime.Pinner
	pin.Pin(&buffer[0])
	pin.Pin(&returned)
	defer pin.Unpin()
	status, _, _ := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryObject").Call(
		uintptr(handle), 1, uintptr(unsafe.Pointer(&buffer[0])), unsafe.Sizeof(buffer), uintptr(unsafe.Pointer(&returned)))
	if status != 0 {
		return false
	}
	name := (*windows.NTUnicodeString)(unsafe.Pointer(&buffer[0]))
	start := uintptr(unsafe.Pointer(&buffer[0]))
	value := uintptr(unsafe.Pointer(name.Buffer))
	if value < start || value+uintptr(name.Length) > start+unsafe.Sizeof(buffer) {
		return false
	}
	return name.String() == `\Device\Null`
}
