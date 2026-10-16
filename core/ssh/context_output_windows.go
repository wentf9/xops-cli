//go:build windows

package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsConsoleRelayChunk = 16 << 10

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

// windowsConsoleOutput owns a duplicate console screen-buffer handle and a
// lazily started host-selected relay subprocess connected via anonymous pipes. Main
// process writes and ACKs use pipe I/O that cancels deterministically with
// CancelIoEx/CancelSynchronousIo; canceling a stalled ConPTY write terminates
// the relay subprocess without closing or mutating the caller's console handle.
type windowsConsoleOutput struct {
	mu           sync.Mutex
	handle       windows.Handle
	relay        ConsoleOutputRelay
	perWrite     time.Duration
	reqWriter    windows.Handle
	ackReader    windows.Handle
	relayProcess windows.Handle
	frame        []byte
	closed       bool
	closeErr     error
	job          windows.Handle
	source       io.Writer // Borrowed sink identity for cleanup errors; never closed.
	owner        *consoleRelayScope
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
	var isConsole bool
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
			isConsole = windowsConsoleScreenBuffer(handle)
			if isConsole {
				scope, _ := ctx.Value(consoleOutputRelayKey{}).(*consoleRelayScope)
				if scope == nil || scope.config.Executable == "" {
					prepareErr = fmt.Errorf("console output requires a host-injected relay")
					return
				}
			}
		}
		if !isConsole && kind != windows.FILE_TYPE_PIPE {
			prepareErr = fmt.Errorf("native cancelable output requires a console or pipe")
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
	if isConsole {
		scope := ctx.Value(consoleOutputRelayKey{}).(*consoleRelayScope)
		output := &windowsConsoleOutput{handle: duplicate, relay: scope.config, perWrite: perWrite, source: source, owner: scope}
		if err := scope.add(output); err != nil {
			return nil, nil, &OutputError{Target: source, Err: errors.Join(err, windows.CloseHandle(duplicate))}
		}
		return contextOutput{ctx, output, source}, output.close, nil
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
	return transferWindowsHandle(ctx, w.handle, data, true)
}

func (w *windowsConsoleOutput) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	// Failed stops stay registered with the command scope, even after this
	// binding's local defer returns. Scope cleanup owns the next attempt.
	stopErr := w.stopRelay(false)
	if w.handle != 0 {
		w.closeErr = errors.Join(w.closeErr, windows.CloseHandle(w.handle))
		w.handle = 0
	}
	if w.relayProcess == 0 && w.job == 0 {
		w.owner.remove(w)
	}
	if err := errors.Join(w.closeErr, stopErr); err != nil {
		return &OutputError{Target: w.source, Err: err}
	}
	return nil
}

func (w *windowsConsoleOutput) WriteContext(ctx context.Context, data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, os.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}
	if w.perWrite > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, w.perWrite)
		defer cancel()
	}
	total := 0
	var ack [8]byte
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		if err := w.ensureRelay(); err != nil {
			return total, err
		}
		chunk := data[:min(len(data), windowsConsoleRelayChunk)]
		frameLen := 4 + len(chunk)
		binary.LittleEndian.PutUint32(w.frame[:4], uint32(len(chunk)))
		copy(w.frame[4:frameLen], chunk)
		if err := writeAllWindowsHandle(ctx, w.reqWriter, w.frame[:frameLen]); err != nil {
			return total, errors.Join(err, w.stopRelay(true))
		}
		if err := readAllWindowsHandle(ctx, w.ackReader, ack[:]); err != nil {
			return total, errors.Join(err, w.stopRelay(true))
		}
		written := min(int(binary.LittleEndian.Uint32(ack[:4])), len(chunk))
		errCode := binary.LittleEndian.Uint32(ack[4:8])
		total += written
		if errCode != 0 {
			return total, errors.Join(syscall.Errno(errCode), w.stopRelay(true))
		}
		if written != len(chunk) {
			return total, errors.Join(io.ErrShortWrite, w.stopRelay(true))
		}
		data = data[written:]
	}
	return total, nil
}

func (w *windowsConsoleOutput) ensureRelay() error {
	if w.relayProcess != 0 {
		return nil
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{}))}
	var reqReader, reqWriter windows.Handle
	if err := windows.CreatePipe(&reqReader, &reqWriter, sa, windowsConsoleRelayChunk+64); err != nil {
		return fmt.Errorf("create console output request pipe: %w", err)
	}
	var ackReader, ackWriter windows.Handle
	if err := windows.CreatePipe(&ackReader, &ackWriter, sa, 64); err != nil {
		_ = windows.CloseHandle(reqReader)
		_ = windows.CloseHandle(reqWriter)
		return fmt.Errorf("create console output ack pipe: %w", err)
	}
	process := windows.CurrentProcess()
	var childConsole windows.Handle
	if err := windows.DuplicateHandle(process, w.handle, process, &childConsole, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
		_ = windows.CloseHandle(reqReader)
		_ = windows.CloseHandle(reqWriter)
		_ = windows.CloseHandle(ackReader)
		_ = windows.CloseHandle(ackWriter)
		return fmt.Errorf("duplicate console handle for relay: %w", err)
	}
	if err := errors.Join(
		windows.SetHandleInformation(reqReader, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT),
		windows.SetHandleInformation(ackWriter, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT),
	); err != nil {
		_ = windows.CloseHandle(reqReader)
		_ = windows.CloseHandle(reqWriter)
		_ = windows.CloseHandle(ackReader)
		_ = windows.CloseHandle(ackWriter)
		_ = windows.CloseHandle(childConsole)
		return fmt.Errorf("configure console relay pipe inheritance: %w", err)
	}
	spec := fmt.Sprintf("%d,%d,%d", uintptr(reqReader), uintptr(ackWriter), uintptr(childConsole))
	procHandle, job, startErr := startWindowsConsoleRelay(w.relay, spec, []windows.Handle{reqReader, ackWriter, childConsole})
	childCloseErr := errors.Join(
		windows.CloseHandle(reqReader),
		windows.CloseHandle(ackWriter),
		windows.CloseHandle(childConsole),
	)
	if procHandle == 0 {
		return fmt.Errorf("start console output relay: %w", errors.Join(startErr, childCloseErr,
			windows.CloseHandle(reqWriter), windows.CloseHandle(ackReader)))
	}
	w.reqWriter = reqWriter
	w.ackReader = ackReader
	w.relayProcess = procHandle
	w.job = job
	if startErr != nil || childCloseErr != nil {
		w.closed = true
		return errors.Join(startErr, childCloseErr, w.stopRelay(true))
	}
	if len(w.frame) < 4+windowsConsoleRelayChunk {
		w.frame = make([]byte, 4+windowsConsoleRelayChunk)
	}
	return nil
}

func (w *windowsConsoleOutput) stopRelay(kill bool) error {
	if kill {
		w.closed = true
	}
	if w.relayProcess == 0 {
		return nil
	}
	var closeErr error
	if w.reqWriter != 0 {
		closeErr = windows.CloseHandle(w.reqWriter)
		w.reqWriter = 0
	}
	wait := uint32(200)
	if kill {
		wait = 0
	}
	status, err := windows.WaitForSingleObject(w.relayProcess, wait)
	if err != nil {
		w.closed = true
		return errors.Join(closeErr, fmt.Errorf("wait for console relay: %w", err))
	}
	if status != windows.WAIT_OBJECT_0 {
		if err := w.terminateRelay(); err != nil {
			// The process can exit between waiting and requesting termination.
			if exited, waitErr := windows.WaitForSingleObject(w.relayProcess, 0); waitErr != nil || exited != windows.WAIT_OBJECT_0 {
				w.closed = true
				return errors.Join(closeErr, fmt.Errorf("terminate console relay: %w", err), waitErr)
			}
		}
		// TerminateProcess is asynchronous. Never discard ownership or claim
		// successful cleanup until the process object is signaled. A timeout
		// is an explicit cleanup failure, retaining handles for Close to retry.
		status, err = windows.WaitForSingleObject(w.relayProcess, 5000)
		if err != nil || status != windows.WAIT_OBJECT_0 {
			w.closed = true
			return errors.Join(closeErr, fmt.Errorf("console relay exit not confirmed (wait=%d): %w", status, errors.Join(err, context.DeadlineExceeded)))
		}
	}
	closeErr = errors.Join(closeErr, windows.CloseHandle(w.ackReader), windows.CloseHandle(w.relayProcess))
	w.ackReader = 0
	w.relayProcess = 0
	if w.job != 0 {
		closeErr = errors.Join(closeErr, windows.CloseHandle(w.job))
		w.job = 0
	}
	return closeErr
}

func (w *windowsConsoleOutput) terminateRelay() error {
	if w.job != 0 {
		return windows.TerminateJobObject(w.job, 1)
	}
	return windows.TerminateProcess(w.relayProcess, 1)
}

func writeAllWindowsHandle(ctx context.Context, handle windows.Handle, data []byte) error {
	for len(data) > 0 {
		n, err := transferWindowsHandle(ctx, handle, data, true)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func readAllWindowsHandle(ctx context.Context, handle windows.Handle, data []byte) error {
	for len(data) > 0 {
		n, err := transferWindowsHandle(ctx, handle, data, false)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}

func transferWindowsHandle(ctx context.Context, handle windows.Handle, data []byte, write bool) (n int, retErr error) {
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
	go func() { canceled <- cancelWindowsOutput(ctx, finished, thread, handle, overlapped) }()
	if err := ctx.Err(); err != nil {
		retErr = err
	} else {
		var transferred uint32
		if write {
			retErr = windows.WriteFile(handle, data, &transferred, overlapped)
		} else {
			retErr = windows.ReadFile(handle, data, &transferred, overlapped)
		}
		if errors.Is(retErr, windows.ERROR_IO_PENDING) {
			retErr = windows.GetOverlappedResult(handle, overlapped, &transferred, true)
		}
		n = int(transferred)
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

func windowsConsoleScreenBuffer(handle windows.Handle) bool {
	var info windows.ConsoleScreenBufferInfo
	if windows.GetConsoleScreenBufferInfo(handle, &info) == nil {
		return true
	}
	var mode uint32
	if windows.GetConsoleMode(handle, &mode) != nil {
		return false
	}
	var events uint32
	return windows.GetNumberOfConsoleInputEvents(handle, &events) != nil
}

// ServeConsoleOutputRelay runs only when explicitly dispatched by a Windows
// host entry point. It returns an exit code and never exits the host itself.
// spec contains only inherited handles, not paths, commands, or credentials.
func ServeConsoleOutputRelay(spec string) int {
	reqHandle, ackHandle, consoleHandle, err := parseWindowsConsoleRelaySpec(spec)
	if err != nil {
		return 2
	}
	if !windowsConsoleScreenBuffer(consoleHandle) {
		return 2
	}
	for _, handle := range []windows.Handle{reqHandle, ackHandle} {
		if kind, err := windows.GetFileType(handle); err != nil || kind != windows.FILE_TYPE_PIPE {
			return 2
		}
	}
	consoleFile := os.NewFile(uintptr(consoleHandle), "console")
	if consoleFile == nil {
		return 2
	}
	defer func() { _ = consoleFile.Close() }()
	return serveWindowsConsoleOutput(reqHandle, ackHandle, consoleFile)
}

func serveWindowsConsoleOutput(reqHandle, ackHandle windows.Handle, console io.Writer) int {
	var header [4]byte
	buf := make([]byte, windowsConsoleRelayChunk)
	var ack [8]byte
	for {
		if err := readFullSyncWindowsHandle(reqHandle, header[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, windows.ERROR_BROKEN_PIPE) {
				return 0
			}
			return 1
		}
		length := binary.LittleEndian.Uint32(header[:])
		if length == 0 || length > windowsConsoleRelayChunk {
			return 1
		}
		chunk := buf[:length]
		if err := readFullSyncWindowsHandle(reqHandle, chunk); err != nil {
			return 1
		}
		written, writeErr := console.Write(chunk)
		if written < 0 {
			written = 0
		}
		binary.LittleEndian.PutUint32(ack[:4], uint32(written))
		var errCode uint32
		if writeErr != nil {
			var errno syscall.Errno
			if errors.As(writeErr, &errno) {
				errCode = uint32(errno)
			}
			if errCode == 0 {
				errCode = uint32(windows.ERROR_GEN_FAILURE)
			}
		}
		binary.LittleEndian.PutUint32(ack[4:8], errCode)
		if err := writeFullSyncWindowsHandle(ackHandle, ack[:]); err != nil {
			return 1
		}
		if writeErr != nil {
			return 0
		}
	}
}

func parseWindowsConsoleRelaySpec(spec string) (req, ack, console windows.Handle, err error) {
	parts := strings.Split(spec, ",")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("invalid console relay spec")
	}
	var handles [3]windows.Handle
	for i, part := range parts {
		val, parseErr := strconv.ParseUint(part, 10, 64)
		if parseErr != nil || val == 0 || uint64(uintptr(val)) != val || windows.Handle(uintptr(val)) == windows.InvalidHandle {
			return 0, 0, 0, fmt.Errorf("invalid console relay handle")
		}
		handles[i] = windows.Handle(uintptr(val))
	}
	return handles[0], handles[1], handles[2], nil
}

func readFullSyncWindowsHandle(handle windows.Handle, data []byte) error {
	for len(data) > 0 {
		var read uint32
		err := windows.ReadFile(handle, data, &read, nil)
		if err != nil {
			return err
		}
		if read == 0 {
			return io.EOF
		}
		data = data[read:]
	}
	return nil
}

func writeFullSyncWindowsHandle(handle windows.Handle, data []byte) error {
	for len(data) > 0 {
		var written uint32
		err := windows.WriteFile(handle, data, &written, nil)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
