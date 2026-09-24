//go:build windows

package terminal

import (
	"errors"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/sys/windows"
)

var peekNamedPipe = windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekNamedPipe")

const pipeInputPollMilliseconds = 10

// Anonymous and named stdin pipes may be synchronous: a one-shot CancelIoEx
// can run before ReadFile submits its request, leaving Close waiting forever.
// With exclusive ownership of stdin, read only bytes already buffered in the
// pipe. An idle pipe waits on cancellation instead of starting a blocking read.
func (i *windowsPromptInput) readPipe(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	for {
		n, ready, err := i.readAvailablePipe(buffer)
		if ready || err != nil {
			return n, err
		}
		// Windows pipes do not provide a readable-data wait handle. Poll data
		// availability at a bounded interval; cancellation wakes immediately.
		woken, err := windows.WaitForSingleObject(i.cancelEvent, pipeInputPollMilliseconds)
		if err != nil {
			return 0, fmt.Errorf("wait for pipe input cancellation failed: %w", err)
		}
		switch woken {
		case windows.WAIT_OBJECT_0:
			return 0, io.EOF
		case uint32(windows.WAIT_TIMEOUT):
		default:
			return 0, fmt.Errorf("wait for pipe input returned unexpected result %d", woken)
		}
	}
}

func (i *windowsPromptInput) readAvailablePipe(buffer []byte) (int, bool, error) {
	// Serialize reads with each other and with cancellation. Once Interrupt
	// returns, no late reader may consume bytes intended for the next owner.
	i.stateMu.Lock()
	defer i.stateMu.Unlock()
	if i.interrupted {
		return 0, false, io.EOF
	}
	available, err := availablePipeBytes(i.handle)
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) {
		return 0, false, io.EOF
	}
	if err != nil {
		return 0, false, fmt.Errorf("inspect buffered pipe input failed: %w", err)
	}
	if available == 0 {
		return 0, false, nil
	}
	// The sole reader holds stateMu from peek through read, so these bytes
	// cannot be consumed by another owned read in between. Do not change the
	// borrowed pipe's mode or close its writer to interrupt an empty read.
	size := min(uint64(len(buffer)), uint64(available))
	n, err := i.file.Read(buffer[:size])
	return n, true, err
}

func availablePipeBytes(handle windows.Handle) (uint32, error) {
	var available uint32
	result, _, err := peekNamedPipe.Call(uintptr(handle), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
	if result == 0 {
		return 0, err
	}
	return available, nil
}
