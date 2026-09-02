//go:build windows

package sftpshell

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/chzyer/readline"
	"github.com/erikgeiser/coninput"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

type windowsPromptInput struct {
	file          *os.File
	console       *windowsConsolePromptReader
	cancelEvent   windows.Handle
	stateMu       sync.Mutex
	interrupted   bool
	readers       sync.WaitGroup
	interruptOnce sync.Once
	interruptErr  error
	closeOnce     sync.Once
	closeErr      error
}

type windowsConsoleEventReader func(windows.Handle, windows.Handle) (coninput.EventRecord, error)

type windowsConsolePromptReader struct {
	handle      windows.Handle
	cancelEvent windows.Handle
	readEvent   windowsConsoleEventReader
	ctrlKey     bool
	altKey      bool
	pending     []byte
}

func duplicatePromptInput(input io.Reader) (promptInput, error) {
	file, ok := input.(*os.File)
	if !ok {
		if closer, hasCloser := input.(io.ReadCloser); hasCloser {
			return &closablePromptInput{ReadCloser: closer}, nil
		}
		return nil, fmt.Errorf("prompt input must be an *os.File or io.ReadCloser")
	}
	process := windows.CurrentProcess()
	var duplicate windows.Handle
	if err := windows.DuplicateHandle(
		process,
		windows.Handle(file.Fd()),
		process,
		&duplicate,
		0,
		false,
		windows.DUPLICATE_SAME_ACCESS,
	); err != nil {
		return nil, err
	}
	promptFile := os.NewFile(uintptr(duplicate), file.Name())
	promptInput := &windowsPromptInput{file: promptFile}
	if term.IsTerminal(int(file.Fd())) {
		cancelEvent, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			if closeErr := promptFile.Close(); closeErr != nil {
				return nil, fmt.Errorf(
					"create prompt input cancellation event failed: %w; close duplicated prompt input failed: %w",
					err,
					closeErr,
				)
			}
			return nil, fmt.Errorf("create prompt input cancellation event failed: %w", err)
		}
		promptInput.cancelEvent = cancelEvent
		promptInput.console = &windowsConsolePromptReader{
			handle:      duplicate,
			cancelEvent: cancelEvent,
			readEvent:   readWindowsConsoleEvent,
			pending:     []byte{},
		}
	}
	return promptInput, nil
}

func (i *windowsPromptInput) Read(buffer []byte) (int, error) {
	i.stateMu.Lock()
	if i.interrupted {
		i.stateMu.Unlock()
		return 0, io.EOF
	}
	i.readers.Add(1)
	i.stateMu.Unlock()
	defer i.readers.Done()

	if i.console != nil {
		return i.console.Read(buffer)
	}
	return i.file.Read(buffer)
}

func readWindowsConsoleEvent(handle, cancelEvent windows.Handle) (coninput.EventRecord, error) {
	// A console input handle is signaled while unread records are available.
	// Waiting on a separate cancellation event keeps ReadConsoleInputW itself
	// non-blocking and lets Interrupt wake the reader without touching process
	// stdin. Put cancellation first so shutdown wins if both handles are ready.
	woken, err := windows.WaitForMultipleObjects(
		[]windows.Handle{cancelEvent, handle},
		false,
		windows.INFINITE,
	)
	if err != nil {
		return nil, fmt.Errorf("wait for Windows console input failed: %w", err)
	}
	switch woken {
	case windows.WAIT_OBJECT_0:
		return nil, io.EOF
	case windows.WAIT_OBJECT_0 + 1:
	default:
		return nil, fmt.Errorf("wait for Windows console input returned unexpected result %d", woken)
	}

	records := []coninput.InputRecord{{}}
	read, err := coninput.ReadConsoleInput(handle, records)
	if err != nil {
		return nil, err
	}
	if read == 0 {
		return nil, nil
	}
	return records[0].Unwrap(), nil
}

func (r *windowsConsolePromptReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if len(r.pending) > 0 {
		return r.copyPending(buffer), nil
	}
	for {
		event, err := r.readEvent(r.handle, r.cancelEvent)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, err
			}
			return 0, fmt.Errorf("read Windows console input event failed: %w", err)
		}
		key, ok := event.(coninput.KeyEventRecord)
		if !ok {
			continue
		}
		r.pending = r.translateKeyEvent(key)
		if len(r.pending) > 0 {
			return r.copyPending(buffer), nil
		}
	}
}

func (r *windowsConsolePromptReader) copyPending(buffer []byte) int {
	copied := copy(buffer, r.pending)
	r.pending = r.pending[copied:]
	if len(r.pending) == 0 {
		r.pending = []byte{}
	}
	return copied
}

func (r *windowsConsolePromptReader) translateKeyEvent(key coninput.KeyEventRecord) []byte {
	if !key.KeyDown {
		r.releaseModifier(key.VirtualKeyCode)
		return []byte{}
	}
	if key.Char == 0 {
		return r.translateControlKey(key.VirtualKeyCode)
	}
	char := key.Char
	if r.ctrlKey {
		char = translateCtrlKey(char)
	}
	if r.altKey {
		return append([]byte{readline.CharEsc}, []byte(string(char))...)
	}
	return []byte(string(char))
}

func (r *windowsConsolePromptReader) releaseModifier(key coninput.VirtualKeyCode) {
	switch key {
	case coninput.VK_LCONTROL, coninput.VK_RCONTROL, coninput.VK_CONTROL:
		r.ctrlKey = false
	case coninput.VK_LMENU, coninput.VK_RMENU, coninput.VK_MENU:
		r.altKey = false
	}
}

func (r *windowsConsolePromptReader) translateControlKey(key coninput.VirtualKeyCode) []byte {
	switch key {
	case coninput.VK_LCONTROL, coninput.VK_RCONTROL, coninput.VK_CONTROL:
		r.ctrlKey = true
	case coninput.VK_LMENU, coninput.VK_RMENU, coninput.VK_MENU:
		r.altKey = true
	case coninput.VK_LEFT:
		return []byte{readline.CharBackward}
	case coninput.VK_RIGHT:
		return []byte{readline.CharForward}
	case coninput.VK_UP:
		return []byte{readline.CharPrev}
	case coninput.VK_DOWN:
		return []byte{readline.CharNext}
	}
	return []byte{}
}

func translateCtrlKey(char rune) rune {
	switch char {
	case 'A':
		return readline.CharLineStart
	case 'E':
		return readline.CharLineEnd
	case 'R':
		return readline.CharBckSearch
	case 'S':
		return readline.CharFwdSearch
	default:
		return char
	}
}

func (i *windowsPromptInput) Interrupt() error {
	i.interruptOnce.Do(func() {
		i.stateMu.Lock()
		i.interrupted = true
		i.stateMu.Unlock()

		var signalErr error
		if i.cancelEvent != 0 {
			signalErr = windows.SetEvent(i.cancelEvent)
		}
		handle := windows.Handle(i.file.Fd())
		cancelErr := windows.CancelIoEx(handle, nil)
		if errors.Is(cancelErr, windows.ERROR_NOT_FOUND) || errors.Is(cancelErr, windows.ERROR_INVALID_HANDLE) {
			cancelErr = nil
		}
		closeErr := i.file.Close()
		if signalErr != nil {
			i.interruptErr = fmt.Errorf("signal prompt input cancellation failed: %w", signalErr)
		}
		if cancelErr != nil {
			i.interruptErr = appendWindowsPromptInputError(i.interruptErr, "cancel prompt input failed", cancelErr)
		}
		if closeErr != nil {
			i.interruptErr = appendWindowsPromptInputError(i.interruptErr, "close prompt input failed", closeErr)
		}
	})
	return i.interruptErr
}

func (i *windowsPromptInput) Close() error {
	i.closeOnce.Do(func() {
		interruptErr := i.Interrupt()
		i.readers.Wait()
		var closeEventErr error
		if i.cancelEvent != 0 {
			closeEventErr = windows.CloseHandle(i.cancelEvent)
		}
		i.closeErr = interruptErr
		if closeEventErr != nil {
			i.closeErr = appendWindowsPromptInputError(
				i.closeErr,
				"close prompt input cancellation event failed",
				closeEventErr,
			)
		}
	})
	return i.closeErr
}

func appendWindowsPromptInputError(combined error, action string, err error) error {
	if combined == nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%w; %s: %w", combined, action, err)
}
