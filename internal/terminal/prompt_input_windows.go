//go:build windows

package terminal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"unicode/utf16"

	"github.com/erikgeiser/coninput"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

type windowsPromptInput struct {
	file          *os.File
	handle        windows.Handle
	pipe          bool
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

// Match the Windows OpenSSH input batch size. A batch is a byte-stream chunk,
// not an ANSI message boundary; consumers must tolerate split sequences.
const windowsConsoleInputBatchSize = 1024

type windowsConsoleEvents struct {
	records []coninput.EventRecord
	mode    uint32
}

type windowsConsoleEventReader func(windows.Handle, windows.Handle, int) (windowsConsoleEvents, error)

type windowsConsolePromptReader struct {
	handle        windows.Handle
	cancelEvent   windows.Handle
	readEvent     windowsConsoleEventReader
	interactive   bool
	ctrlKey       bool
	altKey        bool
	pending       []byte
	highSurrogate rune
}

// DuplicatePromptInput duplicates an input stream and equips it with an interrupt mechanism for Windows.
func DuplicatePromptInput(input io.Reader) (PromptInput, error) {
	return duplicateWindowsInput(input, false)
}

// DuplicateInteractiveInput preserves terminal key sequences for SSH PTY input,
// using an owned handle and a cancellation event instead of reading os.Stdin.
func DuplicateInteractiveInput(input *os.File) (PromptInput, error) {
	return duplicateWindowsInput(input, true)
}

func duplicateWindowsInput(input io.Reader, interactive bool) (PromptInput, error) {
	file, ok := input.(*os.File)
	if !ok {
		if closer, hasCloser := input.(io.ReadCloser); hasCloser {
			return &ClosablePromptInput{ReadCloser: closer}, nil
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
	fileType, err := windows.GetFileType(duplicate)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("inspect duplicated prompt input failed: %w", err), promptFile.Close())
	}
	isConsole := term.IsTerminal(int(duplicate))
	promptInput := &windowsPromptInput{file: promptFile, handle: duplicate, pipe: fileType == windows.FILE_TYPE_PIPE}
	if isConsole || promptInput.pipe {
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
	}
	if isConsole {
		promptInput.console = &windowsConsolePromptReader{
			interactive: interactive,
			handle:      duplicate,
			cancelEvent: promptInput.cancelEvent,
			readEvent:   readWindowsConsoleEvents,
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
	if i.pipe {
		return i.readPipe(buffer)
	}
	return i.file.Read(buffer)
}

func readWindowsConsoleEvents(handle, cancelEvent windows.Handle, limit int) (windowsConsoleEvents, error) {
	woken, err := windows.WaitForMultipleObjects(
		[]windows.Handle{cancelEvent, handle},
		false,
		windows.INFINITE,
	)
	if err != nil {
		return windowsConsoleEvents{}, fmt.Errorf("wait for Windows console input failed: %w", err)
	}
	switch woken {
	case windows.WAIT_OBJECT_0:
		return windowsConsoleEvents{}, io.EOF
	case windows.WAIT_OBJECT_0 + 1:
	default:
		return windowsConsoleEvents{}, fmt.Errorf("wait for Windows console input returned unexpected result %d", woken)
	}

	// Read the mode here rather than when duplicating the handle: the SFTP
	// editor creates its reader before enabling raw/VT input.
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return windowsConsoleEvents{}, fmt.Errorf("read Windows console input mode failed: %w", err)
	}
	records := make([]coninput.InputRecord, limit)
	read, err := coninput.ReadConsoleInput(handle, records)
	if err != nil {
		return windowsConsoleEvents{}, err
	}
	if read == 0 {
		return windowsConsoleEvents{}, nil
	}
	events := make([]coninput.EventRecord, read)
	for index := range events {
		events[index] = records[index].Unwrap()
	}
	return windowsConsoleEvents{records: events, mode: mode}, nil
}

func (r *windowsConsolePromptReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if len(r.pending) > 0 {
		return r.copyPending(buffer), nil
	}
	// Forward available console input in batches, without adding a timer or
	// parsing ANSI sequences. Plain prompts retain single-event reads to avoid
	// consuming the next prompt's input.
	limit := 1
	if r.interactive {
		limit = windowsConsoleInputBatchSize
	}
	for {
		events, err := r.readEvent(r.handle, r.cancelEvent, limit)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, err
			}
			return 0, fmt.Errorf("read Windows console input event failed: %w", err)
		}
		for _, event := range events.records {
			if key, ok := event.(coninput.KeyEventRecord); ok {
				if r.interactive && events.mode&windows.ENABLE_VIRTUAL_TERMINAL_INPUT != 0 {
					r.appendVTKey(key)
				} else {
					r.pending = append(r.pending, r.translateKeyEvent(key)...)
				}
			}
		}
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
	single := r.translateSingleKeyEvent(key)
	if len(single) == 0 {
		return []byte{}
	}
	repeat := int(key.RepeatCount)
	if repeat <= 1 {
		return single
	}
	return bytes.Repeat(single, repeat)
}

func (r *windowsConsolePromptReader) translateSingleKeyEvent(key coninput.KeyEventRecord) []byte {
	if r.interactive {
		if key.KeyDown && key.Char >= 0xd800 && key.Char <= 0xdbff {
			r.highSurrogate = key.Char
			return nil
		}
		if key.KeyDown && r.highSurrogate != 0 {
			if key.Char >= 0xdc00 && key.Char <= 0xdfff {
				key.Char = utf16.DecodeRune(r.highSurrogate, key.Char)
			}
			r.highSurrogate = 0
		}
		return translateInteractiveKey(key)
	}
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
		return append([]byte{0x1b}, []byte(string(char))...)
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
		return []byte{0x02}
	case coninput.VK_RIGHT:
		return []byte{0x06}
	case coninput.VK_UP:
		return []byte{0x10}
	case coninput.VK_DOWN:
		return []byte{0x0e}
	}
	return []byte{}
}

func translateCtrlKey(char rune) rune {
	switch char {
	case 'A':
		return 0x01
	case 'E':
		return 0x05
	case 'R':
		return 0x12
	case 'S':
		return 0x13
	default:
		return char
	}
}

func (i *windowsPromptInput) Interrupt() error {
	i.interruptOnce.Do(func() {
		i.stateMu.Lock()
		i.interrupted = true
		i.stateMu.Unlock()

		if i.cancelEvent != 0 {
			// Console and pipe readers observe a persistent cancellation event;
			// keep the handles alive until every admitted reader has exited.
			if err := windows.SetEvent(i.cancelEvent); err != nil {
				i.interruptErr = fmt.Errorf("signal prompt input cancellation failed: %w", err)
			}
			return
		}
		cancelErr := windows.CancelIoEx(i.handle, nil)
		if errors.Is(cancelErr, windows.ERROR_NOT_FOUND) || errors.Is(cancelErr, windows.ERROR_INVALID_HANDLE) {
			cancelErr = nil
		}
		closeErr := i.file.Close()
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
		if i.cancelEvent != 0 {
			if err := i.file.Close(); err != nil {
				i.closeErr = appendWindowsPromptInputError(i.closeErr, "close prompt input failed", err)
			}
		}
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

// Interactive PTYs expect escape sequences, not line-editing control characters.
func translateInteractiveKey(key coninput.KeyEventRecord) []byte {
	if !key.KeyDown {
		return nil
	}
	if key.Char == '\t' && key.ControlKeyState&coninput.SHIFT_PRESSED != 0 {
		return []byte("\x1b[Z")
	}
	if key.Char != 0 {
		value := []byte(string(key.Char))
		// AltGr produces text and must not be interpreted as an Alt shortcut.
		alt := key.ControlKeyState&(coninput.LEFT_ALT_PRESSED|coninput.RIGHT_ALT_PRESSED) != 0
		ctrl := key.ControlKeyState&(coninput.LEFT_CTRL_PRESSED|coninput.RIGHT_CTRL_PRESSED) != 0
		if alt && !ctrl {
			return append([]byte{0x1b}, value...)
		}
		return value
	}
	if key.VirtualKeyCode == coninput.VK_SPACE && key.ControlKeyState&(coninput.LEFT_CTRL_PRESSED|coninput.RIGHT_CTRL_PRESSED) != 0 {
		return []byte{0}
	}
	return translateInteractiveNavigationKey(key)
}

func translateInteractiveNavigationKey(key coninput.KeyEventRecord) []byte {
	var sequence string
	switch key.VirtualKeyCode {
	case coninput.VK_UP:
		sequence = "A"
	case coninput.VK_DOWN:
		sequence = "B"
	case coninput.VK_RIGHT:
		sequence = "C"
	case coninput.VK_LEFT:
		sequence = "D"
	case coninput.VK_HOME:
		sequence = "H"
	case coninput.VK_END:
		sequence = "F"
	case coninput.VK_INSERT:
		sequence = "2~"
	case coninput.VK_DELETE:
		sequence = "3~"
	case coninput.VK_PRIOR:
		sequence = "5~"
	case coninput.VK_NEXT:
		sequence = "6~"
	default:
		return nil
	}
	// Xterm CSI modifiers are 1 + Shift(1) + Alt(2) + Ctrl(4).
	// Enhanced-key and lock-state bits are not keyboard modifiers.
	modifier := 1
	if key.ControlKeyState&coninput.SHIFT_PRESSED != 0 {
		modifier += 1
	}
	if key.ControlKeyState&(coninput.LEFT_ALT_PRESSED|coninput.RIGHT_ALT_PRESSED) != 0 {
		modifier += 2
	}
	if key.ControlKeyState&(coninput.LEFT_CTRL_PRESSED|coninput.RIGHT_CTRL_PRESSED) != 0 {
		modifier += 4
	}
	if modifier == 1 {
		return []byte("\x1b[" + sequence)
	}
	if len(sequence) == 1 {
		return fmt.Appendf(nil, "\x1b[1;%d%s", modifier, sequence)
	}
	return fmt.Appendf(nil, "\x1b[%s;%d~", sequence[:len(sequence)-1], modifier)
}
