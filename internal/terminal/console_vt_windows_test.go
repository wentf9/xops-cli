//go:build windows

package terminal

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/erikgeiser/coninput"
	"golang.org/x/sys/windows"
)

func newTestWindowsVTReader(events []coninput.EventRecord) *windowsConsolePromptReader {
	reader := newTestWindowsConsolePromptReader(events)
	reader.interactive = true
	readEvents := reader.readEvent
	reader.readEvent = func(handle, cancel windows.Handle, limit int) (windowsConsoleEvents, error) {
		batch, err := readEvents(handle, cancel, limit)
		batch.mode = windows.ENABLE_VIRTUAL_TERMINAL_INPUT
		return batch, err
	}
	return reader
}

func TestWindowsVTInputPreservesNativeText(t *testing.T) {
	tests := []struct {
		name string
		key  coninput.KeyEventRecord
		want string
	}{
		{"encoded alt escape", coninput.KeyEventRecord{KeyDown: true, Char: '\x1b', ControlKeyState: coninput.LEFT_ALT_PRESSED}, "\x1b"},
		{"encoded shift tab", coninput.KeyEventRecord{KeyDown: true, Char: '\t', ControlKeyState: coninput.SHIFT_PRESSED}, "\t"},
		{"normalized repeat", coninput.KeyEventRecord{KeyDown: true, Char: 'x', RepeatCount: 3}, "x"},
		{"NUL", coninput.KeyEventRecord{KeyDown: true}, "\x00"},
		{"modifier artifact", coninput.KeyEventRecord{KeyDown: true, VirtualKeyCode: coninput.VK_MENU, VirtualScanCode: 0x38}, ""},
		{"ordinary key up", coninput.KeyEventRecord{Char: 'x'}, ""},
		{"Unicode menu key up", coninput.KeyEventRecord{VirtualKeyCode: coninput.VK_MENU, Char: '界'}, "界"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := newTestWindowsVTReader([]coninput.EventRecord{coninput.FocusEventRecord{}, tt.key})
			data, err := io.ReadAll(reader)
			if err != nil || string(data) != tt.want {
				t.Fatalf("read %q, err=%v, want %q", data, err, tt.want)
			}
		})
	}
}

func TestWindowsVTInputSurrogatesAcrossBatches(t *testing.T) {
	for _, size := range []int{1, 7, 4096} {
		var events []coninput.EventRecord
		prefix := strings.Repeat("x", windowsConsoleInputBatchSize-1)
		for range prefix {
			events = append(events, coninput.KeyEventRecord{KeyDown: true, Char: 'x'})
		}
		// Put the high surrogate in the final record of a full batch. Windows
		// can deliver both halves on VK_MENU key-up, with non-text events between.
		events = append(events,
			coninput.KeyEventRecord{VirtualKeyCode: coninput.VK_MENU, Char: 0xd83d},
			coninput.FocusEventRecord{},
			coninput.KeyEventRecord{KeyDown: true, VirtualScanCode: 0x38},
			coninput.KeyEventRecord{VirtualKeyCode: coninput.VK_MENU, Char: 0xde00},
		)
		for _, char := range "\x1b[A\x00" {
			events = append(events, coninput.KeyEventRecord{KeyDown: true, Char: char})
		}
		reader := newTestWindowsVTReader(events)
		var got strings.Builder
		buffer := make([]byte, size)
		for {
			n, err := reader.Read(buffer)
			got.Write(buffer[:n])
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if want := prefix + "😀\x1b[A\x00"; got.String() != want {
			t.Fatalf("buffer size %d: got %q, want %q", size, got.String(), want)
		}
	}
}

func TestWindowsVTInputPreservesSplitEscapeSequence(t *testing.T) {
	var events []coninput.EventRecord
	prefix := strings.Repeat("x", windowsConsoleInputBatchSize-1)
	want := prefix + "\x1b[30;1R\x1b[O\x1b[A"
	for _, char := range want {
		events = append(events, coninput.KeyEventRecord{KeyDown: true, Char: char})
	}
	data, err := io.ReadAll(newTestWindowsVTReader(events))
	if err != nil || string(data) != want {
		t.Fatalf("split VT stream changed: got %q, err=%v", data, err)
	}
}

func TestWindowsVTInputWideBatch(t *testing.T) {
	events := make([]coninput.EventRecord, windowsConsoleInputBatchSize)
	for i := range events {
		events[i] = coninput.KeyEventRecord{KeyDown: true, Char: '界'}
	}
	buffer := make([]byte, 4096)
	n, err := newTestWindowsVTReader(events).Read(buffer)
	if want := strings.Repeat("界", len(events)); err != nil || string(buffer[:n]) != want {
		t.Fatalf("wide batch: read %d bytes, err=%v, want %d bytes", n, err, len(want))
	}
}

func TestWindowsInteractiveInputUsesCurrentConsoleMode(t *testing.T) {
	reader := newTestWindowsConsolePromptReader([]coninput.EventRecord{
		coninput.KeyEventRecord{KeyDown: true, Char: '\t', ControlKeyState: coninput.SHIFT_PRESSED},
		coninput.KeyEventRecord{KeyDown: true, Char: '\t', ControlKeyState: coninput.SHIFT_PRESSED},
	})
	reader.interactive = true
	readEvents := reader.readEvent
	var mode uint32
	reader.readEvent = func(handle, cancel windows.Handle, _ int) (windowsConsoleEvents, error) {
		batch, err := readEvents(handle, cancel, 1)
		batch.mode = mode
		return batch, err
	}
	buffer := make([]byte, 16)
	for _, want := range []string{"\x1b[Z", "\t"} {
		n, err := reader.Read(buffer)
		if err != nil || string(buffer[:n]) != want {
			t.Fatalf("mode %x: read %q, err=%v, want %q", mode, buffer[:n], err, want)
		}
		mode = windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	}
}

func TestWindowsVTInputMalformedSurrogatesPreserveFollowingText(t *testing.T) {
	var events []coninput.EventRecord
	for _, char := range []rune{0xd83d, 'x', 0xde00, 0xd83d, 0xd83d, 0xde00} {
		events = append(events, coninput.KeyEventRecord{KeyDown: true, Char: char})
	}
	data, err := io.ReadAll(newTestWindowsVTReader(events))
	if want := "�x��😀"; err != nil || string(data) != want {
		t.Fatalf("malformed UTF-16: got %q, err=%v, want %q", data, err, want)
	}
}
