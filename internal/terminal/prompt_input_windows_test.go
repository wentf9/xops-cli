//go:build windows

package terminal

import (
	"errors"
	"io"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/chzyer/readline"
	"github.com/erikgeiser/coninput"
	"golang.org/x/sys/windows"
)

func TestWindowsPromptInputInterruptsPendingRead(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe failed: %v", err)
	}
	defer func() {
		if closeErr := reader.Close(); closeErr != nil {
			t.Logf("close source reader failed: %v", closeErr)
		}
		if closeErr := writer.Close(); closeErr != nil {
			t.Logf("close source writer failed: %v", closeErr)
		}
	}()

	input, err := DuplicatePromptInput(reader)
	if err != nil {
		t.Fatalf("duplicate prompt input failed: %v", err)
	}
	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, readErr := input.Read(buffer)
		readDone <- readErr
	}()

	if err := input.Interrupt(); err != nil {
		t.Fatalf("interrupt prompt input failed: %v", err)
	}
	select {
	case readErr := <-readDone:
		if readErr == nil {
			t.Fatal("pending read unexpectedly succeeded")
		}
		if !errors.Is(readErr, io.EOF) {
			t.Logf("pending read returned platform error after cancellation: %v", readErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pending prompt read was not interrupted")
	}
	if err := input.Close(); err != nil {
		t.Fatalf("close prompt input failed: %v", err)
	}
}

func TestWindowsConsolePromptReaderTranslatesNavigationKeys(t *testing.T) {
	tests := []struct {
		name string
		key  coninput.VirtualKeyCode
		want byte
	}{
		{name: "left", key: coninput.VK_LEFT, want: readline.CharBackward},
		{name: "right", key: coninput.VK_RIGHT, want: readline.CharForward},
		{name: "previous history", key: coninput.VK_UP, want: readline.CharPrev},
		{name: "next history", key: coninput.VK_DOWN, want: readline.CharNext},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := newTestWindowsConsolePromptReader([]coninput.EventRecord{
				coninput.FocusEventRecord{},
				coninput.KeyEventRecord{KeyDown: true, VirtualKeyCode: tt.key},
			})
			buffer := make([]byte, 1)
			read, err := reader.Read(buffer)
			if err != nil {
				t.Fatalf("read translated key failed: %v", err)
			}
			if read != 1 || buffer[0] != tt.want {
				t.Fatalf("translated key = %v, want [%d]", buffer[:read], tt.want)
			}
		})
	}
}

func TestWindowsConsolePromptReaderPreservesPartialUTF8Rune(t *testing.T) {
	reader := newTestWindowsConsolePromptReader([]coninput.EventRecord{
		coninput.KeyEventRecord{KeyDown: true, Char: '界'},
	})
	want := []byte("界")
	got := []byte{}
	buffer := make([]byte, 1)
	for range len(want) {
		read, err := reader.Read(buffer)
		if err != nil {
			t.Fatalf("read translated Unicode key failed: %v", err)
		}
		got = append(got, buffer[:read]...)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("translated Unicode key = %v, want %v", got, want)
	}
}

func TestWindowsConsolePromptReaderExpandsRepeatCount(t *testing.T) {
	tests := []struct {
		name  string
		event coninput.KeyEventRecord
		want  []byte
	}{
		{
			name:  "repeated ascii char",
			event: coninput.KeyEventRecord{KeyDown: true, Char: 'x', RepeatCount: 3},
			want:  []byte("xxx"),
		},
		{
			name:  "repeated unicode char",
			event: coninput.KeyEventRecord{KeyDown: true, Char: '中', RepeatCount: 2},
			want:  []byte("中中"),
		},
		{
			name:  "repeated backspace 8",
			event: coninput.KeyEventRecord{KeyDown: true, Char: 8, RepeatCount: 4},
			want:  []byte{8, 8, 8, 8},
		},
		{
			name:  "repeated backspace 127",
			event: coninput.KeyEventRecord{KeyDown: true, Char: 127, RepeatCount: 2},
			want:  []byte{127, 127},
		},
		{
			name:  "repeated navigation key",
			event: coninput.KeyEventRecord{KeyDown: true, VirtualKeyCode: coninput.VK_LEFT, RepeatCount: 3},
			want:  []byte{readline.CharBackward, readline.CharBackward, readline.CharBackward},
		},
		{
			name:  "repeat count 0 produces single",
			event: coninput.KeyEventRecord{KeyDown: true, Char: 'z', RepeatCount: 0},
			want:  []byte("z"),
		},
		{
			name:  "repeat count 1 produces single",
			event: coninput.KeyEventRecord{KeyDown: true, Char: 'y', RepeatCount: 1},
			want:  []byte("y"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := newTestWindowsConsolePromptReader([]coninput.EventRecord{tt.event})
			buffer := make([]byte, len(tt.want)+10)
			read, err := reader.Read(buffer)
			if err != nil {
				t.Fatalf("read failed: %v", err)
			}
			if !slices.Equal(buffer[:read], tt.want) {
				t.Fatalf("got %v (%q), want %v (%q)", buffer[:read], string(buffer[:read]), tt.want, string(tt.want))
			}
		})
	}
}

func TestReadWindowsConsoleEventReturnsWhenCanceled(t *testing.T) {
	inputEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatalf("create test input event failed: %v", err)
	}
	defer closeWindowsTestHandle(t, inputEvent)
	cancelEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatalf("create test cancellation event failed: %v", err)
	}
	defer closeWindowsTestHandle(t, cancelEvent)

	readDone := make(chan error, 1)
	go func() {
		_, readErr := readWindowsConsoleEvent(inputEvent, cancelEvent)
		readDone <- readErr
	}()
	if err := windows.SetEvent(cancelEvent); err != nil {
		t.Fatalf("signal test cancellation event failed: %v", err)
	}
	select {
	case readErr := <-readDone:
		if !errors.Is(readErr, io.EOF) {
			t.Fatalf("canceled console event read error = %v, want EOF", readErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("console event read was not canceled")
	}
}

func newTestWindowsConsolePromptReader(events []coninput.EventRecord) *windowsConsolePromptReader {
	next := 0
	return &windowsConsolePromptReader{
		handle:      windows.Handle(1),
		cancelEvent: windows.Handle(2),
		readEvent: func(windows.Handle, windows.Handle) (coninput.EventRecord, error) {
			event := events[next]
			next++
			return event, nil
		},
		pending: []byte{},
	}
}

func closeWindowsTestHandle(t *testing.T, handle windows.Handle) {
	t.Helper()
	if err := windows.CloseHandle(handle); err != nil {
		t.Errorf("close Windows test handle failed: %v", err)
	}
}
