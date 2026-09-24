//go:build windows

package terminal

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"
	"time"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/erikgeiser/coninput"
	"golang.org/x/sys/windows"
)

func TestWindowsPromptInputInterruptsPendingRead(t *testing.T) {
	input, _, _ := newWindowsPipeTestInput(t)
	readDone := make(chan error, 1)
	go func() {
		var buffer [1]byte
		_, err := input.Read(buffer[:])
		readDone <- err
	}()
	interruptWindowsPipeTestInput(t, input, readDone)
}

func TestWindowsConsolePromptReaderTranslatesNavigationKeys(t *testing.T) {
	tests := []struct {
		name string
		key  coninput.VirtualKeyCode
		want byte
	}{
		{name: "left", key: coninput.VK_LEFT, want: 0x02},
		{name: "right", key: coninput.VK_RIGHT, want: 0x06},
		{name: "previous history", key: coninput.VK_UP, want: 0x10},
		{name: "next history", key: coninput.VK_DOWN, want: 0x0e},
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
			want:  []byte{0x02, 0x02, 0x02},
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
		_, readErr := readWindowsConsoleEvents(inputEvent, cancelEvent, windowsConsoleInputBatchSize)
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
		readEvent: func(_, _ windows.Handle, limit int) (windowsConsoleEvents, error) {
			if next == len(events) {
				return windowsConsoleEvents{}, io.EOF
			}
			end := min(next+limit, len(events))
			batch := events[next:end]
			next = end
			return windowsConsoleEvents{records: batch}, nil
		},
		pending: []byte{},
	}
}

func TestWindowsInteractiveInputBatchesVTSequences(t *testing.T) {
	for _, sequence := range []string{"\x1b[30;1R", "\x1b[O", "\x1b[A", "\x1b[B", "\x1b[200~paste\x1b[201~"} {
		t.Run(fmt.Sprintf("%q", sequence), func(t *testing.T) {
			events := []coninput.EventRecord{coninput.FocusEventRecord{}}
			for _, char := range sequence {
				events = append(events, coninput.KeyEventRecord{KeyDown: true, Char: char})
			}
			reader := newTestWindowsConsolePromptReader(events)
			reader.interactive = true
			buffer := make([]byte, 1024)
			n, err := reader.Read(buffer)
			if err != nil || string(buffer[:n]) != sequence {
				t.Fatalf("queued VT input split: read %q, err=%v, want %q in one read", buffer[:n], err, sequence)
			}
		})
	}
}

func TestWindowsPromptInputDoesNotReadAhead(t *testing.T) {
	reader := newTestWindowsConsolePromptReader([]coninput.EventRecord{
		coninput.KeyEventRecord{KeyDown: true, Char: '\r'},
		coninput.KeyEventRecord{KeyDown: true, Char: 'x'},
	})
	buffer := make([]byte, 1024)
	for _, want := range []string{"\r", "x"} {
		n, err := reader.Read(buffer)
		if err != nil || string(buffer[:n]) != want {
			t.Fatalf("prompt read %q, err=%v, want %q", buffer[:n], err, want)
		}
	}
}

func closeWindowsTestHandle(t *testing.T, handle windows.Handle) {
	t.Helper()
	if err := windows.CloseHandle(handle); err != nil {
		t.Errorf("close Windows test handle failed: %v", err)
	}
}

func TestWindowsInteractiveInputPreservesTerminalKeys(t *testing.T) {
	tests := []struct {
		name string
		key  coninput.KeyEventRecord
		want string
	}{
		{"up", coninput.KeyEventRecord{KeyDown: true, VirtualKeyCode: coninput.VK_UP}, "\x1b[A"},
		{"shift tab", coninput.KeyEventRecord{KeyDown: true, Char: '\t', ControlKeyState: coninput.SHIFT_PRESSED}, "\x1b[Z"},
		{"control D", coninput.KeyEventRecord{KeyDown: true, Char: 4}, "\x04"},
		{"delete", coninput.KeyEventRecord{KeyDown: true, VirtualKeyCode: coninput.VK_DELETE}, "\x1b[3~"},
		{"control C", coninput.KeyEventRecord{KeyDown: true, Char: 3}, "\x03"},
		{"unicode", coninput.KeyEventRecord{KeyDown: true, Char: '界'}, "界"},
		{"repeat", coninput.KeyEventRecord{KeyDown: true, Char: 'x', RepeatCount: 3}, "xxx"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := newTestWindowsConsolePromptReader([]coninput.EventRecord{coninput.FocusEventRecord{}, coninput.KeyEventRecord{KeyDown: false, Char: 'z'}, tt.key})
			reader.interactive = true
			var got []byte
			for len(got) < len(tt.want) {
				var b [1]byte
				n, err := reader.Read(b[:])
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, b[:n]...)
			}
			if string(got) != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWindowsInteractiveInputDecodesSurrogatePair(t *testing.T) {
	reader := newTestWindowsConsolePromptReader([]coninput.EventRecord{
		coninput.KeyEventRecord{KeyDown: true, Char: 0xd83d},
		coninput.KeyEventRecord{KeyDown: true, Char: 0xde00},
	})
	reader.interactive = true
	var buf [4]byte
	n, err := reader.Read(buf[:])
	if err != nil || string(buf[:n]) != "😀" {
		t.Fatalf("surrogate pair: %q, %v", buf[:n], err)
	}
}

func TestWindowsInteractiveNavigationModifiers(t *testing.T) {
	keys := []struct {
		name    string
		code    coninput.VirtualKeyCode
		decoded rune
	}{
		{"left", coninput.VK_LEFT, uv.KeyLeft},
		{"right", coninput.VK_RIGHT, uv.KeyRight},
		{"up", coninput.VK_UP, uv.KeyUp},
		{"down", coninput.VK_DOWN, uv.KeyDown},
		{"home", coninput.VK_HOME, uv.KeyHome},
		{"end", coninput.VK_END, uv.KeyEnd},
		{"insert", coninput.VK_INSERT, uv.KeyInsert},
		{"delete", coninput.VK_DELETE, uv.KeyDelete},
		{"pageup", coninput.VK_PRIOR, uv.KeyPgUp},
		{"pagedown", coninput.VK_NEXT, uv.KeyPgDown},
	}
	modifiers := []struct {
		name    string
		state   coninput.ControlKeyState
		decoded uv.KeyMod
	}{
		{"plain", 0, 0},
		{"left ctrl", coninput.LEFT_CTRL_PRESSED, uv.ModCtrl},
		{"right ctrl", coninput.RIGHT_CTRL_PRESSED, uv.ModCtrl},
		{"left alt", coninput.LEFT_ALT_PRESSED, uv.ModAlt},
		{"right alt", coninput.RIGHT_ALT_PRESSED, uv.ModAlt},
		{"shift", coninput.SHIFT_PRESSED, uv.ModShift},
		{"ctrl shift", coninput.LEFT_CTRL_PRESSED | coninput.SHIFT_PRESSED, uv.ModCtrl | uv.ModShift},
		{"alt shift", coninput.LEFT_ALT_PRESSED | coninput.SHIFT_PRESSED, uv.ModAlt | uv.ModShift},
		{"ctrl alt", coninput.LEFT_CTRL_PRESSED | coninput.LEFT_ALT_PRESSED, uv.ModCtrl | uv.ModAlt},
		{"all", coninput.RIGHT_CTRL_PRESSED | coninput.RIGHT_ALT_PRESSED | coninput.SHIFT_PRESSED, uv.ModCtrl | uv.ModAlt | uv.ModShift},
		{"lock states", coninput.CAPSLOCK_ON | coninput.NUMLOCK_ON | coninput.SCROLLLOCK_ON, 0},
	}
	for _, key := range keys {
		for _, modifier := range modifiers {
			t.Run(key.name+"/"+modifier.name, func(t *testing.T) {
				// Include the enhanced-key flag and read one byte at a time to
				// cover the same buffering/repeat path used by the owned reader.
				reader := newTestWindowsConsolePromptReader([]coninput.EventRecord{
					coninput.KeyEventRecord{KeyDown: false, VirtualKeyCode: key.code},
					coninput.KeyEventRecord{KeyDown: true, VirtualKeyCode: key.code, RepeatCount: 2,
						ControlKeyState: modifier.state | coninput.ENHANCED_KEY},
				})
				reader.interactive = true
				want := uv.KeyPressEvent{Code: key.decoded, Mod: modifier.decoded}
				encoded := reader.translateKeyEvent(coninput.KeyEventRecord{KeyDown: true, VirtualKeyCode: key.code,
					ControlKeyState: modifier.state | coninput.ENHANCED_KEY, RepeatCount: 2})
				var data []byte
				for range len(encoded) {
					var b [1]byte
					n, err := reader.Read(b[:])
					if err != nil || n != 1 {
						t.Fatalf("read key byte: n=%d err=%v", n, err)
					}
					data = append(data, b[0])
				}
				var decoder uv.EventDecoder
				for range 2 {
					n, event := decoder.Decode(data)
					got, ok := event.(uv.KeyPressEvent)
					if n <= 0 || !ok || got.Code != want.Code || got.Mod != want.Mod {
						t.Fatalf("decoded %q as %v, want %v", data, event, want)
					}
					data = data[n:]
				}
				if len(data) != 0 {
					t.Fatalf("unconsumed navigation bytes: %q", data)
				}
			})
		}
	}
}

func TestWindowsInteractiveAltGrRemainsText(t *testing.T) {
	for _, char := range []rune{'@', '界'} {
		t.Run(fmt.Sprintf("%U", char), func(t *testing.T) {
			key := coninput.KeyEventRecord{KeyDown: true, Char: char,
				ControlKeyState: coninput.RIGHT_ALT_PRESSED | coninput.LEFT_CTRL_PRESSED}
			if got := string(translateInteractiveKey(key)); got != string(char) {
				t.Fatalf("AltGr text = %q, want %q", got, string(char))
			}
		})
	}
}
