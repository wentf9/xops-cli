package sftpshell

import (
	"fmt"
	"reflect"
	"testing"

	uv "github.com/charmbracelet/ultraviolet"
)

func TestEditorDecoderSplitInput(t *testing.T) {
	tests := []struct {
		name, input string
		want        []string
	}{
		{"UTF-8", "界🙂\r", []string{"界", "🙂", "enter"}},
		{"paste", "\x1b[200~get 界\nrm second\x1b[201~\r", []string{"paste:get 界\nrm second", "enter"}},
		{"navigation", "ab\x1b[D\x1b[3~\r", []string{"a", "b", "left", "delete", "enter"}},
	}
	for _, tt := range tests {
		for split := 0; split <= len(tt.input); split++ {
			t.Run(fmt.Sprintf("%s/%d", tt.name, split), func(t *testing.T) {
				decoder := editorDecoder{}
				var got []string
				for _, chunk := range []string{tt.input[:split], tt.input[split:]} {
					decoder.buffer = append(decoder.buffer, chunk...)
					for {
						msg, ok := decoder.next(false)
						if !ok {
							break
						}
						switch msg := msg.(type) {
						case uv.KeyPressEvent:
							got = append(got, msg.String())
						case uv.PasteEvent:
							got = append(got, "paste:"+msg.Content)
						default:
							t.Fatalf("unexpected event %#v", msg)
						}
					}
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Fatalf("got %q, want %q", got, tt.want)
				}
			})
		}
	}
}

func TestEditorDecoderTimeout(t *testing.T) {
	for _, input := range []string{"\xe7", "\x1b[", "\x1b[20", "\x1bO", "\x1b[200~get first\n"} {
		decoder := editorDecoder{buffer: []byte(input)}
		for _, expired := range []bool{false, true} {
			if msg, ok := decoder.next(expired); ok {
				t.Fatalf("partial input %q emitted %#v", input, msg)
			}
		}
	}
	decoder := editorDecoder{buffer: []byte("\x1b")}
	if msg, ok := decoder.next(false); ok {
		t.Fatalf("escape emitted before timeout: %#v", msg)
	}
	msg, ok := decoder.next(true)
	key, isKey := msg.(uv.KeyPressEvent)
	if !ok || !isKey || key.Code != uv.KeyEscape {
		t.Fatalf("escape after timeout: %#v", msg)
	}
}
