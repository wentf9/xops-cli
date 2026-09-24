package sftpshell

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// Keep the raw transcript separate from screen replay. Explicit harness resize
// requests join any in-band reports at their position in the replay, without
// inventing terminal output or reinterpreting all earlier output at a new size.
type conPTYOutput struct {
	mu         sync.Mutex
	data       []byte
	replay     []byte
	cols, rows int
	screen     string
	screenErr  error
	updated    chan struct{}
}

func newConPTYOutput(cols, rows int) *conPTYOutput {
	return &conPTYOutput{cols: cols, rows: rows, updated: make(chan struct{}, 1)}
}

func (o *conPTYOutput) Append(data []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.data = append(o.data, data...)
	o.replay = append(o.replay, data...)
	o.updateScreen()
}

func (o *conPTYOutput) Resize(cols, rows int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.replay = fmt.Appendf(o.replay, "\x1b[8;%d;%dt", rows, cols)
	o.updateScreen()
}

// updateScreen runs with mu held.
func (o *conPTYOutput) updateScreen() {
	o.screen, o.screenErr = terminalScreen(string(o.replay), o.cols, o.rows)
	select {
	case o.updated <- struct{}{}:
	default:
	}
}

func (o *conPTYOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return string(o.data)
}

func TestConPTYOutputExplicitResize(t *testing.T) {
	for _, inBand := range []bool{false, true} {
		t.Run(fmt.Sprintf("in-band-%t", inBand), func(t *testing.T) {
			output := newConPTYOutput(100, 30)
			// This marker fits only before the resize. Replaying the complete
			// transcript at the latest dimensions would incorrectly retain it.
			prefix := "\x1b[30;90HOLD"
			output.Append([]byte(prefix))
			output.Resize(72, 24)
			raw := "\x1b[18;1HSFTP_PAGES> put bin0\r\n" +
				strings.Repeat("  candidates\r\n", 6) + "Page 1/3, 80 items" +
				"\x1b[17;21H36\\\x1b[24;6H2/"
			if inBand {
				raw = "\x1b[8;24;72t" + raw
			}
			output.Append([]byte(raw))
			if output.screenErr != nil {
				t.Fatal(output.screenErr)
			}
			for _, want := range []string{"SFTP_PAGES> put bin036\\", "Page 2/3, 80 items"} {
				if !strings.Contains(output.screen, want) {
					t.Fatalf("missing %q after resize:\n%s", want, output.screen)
				}
			}
			output.Resize(100, 30)
			output.Append([]byte("\x1b[30;90HGROWN"))
			if output.screenErr != nil || !strings.Contains(output.screen, "GROWN") || strings.Contains(output.screen, "OLD") {
				t.Fatalf("resize history lost: %v\n%s", output.screenErr, output.screen)
			}
			cursor, err := terminalCursor(string(output.replay), 100, 30)
			if err != nil || cursor.X != 94 || cursor.Y != 29 {
				t.Fatalf("cursor after grow: %+v, err=%v", cursor, err)
			}
			if output.String() != prefix+raw+"\x1b[30;90HGROWN" {
				t.Fatal("explicit resize modified the raw transcript")
			}
		})
	}
}
