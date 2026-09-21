package sftpshell

import (
	"fmt"
	"github.com/charmbracelet/x/ansi"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/hinshun/vt10x"
)

// vt10x predates the Kitty keyboard protocol and treats private CSI ... u as
// the legacy restore-cursor command. Strip only those unsupported extensions;
// preserve ordinary cursor movement/erasure so assertions check the screen.
var terminalExtensions = regexp.MustCompile(`\x1b\[[><=][0-9;:]*[um]|\x1b\[\?[0-9;]*\$p`)

// ConPTY emits an in-band window resize before redrawing at the new size.
// Replaying at the initial dimensions misplaces absolute cursor updates after
// wrapping or scrolling, which can hide a correctly rendered completion line.
var terminalResizes = regexp.MustCompile(`\x1b\[8;([1-9][0-9]*);([1-9][0-9]*)t`)

func terminalScreen(raw string, cols, rows int) (string, error) {
	screen, err := parseTerminalScreen(raw, cols, rows)
	if err != nil {
		return "", err
	}
	return screen.String(), nil
}

func parseTerminalScreen(raw string, cols, rows int) (vt10x.Terminal, error) {
	screen := vt10x.New(vt10x.WithSize(cols, rows))
	raw = terminalExtensions.ReplaceAllString(raw, "")
	offset := 0
	for _, match := range terminalResizes.FindAllStringSubmatchIndex(raw, -1) {
		if _, err := screen.Write([]byte(raw[offset:match[0]])); err != nil {
			return nil, err
		}
		height, err := strconv.Atoi(raw[match[2]:match[3]])
		if err != nil {
			return nil, fmt.Errorf("parse terminal resize height failed: %w", err)
		}
		width, err := strconv.Atoi(raw[match[4]:match[5]])
		if err != nil {
			return nil, fmt.Errorf("parse terminal resize width failed: %w", err)
		}
		screen.Resize(width, height)
		offset = match[1]
	}
	if _, err := screen.Write([]byte(raw[offset:])); err != nil {
		return nil, err
	}
	return screen, nil
}

// vt10x assumes one cell per rune. For cursor assertions only, expand each
// grapheme into its cell footprint while preserving terminal control sequences.
func terminalCursor(raw string, cols, rows int) (vt10x.Cursor, error) {
	var cells strings.Builder
	var state byte
	for len(raw) > 0 {
		seq, width, n, next := ansi.DecodeSequence(raw, state, nil)
		if width > 0 {
			r, _ := utf8.DecodeRuneInString(seq)
			cells.WriteRune(r)
			cells.WriteString(strings.Repeat(" ", width-1))
		} else {
			cells.WriteString(seq)
		}
		raw = raw[n:]
		state = next
	}
	screen, err := parseTerminalScreen(cells.String(), cols, rows)
	if err != nil {
		return vt10x.Cursor{}, err
	}
	return screen.Cursor(), nil
}

func TestTerminalScreenConPTYResize(t *testing.T) {
	// At 24 rows this eight-line view scrolls up once, moving the prompt from
	// row 18 to row 17. ConPTY then updates only the changed completion suffix.
	raw := "\x1b[8;24;72t\x1b[18;1HSFTP_PAGES> put bin0\r\n" +
		strings.Repeat("  candidates\r\n", 6) + "Page 1/3, 80 items" +
		"\x1b[17;21H36\\\x1b[24;6H2/"
	screen, err := parseTerminalScreen(raw, 100, 30)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SFTP_PAGES> put bin036\\", "Page 2/3, 80 items"} {
		if !strings.Contains(screen.String(), want) {
			t.Fatalf("resized screen does not contain %q:\n%s", want, screen.String())
		}
	}
	if width, height := screen.Size(); width != 72 || height != 24 {
		t.Fatalf("screen size = %dx%d, want 72x24", width, height)
	}
	// Apply each resize at its position in the stream, not just the last size.
	screen, err = parseTerminalScreen(raw+"\x1b[8;30;100t\x1b[30;90HGROWN", 100, 30)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(screen.String(), "SFTP_PAGES> put bin036\\") || !strings.Contains(screen.String(), "GROWN") {
		t.Fatalf("screen contents lost after growing:\n%s", screen.String())
	}
}
