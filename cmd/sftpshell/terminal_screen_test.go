package sftpshell

import (
	"github.com/charmbracelet/x/ansi"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/hinshun/vt10x"
)

// vt10x predates the Kitty keyboard protocol and treats private CSI ... u as
// the legacy restore-cursor command. Strip only those unsupported extensions;
// preserve ordinary cursor movement/erasure so assertions check the screen.
var terminalExtensions = regexp.MustCompile(`\x1b\[[><=][0-9;:]*[um]|\x1b\[\?[0-9;]*\$p`)

func terminalScreen(raw string, cols, rows int) (string, error) {
	screen, err := parseTerminalScreen(raw, cols, rows)
	if err != nil {
		return "", err
	}
	return screen.String(), nil
}

func parseTerminalScreen(raw string, cols, rows int) (vt10x.Terminal, error) {
	screen := vt10x.New(vt10x.WithSize(cols, rows))
	if _, err := screen.Write([]byte(terminalExtensions.ReplaceAllString(raw, ""))); err != nil {
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
