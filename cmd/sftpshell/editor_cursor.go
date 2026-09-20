package sftpshell

import (
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/rivo/uniseg"
)

type editorViewport struct {
	prompt, value        string
	start, cells, cursor int
}

// The pinned textinput cursor/viewport use rune offsets. Own the visible slice
// and cursor together so wide and combining characters share cell coordinates.
func (m *editorModel) inputViewport() editorViewport {
	prompt := ansi.Truncate(m.input.Prompt, max(0, m.width-1), "")
	room := max(0, m.width-ansi.StringWidth(prompt)-1)
	value := m.input.Value()
	cursorByte := len(value)
	position := 0
	for offset := range value {
		if position == m.input.Position() {
			cursorByte = offset
			break
		}
		position++
	}
	start := min(m.inputOffset, cursorByte)
	if ansi.StringWidth(value) <= room {
		start = 0
	}
	// Input replacement can leave the old byte offset inside a grapheme.
	clusters := uniseg.NewGraphemes(value)
	for clusters.Next() {
		from, to := clusters.Positions()
		if from <= start && start < to {
			start = from
			break
		}
	}
	cursorCells := ansi.StringWidth(value[start:cursorByte])
	left := uniseg.NewGraphemes(value[start:cursorByte])
	base := start
	for cursorCells > room && left.Next() {
		_, end := left.Positions()
		start = base + end
		cursorCells -= ansi.StringWidth(left.Str())
	}
	end, cells := start, 0
	visible := uniseg.NewGraphemes(value[start:])
	for visible.Next() {
		width := ansi.StringWidth(visible.Str())
		if cells+width > room {
			break
		}
		cells += width
		_, next := visible.Positions()
		end = start + next
	}
	return editorViewport{prompt: prompt, value: value[start:end], start: start, cells: cells, cursor: cursorCells}
}

func (m *editorModel) updateInputViewport() { m.inputOffset = m.inputViewport().start }

func (m *editorModel) inputView() (string, *tea.Cursor) {
	viewport := m.inputViewport()
	promptCells := ansi.StringWidth(viewport.prompt)
	row := viewport.prompt + viewport.value + strings.Repeat(" ", max(0, m.width-promptCells-viewport.cells))
	if !m.input.Focused() {
		return row, nil
	}
	cursor := tea.NewCursor(promptCells+viewport.cursor, strings.Count(m.promptPrefix, "\n"))
	style := m.input.Styles().Cursor
	cursor.Color, cursor.Shape, cursor.Blink = style.Color, style.Shape, style.Blink
	return row, cursor
}
