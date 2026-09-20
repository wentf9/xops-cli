package sftpshell

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestEditorCursorUsesDisplayCells(t *testing.T) {
	for _, tt := range []struct {
		value  string
		column int
	}{
		{"界", 10}, {"e\u0301", 9}, {"👩‍💻", 10}, {"🇨🇳", 10}, {"界a", 11},
	} {
		t.Run(tt.value, func(t *testing.T) {
			m := newEditorModel(promptOptions{text: "REVIEW> "}, nil, nil)
			m.Update(tea.PasteMsg{Content: tt.value})
			cursor := m.View().Cursor
			if cursor == nil || cursor.X != tt.column || cursor.Y != 0 {
				t.Fatalf("cursor=%+v, want column %d", cursor, tt.column)
			}
		})
	}
}

func TestEditorCursorMovesWithinScrolledViewport(t *testing.T) {
	m := newEditorModel(promptOptions{text: "> "}, nil, nil)
	m.Update(tea.WindowSizeMsg{Width: 10, Height: 10})
	m.Update(tea.PasteMsg{Content: "abcdefghijklmn"})
	view := m.View()
	if view.Cursor.X != 9 || !strings.Contains(view.Content, "hijklmn") {
		t.Fatalf("end viewport=%q cursor=%+v", view.Content, view.Cursor)
	}
	for column := 8; column >= 2; column-- {
		m.Update(editorKey("left"))
		view = m.View()
		if view.Cursor.X != column || !strings.Contains(view.Content, "hijklmn") {
			t.Fatalf("left viewport=%q cursor=%+v, want %d", view.Content, view.Cursor, column)
		}
	}
	m.Update(editorKey("left"))
	view = m.View()
	if view.Cursor.X != 2 || !strings.Contains(view.Content, "ghijklm") {
		t.Fatalf("left scroll=%q cursor=%+v", view.Content, view.Cursor)
	}
	m.Update(editorKey("X"))
	if m.input.Value() != "abcdefXghijklmn" {
		t.Fatal(m.input.Value())
	}
}
