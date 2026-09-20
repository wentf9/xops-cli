package sftpshell

import (
	"context"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/hinshun/vt10x"
)

func completionMenuModel(candidates []string) *editorModel {
	m := newEditorModel(promptOptions{}, nil, func(uint64, string, int) context.CancelFunc { return func() {} })
	m.input.SetValue("put bin")
	m.input.CursorEnd()
	m.Update(editorKey("tab"))
	m.Update(completionMsg{m.requestID, m.input.Value(), m.input.Position(), completionResult{head: "put ", candidates: candidates}})
	return m
}

func assertCompletionHighlight(t *testing.T, m *editorModel, candidates []string, selected int) {
	t.Helper()
	lines := strings.Split(m.View().Content, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected a candidate panel, got %q", m.View().Content)
	}
	menuLines := lines[1:]
	for _, line := range menuLines {
		if ansi.StringWidth(line) > m.width {
			t.Fatalf("menu exceeds terminal width: %q", line)
		}
	}
	screen := vt10x.New(vt10x.WithSize(max(1, m.width), len(menuLines)))
	if _, err := screen.Write([]byte(strings.Join(menuLines, "\r\n"))); err != nil {
		t.Fatal(err)
	}
	plain := ansi.Strip(strings.Join(menuLines, "\n"))
	for i, candidate := range candidates {
		found := false
		for row, line := range strings.Split(plain, "\n") {
			offset := strings.Index(line, candidate)
			if offset < 0 {
				continue
			}
			found = true
			x := ansi.StringWidth(line[:offset])
			for column := x; column < x+ansi.StringWidth(candidate); column++ {
				highlighted := screen.Cell(column, row).Mode != 0
				if highlighted != (i == selected) {
					t.Fatalf("candidate %q highlighted=%v, want %v; panel=%q", candidate, highlighted, i == selected, plain)
				}
			}
		}
		if !found && i == selected {
			t.Fatalf("selected candidate %q is hidden: %q", candidate, plain)
		}
	}

	if selected >= 0 && !strings.Contains(plain, "> "+candidates[selected]) {
		t.Fatalf("selection has no plain-text marker: %q", plain)
	}
}

func TestCompletionHighlightTracksSelection(t *testing.T) {
	candidates := []string{"bina/", "binb/", "binc/"}
	m := completionMenuModel(candidates)
	assertCompletionHighlight(t, m, candidates, -1)
	for i := 0; i < 4; i++ {
		m.Update(editorKey("tab"))
		assertCompletionHighlight(t, m, candidates, i%len(candidates))
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
	assertCompletionHighlight(t, m, candidates, 2)
	_, cmd := m.Update(editorKey("enter"))
	if m.done || cmd != nil || m.input.Value() != "put binc/" {
		t.Fatal("highlight changed Enter confirmation behavior")
	}
	if strings.Contains(m.View().Content, "\n") {
		t.Fatal("confirmed menu is still visible")
	}
}

func TestCompletionHighlightKeepsSelectionVisible(t *testing.T) {
	candidates := []string{"bina/", "binb/", "binc/", "bind/", "bine/"}
	m := completionMenuModel(candidates)
	m.Update(tea.WindowSizeMsg{Width: 14, Height: 10})
	for i := range candidates {
		m.Update(editorKey("tab"))
		assertCompletionHighlight(t, m, candidates, i)
	}
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 10})
	assertCompletionHighlight(t, m, candidates, 4)
}
