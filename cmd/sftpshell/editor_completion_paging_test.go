package sftpshell

import (
	"context"
	"fmt"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
)

func numberedCompletions(count int) []string {
	candidates := make([]string, count)
	for i := range candidates {
		candidates[i] = fmt.Sprintf("bin%03d/", i)
	}
	return candidates
}

func TestCompletionPagingLayoutAndNavigation(t *testing.T) {
	initTestI18n(t)
	candidates := numberedCompletions(50)
	m := completionMenuModel(candidates)
	// Nine cells per item (including the marker), plus two between columns:
	// a 31-column terminal fits three columns and six candidate rows.
	m.Update(tea.WindowSizeMsg{Width: 31, Height: 24})
	view := ansi.Strip(m.View().Content)
	if !strings.Contains(view, "1/3") || !strings.Contains(view, "50") {
		t.Fatalf("missing page/count: %q", view)
	}
	if strings.Count(view, "\n") != 7 {
		t.Fatalf("expected input, six candidate rows and status: %q", view)
	}
	if !strings.Contains(view, "bin017/") || strings.Contains(view, "bin018/") {
		t.Fatalf("first page includes wrong candidates: %q", view)
	}
	for range 19 {
		m.Update(editorKey("tab"))
	}
	if m.input.Value() != "put bin018/" || !strings.Contains(ansi.Strip(m.View().Content), "2/3") {
		t.Fatalf("Tab did not turn page: %q", m.View().Content)
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
	if m.input.Value() != "put bin017/" || !strings.Contains(ansi.Strip(m.View().Content), "1/3") {
		t.Fatal("reverse crossing did not return to first page")
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyPgDown})
	if m.input.Value() != "put bin035/" {
		t.Fatalf("PageDown lost relative position: %q", m.input.Value())
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyPgDown})
	if m.input.Value() != "put bin049/" {
		t.Fatalf("last page did not clamp selection: %q", m.input.Value())
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyPgDown})
	if m.input.Value() != "put bin049/" {
		t.Fatal("PageDown wrapped at last page")
	}
	m.Update(editorKey("tab"))
	if m.input.Value() != "put bin000/" {
		t.Fatal("Tab did not wrap to the first page")
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
	if m.input.Value() != "put bin049/" {
		t.Fatal("Shift+Tab did not wrap to the last page")
	}
	_, cmd := m.Update(editorKey("enter"))
	if m.done || cmd != nil || m.input.Value() != "put bin049/" {
		t.Fatal("Enter submitted instead of accepting a paged candidate")
	}
	if strings.Contains(m.View().Content, "\n") {
		t.Fatal("confirmed page stayed open")
	}
}

func TestCompletionPageKeysAndResize(t *testing.T) {
	initTestI18n(t)
	candidates := numberedCompletions(50)
	m := completionMenuModel(candidates)
	m.Update(tea.WindowSizeMsg{Width: 31, Height: 24})
	m.Update(tea.KeyPressMsg{Code: tea.KeyPgUp})
	if m.candidate != -1 {
		t.Fatal("PageUp on first page inserted a candidate")
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyPgDown})
	if m.input.Value() != "put bin018/" {
		t.Fatalf("initial PageDown=%q", m.input.Value())
	}
	// Reflow to one column and three candidate rows, keeping candidate 18.
	m.Update(tea.WindowSizeMsg{Width: 12, Height: 5})
	view := ansi.Strip(m.View().Content)
	if m.input.Value() != "put bin018/" || !strings.Contains(view, "> bin018/") {
		t.Fatal("resize lost selection")
	}
	if !strings.Contains(view, "7/17") {
		t.Fatalf("resize page count is wrong: %q", view)
	}
	if len(strings.Split(view, "\n")) > 5 {
		t.Fatalf("menu exceeds available terminal height: %q", view)
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyPgUp})
	if m.input.Value() != "put bin015/" {
		t.Fatalf("PageUp after resize=%q", m.input.Value())
	}
	m.Update(editorKey("esc"))
	m.Update(tea.KeyPressMsg{Code: tea.KeyPgDown})
	if m.input.Value() != "put bin015/" || strings.Contains(m.View().Content, "\n") {
		t.Fatal("PageDown without a menu changed input")
	}
}

func TestCompletionPagingLargeListAndNarrowTerminal(t *testing.T) {
	initTestI18n(t)
	candidates := numberedCompletions(1000)
	m := completionMenuModel(candidates)
	for _, size := range []tea.WindowSizeMsg{{Width: 31, Height: 24}, {Width: 9, Height: 4}, {Width: 4, Height: 2}, {Width: 1, Height: 1}} {
		m.Update(size)
		view := m.View().Content
		if len(strings.Split(view, "\n")) > size.Height {
			t.Fatalf("menu exceeds %d rows: %q", size.Height, view)
		}
		// The input has separate horizontal scrolling; check candidate/status rows.
		for _, line := range strings.Split(view, "\n")[1:] {
			if ansi.StringWidth(line) > size.Width {
				t.Fatalf("menu exceeds %d columns: %q", size.Width, line)
			}
		}
		if strings.Contains(view, "bin999/") {
			t.Fatal("off-page candidates were rendered")
		}
	}
}

func TestCompletionPagingLocaleAndUnicodeWidths(t *testing.T) {
	initTestI18n(t)
	candidates := make([]string, 25)
	for i := range candidates {
		candidates[i] = fmt.Sprintf("bin目录%02d/", i)
	}
	m := completionMenuModel(candidates)
	m.Update(tea.WindowSizeMsg{Width: 26, Height: 24})
	m.Update(tea.KeyPressMsg{Code: tea.KeyPgDown})
	if m.candidate != 12 {
		t.Fatalf("wide labels did not produce two columns: selected=%d", m.candidate)
	}
	view := ansi.Strip(m.View().Content)
	if !strings.Contains(view, "> bin目录12/") || !strings.Contains(view, "第 2/3 页，共 25 项") {
		t.Fatalf("localized page=%q", view)
	}
	for _, line := range strings.Split(m.completionView(), "\n") {
		if ansi.StringWidth(line) > 26 {
			t.Fatalf("wide labels overflow: %q", line)
		}
	}
	i18n.SetLang("en")
	t.Cleanup(func() { i18n.SetLang("zh") })
	// Widening recalculates page size without changing selection.
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	if !strings.Contains(ansi.Strip(m.View().Content), "Page 1/1, 25 items") || m.candidate != 12 {
		t.Fatal("English count or resize selection is incorrect")
	}
}

func TestCompletionPagingNewPrefixResetsPage(t *testing.T) {
	initTestI18n(t)
	requests := 0
	m := newEditorModel(promptOptions{}, nil, func(uint64, string, int) context.CancelFunc { requests++; return func() {} })
	m.Update(tea.WindowSizeMsg{Width: 31, Height: 24})
	m.input.SetValue("put bin")
	m.input.CursorEnd()
	m.Update(editorKey("tab"))
	original := completionMsg{m.requestID, m.input.Value(), m.input.Position(), completionResult{head: "put ", candidates: numberedCompletions(50)}}
	m.Update(original)
	m.Update(tea.KeyPressMsg{Code: tea.KeyPgDown})
	m.Update(editorKey("ctrl+u"))
	m.Update(editorKey("put bin01"))
	if len(m.menu.labels) != 0 || m.completion != nil {
		t.Fatal("editing kept the old pages")
	}
	m.Update(editorKey("tab"))
	filtered := numberedCompletions(20)[10:20]
	m.Update(completionMsg{m.requestID, m.input.Value(), m.input.Position(), completionResult{head: "put ", candidates: filtered}})
	m.Update(original)
	if requests != 2 || m.candidate != -1 || !strings.Contains(ansi.Strip(m.View().Content), "1/1") || len(m.menu.labels) != 10 {
		t.Fatal("new prefix did not reset pagination or stale result was accepted")
	}
}
