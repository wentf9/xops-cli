package sftpshell

import (
	"context"
	"errors"
	"io"
	"reflect"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func editorKey(name string) tea.KeyPressMsg {
	keys := map[string]rune{"enter": tea.KeyEnter, "delete": tea.KeyDelete, "backspace": tea.KeyBackspace, "left": tea.KeyLeft, "right": tea.KeyRight, "up": tea.KeyUp, "down": tea.KeyDown, "tab": tea.KeyTab, "esc": tea.KeyEscape}
	if code, ok := keys[name]; ok {
		return tea.KeyPressMsg{Code: code}
	}
	if len(name) == 6 && name[:5] == "ctrl+" {
		return tea.KeyPressMsg{Code: rune(name[5]), Mod: tea.ModCtrl}
	}
	return tea.KeyPressMsg{Code: []rune(name)[0], Text: name}
}
func TestEditorDeleteAndEOF(t *testing.T) {
	for _, tt := range []struct {
		name, value, key, want string
		pos                    int
		err                    error
		done                   bool
	}{
		{name: "empty delete", key: "delete"},
		{name: "empty EOF", key: "ctrl+d", err: io.EOF, done: true},
		{name: "delete forward", value: "abc", key: "delete", want: "bc"},
		{name: "control delete forward", value: "abc", key: "ctrl+d", want: "bc"},
		{name: "delete end", value: "abc", pos: 3, key: "delete", want: "abc"},
		{name: "control delete end", value: "abc", pos: 3, key: "ctrl+d", want: "abc"},
		{name: "interrupt", value: "abc", pos: 3, key: "ctrl+c", want: "abc", done: true, err: ErrPromptInterrupted},
		{name: "combining delete", value: "e\u0301界", key: "delete", want: "界"},
		{name: "combining backspace", value: "e\u0301界", pos: 2, key: "backspace", want: "界"},
		{name: "emoji delete", value: "👩‍💻界", key: "delete", want: "界"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := newEditorModel(promptOptions{}, nil, nil)
			m.input.SetValue(tt.value)
			m.input.SetCursor(tt.pos)
			m.Update(editorKey(tt.key))
			if m.input.Value() != tt.want || m.done != tt.done || !errors.Is(m.err, tt.err) {
				t.Fatalf("value=%q done=%v err=%v", m.input.Value(), m.done, m.err)
			}
		})
	}
}
func TestEditorHistoryDraftAndSearch(t *testing.T) {
	m := newEditorModel(promptOptions{}, []string{"ls /etc", "get file", "ls /tmp"}, nil)
	m.input.SetValue("draft")
	for _, key := range []string{"up", "up", "down", "down"} {
		m.Update(editorKey(key))
	}
	if m.input.Value() != "draft" {
		t.Fatalf("draft lost: %q", m.input.Value())
	}
	for _, key := range []string{"ctrl+r", "l", "s", "ctrl+r"} {
		m.Update(editorKey(key))
	}
	if m.input.Value() != "ls /etc" {
		t.Fatalf("search = %q", m.input.Value())
	}
	m.Update(editorKey("enter"))
	if m.done || m.search {
		t.Fatal("accepting search must return to editing, not execute")
	}
}
func TestEditorConfirmationAndPaste(t *testing.T) {
	m := newEditorModel(promptOptions{confirmation: true}, []string{"dangerous command"}, func(uint64, string, int) context.CancelFunc { t.Fatal("confirmation requested completion"); return nil })
	for _, key := range []string{"up", "tab", "ctrl+r"} {
		m.Update(editorKey(key))
	}
	if m.input.Value() != "" || m.search {
		t.Fatal("confirmation accessed history")
	}
	m.Update(tea.PasteMsg{Content: "first\r\nsecond\nthird\t\x03"})
	if m.done || m.input.Value() != "first second third " {
		t.Fatalf("paste = %q done=%v", m.input.Value(), m.done)
	}
}
func TestEditorAsyncCompletionPreservesTailAndDiscardsStale(t *testing.T) {
	var id uint64
	canceled := false
	m := newEditorModel(promptOptions{}, nil, func(n uint64, _ string, _ int) context.CancelFunc { id = n; return func() { canceled = true } })
	m.input.SetValue("get 目 tail")
	m.input.SetCursor(5)
	m.Update(editorKey("tab"))
	m.Update(completionMsg{id, "get 目 tail", 5, completionResult{head: "get ", candidates: []string{"目录一/", "目录二/"}, tail: " tail"}})
	if !canceled || m.input.Value() != "get 目录 tail" || m.input.Position() != 6 {
		t.Fatalf("completion = %q @ %d", m.input.Value(), m.input.Position())
	}
	m.Update(editorKey("tab"))
	if m.input.Value() != "get 目录一/ tail" {
		t.Fatal(m.input.Value())
	}
	m.Update(editorKey("x"))
	before := m.input.Value()
	m.Update(completionMsg{id, before, m.input.Position(), completionResult{candidates: []string{"stale"}}})
	if m.input.Value() != before {
		t.Fatal("stale completion applied")
	}
}
func TestEditorResizeAndNavigation(t *testing.T) {
	m := newEditorModel(promptOptions{text: "sftp:界> "}, nil, nil)
	m.input.SetValue("e\u0301界")
	m.input.CursorEnd()
	for _, key := range []string{"left", "left"} {
		m.Update(editorKey(key))
	}
	if m.input.Position() != 0 {
		t.Fatal(m.input.Position())
	}
	m.Update(editorKey("right"))
	if m.input.Position() != 2 {
		t.Fatal(m.input.Position())
	}
	m.Update(tea.WindowSizeMsg{Width: 12, Height: 4})
	if m.View().Content == "" {
		t.Fatal("empty view")
	}
}
func TestCompletionWorkerCancellationAndClose(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	worker := newCompletionWorker(t.Context(), func(ctx context.Context, _ string, _ int) completionResult {
		close(started)
		<-ctx.Done()
		close(finished)
		return completionResult{err: ctx.Err()}
	})
	worker.Start(func(tea.Msg) { t.Error("canceled result was delivered") })
	cancel := worker.Schedule(1, "get ", 4)
	<-started
	cancel()
	worker.Close()
	<-finished
}
func TestCommonCompletionPrefix(t *testing.T) {
	if got := commonCompletionPrefix([]string{"目录a", "目录b"}); got != "目录" {
		t.Fatal(got)
	}
	if !reflect.DeepEqual(normalizePastedText("a\r\nb\x00"), "a b") {
		t.Fatal("paste normalization")
	}
}

func TestEditorCompletionFailureAndReverseCycle(t *testing.T) {
	m := newEditorModel(promptOptions{}, nil, func(uint64, string, int) context.CancelFunc { return func() {} })
	m.input.SetValue("ex")
	m.input.CursorEnd()
	m.Update(editorKey("tab"))
	m.Update(completionMsg{m.requestID, "ex", 2, completionResult{err: context.DeadlineExceeded}})
	if m.hint == "" || m.input.Value() != "ex" {
		t.Fatal("completion error changed input or was hidden")
	}
	m.Update(editorKey("tab"))
	m.Update(completionMsg{m.requestID, "ex", 2, completionResult{candidates: []string{"exec", "exit"}}})
	m.Update(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
	if m.input.Value() != "exit" {
		t.Fatalf("reverse cycle = %q", m.input.Value())
	}
}

func TestEditorLongPromptRetainsQuestion(t *testing.T) {
	m := newEditorModel(promptOptions{text: "a very long confirmation question [y/N]: ", confirmation: true}, nil, nil)
	m.Update(tea.WindowSizeMsg{Width: 20, Height: 10})
	view := m.View()
	if m.promptPrefix == "" || view.Cursor == nil || view.Cursor.Y == 0 {
		t.Fatal("long prompt did not reserve rows for its text")
	}
	m.Update(editorKey("n"))
	if m.input.Value() != "n" {
		t.Fatal("long prompt cannot accept input")
	}
}

func TestEditorUniqueCompletionStartsNewRequest(t *testing.T) {
	for _, tt := range []struct{ name, command, directory string }{
		{"local", "put ", "bin/"},
		{"remote", "get ", "bin/"},
		{"windows local", "put ", "bin\\"},
		{"unicode remote", "get ", "目录/"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var requests []completionMsg
			m := newEditorModel(promptOptions{}, nil, func(id uint64, line string, pos int) context.CancelFunc {
				requests = append(requests, completionMsg{id: id, line: line, pos: pos})
				return func() {}
			})
			const tail = " destination"
			prefix := tt.command + tt.directory[:len(tt.directory)-1]
			m.input.SetValue(prefix + tail)
			m.input.SetCursor(len([]rune(prefix)))
			m.Update(editorKey("tab"))
			reply := requests[0]
			reply.result = completionResult{head: tt.command, candidates: []string{tt.directory}, tail: tail}
			m.Update(reply)
			completed := tt.command + tt.directory
			if m.input.Value() != completed+tail {
				t.Fatal(m.input.Value())
			}
			m.Update(editorKey("tab"))
			if len(requests) != 2 {
				t.Fatalf("Tab after unique directory completion made %d requests, want 2", len(requests))
			}
			next := requests[1]
			if next.line != completed+tail || next.pos != len([]rune(completed)) {
				t.Fatalf("next request = %+v", next)
			}
			next.result = completionResult{head: tt.command, candidates: []string{tt.directory + "file.txt"}, tail: tail}
			m.Update(next)
			if m.input.Value() != tt.command+tt.directory+"file.txt"+tail {
				t.Fatal(m.input.Value())
			}
			// A late response from the parent directory must not replace the child.
			m.Update(reply)
			if m.input.Value() != tt.command+tt.directory+"file.txt"+tail {
				t.Fatal("stale directory completion applied")
			}
		})
	}
}

func TestEditorEnterConfirmsCompletionBeforeSubmitting(t *testing.T) {
	for _, key := range []string{"enter", "ctrl+j"} {
		for _, selection := range []struct {
			name    string
			tabs    int
			reverse bool
			want    string
		}{
			{name: "default first", want: "目录一/"},
			{name: "selected second", tabs: 2, want: "目录二/"},
			{name: "reverse selected", tabs: 1, reverse: true, want: "目录二/"},
		} {
			t.Run(key+"/"+selection.name, func(t *testing.T) {
				requests := 0
				m := newEditorModel(promptOptions{}, nil, func(uint64, string, int) context.CancelFunc { requests++; return func() {} })
				m.input.SetValue("put 目 destination")
				m.input.SetCursor(5)
				m.Update(editorKey("tab"))
				reply := completionMsg{m.requestID, m.input.Value(), m.input.Position(), completionResult{head: "put ", candidates: []string{"目录一/", "目录二/"}, tail: " destination"}}
				m.Update(reply)
				for i := 0; i < selection.tabs; i++ {
					if selection.reverse {
						m.Update(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
					} else {
						m.Update(editorKey("tab"))
					}
				}
				_, cmd := m.Update(editorKey(key))
				if m.done || cmd != nil {
					t.Fatal("confirming a completion submitted the command")
				}
				want := "put " + selection.want + " destination"
				if m.input.Value() != want || m.input.Position() != len([]rune("put "+selection.want)) {
					t.Fatalf("confirmed input=%q @ %d", m.input.Value(), m.input.Position())
				}
				if m.completion != nil || m.hint != "" {
					t.Fatal("confirmation left candidate selection active")
				}
				m.Update(reply)
				if m.input.Value() != want || m.completion != nil {
					t.Fatal("late result reopened completion")
				}
				if requests != 1 {
					t.Fatalf("confirmation scheduled another completion: %d requests", requests)
				}
				// A second Enter submits, without requiring any extra editing.
				_, cmd = m.Update(editorKey(key))
				if !m.done || cmd == nil || m.err != nil {
					t.Fatal("Enter without a menu did not submit")
				}
			})
		}
	}
}

func TestHistorySearchPasteUpdatesQuery(t *testing.T) {
	m := newEditorModel(promptOptions{}, []string{"get needle", "rm other"}, nil)
	m.input.SetValue("draft")
	m.Update(editorKey("ctrl+r"))
	m.Update(tea.PasteMsg{Content: "needle"})
	if m.searchQuery != "needle" || m.input.Value() != "get needle" || !m.search || m.done {
		t.Fatalf("paste: query=%q input=%q search=%v done=%v", m.searchQuery, m.input.Value(), m.search, m.done)
	}
	m.Update(tea.PasteMsg{Content: "\r\nmissing\x03"})
	if m.searchQuery != "needle missing" || m.input.Value() != "get needle" {
		t.Fatalf("unmatched paste changed command: query=%q input=%q", m.searchQuery, m.input.Value())
	}
	m.Update(editorKey("ctrl+g"))
	if m.input.Value() != "draft" || m.search {
		t.Fatal("canceling pasted search did not restore draft")
	}
	m.Update(editorKey("ctrl+r"))
	m.Update(tea.PasteMsg{Content: "needle"})
	m.Update(editorKey("enter"))
	if m.done || m.search || m.input.Value() != "get needle" {
		t.Fatal("accepting pasted search executed or corrupted the match")
	}
}
