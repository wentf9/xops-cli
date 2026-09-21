package sftpshell

import (
	"context"
	"errors"
	"io"
	"strings"
	"unicode"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/rivo/uniseg"
)

type completionScheduler func(uint64, string, int) context.CancelFunc

type editorModel struct {
	input         textinput.Model
	options       promptOptions
	history       []string
	historyPos    int
	draft         string
	search        bool
	searchQuery   string
	searchPos     int
	searchDraft   string
	hint          string
	width         int
	height        int
	menu          completionMenu
	promptPrefix  string
	inputOffset   int
	done          bool
	err           error
	schedule      completionScheduler
	requestID     uint64
	pendingCancel context.CancelFunc
	completion    *completionResult
	candidate     int
}

func newEditorModel(options promptOptions, history []string, schedule completionScheduler) *editorModel {
	input := textinput.New()
	input.Prompt = options.text
	input.SetVirtualCursor(false)
	input.SetStyles(textinput.Styles{})
	input.CharLimit = 1024 * 1024
	input.KeyMap.Paste.SetEnabled(false) // Terminal bracketed paste is handled below.
	input.Focus()
	return &editorModel{input: input, options: options, history: history, historyPos: len(history), schedule: schedule, width: 80, height: 24, candidate: -1}
}
func (m *editorModel) Init() tea.Cmd { return nil }
func (m *editorModel) View() tea.View {
	if m.done {
		// The runner writes the transcript after the renderer has stopped.
		// A final View would clip commands taller than the terminal.
		return tea.NewView("")
	}
	input, cursor := m.inputView()
	text := m.promptPrefix + input
	if m.completion != nil && len(m.completion.candidates) > 1 {
		if menu := m.completionView(); menu != "" {
			text += "\n" + menu
		}
	} else if m.hint != "" {
		text += "\n" + ansi.Truncate(m.hint, max(1, m.width), "…")
	}
	view := tea.NewView(text)
	view.Cursor = cursor
	return view
}

// transcript is regular output, so the terminal can wrap and scroll all of it.
func (m *editorModel) transcript() string {
	suffix := ""
	if errors.Is(m.err, ErrPromptInterrupted) {
		suffix = "^C"
	}
	if errors.Is(m.err, io.EOF) {
		suffix = "^D"
	}
	return m.options.text + m.input.Value() + suffix + "\n"
}

func (m *editorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if delivery, ok := msg.(editorDelivery); ok {
		if m.done {
			delivery.receipt <- editorReceipt{}
			return m, nil
		}
		model, command := m.Update(delivery.message)
		delivery.receipt <- editorReceipt{consumed: true, finished: m.done}
		return model, command
	}
	defer m.updateInputViewport()
	if m.done {
		return m, nil
	}
	switch msg := msg.(type) {
	case editorInputEnded:
		return m.finish(msg.err)
	case tea.WindowSizeMsg:
		m.width = max(1, msg.Width)
		if msg.Height > 0 {
			m.height = msg.Height
		}
		m.promptPrefix = ""
		m.input.Prompt = m.options.text
		if ansi.StringWidth(m.options.text) >= max(1, msg.Width-2) {
			m.promptPrefix = ansi.Hardwrap(strings.TrimSpace(m.options.text), max(1, msg.Width), true) + "\n"
			m.input.Prompt = "> "
		}
		m.input.SetWidth(max(1, msg.Width-ansi.StringWidth(m.input.Prompt)-1))
		m.input.SetCursor(m.input.Position()) // Recompute horizontal scrolling after a resize.
		return m, nil
	case completionMsg:
		m.acceptCompletion(msg)
		return m, nil
	case tea.PasteMsg:
		if m.search {
			m.searchQuery += normalizePastedText(msg.Content)
			m.searchPos = len(m.history)
			m.findHistory()
			return m, nil
		}
		m.invalidateCompletion()
		m.insertText(normalizePastedText(msg.Content))
		return m, nil
	case tea.KeyPressMsg:
		return m.updateKey(msg)
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}
func (m *editorModel) finish(err error) (tea.Model, tea.Cmd) {
	m.invalidateCompletion()
	m.done = true
	m.err = err
	return m, tea.Quit
}

//nolint:gocyclo
func (m *editorModel) updateKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key == "ctrl+c" {
		return m.finish(ErrPromptInterrupted)
	}
	if m.search {
		return m.updateSearch(msg)
	}
	switch key {
	case "enter", "ctrl+j":
		if m.confirmCompletion() {
			return m, nil
		}
		return m.finish(nil)
	case "ctrl+d":
		if m.input.Value() == "" {
			return m.finish(io.EOF)
		}
	case "tab", "shift+tab":
		if !m.options.confirmation {
			m.complete(key == "shift+tab")
		}
		return m, nil
	case "pgup":
		m.pageCompletion(-1)
		return m, nil
	case "pgdown":
		m.pageCompletion(1)
		return m, nil
	case "up", "ctrl+p":
		if !m.options.confirmation {
			m.browseHistory(-1)
		}
		return m, nil
	case "down", "ctrl+n":
		if !m.options.confirmation {
			m.browseHistory(1)
		}
		return m, nil
	case "ctrl+r":
		if !m.options.confirmation {
			m.invalidateCompletion()
			m.search = true
			m.searchQuery = ""
			m.searchDraft = m.input.Value()
			m.searchPos = len(m.history)
			m.findHistory()
		}
		return m, nil
	case "esc":
		m.invalidateCompletion()
		return m, nil
	}
	m.invalidateCompletion()
	if m.editGrapheme(key) {
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}
func normalizePastedText(text string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.ReplaceAll(text, "\r\n", "\n"))
}
func (m *editorModel) insertText(text string) {
	line := []rune(m.input.Value())
	pos := m.input.Position()
	m.input.SetValue(string(line[:pos]) + text + string(line[pos:]))
	m.input.SetCursor(pos + len([]rune(text)))
}
func (m *editorModel) browseHistory(delta int) {
	m.invalidateCompletion()
	if m.historyPos == len(m.history) {
		m.draft = m.input.Value()
	}
	m.historyPos = max(0, min(len(m.history), m.historyPos+delta))
	value := m.draft
	if m.historyPos < len(m.history) {
		value = m.history[m.historyPos]
	}
	m.input.SetValue(value)
	m.input.CursorEnd()
}
func (m *editorModel) updateSearch(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc":
		m.search = false
		m.hint = ""
		return m, nil
	case "ctrl+g":
		m.search = false
		m.hint = ""
		m.input.SetValue(m.searchDraft)
		m.input.CursorEnd()
		return m, nil
	case "ctrl+r":
		m.findHistory()
		return m, nil
	case "backspace", "ctrl+h":
		query := []rune(m.searchQuery)
		if len(query) > 0 {
			m.searchQuery = string(query[:len(query)-1])
		}
	default:
		if msg.Text == "" {
			return m, nil
		}
		m.searchQuery += normalizePastedText(msg.Text)
	}
	m.searchPos = len(m.history)
	m.findHistory()
	return m, nil
}
func (m *editorModel) findHistory() {
	for i := m.searchPos - 1; i >= 0; i-- {
		if strings.Contains(m.history[i], m.searchQuery) {
			m.searchPos = i
			m.input.SetValue(m.history[i])
			m.input.CursorEnd()
			m.hint = "history search: " + m.searchQuery
			return
		}
	}
	m.hint = "history search: " + m.searchQuery + " (no match)"
}
func (m *editorModel) invalidateCompletion() {
	m.requestID++
	if m.pendingCancel != nil {
		m.pendingCancel()
		m.pendingCancel = nil
	}
	m.completion = nil
	m.menu = completionMenu{}
	m.candidate = -1
	m.hint = ""
}

// confirmCompletion accepts the current candidate without submitting input.
// Before cycling begins, Enter chooses the first candidate in the menu.
func (m *editorModel) confirmCompletion() bool {
	if m.completion == nil || len(m.completion.candidates) < 2 {
		return false
	}
	m.replaceCompletion(m.completion.candidates[max(0, m.candidate)])
	m.invalidateCompletion()
	return true
}

func (m *editorModel) complete(reverse bool) {
	if m.completion != nil && len(m.completion.candidates) > 0 {
		delta := 1
		if reverse {
			delta = -1
		}
		if m.candidate < 0 && reverse {
			m.candidate = len(m.completion.candidates) - 1
		} else {
			m.candidate = (m.candidate + delta + len(m.completion.candidates)) % len(m.completion.candidates)
		}
		m.replaceCompletion(m.completion.candidates[m.candidate])
		return
	}
	if m.pendingCancel != nil || m.schedule == nil {
		return
	}
	m.requestID++
	m.hint = "completing…"
	m.pendingCancel = m.schedule(m.requestID, m.input.Value(), m.input.Position())
}
func (m *editorModel) acceptCompletion(msg completionMsg) {
	if msg.id != m.requestID || msg.line != m.input.Value() || msg.pos != m.input.Position() {
		return
	}
	if m.pendingCancel != nil {
		m.pendingCancel()
		m.pendingCancel = nil
	}
	if msg.result.err != nil {
		m.hint = "completion failed: " + normalizePastedText(msg.result.err.Error())
		return
	}
	m.completion = &msg.result
	m.candidate = -1
	switch len(msg.result.candidates) {
	case 0:
		m.hint = "no completions"
	case 1:
		m.replaceCompletion(msg.result.candidates[0])
		// A unique result is accepted, not a candidate-cycling session. The
		// next Tab must query the new input (for example, children of bin/).
		m.invalidateCompletion()
	default:
		m.menu = newCompletionMenu(msg.result.candidates)
		prefix := commonCompletionPrefix(msg.result.candidates)
		typed := []rune(msg.line)[len([]rune(msg.result.head)):msg.pos]
		if len([]rune(prefix)) > len(typed) {
			m.replaceCompletion(prefix)
		}
		m.hint = ""
	}
}
func (m *editorModel) replaceCompletion(value string) {
	m.input.SetValue(m.completion.head + value + m.completion.tail)
	m.input.SetCursor(len([]rune(m.completion.head + value)))
}
func commonCompletionPrefix(candidates []string) string {
	prefix := []rune(candidates[0])
	for _, candidate := range candidates[1:] {
		rs := []rune(candidate)
		n := 0
		for n < len(prefix) && n < len(rs) && prefix[n] == rs[n] {
			n++
		}
		prefix = prefix[:n]
	}
	return string(prefix)
}

// Cursor positions use runes, while edits operate on complete grapheme clusters.
func (m *editorModel) editGrapheme(key string) bool {
	switch key {
	case "left", "ctrl+b", "right", "ctrl+f", "delete", "ctrl+d", "backspace", "ctrl+h":
	default:
		return false
	}
	text := m.input.Value()
	pos := m.input.Position()
	before, after := 0, len([]rune(text))
	gr := uniseg.NewGraphemes(text)
	offset := 0
	for gr.Next() {
		end := offset + len([]rune(gr.Str()))
		if offset < pos {
			before = offset
		}
		if end > pos {
			after = end
			break
		}
		offset = end
	}
	switch key {
	case "left", "ctrl+b":
		m.input.SetCursor(before)
	case "right", "ctrl+f":
		m.input.SetCursor(after)
	default:
		start, end := pos, after
		if key == "backspace" || key == "ctrl+h" {
			start, end = before, pos
		}
		rs := []rune(text)
		m.input.SetValue(string(rs[:start]) + string(rs[end:]))
		m.input.SetCursor(start)
	}
	return true
}
