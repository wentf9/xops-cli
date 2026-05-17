package tui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type logLineMsg string
type logStreamClosedMsg struct{ err error }
type logStreamSessionMsg struct {
	reader io.ReadCloser
}

type logStreamerModel struct {
	file      string
	client    *ssh.Client
	reader    io.ReadCloser
	viewport  viewport.Model
	textInput textinput.Model

	lineChan chan string
	lines    []string
	maxLines int

	filterOn    bool
	highlightOn bool
	isSearching bool

	width  int
	height int
	err    error
}

func newLogStreamerModel(client *ssh.Client, file string, size tea.WindowSizeMsg) logStreamerModel {
	ti := textinput.New()
	ti.Placeholder = i18n.T("tui_log_search_prompt")

	vp := viewport.New(size.Width, size.Height-3)

	return logStreamerModel{
		file:      file,
		client:    client,
		viewport:  vp,
		textInput: ti,
		maxLines:  1000,
		lines:     make([]string, 0, 1000),
		lineChan:  make(chan string, 100),
		width:     size.Width,
		height:    size.Height,
	}
}

func (m logStreamerModel) Init() tea.Cmd {
	return tea.Batch(
		m.startStream(),
		m.waitForLine(),
	)
}

func (m *logStreamerModel) startStream() tea.Cmd {
	return func() tea.Msg {
		cmd := fmt.Sprintf("tail -n 100 -f %s", m.file)
		if after, ok := strings.CutPrefix(m.file, "docker:"); ok {
			container := after
			cmd = fmt.Sprintf("docker logs --tail 100 -f %s", container)
		}

		stdout, err := m.client.RunStream(context.Background(), cmd)
		if err != nil {
			return logStreamClosedMsg{err: err}
		}

		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				m.lineChan <- scanner.Text()
			}
			m.lineChan <- "\x04EOF\x04"
		}()

		return logStreamSessionMsg{reader: stdout}
	}
}

func (m logStreamerModel) waitForLine() tea.Cmd {
	return func() tea.Msg {
		line := <-m.lineChan
		if line == "\x04EOF\x04" {
			return logStreamClosedMsg{err: nil}
		}
		return logLineMsg(line)
	}
}

func (m logStreamerModel) Update(msg tea.Msg) (logStreamerModel, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - 3
		m.updateViewportContent()

	case logStreamSessionMsg:
		m.reader = msg.reader

	case logLineMsg:
		if len(m.lines) >= m.maxLines {
			m.lines = m.lines[1:]
		}
		m.lines = append(m.lines, string(msg))
		m.updateViewportContent()
		m.viewport.GotoBottom()
		cmds = append(cmds, m.waitForLine())

	case logStreamClosedMsg:
		m.err = msg.err

	case tea.KeyMsg:
		if m.isSearching {
			switch msg.String() {
			case "enter":
				m.isSearching = false
				m.updateViewportContent()
				m.viewport.GotoBottom()
				return m, nil
			case "esc":
				m.isSearching = false
				m.textInput.SetValue("")
				m.updateViewportContent()
				return m, nil
			}
			m.textInput, cmd = m.textInput.Update(msg)
			cmds = append(cmds, cmd)
			m.updateViewportContent()
			return m, tea.Batch(cmds...)
		}

		switch msg.String() {
		case "esc", "q":
			if m.reader != nil {
				_ = m.reader.Close()
			}
			// Let parent handle it to return
		case "/":
			m.isSearching = true
			m.textInput.Focus()
			cmds = append(cmds, textinput.Blink)
		case "f":
			m.filterOn = !m.filterOn
			m.updateViewportContent()
		case "h":
			m.highlightOn = !m.highlightOn
			m.updateViewportContent()
		}

		m.viewport, cmd = m.viewport.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *logStreamerModel) updateViewportContent() {
	term := m.textInput.Value()

	var visibleLines []string
	for _, line := range m.lines {
		if m.filterOn && term != "" {
			if !strings.Contains(line, term) {
				continue
			}
		}

		displayLine := line
		if m.highlightOn && term != "" {
			displayLine = strings.ReplaceAll(displayLine, term, lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render(term))
		}
		visibleLines = append(visibleLines, displayLine)
	}

	m.viewport.SetContent(strings.Join(visibleLines, "\n"))
}

func (m logStreamerModel) View() string {
	if m.err != nil {
		return errorStyle.Render(fmt.Sprintf("Stream error: %v", m.err))
	}

	header := headerStyle.Render(i18n.Tf("tui_log_stream_header", map[string]any{
		"File":      m.file,
		"Filter":    m.filterOn,
		"Highlight": m.highlightOn,
	}))

	footerText := i18n.T("tui_log_stream_footer")
	if m.isSearching {
		footerText = "\n" + m.textInput.View()
	}

	return fmt.Sprintf("%s\n%s%s", header, m.viewport.View(), footerText)
}
