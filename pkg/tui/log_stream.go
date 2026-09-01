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

type logLineMsg struct {
	sessionID int64
	line      string
}
type logStreamClosedMsg struct {
	sessionID int64
	err       error
}
type logStreamSessionMsg struct {
	sessionID int64
	reader    io.ReadCloser
}

type logStreamerModel struct {
	ctx       context.Context
	cancel    context.CancelFunc
	sessionID int64
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

func newLogStreamerModel(ctx context.Context, sessionID int64, client *ssh.Client, file string, size tea.WindowSizeMsg) logStreamerModel {
	ti := textinput.New()
	ti.Placeholder = i18n.T("tui_log_search_prompt")

	vp := viewport.New(size.Width, size.Height-3)

	streamCtx, cancel := context.WithCancel(ctx)
	return logStreamerModel{
		ctx:       streamCtx,
		cancel:    cancel,
		sessionID: sessionID,
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

		stdout, err := m.client.RunStream(m.ctx, cmd)
		if err != nil {
			return logStreamClosedMsg{sessionID: m.sessionID, err: err}
		}

		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				select {
				case m.lineChan <- scanner.Text():
				case <-m.ctx.Done():
					return
				}
			}
			if err := scanner.Err(); err != nil {
				select {
				case m.lineChan <- fmt.Sprintf("error scanning log stream: %v", err):
				case <-m.ctx.Done():
					return
				}
			}
			select {
			case m.lineChan <- "\x04EOF\x04":
			case <-m.ctx.Done():
			}
		}()

		return logStreamSessionMsg{sessionID: m.sessionID, reader: stdout}
	}
}

func (m logStreamerModel) waitForLine() tea.Cmd {
	return func() tea.Msg {
		var line string
		select {
		case line = <-m.lineChan:
		case <-m.ctx.Done():
			return logStreamClosedMsg{sessionID: m.sessionID, err: m.ctx.Err()}
		}
		if line == "\x04EOF\x04" {
			return logStreamClosedMsg{sessionID: m.sessionID}
		}
		return logLineMsg{sessionID: m.sessionID, line: line}
	}
}

func (m *logStreamerModel) Close() error {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	if m.reader == nil {
		return nil
	}
	reader := m.reader
	m.reader = nil
	if err := reader.Close(); err != nil {
		return fmt.Errorf("close log stream failed: %w", err)
	}
	return nil
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
		if msg.sessionID == m.sessionID {
			m.reader = msg.reader
		}

	case logLineMsg:
		if msg.sessionID != m.sessionID {
			return m, nil
		}
		if len(m.lines) >= m.maxLines {
			m.lines = m.lines[1:]
		}
		m.lines = append(m.lines, msg.line)
		m.updateViewportContent()
		m.viewport.GotoBottom()
		cmds = append(cmds, m.waitForLine())

	case logStreamClosedMsg:
		if msg.sessionID == m.sessionID {
			m.err = msg.err
		}

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
			if err := m.Close(); err != nil {
				m.err = err
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
