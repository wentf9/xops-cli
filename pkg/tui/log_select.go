package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type logScannerConnectedMsg struct {
	nodeID string
	client *ssh.Client
	err    error
}

type logScanResultMsg struct {
	files []string
	err   error
}

type logFileSelectedMsg struct {
	nodeID string
	client *ssh.Client
	file   string
}

type logSelectItem struct {
	title       string
	description string
}

func (i logSelectItem) Title() string       { return i.title }
func (i logSelectItem) Description() string { return i.description }
func (i logSelectItem) FilterValue() string { return i.title }

type logSelectModel struct {
	nodeID    string
	client    *ssh.Client
	list      list.Model
	textInput textinput.Model
	isManual  bool
	err       error
	fetching  bool
	width     int
	height    int
}

func newLogSelectModel(nodeID string, client *ssh.Client, size tea.WindowSizeMsg) logSelectModel {
	ti := textinput.New()
	ti.Placeholder = i18n.T("tui_log_manual_prompt")
	ti.Focus()

	delegate := list.NewDefaultDelegate()
	l := list.New([]list.Item{}, delegate, size.Width, size.Height)
	l.Title = i18n.T("tui_log_title")
	l.SetShowStatusBar(false)

	return logSelectModel{
		nodeID:    nodeID,
		client:    client,
		list:      l,
		textInput: ti,
		fetching:  true,
		width:     size.Width,
		height:    size.Height,
	}
}

func (m logSelectModel) Init() tea.Cmd {
	return tea.Batch(
		textinput.Blink,
		func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			cmd := `find /var/log -type f -name "*.log" 2>/dev/null | head -n 50`
			// Include docker logs if docker exists
			cmd += `; if command -v docker >/dev/null 2>&1; then docker ps --format 'docker:{{.Names}}' 2>/dev/null; fi`

			out, err := m.client.RunWithoutLogin(ctx, cmd)
			if err != nil {
				return logScanResultMsg{err: err}
			}

			var files []string
			lines := strings.Split(strings.TrimSpace(out), "\n")
			for _, line := range lines {
				if line = strings.TrimSpace(line); line != "" {
					files = append(files, line)
				}
			}
			return logScanResultMsg{files: files}
		},
	)
}

func (m logSelectModel) Update(msg tea.Msg) (logSelectModel, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.list.SetSize(msg.Width, msg.Height)
	case logScanResultMsg:
		m.fetching = false
		m.err = msg.err
		if msg.err == nil {
			var items []list.Item
			items = append(items, logSelectItem{
				title:       i18n.T("tui_log_manual"),
				description: "Enter a custom absolute path to a log file",
			})
			for _, f := range msg.files {
				items = append(items, logSelectItem{
					title:       f,
					description: "Found on remote server",
				})
			}
			cmd = m.list.SetItems(items)
		}
	case tea.KeyMsg:
		if m.isManual {
			switch msg.String() {
			case "enter":
				val := strings.TrimSpace(m.textInput.Value())
				if val != "" {
					return m, func() tea.Msg {
						return logFileSelectedMsg{nodeID: m.nodeID, client: m.client, file: val}
					}
				}
			case "esc":
				m.isManual = false
				m.textInput.SetValue("")
				return m, nil
			}
			m.textInput, cmd = m.textInput.Update(msg)
			return m, cmd
		}

		switch msg.String() {
		case "esc", "q":
			// Handled by parent to go back
		case "enter":
			selected := m.list.SelectedItem()
			if selected != nil {
				title := selected.(logSelectItem).title
				if title == i18n.T("tui_log_manual") {
					m.isManual = true
					return m, nil
				}
				return m, func() tea.Msg {
					return logFileSelectedMsg{nodeID: m.nodeID, client: m.client, file: title}
				}
			}
		}
		m.list, cmd = m.list.Update(msg)
	}
	return m, cmd
}

func (m logSelectModel) View() string {
	if m.err != nil {
		return errorStyle.Render(fmt.Sprintf("Scan error: %v", m.err))
	}
	if m.fetching {
		return i18n.T("tui_log_fetching")
	}
	if m.isManual {
		return fmt.Sprintf("\n%s\n\n%s\n\n(Esc to cancel)",
			i18n.T("tui_log_manual_prompt"),
			m.textInput.View())
	}
	return m.list.View()
}
