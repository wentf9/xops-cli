package tui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type viewState int

const (
	viewList viewState = iota
	viewForm
	viewTagSelect
	viewMonitor
)

type Model struct {
	provider      config.ConfigProvider
	configStore   config.Store
	connector     *ssh.Connector
	list          list.Model
	form          *huh.Form
	formState     *nodeFormState
	tagForm       *huh.Form
	monitor       monitorModel
	tagMode       string // "add" or "remove"
	selectedTags  []string
	newTagsInput  string // 新标签输入
	state         viewState
	status        string
	lastSize      tea.WindowSizeMsg
	deletePending bool
}

// NewModel initializes the TUI model.
func NewModel(provider config.ConfigProvider, configStore config.Store) Model {
	m := Model{
		provider:    provider,
		configStore: configStore,
		connector:   ssh.NewConnector(provider),
		state:       viewList,
	}
	m.list = newListModel(provider)
	return m
}

func (m Model) Init() tea.Cmd {
	return nil
}

type tickMsg time.Time

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.lastSize = msg
	case monitorConnectedMsg:
		if msg.err != nil {
			m.status = errorStyle.Render(fmt.Sprintf("Connection failed: %v", msg.err))
			return m, nil
		}
		m.status = ""
		m.monitor = newMonitorModel(msg.nodeID, msg.client)
		m.state = viewMonitor
		return m, m.monitor.Init()
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case tickMsg:
		// 只有在非删除确认状态下，才自动清除状态
		if !m.deletePending {
			m.status = ""
			if m.state == viewList {
				*m, _ = m.updateList(m.lastSize)
			}
		}
		return m, nil
	}

	cmd := m.handleStateUpdate(msg)

	// If status was just set, start a timer to clear it
	// 但如果是删除确认状态，我们不希望它自动消失
	if m.status != "" && !m.deletePending {
		return m, tea.Batch(cmd, tea.Tick(time.Second*3, func(t time.Time) tea.Msg {
			return tickMsg(t)
		}))
	}

	return m, cmd
}

func (m *Model) handleStateUpdate(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	oldState := m.state
	switch m.state {
	case viewList:
		*m, cmd = m.updateList(msg)
	case viewForm:
		*m, cmd = m.updateForm(msg)
	case viewTagSelect:
		*m, cmd = m.updateTagSelect(msg)
	case viewMonitor:
		if kmsg, ok := msg.(tea.KeyMsg); ok {
			if kmsg.String() == "esc" || kmsg.String() == "q" {
				m.state = viewList
				*m, _ = m.updateList(m.lastSize)
				return nil
			}
		}
		var mCmd tea.Cmd
		m.monitor, mCmd = m.monitor.Update(msg)
		cmd = mCmd
	}

	// If we just switched from form to list, force a resize
	if oldState == viewForm && m.state == viewList {
		*m, _ = m.updateList(m.lastSize)
	}

	return cmd
}

func (m Model) View() string {
	var s string
	switch m.state {
	case viewList:
		s = m.list.View()
	case viewForm:
		if m.form != nil {
			s = m.form.View()
		} else {
			s = "Form View (WIP)"
		}
	case viewTagSelect:
		if m.tagForm != nil {
			s = m.tagForm.View()
		} else {
			s = "Tag Select (WIP)"
		}
	case viewMonitor:
		s = m.monitor.View()
	}

	if m.status != "" {
		s += "\n\n" + statusStyle.Render(m.status)
	}

	return appStyle.Render(s)
}
