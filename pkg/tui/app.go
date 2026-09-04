package tui

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type viewState int

const (
	viewList viewState = iota
	viewForm
	viewTagSelect
	viewMonitor
	viewLogSelect
	viewLogStream
)

type Model struct {
	ctx              context.Context
	repository       *config.Repository
	connector        *ssh.Connector
	list             list.Model
	form             *huh.Form
	formState        *nodeFormState
	tagForm          *huh.Form
	monitor          monitorModel
	logSelect        logSelectModel
	logStreamer      logStreamerModel
	logSessionID     int64
	tagMode          string // "add" or "remove"
	selectedTags     []string
	newTagsInput     string // 新标签输入
	listRevision     uint64
	tagRevision      uint64
	state            viewState
	status           string
	lastSize         tea.WindowSizeMsg
	deletePending    bool
	mutationPending  bool
	mutation         *configurationMutation
	lifecycleCancel  context.CancelFunc
	statusGeneration uint64
	formConflict     bool
}

const configMutationTimeout = 10 * time.Second

type configurationMutationKind int

const (
	configurationMutationForm configurationMutationKind = iota
	configurationMutationTags
	configurationMutationDelete
)

type configurationMutationMsg struct {
	id     uint64
	kind   configurationMutationKind
	nodeID string
	count  int
	err    error
}

// configurationMutation owns one configuration write started by the TUI.  A
// Bubble Tea command is not joined by Program.Run, so the owner must be able
// to cancel and wait for it during shutdown.
type configurationMutation struct {
	mu       sync.Mutex
	id       uint64
	cancel   context.CancelFunc
	done     chan struct{}
	started  bool
	closing  bool
	finished bool
	err      error
	observed bool
}

func newConfigurationMutation(id uint64) *configurationMutation {
	return &configurationMutation{id: id, done: make(chan struct{})}
}

func (m *configurationMutation) start(parent context.Context) (context.Context, context.CancelFunc, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(parent, configMutationTimeout)
	m.cancel = cancel
	m.started = true
	return ctx, cancel, true
}

func (m *configurationMutation) finish(err error) {
	m.mu.Lock()
	m.err = err
	m.finished = true
	close(m.done)
	m.mu.Unlock()
}

func (m *configurationMutation) observe() {
	m.mu.Lock()
	m.observed = true
	m.mu.Unlock()
}

func (m *configurationMutation) close() error {
	m.mu.Lock()
	m.closing = true
	cancel := m.cancel
	started := m.started
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if !started {
		return nil
	}
	<-m.done
	m.mu.Lock()
	err := m.err
	observed := m.observed
	m.mu.Unlock()
	if observed || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// ModelOption configures dependencies used by a TUI model.
type ModelOption func(*modelConfig)

type modelConfig struct {
	logger      logger.DebugLogger
	ctx         context.Context
	interaction ssh.InteractionHandler
}

// WithInteractionHandler injects presentation-owned SSH prompts into the TUI.
func WithInteractionHandler(interaction ssh.InteractionHandler) ModelOption {
	return func(cfg *modelConfig) {
		cfg.interaction = interaction
	}
}

// WithLogger injects the debug logger used by TUI-owned package components.
func WithLogger(l logger.DebugLogger) ModelOption {
	return func(cfg *modelConfig) {
		if l != nil {
			cfg.logger = l
		}
	}
}

// WithContext injects the lifetime context for TUI-owned I/O and goroutines.
func WithContext(ctx context.Context) ModelOption {
	return func(cfg *modelConfig) {
		if ctx != nil {
			cfg.ctx = ctx
		}
	}
}

// NewModel initializes the TUI model. Package components use a no-op logger
// unless the CLI composition root explicitly supplies one with WithLogger.
func NewModel(repository *config.Repository, opts ...ModelOption) (Model, error) {
	if repository == nil {
		return Model{}, fmt.Errorf("TUI configuration repository is nil")
	}
	cfg := modelConfig{logger: logger.NopLogger, ctx: context.Background()}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	var connOpts []ssh.Option
	if cfg.logger != nil {
		connOpts = append(connOpts, ssh.WithLogger(cfg.logger))
	}
	if cfg.interaction != nil {
		connOpts = append(connOpts, ssh.WithInteractionHandler(cfg.interaction))
	}
	connector := adapter.NewConnector(repository, connOpts...)
	view := repository.View()
	lifecycleCtx, lifecycleCancel := context.WithCancel(cfg.ctx)
	m := Model{
		ctx:             lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		repository:      repository,
		connector:       connector,
		state:           viewList,
		listRevision:    view.Revision,
	}
	m.list = newListModelFromView(view)
	return m, nil
}

func (m *Model) refreshList() {
	view := m.repository.View()
	m.list = newListModelFromView(view)
	m.listRevision = view.Revision
}

func configurationMutationCmd(parent context.Context, task *configurationMutation, kind configurationMutationKind, nodeID string, count int, run func(context.Context) error) tea.Cmd {
	if parent == nil {
		parent = context.Background()
	}
	return func() tea.Msg {
		ctx, cancel, ok := task.start(parent)
		if !ok {
			return configurationMutationMsg{id: task.id, kind: kind, nodeID: nodeID, count: count, err: context.Canceled}
		}
		err := run(ctx)
		cancel()
		task.finish(err)
		return configurationMutationMsg{id: task.id, kind: kind, nodeID: nodeID, count: count, err: err}
	}
}

func (m *Model) beginConfigurationMutation(kind configurationMutationKind, nodeID string, count int, run func(context.Context) error) tea.Cmd {
	if m.mutationPending {
		return nil
	}
	m.statusGeneration++
	task := newConfigurationMutation(m.statusGeneration)
	m.mutation = task
	m.mutationPending = true
	m.status = i18n.T("tui_status_saving")
	return configurationMutationCmd(m.ctx, task, kind, nodeID, count, run)
}

func (m *Model) setConfigurationStatus(status string) tea.Cmd {
	m.statusGeneration++
	m.status = status
	generation := m.statusGeneration
	return tea.Tick(3*time.Second, func(time.Time) tea.Msg {
		return tickMsg{generation: generation}
	})
}

func (m *Model) handleConfigurationMutation(msg configurationMutationMsg) (tea.Model, tea.Cmd) {
	if m.mutation == nil || msg.id != m.mutation.id {
		return m, nil
	}
	m.mutation.observe()
	m.mutation = nil
	m.mutationPending = false
	if msg.err != nil {
		var durabilityErr *config.DurabilityError
		switch {
		case errors.As(msg.err, &durabilityErr):
			m.refreshList()
			m.state = viewList
			m.status = errorStyle.Render(i18n.Tf("tui_status_not_durable", map[string]any{"Error": msg.err}))
		case errors.Is(msg.err, config.ErrConfigConflict):
			m.formConflict = msg.kind == configurationMutationForm
			m.status = errorStyle.Render(i18n.Tf("tui_status_conflict", map[string]any{"Error": msg.err}))
		case errors.Is(msg.err, context.Canceled), errors.Is(msg.err, context.DeadlineExceeded):
			m.status = errorStyle.Render(i18n.Tf("tui_status_update_canceled", map[string]any{"Error": msg.err}))
		default:
			m.status = errorStyle.Render(i18n.Tf("tui_status_update_failed", map[string]any{"Error": msg.err}))
		}
		if m.state == viewForm && m.formState != nil {
			_, formCmd := m.initForm("")
			return m, tea.Batch(formCmd, m.setConfigurationStatus(m.status))
		}
		if m.state == viewTagSelect {
			_, tagCmd := m.rebuildTagSelectForm()
			return m, tea.Batch(tagCmd, m.setConfigurationStatus(m.status))
		}
		if m.state == viewList {
			if msg.kind == configurationMutationDelete {
				m.refreshList()
				m.deletePending = false
			}
			*m, _ = m.updateList(m.lastSize)
		}
		return m, m.setConfigurationStatus(m.status)
	}

	switch msg.kind {
	case configurationMutationForm:
		m.status = successStyle.Render(i18n.Tf("tui_status_saved", map[string]any{"ID": msg.nodeID}))
	case configurationMutationTags:
		m.updateTagStatus(msg.count)
	case configurationMutationDelete:
		m.status = successStyle.Render(i18n.Tf("tui_status_deleted", map[string]any{"Count": msg.count}))
	}
	m.state = viewList
	m.refreshList()
	*m, _ = m.updateList(m.lastSize)
	return m, m.setConfigurationStatus(m.status)
}

func (m Model) Init() tea.Cmd {
	return nil
}

// Close releases all TUI-owned streams and pooled SSH connections.
func (m *Model) Close() error {
	var closeErrs []error
	if m.lifecycleCancel != nil {
		m.lifecycleCancel()
	}
	if m.mutation != nil {
		if err := m.mutation.close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("wait for configuration mutation: %w", err))
		}
	}
	if m.monitor.collector != nil {
		if err := m.monitor.collector.Close(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("close TUI monitor: %w", err))
		}
	}
	if err := m.logStreamer.Close(); err != nil {
		closeErrs = append(closeErrs, err)
	}
	if m.connector != nil {
		if err := m.connector.CloseAll(); err != nil {
			closeErrs = append(closeErrs, fmt.Errorf("close SSH connector failed: %w", err))
		}
	}
	return errors.Join(closeErrs...)
}

type tickMsg struct {
	generation uint64
}

// handleAsyncMessage routes messages produced by connection and configuration
// commands. It keeps the primary Bubble Tea update loop focused on lifecycle
// events and view dispatch.
func (m *Model) handleAsyncMessage(msg tea.Msg) (bool, tea.Cmd) {
	switch msg := msg.(type) {
	case monitorConnectedMsg:
		if msg.err != nil {
			m.status = errorStyle.Render(fmt.Sprintf("Connection failed: %v", msg.err))
			return true, nil
		}
		m.status = ""
		m.monitor = newMonitorModel(m.ctx, msg.nodeID, msg.client)
		m.state = viewMonitor
		return true, m.monitor.Init()
	case logScannerConnectedMsg:
		if msg.err != nil {
			m.status = errorStyle.Render(fmt.Sprintf("Connection failed: %v", msg.err))
			return true, nil
		}
		m.status = ""
		m.logSelect = newLogSelectModel(m.ctx, msg.nodeID, msg.client, m.lastSize)
		m.state = viewLogSelect
		return true, m.logSelect.Init()
	case logFileSelectedMsg:
		m.logSessionID++
		m.logStreamer = newLogStreamerModel(m.ctx, m.logSessionID, msg.client, msg.file, m.lastSize)
		m.state = viewLogStream
		return true, m.logStreamer.Init()
	case logStreamSessionMsg:
		if m.state == viewLogStream && msg.sessionID == m.logSessionID {
			m.logStreamer.reader = msg.reader
			return true, nil
		}
		if err := msg.reader.Close(); err != nil {
			m.status = errorStyle.Render(fmt.Sprintf("Close stale log stream failed: %v", err))
		}
		return true, nil
	case logStreamClosedMsg:
		if msg.sessionID != m.logSessionID {
			return true, nil
		}
		return false, nil
	case configurationMutationMsg:
		_, cmd := m.handleConfigurationMutation(msg)
		return true, cmd
	default:
		return false, nil
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if handled, cmd := m.handleAsyncMessage(msg); handled {
		return m, cmd
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.lastSize = msg
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case tickMsg:
		// 只有在非删除确认状态下，才自动清除状态
		if msg.generation == m.statusGeneration && !m.deletePending && !m.mutationPending {
			m.status = ""
			if m.state == viewList {
				m.refreshList()
				*m, _ = m.updateList(m.lastSize)
			}
		}
		return m, nil
	}

	cmd := m.handleStateUpdate(msg)

	// If status was just set, start a timer to clear it
	// 但如果是删除确认状态，我们不希望它自动消失
	if m.status != "" && !m.deletePending && !m.mutationPending {
		return m, tea.Batch(cmd, tea.Tick(time.Second*3, func(t time.Time) tea.Msg {
			return tickMsg{generation: m.statusGeneration}
		}))
	}

	return m, cmd
}

//nolint:gocyclo
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
				if err := m.monitor.collector.Close(); err != nil {
					m.status = errorStyle.Render(fmt.Sprintf("Close monitor failed: %v", err))
				}
				m.state = viewList
				m.refreshList()
				*m, _ = m.updateList(m.lastSize)
				return nil
			}
		}
		var mCmd tea.Cmd
		m.monitor, mCmd = m.monitor.Update(msg)
		cmd = mCmd
	case viewLogSelect:
		if kmsg, ok := msg.(tea.KeyMsg); ok {
			if (kmsg.String() == "esc" || kmsg.String() == "q") && !m.logSelect.isManual {
				m.state = viewList
				*m, _ = m.updateList(m.lastSize)
				return nil
			}
		}
		var lsCmd tea.Cmd
		m.logSelect, lsCmd = m.logSelect.Update(msg)
		cmd = lsCmd
	case viewLogStream:
		if kmsg, ok := msg.(tea.KeyMsg); ok {
			if (kmsg.String() == "esc" || kmsg.String() == "q") && !m.logStreamer.isSearching {
				if err := m.logStreamer.Close(); err != nil {
					m.status = errorStyle.Render(fmt.Sprintf("Close log stream failed: %v", err))
				}
				m.state = viewLogSelect
				m.logSelect.list.SetSize(m.lastSize.Width, m.lastSize.Height)
				return nil
			}
		}
		var lstCmd tea.Cmd
		m.logStreamer, lstCmd = m.logStreamer.Update(msg)
		cmd = lstCmd
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
			s += "\n\n" + statusStyle.Render(i18n.T("tui_form_help"))
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
	case viewLogSelect:
		s = m.logSelect.View()
	case viewLogStream:
		s = m.logStreamer.View()
	}

	if m.status != "" {
		s += "\n\n" + statusStyle.Render(m.status)
	}

	return appStyle.Render(s)
}
