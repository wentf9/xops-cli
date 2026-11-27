package tui

import (
	"fmt"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/engine"
)

// Model 实现 Bubble Tea v2 的纯函数 Elm 状态机（tea.Model）：
// 所有副作用均通过有界 actionCh 交由 core/conc.Nursery 监督执行，绝不在 Update 中启动不可取消的慢 Cmd。
type Model struct {
	width, height    int
	altScreen        bool
	activeView       ViewKind
	filterActive     bool
	filterQuery      string
	statusMsg        string
	lastErr          string
	quitting         bool
	canTakeover      bool
	pendingTakeover  algebraic.Option[TakeoverRequest]
	initialTarget    string
	processSort      engine.ProcessSortBy
	maxLogs          int
	theme            workbenchTheme
	actions          chan<- actionRequest
	inventoryRev     string
	hosts            []HostItem
	selectedHost     int
	logScroll        int
	metricsActive    bool
	metricsTarget    string
	metricsSeq       uint64
	logsActive       bool
	logsTarget       string
	logsSeq          uint64
	latestFrame      algebraic.Option[engine.HostMetricsFrame]
	gateHalted       bool
	haltReason       string
	hasUnknownOut    bool
	projVersion      uint64
	projSnap         ProjectionView
	directEvents     uint64
	directDropped    uint64
	totalEvents      uint64
	droppedEvents    uint64
	activeStreams    int
	operations       []engine.OperationView
	metrics          []engine.MetricPoint
	logs             []engine.LogEntry
	diagnostics      []engine.DiagnosticRecord
	poolEvents       []engine.PoolRecord
	directOpsByID    map[string]engine.OperationView
	directOpOrder    []string
	directMetricByID map[string]engine.MetricPoint
	directLogs       []engine.LogEntry
	directDiags      []engine.DiagnosticRecord
	directPool       []engine.PoolRecord
}

// ModelOptions 控制纯 Model 构造的初始视图、窗口尺寸与可选异步动作派发通道。
type ModelOptions struct {
	InitialView      ViewKind
	InitialWidth     int
	InitialHeight    int
	DisableAltScreen bool
	InitialTarget    string
	MaxLogLines      int
	CanTakeover      bool
}

// NewModel 构造纯 Elm 架构工作台模型，供 Run 与无头单元测试直接复用。
func NewModel(opts ModelOptions) Model {
	return newModelWithActions(opts, nil)
}

func newModelWithActions(opts ModelOptions, actions chan<- actionRequest) Model {
	view := opts.InitialView
	if !view.IsValid() {
		view = ViewHosts
	}
	w, h := opts.InitialWidth, opts.InitialHeight
	if w <= 0 {
		w = defaultWindowWidth
	}
	if h <= 0 {
		h = defaultWindowHeight
	}
	maxLogs := opts.MaxLogLines
	if maxLogs <= 0 {
		maxLogs = defaultMaxLogLines
	}
	return Model{
		width:            w,
		height:           h,
		altScreen:        !opts.DisableAltScreen,
		activeView:       view,
		canTakeover:      opts.CanTakeover,
		initialTarget:    strings.TrimSpace(opts.InitialTarget),
		processSort:      engine.ProcessSortCPU,
		maxLogs:          maxLogs,
		theme:            newWorkbenchTheme(),
		actions:          actions,
		statusMsg:        "Ready",
		directOpsByID:    make(map[string]engine.OperationView),
		directMetricByID: make(map[string]engine.MetricPoint),
	}
}

// Init 实现 tea.Model；所有初始化加载由受 Nursery 监督的控制器驱动，避免 Bubble Tea 产生未追踪 Cmd 协程。
func (m Model) Init() tea.Cmd { return nil }

// ActiveView / FilterQuery / GateHalted / HasUnknownOutcome / PendingTakeover 等提供只读状态访问器。
func (m Model) ActiveView() ViewKind                                { return m.activeView }
func (m Model) FilterQuery() string                                 { return m.filterQuery }
func (m Model) GateHalted() bool                                    { return m.gateHalted }
func (m Model) HasUnknownOutcome() bool                             { return m.hasUnknownOut }
func (m Model) MetricsActive() bool                                 { return m.metricsActive }
func (m Model) LogsActive() bool                                    { return m.logsActive }
func (m Model) PendingTakeover() (TakeoverRequest, bool)            { return m.pendingTakeover.Get() }
func (m Model) LatestMetricsFrame() (engine.HostMetricsFrame, bool) { return m.latestFrame.Get() }
func (m Model) DroppedEvents() uint64                               { return m.droppedEvents }
func (m Model) Operations() []engine.OperationView                  { return slices.Clone(m.operations) }
func (m Model) Metrics() []engine.MetricPoint                       { return slices.Clone(m.metrics) }
func (m Model) Logs() []engine.LogEntry                             { return slices.Clone(m.logs) }
func (m Model) Diagnostics() []engine.DiagnosticRecord              { return slices.Clone(m.diagnostics) }
func (m Model) PoolEvents() []engine.PoolRecord                     { return slices.Clone(m.poolEvents) }

// SelectedTarget 返回当前光标选中主机的可解析目标规格（节点返回 NodeID，独立主机返回 Endpoint）；列表为空时回退至 InitialTarget。
func (m Model) SelectedTarget() string {
	if item, ok := m.selectedHostItem(); ok {
		return item.EffectiveTarget()
	}
	return m.initialTarget
}

func (m Model) selectedHostItem() (HostItem, bool) {
	filtered := m.filteredHosts()
	if len(filtered) > 0 && m.selectedHost >= 0 && m.selectedHost < len(filtered) {
		return filtered[m.selectedHost], true
	}
	return HostItem{}, false
}

// resetActiveStreams 在一轮 TUI 运行退出（如切入交互接管）时清零瞬时流活跃标志与序号，防止重入后显示过期 [streaming]。
func (m *Model) resetActiveStreams() {
	m.metricsActive = false
	m.logsActive = false
	m.metricsSeq = 0
	m.logsSeq = 0
}

// Update 实现 tea.Model，按纯消息驱动方式更新工作台状态并按需派发非阻塞后台动作。
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		if v.Width > 0 && v.Height > 0 {
			m.width, m.height = v.Width, v.Height
		}
		return m, nil
	case tea.KeyPressMsg:
		return m.handleKeyPress(v)
	case InventoryLoadedMsg:
		m.applyInventoryLoaded(v)
	case ProjectionUpdatedMsg:
		m.applyProjectionSnapshot(v.Snapshot)
	case ProjectionViewMsg:
		m.applyProjectionView(v.View)
	case EventProjectedMsg:
		m.applyProjectedEvent(v)
	case MetricsFrameMsg:
		m.metricsTarget, m.latestFrame = v.Target, algebraic.Some(v.Frame)
		m.statusMsg = fmt.Sprintf("Metrics updated (%s: CPU %.1f%% Mem %.1f%%)", v.Target, v.Frame.CPUPercent, v.Frame.MemPercent)
	case LogChunkMsg:
		m.appendLogChunk(v)
	case StreamStateMsg:
		m.applyStreamState(v)
	case SystemBusDroppedMsg:
		m.directDropped += v.Delta
		m.droppedEvents = max(m.projSnap.DroppedEvents+m.directDropped, v.Total)
	case HaltedStateMsg:
		m.gateHalted, m.haltReason = true, v.Reason
		m.statusMsg = "CRITICAL: Engine security gate HALTED"
	case TakeoverResultMsg:
		m.applyTakeoverResult(v)
	}
	return m, nil
}

func (m Model) handleKeyPress(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "ctrl+c" {
		m.quitting = true
		return m, tea.Quit
	}
	if m.filterActive {
		return m.handleFilterKey(msg)
	}
	switch msg.String() {
	case "q":
		m.quitting = true
		return m, tea.Quit
	case "tab":
		m.activeView = m.activeView.Next()
	case "shift+tab":
		m.activeView = m.activeView.Prev()
	case "1":
		m.activeView = ViewHosts
	case "2":
		m.activeView = ViewMetrics
	case "3":
		m.activeView = ViewLogs
	case "4":
		m.activeView = ViewOperations
	case "?":
		m.activeView = ViewHelp
	case "/":
		m.filterActive = true
		m.statusMsg = "Filter mode: type to filter, Enter to apply, Esc to clear"
	default:
		return m.handleActionOrNavKey(msg.String())
	}
	return m, nil
}

func (m Model) handleFilterKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.filterActive = false
		m.filterQuery = ""
		m.selectedHost = 0
		m.statusMsg = "Filter cleared"
	case "enter":
		m.filterActive = false
		m.clampHostSelection()
		m.statusMsg = fmt.Sprintf("Filter applied: %q", m.filterQuery)
	case "backspace":
		runes := []rune(m.filterQuery)
		if len(runes) > 0 {
			m.filterQuery = string(runes[:len(runes)-1])
			m.clampHostSelection()
		}
	default:
		if len(msg.Text) > 0 {
			m.filterQuery += msg.Text
			m.clampHostSelection()
		}
	}
	return m, nil
}

func (m Model) handleActionOrNavKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		m.moveCursor(-1)
	case "down", "j":
		m.moveCursor(1)
	case "g", "home":
		m.jumpTop()
	case "G", "end":
		m.jumpBottom()
	case "r":
		m.dispatchAction(actionRequest{kind: actionRefreshInventory})
		m.statusMsg = "Refreshing inventory..."
	case "m":
		return m.triggerMetricsStream()
	case "l":
		return m.triggerLogStream()
	case "x":
		m.dispatchAction(actionRequest{kind: actionStopStreams})
		m.statusMsg = "Stopping active streams..."
	case "s":
		m.toggleProcessSort()
	case "enter":
		return m.triggerTakeover()
	}
	return m, nil
}

func (m Model) triggerMetricsStream() (tea.Model, tea.Cmd) {
	target := m.SelectedTarget()
	if target == "" {
		m.lastErr = "no host selected for metrics stream"
		return m, nil
	}
	m.activeView = ViewMetrics
	m.metricsTarget = target
	m.dispatchAction(actionRequest{kind: actionStartMetrics, target: target, sortBy: m.processSort})
	m.statusMsg = fmt.Sprintf("Starting metrics stream for %s...", target)
	return m, nil
}

func (m Model) triggerLogStream() (tea.Model, tea.Cmd) {
	target := m.SelectedTarget()
	if target == "" {
		m.lastErr = "no host selected for log stream"
		return m, nil
	}
	m.activeView = ViewLogs
	m.logsTarget = target
	m.dispatchAction(actionRequest{kind: actionStartLogs, target: target})
	m.statusMsg = fmt.Sprintf("Starting log stream for %s...", target)
	return m, nil
}

func (m *Model) toggleProcessSort() {
	if m.processSort == engine.ProcessSortCPU {
		m.processSort = engine.ProcessSortMem
	} else {
		m.processSort = engine.ProcessSortCPU
	}
	m.statusMsg = "Process sort: " + m.processSort.String()
	if m.metricsActive && m.metricsTarget != "" {
		m.dispatchAction(actionRequest{kind: actionStartMetrics, target: m.metricsTarget, sortBy: m.processSort})
	}
}

func (m Model) triggerTakeover() (tea.Model, tea.Cmd) {
	if m.activeView != ViewHosts || !m.canTakeover {
		return m, nil
	}
	nodeID, target := "", m.initialTarget
	if item, ok := m.selectedHostItem(); ok {
		nodeID, target = item.NodeID, item.EffectiveTarget()
	} else {
		nodeID = target
	}
	if target == "" {
		m.lastErr = "no host selected for interactive session"
		return m, nil
	}
	m.pendingTakeover = algebraic.Some(TakeoverRequest{NodeID: nodeID, TargetSpec: target})
	m.quitting = true
	return m, tea.Quit
}

func (m *Model) dispatchAction(req actionRequest) {
	if m.actions == nil {
		return
	}
	select {
	case m.actions <- req:
	default:
		m.lastErr = "action queue busy; try again"
	}
}

func (m *Model) moveCursor(delta int) {
	if m.activeView == ViewHosts {
		n := len(m.filteredHosts())
		if n == 0 {
			m.selectedHost = 0
			return
		}
		m.selectedHost = min(max(m.selectedHost+delta, 0), n-1)
		return
	}
	if m.activeView == ViewLogs {
		m.logScroll = max(m.logScroll+delta, 0)
	}
}

func (m *Model) jumpTop() {
	switch m.activeView {
	case ViewHosts:
		m.selectedHost = 0
	case ViewLogs:
		m.logScroll = 0
	}
}

func (m *Model) jumpBottom() {
	switch m.activeView {
	case ViewHosts:
		if n := len(m.filteredHosts()); n > 0 {
			m.selectedHost = n - 1
		}
	case ViewLogs:
		m.logScroll = max(len(m.filteredLogs())-1, 0)
	}
}

func (m *Model) clampHostSelection() {
	n := len(m.filteredHosts())
	if n == 0 {
		m.selectedHost = 0
		return
	}
	m.selectedHost = min(max(m.selectedHost, 0), n-1)
}
