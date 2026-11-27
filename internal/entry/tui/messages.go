package tui

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
)

// ViewKind 标识工作台当前激活的子视图；零值 ViewInvalid 严格失败关闭。
//
//xops:opaque
//xops:failclosed
type ViewKind uint8

const (
	// ViewInvalid 为未初始化零值（失败关闭）。
	ViewInvalid ViewKind = iota
	// ViewHosts 展示资产主机/节点清单、筛选与会话/监控入口。
	ViewHosts
	// ViewMetrics 展示实时主机指标帧与投影指标点。
	ViewMetrics
	// ViewLogs 展示实时远端日志流与操作输出分块。
	ViewLogs
	// ViewOperations 展示活跃/已完成操作、连接池状态与系统诊断。
	ViewOperations
	// ViewHelp 展示快捷键说明与运行期状态摘要。
	ViewHelp
)

// IsValid 报告 ViewKind 是否为有效工作台视图。
func (v ViewKind) IsValid() bool { return v >= ViewHosts && v <= ViewHelp }

// IsZero 报告 ViewKind 是否为无效零值。
func (v ViewKind) IsZero() bool { return v == ViewInvalid }

// String 返回视图的可读名称。
func (v ViewKind) String() string {
	switch v {
	case ViewHosts:
		return "Hosts"
	case ViewMetrics:
		return "Metrics"
	case ViewLogs:
		return "Logs"
	case ViewOperations:
		return "Operations"
	case ViewHelp:
		return "Help"
	default:
		return "Invalid"
	}
}

// Next 返回顺时针切换后的下一个视图。
func (v ViewKind) Next() ViewKind {
	if !v.IsValid() || v == ViewHelp {
		return ViewHosts
	}
	return v + 1
}

// Prev 返回逆时针切换后的上一个视图。
func (v ViewKind) Prev() ViewKind {
	if !v.IsValid() || v == ViewHosts {
		return ViewHelp
	}
	return v - 1
}

// HostItem 是从 core/engine InventorySnapshot 投影出的不可变主机/节点行视图。
type HostItem struct {
	NodeID      string
	TargetSpec  string
	HostID      string
	Endpoint    string
	User        string
	Origin      string
	Aliases     []string
	Tags        []string
	Description string
}

// EffectiveTarget 返回面向 core/engine 目标解析的真实目标规格：
// 受管节点返回 NodeID，独立 Host 返回其可直连 Endpoint（缺失时回退 NodeID）。
func (h HostItem) EffectiveTarget() string {
	return pickStr(h.TargetSpec, h.NodeID)
}

// MatchesFilter 判定主机条目是否匹配不区分大小写的筛选关键词。
func (h HostItem) MatchesFilter(query string) bool {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return true
	}
	if strings.Contains(strings.ToLower(h.NodeID), q) ||
		strings.Contains(strings.ToLower(h.HostID), q) ||
		strings.Contains(strings.ToLower(h.Endpoint), q) ||
		strings.Contains(strings.ToLower(h.User), q) ||
		strings.Contains(strings.ToLower(h.Description), q) {
		return true
	}
	for _, a := range h.Aliases {
		if strings.Contains(strings.ToLower(a), q) {
			return true
		}
	}
	for _, t := range h.Tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	return false
}

// BuildHostItems 将核心资产图快照投影为确定性排序的主机/节点视图列表。
func BuildHostItems(snap engine.InventorySnapshot) []HostItem {
	if !snap.IsValid() {
		return nil
	}
	g := snap.Graph()
	return BuildHostItemsFromEntities(g.Hosts(), g.Identities(), g.Nodes())
}

// BuildHostItemsFromEntities 从资产实体切片构造确定性排序的主机/节点视图列表。
func BuildHostItemsFromEntities(hosts []inventory.Host, idents []inventory.Identity, nodes []inventory.Node) []HostItem {
	hostMap := make(map[string]inventory.Host, len(hosts))
	for _, h := range hosts {
		hostMap[h.ID().String()] = h
	}
	identMap := make(map[string]inventory.Identity, len(idents))
	for _, id := range idents {
		identMap[id.ID().String()] = id
	}
	items := make([]HostItem, 0, len(nodes)+len(hosts))
	referencedHosts := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		referencedHosts[n.HostRef().String()] = true
		items = append(items, hostItemFromNode(n, hostMap, identMap))
	}
	// 补充未被任何 Node 引用的独立 Host，确保资产面板完整可见。
	for _, h := range hosts {
		if referencedHosts[h.ID().String()] {
			continue
		}
		items = append(items, hostItemFromStandaloneHost(h))
	}
	slices.SortFunc(items, func(a, b HostItem) int {
		return cmp.Or(
			cmp.Compare(a.NodeID, b.NodeID),
			cmp.Compare(a.HostID, b.HostID),
			cmp.Compare(a.Endpoint, b.Endpoint),
		)
	})
	return items
}

func hostItemFromNode(n inventory.Node, hosts map[string]inventory.Host, idents map[string]inventory.Identity) HostItem {
	nodeID := n.ID().String()
	item := HostItem{
		NodeID:      nodeID,
		TargetSpec:  nodeID,
		HostID:      n.HostRef().String(),
		Origin:      n.OriginKind().String(),
		Description: n.Description(),
	}
	if h, ok := hosts[item.HostID]; ok {
		item.Endpoint = h.Endpoint().String()
	}
	if id, ok := idents[n.IdentityRef().String()]; ok {
		item.User = id.User().String()
	}
	for _, a := range n.Aliases() {
		item.Aliases = append(item.Aliases, a.String())
	}
	for _, t := range n.Tags() {
		item.Tags = append(item.Tags, t.String())
	}
	return item
}

func hostItemFromStandaloneHost(h inventory.Host) HostItem {
	ep := h.Endpoint().String()
	id := h.ID().String()
	item := HostItem{
		NodeID:      id,
		TargetSpec:  pickStr(ep, id),
		HostID:      id,
		Endpoint:    ep,
		Origin:      "host",
		Description: h.Description(),
	}
	if a, ok := h.Alias().Get(); ok {
		item.Aliases = []string{a.String()}
	}
	for _, t := range h.Tags() {
		item.Tags = append(item.Tags, t.String())
	}
	return item
}

// 以下为 TUI 工作台与核心流/引擎之间流转的强类型 Bubble Tea v2 消息（零明文、零裸 time.Duration）。
type (
	// InventoryLoadedMsg 携带异步加载的资产图快照与主机列表（或错误信息）。
	InventoryLoadedMsg struct {
		Revision string
		Hosts    []HostItem
		Err      error
	}

	// ProjectionView 是从 engine.ProjectionSnapshot 解包得到的纯值投影视图，
	// 使状态折叠、去重同步与无头多轮测试共用同一不可变数据结构。
	ProjectionView struct {
		Valid             bool
		Version           uint64
		TotalEvents       uint64
		DroppedEvents     uint64
		GateHalted        bool
		HasUnknownOutcome bool
		ActiveStreams     int
		Operations        []engine.OperationView
		Metrics           []engine.MetricPoint
		Logs              []engine.LogEntry
		Diagnostics       []engine.DiagnosticRecord
		PoolEvents        []engine.PoolRecord
	}

	// ProjectionUpdatedMsg 携带来自 engine.Projection.WaitUpdate 的最新不可变聚合快照。
	ProjectionUpdatedMsg struct {
		Snapshot engine.ProjectionSnapshot
	}

	// ProjectionViewMsg 携带解包后的 ProjectionView，供多轮快照折叠与无头集成测试直接驱动。
	ProjectionViewMsg struct {
		View ProjectionView
	}

	// MetricsFrameMsg 携带来自 Engine.StreamMetrics OnFrame 回调的实时主机指标帧。
	MetricsFrameMsg struct {
		Target string
		Frame  engine.HostMetricsFrame
	}

	// LogChunkMsg 携带来自 Engine.StreamLogs 输出流或 OutputChunkEvent 的日志文本行。
	LogChunkMsg struct {
		Target     string
		Stream     events.OutputStreamKind
		Text       string
		Truncated  bool
		OccurredAt time.Time
	}

	// StreamStateMsg 报告活跃远端流（metrics/logs）的启动、停止或出错状态；Seq 用于过滤切换目标后的陈旧状态消息。
	StreamStateMsg struct {
		Kind   string // "metrics" 或 "logs"
		Target string
		Active bool
		Seq    uint64
		Err    error
	}

	// SystemBusDroppedMsg 报告 SystemBus 订阅者增量丢弃事件数（DropAndCount 背压可见性）。
	SystemBusDroppedMsg struct {
		Delta uint64
		Total uint64
	}

	// HaltedStateMsg 通知工作台底层安全门控已进入不可逆 Halted 熔断态。
	HaltedStateMsg struct {
		Reason string
	}

	// TakeoverResultMsg 携带交互会话接管结束后的状态摘要，用于恢复工作台后反馈给操作员。
	TakeoverResultMsg struct {
		Target string
		Err    error
	}

	// EventProjectedMsg 封装由核心封闭 events.Event 直接投影得到的强类型 TUI 消息。
	EventProjectedMsg struct {
		Kind        events.EventKind
		TraceID     string
		OperationID string
		NodeID      string
		OccurredAt  time.Time
		Operation   *engine.OperationView
		Metric      *engine.MetricPoint
		Log         *engine.LogEntry
		Diagnostic  *engine.DiagnosticRecord
		Pool        *engine.PoolRecord
		Dropped     uint64
		GateHalted  bool
		UnknownOut  bool
	}
)

// ProjectionViewFromSnapshot 将不可变 engine.ProjectionSnapshot 解包为纯值 ProjectionView；零值或无效快照返回 Valid=false。
func ProjectionViewFromSnapshot(snap engine.ProjectionSnapshot) ProjectionView {
	if !snap.IsValid() {
		return ProjectionView{}
	}
	return ProjectionView{
		Valid:             true,
		Version:           snap.Version(),
		TotalEvents:       snap.TotalEvents(),
		DroppedEvents:     snap.DroppedEvents(),
		GateHalted:        snap.GateHalted(),
		HasUnknownOutcome: snap.HasUnknownOutcome(),
		ActiveStreams:     snap.ActiveStreams(),
		Operations:        snap.Operations(),
		Metrics:           snap.Metrics(),
		Logs:              snap.Logs(),
		Diagnostics:       snap.Diagnostics(),
		PoolEvents:        snap.PoolEvents(),
	}
}

// ProjectEvent 穷尽匹配全部 12 类封闭 core/events.Event 变体并投影为强类型 EventProjectedMsg；
// 对 nil、无效事件或未知变体严格失败关闭返回 ErrInvalidEvent（满足 xopsvet/sumexhaust）。
func ProjectEvent(ev events.Event) (tea.Msg, error) {
	if ev == nil || !ev.IsValid() {
		return nil, fmt.Errorf("%w: 事件为空或未通过有效性校验", ErrInvalidEvent)
	}
	meta := ev.Meta()
	msg := EventProjectedMsg{
		Kind:        ev.Kind(),
		TraceID:     meta.TraceID().String(),
		OperationID: optString(meta.OperationID()),
		NodeID:      optString(meta.NodeID()),
		OccurredAt:  meta.OccurredAt(),
	}
	if err := fillProjectedEvent(&msg, ev); err != nil {
		return nil, err
	}
	return msg, nil
}

func fillProjectedEvent(msg *EventProjectedMsg, ev events.Event) error {
	switch v := ev.(type) {
	case *events.OperationStartedEvent:
		msg.Operation = &engine.OperationView{
			OperationID: pickStr(msg.OperationID, msg.TraceID), TraceID: msg.TraceID, NodeID: msg.NodeID,
			Tool: v.Tool(), Action: v.Action(), Summary: v.Summary(), UpdatedAt: msg.OccurredAt,
		}
	case *events.OperationCompletedEvent:
		unk := isOutcomeUnknown(v.Outcome())
		msg.UnknownOut = unk
		msg.Operation = &engine.OperationView{
			OperationID: pickStr(msg.OperationID, msg.TraceID), TraceID: msg.TraceID, NodeID: msg.NodeID,
			Completed: true, Succeeded: v.Succeeded() && !unk, Unknown: unk,
			LastCode: v.Code(), LastMessage: v.Message(), Duration: v.Duration(), UpdatedAt: msg.OccurredAt,
		}
	case *events.OutputChunkEvent:
		msg.Log = &engine.LogEntry{
			TraceID: msg.TraceID, OperationID: msg.OperationID, NodeID: msg.NodeID,
			Stream: v.Stream(), ChunkIndex: v.ChunkIndex(), Data: string(v.Data()),
			Truncated: v.Truncated(), OccurredAt: msg.OccurredAt,
		}
	case *events.StepEvent:
		unk := isOutcomeUnknown(v.Outcome())
		msg.UnknownOut = unk
		msg.Operation = &engine.OperationView{
			OperationID: pickStr(msg.OperationID, msg.TraceID), TraceID: msg.TraceID, NodeID: msg.NodeID,
			Unknown: unk, LastStepID: v.StepID().String(), LastStepStat: v.Status().String(),
			LastMessage: v.Message(), Duration: v.Duration(), UpdatedAt: msg.OccurredAt,
		}
	case *events.FSMTransitionEvent:
		msg.Operation = &engine.OperationView{
			OperationID: pickStr(msg.OperationID, msg.TraceID), TraceID: msg.TraceID, NodeID: msg.NodeID,
			LastCode: v.EventName(), LastMessage: fmt.Sprintf("%s:%s->%s", v.Machine(), v.FromState(), v.ToState()),
			UpdatedAt: msg.OccurredAt,
		}
	case *events.ApprovalChallengeEvent:
		msg.Operation = &engine.OperationView{
			OperationID: pickStr(msg.OperationID, msg.TraceID), TraceID: msg.TraceID, NodeID: msg.NodeID,
			LastCode: "approval_challenge", LastMessage: v.Reason(), UpdatedAt: msg.OccurredAt,
		}
	case *events.TransferProgressEvent:
		msg.Operation = &engine.OperationView{
			OperationID: pickStr(msg.OperationID, msg.TraceID), TraceID: msg.TraceID, NodeID: msg.NodeID,
			LastCode:    "transfer_progress",
			LastMessage: fmt.Sprintf("%s %d/%d", v.Stage(), v.BytesTransferred(), v.TotalBytes()),
			UpdatedAt:   msg.OccurredAt,
		}
	case *events.MetricSampleEvent:
		msg.Metric = &engine.MetricPoint{
			Key: v.CoalesceKey(), NodeID: msg.NodeID, Name: v.MetricName(), Unit: v.Unit(),
			Value: v.Value(), Interval: v.Interval(), Labels: v.Labels(), OccurredAt: msg.OccurredAt,
		}
	case *events.AuditRecordEvent:
		msg.GateHalted = v.Stage() == events.AuditStageHalted
		msg.UnknownOut = isOutcomeUnknown(v.Outcome())
	case *events.PoolStateEvent:
		msg.GateHalted = v.Action() == events.PoolActionGateHalted
		msg.Pool = &engine.PoolRecord{
			Action: v.Action(), Endpoint: optString(v.Endpoint()), ActiveLeases: v.ActiveLeases(),
			Latency: v.Latency(), Detail: v.Detail(), OccurredAt: msg.OccurredAt,
		}
	case *events.DiagnosticEvent:
		msg.GateHalted = v.Code() == "gate_halted"
		msg.Diagnostic = &engine.DiagnosticRecord{
			Scope: v.Scope(), Severity: v.Severity(), Code: v.Code(),
			Message: v.Message(), Attrs: v.Attrs(), OccurredAt: msg.OccurredAt,
		}
	case *events.BusDroppedEvent:
		msg.Dropped = v.DroppedDelta()
	default:
		return fmt.Errorf("%w: 未支持的事件类型 %T", ErrInvalidEvent, ev)
	}
	return nil
}

func isOutcomeUnknown(opt algebraic.Option[execution.ExecutionOutcome]) bool {
	out, ok := opt.Get()
	return ok && out != nil && out.Kind() == execution.OutcomeKindUnknown
}

func optString[T interface{ String() string }](o algebraic.Option[T]) string {
	if v, ok := o.Get(); ok {
		return v.String()
	}
	return ""
}

func pickStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// actionKind 表示 Model 向受 Nursery 监督的异步控制器派发的副作用指令类型。
type actionKind uint8

const (
	actionNone actionKind = iota
	actionRefreshInventory
	actionStartMetrics
	actionStartLogs
	actionStopStreams
)

type actionRequest struct {
	kind   actionKind
	target string
	sortBy engine.ProcessSortBy
}

func cloneStrings(src []string) []string { return slices.Clone(src) }
