package tui

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func (m *Model) applyInventoryLoaded(msg InventoryLoadedMsg) {
	if msg.Err != nil {
		m.lastErr = i18n.Wrap(msg.Err, i18n.KeyTUIInventoryErr)
		m.statusMsg = i18n.NewMessage(i18n.KeyTUIStatusInventoryFailed)
		return
	}
	m.inventoryRev = msg.Revision
	m.hosts = slices.Clone(msg.Hosts)
	m.lastErr = nil
	m.clampHostSelection()
	m.statusMsg = i18n.NewMessage(
		i18n.KeyTUIStatusInventoryLoaded,
		i18n.Int("count", len(m.hosts)),
		i18n.BoundStr("rev", pickStr(m.inventoryRev, "-")),
	)
}

func (m *Model) applyProjectionSnapshot(snap engine.ProjectionSnapshot) {
	m.applyProjectionView(ProjectionViewFromSnapshot(snap))
}

// applyProjectionView 原子替换最新 Projection 快照视图并与直连流状态无损合并：
// 绝不将全量环形 snap.Logs() 重复追加至历史日志，也不覆盖独立 OperationStream 的操作与指标状态。
func (m *Model) applyProjectionView(view ProjectionView) {
	if !view.Valid || view.Version < m.projVersion {
		return
	}
	m.projVersion = view.Version
	m.projSnap = normalizeProjectionView(view, m.logLimit())
	m.activeStreams = view.ActiveStreams
	m.gateHalted = m.gateHalted || view.GateHalted
	m.hasUnknownOut = m.hasUnknownOut || view.HasUnknownOutcome
	m.totalEvents = m.projSnap.TotalEvents + m.directEvents
	m.droppedEvents = max(m.droppedEvents, m.projSnap.DroppedEvents+m.directDropped)
	m.rebuildMergedViews()
}

func normalizeProjectionView(view ProjectionView, maxLogs int) ProjectionView {
	out := ProjectionView{
		Valid:             true,
		Version:           view.Version,
		TotalEvents:       view.TotalEvents,
		DroppedEvents:     view.DroppedEvents,
		GateHalted:        view.GateHalted,
		HasUnknownOutcome: view.HasUnknownOutcome,
		ActiveStreams:     view.ActiveStreams,
		Operations:        slices.Clone(view.Operations),
		Metrics:           cloneMetricPoints(view.Metrics),
		Diagnostics:       slices.Clone(view.Diagnostics),
		PoolEvents:        slices.Clone(view.PoolEvents),
	}
	for _, entry := range view.Logs {
		out.Logs = appendNormalizedLogEntry(out.Logs, entry, maxLogs)
	}
	return out
}

func cloneMetricPoints(src []engine.MetricPoint) []engine.MetricPoint {
	out := slices.Clone(src)
	for i := range out {
		out[i].Labels = maps.Clone(out[i].Labels)
	}
	return out
}

func (m *Model) applyProjectedEvent(msg EventProjectedMsg) {
	m.directEvents++
	m.directDropped += msg.Dropped
	m.totalEvents = m.projSnap.TotalEvents + m.directEvents
	m.droppedEvents = max(m.droppedEvents, m.projSnap.DroppedEvents+m.directDropped)
	m.gateHalted = m.gateHalted || msg.GateHalted
	m.hasUnknownOut = m.hasUnknownOut || msg.UnknownOut
	if msg.Operation != nil {
		m.upsertDirectOp(*msg.Operation)
	}
	if msg.Metric != nil {
		m.upsertDirectMetric(*msg.Metric)
	}
	if msg.Log != nil {
		m.directLogs = appendNormalizedLogEntry(m.directLogs, *msg.Log, m.logLimit())
	}
	if msg.Diagnostic != nil {
		m.directDiags = appendBoundedSlice(m.directDiags, *msg.Diagnostic, defaultMaxSystemItems)
	}
	if msg.Pool != nil {
		m.directPool = appendBoundedSlice(m.directPool, *msg.Pool, defaultMaxSystemItems)
	}
	m.rebuildMergedViews()
}

func (m *Model) upsertDirectOp(in engine.OperationView) {
	if m.directOpsByID == nil {
		m.directOpsByID = make(map[string]engine.OperationView)
	}
	cur, exists := m.directOpsByID[in.OperationID]
	if !exists {
		if len(m.directOpOrder) >= defaultMaxOperations {
			delete(m.directOpsByID, m.directOpOrder[0])
			m.directOpOrder = m.directOpOrder[1:]
		}
		m.directOpOrder = append(m.directOpOrder, in.OperationID)
		cur = in
	} else {
		cur = mergeOperationView(cur, in)
	}
	m.directOpsByID[in.OperationID] = cur
}

func mergeOperationView(cur, in engine.OperationView) engine.OperationView {
	cur.Tool = pickStr(in.Tool, cur.Tool)
	cur.Action = pickStr(in.Action, cur.Action)
	cur.Summary = pickStr(in.Summary, cur.Summary)
	cur.NodeID = pickStr(in.NodeID, cur.NodeID)
	cur.LastCode = pickStr(in.LastCode, cur.LastCode)
	cur.LastMessage = pickStr(in.LastMessage, cur.LastMessage)
	cur.LastStepID = pickStr(in.LastStepID, cur.LastStepID)
	cur.LastStepStat = pickStr(in.LastStepStat, cur.LastStepStat)
	if in.Completed {
		cur.Completed, cur.Succeeded, cur.Duration = true, in.Succeeded, in.Duration
	}
	cur.Unknown = cur.Unknown || in.Unknown
	if !in.UpdatedAt.IsZero() {
		cur.UpdatedAt = in.UpdatedAt
	}
	return cur
}

func (m *Model) upsertDirectMetric(pt engine.MetricPoint) {
	if m.directMetricByID == nil {
		m.directMetricByID = make(map[string]engine.MetricPoint)
	}
	pt.Labels = maps.Clone(pt.Labels)
	if len(m.directMetricByID) >= defaultMaxMetrics {
		if _, ok := m.directMetricByID[pt.Key]; !ok {
			evictOldestMetricKey(m.directMetricByID)
		}
	}
	m.directMetricByID[pt.Key] = pt
}

func evictOldestMetricKey(m map[string]engine.MetricPoint) {
	var minKey string
	for k := range m {
		if minKey == "" || k < minKey {
			minKey = k
		}
	}
	if minKey != "" {
		delete(m, minKey)
	}
}

func (m *Model) rebuildMergedViews() {
	m.operations = mergeOperationSlices(m.projSnap.Operations, m.directOpOrder, m.directOpsByID)
	m.metrics = mergeMetricSlices(m.projSnap.Metrics, m.directMetricByID)
	m.logs = mergeBoundedSlices(m.projSnap.Logs, m.directLogs, m.logLimit())
	m.diagnostics = mergeBoundedSlices(m.projSnap.Diagnostics, m.directDiags, defaultMaxSystemItems)
	m.poolEvents = mergeBoundedSlices(m.projSnap.PoolEvents, m.directPool, defaultMaxSystemItems)
}

func mergeOperationSlices(projOps []engine.OperationView, directOrder []string, directMap map[string]engine.OperationView) []engine.OperationView {
	if len(directMap) == 0 {
		return slices.Clone(projOps)
	}
	if len(projOps) == 0 {
		out := make([]engine.OperationView, 0, len(directOrder))
		for _, id := range directOrder {
			if op, ok := directMap[id]; ok {
				out = append(out, op)
			}
		}
		return out
	}
	merged := make(map[string]engine.OperationView, len(projOps)+len(directMap))
	order := make([]string, 0, len(projOps)+len(directOrder))
	for _, op := range projOps {
		merged[op.OperationID] = op
		order = append(order, op.OperationID)
	}
	for _, id := range directOrder {
		op, ok := directMap[id]
		if !ok {
			continue
		}
		if existing, exists := merged[id]; exists {
			merged[id] = mergeOperationView(existing, op)
			continue
		}
		merged[id] = op
		order = append(order, id)
	}
	out := make([]engine.OperationView, 0, len(order))
	for _, id := range order {
		out = append(out, merged[id])
	}
	return out
}

func mergeMetricSlices(projMetrics []engine.MetricPoint, directMap map[string]engine.MetricPoint) []engine.MetricPoint {
	if len(directMap) == 0 {
		return cloneMetricPoints(projMetrics)
	}
	merged := make(map[string]engine.MetricPoint, len(projMetrics)+len(directMap))
	for _, pt := range projMetrics {
		pt.Labels = maps.Clone(pt.Labels)
		merged[pt.Key] = pt
	}
	for k, pt := range directMap {
		pt.Labels = maps.Clone(pt.Labels)
		merged[k] = pt
	}
	out := make([]engine.MetricPoint, 0, len(merged))
	for _, pt := range merged {
		out = append(out, pt)
	}
	slices.SortFunc(out, func(a, b engine.MetricPoint) int { return cmp.Compare(a.Key, b.Key) })
	return out
}

func mergeBoundedSlices[T any](projItems, directItems []T, maxLen int) []T {
	total := len(projItems) + len(directItems)
	if total == 0 {
		return nil
	}
	combined := make([]T, 0, total)
	combined = append(combined, projItems...)
	combined = append(combined, directItems...)
	if maxLen > 0 && len(combined) > maxLen {
		combined = combined[len(combined)-maxLen:]
	}
	return combined
}

func (m *Model) appendLogChunk(msg LogChunkMsg) {
	streamKind := msg.Stream
	if !streamKind.IsValid() {
		streamKind = events.OutputStreamStdout
	}
	entry := engine.LogEntry{
		NodeID:     msg.Target,
		Stream:     streamKind,
		Data:       msg.Text,
		Truncated:  msg.Truncated,
		OccurredAt: msg.OccurredAt,
	}
	m.directLogs = appendNormalizedLogEntry(m.directLogs, entry, m.logLimit())
	m.rebuildMergedViews()
}

// appendNormalizedLogEntry 将可能包含多行换行符的单条 LogEntry 拆分为单行记录，
// 保障视图行窗口分页切片与环形容量上限精确一致。
func appendNormalizedLogEntry(dst []engine.LogEntry, entry engine.LogEntry, maxLen int) []engine.LogEntry {
	norm := strings.ReplaceAll(entry.Data, "\r\n", "\n")
	lines := strings.Split(norm, "\n")
	if len(lines) > 1 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i, line := range lines {
		if line == "" && !entry.Truncated {
			continue
		}
		item := entry
		item.Data = line
		item.Truncated = entry.Truncated && i == len(lines)-1
		dst = appendBoundedSlice(dst, item, maxLen)
	}
	return dst
}

func (m Model) logLimit() int {
	if m.maxLogs <= 0 {
		return defaultMaxLogLines
	}
	return m.maxLogs
}

func (m *Model) applyStreamState(msg StreamStateMsg) {
	if !msg.Kind.IsValid() {
		return
	}
	switch msg.Kind {
	case StreamKindMetrics:
		if !applyStreamSlotState(&m.metricsSeq, &m.metricsActive, &m.metricsTarget, msg) {
			return
		}
	case StreamKindLogs:
		if !applyStreamSlotState(&m.logsSeq, &m.logsActive, &m.logsTarget, msg) {
			return
		}
	default:
		return
	}
	kindParam := i18n.Msg("kind", i18n.NewMessage(msg.Kind.LabelKey()))
	if msg.Err != nil {
		m.lastErr = i18n.Wrap(msg.Err, i18n.KeyTUIStreamErr, kindParam, i18n.BoundStr("target", msg.Target))
		m.statusMsg = i18n.NewMessage(i18n.KeyTUIStatusStreamErr, kindParam)
		return
	}
	if msg.Active {
		m.lastErr = nil
		m.statusMsg = i18n.NewMessage(i18n.KeyTUIStatusStreamActive, kindParam, i18n.BoundStr("target", msg.Target))
		return
	}
	m.statusMsg = i18n.NewMessage(i18n.KeyTUIStatusStreamIdle, kindParam)
}

func applyStreamSlotState(curSeq *uint64, active *bool, target *string, msg StreamStateMsg) bool {
	if msg.Seq > 0 && msg.Seq < *curSeq {
		return false
	}
	if msg.Seq > *curSeq {
		*curSeq = msg.Seq
	}
	*active = msg.Active
	if msg.Target != "" {
		*target = msg.Target
	}
	return true
}

func (m *Model) applyTakeoverResult(msg TakeoverResultMsg) {
	m.pendingTakeover = algebraic.None[TakeoverRequest]()
	if msg.Err != nil {
		m.lastErr = i18n.Wrap(msg.Err, i18n.KeyTUITakeoverErr, i18n.BoundStr("target", msg.Target))
		m.statusMsg = i18n.NewMessage(i18n.KeyTUIStatusTakeoverErr)
		return
	}
	m.lastErr = nil
	m.statusMsg = i18n.NewMessage(i18n.KeyTUIStatusTakeoverDone, i18n.BoundStr("target", msg.Target))
}

func (m Model) filteredHosts() []HostItem {
	if strings.TrimSpace(m.filterQuery) == "" {
		return m.hosts
	}
	out := make([]HostItem, 0, len(m.hosts))
	for _, h := range m.hosts {
		if h.MatchesFilter(m.filterQuery) {
			out = append(out, h)
		}
	}
	return out
}

func (m Model) filteredLogs() []engine.LogEntry {
	q := strings.ToLower(strings.TrimSpace(m.filterQuery))
	if q == "" {
		return m.logs
	}
	out := make([]engine.LogEntry, 0, len(m.logs))
	for _, l := range m.logs {
		if strings.Contains(strings.ToLower(l.Data), q) || strings.Contains(strings.ToLower(l.NodeID), q) {
			out = append(out, l)
		}
	}
	return out
}

func appendBoundedSlice[T any](items []T, v T, maxLen int) []T {
	if maxLen <= 0 {
		return items
	}
	if len(items) >= maxLen {
		copy(items, items[len(items)-maxLen+1:])
		items = items[:maxLen-1]
	}
	return append(items, v)
}
