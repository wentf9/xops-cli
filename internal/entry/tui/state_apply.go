package tui

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
)

func (m *Model) applyInventoryLoaded(msg InventoryLoadedMsg) {
	if msg.Err != nil {
		m.lastErr = "inventory: " + msg.Err.Error()
		m.statusMsg = "Inventory refresh failed"
		return
	}
	m.inventoryRev = msg.Revision
	m.hosts = slices.Clone(msg.Hosts)
	m.lastErr = ""
	m.clampHostSelection()
	m.statusMsg = fmt.Sprintf("Loaded %d target(s) (rev %s)", len(m.hosts), pickStr(m.inventoryRev, "-"))
}

func (m *Model) applyProjectionSnapshot(snap engine.ProjectionSnapshot) {
	if !snap.IsValid() || snap.Version() < m.projVersion {
		return
	}
	m.projVersion = snap.Version()
	m.totalEvents = max(m.totalEvents, snap.TotalEvents())
	m.droppedEvents = max(m.droppedEvents, snap.DroppedEvents())
	m.activeStreams = snap.ActiveStreams()
	m.gateHalted = m.gateHalted || snap.GateHalted()
	m.hasUnknownOut = m.hasUnknownOut || snap.HasUnknownOutcome()
	m.operations = snap.Operations()
	m.metrics = snap.Metrics()
	m.diagnostics = snap.Diagnostics()
	m.poolEvents = snap.PoolEvents()
	for _, entry := range snap.Logs() {
		m.appendUniqueLog(entry)
	}
}

func (m *Model) applyProjectedEvent(msg EventProjectedMsg) {
	m.totalEvents++
	m.droppedEvents += msg.Dropped
	m.gateHalted = m.gateHalted || msg.GateHalted
	m.hasUnknownOut = m.hasUnknownOut || msg.UnknownOut
	if msg.Operation != nil {
		m.upsertDirectOp(*msg.Operation)
	}
	if msg.Metric != nil {
		m.upsertDirectMetric(*msg.Metric)
	}
	if msg.Log != nil {
		m.appendBoundedLog(*msg.Log)
	}
	if msg.Diagnostic != nil {
		m.diagnostics = appendBoundedSlice(m.diagnostics, *msg.Diagnostic, defaultMaxSystemItems)
	}
	if msg.Pool != nil {
		m.poolEvents = appendBoundedSlice(m.poolEvents, *msg.Pool, defaultMaxSystemItems)
	}
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
	m.operations = make([]engine.OperationView, 0, len(m.directOpOrder))
	for _, id := range m.directOpOrder {
		if op, ok := m.directOpsByID[id]; ok {
			m.operations = append(m.operations, op)
		}
	}
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
		if _, ok := m.directMetricByID[pt.Key]; !ok && len(m.metrics) > 0 {
			delete(m.directMetricByID, m.metrics[0].Key)
		}
	}
	m.directMetricByID[pt.Key] = pt
	m.metrics = make([]engine.MetricPoint, 0, len(m.directMetricByID))
	for _, v := range m.directMetricByID {
		m.metrics = append(m.metrics, v)
	}
	slices.SortFunc(m.metrics, func(a, b engine.MetricPoint) int { return cmp.Compare(a.Key, b.Key) })
}

func (m *Model) appendLogChunk(msg LogChunkMsg) {
	streamKind := msg.Stream
	if !streamKind.IsValid() {
		streamKind = events.OutputStreamStdout
	}
	for line := range strings.SplitSeq(strings.ReplaceAll(msg.Text, "\r\n", "\n"), "\n") {
		if line == "" && !msg.Truncated {
			continue
		}
		m.appendBoundedLog(engine.LogEntry{
			NodeID: msg.Target, Stream: streamKind, Data: line,
			Truncated: msg.Truncated, OccurredAt: msg.OccurredAt,
		})
	}
}

func (m *Model) appendUniqueLog(entry engine.LogEntry) {
	if len(m.logs) > 0 {
		last := m.logs[len(m.logs)-1]
		if last.TraceID == entry.TraceID && last.ChunkIndex == entry.ChunkIndex && last.Data == entry.Data && last.OccurredAt.Equal(entry.OccurredAt) {
			return
		}
	}
	m.appendBoundedLog(entry)
}

func (m *Model) appendBoundedLog(entry engine.LogEntry) {
	limit := m.maxLogs
	if limit <= 0 {
		limit = defaultMaxLogLines
	}
	m.logs = appendBoundedSlice(m.logs, entry, limit)
}

func (m *Model) applyStreamState(msg StreamStateMsg) {
	switch msg.Kind {
	case "metrics":
		m.metricsActive = msg.Active
		if msg.Target != "" {
			m.metricsTarget = msg.Target
		}
	case "logs":
		m.logsActive = msg.Active
		if msg.Target != "" {
			m.logsTarget = msg.Target
		}
	}
	if msg.Err != nil {
		m.lastErr = fmt.Sprintf("%s stream (%s): %v", msg.Kind, msg.Target, msg.Err)
		m.statusMsg = fmt.Sprintf("%s stream stopped with error", msg.Kind)
		return
	}
	if msg.Active {
		m.lastErr = ""
		m.statusMsg = fmt.Sprintf("%s stream active (%s)", msg.Kind, msg.Target)
		return
	}
	m.statusMsg = fmt.Sprintf("%s stream idle", msg.Kind)
}

func (m *Model) applyTakeoverResult(msg TakeoverResultMsg) {
	m.pendingTakeover = algebraic.None[TakeoverRequest]()
	if msg.Err != nil {
		m.lastErr = fmt.Sprintf("session (%s): %v", msg.Target, msg.Err)
		m.statusMsg = "Interactive session ended with error"
		return
	}
	m.lastErr = ""
	m.statusMsg = fmt.Sprintf("Returned from interactive session (%s)", msg.Target)
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
		items[maxLen-1] = v
		return items[:maxLen]
	}
	return append(items, v)
}
