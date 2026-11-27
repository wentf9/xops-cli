package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/i18n"
)

// workbenchTheme 封装 Lipgloss v2 样式表（在实例字段内构造，严格 0 包级 var、0 init()）。
type workbenchTheme struct {
	title     lipgloss.Style
	tabActive lipgloss.Style
	tabIdle   lipgloss.Style
	bannerErr lipgloss.Style
	bannerWrn lipgloss.Style
	selected  lipgloss.Style
	muted     lipgloss.Style
	section   lipgloss.Style
	footer    lipgloss.Style
}

func newWorkbenchTheme() workbenchTheme {
	return workbenchTheme{
		title:     lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7DCFFF")),
		tabActive: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#1A1B26")).Background(lipgloss.Color("#7AA2F7")).Padding(0, 1),
		tabIdle:   lipgloss.NewStyle().Foreground(lipgloss.Color("#A9B1D6")).Padding(0, 1),
		bannerErr: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(lipgloss.Color("#F7768E")).Padding(0, 1),
		bannerWrn: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#1A1B26")).Background(lipgloss.Color("#E0AF68")).Padding(0, 1),
		selected:  lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#9ECE6A")),
		muted:     lipgloss.NewStyle().Foreground(lipgloss.Color("#787C99")),
		section:   lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#BB9AF7")),
		footer:    lipgloss.NewStyle().Foreground(lipgloss.Color("#C0CAF5")),
	}
}

// View 实现 Bubble Tea v2 声明式视图渲染（tea.View），按当前激活语种实时本地化全部界面元素并控制 AltScreen 与窗口标题。
func (m Model) View() tea.View {
	loc := m.loc()
	var b strings.Builder
	b.WriteString(m.renderHeader(loc))
	b.WriteByte('\n')
	if banners := m.renderSafetyBanners(loc); banners != "" {
		b.WriteString(banners)
		b.WriteByte('\n')
	}
	if m.filterActive || m.filterQuery != "" {
		b.WriteString(m.renderFilterBar(loc))
		b.WriteByte('\n')
	}
	b.WriteString(m.renderBody(loc))
	b.WriteByte('\n')
	b.WriteString(m.renderFooter(loc))

	view := tea.NewView(b.String())
	view.AltScreen = m.altScreen
	view.WindowTitle = loc.T(i18n.KeyTUIWindowTitle, i18n.Str("view", loc.T(m.activeView.LabelKey())))
	return view
}

func (m Model) renderHeader(loc *i18n.Localizer) string {
	tabs := []ViewKind{ViewHosts, ViewMetrics, ViewLogs, ViewOperations, ViewHelp}
	parts := make([]string, 0, len(tabs)+2)
	parts = append(parts, m.theme.title.Render(loc.T(i18n.KeyTUIBrand)))
	for i, vk := range tabs {
		viewName := loc.T(vk.LabelKey())
		label := fmt.Sprintf("%d:%s", i+1, viewName)
		if vk == ViewHelp {
			label = "?:" + viewName
		}
		if vk == m.activeView {
			parts = append(parts, m.theme.tabActive.Render(label))
		} else {
			parts = append(parts, m.theme.tabIdle.Render(label))
		}
	}
	meta := loc.T(
		i18n.KeyTUIHeaderMeta,
		i18n.Uint64("events", m.totalEvents),
		i18n.Uint64("dropped", m.droppedEvents),
		i18n.Int("streams", m.activeStreams),
	)
	parts = append(parts, m.theme.muted.Render(meta))
	return strings.Join(parts, " ")
}

func (m Model) renderSafetyBanners(loc *i18n.Localizer) string {
	var lines []string
	if m.gateHalted {
		reason := m.resolveHaltReason(loc)
		lines = append(lines, m.theme.bannerErr.Render(loc.T(i18n.KeyTUIBannerHalted, i18n.BoundStr("reason", reason))))
	}
	if m.hasUnknownOut {
		lines = append(lines, m.theme.bannerWrn.Render(loc.T(i18n.KeyTUIBannerUnknownOutcome)))
	}
	return strings.Join(lines, "\n")
}

func (m Model) resolveHaltReason(loc *i18n.Localizer) string {
	if m.haltErr != nil {
		if rendered := strings.TrimSpace(loc.RenderError(m.haltErr)); rendered != "" {
			return rendered
		}
	}
	if trimmed := strings.TrimSpace(m.haltReason); trimmed != "" {
		return trimmed
	}
	return loc.T(i18n.KeyTUIBannerHaltedDefaultReason)
}

func (m Model) renderFilterBar(loc *i18n.Localizer) string {
	if m.filterActive {
		return loc.T(i18n.KeyTUIFilterEditing, i18n.BoundStr("query", m.filterQuery))
	}
	return loc.T(i18n.KeyTUIFilterLabel, i18n.BoundStr("query", m.filterQuery))
}

func (m Model) renderBody(loc *i18n.Localizer) string {
	switch m.activeView {
	case ViewHosts:
		return m.renderHostsView(loc)
	case ViewMetrics:
		return m.renderMetricsView(loc)
	case ViewLogs:
		return m.renderLogsView(loc)
	case ViewOperations:
		return m.renderOperationsView(loc)
	case ViewHelp:
		return m.renderHelpView(loc)
	default:
		return loc.T(i18n.KeyTUIViewInvalid)
	}
}

func (m Model) renderHostsView(loc *i18n.Localizer) string {
	hosts := m.filteredHosts()
	var b strings.Builder
	title := loc.T(
		i18n.KeyTUIHostsTitle,
		i18n.Int("shown", len(hosts)),
		i18n.Int("total", len(m.hosts)),
		i18n.BoundStr("rev", pickStr(m.inventoryRev, "-")),
	)
	b.WriteString(m.theme.section.Render(title))
	b.WriteByte('\n')
	if len(hosts) == 0 {
		b.WriteString(m.theme.muted.Render(loc.T(i18n.KeyTUIHostsEmpty)))
		return b.String()
	}
	maxRows := max(m.height-8, 5)
	start, end := visibleWindow(m.selectedHost, len(hosts), maxRows)
	for i := start; i < end; i++ {
		h := hosts[i]
		prefix := "  "
		if i == m.selectedHost {
			prefix = "> "
		}
		tags := ""
		if len(h.Tags) > 0 {
			tags = " [" + strings.Join(h.Tags, ",") + "]"
		}
		line := fmt.Sprintf("%s%-18s %-24s user=%-10s origin=%-8s%s", prefix, h.NodeID, pickStr(h.Endpoint, "-"), pickStr(h.User, "-"), h.Origin, tags)
		if i == m.selectedHost {
			b.WriteString(m.theme.selected.Render(line))
		} else {
			b.WriteString(line)
		}
		if i+1 < end {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func (m Model) renderMetricsView(loc *i18n.Localizer) string {
	var b strings.Builder
	title := loc.T(
		i18n.KeyTUIMetricsTitle,
		i18n.Str("state", loc.T(streamActiveKey(m.metricsActive))),
		i18n.BoundStr("target", pickStr(m.metricsTarget, "-")),
		i18n.Str("sort", loc.T(processSortKey(m.processSort))),
	)
	b.WriteString(m.theme.section.Render(title))
	b.WriteByte('\n')
	if frame, ok := m.latestFrame.Get(); ok {
		b.WriteString(formatMetricsFrame(loc, frame))
		b.WriteByte('\n')
	}
	if len(m.metrics) == 0 && m.latestFrame.IsNone() {
		b.WriteString(m.theme.muted.Render(loc.T(i18n.KeyTUIMetricsEmpty)))
		return b.String()
	}
	q := strings.ToLower(strings.TrimSpace(m.filterQuery))
	shown := 0
	for _, pt := range m.metrics {
		if q != "" && !strings.Contains(strings.ToLower(pt.Name+pt.NodeID), q) {
			continue
		}
		fmt.Fprintf(&b, "  %-16s %-24s %.2f %s\n", pickStr(pt.NodeID, "-"), pt.Name, pt.Value, pt.Unit)
		shown++
		if shown >= max(m.height-12, 5) {
			break
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatMetricsFrame(loc *i18n.Localizer, f engine.HostMetricsFrame) string {
	var b strings.Builder
	b.WriteString(loc.T(
		i18n.KeyTUIMetricsFrameSummary,
		i18n.BoundStr("host", pickStr(f.Hostname, f.NodeID)),
		i18n.BoundStr("node", f.NodeID),
		safeFloatParam("cpu", f.CPUPercent, 1),
		safeFloatParam("load1", f.Load1, 2),
		safeFloatParam("load5", f.Load5, 2),
		safeFloatParam("load15", f.Load15, 2),
		safeFloatParam("mem_pct", f.MemPercent, 1),
		i18n.Uint64("mem_used", f.MemUsed),
		i18n.Uint64("mem_total", f.MemTotal),
		i18n.BoundStr("uptime", f.Uptime.String()),
	))
	if len(f.Disks) > 0 {
		b.WriteByte('\n')
		b.WriteString(loc.T(i18n.KeyTUIMetricsDisks))
		for _, d := range f.Disks {
			fmt.Fprintf(&b, " %s=%.1f%%", d.Mount, d.UsedPercent)
		}
	}
	if len(f.Processes) > 0 {
		b.WriteByte('\n')
		b.WriteString(loc.T(i18n.KeyTUIMetricsTopProcesses))
		for i, p := range f.Processes {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&b, "\n    pid=%-6d user=%-10s cpu=%5.1f%% mem=%5.1f%% %s", p.PID, p.User, p.CPUPercent, p.MemPercent, p.Command)
		}
	}
	return b.String()
}

func (m Model) renderLogsView(loc *i18n.Localizer) string {
	var b strings.Builder
	logs := m.filteredLogs()
	title := loc.T(
		i18n.KeyTUILogsTitle,
		i18n.Str("state", loc.T(streamActiveKey(m.logsActive))),
		i18n.BoundStr("target", pickStr(m.logsTarget, "-")),
		i18n.Int("lines", len(logs)),
	)
	b.WriteString(m.theme.section.Render(title))
	b.WriteByte('\n')
	if len(logs) == 0 {
		b.WriteString(m.theme.muted.Render(loc.T(i18n.KeyTUILogsEmpty)))
		return b.String()
	}
	maxRows := max(m.height-8, 5)
	start := min(m.logScroll, max(len(logs)-maxRows, 0))
	end := min(start+maxRows, len(logs))
	truncLabel := " " + loc.T(i18n.KeyTUILogsTruncated)
	for i := start; i < end; i++ {
		l := logs[i]
		trunc := ""
		if l.Truncated {
			trunc = truncLabel
		}
		fmt.Fprintf(&b, "  [%s|%s] %s%s", pickStr(l.NodeID, "-"), l.Stream.String(), l.Data, trunc)
		if i+1 < end {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func (m Model) renderOperationsView(loc *i18n.Localizer) string {
	var b strings.Builder
	title := loc.T(
		i18n.KeyTUIOpsTitle,
		i18n.Int("ops", len(m.operations)),
		i18n.Int("pool", len(m.poolEvents)),
		i18n.Int("diags", len(m.diagnostics)),
	)
	b.WriteString(m.theme.section.Render(title))
	b.WriteByte('\n')
	if len(m.operations) == 0 && len(m.poolEvents) == 0 && len(m.diagnostics) == 0 {
		b.WriteString(m.theme.muted.Render(loc.T(i18n.KeyTUIOpsEmpty)))
		return b.String()
	}
	q := strings.ToLower(strings.TrimSpace(m.filterQuery))
	for _, op := range m.operations {
		line := formatOperationLine(loc, op)
		if q != "" && !strings.Contains(strings.ToLower(line), q) {
			continue
		}
		b.WriteString("  " + line + "\n")
	}
	for _, d := range tailSlice(m.diagnostics, 4) {
		fmt.Fprintf(&b, "  [diag:%s/%s] %s: %s\n", d.Scope.String(), d.Severity.String(), d.Code, d.Message)
	}
	for _, pe := range tailSlice(m.poolEvents, 4) {
		fmt.Fprintf(&b, "  [pool:%s] ep=%s leases=%d %s\n", pe.Action.String(), pickStr(pe.Endpoint, "-"), pe.ActiveLeases, pe.Detail)
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatOperationLine(loc *i18n.Localizer, op engine.OperationView) string {
	status := loc.T(operationStatusKey(op))
	return fmt.Sprintf("%-8s %-12s %s.%s node=%s %s", status, shortID(op.OperationID), pickStr(op.Tool, "-"), pickStr(op.Action, "-"), pickStr(op.NodeID, "-"), pickStr(op.LastMessage, op.Summary))
}

func (m Model) renderHelpView(loc *i18n.Localizer) string {
	var b strings.Builder
	b.WriteString(m.theme.section.Render(loc.T(i18n.KeyTUIHelpTitle)))
	for line := range strings.SplitSeq(loc.T(i18n.KeyTUIHelpBody), "\n") {
		b.WriteString("\n  ")
		b.WriteString(line)
	}
	return b.String()
}

func (m Model) renderFooter(loc *i18n.Localizer) string {
	status := loc.Render(m.statusMsg)
	if m.lastErr != nil {
		status = loc.T(i18n.KeyTUIFooterErrPrefix, i18n.BoundStr("err", loc.RenderError(m.lastErr)))
	}
	help := loc.T(i18n.KeyTUIFooterHelp)
	return m.theme.footer.Render(status) + "  " + m.theme.muted.Render(help)
}

func streamActiveKey(active bool) domi18n.MessageID {
	if active {
		return i18n.KeyTUIStreamStreaming
	}
	return i18n.KeyTUIStreamIdle
}

func processSortKey(sortBy engine.ProcessSortBy) domi18n.MessageID {
	if sortBy == engine.ProcessSortMem {
		return i18n.KeyTUISortMem
	}
	return i18n.KeyTUISortCPU
}

func localeNameKey(loc domi18n.Locale) domi18n.MessageID {
	if loc == domi18n.LocaleZh {
		return i18n.KeyTUILangNameZh
	}
	return i18n.KeyTUILangNameEn
}

func operationStatusKey(op engine.OperationView) domi18n.MessageID {
	switch {
	case op.Unknown:
		return i18n.KeyTUIOpStatusUnknown
	case op.Completed && op.Succeeded:
		return i18n.KeyTUIOpStatusOK
	case op.Completed:
		return i18n.KeyTUIOpStatusFailed
	default:
		return i18n.KeyTUIOpStatusRunning
	}
}

// safeFloatParam 构造有限浮点参数；对 NaN/±Inf 降级为 "-" 占位串，防止单帧异常浮点导致整条消息失效。
func safeFloatParam(key string, v float64, prec int) domi18n.Param {
	if p := i18n.Float(key, v, prec); p.IsValid() {
		return p
	}
	return i18n.Str(key, "-")
}

func visibleWindow(cursor, total, maxRows int) (int, int) {
	if total <= maxRows {
		return 0, total
	}
	start := max(cursor-maxRows/2, 0)
	if start+maxRows > total {
		start = total - maxRows
	}
	return start, start + maxRows
}

func tailSlice[T any](items []T, n int) []T {
	if len(items) <= n {
		return items
	}
	return items[len(items)-n:]
}

func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}
