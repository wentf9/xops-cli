package tui

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/wentf9/xops-cli/core/engine"
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

// View 实现 Bubble Tea v2 声明式视图渲染（tea.View），自动控制 AltScreen 与窗口标题。
func (m Model) View() tea.View {
	var b strings.Builder
	b.WriteString(m.renderHeader())
	b.WriteByte('\n')
	if banners := m.renderSafetyBanners(); banners != "" {
		b.WriteString(banners)
		b.WriteByte('\n')
	}
	if m.filterActive || m.filterQuery != "" {
		b.WriteString(m.renderFilterBar())
		b.WriteByte('\n')
	}
	b.WriteString(m.renderBody())
	b.WriteByte('\n')
	b.WriteString(m.renderFooter())

	view := tea.NewView(b.String())
	view.AltScreen = m.altScreen
	view.WindowTitle = "XOps v2 Workbench — " + m.activeView.String()
	return view
}

func (m Model) renderHeader() string {
	tabs := []ViewKind{ViewHosts, ViewMetrics, ViewLogs, ViewOperations, ViewHelp}
	parts := make([]string, 0, len(tabs)+2)
	parts = append(parts, m.theme.title.Render("XOps v2"))
	for i, vk := range tabs {
		label := fmt.Sprintf("%d:%s", i+1, vk.String())
		if vk == ViewHelp {
			label = "?:Help"
		}
		if vk == m.activeView {
			parts = append(parts, m.theme.tabActive.Render(label))
		} else {
			parts = append(parts, m.theme.tabIdle.Render(label))
		}
	}
	meta := fmt.Sprintf("events=%d dropped=%d streams=%d", m.totalEvents, m.droppedEvents, m.activeStreams)
	parts = append(parts, m.theme.muted.Render(meta))
	return strings.Join(parts, " ")
}

func (m Model) renderSafetyBanners() string {
	var lines []string
	if m.gateHalted {
		reason := pickStr(m.haltReason, "audit post-write failure")
		lines = append(lines, m.theme.bannerErr.Render("SECURITY GATE HALTED: "+reason))
	}
	if m.hasUnknownOut {
		lines = append(lines, m.theme.bannerWrn.Render("WARNING: OutcomeUnknown detected — DO NOT auto-retry"))
	}
	return strings.Join(lines, "\n")
}

func (m Model) renderFilterBar() string {
	mode := "filter"
	if m.filterActive {
		mode = "filter (editing)"
	}
	return fmt.Sprintf("[%s]: %s", mode, m.filterQuery)
}

func (m Model) renderBody() string {
	switch m.activeView {
	case ViewHosts:
		return m.renderHostsView()
	case ViewMetrics:
		return m.renderMetricsView()
	case ViewLogs:
		return m.renderLogsView()
	case ViewOperations:
		return m.renderOperationsView()
	case ViewHelp:
		return m.renderHelpView()
	default:
		return "Invalid view"
	}
}

func (m Model) renderHostsView() string {
	hosts := m.filteredHosts()
	var b strings.Builder
	b.WriteString(m.theme.section.Render(fmt.Sprintf("Hosts & Nodes (%d/%d) rev=%s", len(hosts), len(m.hosts), pickStr(m.inventoryRev, "-"))))
	b.WriteByte('\n')
	if len(hosts) == 0 {
		b.WriteString(m.theme.muted.Render("  (no hosts loaded; press 'r' to refresh or adjust filter)"))
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

func (m Model) renderMetricsView() string {
	var b strings.Builder
	state := "idle"
	if m.metricsActive {
		state = "streaming"
	}
	b.WriteString(m.theme.section.Render(fmt.Sprintf("Host Metrics [%s] target=%s sort=%s", state, pickStr(m.metricsTarget, "-"), m.processSort.String())))
	b.WriteByte('\n')
	if frame, ok := m.latestFrame.Get(); ok {
		b.WriteString(formatMetricsFrame(frame))
		b.WriteByte('\n')
	}
	if len(m.metrics) == 0 && m.latestFrame.IsNone() {
		b.WriteString(m.theme.muted.Render("  (no metric samples yet; press 'm' on a host to start streaming)"))
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

func formatMetricsFrame(f engine.HostMetricsFrame) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  Host: %s (%s)  CPU: %.1f%%  Load: %.2f %.2f %.2f  Mem: %.1f%% (%d/%d B)  Uptime: %s",
		pickStr(f.Hostname, f.NodeID), f.NodeID, f.CPUPercent, f.Load1, f.Load5, f.Load15,
		f.MemPercent, f.MemUsed, f.MemTotal, f.Uptime.String())
	if len(f.Disks) > 0 {
		b.WriteString("\n  Disks:")
		for _, d := range f.Disks {
			fmt.Fprintf(&b, " %s=%.1f%%", d.Mount, d.UsedPercent)
		}
	}
	if len(f.Processes) > 0 {
		b.WriteString("\n  Top Processes:")
		for i, p := range f.Processes {
			if i >= 5 {
				break
			}
			fmt.Fprintf(&b, "\n    pid=%-6d user=%-10s cpu=%5.1f%% mem=%5.1f%% %s", p.PID, p.User, p.CPUPercent, p.MemPercent, p.Command)
		}
	}
	return b.String()
}

func (m Model) renderLogsView() string {
	var b strings.Builder
	state := "idle"
	if m.logsActive {
		state = "streaming"
	}
	logs := m.filteredLogs()
	b.WriteString(m.theme.section.Render(fmt.Sprintf("Live Logs [%s] target=%s lines=%d", state, pickStr(m.logsTarget, "-"), len(logs))))
	b.WriteByte('\n')
	if len(logs) == 0 {
		b.WriteString(m.theme.muted.Render("  (no log entries yet; press 'l' on a host to stream logs)"))
		return b.String()
	}
	maxRows := max(m.height-8, 5)
	start := min(m.logScroll, max(len(logs)-maxRows, 0))
	end := min(start+maxRows, len(logs))
	for i := start; i < end; i++ {
		l := logs[i]
		trunc := ""
		if l.Truncated {
			trunc = " [truncated]"
		}
		fmt.Fprintf(&b, "  [%s|%s] %s%s", pickStr(l.NodeID, "-"), l.Stream.String(), l.Data, trunc)
		if i+1 < end {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func (m Model) renderOperationsView() string {
	var b strings.Builder
	b.WriteString(m.theme.section.Render(fmt.Sprintf("Operations (%d) | Pool (%d) | Diagnostics (%d)", len(m.operations), len(m.poolEvents), len(m.diagnostics))))
	b.WriteByte('\n')
	if len(m.operations) == 0 && len(m.poolEvents) == 0 && len(m.diagnostics) == 0 {
		b.WriteString(m.theme.muted.Render("  (no operation or system events recorded yet)"))
		return b.String()
	}
	q := strings.ToLower(strings.TrimSpace(m.filterQuery))
	for _, op := range m.operations {
		line := formatOperationLine(op)
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

func formatOperationLine(op engine.OperationView) string {
	status := "RUNNING"
	switch {
	case op.Unknown:
		status = "UNKNOWN"
	case op.Completed && op.Succeeded:
		status = "OK"
	case op.Completed:
		status = "FAILED"
	}
	return fmt.Sprintf("%-8s %-12s %s.%s node=%s %s", status, shortID(op.OperationID), pickStr(op.Tool, "-"), pickStr(op.Action, "-"), pickStr(op.NodeID, "-"), pickStr(op.LastMessage, op.Summary))
}

func (m Model) renderHelpView() string {
	return strings.Join([]string{
		m.theme.section.Render("Keybindings & Runtime Controls"),
		"  1-4 / ? / Tab / Shift+Tab : Switch workbench views (Hosts, Metrics, Logs, Operations, Help)",
		"  j/k or Up/Down / g / G    : Navigate host selection or scroll logs",
		"  /                         : Filter current view (Enter apply, Esc clear)",
		"  r                         : Refresh inventory snapshot from Engine",
		"  m / l / x                 : Start Metrics stream / Start Log stream / Stop active streams",
		"  s                         : Toggle process sort order (CPU / Mem)",
		"  Enter (Hosts view)        : Trigger supervised interactive terminal takeover (if wired)",
		"  q / Ctrl+C                : Quit cleanly and restore terminal state",
	}, "\n")
}

func (m Model) renderFooter() string {
	status := m.statusMsg
	if m.lastErr != "" {
		status = "ERR: " + m.lastErr
	}
	help := "keys: 1-4/? views | / filter | r refresh | m metrics | l logs | x stop | q quit"
	return m.theme.footer.Render(status) + "  " + m.theme.muted.Render(help)
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
