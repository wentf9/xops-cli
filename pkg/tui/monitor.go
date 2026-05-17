package tui

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type monitorMsg *ssh.SystemMetrics
type monitorErrorMsg error

type monitorModel struct {
	nodeID    string
	collector *ssh.MetricsCollector
	metrics   *ssh.SystemMetrics
	err       error
	width     int
	height    int
	lastFetch time.Time
	paused    bool
}

func newMonitorModel(nodeID string, client *ssh.Client) monitorModel {
	return monitorModel{
		nodeID:    nodeID,
		collector: ssh.NewMetricsCollector(client),
	}
}

func (m monitorModel) Init() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithCancel(context.Background())
		// Ideally store cancel in a long-lived context holder, but we can rely on standard connection dropping on exit
		_ = cancel
		if err := m.collector.Start(ctx); err != nil {
			return monitorErrorMsg(err)
		}
		return m.fetchMetrics()()
	}
}

func (m monitorModel) fetchMetrics() tea.Cmd {
	return func() tea.Msg {
		// Do not timeout NextFrame, it blocks for 2 seconds remotely by design
		ctx := context.Background()
		metrics, err := m.collector.NextFrame(ctx)
		if err != nil {
			return monitorErrorMsg(err)
		}
		return monitorMsg(metrics)
	}
}

func (m monitorModel) Update(msg tea.Msg) (monitorModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case monitorMsg:
		m.metrics = msg
		m.err = nil
		m.lastFetch = time.Now()
		// Auto trigger next frame if not paused
		if !m.paused {
			return m, m.fetchMetrics()
		}
	case monitorErrorMsg:
		m.err = msg
	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "q":
			m.collector.Close()
			return m, nil // Will be handled by parent model to switch state
		case "p", " ":
			m.paused = !m.paused
			if !m.paused {
				return m, m.fetchMetrics()
			}
		case "s":
			if m.collector.SortBy == "cpu" {
				m.collector.SortBy = "mem"
			} else {
				m.collector.SortBy = "cpu"
			}
		case "o":
			m.collector.SortAsc = !m.collector.SortAsc
		}
	}
	return m, nil
}

func (m monitorModel) View() string {
	if m.err != nil {
		return errorStyle.Render(i18n.Tf("tui_monitor_error", map[string]any{"Error": m.err}))
	}

	if m.metrics == nil {
		return i18n.T("tui_monitor_fetching")
	}

	// 基础布局：使用 Lipgloss 渲染简单的仪表盘
	statusInfo := ""
	if m.paused {
		statusInfo = " [" + i18n.T("tui_monitor_paused") + "]"
	}

	sortInfo := i18n.T("tui_monitor_sort_by_" + m.collector.SortBy)
	orderKey := "tui_monitor_order_desc"
	if m.collector.SortAsc {
		orderKey = "tui_monitor_order_asc"
	}
	sortInfo += " | " + i18n.T(orderKey)

	headerStr := i18n.Tf("tui_monitor_header", map[string]any{
		"Node":   m.nodeID,
		"Cores":  m.metrics.Cores,
		"Uptime": m.metrics.Uptime,
		"Load":   m.metrics.LoadAverage,
	}) + statusInfo + "\n" + sortInfo
	header := headerStyle.Render(headerStr)

	// 左侧：进度条区域
	cpuBar := renderProgressBar(i18n.T("tui_monitor_cpu"), m.metrics.CPUUsage)

	// 内存行：合并百分比、进度条和原始数值
	memBar := renderProgressBar(i18n.T("tui_monitor_mem"), m.metrics.MemUsage)
	memRaw := fmt.Sprintf(" (%d MB / %d MB)", m.metrics.MemUsed, m.metrics.MemTotal)

	leftElements := []string{
		cpuBar,
		memBar + memRaw,
		"",
		lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Underline(true).Render(i18n.T("tui_monitor_disk_parts")),
	}

	for _, d := range m.metrics.Disks {
		diskLabel := i18n.Tf("tui_monitor_disk", map[string]any{"Mount": d.MountPoint})
		bar := renderProgressBar(diskLabel, d.Usage)

		totalGB := float64(d.Total) / 1024.0
		usedGB := float64(d.Used) / 1024.0
		raw := fmt.Sprintf(" (%.1f GB / %.1f GB)", usedGB, totalGB)

		leftElements = append(leftElements, bar+raw)
	}

	leftBox := lipgloss.JoinVertical(lipgloss.Left, leftElements...)

	// 右侧：Top 进程区域
	processTitle := lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Underline(true).Render(i18n.T("tui_monitor_top_procs"))
	processList := ""
	for _, p := range m.metrics.TopProcesses {
		processList += p + "\n"
	}

	rightBox := lipgloss.JoinVertical(lipgloss.Left,
		processTitle,
		processList,
	)

	// 响应式布局：如果宽度不足 100，则垂直排列，否则水平排列
	var content string
	if m.width > 0 && m.width < 100 {
		// 垂直模式：在下方增加一个明显的分割线
		separator := lipgloss.NewStyle().
			Foreground(lipgloss.Color("8")).
			MarginTop(1).
			MarginBottom(1).
			Render(strings.Repeat("─", 50))

		content = lipgloss.JoinVertical(lipgloss.Left, leftBox, separator, rightBox)
	} else {
		// 水平模式
		// 为左侧增加一些 Padding
		leftBox = lipgloss.NewStyle().PaddingRight(5).Render(leftBox)
		content = lipgloss.JoinHorizontal(lipgloss.Top, leftBox, rightBox)
	}

	footer := i18n.Tf("tui_monitor_footer", map[string]any{"Time": m.lastFetch.Format("15:04:05")})
	helpStr := lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(
		"\n[Space/P] " + i18n.T("tui_help_pause") +
			" | [S] " + i18n.T("tui_help_sort") +
			" | [O] " + i18n.T("tui_help_order"),
	)

	return lipgloss.JoinVertical(lipgloss.Left, header, "", content, footer, helpStr)
}

func renderProgressBar(label string, percent float64) string {
	if math.IsNaN(percent) || math.IsInf(percent, 0) || percent < 0 {
		percent = 0
	}

	width := 30
	filled := int(percent / 100.0 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)

	color := "2" // Green
	if percent > 80 {
		color = "1" // Red
	} else if percent > 50 {
		color = "3" // Yellow
	}

	style := lipgloss.NewStyle().Foreground(lipgloss.Color(color))
	return fmt.Sprintf("%-12s [%s] %.1f%%", label, style.Render(bar), percent)
}

// 补充一些样式，如果 style.go 里没有的话
var (
	headerStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("12")).
		Bold(true).
		Border(lipgloss.NormalBorder(), false, false, true, false)
)
