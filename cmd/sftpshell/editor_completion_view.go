package sftpshell

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

const completionMaxRows = 6
const completionColumnGap = 2

// Normalize labels and measure them once per result. Rendering and navigation
// use only the current page, even when a directory contains thousands of items.
type completionMenu struct {
	labels     []string
	labelWidth int
}

func newCompletionMenu(candidates []string) completionMenu {
	menu := completionMenu{labels: make([]string, len(candidates))}
	for i, candidate := range candidates {
		menu.labels[i] = normalizePastedText(candidate)
		menu.labelWidth = max(menu.labelWidth, ansi.StringWidth(menu.labels[i]))
	}
	return menu
}

type completionPage struct {
	columns, rows, cellWidth int
	size, number, count      int
	start, end               int
	status                   bool
}

func (m *editorModel) completionPage() completionPage {
	total := len(m.menu.labels)
	width := max(1, m.width)
	cellWidth := min(width, max(3, m.menu.labelWidth+2))
	columns := max(1, min(total, (width+completionColumnGap)/(cellWidth+completionColumnGap)))
	available := max(0, m.height-strings.Count(m.promptPrefix, "\n")-1)
	status := available >= 2
	rows := min(completionMaxRows, available)
	if status {
		rows = min(completionMaxRows, available-1)
	}
	size := columns * max(1, rows)
	count := max(1, (total+size-1)/size)
	number := min(count-1, max(0, m.candidate)/size)
	start := number * size
	return completionPage{columns: columns, rows: rows, cellWidth: cellWidth, size: size,
		number: number, count: count, start: start, end: min(start+size, total), status: status}
}

func (m *editorModel) completionView() string {
	page := m.completionPage()
	if page.rows == 0 {
		return ""
	}
	// Retain the same number of rows on the final partial page to avoid jumps.
	rows := min(page.rows, (len(m.menu.labels)+page.columns-1)/page.columns)
	lines := make([]string, 0, rows+1)
	for row := 0; row < rows; row++ {
		var line strings.Builder
		for col := 0; col < page.columns; col++ {
			index := page.start + row*page.columns + col
			if index >= page.end {
				break
			}
			if col > 0 {
				line.WriteString(strings.Repeat(" ", completionColumnGap))
			}
			marker := "  "
			if index == m.candidate {
				marker = "> "
			}
			cell := ansi.Truncate(marker+m.menu.labels[index], page.cellWidth, "…")
			cell += strings.Repeat(" ", max(0, page.cellWidth-ansi.StringWidth(cell)))
			if index == m.candidate {
				cell = lipgloss.NewStyle().Reverse(true).Render(cell)
			}
			line.WriteString(cell)
		}
		lines = append(lines, line.String())
	}
	if page.status {
		lines = append(lines, m.completionPageStatus(page))
	}
	return strings.Join(lines, "\n")
}

func (m *editorModel) completionPageStatus(page completionPage) string {
	status := i18n.Tf("sftp_completion_page", map[string]any{
		"Page": page.number + 1, "Pages": page.count, "Count": len(m.menu.labels),
	})
	if ansi.StringWidth(status) > m.width {
		status = fmt.Sprintf("%d/%d · %d", page.number+1, page.count, len(m.menu.labels))
	}
	return ansi.Truncate(status, max(1, m.width), "…")
}

// Page keys retain the slot within a page, clamping on a partial final page.
// Unlike Tab, PageUp/PageDown stop at the first and last pages.
func (m *editorModel) pageCompletion(delta int) {
	if m.completion == nil || len(m.completion.candidates) < 2 {
		return
	}
	page := m.completionPage()
	next := max(0, min(page.count-1, page.number+delta))
	if next == page.number {
		return
	}
	slot := max(0, m.candidate) % page.size
	m.candidate = min(next*page.size+slot, len(m.completion.candidates)-1)
	m.replaceCompletion(m.completion.candidates[m.candidate])
}
