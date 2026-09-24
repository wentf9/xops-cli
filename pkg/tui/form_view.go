package tui

import (
	"errors"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func (m Model) formWidth() int {
	return max(m.lastSize.Width-appStyle.GetHorizontalFrameSize(), 1)
}

func (m Model) formFeedback() string {
	// Huh validates on field navigation. Display those live errors in the
	// same bounded area as Ctrl+S errors, without obscuring save confirmations.
	if m.form != nil && !m.mutationPending && !m.formConflict && m.formVerifyErr == nil {
		if err := errors.Join(m.form.Errors()...); err != nil {
			return errorStyle.Render(err.Error())
		}
	}
	return m.status
}

func (m Model) formFooter() string {
	width := m.formWidth()
	// Huh needs the focused field plus its own help. The two extra rows
	// account for Huh's help separator and the gap before this footer.
	fieldHeight := 2
	if m.form != nil {
		fieldHeight = max(fieldHeight, lipgloss.Height(m.form.GetFocusedField().View()))
	}
	budget := max(m.lastSize.Height-appStyle.GetVerticalFrameSize()-fieldHeight-3, 1)
	if m.form != nil && m.form.State == huh.StateCompleted {
		// Completed forms render no fields or Huh help, so feedback owns the
		// whole available height rather than reserving space for the last field.
		budget = max(m.lastSize.Height-appStyle.GetVerticalFrameSize(), 1)
	}
	if m.formVerifyErr != nil {
		return m.formVerificationFooter(budget, width)
	}
	help := ansi.Wrap(statusStyle.Render(i18n.T("tui_form_help")), width, "")
	feedback := m.formFeedback()
	if feedback == "" {
		return limitFormFeedback(help, budget, width)
	}
	status := ansi.Wrap(statusStyle.Render(feedback), width, "")
	if budget == 1 {
		return limitFormFeedback(status, 1, width)
	}
	help = limitFormFeedback(help, budget-1, width)
	status = limitFormFeedback(status, budget-lipgloss.Height(help), width)
	return status + "\n" + help
}

func (m Model) formVerificationFooter(height, width int) string {
	// Verification decisions have their own input bindings. Reserve the
	// question first, especially its trailing [y/N], and omit generic help.
	reason, question := "", m.status
	if split := strings.LastIndex(m.status, "\n"); split >= 0 {
		reason, question = m.status[:split], m.status[split+1:]
	}
	question = ansi.Wrap(question, width, "")
	lines := strings.Split(question, "\n")
	if len(lines) >= height {
		return strings.Join(lines[len(lines)-height:], "\n")
	}
	if reason == "" {
		return question
	}
	reason = ansi.Wrap(reason, width, "")
	return limitFormFeedback(reason, height-len(lines), width) + "\n" + question
}

// Keep both the beginning and end of long feedback so error context and
// trailing confirmation prompts remain visible. The full status is retained.
func limitFormFeedback(text string, height, width int) string {
	lines := strings.Split(text, "\n")
	if len(lines) <= height {
		return text
	}
	if height <= 2 {
		first := ansi.Truncate(lines[0], max(width-1, 0), "") + "…"
		if height == 1 {
			return first + ansi.ResetStyle
		}
		return first + "\n" + lines[len(lines)-1]
	}
	return strings.Join(append(lines[:height-2:height-2], "…", lines[len(lines)-1]), "\n")
}

// Reserve the actual wrapped footer height after every update, including
// asynchronous save results and resizes during verification or persistence.
func (m *Model) resizeNodeForm() tea.Cmd {
	if m.state != viewForm || m.form == nil {
		return nil
	}
	// Enter answers the confirmation instead of submitting a field here.
	m.form.WithShowHelp(m.formVerifyErr == nil)
	if m.form.State == huh.StateCompleted {
		return nil
	}
	// Measure wrapped field titles at the new width before reserving space.
	m.form.WithWidth(m.formWidth())
	height := m.lastSize.Height - appStyle.GetVerticalFrameSize() - lipgloss.Height(m.formFooter()) - 2
	m.form.WithHeight(max(height, 1))
	// WithWidth/WithHeight resize Huh's viewport without rebuilding its content
	// or scroll offset. A size update rebuilds both around the focused field.
	_, cmd := m.form.Update(tea.WindowSizeMsg{Width: m.formWidth(), Height: max(height, 1)})
	return cmd
}
