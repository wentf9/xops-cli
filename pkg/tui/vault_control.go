package tui

import (
	"context"
	"io"

	tea "github.com/charmbracelet/bubbletea"
)

// WithVaultControl injects process-local lock/unlock actions. Unlock runs with
// Bubble Tea's terminal released; no master password enters the model state.
func WithVaultControl(control func(context.Context, bool) error) ModelOption {
	return func(c *modelConfig) { c.vaultControl = control }
}

type vaultControlResult struct{ err error }

type vaultControlCommand struct{ run func() error }

func (c *vaultControlCommand) Run() error        { return c.run() }
func (*vaultControlCommand) SetStdin(io.Reader)  {}
func (*vaultControlCommand) SetStdout(io.Writer) {}
func (*vaultControlCommand) SetStderr(io.Writer) {}

func (m *Model) vaultCommand(unlock bool) tea.Cmd {
	run := func() error { return m.runVaultControl(unlock) }
	if unlock {
		return tea.Exec(&vaultControlCommand{run: run}, func(err error) tea.Msg { return vaultControlResult{err} })
	}
	return func() tea.Msg { return vaultControlResult{run()} }
}

func (m *Model) runVaultControl(unlock bool) error {
	ctx := m.ctx
	if unlock {
		ctx = m.terminalContext
	}
	return m.vaultControl(ctx, unlock)
}

func (m *Model) handleVaultMessage(msg tea.Msg) (bool, tea.Cmd) {
	if result, ok := msg.(vaultControlResult); ok {
		m.status = "Vault action completed"
		if result.err != nil {
			m.status = "Vault action failed: " + result.err.Error()
		}
		return true, nil
	}
	if key, ok := msg.(tea.KeyMsg); ok && m.state == viewList && m.vaultControl != nil {
		switch key.String() {
		case "ctrl+l":
			return true, m.vaultCommand(false)
		case "ctrl+u":
			return true, m.vaultCommand(true)
		}
	}
	return false, nil
}
