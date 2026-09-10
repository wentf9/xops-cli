package tui

import (
	"context"
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestVaultControlLockAndFailure(t *testing.T) {
	want := errors.New("public lock failure")
	calls := 0
	m, err := NewModel(newTestRepository(t, &config.Configuration{}), WithContext(t.Context()), WithVaultControl(func(ctx context.Context, unlock bool) error {
		calls++
		if unlock {
			t.Error("lock requested unlock")
		}
		if ctx == nil {
			t.Error("missing lifecycle context")
		}
		return want
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlL})
	if cmd == nil || calls != 0 {
		t.Fatal("control not deferred")
	}
	result, ok := cmd().(vaultControlResult)
	if !ok || !errors.Is(result.err, want) || calls != 1 {
		t.Fatal("lock result", result)
	}
	m.Update(result)
	if m.status == "" {
		t.Fatal("no lock result status")
	}
}
