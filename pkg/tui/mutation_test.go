package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestConfigurationMutationCmdPropagatesParentCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := configurationMutationCmd(parent, newConfigurationMutation(1), configurationMutationForm, "node", 0, func(ctx context.Context) error {
		return ctx.Err()
	})

	message := cmd()
	msg, ok := message.(configurationMutationMsg)
	if !ok {
		t.Fatalf("command message = %T, want configurationMutationMsg", message)
	}
	if !errors.Is(msg.err, context.Canceled) {
		t.Fatalf("mutation error = %v, want context.Canceled", msg.err)
	}
}

func TestBeginConfigurationMutationPreventsOverlappingWrites(t *testing.T) {
	m := Model{}
	first := m.beginConfigurationMutation(configurationMutationForm, "node", 0, func(context.Context) error { return nil })
	if first == nil {
		t.Fatal("first mutation command is nil")
	}
	if !m.mutationPending {
		t.Fatal("first mutation did not mark the model pending")
	}
	if second := m.beginConfigurationMutation(configurationMutationDelete, "", 1, func(context.Context) error { return nil }); second != nil {
		t.Fatal("overlapping mutation command was accepted")
	}
}

func TestPendingConfigurationMutationBlocksFormNavigation(t *testing.T) {
	m := Model{
		state:           viewForm,
		mutationPending: true,
		formState:       &nodeFormState{originalID: "node"},
	}
	updated, cmd := m.updateForm(tea.KeyMsg{Type: tea.KeyEscape})
	if cmd != nil {
		t.Fatal("updateForm() returned a command while mutation is pending")
	}
	if updated.state != viewForm {
		t.Fatalf("state = %v, want form state while mutation is pending", updated.state)
	}
}

func TestConfigurationConflictRequiresExplicitReload(t *testing.T) {
	repository := newTestRepository(t, &config.Configuration{})
	m, err := NewModel(repository)
	if err != nil {
		t.Fatalf("NewModel() error = %v", err)
	}
	m.state = viewForm
	m.formState = &nodeFormState{alias: "draft"}
	m.formConflict = true

	updated, cmd := m.updateForm(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatal("updateForm() returned a command before explicit reload")
	}
	if updated.formState.alias != "draft" || !updated.formConflict {
		t.Fatalf("draft or conflict state changed before reload: %#v, conflict=%v", updated.formState, updated.formConflict)
	}

	updated, _ = updated.updateForm(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	if updated.formConflict {
		t.Fatal("explicit reload did not clear conflict state")
	}
	if updated.formState.alias == "draft" {
		t.Fatal("explicit reload retained stale draft")
	}
}

func TestHandleConfigurationMutationClassifiesTerminalErrors(t *testing.T) {
	repository := newTestRepository(t, &config.Configuration{})
	base, err := NewModel(repository)
	if err != nil {
		t.Fatalf("NewModel() error = %v", err)
	}
	base.lastSize = tea.WindowSizeMsg{Width: 80, Height: 24}

	tests := []struct {
		name      string
		err       error
		wantState viewState
		wantText  string
	}{
		{name: "conflict", err: config.ErrConfigConflict, wantState: viewForm, wantText: "tui_status_conflict"},
		{name: "canceled", err: context.Canceled, wantState: viewForm, wantText: "canceled"},
		{name: "durability", err: &config.DurabilityError{Err: errors.New("sync directory")}, wantState: viewList, wantText: "tui_status_not_durable"},
		{name: "ordinary failure", err: errors.New("write failed"), wantState: viewForm, wantText: "failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := base
			m.state = viewForm
			m.mutationPending = true
			m.mutation = newConfigurationMutation(1)
			updated, _ := m.handleConfigurationMutation(configurationMutationMsg{id: 1, kind: configurationMutationForm, err: tt.err})
			result, ok := updated.(*Model)
			if !ok {
				t.Fatalf("handleConfigurationMutation() model = %T, want *Model", updated)
			}
			if result.mutationPending {
				t.Fatal("terminal mutation result left the model pending")
			}
			if result.state != tt.wantState {
				t.Fatalf("state = %v, want %v", result.state, tt.wantState)
			}
			if !strings.Contains(result.status, tt.wantText) {
				t.Fatalf("status = %q, want text %q", result.status, tt.wantText)
			}
		})
	}
}

func TestModelCloseCancelsAndWaitsForConfigurationMutation(t *testing.T) {
	m, err := NewModel(newTestRepository(t, &config.Configuration{}), WithContext(t.Context()))
	if err != nil {
		t.Fatalf("NewModel() error = %v", err)
	}
	started := make(chan struct{})
	cmd := m.beginConfigurationMutation(configurationMutationForm, "node", 0, func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	result := make(chan tea.Msg, 1)
	go func() { result <- cmd() }()
	<-started
	if err := m.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	msg := <-result
	mutationMsg, ok := msg.(configurationMutationMsg)
	if !ok {
		t.Fatalf("command message = %T, want configurationMutationMsg", msg)
	}
	if !errors.Is(mutationMsg.err, context.Canceled) {
		t.Fatalf("mutation error = %v, want context.Canceled", mutationMsg.err)
	}
}
