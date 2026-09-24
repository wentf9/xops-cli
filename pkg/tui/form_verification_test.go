package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func TestFormVerificationConfirmationInSmallTerminal(t *testing.T) {
	if !localizedFormTestProcess(t) {
		return
	}
	for _, submit := range []string{"enter", "ctrl+s"} {
		for _, answer := range []string{"y", "n"} {
			t.Run(submit+"/"+answer, func(t *testing.T) {
				if err := i18n.Init("en"); err != nil {
					t.Fatal(err)
				}
				m := newVerificationLayoutTestModel(t)
				key := tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl}
				if submit == "enter" {
					key = tea.KeyPressMsg{Code: tea.KeyEnter}
				}
				_, cmd := m.Update(key)
				cmd = advanceFormSubmission(t, m, cmd)
				m.Update(cmd())
				if m.formVerifyErr == nil {
					t.Fatal("verification did not request confirmation")
				}
				for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 8}, {Width: 40, Height: 8}, {Width: 100, Height: 30}} {
					m.Update(size)
					view := m.View().Content
					if lipgloss.Height(view) > size.Height || lipgloss.Width(view) > size.Width {
						t.Fatalf("confirmation exceeds terminal dimensions:\n%s", view)
					}
					plain := ansi.Strip(view)
					if !strings.Contains(plain, "[y/N]") || strings.Contains(plain, "ctrl+s:") || strings.Contains(plain, "enter submit") {
						t.Fatalf("confirmation is missing or displays inactive save help:\n%s", plain)
					}
				}
				_, save := m.Update(tea.KeyPressMsg{Code: rune(answer[0]), Text: answer})
				if answer == "y" {
					completeConfigurationMutation(t, m, save)
					if m.repository.Snapshot().Nodes.Count() != 1 {
						t.Fatal("confirmed node was not saved")
					}
				} else if m.repository.Snapshot().Nodes.Count() != 0 || m.form.State != huh.StateNormal || m.formState.user != "root" {
					t.Fatal("decline did not preserve the unsaved draft")
				}
			})
		}
	}
}

func newVerificationLayoutTestModel(t *testing.T) *Model {
	t.Helper()
	m := &Model{repository: newTestRepository(t, nil), ctx: t.Context(), state: viewForm,
		lastSize:  tea.WindowSizeMsg{Width: 80, Height: 8},
		formState: &nodeFormState{user: "root", address: "192.0.2.1", port: "22", authType: "password"},
	}
	m.connectionConfig.verifyConnection = func(context.Context, *config.Provider, string, adapter.CredentialResolver) error {
		return errors.New("SSH refused: " + strings.Repeat("connection detail ", 30))
	}
	t.Cleanup(func() { closeTUITestResource(t, m) })
	m.initForm("")
	for range 20 {
		if _, ok := m.form.GetFocusedField().GetValue().(bool); ok {
			return m
		}
		m.Update(huh.NextField())
	}
	t.Fatal("did not reach the final verification field")
	return nil
}

// Run Huh's field/group navigation commands until submission produces the
// asynchronous verification command, without executing the verification yet.
func advanceFormSubmission(t *testing.T, m *Model, cmd tea.Cmd) tea.Cmd {
	t.Helper()
	queue := []tea.Cmd{cmd}
	for steps := 0; len(queue) > 0 && steps < 30; steps++ {
		current := queue[0]
		queue = queue[1:]
		if current == nil {
			continue
		}
		if m.mutationPending {
			return current
		}
		msg := current()
		if batch, ok := msg.(tea.BatchMsg); ok {
			queue = append(queue, batch...)
			continue
		}
		_, next := m.Update(msg)
		queue = append(queue, next)
	}
	t.Fatal("submission did not start verification")
	return nil
}

func TestNewNodeFormVerificationPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, answer string
		verifyErr    error
		skip, saved  bool
	}{
		{name: "verified", saved: true},
		{name: "skip", skip: true, saved: true},
		{name: "failed_no", verifyErr: errors.New("refused"), answer: "n"},
		{name: "failed_default_no", verifyErr: errors.New("refused"), answer: "enter"},
		{name: "failed_escape", verifyErr: errors.New("refused"), answer: "esc"},
		{name: "failed_yes", verifyErr: errors.New("refused"), answer: "y", saved: true},
		{name: "timeout_yes", verifyErr: context.DeadlineExceeded, answer: "y", saved: true},
		{name: "canceled", verifyErr: context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newTestRepository(t, nil)
			m := &Model{repository: repo, ctx: t.Context(), state: viewForm,
				lastSize:  tea.WindowSizeMsg{Width: 100, Height: 30},
				formState: &nodeFormState{user: "root", address: "192.0.2.1", port: "2222", authType: "password", password: "draft-secret", skipVerify: tc.skip},
			}
			calls := 0
			m.connectionConfig.verifyConnection = func(_ context.Context, preview *config.Provider, id string, _ adapter.CredentialResolver) error {
				calls++
				if repo.Snapshot().Nodes.Count() != 0 {
					t.Error("form saved before verification")
				}
				_, host, identity, err := preview.Resolve(id)
				if err != nil || host.Port != 2222 || identity.Password != "draft-secret" {
					t.Errorf("invalid connection preview: %v", err)
				}
				return tc.verifyErr
			}
			cmd := m.saveFormCmd()
			if cmd == nil {
				t.Fatal("missing form command")
			}
			_, next := m.Update(cmd())
			if !tc.skip && tc.verifyErr == nil {
				if next == nil {
					t.Fatal("verified node did not proceed to save")
				}
				m.Update(next())
			} else if tc.answer != "" {
				assertFormVerificationPrompt(t, m)
				key := tea.KeyPressMsg{Code: []rune(tc.answer)[0], Text: tc.answer}
				if tc.answer == "enter" {
					key = tea.KeyPressMsg{Code: tea.KeyEnter}
				}
				if tc.answer == "esc" {
					key = tea.KeyPressMsg{Code: tea.KeyEscape}
				}
				_, save := m.updateVerificationConfirmation(key)
				if tc.saved {
					if save == nil {
						t.Fatal("confirmation did not start saving")
					}
					m.Update(save())
				}
			}
			if (repo.Snapshot().Nodes.Count() == 1) != tc.saved {
				t.Fatalf("saved nodes = %d, expected saved=%v", repo.Snapshot().Nodes.Count(), tc.saved)
			}
			if (calls == 0) != tc.skip {
				t.Fatalf("verification calls = %d", calls)
			}
		})
	}
}

func assertFormVerificationPrompt(t *testing.T, m *Model) {
	t.Helper()
	if m.repository.Snapshot().Nodes.Count() != 0 || m.formVerifyErr == nil || !strings.Contains(m.status, "[y/N]") {
		t.Fatalf("failure did not request confirmation without saving: %s", m.status)
	}
	before := m.status
	m.Update(tickMsg{generation: m.statusGeneration})
	if m.status != before {
		t.Fatal("confirmation disappeared while waiting for input")
	}
}
