package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
)

// Keep initialized translations out of tests that intentionally use i18n's
// uninitialized message-ID fallback.
func localizedFormTestProcess(t *testing.T) bool {
	t.Helper()
	const flag = "XOPS_LOCALIZED_FORM_TEST"
	if os.Getenv(flag) == t.Name() {
		return true
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), flag+"="+t.Name())
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("localized form test: %v\n%s", err, output)
	}
	return false
}

func TestFormLongFeedbackKeepsInputVisible(t *testing.T) {
	if !localizedFormTestProcess(t) {
		return
	}
	for _, lang := range []string{"en", "zh"} {
		t.Run(lang, func(t *testing.T) {
			if err := i18n.Init(lang); err != nil {
				t.Fatal(err)
			}
			m := newV2TestModel(t)
			m.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
			m.Update(tea.KeyPressMsg{Code: 'e', Text: "e"})
			alias := strings.Repeat("a", 170)
			replaceFormAlias(m, alias+","+alias)
			revision := m.repository.Revision()
			m.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
			if m.status == "" || m.mutationPending || m.repository.Revision() != revision {
				t.Fatal("duplicate alias was not rejected")
			}
			assertFormInputVisible(t, m, "aaaa")
			if !strings.Contains(ansi.Strip(m.formFooter()), "…") {
				t.Fatal("long feedback has no truncation indicator")
			}
			replaceFormAlias(m, "corrected")
			assertFormInputVisible(t, m, "corrected")
			m.Update(tickMsg{generation: m.statusGeneration})
			assertFormInputVisible(t, m, "corrected")
			for _, height := range []int{9, 8, 6, 12} {
				m.Update(tea.WindowSizeMsg{Width: 40, Height: height})
				assertFormInputVisible(t, m, "corrected")
			}
			// Expanding restores the full message without discarding the draft.
			m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
			assertFormStatusVisible(t, m)
			assertFormInputVisible(t, m, "corrected")
			m.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
			assertFormInputVisible(t, m, "corrected")
			_, cmd := m.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
			completeConfigurationMutation(t, m, cmd)
			if m.state != viewList || m.repository.FindAlias("corrected") != formCredentialTestNodeID {
				t.Fatal("corrected alias was not saved")
			}
		})
	}
}

func TestFormLongConfirmationKeepsAnswerVisible(t *testing.T) {
	m := newV2TestModel(t)
	m.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
	m.Update(tea.KeyPressMsg{Code: 'e', Text: "e"})
	replaceFormAlias(m, "draft")
	m.formVerifyErr = errors.New("verification failed")
	m.status = errorStyle.Render("Verification failed: " + strings.Repeat("details ", 60) + "\nSave anyway? [y/N]")
	m.Update(m.lastSize)
	assertFormInputVisible(t, m, "draft")
	foot := ansi.Strip(m.formFooter())
	for _, want := range []string{"Verification failed:", "…", "Save anyway? [y/N]"} {
		if !strings.Contains(foot, want) {
			t.Fatalf("bounded confirmation does not contain %q:\n%s", want, foot)
		}
	}
}

func TestFormTagsRemainVisibleAfterFooterResize(t *testing.T) {
	m := newV2TestModel(t)
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m.Update(tea.KeyPressMsg{Code: 'e', Text: "e"})
	for range 20 {
		if m.form.GetFocusedField().GetValue() == "prod" {
			break
		}
		m.Update(huh.NextField())
	}
	if m.form.GetFocusedField().GetValue() != "prod" {
		t.Fatal("did not reach the final Tags field")
	}
	replaceFormAlias(m, "draft-tag,draft-tag")
	assertFormInputVisible(t, m, "> draft-tag,draft-tag")
	m.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
	if m.status == "" || m.mutationPending {
		t.Fatal("duplicate tags were not rejected")
	}
	// No additional Huh message may be required to reveal the focused input.
	assertFormInputVisible(t, m, "> draft-tag,draft-tag")
	for _, size := range []tea.WindowSizeMsg{{Width: 40, Height: 12}, {Width: 80, Height: 24}} {
		m.Update(size)
		assertFormInputVisible(t, m, "> draft-tag,draft-tag")
	}
	replaceFormAlias(m, "corrected-tag")
	_, cmd := m.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
	completeConfigurationMutation(t, m, cmd)
	node, ok := m.repository.GetNode(formCredentialTestNodeID)
	if !ok || len(node.Tags) != 1 || node.Tags[0] != "corrected-tag" {
		t.Fatal("corrected tags were not saved")
	}
}

func TestFormTabValidationKeepsInputVisible(t *testing.T) {
	if !localizedFormTestProcess(t) {
		return
	}
	for _, lang := range []string{"en", "zh"} {
		t.Run(lang, func(t *testing.T) {
			if err := i18n.Init(lang); err != nil {
				t.Fatal(err)
			}
			m := newV2TestModel(t)
			m.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
			m.Update(tea.KeyPressMsg{Code: 'e', Text: "e"})
			alias := strings.Repeat("a", 240)
			replaceFormAlias(m, alias+","+alias)
			field := m.form.GetFocusedField()
			m.Update(tea.KeyPressMsg{Code: tea.KeyTab})
			if len(m.form.Errors()) != 1 || m.form.GetFocusedField() != field {
				t.Fatal("Tab did not keep the invalid field focused")
			}
			assertFormInputVisible(t, m, "> aaaa")
			if !strings.Contains(ansi.Strip(m.formFooter()), "…") {
				t.Fatal("long field validation error has no truncation indicator")
			}
			m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
			want := i18n.Tf("alias_err_duplicate_input", map[string]any{"Alias": alias})
			compact := func(s string) string { return strings.Join(strings.Fields(ansi.Strip(s)), "") }
			if !strings.Contains(compact(m.formFooter()), compact(want)) {
				t.Fatal("expanded footer does not contain the full field error")
			}
			m.Update(tea.WindowSizeMsg{Width: 40, Height: 12})
			replaceFormAlias(m, "corrected")
			assertFormInputVisible(t, m, "> corrected")
			_, next := m.Update(tea.KeyPressMsg{Code: tea.KeyTab})
			if next == nil {
				t.Fatal("corrected field cannot advance")
			}
			m.Update(next())
			if len(m.form.Errors()) != 0 || m.form.GetFocusedField() == field {
				t.Fatal("field validation did not recover after correction")
			}
			_, save := m.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
			completeConfigurationMutation(t, m, save)
			if m.repository.FindAlias("corrected") != formCredentialTestNodeID {
				t.Fatal("corrected alias was not saved")
			}
		})
	}
}

func assertFormInputVisible(t *testing.T, m *Model, value string) {
	t.Helper()
	view := m.View().Content
	if lipgloss.Height(view) > m.lastSize.Height || lipgloss.Width(view) > m.lastSize.Width {
		t.Fatalf("form exceeds terminal dimensions:\n%s", view)
	}
	// Inspect the form viewport, not the field or status, which can contain
	// the value even when the editable line has been clipped from the screen.
	if !strings.Contains(ansi.Strip(m.form.View()), value) {
		t.Fatalf("editable value %q is hidden:\n%s", value, view)
	}
}

func newAliasConflictTestModel(t *testing.T) *Model {
	t.Helper()
	m := newV2TestModel(t)
	_, err := m.repository.CreateNodeContext(t.Context(), "other@192.0.2.2:22",
		models.Node{HostRef: "192.0.2.2:22", IdentityRef: "other@192.0.2.2", Alias: []string{"taken"}},
		models.Host{Address: "192.0.2.2", Port: 22}, models.Identity{User: "other"})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func replaceFormAlias(m *Model, alias string) {
	m.Update(tea.KeyPressMsg{Code: 'a', Mod: tea.ModCtrl})
	m.Update(tea.KeyPressMsg{Code: 'k', Mod: tea.ModCtrl})
	m.Update(tea.PasteMsg{Content: alias})
}

func assertFormStatusVisible(t *testing.T, m *Model) {
	t.Helper()
	view := m.View().Content
	if height := lipgloss.Height(view); height > m.lastSize.Height {
		t.Fatalf("form occupies %d rows in a %d-row terminal; status is clipped:\n%s", height, m.lastSize.Height, view)
	}
	if width := lipgloss.Width(view); width > m.lastSize.Width {
		t.Fatalf("form occupies %d columns in a %d-column terminal", width, m.lastSize.Width)
	}
	// Ignore wrapping and padding while checking that the complete message is present.
	compact := func(s string) string { return strings.Join(strings.Fields(ansi.Strip(s)), "") }
	if m.status == "" || !strings.Contains(compact(view), compact(m.status)) {
		t.Fatalf("form does not display status %q:\n%s", m.status, view)
	}
}

func TestFormAliasConflictVisibleAndCorrectable(t *testing.T) {
	for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 24}, {Width: 40, Height: 12}, {Width: 120, Height: 40}} {
		t.Run(fmt.Sprintf("%dx%d", size.Width, size.Height), func(t *testing.T) {
			m := newAliasConflictTestModel(t)
			m.Update(size)
			m.state = viewForm
			m.initForm(formCredentialTestNodeID)
			revision := m.repository.Revision()
			replaceFormAlias(m, "taken")
			m.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
			if m.state != viewForm || m.mutationPending || m.repository.Revision() != revision {
				t.Fatal("invalid alias changed the repository or left the editor")
			}
			want := i18n.Tf("alias_err_exists", map[string]any{"Alias": "taken", "Node": "other@192.0.2.2:22"})
			if !strings.Contains(ansi.Strip(m.status), want) {
				t.Fatalf("status = %q, want alias conflict %q", m.status, want)
			}
			assertFormStatusVisible(t, m)
			m.Update(tickMsg{generation: m.statusGeneration})
			assertFormStatusVisible(t, m)
			replaceFormAlias(m, "corrected")
			_, cmd := m.Update(tea.KeyPressMsg{Code: 's', Mod: tea.ModCtrl})
			completeConfigurationMutation(t, m, cmd)
			if m.state != viewList || m.repository.FindAlias("corrected") != formCredentialTestNodeID {
				t.Fatal("corrected alias was not saved")
			}
			if m.repository.FindAlias("taken") != "other@192.0.2.2:22" {
				t.Fatal("saving changed the other node's alias")
			}
			// Reopening starts with fresh feedback and permits keeping this node's alias.
			m.formState = nil
			m.state = viewForm
			m.initForm(formCredentialTestNodeID)
			if m.status != "" {
				t.Fatalf("reopened editor retained stale status: %q", m.status)
			}
			if err := m.validateFormState(); err != nil {
				t.Fatalf("existing node cannot retain its own alias: %v", err)
			}
		})
	}
}

func TestFormAsyncSaveErrorRemainsVisible(t *testing.T) {
	for _, saveErr := range []error{errors.New("write failed"), config.ErrConfigConflict} {
		t.Run(saveErr.Error(), func(t *testing.T) {
			m := newV2TestModel(t)
			m.Update(tea.KeyPressMsg{Code: 'e', Text: "e"})
			replaceFormAlias(m, "draft")
			cmd := m.beginConfigurationMutation(configurationMutationForm, formCredentialTestNodeID, 0,
				func(context.Context) error { return saveErr })
			m.Update(cmd())
			if m.state != viewForm || m.formState.alias != "draft" || m.mutationPending {
				t.Fatal("save error did not retain the editable draft")
			}
			assertFormStatusVisible(t, m)
			m.Update(tickMsg{generation: m.statusGeneration})
			assertFormStatusVisible(t, m)
		})
	}
}

func TestFormStatusLayoutAfterResize(t *testing.T) {
	for _, phase := range []string{"validation", "saving", "verification"} {
		t.Run(phase, func(t *testing.T) {
			m := newV2TestModel(t)
			m.Update(tea.KeyPressMsg{Code: 'e', Text: "e"})
			m.status = errorStyle.Render("别名已被其他节点占用，请修改后重试。\n" + strings.Repeat("long-alias-", 6))
			m.mutationPending = phase == "saving"
			if phase == "verification" {
				m.formVerifyErr = errors.New("verification failed")
			}
			for _, size := range []tea.WindowSizeMsg{{Width: 80, Height: 24}, {Width: 40, Height: 12}, {Width: 100, Height: 30}} {
				m.Update(size)
				assertFormStatusVisible(t, m)
			}
		})
	}
}
