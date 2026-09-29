package tui

import (
	"errors"
	"fmt"
	"image/color"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func TestTagFormExistingTagsVisibleOnOpen(t *testing.T) {
	for _, tc := range []struct {
		name       string
		background color.Color
	}{
		{name: "no background response"},
		{name: "light background", background: color.White},
		{name: "dark background", background: color.Black},
	} {
		for _, tags := range [][]string{{"prod"}, {"prod", "staging"}} {
			t.Run(tc.name+"/"+strings.Join(tags, ","), func(t *testing.T) {
				m := newTagFormTestModel(t, tags...)
				if tc.background != nil {
					m.Update(tea.BackgroundColorMsg{Color: tc.background})
				}
				m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
				_, cmd := m.Update(tea.KeyPressMsg{Code: 'g', Text: "g"})
				if m.state != viewTagSelect || m.tagForm == nil {
					t.Fatal("tag form did not open")
				}
				// No extra navigation or terminal reply should be needed to reveal
				// the options on the first frame.
				view := ansi.Strip(m.View().Content)
				for _, tag := range tags {
					if !strings.Contains(view, tag) {
						t.Errorf("existing tag %q is hidden on entry:\n%s", tag, view)
					}
				}
				if cmd == nil {
					t.Error("tag form initialization command was discarded")
				}
			})
		}
	}
}

func newTagFormTestModel(t *testing.T, tags ...string) *Model {
	t.Helper()
	cfg := newFormCredentialTestConfiguration("")
	node, _ := cfg.Nodes.Get(formCredentialTestNodeID)
	node.Tags = tags
	cfg.Nodes.Set(formCredentialTestNodeID, node)
	m, err := NewModel(newTestRepository(t, cfg), WithContext(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTUITestResource(t, &m) })
	m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	return &m
}

func TestTagFormResizeKeepsFocusedInputVisible(t *testing.T) {
	m := newTagColorTestModel(t)
	m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m.Update(tea.KeyPressMsg{Code: 'g', Text: "g"})
	m.Update(huh.NextField())
	m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m.Update(huh.NextField())
	m.Update(tea.PasteMsg{Content: "draft-tag"})
	field := m.tagForm.GetFocusedField()
	for _, size := range []tea.WindowSizeMsg{
		{Width: 40, Height: 8},
		{Width: 80, Height: 24},
		{Width: 100, Height: 30},
	} {
		m.Update(size)
		view := m.View().Content
		if lipgloss.Width(view) > size.Width || lipgloss.Height(view) > size.Height {
			t.Errorf("tag form exceeds %dx%d terminal:\n%s", size.Width, size.Height, view)
		}
		if !strings.Contains(ansi.Strip(m.tagForm.View()), "> draft-tag") {
			t.Errorf("focused tag input is hidden after resize:\n%s", view)
		}
		if m.tagForm.GetFocusedField() != field || m.newTagsInput != "draft-tag" || len(m.selectedTags) != 1 {
			t.Fatal("resize changed the tag draft or focus")
		}
	}
}

func TestTagFormManyTagsRemainSelectable(t *testing.T) {
	tags := make([]string, 30)
	for i := range tags {
		tags[i] = fmt.Sprintf("tag-%02d", i)
	}
	m := newTagFormTestModel(t, tags...)
	m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m.Update(tea.KeyPressMsg{Code: 'g', Text: "g"})
	m.Update(huh.NextField())
	field, ok := m.tagForm.GetFocusedField().(*huh.MultiSelect[string])
	if !ok {
		t.Fatal("tag selector is not focused")
	}
	for _, size := range []tea.WindowSizeMsg{{Width: 40, Height: 8}, {Width: 80, Height: 24}} {
		m.Update(size)
		for _, key := range []rune{tea.KeyEnd, tea.KeyHome} {
			m.Update(tea.KeyPressMsg{Code: key})
			tag, ok := field.Hovered()
			view := m.View().Content
			if !ok || !strings.Contains(ansi.Strip(view), tag) {
				t.Fatalf("hovered tag %q is hidden:\n%s", tag, view)
			}
			if lipgloss.Width(view) > size.Width || lipgloss.Height(view) > size.Height {
				t.Fatalf("tag form %dx%d exceeds %dx%d terminal:\n%s", lipgloss.Width(view), lipgloss.Height(view), size.Width, size.Height, ansi.Strip(view))
			}
			m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
			if len(m.selectedTags) != 1 || m.selectedTags[0] != tag {
				t.Fatalf("selected tags = %v, want %q", m.selectedTags, tag)
			}
			m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
		}
	}
}

func TestTagFormWithoutExistingTags(t *testing.T) {
	m := newTagFormTestModel(t)
	m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m.Update(tea.KeyPressMsg{Code: 'g', Text: "g"})
	view := ansi.Strip(m.View().Content)
	if strings.Contains(view, i18n.T("tui_tag_select")) || !strings.Contains(view, i18n.T("tui_tag_input")) {
		t.Fatalf("empty inventory should offer tag entry:\n%s", view)
	}
	m.Update(huh.NextField())
	m.Update(tea.PasteMsg{Content: "new-tag"})
	completeConfigurationMutation(t, m, m.applyTagChangesCmd())
	node, ok := m.repository.GetNode(formCredentialTestNodeID)
	if !ok || len(node.Tags) != 1 || node.Tags[0] != "new-tag" {
		t.Fatal("new tag was not saved")
	}
}

func TestTagFormRebuildAfterFailureKeepsDraft(t *testing.T) {
	m := newTagFormTestModel(t, "prod")
	m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m.Update(tea.KeyPressMsg{Code: 'g', Text: "g"})
	m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	m.Update(huh.NextField())
	m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m.Update(huh.NextField())
	m.Update(tea.PasteMsg{Content: "draft-tag"})
	m.tagForm.State = huh.StateCompleted
	m.mutation = newConfigurationMutation(1)
	m.mutationPending = true
	_, cmd := m.Update(configurationMutationMsg{id: 1, kind: configurationMutationTags, err: errors.New("write failed")})
	if cmd == nil || m.state != viewTagSelect || m.tagForm.State != huh.StateNormal || m.mutationPending {
		t.Fatal("failed tag save did not reopen the form")
	}
	if m.tagMode != "remove" || m.newTagsInput != "draft-tag" || len(m.selectedTags) != 1 || m.selectedTags[0] != "prod" {
		t.Fatal("failed tag save discarded the draft")
	}
	view := ansi.Strip(m.tagForm.View())
	if !strings.Contains(view, "✓ prod") || !strings.Contains(view, "> draft-tag") {
		t.Fatalf("rebuilt form hides the tag draft:\n%s", view)
	}
}
