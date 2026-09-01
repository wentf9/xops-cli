package tui

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
	fileutil "github.com/wentf9/xops-cli/pkg/utils/file"
)

type nodeFormState struct {
	isEdit     bool
	originalID string
	revision   uint64
	ref        config.NodeRef

	alias      string
	user       string
	address    string
	port       string
	authType   string
	password   string
	keyPath    string
	passphrase string
	sudoMode   string
	tags       string
}

func (m *Model) initForm(nodeID string) (Model, tea.Cmd) {
	state := m.formState
	if state == nil {
		var err error
		state, err = m.newNodeFormState(nodeID)
		if err != nil {
			m.status = errorStyle.Render(err.Error())
			m.state = viewList
			return *m, nil
		}
		m.formState = state
	}

	// 自定义快捷键以支持 Up/Down 切换
	km := huh.NewDefaultKeyMap()
	km.Input.Next = key.NewBinding(
		key.WithKeys("tab", "down"),
		key.WithHelp("tab/down", "next"),
	)
	km.Input.Prev = key.NewBinding(
		key.WithKeys("shift+tab", "up"),
		key.WithHelp("shift+tab/up", "prev"),
	)

	// 解绑 Select 字段的 Up/Down，改用横向 Left/Right 切换选项，并将上下键绑定到切换字段
	km.Select.Next = key.NewBinding(
		key.WithKeys("tab", "down"),
		key.WithHelp("tab/down", "next"),
	)
	km.Select.Prev = key.NewBinding(
		key.WithKeys("shift+tab", "up"),
		key.WithHelp("shift+tab/up", "prev"),
	)
	km.Select.Up = key.NewBinding()
	km.Select.Down = key.NewBinding()

	// 计算合理高度（保留 3 行用于底部状态和 help 说明）
	formHeight := max(m.lastSize.Height-3, 1)

	m.form = huh.NewForm(
		huh.NewGroup(
			// 基本信息
			huh.NewInput().
				Title(i18n.T("tui_form_alias")).
				Value(&state.alias).
				Validate(m.validateAliases),
			huh.NewInput().
				Title(i18n.T("tui_form_user")).
				Value(&state.user).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return errors.New(i18n.T("tui_validation_user_required"))
					}
					return nil
				}),
			huh.NewInput().
				Title(i18n.T("tui_form_address")).
				Value(&state.address).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return errors.New(i18n.T("tui_validation_address_required"))
					}
					return nil
				}),
			huh.NewInput().
				Title(i18n.T("tui_form_port")).
				Value(&state.port).
				Validate(func(s string) error {
					if _, err := strconv.Atoi(s); err != nil {
						return errors.New(i18n.T("tui_validation_port_invalid"))
					}
					return nil
				}),
			// 认证信息
			huh.NewSelect[string]().
				Title(i18n.T("tui_form_auth_type")).
				Options(
					huh.NewOption("Password", "password"),
					huh.NewOption("Key File", "key"),
				).
				Value(&state.authType).
				Inline(true),
			huh.NewInput().
				Title(i18n.T("tui_form_password")).
				EchoMode(huh.EchoModePassword).
				Value(&state.password),
			huh.NewInput().
				Title(i18n.T("tui_form_key_path")).
				Value(&state.keyPath),
			huh.NewInput().
				Title(i18n.T("tui_form_key_pass")).
				EchoMode(huh.EchoModePassword).
				Value(&state.passphrase),
			// 其他设置
			huh.NewSelect[string]().
				Title(i18n.T("tui_form_sudo_mode")).
				Options(
					huh.NewOption("Auto", string(models.SudoModeAuto)),
					huh.NewOption("Sudo", string(models.SudoModeSudo)),
					huh.NewOption("Su", string(models.SudoModeSu)),
					huh.NewOption("Sudoer", string(models.SudoModeSudoer)),
					huh.NewOption("Root", string(models.SudoModeRoot)),
					huh.NewOption("None", string(models.SudoModeNone)),
				).
				Value(&state.sudoMode).
				Inline(true),
			huh.NewInput().
				Title(i18n.T("tui_form_tags")).
				Value(&state.tags).
				Validate(m.validateTags),
		),
	).WithTheme(huh.ThemeCharm()).
		WithKeyMap(km).
		WithWidth(m.lastSize.Width).
		WithHeight(formHeight)

	cmd := m.form.Init()
	return *m, cmd
}

func (m *Model) newNodeFormState(nodeID string) (*nodeFormState, error) {
	view := m.repository.View()
	state := &nodeFormState{
		port:     "22",
		authType: "password",
		sudoMode: string(models.SudoModeAuto),
		revision: view.Revision,
	}

	if nodeID == "" {
		return state, nil
	}

	state.isEdit = true
	state.originalID = nodeID
	state.ref = view.NodeRefs[nodeID]
	node, ok := view.Configuration.Nodes.Get(nodeID)
	if !ok {
		return nil, fmt.Errorf("resolve node %q for editing: %w", nodeID, config.ErrNodeNotFound)
	}
	host, ok := view.Configuration.Hosts.Get(node.HostRef)
	if !ok {
		return nil, fmt.Errorf("resolve node %q host %q for editing: %w", nodeID, node.HostRef, config.ErrHostNotFound)
	}
	identity, ok := view.Configuration.Identities.Get(node.IdentityRef)
	if !ok {
		return nil, fmt.Errorf("resolve node %q identity %q for editing: %w", nodeID, node.IdentityRef, config.ErrIdentityNotFound)
	}

	if len(node.Alias) > 0 {
		state.alias = strings.Join(node.Alias, ",")
	}
	state.user = identity.User
	state.address = host.Address
	state.port = strconv.Itoa(int(host.Port))
	if identity.AuthType != "" {
		state.authType = identity.AuthType
	} else if identity.KeyPath != "" {
		state.authType = "key"
	}
	state.password = identity.Password
	state.keyPath = identity.KeyPath
	state.passphrase = identity.Passphrase
	state.sudoMode = string(node.SudoMode)
	if state.sudoMode == "" {
		state.sudoMode = string(models.SudoModeAuto)
	}
	state.tags = strings.Join(node.Tags, ",")
	return state, nil
}

func (m *Model) validateAliases(s string) error {
	if s == "" {
		return nil
	}
	seen := make(map[string]bool)
	for a := range strings.SplitSeq(s, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if seen[a] {
			return errors.New(i18n.Tf("alias_err_duplicate_input", map[string]any{"Alias": a}))
		}
		seen[a] = true

		if existingNode := m.repository.FindAlias(a); existingNode != "" {
			if m.formState.isEdit && existingNode == m.formState.originalID {
				continue
			}
			return errors.New(i18n.Tf("alias_err_exists", map[string]any{"Alias": a, "Node": existingNode}))
		}
	}
	return nil
}

func (m *Model) validateTags(s string) error {
	if s == "" {
		return nil
	}
	seen := make(map[string]bool)
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if seen[t] {
			return errors.New(i18n.Tf("tag_err_duplicate_input", map[string]any{"Tag": t}))
		}
		seen[t] = true
	}
	return nil
}

func (m *Model) validateFormState() error {
	s := m.formState
	if err := m.validateAliases(s.alias); err != nil {
		return err
	}
	if strings.TrimSpace(s.user) == "" {
		return errors.New(i18n.T("tui_validation_user_required"))
	}
	if strings.TrimSpace(s.address) == "" {
		return errors.New(i18n.T("tui_validation_address_required"))
	}
	if _, err := strconv.Atoi(s.port); err != nil {
		return errors.New(i18n.T("tui_validation_port_invalid"))
	}
	if err := m.validateTags(s.tags); err != nil {
		return err
	}
	return nil
}

func (m *Model) updateForm(msg tea.Msg) (Model, tea.Cmd) {
	if m.mutationPending {
		return *m, nil
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if m.form != nil {
			formHeight := max(msg.Height-3, 1)
			m.form.WithWidth(msg.Width).WithHeight(formHeight)
		}
		return *m, nil
	case tea.KeyMsg:
		if m.formConflict {
			if msg.String() != "r" {
				m.status = errorStyle.Render(i18n.T("tui_status_conflict_reload"))
				return *m, nil
			}
			nodeID := m.formState.originalID
			m.formState = nil
			m.formConflict = false
			return m.initForm(nodeID)
		}
		if msg.String() == "ctrl+s" {
			if m.mutationPending {
				return *m, nil
			}
			if err := m.validateFormState(); err != nil {
				m.status = errorStyle.Render(err.Error())
				return *m, nil
			}
			return *m, m.saveFormCmd()
		}
		if msg.String() == "esc" {
			// cancel
			m.state = viewList
			return *m, nil
		}
	}
	form, cmd := m.form.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		m.form = f
	}

	if m.form.State == huh.StateCompleted {
		return *m, m.saveFormCmd()
	}

	return *m, cmd
}

func (m *Model) saveFormCmd() tea.Cmd {
	s := m.formState

	port, _ := strconv.Atoi(s.port)

	// Prepare IDs
	identityID := fmt.Sprintf("%s@%s", s.user, s.address)
	hostID := fmt.Sprintf("%s:%d", s.address, port)
	nodeID := fmt.Sprintf("%s@%s:%d", s.user, s.address, port)

	view := m.repository.View()
	// The read and conditional write are tied to the same revision. This keeps
	// fields which the form does not own intact without overwriting a concurrent
	// edit made after the form was opened.
	var node models.Node
	if s.isEdit {
		var ok bool
		node, ok = view.Configuration.Nodes.Get(s.originalID)
		if !ok {
			m.status = errorStyle.Render(fmt.Sprintf("resolve node %q before saving: %v", s.originalID, config.ErrNodeNotFound))
			return nil
		}
	}

	// Standardize key path
	absKeyPath := ""
	if s.authType == "key" && s.keyPath != "" {
		absKeyPath = fileutil.ToAbsolutePath(s.keyPath)
	}

	// Try to get existing identity to preserve any extra fields.
	identity, _ := view.Configuration.Identities.Get(identityID)
	identity.User = s.user
	identity.AuthType = s.authType
	if s.authType == "password" {
		identity.Password = s.password
		identity.KeyPath = ""
		identity.Passphrase = ""
	} else {
		identity.KeyPath = absKeyPath
		identity.Passphrase = s.passphrase
		identity.Password = ""
	}
	// Try to get existing host to preserve any extra fields (like Host.Alias).
	host, _ := view.Configuration.Hosts.Get(hostID)
	host.Address = s.address
	host.Port = uint16(port)
	node.HostRef = hostID
	node.IdentityRef = identityID
	node.SudoMode = models.SudoMode(s.sudoMode)
	node.Alias = splitComma(s.alias)
	node.Tags = splitComma(s.tags)

	var run func(context.Context) error
	repository := m.repository
	if s.isEdit {
		ref := s.ref
		if ref.ID == "" {
			// Tests and non-interactive callers that construct form state directly do
			// not have a displayed ref. The normal TUI path always captures it when
			// the form opens; this fallback preserves that internal construction path.
			ref = view.NodeRefs[s.originalID]
		}
		run = func(ctx context.Context) error {
			return repository.ReplaceNodeAtRefContext(ctx, ref, nodeID, node, host, identity)
		}
	} else {
		run = func(ctx context.Context) error {
			_, err := repository.CreateNodeContext(ctx, nodeID, node, host, identity)
			return err
		}
	}
	return m.beginConfigurationMutation(configurationMutationForm, nodeID, 0, run)
}

// splitComma parses a comma-separated string into a slice of trimmed strings
func splitComma(s string) []string {
	var res []string
	if strings.TrimSpace(s) == "" {
		return res
	}
	for _, part := range strings.Split(s, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}

// getAllTags 获取所有现有标签
func getAllTags(cfg *config.Configuration) []string {
	tagSet := make(map[string]bool)
	if cfg == nil || cfg.Nodes == nil {
		return nil
	}
	for _, nodeID := range cfg.Nodes.Keys() {
		node, exists := cfg.Nodes.Get(nodeID)
		if !exists {
			continue
		}
		for _, tag := range node.Tags {
			tagSet[tag] = true
		}
	}
	var tags []string
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	return tags
}

// getSelectedNodeIDs 获取勾选的节点 ID
func (m *Model) getSelectedNodeRefs() []config.NodeRef {
	visibleItems := m.list.VisibleItems()
	visibleMap := make(map[string]bool)
	for _, item := range visibleItems {
		if ni, ok := item.(*nodeItem); ok {
			visibleMap[ni.id] = true
		}
	}

	var refs []config.NodeRef
	all := m.list.Items()
	for _, i := range all {
		if ni, ok := i.(*nodeItem); ok && ni.selected && visibleMap[ni.id] {
			refs = append(refs, ni.ref)
		}
	}
	return refs
}

// initTagSelectForm 初始化标签选择表单
func (m *Model) initTagSelectForm() Model {
	view := m.repository.View()
	m.selectedTags = []string{}
	m.tagMode = "add"
	m.newTagsInput = ""
	m.tagRevision = view.Revision
	updated, _ := m.rebuildTagSelectForm()
	return updated
}

// rebuildTagSelectForm recreates Huh's completed form while retaining the
// user's in-memory tag draft. It is used after an asynchronous write fails.
func (m *Model) rebuildTagSelectForm() (Model, tea.Cmd) {
	view := m.repository.View()
	existingTags := getAllTags(view.Configuration)
	m.tagRevision = view.Revision

	// 构建标签选项
	var tagOpts []huh.Option[string]
	for _, tag := range existingTags {
		tagOpts = append(tagOpts, huh.NewOption(tag, tag))
	}

	// 如果有现有标签，使用多选；否则使用输入框
	if len(tagOpts) > 0 {
		m.tagForm = huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title(i18n.T("tui_tag_action")).
					Options(
						huh.NewOption(i18n.T("tui_tag_add"), "add"),
						huh.NewOption(i18n.T("tui_tag_remove"), "remove"),
					).
					Value(&m.tagMode),
				huh.NewMultiSelect[string]().
					Title(i18n.T("tui_tag_select")).
					Options(tagOpts...).
					Value(&m.selectedTags),
				huh.NewInput().
					Title(i18n.T("tui_tag_new_input")).
					Value(&m.newTagsInput),
			),
		).WithTheme(huh.ThemeCharm()).WithWidth(m.lastSize.Width).WithHeight(m.lastSize.Height - 1)
	} else {
		// 没有现有标签，只显示输入框
		m.tagForm = huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title(i18n.T("tui_tag_action")).
					Options(
						huh.NewOption(i18n.T("tui_tag_add"), "add"),
					).
					Value(&m.tagMode),
				huh.NewInput().
					Title(i18n.T("tui_tag_input")).
					Value(&m.newTagsInput),
			),
		).WithTheme(huh.ThemeCharm()).WithWidth(m.lastSize.Width).WithHeight(m.lastSize.Height - 1)
	}
	return *m, m.tagForm.Init()
}

// updateTagSelect 处理标签选择视图的更新
func (m *Model) updateTagSelect(msg tea.Msg) (Model, tea.Cmd) {
	if m.mutationPending {
		return *m, nil
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if m.tagForm != nil {
			m.tagForm.WithWidth(msg.Width).WithHeight(msg.Height - 1)
		}
		return *m, nil
	case tea.KeyMsg:
		if msg.String() == "esc" {
			m.state = viewList
			*m, _ = m.updateList(m.lastSize)
			return *m, nil
		}
	}
	form, cmd := m.tagForm.Update(msg)
	if f, ok := form.(*huh.Form); ok {
		m.tagForm = f
	}

	if m.tagForm.State == huh.StateCompleted {
		cmd := m.applyTagChangesCmd()
		if cmd == nil {
			m.state = viewList
			m.refreshList()
			*m, _ = m.updateList(m.lastSize)
		}
		return *m, cmd
	}

	return *m, cmd
}

// mergeTags 合并选中的标签和输入的新标签
func (m *Model) mergeTags() map[string]bool {
	tags := make(map[string]bool)

	for _, tag := range m.selectedTags {
		if tag != "" {
			tags[tag] = true
		}
	}

	if m.newTagsInput != "" {
		for _, tag := range strings.Split(m.newTagsInput, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				tags[tag] = true
			}
		}
	}
	return tags
}

// applyTagChangesCmd applies tags in a bounded asynchronous configuration transaction.
func (m *Model) applyTagChangesCmd() tea.Cmd {
	selectedNodeRefs := m.getSelectedNodeRefs()
	if len(selectedNodeRefs) == 0 {
		return nil
	}

	tagsToApply := m.mergeTags()
	if len(tagsToApply) == 0 {
		return nil
	}

	tags := make([]string, 0, len(tagsToApply))
	for tag := range tagsToApply {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	nodeIDs := make([]string, 0, len(selectedNodeRefs))
	for _, ref := range selectedNodeRefs {
		nodeIDs = append(nodeIDs, ref.ID)
	}
	add := m.tagMode == "add"
	repository := m.repository
	return m.beginConfigurationMutation(configurationMutationTags, "", len(selectedNodeRefs), func(ctx context.Context) error {
		_, err := repository.UpdateNodeTagsContext(ctx, nodeIDs, tags, add)
		return err
	})
}

// updateTagStatus 更新标签操作状态
func (m *Model) updateTagStatus(count int) {
	if count == 0 {
		return
	}
	if m.tagMode == "add" {
		m.status = successStyle.Render(i18n.Tf("tui_status_tag_added", map[string]any{"Count": count}))
	} else {
		m.status = successStyle.Render(i18n.Tf("tui_status_tag_removed", map[string]any{"Count": count}))
	}
}
