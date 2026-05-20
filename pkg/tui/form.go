package tui

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
)

type nodeFormState struct {
	isEdit     bool
	originalID string

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
	state := m.newNodeFormState(nodeID)
	m.formState = state

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

func (m *Model) newNodeFormState(nodeID string) *nodeFormState {
	state := &nodeFormState{
		port:     "22",
		authType: "password",
		sudoMode: string(models.SudoModeAuto),
	}

	if nodeID == "" {
		return state
	}

	state.isEdit = true
	state.originalID = nodeID
	node, _ := m.provider.GetNode(nodeID)
	host, _ := m.provider.GetHost(nodeID)
	identity, _ := m.provider.GetIdentity(nodeID)

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
	return state
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

		if existingNode := m.provider.FindAlias(a); existingNode != "" {
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
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if m.form != nil {
			formHeight := max(msg.Height-3, 1)
			m.form.WithWidth(msg.Width).WithHeight(formHeight)
		}
		return *m, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+s" {
			if err := m.validateFormState(); err != nil {
				m.status = errorStyle.Render(err.Error())
				return *m, nil
			}
			m.saveForm()
			m.state = viewList
			m.list = newListModel(m.provider) // refresh list
			*m, _ = m.updateList(m.lastSize)
			return *m, nil
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
		m.saveForm()
		m.state = viewList
		m.list = newListModel(m.provider) // refresh list
		// 应用窗口大小
		*m, _ = m.updateList(m.lastSize)
		return *m, nil
	}

	return *m, cmd
}

func (m *Model) saveForm() {
	s := m.formState

	port, _ := strconv.Atoi(s.port)

	// Prepare IDs
	identityID := fmt.Sprintf("%s@%s", s.user, s.address)
	hostID := fmt.Sprintf("%s:%d", s.address, port)
	nodeID := fmt.Sprintf("%s@%s:%d", s.user, s.address, port)

	// Standardize key path
	absKeyPath := ""
	if s.authType == "key" && s.keyPath != "" {
		absKeyPath = utils.ToAbsolutePath(s.keyPath)
	}

	// 1. Save Identity
	// Try to get existing identity to preserve any extra fields
	identity, _ := m.provider.GetConfig().Identities.Get(identityID)
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
	m.provider.AddIdentity(identityID, identity)

	// 2. Save Host
	// Try to get existing host to preserve any extra fields (like Host.Alias)
	host, _ := m.provider.GetConfig().Hosts.Get(hostID)
	host.Address = s.address
	host.Port = uint16(port)
	m.provider.AddHost(hostID, host)

	// 3. Save Node
	var node models.Node
	if s.isEdit {
		// Load existing node from original ID to preserve ProxyJump, SuPwd, etc.
		node, _ = m.provider.GetNode(s.originalID)
	} else {
		// If not edit, check if nodeID already exists to avoid blind overwrite
		node, _ = m.provider.GetNode(nodeID)
	}

	// Update fields from form
	node.HostRef = hostID
	node.IdentityRef = identityID
	node.SudoMode = models.SudoMode(s.sudoMode)
	node.Alias = splitComma(s.alias)
	node.Tags = splitComma(s.tags)

	// Add new node first, then clean up old node if ID changed.
	// This ensures referenced Host/Identity aren't prematurely deleted by DeleteNode's reference counting check.
	m.provider.AddNode(nodeID, node)
	if s.isEdit && s.originalID != nodeID {
		m.provider.DeleteNode(s.originalID)
	}

	err := m.configStore.Save(m.provider.GetConfig())
	if err != nil {
		m.status = errorStyle.Render(i18n.Tf("tui_status_save_failed", map[string]any{"Error": err}))
	} else {
		m.status = successStyle.Render(i18n.Tf("tui_status_saved", map[string]any{"ID": nodeID}))
	}
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
func (m *Model) getAllTags() []string {
	tagSet := make(map[string]bool)
	for _, node := range m.provider.ListNodes() {
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
func (m *Model) getSelectedNodeIDs() []string {
	visibleItems := m.list.VisibleItems()
	visibleMap := make(map[string]bool)
	for _, item := range visibleItems {
		if ni, ok := item.(*nodeItem); ok {
			visibleMap[ni.id] = true
		}
	}

	var ids []string
	all := m.list.Items()
	for _, i := range all {
		if ni, ok := i.(*nodeItem); ok && ni.selected && visibleMap[ni.id] {
			ids = append(ids, ni.id)
		}
	}
	return ids
}

// initTagSelectForm 初始化标签选择表单
func (m *Model) initTagSelectForm() Model {
	existingTags := m.getAllTags()
	m.selectedTags = []string{}
	m.tagMode = "add"
	m.newTagsInput = ""

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
	m.tagForm.Init()
	return *m
}

// updateTagSelect 处理标签选择视图的更新
func (m *Model) updateTagSelect(msg tea.Msg) (Model, tea.Cmd) {
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
		m.applyTagChanges()
		m.state = viewList
		m.list = newListModel(m.provider)
		*m, _ = m.updateList(m.lastSize)
		return *m, nil
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

// addTagsToNode 为节点添加标签
func addTagsToNode(node *models.Node, tags map[string]bool) {
	existing := make(map[string]bool)
	for _, t := range node.Tags {
		existing[t] = true
	}
	for tag := range tags {
		if !existing[tag] {
			node.Tags = append(node.Tags, tag)
		}
	}
}

// removeTagsFromNode 从节点移除标签
func removeTagsFromNode(node *models.Node, tags map[string]bool) {
	var newTags []string
	for _, t := range node.Tags {
		if !tags[t] {
			newTags = append(newTags, t)
		}
	}
	node.Tags = newTags
}

// applyTagChanges 应用标签变更
func (m *Model) applyTagChanges() {
	selectedNodeIDs := m.getSelectedNodeIDs()
	if len(selectedNodeIDs) == 0 {
		return
	}

	tagsToApply := m.mergeTags()
	if len(tagsToApply) == 0 {
		return
	}

	updatedCount := 0
	for _, nodeID := range selectedNodeIDs {
		node, ok := m.provider.GetNode(nodeID)
		if !ok {
			continue
		}

		if m.tagMode == "add" {
			addTagsToNode(&node, tagsToApply)
		} else {
			removeTagsFromNode(&node, tagsToApply)
		}

		m.provider.AddNode(nodeID, node)
		updatedCount++
	}

	m.updateTagStatus(updatedCount)
}

// updateTagStatus 更新标签操作状态
func (m *Model) updateTagStatus(count int) {
	if count == 0 {
		return
	}
	if err := m.configStore.Save(m.provider.GetConfig()); err != nil {
		m.status = errorStyle.Render(i18n.Tf("tui_status_save_failed", map[string]any{"Error": err}))
		return
	}
	if m.tagMode == "add" {
		m.status = successStyle.Render(i18n.Tf("tui_status_tag_added", map[string]any{"Count": count}))
	} else {
		m.status = successStyle.Render(i18n.Tf("tui_status_tag_removed", map[string]any{"Count": count}))
	}
}
