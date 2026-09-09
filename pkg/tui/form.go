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
	"github.com/wentf9/xops-cli/pkg/credential"
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

	// 凭据状态与操作
	passwordAction          string // "keep", "replace", "delete"
	passwordStoreStatus     string // "stored in <StoreID>", "legacy plaintext", "not set"
	passphraseAction        string // "keep", "replace", "delete"
	passphraseStoreStatus   string // "stored in <StoreID>", "legacy plaintext", "not set"
	existingPasswordRef     *credential.Ref
	existingPassphraseRef   *credential.Ref
	existingPlainPassword   string
	existingPlainPassphrase string
}

type formCredentialActions struct {
	password   string
	passphrase string
	// cleanupRef is the old authentication method's reference. It is removed
	// only after the replacement credential has been committed successfully.
	cleanupKind              credential.Kind
	cleanupRef               *credential.Ref
	keyPath                  string
	clearKeyPath             bool
	clearLegacyLoginPassword bool
	clearLegacyPassphrase    bool
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

	var fields []huh.Field
	fields = append(fields,
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
	)

	if state.isEdit {
		fields = append(fields,
			huh.NewSelect[string]().
				Title(fmt.Sprintf("%s (%s)", i18n.T("tui_form_password_action"), state.passwordStoreStatus)).
				Options(
					huh.NewOption(i18n.T("tui_action_keep"), "keep"),
					huh.NewOption(i18n.T("tui_action_replace"), "replace"),
					huh.NewOption(i18n.T("tui_action_delete"), "delete"),
				).
				Value(&state.passwordAction).
				Inline(true),
		)
	}

	fields = append(fields,
		huh.NewInput().
			Title(i18n.T("tui_form_password")).
			EchoMode(huh.EchoModePassword).
			Value(&state.password),
		huh.NewInput().
			Title(i18n.T("tui_form_key_path")).
			Value(&state.keyPath),
	)

	if state.isEdit {
		fields = append(fields,
			huh.NewSelect[string]().
				Title(fmt.Sprintf("%s (%s)", i18n.T("tui_form_passphrase_action"), state.passphraseStoreStatus)).
				Options(
					huh.NewOption(i18n.T("tui_action_keep"), "keep"),
					huh.NewOption(i18n.T("tui_action_replace"), "replace"),
					huh.NewOption(i18n.T("tui_action_delete"), "delete"),
				).
				Value(&state.passphraseAction).
				Inline(true),
		)
	}

	fields = append(fields,
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
	)

	m.form = huh.NewForm(
		huh.NewGroup(fields...),
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
		state.passwordAction = "replace"
		state.passwordStoreStatus = "not set"
		state.passphraseAction = "replace"
		state.passphraseStoreStatus = "not set"
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

	// 追踪凭据 Store 状态，默认 keep，绝对不回填秘密明文
	if identity.LoginPasswordRef != nil && !identity.LoginPasswordRef.IsEmpty() {
		state.passwordStoreStatus = fmt.Sprintf("stored in %s", identity.LoginPasswordRef.StoreID)
		state.existingPasswordRef = identity.LoginPasswordRef.Clone()
		state.passwordAction = "keep"
	} else if identity.Password != "" {
		state.passwordStoreStatus = "legacy plaintext"
		state.existingPlainPassword = identity.Password
		state.passwordAction = "keep"
	} else {
		state.passwordStoreStatus = "not set"
		state.passwordAction = "keep"
	}

	if identity.PassphraseRef != nil && !identity.PassphraseRef.IsEmpty() {
		state.passphraseStoreStatus = fmt.Sprintf("stored in %s", identity.PassphraseRef.StoreID)
		state.existingPassphraseRef = identity.PassphraseRef.Clone()
		state.passphraseAction = "keep"
	} else if identity.Passphrase != "" {
		state.passphraseStoreStatus = "legacy plaintext"
		state.existingPlainPassphrase = identity.Passphrase
		state.passphraseAction = "keep"
	} else {
		state.passphraseStoreStatus = "not set"
		state.passphraseAction = "keep"
	}

	state.password = ""
	state.keyPath = identity.KeyPath
	state.passphrase = ""
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

	// Preserve the actual identity referenced by an edited node. The canonical
	// ID is only suitable for a new node or a deliberate rename.
	identity, ok := view.Configuration.Identities.Get(identityID)
	if s.isEdit && node.IdentityRef != "" {
		identity, ok = view.Configuration.Identities.Get(node.IdentityRef)
	}
	if !ok {
		identity = models.Identity{}
	}
	actions := s.applyIdentityCredentials(&identity, absKeyPath)

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
			authVersion, err := repository.ReplaceNodeAtRefWithAuthVersionContext(ctx, ref, nodeID, node, host, identity)
			if err != nil {
				return err
			}
			return m.syncCredentialsToStore(ctx, nodeID, authVersion, s, actions)
		}
	} else {
		run = func(ctx context.Context) error {
			mutation, err := repository.CreateNodeContext(ctx, nodeID, node, host, identity)
			if err != nil {
				return err
			}
			return m.syncCredentialsToStore(ctx, nodeID, mutation.AuthVersion, s, actions)
		}
	}
	return m.beginConfigurationMutation(configurationMutationForm, nodeID, 0, run)
}

//nolint:gocyclo // credential actions and cross-authentication transitions must stay in one atomic state calculation
func (s *nodeFormState) applyIdentityCredentials(identity *models.Identity, absKeyPath string) formCredentialActions {
	actions := formCredentialActions{keyPath: absKeyPath}
	previousAuthType := identity.AuthType
	identity.User = s.user

	actions.password = s.passwordAction
	if actions.password == "" {
		if s.password != "" {
			actions.password = "replace"
		} else {
			actions.password = "keep"
		}
	}

	actions.passphrase = s.passphraseAction
	if actions.passphrase == "" {
		if s.passphrase != "" {
			actions.passphrase = "replace"
		} else {
			actions.passphrase = "keep"
		}
	}

	// A credential store write occurs after this metadata mutation. Keep the
	// previous authentication usable until that write atomically installs the
	// new reference and key path.
	credentialReplacement := (s.authType == "password" && actions.password == "replace" && s.password != "") ||
		(s.authType == "key" && actions.passphrase == "replace" && s.passphrase != "")
	previousRef := (*credential.Ref)(nil)
	switch previousAuthType {
	case "password":
		previousRef = identity.LoginPasswordRef
	case "key":
		previousRef = identity.PassphraseRef
	}
	deferSwitch := previousAuthType != s.authType && (credentialReplacement || previousRef != nil)
	deferKeyPath := previousAuthType == "key" && s.authType == "key" && credentialReplacement
	deferCredentialMetadata := deferSwitch || deferKeyPath
	identity.AuthType = s.authType
	if deferSwitch {
		identity.AuthType = previousAuthType
		if previousAuthType == "password" {
			actions.cleanupKind = credential.KindLoginPassword
			actions.cleanupRef = identity.LoginPasswordRef.Clone()
		} else {
			actions.cleanupKind = credential.KindPassphrase
			actions.cleanupRef = identity.PassphraseRef.Clone()
		}
	}
	if deferSwitch && previousAuthType == "key" && s.authType == "password" {
		actions.clearKeyPath = true
	}
	if previousAuthType != s.authType {
		switch previousAuthType {
		case "password":
			actions.cleanupKind = credential.KindLoginPassword
			actions.cleanupRef = identity.LoginPasswordRef.Clone()
			if deferSwitch && identity.Password != "" {
				actions.clearLegacyLoginPassword = true
			}
		case "key":
			actions.cleanupKind = credential.KindPassphrase
			actions.cleanupRef = identity.PassphraseRef.Clone()
			if deferSwitch && identity.Passphrase != "" {
				actions.clearLegacyPassphrase = true
			}
		}
	}

	if s.authType == "password" {
		if !deferCredentialMetadata {
			identity.KeyPath = ""
			identity.Passphrase = ""
			identity.PassphraseRef = nil
		}

		switch actions.password {
		case "keep":
			identity.Password = s.existingPlainPassword
			identity.LoginPasswordRef = s.existingPasswordRef
		case "delete":
			if s.existingPasswordRef != nil {
				// Keep the reference until credential.Service completes its
				// transactional delete. This preserves a usable configuration if
				// the store operation fails.
				identity.Password = s.existingPlainPassword
				identity.LoginPasswordRef = s.existingPasswordRef.Clone()
			} else {
				identity.Password = ""
				identity.LoginPasswordRef = nil
			}
		case "replace":
			// The secret is committed by credential.Service after this metadata
			// update. Keep the previous ref until that transaction succeeds, so a
			// store failure leaves a usable, secret-free configuration.
			identity.Password = s.existingPlainPassword
			identity.LoginPasswordRef = s.existingPasswordRef.Clone()
		}
	} else {
		if !deferCredentialMetadata {
			identity.KeyPath = absKeyPath
			identity.Password = ""
			identity.LoginPasswordRef = nil
		}

		switch actions.passphrase {
		case "keep":
			identity.Passphrase = s.existingPlainPassphrase
			identity.PassphraseRef = s.existingPassphraseRef
		case "delete":
			if s.existingPassphraseRef != nil {
				identity.Passphrase = s.existingPlainPassphrase
				identity.PassphraseRef = s.existingPassphraseRef.Clone()
			} else {
				identity.Passphrase = ""
				identity.PassphraseRef = nil
			}
		case "replace":
			identity.Passphrase = s.existingPlainPassphrase
			identity.PassphraseRef = s.existingPassphraseRef.Clone()
		}
	}
	return actions
}

func (m *Model) syncCredentialsToStore(ctx context.Context, nodeID, authVersion string, s *nodeFormState, actions formCredentialActions) error {
	if m.credentialService == nil {
		if m.repository.Snapshot().Credential != nil && ((s.authType == "password" && (actions.password == "replace" || actions.password == "delete")) ||
			(s.authType == "key" && (actions.passphrase == "replace" || actions.passphrase == "delete"))) {
			return errors.New("credential service is unavailable")
		}
		return nil
	}
	credSvc := m.credentialService
	cfg := m.repository.Snapshot()
	targetStore := "none"
	if cfg != nil && cfg.Credential != nil {
		targetStore = cfg.Credential.DefaultStore
	}

	keyFingerprint := ""
	if s.authType == "key" && actions.passphrase == "replace" {
		target, err := config.BindPrivateKeyFingerprint(cfg, credential.Target{Kind: credential.KindPassphrase, KeyPath: actions.keyPath}, []byte(s.passphrase))
		if err != nil {
			return err
		}
		keyFingerprint = target.KeyFingerprint
	}
	version := authVersion
	var err error
	switch s.authType {
	case "password":
		version, err = syncFormCredential(ctx, credSvc, nodeID, credential.KindLoginPassword, authVersion, actions.password, s.existingPasswordRef, targetStore, s.password, "", s.authType, keyFingerprint, actions.clearKeyPath, actions.clearLegacyLoginPassword, actions.clearLegacyPassphrase)
	case "key":
		version, err = syncFormCredential(ctx, credSvc, nodeID, credential.KindPassphrase, authVersion, actions.passphrase, s.existingPassphraseRef, targetStore, s.passphrase, actions.keyPath, s.authType, keyFingerprint, actions.clearKeyPath, actions.clearLegacyLoginPassword, actions.clearLegacyPassphrase)
	}
	if err != nil {
		return err
	}
	if actions.cleanupRef != nil {
		target := credential.Target{NodeID: nodeID, Kind: actions.cleanupKind, KeyPath: actions.keyPath, AuthType: s.authType, ClearKeyPath: actions.clearKeyPath, ClearLegacyLoginPassword: actions.clearLegacyLoginPassword, ClearLegacyPassphrase: actions.clearLegacyPassphrase}
		if _, err := credSvc.Delete(ctx, target, version, *actions.cleanupRef); err != nil {
			return fmt.Errorf("remove replaced %s from credential store: %w", actions.cleanupKind, err)
		}
	}
	return nil
}

func syncFormCredential(ctx context.Context, service *credential.Service, nodeID string, kind credential.Kind, version, action string, oldRef *credential.Ref, storeID, value, keyPath, authType, keyFingerprint string, clearKeyPath, clearLegacyLoginPassword, clearLegacyPassphrase bool) (string, error) {
	target := credential.Target{NodeID: nodeID, Kind: kind, KeyPath: keyPath, KeyFingerprint: keyFingerprint, AuthType: authType, ClearKeyPath: clearKeyPath, ClearLegacyLoginPassword: clearLegacyLoginPassword, ClearLegacyPassphrase: clearLegacyPassphrase}
	if action == "replace" && value != "" {
		_, nextVersion, err := service.Rotate(ctx, target, version, oldRef, storeID, credential.Secret{Value: []byte(value)})
		if err != nil {
			return "", fmt.Errorf("save %s to credential store: %w", kind, err)
		}
		return nextVersion, nil
	}
	if action == "delete" && oldRef != nil {
		nextVersion, err := service.Delete(ctx, target, version, *oldRef)
		if err != nil {
			return "", fmt.Errorf("delete %s from credential store: %w", kind, err)
		}
		return nextVersion, nil
	}
	return version, nil
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
