package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

type mockStore struct{}

func (m *mockStore) Load() (*config.Configuration, error) {
	return nil, nil
}

func (m *mockStore) Save(cfg *config.Configuration) error {
	return nil
}

func newTestRepository(t *testing.T, cfg *config.Configuration) *config.Repository {
	t.Helper()
	repository, err := config.NewRepositoryWithoutOpenSSH(cfg, &mockStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}
	return repository
}

func completeConfigurationMutation(t *testing.T, model *Model, cmd tea.Cmd) Model {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected configuration mutation command")
	}
	updated, _ := model.Update(cmd())
	result, ok := updated.(*Model)
	if !ok {
		t.Fatalf("Update() model = %T, want *tui.Model", updated)
	}
	return *result
}

func TestSaveForm_ModifyUserPreservesHost(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	originalNodeID := "admin@10.0.0.1:22"
	cfg.Nodes.Set(originalNodeID, models.Node{
		HostRef:     "10.0.0.1:22",
		IdentityRef: "admin@10.0.0.1",
		SudoMode:    models.SudoModeAuto,
		Alias:       []string{"server1"},
		Tags:        []string{"prod"},
	})
	cfg.Hosts.Set("10.0.0.1:22", models.Host{
		Address: "10.0.0.1",
		Port:    22,
		Alias:   []string{"host-alias"},
	})
	cfg.Identities.Set("admin@10.0.0.1", models.Identity{
		User:     "admin",
		AuthType: "password",
		Password: "password123",
	})

	repository := newTestRepository(t, cfg)

	model := Model{
		repository: repository,
		formState: &nodeFormState{
			isEdit:     true,
			originalID: originalNodeID,
			alias:      "server1",
			user:       "root",
			address:    "10.0.0.1",
			port:       "22",
			authType:   "password",
			password:   "newpassword",
			sudoMode:   "auto",
			tags:       "prod",
		},
	}

	completeConfigurationMutation(t, &model, model.saveFormCmd())

	newNodeID := "root@10.0.0.1:22"
	newNode, exists := repository.GetNode(newNodeID)
	if !exists {
		t.Fatalf("expected new node %q to exist", newNodeID)
	}

	if _, exists := repository.GetNode(originalNodeID); exists {
		t.Errorf("expected old node %q to be deleted", originalNodeID)
	}

	host, hostExists := repository.Snapshot().Hosts.Get(newNode.HostRef)
	if !hostExists {
		t.Fatalf("expected host %q to exist", newNode.HostRef)
	}

	if host.Address != "10.0.0.1" || host.Port != 22 {
		t.Errorf("unexpected host config: %+v", host)
	}

	if len(host.Alias) == 0 || host.Alias[0] != "host-alias" {
		t.Errorf("expected host alias 'host-alias' to be preserved, but got %v", host.Alias)
	}
}

func TestValidateFormState(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	repository := newTestRepository(t, cfg)

	tests := []struct {
		name    string
		state   *nodeFormState
		wantErr string
	}{
		{
			name: "valid state",
			state: &nodeFormState{
				user:    "admin",
				address: "1.1.1.1",
				port:    "22",
			},
			wantErr: "",
		},
		{
			name: "missing user",
			state: &nodeFormState{
				user:    " ",
				address: "1.1.1.1",
				port:    "22",
			},
			wantErr: "user is required",
		},
		{
			name: "missing address",
			state: &nodeFormState{
				user:    "admin",
				address: "",
				port:    "22",
			},
			wantErr: "address is required",
		},
		{
			name: "invalid port",
			state: &nodeFormState{
				user:    "admin",
				address: "1.1.1.1",
				port:    "abc",
			},
			wantErr: "invalid port, must be number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := Model{
				repository: repository,
				formState:  tt.state,
			}
			err := m.validateFormState()
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected nil error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else {
					errMsg := err.Error()
					expectedMsgs := []string{
						"tui_validation_user_required", "用户名必填", "user is required",
						"tui_validation_address_required", "地址必填", "address is required",
						"tui_validation_port_invalid", "端口无效，必须为数字", "invalid port, must be number",
					}
					matched := false
					for _, em := range expectedMsgs {
						if strings.Contains(errMsg, em) {
							matched = true
							break
						}
					}
					if !matched {
						t.Errorf("unexpected error message: %q", errMsg)
					}
				}
			}
		})
	}
}

func TestMalformedNodeIsReportedInsteadOfRenderedAsZeroValues(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Nodes.Set("broken", models.Node{HostRef: "host", IdentityRef: "missing"})
	cfg.Hosts.Set("host", models.Host{Address: "10.0.0.1", Port: 22})
	if _, err := config.NewRepositoryWithoutOpenSSH(cfg, &mockStore{}); err == nil {
		t.Fatal("NewRepositoryWithoutOpenSSH() error = nil, want invalid reference error")
	}
	provider := config.NewProviderWithoutOpenSSH(cfg)
	items := newListModel(provider).Items()
	if len(items) != 1 {
		t.Fatalf("list item count = %d, want 1", len(items))
	}
	item, ok := items[0].(*nodeItem)
	if !ok {
		t.Fatalf("list item type = %T, want *nodeItem", items[0])
	}
	if item.resolveErr == nil || !strings.Contains(item.Description(), "invalid configuration") {
		t.Fatalf("malformed item description = %q, want explicit configuration error", item.Description())
	}
}

func TestListModelFromViewDoesNotMixLaterRepositoryRevision(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Nodes.Set("first", models.Node{HostRef: "first-host", IdentityRef: "first-identity"})
	cfg.Hosts.Set("first-host", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Identities.Set("first-identity", models.Identity{User: "root"})
	repository := newTestRepository(t, cfg)

	view := repository.View()
	if _, err := repository.CreateNodeContext(t.Context(), "later", models.Node{HostRef: "later-host", IdentityRef: "later-identity"}, models.Host{Address: "192.0.2.2", Port: 22}, models.Identity{User: "deploy"}); err != nil {
		t.Fatalf("add later node: %v", err)
	}
	items := newListModelFromView(view).Items()
	if len(items) != 1 {
		t.Fatalf("view list item count = %d, want 1", len(items))
	}
	item, ok := items[0].(*nodeItem)
	if !ok || item.id != "first" {
		t.Fatalf("view list item = %#v, want first node", items[0])
	}
	if repository.Revision() == view.Revision {
		t.Fatal("repository revision did not advance after later mutation")
	}
}

func TestUpdateForm_CtrlS_Valid(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	repository := newTestRepository(t, cfg)

	m := Model{
		repository: repository,
		state:      viewForm,
		formState: &nodeFormState{
			isEdit:   false,
			alias:    "server1",
			user:     "admin",
			address:  "127.0.0.1",
			port:     "22",
			authType: "password",
			password: "password123",
			sudoMode: "auto",
		},
	}

	// 模拟 ctrl+s 按键
	msgCtrlS := tea.KeyMsg{Type: tea.KeyCtrlS}
	updatedModel, cmd := m.updateForm(msgCtrlS)
	if updatedModel.state != viewForm {
		t.Errorf("expected state to remain viewForm while saving, got %v", updatedModel.state)
	}
	updatedModel = completeConfigurationMutation(t, &updatedModel, cmd)

	if updatedModel.state != viewList {
		t.Errorf("expected state to transition to viewList, but got %v", updatedModel.state)
	}

	// 确认数据已写入 provider
	nodeID := "admin@127.0.0.1:22"
	if _, exists := repository.GetNode(nodeID); !exists {
		t.Errorf("expected node %q to be saved", nodeID)
	}
}

func TestUpdateForm_CtrlS_Invalid(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	repository := newTestRepository(t, cfg)

	m := Model{
		repository: repository,
		state:      viewForm,
		formState: &nodeFormState{
			isEdit:   false,
			user:     "", // 无效：用户名为空
			address:  "127.0.0.1",
			port:     "22",
			authType: "password",
		},
	}

	// 模拟 ctrl+s 按键
	msgCtrlS := tea.KeyMsg{Type: tea.KeyCtrlS}
	updatedModel, _ := m.updateForm(msgCtrlS)

	// 因为验证失败，不应该跳转回列表，依然是 viewForm
	if updatedModel.state != viewForm {
		t.Errorf("expected state to remain viewForm, but got %v", updatedModel.state)
	}

	// 错误状态消息应该被设置
	if updatedModel.status == "" {
		t.Error("expected error status msg to be set, but was empty")
	}
}

func TestSaveForm_MergesUnrelatedConcurrentChange(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	repository := newTestRepository(t, cfg)
	state := &nodeFormState{
		revision: repository.Revision(),
		user:     "admin",
		address:  "127.0.0.1",
		port:     "22",
		authType: "password",
		password: "password123",
		sudoMode: "auto",
	}
	if _, err := repository.CreateIdentityContext(t.Context(), "newer", models.Identity{User: "newer"}); err != nil {
		t.Fatalf("CreateIdentityContext() error = %v", err)
	}
	m := Model{repository: repository, formState: state}

	completeConfigurationMutation(t, &m, m.saveFormCmd())
	if _, exists := repository.GetNode("admin@127.0.0.1:22"); !exists {
		t.Fatal("saveForm() did not publish the new node")
	}
	if _, exists := repository.ListIdentities()["newer"]; !exists {
		t.Fatal("saveForm() lost the unrelated concurrent identity")
	}
}

func TestUpdateForm_Esc(t *testing.T) {
	m := Model{
		state: viewForm,
	}

	// 模拟 esc 按键
	msgEsc := tea.KeyMsg{Type: tea.KeyEsc}
	updatedModel, _ := m.updateForm(msgEsc)

	// 应切回 viewList
	if updatedModel.state != viewList {
		t.Errorf("expected state to transition to viewList, but got %v", updatedModel.state)
	}
}
