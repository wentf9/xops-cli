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

	provider := config.NewProvider(cfg)
	store := &mockStore{}

	model := Model{
		provider:    provider,
		configStore: store,
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

	model.saveForm()

	newNodeID := "root@10.0.0.1:22"
	newNode, exists := provider.GetNode(newNodeID)
	if !exists {
		t.Fatalf("expected new node %q to exist", newNodeID)
	}

	if _, exists := provider.GetNode(originalNodeID); exists {
		t.Errorf("expected old node %q to be deleted", originalNodeID)
	}

	host, hostExists := provider.GetConfig().Hosts.Get(newNode.HostRef)
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
	provider := config.NewProvider(cfg)

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
				provider:  provider,
				formState: tt.state,
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

func TestUpdateForm_CtrlS_Valid(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	provider := config.NewProvider(cfg)
	store := &mockStore{}

	m := Model{
		provider:    provider,
		configStore: store,
		state:       viewForm,
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
	updatedModel, _ := m.updateForm(msgCtrlS)

	if updatedModel.state != viewList {
		t.Errorf("expected state to transition to viewList, but got %v", updatedModel.state)
	}

	// 确认数据已写入 provider
	nodeID := "admin@127.0.0.1:22"
	if _, exists := provider.GetNode(nodeID); !exists {
		t.Errorf("expected node %q to be saved", nodeID)
	}
}

func TestUpdateForm_CtrlS_Invalid(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	provider := config.NewProvider(cfg)
	store := &mockStore{}

	m := Model{
		provider:    provider,
		configStore: store,
		state:       viewForm,
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
