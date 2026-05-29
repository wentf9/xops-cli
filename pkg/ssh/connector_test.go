package ssh

import (
	"context"
	"testing"

	"golang.org/x/crypto/ssh"
)

type mockConfigStore struct {
	cfg *ClientConfig
}

func (m *mockConfigStore) GetConfig(nodeID string) (*ClientConfig, error) {
	return m.cfg, nil
}

func (m *mockConfigStore) UpdateAuth(nodeID string, password, keyPath, passphrase string) error {
	return nil
}

func (m *mockConfigStore) UpdateSudo(nodeID string, mode SudoMode, suPwd string) error {
	return nil
}

type mockUI struct{}

func (m *mockUI) PromptPassword(prompt string) (string, error) {
	return "mockpass", nil
}

func (m *mockUI) ConfirmHostKey(hostname string, fingerprint string) (bool, error) {
	return true, nil
}

func TestConnector_Connect_Cached(t *testing.T) {
	store := &mockConfigStore{
		cfg: &ClientConfig{
			NodeID:   "node-1",
			Address:  "10.0.0.1",
			Port:     22,
			User:     "admin",
			AuthType: "password",
			Password: "mockpassword",
		},
	}
	ui := &mockUI{}

	connector := NewConnector(store, ui)

	// 模拟已存在缓存连接
	dummyClient := &ssh.Client{}
	connector.clients.Set("node-1", dummyClient)

	ctx := context.Background()
	client, err := connector.Connect(ctx, "node-1")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	// 验证在缓存命中时，配置是否正确附加
	if client.cfg.Address != "10.0.0.1" {
		t.Errorf("expected host address '10.0.0.1', got %q", client.cfg.Address)
	}
	if client.cfg.User != "admin" {
		t.Errorf("expected identity user 'admin', got %q", client.cfg.User)
	}
}
