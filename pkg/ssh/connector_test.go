package ssh

import (
	"context"
	"fmt"
	"strings"
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

type mockConn struct {
	ssh.Conn
	closeCalled bool
}

func (m *mockConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	return false, nil, fmt.Errorf("connection lost")
}

func (m *mockConn) Close() error {
	m.closeCalled = true
	return nil
}

func TestConnector_Connect_Reconnection(t *testing.T) {
	store := &mockConfigStore{
		cfg: &ClientConfig{
			NodeID:   "node-1",
			Address:  "127.0.0.1",
			Port:     9999, // 使用一个不会有真实服务的端口
			User:     "admin",
			AuthType: "password",
			Password: "mockpassword",
		},
	}
	ui := &mockUI{}

	connector := NewConnector(store, ui)

	// 模拟已存在缓存连接，但该连接已经失效
	mc := &mockConn{}
	dummyClient := &ssh.Client{
		Conn: mc,
	}
	connector.clients.Set("node-1", dummyClient)

	ctx := context.Background()
	_, err := connector.Connect(ctx, "node-1")
	if err == nil {
		t.Fatal("expected connect to fail because connection is stale and dial will fail")
	}

	// 验证连接是否已从缓存中移除
	if _, ok := connector.clients.Get("node-1"); ok {
		t.Error("expected node-1 to be evicted from clients cache")
	}

	// 验证旧连接是否被 Close
	if !mc.closeCalled {
		t.Error("expected stale client to be closed")
	}
}

func TestConnector_Connect_ProxyJumpCycle(t *testing.T) {
	// 模拟一个形成了 ProxyJump 环的配置：node-1 依赖 node-2，node-2 依赖 node-1
	cfg1 := &ClientConfig{
		NodeID:    "node-1",
		Address:   "127.0.0.1",
		Port:      22,
		User:      "admin",
		AuthType:  "password",
		Password:  "pass",
		ProxyJump: "node-2",
	}
	cfg2 := &ClientConfig{
		NodeID:    "node-2",
		Address:   "127.0.0.2",
		Port:      22,
		User:      "admin",
		AuthType:  "password",
		Password:  "pass",
		ProxyJump: "node-1",
	}

	store := &mockProxyJumpCycleStore{
		cfgs: map[string]*ClientConfig{
			"node-1": cfg1,
			"node-2": cfg2,
		},
	}
	ui := &mockUI{}

	connector := NewConnector(store, ui)
	ctx := context.Background()
	_, err := connector.Connect(ctx, "node-1")
	if err == nil {
		t.Fatal("expected Connect to fail due to proxy jump cycle, got nil error")
	}

	// 验证错误消息中是否包含 "cycle detected"
	expectedSub := "proxy jump cycle detected"
	if !strings.Contains(err.Error(), expectedSub) {
		t.Errorf("expected error message to contain %q, got %q", expectedSub, err.Error())
	}
}

type mockProxyJumpCycleStore struct {
	cfgs map[string]*ClientConfig
}

func (m *mockProxyJumpCycleStore) GetConfig(nodeID string) (*ClientConfig, error) {
	if cfg, ok := m.cfgs[nodeID]; ok {
		return cfg, nil
	}
	return nil, fmt.Errorf("node not found: %s", nodeID)
}

func (m *mockProxyJumpCycleStore) UpdateAuth(nodeID string, password, keyPath, passphrase string) error {
	return nil
}

func (m *mockProxyJumpCycleStore) UpdateSudo(nodeID string, mode SudoMode, suPwd string) error {
	return nil
}
