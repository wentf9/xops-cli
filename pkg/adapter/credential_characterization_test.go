package adapter

import (
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/internal/testleak"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func TestCharacterization_SSHAdapter_GetConfig_CarriesPlaintextAndTokens(t *testing.T) {
	const (
		plainPassword   = "adapter-test-login-password"
		plainPassphrase = "adapter-test-key-passphrase"
		plainSuPwd      = "adapter-test-sudo-elevation-password"
	)

	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)
	nodes.Set("node-target", models.Node{
		HostRef:     "host-target",
		IdentityRef: "id-target",
		SudoMode:    models.SudoModeSu,
		SuPwd:       plainSuPwd,
		ProxyJump:   "jump-node",
	})

	hosts := concurrent.NewMap[string, models.Host](concurrent.HashString)
	hosts.Set("host-target", models.Host{Address: "10.0.1.50", Port: 2222})

	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)
	identities.Set("id-target", models.Identity{
		User:       "operator",
		AuthType:   "password",
		Password:   plainPassword,
		KeyPath:    "/home/operator/.ssh/id_ed25519",
		Passphrase: plainPassphrase,
	})

	cfg := &config.Configuration{
		Nodes:      nodes,
		Hosts:      hosts,
		Identities: identities,
	}

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	keyPath := filepath.Join(tempDir, "config.key")

	store := config.NewDefaultStore(configPath, keyPath)
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save failed: %v", err)
	}

	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}

	adapter := NewSSHAdapter(repo)

	// 1. 验证 GetConfig 获取底层 SSH 客户端配置：直接暴露明文凭据和 Token
	clientCfg, err := adapter.GetConfig("node-target")
	if err != nil {
		t.Fatalf("adapter.GetConfig failed: %v", err)
	}

	if clientCfg.NodeID != "node-target" {
		t.Errorf("NodeID = %q, want 'node-target'", clientCfg.NodeID)
	}
	if clientCfg.Address != "10.0.1.50" || clientCfg.Port != 2222 {
		t.Errorf("Address/Port mismatch: %s:%d", clientCfg.Address, clientCfg.Port)
	}
	if clientCfg.User != "operator" || clientCfg.AuthType != "password" {
		t.Errorf("User/AuthType mismatch: user=%q, auth=%q", clientCfg.User, clientCfg.AuthType)
	}
	if clientCfg.Password != plainPassword {
		t.Errorf("Password mismatch: got %q, want %q", clientCfg.Password, plainPassword)
	}
	if clientCfg.Passphrase != plainPassphrase {
		t.Errorf("Passphrase mismatch: got %q, want %q", clientCfg.Passphrase, plainPassphrase)
	}
	if clientCfg.SuPwd != plainSuPwd {
		t.Errorf("SuPwd mismatch: got %q, want %q", clientCfg.SuPwd, plainSuPwd)
	}
	if clientCfg.SudoMode != ssh.SudoModeSu {
		t.Errorf("SudoMode mismatch: got %v, want %v", clientCfg.SudoMode, ssh.SudoModeSu)
	}
	if clientCfg.AuthUpdateToken == "" || clientCfg.SudoUpdateToken == "" {
		t.Errorf("AuthUpdateToken or SudoUpdateToken is empty: auth=%q, sudo=%q", clientCfg.AuthUpdateToken, clientCfg.SudoUpdateToken)
	}

	// 2. 验证未知节点错误，断言错误中不包含敏感凭据
	_, notFoundErr := adapter.GetConfig("non-existent-node")
	if notFoundErr == nil {
		t.Fatal("expected error for non-existent node, got nil")
	}
	testleak.AssertNoSecretInError(t, notFoundErr, plainPassword, plainPassphrase, plainSuPwd)

	// 3. 验证 UpdateAuth 回写新凭据
	const updatedPassword = "adapter-new-password"
	ctx := t.Context()
	_, err = adapter.UpdateAuth(ctx, "node-target", clientCfg.AuthUpdateToken, updatedPassword, "", "")
	if err != nil {
		t.Fatalf("adapter.UpdateAuth failed: %v", err)
	}

	updatedClientCfg, err := adapter.GetConfig("node-target")
	if err != nil {
		t.Fatalf("adapter.GetConfig after update failed: %v", err)
	}
	if updatedClientCfg.Password != updatedPassword {
		t.Fatalf("Password after update = %q, want %q", updatedClientCfg.Password, updatedPassword)
	}
}

func TestCharacterization_SSHAdapter_Connector_DoesNotLeakSecretsInLogsOrErrors(t *testing.T) {
	const (
		sensitivePassword   = "adapter-sensitive-pass-9999"
		sensitivePassphrase = "adapter-sensitive-keypass-8888"
	)

	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)
	nodes.Set("node-secure", models.Node{
		HostRef:     "host-secure",
		IdentityRef: "id-secure",
	})

	hosts := concurrent.NewMap[string, models.Host](concurrent.HashString)
	hosts.Set("host-secure", models.Host{Address: "192.168.10.10", Port: 22})

	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)
	identities.Set("id-secure", models.Identity{
		User:       "secadmin",
		AuthType:   "password",
		Password:   sensitivePassword,
		Passphrase: sensitivePassphrase,
	})

	cfg := &config.Configuration{
		Nodes:      nodes,
		Hosts:      hosts,
		Identities: identities,
	}

	provider := config.NewProviderWithoutOpenSSH(cfg)
	bufLogger := testleak.NewBufferLogger()
	conn := NewConnector(provider, ssh.WithLogger(bufLogger))
	t.Cleanup(func() {
		_ = conn.CloseAll()
	})

	// 请求连接一个不存在的节点
	ctx := t.Context()
	_, err := conn.Connect(ctx, "non-existent-node")
	if err == nil {
		t.Fatal("expected connect to non-existent node to fail, got nil")
	}

	// 验证错误信息和日志流中不包含配置中的任何敏感凭据
	testleak.AssertNoSecretInError(t, err, sensitivePassword, sensitivePassphrase)
	testleak.AssertNoSecretInLogs(t, bufLogger, sensitivePassword, sensitivePassphrase)
}
