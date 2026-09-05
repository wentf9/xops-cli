package adapter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

type adapterTestStore struct{}

func (adapterTestStore) Load() (*config.Configuration, error) { return nil, nil }

func (adapterTestStore) Save(*config.Configuration) error { return nil }

func TestSSHAdapter_NonInteractive(t *testing.T) {
	nodeMap := concurrent.NewMap[string, models.Node](concurrent.HashString)
	hostMap := concurrent.NewMap[string, models.Host](concurrent.HashString)
	identityMap := concurrent.NewMap[string, models.Identity](concurrent.HashString)

	hostMap.Set("host-1", models.Host{Address: "127.0.0.1", Port: 22})
	identityMap.Set("id-1", models.Identity{User: "root", AuthType: "password", Password: "pwd"})

	nodeMap.Set("node-su", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
		SudoMode:    models.SudoModeSu,
	})

	cfg := &config.Configuration{
		Nodes:      nodeMap,
		Identities: identityMap,
		Hosts:      hostMap,
	}
	provider := config.NewProviderWithoutOpenSSH(cfg)

	// 创建非交互式 connector，验证默认策略返回 ErrInteractionRequired
	conn := NewConnector(provider)
	if conn == nil {
		t.Fatal("expected connector to be created, got nil")
	}
	defer func() { _ = conn.CloseAll() }()

	_, err := conn.Connect(context.Background(), "node-su")
	if err == nil {
		t.Fatal("expected interaction required error, got nil")
	}
	if !errors.Is(err, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ssh.ErrInteractionRequired, got: %v", err)
	}
}

func TestSSHAdapterGetConfigOpenSSHVirtualNodeIsSessionLocal(t *testing.T) {
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(`
Host remote-app
    HostName 10.0.0.5
    User deploy
    Port 2200
`))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(&config.Configuration{}, parser)

	clientConfig, err := NewSSHAdapter(provider).GetConfig(config.OpenSSHNodePrefix + "remote-app")
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	if clientConfig.Address != "10.0.0.5" || clientConfig.User != "deploy" {
		t.Fatalf("unexpected SSH client config: %+v", clientConfig)
	}
	if clientConfig.AuthUpdateToken != "" || clientConfig.SudoUpdateToken != "" {
		t.Fatalf("virtual OpenSSH node must not carry persistence tokens: %+v", clientConfig)
	}
}

func TestSSHAdapterRejectsEmptyPersistenceToken(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Nodes.Set("persisted", models.Node{HostRef: "host", IdentityRef: "identity", SudoMode: models.SudoModeAuto})
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "root"})
	repository, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	adapter := NewSSHAdapter(repository)
	if err := adapter.UpdateSudo(t.Context(), "persisted", "", "sudo", ""); err == nil {
		t.Fatal("UpdateSudo() error = nil for empty persistence token")
	}
	node, ok := repository.GetNode("persisted")
	if !ok {
		t.Fatal("persisted node is missing")
	}
	if node.SudoMode != models.SudoModeAuto {
		t.Fatalf("empty token changed sudo mode to %q", node.SudoMode)
	}
}

func TestSSHAdapter_ResolveSecret(t *testing.T) {
	nodeMap := concurrent.NewMap[string, models.Node](concurrent.HashString)
	hostMap := concurrent.NewMap[string, models.Host](concurrent.HashString)
	identityMap := concurrent.NewMap[string, models.Identity](concurrent.HashString)

	hostMap.Set("host-1", models.Host{Address: "127.0.0.1", Port: 22})
	identityMap.Set("id-full", models.Identity{
		User:       "root",
		AuthType:   "password",
		Password:   "login-pwd-123",
		Passphrase: "key-pass-456",
	})
	identityMap.Set("id-empty", models.Identity{
		User:     "guest",
		AuthType: "password",
	})

	nodeMap.Set("node-full", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-full",
		SudoMode:    models.SudoModeSu,
		SuPwd:       "su-pwd-789",
	})
	nodeMap.Set("node-empty", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-empty",
		SudoMode:    models.SudoModeSu,
	})

	cfg := &config.Configuration{
		Nodes:      nodeMap,
		Identities: identityMap,
		Hosts:      hostMap,
	}
	provider := config.NewProviderWithoutOpenSSH(cfg)
	adp := NewSSHAdapter(provider)

	ctx := context.Background()

	// 1. 成功解析 LoginPassword
	pwd, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindLoginPassword,
		NodeID: "node-full",
	})
	if err != nil || string(pwd) != "login-pwd-123" {
		t.Fatalf("ResolveSecret login password failed: err=%v, pwd=%q", err, string(pwd))
	}

	// 2. 成功解析 PrivateKeyPassphrase
	pass, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindPrivateKeyPassphrase,
		NodeID: "node-full",
	})
	if err != nil || string(pass) != "key-pass-456" {
		t.Fatalf("ResolveSecret passphrase failed: err=%v, pass=%q", err, string(pass))
	}

	// 3. 成功解析 SuPassword
	suPwd, err := adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindSuPassword,
		NodeID: "node-full",
	})
	if err != nil || string(suPwd) != "su-pwd-789" {
		t.Fatalf("ResolveSecret su password failed: err=%v, suPwd=%q", err, string(suPwd))
	}

	// 4. 空密码返回 ErrInteractionRequired
	_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindLoginPassword,
		NodeID: "node-empty",
	})
	if !errors.Is(err, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ErrInteractionRequired for empty password, got: %v", err)
	}

	// 5. 空 passphrase 返回 ErrInteractionRequired
	_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindPrivateKeyPassphrase,
		NodeID: "node-empty",
	})
	if !errors.Is(err, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ErrInteractionRequired for empty passphrase, got: %v", err)
	}

	// 6. 空 suPwd 返回 ErrInteractionRequired
	_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindSuPassword,
		NodeID: "node-empty",
	})
	if !errors.Is(err, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ErrInteractionRequired for empty su password, got: %v", err)
	}

	// 7. 取消 context 立即返回 context.Canceled
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = adp.ResolveSecret(canceledCtx, ssh.SecretRequest{
		Kind:   ssh.SecretKindLoginPassword,
		NodeID: "node-full",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}

	// 8. 不支持的 Kind
	_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKind(99),
		NodeID: "node-full",
	})
	if err == nil {
		t.Fatal("expected error for unsupported secret kind, got nil")
	}

	// 9. Provider 为 nil
	nilAdp := &SSHAdapter{}
	_, err = nilAdp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindLoginPassword,
		NodeID: "node-full",
	})
	if err == nil {
		t.Fatal("expected error for nil provider, got nil")
	}

	// 10. 目标主机变动：请求旧主机，但快照主机已变更，必须拒绝
	_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindLoginPassword,
		NodeID: "node-full",
		Host:   "old-host-ip", // 与 127.0.0.1 不一致
	})
	if !errors.Is(err, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch for changed host, got: %v", err)
	}

	// 11. 用户变动：请求旧用户，但快照用户已变更，必须拒绝
	_, err = adp.ResolveSecret(ctx, ssh.SecretRequest{
		Kind:   ssh.SecretKindLoginPassword,
		NodeID: "node-full",
		User:   "old-user", // 与 root 不一致
	})
	if !errors.Is(err, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch for changed user, got: %v", err)
	}
}

func TestSSHAdapter_ResolveSecret_DetectsVersionMismatchAfterUpdate(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Nodes.Set("node-dynamic", models.Node{
		HostRef:     "host-dyn",
		IdentityRef: "id-dyn",
	})
	cfg.Hosts.Set("host-dyn", models.Host{Address: "192.0.2.10", Port: 22})
	cfg.Identities.Set("id-dyn", models.Identity{User: "admin", AuthType: "password", Password: "old-secret"})

	repository, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	adapter := NewSSHAdapter(repository)

	// 获取初始配置快照与 token
	clientCfg, err := adapter.GetConfig("node-dynamic")
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	oldToken := clientCfg.AuthUpdateToken
	if oldToken == "" {
		t.Fatal("expected non-empty AuthUpdateToken")
	}

	// 模拟并发更新：通过 Repository 更新了密码
	err = repository.UpdateAuthAtVersionContext(context.Background(), "node-dynamic", oldToken, "new-secret-456", "", "")
	if err != nil {
		t.Fatalf("UpdateAuthAtVersionContext() error = %v", err)
	}

	// 使用旧快照的 oldToken 尝试解析机密，必须被拒绝，防止将新密码注入给旧连接配置
	_, err = adapter.ResolveSecret(context.Background(), ssh.SecretRequest{
		Kind:         ssh.SecretKindLoginPassword,
		NodeID:       "node-dynamic",
		User:         clientCfg.User,
		Host:         clientCfg.Address,
		VersionToken: oldToken, // 带有旧快照版本
	})
	if !errors.Is(err, ssh.ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch when version changed, got: %v", err)
	}
}
