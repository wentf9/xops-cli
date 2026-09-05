package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/internal/testleak"
	"github.com/wentf9/xops-cli/pkg/crypto"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func TestCharacterization_StoreSave_EncryptsSecretsOnDisk_PreservesCallerMemory(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	keyPath := filepath.Join(tempDir, "config.key")

	store := NewDefaultStore(configPath, keyPath)

	const (
		plainPassword   = "super-secret-login-password"
		plainPassphrase = "super-secret-private-key-passphrase"
		plainSuPwd      = "super-secret-root-elevation-password"
	)

	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)
	nodes.Set("node-web", models.Node{
		HostRef:     "host-web",
		IdentityRef: "id-web",
		SudoMode:    models.SudoModeSu,
		SuPwd:       plainSuPwd,
	})

	hosts := concurrent.NewMap[string, models.Host](concurrent.HashString)
	hosts.Set("host-web", models.Host{
		Address: "192.168.1.10",
		Port:    22,
	})

	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)
	identities.Set("id-web", models.Identity{
		User:       "admin",
		AuthType:   "password",
		Password:   plainPassword,
		KeyPath:    "/home/admin/.ssh/id_rsa",
		Passphrase: plainPassphrase,
	})

	cfg := &Configuration{
		Nodes:      nodes,
		Hosts:      hosts,
		Identities: identities,
	}

	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save() failed: %v", err)
	}

	// 1. 验证磁盘上的 YAML 经过加密，绝无明文密码泄露
	diskData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read persisted configuration: %v", err)
	}
	testleak.AssertNoSecretInYAML(t, diskData, plainPassword, plainPassphrase, plainSuPwd)
	testleak.AssertSecretPresentInBytes(t, diskData, crypto.Prefix)

	// 2. 验证调用方传入的内存对象未被修改，仍然保持明文
	node, ok := cfg.Nodes.Get("node-web")
	if !ok || node.SuPwd != plainSuPwd {
		t.Fatalf("caller node SuPwd was corrupted: %q, want %q", node.SuPwd, plainSuPwd)
	}
	id, ok := cfg.Identities.Get("id-web")
	if !ok || id.Password != plainPassword || id.Passphrase != plainPassphrase {
		t.Fatalf("caller identity was corrupted: pwd=%q, pass=%q", id.Password, id.Passphrase)
	}

	// 3. 验证 Store.Load 能够重新解密回明文
	loadedCfg, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load() failed: %v", err)
	}
	loadedNode, ok := loadedCfg.Nodes.Get("node-web")
	if !ok || loadedNode.SuPwd != plainSuPwd {
		t.Fatalf("loaded node SuPwd = %q, want %q", loadedNode.SuPwd, plainSuPwd)
	}
	loadedID, ok := loadedCfg.Identities.Get("id-web")
	if !ok || loadedID.Password != plainPassword || loadedID.Passphrase != plainPassphrase {
		t.Fatalf("loaded identity mismatch: pwd=%q, pass=%q", loadedID.Password, loadedID.Passphrase)
	}
}

func TestCharacterization_StoreLoad_MigratesPlaintextFileToEncrypted(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	keyPath := filepath.Join(tempDir, "config.key")

	const (
		plainPassword = "plaintext-vulnerable-password"
		plainSuPwd    = "plaintext-vulnerable-supwd"
	)

	plainYAML := `
hosts:
  h1:
    address: 10.0.0.1
    port: 22
identities:
  id1:
    user: test
    auth_type: password
    password: "` + plainPassword + `"
nodes:
  n1:
    host_ref: h1
    identity_ref: id1
    su_pwd: "` + plainSuPwd + `"
`
	if err := os.WriteFile(configPath, []byte(plainYAML), 0o600); err != nil {
		t.Fatalf("failed to write plaintext yaml: %v", err)
	}

	store := NewDefaultStore(configPath, keyPath)

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load() failed to migrate plaintext configuration: %v", err)
	}

	// 检查内存中已正确加载明文
	id, ok := loaded.Identities.Get("id1")
	if !ok || id.Password != plainPassword {
		t.Fatalf("loaded identity password = %q, want %q", id.Password, plainPassword)
	}

	// 检查磁盘文件已经被自动迁移加密，不再包含明文
	diskData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read migrated disk yaml: %v", err)
	}
	testleak.AssertNoSecretInYAML(t, diskData, plainPassword, plainSuPwd)
	testleak.AssertSecretPresentInBytes(t, diskData, crypto.Prefix)
}

func TestCharacterization_ProviderSnapshot_ExposesPlaintextUnderSchemaV1(t *testing.T) {
	const plainPassword = "snapshot-plain-password"

	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)
	identities.Set("id-1", models.Identity{
		User:     "user1",
		AuthType: "password",
		Password: plainPassword,
	})

	cfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: identities,
	}

	provider := NewProviderWithoutOpenSSH(cfg)

	// 特征记录：当前 Schema v1 下 Snapshot 会暴露出明文凭据
	snapshot1 := provider.Snapshot()
	id1, ok := snapshot1.Identities.Get("id-1")
	if !ok || id1.Password != plainPassword {
		t.Fatalf("expected Snapshot to contain plaintext password in schema v1, got: %v", id1.Password)
	}

	// 验证防御性拷贝：修改 Snapshot 不会污染 Provider 内部状态
	id1.Password = "mutated-password"
	snapshot1.Identities.Set("id-1", id1)

	snapshot2 := provider.Snapshot()
	id2, _ := snapshot2.Identities.Get("id-1")
	if id2.Password != plainPassword {
		t.Fatalf("Snapshot was not defensively copied: got %q, want %q", id2.Password, plainPassword)
	}
}

func TestCharacterization_Repository_SharedIdentity_UpdateAuthCreatesPrivateCopy(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	keyPath := filepath.Join(tempDir, "config.key")

	const (
		initialSharedPassword = "initial-shared-password"
		node1NewPassword      = "node-1-discovered-password"
	)

	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)
	nodes.Set("node-1", models.Node{
		HostRef:     "host-shared",
		IdentityRef: "shared-identity",
	})
	nodes.Set("node-2", models.Node{
		HostRef:     "host-shared",
		IdentityRef: "shared-identity",
	})

	hosts := concurrent.NewMap[string, models.Host](concurrent.HashString)
	hosts.Set("host-shared", models.Host{Address: "10.0.0.1", Port: 22})

	identities := concurrent.NewMap[string, models.Identity](concurrent.HashString)
	identities.Set("shared-identity", models.Identity{
		User:     "ops",
		AuthType: "auto",
		Password: initialSharedPassword,
	})

	cfg := &Configuration{
		Nodes:      nodes,
		Hosts:      hosts,
		Identities: identities,
	}

	store := NewDefaultStore(configPath, keyPath)
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save initial cfg failed: %v", err)
	}

	repo, err := NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH failed: %v", err)
	}

	// 获取 node-1 当前的认证版本
	snapshot, err := repo.ResolveConnection("node-1")
	if err != nil {
		t.Fatalf("ResolveConnection failed: %v", err)
	}
	authVersion := string(snapshot.UpdateRef.AuthVersion[:])

	// node-1 触发凭据写回
	ctx := t.Context()
	_, err = repo.UpdateAuthAtVersionContext(ctx, "node-1", authVersion, node1NewPassword, "", "")
	if err != nil {
		t.Fatalf("UpdateAuthAtVersionContext failed: %v", err)
	}

	// 1. 验证 node-1 的 IdentityRef 已经被分裂为私有副本，拥有新密码且 AuthType 变为 password
	node1, _, node1ID, err := repo.Resolve("node-1")
	if err != nil {
		t.Fatalf("resolve node-1 failed: %v", err)
	}
	if node1.IdentityRef == "shared-identity" {
		t.Fatalf("expected node-1 IdentityRef to be split, still %q", node1.IdentityRef)
	}
	if node1ID.Password != node1NewPassword || node1ID.AuthType != "password" {
		t.Fatalf("node-1 identity mismatch: pwd=%q, authType=%q", node1ID.Password, node1ID.AuthType)
	}

	// 2. 验证 node-2 的 IdentityRef 依然指向 shared-identity，且密码仍是原始初始密码
	node2, _, node2ID, err := repo.Resolve("node-2")
	if err != nil {
		t.Fatalf("resolve node-2 failed: %v", err)
	}
	if node2.IdentityRef != "shared-identity" {
		t.Fatalf("expected node-2 IdentityRef to remain shared-identity, got %q", node2.IdentityRef)
	}
	if node2ID.Password != initialSharedPassword {
		t.Fatalf("shared identity was corrupted: %q, want %q", node2ID.Password, initialSharedPassword)
	}

	// 3. 验证磁盘上的持久化内容：加密存储，绝无任何明文密码泄露
	diskData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read disk data failed: %v", err)
	}
	testleak.AssertNoSecretInYAML(t, diskData, initialSharedPassword, node1NewPassword)
}
