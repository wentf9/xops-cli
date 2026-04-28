package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/crypto"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func newTestStoreAndConfig(t *testing.T) (Store, *Configuration) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	keyPath := filepath.Join(dir, "config.key")

	store := NewDefaultStore(configPath, keyPath)

	cfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("h1", models.Host{Address: "192.168.1.1", Port: 22})
	cfg.Identities.Set("i1", models.Identity{
		User:     "root",
		Password: "s3cret",
		AuthType: "password",
	})
	cfg.Nodes.Set("n1", models.Node{
		HostRef:     "h1",
		IdentityRef: "i1",
		SudoMode:    models.SudoModeSu,
		SuPwd:       "supassword",
	})

	return store, cfg
}

func TestSaveAndLoad_RoundTrip(t *testing.T) {
	store, cfg := newTestStoreAndConfig(t)

	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// 验证 host
	h, ok := loaded.Hosts.Get("h1")
	if !ok {
		t.Fatal("host h1 not found after load")
	}
	if h.Address != "192.168.1.1" || h.Port != 22 {
		t.Errorf("host = %+v, want {Address: 192.168.1.1, Port: 22}", h)
	}

	// 验证 identity（密码应已解密）
	i, ok := loaded.Identities.Get("i1")
	if !ok {
		t.Fatal("identity i1 not found after load")
	}
	if i.Password != "s3cret" {
		t.Errorf("password = %q, want 's3cret' (should be decrypted)", i.Password)
	}

	// 验证 node（SuPwd 应已解密）
	n, ok := loaded.Nodes.Get("n1")
	if !ok {
		t.Fatal("node n1 not found after load")
	}
	if n.HostRef != "h1" || n.IdentityRef != "i1" {
		t.Errorf("node = %+v, want {HostRef: h1, IdentityRef: i1}", n)
	}
	if n.SuPwd != "supassword" {
		t.Errorf("SuPwd = %q, want 'supassword' (should be decrypted)", n.SuPwd)
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nonexistent.yaml")
	keyPath := filepath.Join(dir, "config.key")

	store := NewDefaultStore(configPath, keyPath)
	cfg, err := store.Load()
	if err != nil {
		t.Fatalf("Load of nonexistent file should not error: %v", err)
	}
	if cfg.Nodes.Count() != 0 {
		t.Error("expected empty config from nonexistent file")
	}
}

func TestSave_EncryptsPassword(t *testing.T) {
	store, cfg := newTestStoreAndConfig(t)
	s := store.(*defaultStore)

	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// 读取原始文件内容，验证密码不是明文
	data, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}
	content := string(data)

	if strings.Contains(content, "s3cret") {
		t.Error("config file contains plaintext password, expected encrypted")
	}
	if !strings.Contains(content, crypto.Prefix) {
		t.Error("config file should contain ENC: prefix for password")
	}
}

func TestSave_PreservesMemoryPlaintext(t *testing.T) {
	store, cfg := newTestStoreAndConfig(t)

	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// 保存后内存中应仍为明文
	i, _ := cfg.Identities.Get("i1")
	if i.Password != "s3cret" {
		t.Errorf("in-memory password = %q, want 's3cret' (should stay plaintext after save)", i.Password)
	}
	n, _ := cfg.Nodes.Get("n1")
	if n.SuPwd != "supassword" {
		t.Errorf("in-memory SuPwd = %q, want 'supassword' (should stay plaintext after save)", n.SuPwd)
	}
}

func TestSave_EncryptsSuPwd(t *testing.T) {
	store, cfg := newTestStoreAndConfig(t)
	s := store.(*defaultStore)

	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	data, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}
	content := string(data)

	if strings.Contains(content, "supassword") {
		t.Error("config file contains plaintext SuPwd, expected encrypted")
	}
	if !strings.Contains(content, crypto.Prefix) {
		t.Error("config file should contain ENC: prefix for SuPwd")
	}
}

// TestLoad_MigratesPlaintextSecrets 验证：配置文件中存在明文密码时，
// Load() 自动将其加密回写，后续文件不再含明文。
func TestLoad_MigratesPlaintextSecrets(t *testing.T) {
	store, cfg := newTestStoreAndConfig(t)
	s := store.(*defaultStore)

	// 直接写入未加密的 YAML（模拟用户手写配置）
	rawYAML := `
identities:
  i1:
    user: root
    password: s3cret
    auth_type: password
hosts:
  h1:
    address: 192.168.1.1
    port: 22
nodes:
  n1:
    host_ref: h1
    identity_ref: i1
    sudo_mode: su
    su_pwd: supassword
`
	if err := os.WriteFile(s.Path, []byte(rawYAML), 0600); err != nil {
		t.Fatalf("failed to write raw config: %v", err)
	}

	// Load 应触发迁移，加密回写
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// 内存中应为明文
	i, _ := loaded.Identities.Get("i1")
	if i.Password != "s3cret" {
		t.Errorf("in-memory password = %q, want 's3cret'", i.Password)
	}
	n, _ := loaded.Nodes.Get("n1")
	if n.SuPwd != "supassword" {
		t.Errorf("in-memory SuPwd = %q, want 'supassword'", n.SuPwd)
	}

	// 文件中不应再有明文
	data, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatalf("failed to read config file after migration: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "s3cret") {
		t.Error("config file still contains plaintext password after migration")
	}
	if strings.Contains(content, "supassword") {
		t.Error("config file still contains plaintext SuPwd after migration")
	}
	if !strings.Contains(content, crypto.Prefix) {
		t.Error("config file should contain ENC: prefix after migration")
	}

	// 再次 Load 仍能正确解密
	loaded2, err := store.Load()
	if err != nil {
		t.Fatalf("second Load failed: %v", err)
	}
	i2, _ := loaded2.Identities.Get("i1")
	if i2.Password != "s3cret" {
		t.Errorf("second load password = %q, want 's3cret'", i2.Password)
	}
	n2, _ := loaded2.Nodes.Get("n1")
	if n2.SuPwd != "supassword" {
		t.Errorf("second load SuPwd = %q, want 'supassword'", n2.SuPwd)
	}
	_ = cfg
}

func TestSaveAndLoad_SuPwdRoundTrip(t *testing.T) {
	store, cfg := newTestStoreAndConfig(t)

	if err := store.Save(cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	n, ok := loaded.Nodes.Get("n1")
	if !ok {
		t.Fatal("node n1 not found after load")
	}
	if n.SuPwd != "supassword" {
		t.Errorf("SuPwd after round-trip = %q, want 'supassword'", n.SuPwd)
	}
}
