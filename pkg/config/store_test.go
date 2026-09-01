package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/crypto"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func TestCreateDirectoryChainSyncsEachNewDirectoryParent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "one", "two", "three")
	var synced []string

	err := createDirectoryChain(target, func(path string) error {
		synced = append(synced, path)
		return nil
	})
	if err != nil {
		t.Fatalf("createDirectoryChain() failed: %v", err)
	}

	for _, directory := range []string{
		filepath.Join(root, "one"),
		filepath.Join(root, "one", "two"),
		target,
	} {
		info, statErr := os.Stat(directory)
		if statErr != nil || !info.IsDir() {
			t.Fatalf("created directory %q is unavailable: %v", directory, statErr)
		}
	}
	want := []string{root, filepath.Join(root, "one"), filepath.Join(root, "one", "two")}
	if !slices.Equal(synced, want) {
		t.Fatalf("synced directories = %v, want %v", synced, want)
	}
}

func TestTransactionStoreHonorsCancellationWhileWaitingForProcessLock(t *testing.T) {
	dir := t.TempDir()
	store, ok := NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key")).(*defaultStore)
	if !ok {
		t.Fatal("NewDefaultStore() did not return *defaultStore")
	}
	store.mu.Lock()
	release := make(chan struct{})
	go func() {
		<-release
		store.mu.Unlock()
	}()
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err := store.Transact(ctx, func(Snapshot) (*Configuration, error) {
		t.Fatal("mutator ran despite canceled lock acquisition")
		return nil, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Transact() error = %v, want context deadline exceeded", err)
	}
}

func TestCreateDirectoryChainStopsWhenParentSyncFails(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "one", "two")
	syncErr := errors.New("sync failed")

	err := createDirectoryChain(target, func(string) error { return syncErr })
	if !errors.Is(err, syncErr) {
		t.Fatalf("createDirectoryChain() error = %v, want wrapped sync error", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "one", "two")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("directory creation continued after sync failure: %v", statErr)
	}
}

func TestAcquireConfigLockCreatesDirectoryThroughDurablePath(t *testing.T) {
	original := ensureConfigLockDirectory
	t.Cleanup(func() { ensureConfigLockDirectory = original })

	var ensured string
	ensureConfigLockDirectory = func(directory string) error {
		ensured = directory
		return original(directory)
	}

	configPath := filepath.Join(t.TempDir(), "new", "config.yaml")
	lock, err := acquireConfigLock(t.Context(), configPath)
	if err != nil {
		t.Fatalf("acquireConfigLock() error = %v", err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			t.Errorf("close configuration lock: %v", closeErr)
		}
	}()

	want := filepath.Dir(configPath)
	if ensured != want {
		t.Fatalf("durable lock directory = %q, want %q", ensured, want)
	}
}

var errTestConfigWrite = errors.New("config write failed")

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

func TestLoad_ReadFailure(t *testing.T) {
	dir := t.TempDir()
	store := NewDefaultStore(dir, filepath.Join(dir, "config.key"))

	if _, err := store.Load(); err == nil {
		t.Fatal("Load() error = nil, want read failure")
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

func TestLoad_ReturnsPlaintextMigrationWriteError(t *testing.T) {
	store, _ := newTestStoreAndConfig(t)
	s := store.(*defaultStore)
	rawYAML := []byte("identities:\n  i1:\n    user: root\n    password: plaintext\n")
	if err := os.WriteFile(s.Path, rawYAML, 0o600); err != nil {
		t.Fatalf("write plaintext configuration: %v", err)
	}
	s.writeFile = func(string, []byte, os.FileMode) error { return errTestConfigWrite }

	if _, err := store.Load(); !errors.Is(err, errTestConfigWrite) {
		t.Fatalf("Load() error = %v, want migration write error", err)
	}
}

func TestLoad_ReturnsCorruptedSecretError(t *testing.T) {
	store, _ := newTestStoreAndConfig(t)
	s := store.(*defaultStore)
	rawYAML := []byte("identities:\n  i1:\n    user: root\n    password: ENC:not-valid-base64\n")
	if err := os.WriteFile(s.Path, rawYAML, 0o600); err != nil {
		t.Fatalf("write corrupted configuration: %v", err)
	}

	if _, err := store.Load(); err == nil {
		t.Fatal("Load() error = nil, want corrupted secret error")
	}
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

func TestDefaultStoreSave_ReportsAppliedButUndurable(t *testing.T) {
	store, cfg := newTestStoreAndConfig(t)
	s := store.(*defaultStore)
	persistErr := errors.New("sync parent directory failed")
	s.atomicWrite = func(string, []byte, os.FileMode) (PersistResult, error) {
		return PersistResult{Applied: true}, persistErr
	}

	result, err := s.save(cfg)
	if !errors.Is(err, persistErr) {
		t.Fatalf("save() error = %v, want %v", err, persistErr)
	}
	if !result.Applied {
		t.Fatal("save() Applied = false, want true")
	}
	if result.Durable {
		t.Fatal("save() Durable = true, want false")
	}
}

func TestDefaultStoreConcurrentFirstSaveSharesOneAtomicKey(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	keyPath := filepath.Join(dir, "config.key")
	base := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	base.Hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 22})
	base.Identities.Set("identity", models.Identity{User: "root", Password: "secret", AuthType: "password"})
	base.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "identity"})

	const writers = 12
	start := make(chan struct{})
	errs := make(chan error, writers)
	var workers sync.WaitGroup
	workers.Add(writers)
	for range writers {
		go func() {
			defer workers.Done()
			<-start
			if err := NewDefaultStore(configPath, keyPath).Save(cloneConfiguration(base)); err != nil {
				errs <- err
			}
		}()
	}
	close(start)
	workers.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Save() error = %v", err)
	}

	loaded, err := NewDefaultStore(configPath, keyPath).Load()
	if err != nil {
		t.Fatalf("load concurrently initialized configuration: %v", err)
	}
	identity, ok := loaded.Identities.Get("identity")
	if !ok || identity.Password != "secret" {
		t.Fatalf("loaded identity = %+v, want decrypted password", identity)
	}
	if _, err := os.Stat(configPath + ".lock"); err != nil {
		t.Fatalf("stat permanent configuration lock file: %v", err)
	}
}

func TestDefaultStoreLoadRejectsMissingKeyForEncryptedConfiguration(t *testing.T) {
	store, cfg := newTestStoreAndConfig(t)
	if err := store.Save(cfg); err != nil {
		t.Fatalf("save encrypted configuration: %v", err)
	}
	s := store.(*defaultStore)
	if err := os.Remove(s.KeyPath); err != nil {
		t.Fatalf("remove configuration key: %v", err)
	}

	_, err := NewDefaultStore(s.Path, s.KeyPath).Load()
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load() error = %v, want missing key error", err)
	}
	if !strings.Contains(err.Error(), "missing for encrypted configuration") {
		t.Fatalf("Load() error = %v, want encrypted configuration context", err)
	}
}

func TestDefaultStoreTransactReloadsLatestConfiguration(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	keyPath := filepath.Join(dir, "config.key")
	first := NewDefaultStore(configPath, keyPath).(*defaultStore)
	second := NewDefaultStore(configPath, keyPath).(*defaultStore)
	if err := first.Save(cloneConfiguration(nil)); err != nil {
		t.Fatalf("initialize configuration: %v", err)
	}

	start := make(chan struct{})
	errs := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	for _, identityID := range []string{"one", "two"} {
		store := first
		if identityID == "two" {
			store = second
		}
		go func() {
			defer workers.Done()
			<-start
			_, err := store.Transact(context.Background(), func(snapshot Snapshot) (*Configuration, error) {
				updated := cloneConfiguration(snapshot.Configuration)
				updated.Identities.Set(identityID, models.Identity{User: identityID})
				return updated, nil
			})
			errs <- err
		}()
	}
	close(start)
	workers.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Transact() error = %v", err)
		}
	}

	snapshot, err := first.LoadSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LoadSnapshot() error = %v", err)
	}
	for _, identityID := range []string{"one", "two"} {
		if _, exists := snapshot.Configuration.Identities.Get(identityID); !exists {
			t.Fatalf("transaction lost identity %q", identityID)
		}
	}
	if snapshot.Version == (Version{}) {
		t.Fatal("LoadSnapshot() returned a zero version")
	}
}
