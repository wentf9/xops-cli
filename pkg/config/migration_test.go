package config

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	sshcrypto "golang.org/x/crypto/ssh"
)

type migrationTestStore struct {
	mu         sync.Mutex
	values     map[credential.Ref][]byte
	puts       int
	putFailure bool
	uncertain  bool
	corrupt    bool
	locked     bool
}

func (s *migrationTestStore) Get(ctx context.Context, ref credential.Ref) (credential.Secret, error) {
	if err := ctx.Err(); err != nil {
		return credential.Secret{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locked {
		return credential.Secret{}, credential.ErrCredentialStoreLocked
	}
	value, ok := s.values[ref]
	if !ok {
		return credential.Secret{}, credential.ErrCredentialNotFound
	}
	if s.corrupt {
		return credential.NewSecret([]byte("incorrect")), nil
	}
	return credential.NewSecret(value), nil
}

func (s *migrationTestStore) Put(ctx context.Context, ref credential.Ref, secret credential.Secret) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putFailure {
		return credential.ErrCredentialStoreUnavailable
	}
	s.values[ref] = bytes.Clone(secret.Value)
	s.puts++
	if s.uncertain {
		return credential.ErrCredentialStoreUnavailable
	}
	return nil
}

func (s *migrationTestStore) Delete(context.Context, credential.Ref) error {
	return errors.New("migration must not delete backend secrets")
}

func migrationFixture(t *testing.T) (*CredentialMigrator, *migrationTestStore, []byte) {
	t.Helper()
	dir := physicalCredentialTestDir(t)
	keyPath := filepath.Join(dir, "id_ed25519")
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := sshcrypto.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := cloneConfiguration(nil)
	cfg.SchemaVersion = 1
	cfg.Credential = &CredentialConfig{DefaultStore: "vault", RememberPrompted: "ask", Stores: map[string]StoreConfig{
		"vault": {Type: StoreTypeHelper, Command: "/test/helper", Timeout: time.Second, CacheTTL: time.Hour},
	}}
	cfg.Identities.Set("ops", models.Identity{User: "ops", AuthType: "key", KeyPath: keyPath, Password: "login-password", Passphrase: "key-passphrase"})
	cfg.Hosts.Set("host", models.Host{Address: "127.0.0.1", Port: 22})
	cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "ops", SuPwd: "privilege-password", SudoMode: models.SudoModeSu})
	path := filepath.Join(dir, "config.yaml")
	key := filepath.Join(dir, "secret.key")
	if err := NewDefaultStore(path, key).Save(cfg); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := &migrationTestStore{values: make(map[credential.Ref][]byte)}
	m := newTestMigrator(t, path, key, source)
	return m, source, raw
}

func newTestMigrator(t *testing.T, path, key string, source *migrationTestStore) *CredentialMigrator {
	t.Helper()
	m, err := NewCredentialMigrator(path, key)
	if err != nil {
		t.Fatal(err)
	}
	m.registry = func(cfg *CredentialConfig) (*credential.Registry, error) {
		reg := credential.NewRegistry()
		for name, config := range cfg.Stores {
			if config.CacheTTL != 0 {
				t.Error("migration used cached credentials")
			}
			if err := reg.Register(name, source); err != nil {
				return nil, err
			}
		}
		return reg, nil
	}
	return m
}

func assertLegacyRecoverable(t *testing.T, m *CredentialMigrator, source *migrationTestStore) {
	t.Helper()
	raw, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatal(err)
	}
	version, err := DetectSchemaVersion(raw)
	if err != nil {
		t.Fatal(err)
	}
	if version == 2 {
		if err := m.verifyV2(t.Context(), raw, nil); err == nil {
			return
		}
		raw, err = os.ReadFile(m.backupPath())
		if err != nil {
			t.Fatal("neither v2 refs nor legacy backup recoverable")
		}
	}
	key, err := os.ReadFile(m.keyPath)
	if err != nil {
		key, err = os.ReadFile(m.backupKeyPath())
	}
	if err != nil {
		t.Fatal("legacy decryption key lost")
	}
	defer clear(key)
	cfg, err := decodeMigrationLegacy(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer clearMigrationConfiguration(cfg)
	id, _ := cfg.Identities.Get("ops")
	node, _ := cfg.Nodes.Get("node")
	for _, pair := range [][2]string{{id.Password, "login-password"}, {id.Passphrase, "key-passphrase"}, {node.SuPwd, "privilege-password"}} {
		plain, err := migrationPlaintext(pair[0], key)
		if err != nil || string(plain) != pair[1] {
			t.Fatal("legacy credential not recoverable")
		}
		clear(plain)
	}
}

func TestMigrationDryRunDoesNotWrite(t *testing.T) {
	m, store, before := migrationFixture(t)
	files, err := os.ReadDir(filepath.Dir(m.path))
	if err != nil {
		t.Fatal(err)
	}
	report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault", DryRun: true})
	if err != nil || report.Credentials != 3 || !report.DryRun {
		t.Fatalf("dry run: %+v, %v", report, err)
	}
	after, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatal(err)
	}
	newFiles, err := os.ReadDir(filepath.Dir(m.path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || len(files) != len(newFiles) || store.puts != 0 {
		t.Fatal("dry run wrote files or credentials")
	}
}

func TestMigrationRoundTripAndFinalize(t *testing.T) {
	m, store, source := migrationFixture(t)
	report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"})
	if err != nil || !report.Verified || report.Credentials != 3 {
		t.Fatalf("migrate: %+v, %v", report, err)
	}
	backup, err := os.ReadFile(m.backupPath())
	if err != nil || !bytes.Equal(source, backup) {
		t.Fatal("backup differs from original")
	}
	assertMigrationArtifactModes(t, m)
	cfg, err := NewDefaultStore(m.path, m.keyPath).Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaVersion != 2 {
		t.Fatal("schema not upgraded")
	}
	if _, err := cfg.Snapshot().ToV2(); err != nil {
		t.Fatal(err)
	}
	id, _ := cfg.Identities.Get("ops")
	if id.KeyFingerprint == "" || id.PassphraseRef == nil || id.Password != "" {
		t.Fatal("migration omitted key binding or retained plaintext")
	}
	// Metadata edits after migration must not prevent explicit finalization.
	id.User = "changed"
	cfg.Identities.Set("ops", id)
	if err := NewDefaultStore(m.path, m.keyPath).Save(cfg); err != nil {
		t.Fatal(err)
	}
	report, err = m.Finalize(t.Context())
	if err != nil || !report.Finalized {
		t.Fatalf("finalize: %+v, %v", report, err)
	}
	assertLegacyFilesRemoved(t, m)
	cfg, err = NewDefaultStore(m.path, m.keyPath).Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := NewDefaultStore(m.path, m.keyPath).Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("v2 recreated legacy key")
	}
	if _, err := m.Finalize(t.Context()); err != nil {
		t.Fatal(err)
	}
	if store.puts != 3 {
		t.Fatalf("unexpected credential writes: %d", store.puts)
	}
}

func TestMigrationCrashBoundariesResumeWithSameRefs(t *testing.T) {
	for _, point := range []string{"target_validated", "intent", "backup", "key_backup", "decoded", "put:0", "readback:0", "put:1", "readback:1", "put:2", "readback:2", "before_commit", "committed", "verified"} {
		t.Run(point, func(t *testing.T) {
			m, store, _ := migrationFixture(t)
			crash := errors.New("simulated process exit")
			m.checkpoint = func(step string) error {
				if step == point {
					return crash
				}
				return nil
			}
			if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); !errors.Is(err, crash) {
				t.Fatalf("checkpoint not reached: %v", err)
			}
			assertLegacyRecoverable(t, m, store)
			state, err := m.loadState()
			if err != nil {
				t.Fatal(err)
			}
			fresh := newTestMigrator(t, m.path, m.keyPath, store)
			if report, err := fresh.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil || !report.Verified {
				t.Fatalf("resume: %+v, %v", report, err)
			}
			after, err := fresh.loadState()
			if err != nil {
				t.Fatal(err)
			}
			if state != nil && !reflect.DeepEqual(state.Entries, after.Entries) {
				t.Fatal("resume allocated different refs")
			}
			if store.puts != 3 {
				t.Fatalf("resume overwrote immutable credentials: %d puts", store.puts)
			}
		})
	}
}

func TestMigrationBackendFailuresRetainRollback(t *testing.T) {
	for _, mode := range []string{"put", "uncertain", "readback", "locked"} {
		t.Run(mode, func(t *testing.T) {
			m, store, _ := migrationFixture(t)
			store.putFailure = mode == "put"
			store.uncertain = mode == "uncertain"
			store.corrupt = mode == "readback"
			store.locked = mode == "locked"
			if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err == nil {
				t.Fatal("backend failure accepted")
			}
			assertLegacyRecoverable(t, m, store)
			store.putFailure = false
			store.uncertain = false
			store.corrupt = false
			store.locked = false
			if _, err := newTestMigrator(t, m.path, m.keyPath, store).Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMigrationCASConflictDoesNotOverwriteConfig(t *testing.T) {
	m, store, raw := migrationFixture(t)
	concurrent := append(bytes.Clone(raw), []byte("\n# concurrent change\n")...)
	m.checkpoint = func(step string) error {
		if step == "before_commit" {
			return os.WriteFile(m.path, concurrent, 0600)
		}
		return nil
	}
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("CAS: %v", err)
	}
	after, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, concurrent) {
		t.Fatal("concurrent config overwritten")
	}
	assertLegacyRecoverable(t, m, store)
}

func assertMigrationArtifactModes(t *testing.T, m *CredentialMigrator) {
	t.Helper()
	for _, path := range []string{m.backupPath(), m.backupKeyPath(), m.statePath()} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Fatal("insecure migration artifact permissions")
		}
	}

}

func TestMigrationPlaintextWithoutKey(t *testing.T) {
	m, _, _ := migrationFixture(t)
	cfg, err := NewDefaultStore(m.path, m.keyPath).Load()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.keyPath); err != nil {
		t.Fatal(err)
	}
	if report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil || report.BackupKeyPath != "" {
		t.Fatalf("keyless migration: %+v, %v", report, err)
	}
	if _, err := m.Finalize(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("keyless migration created a key")
	}
}

func TestMigrationRejectsUnknownFieldsWithoutLosingData(t *testing.T) {
	m, store, raw := migrationFixture(t)
	raw = bytes.Replace(raw, []byte("user: ops"), []byte("user: ops\n        unrecognized_option: retained-source"), 1)
	if _, err := decodeMigrationLegacy(raw); err == nil {
		t.Fatal("unknown identity field silently dropped")
	}
	if err := os.WriteFile(m.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err == nil {
		t.Fatal("unknown field accepted")
	}
	current, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, current) || store.puts != 0 {
		t.Fatal("failed validation modified source")
	}
}

func TestMigrationRejectsChangedBackupAndMissingKey(t *testing.T) {
	for _, mode := range []string{"backup", "missing_key"} {
		t.Run(mode, func(t *testing.T) {
			m, _, raw := migrationFixture(t)
			if mode == "backup" {
				if err := os.WriteFile(m.backupPath(), []byte("unrelated backup"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(m.keyPath); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err == nil {
				t.Fatal("invalid rollback materials accepted")
			}
			current, err := os.ReadFile(m.path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, current) {
				t.Fatal("failed migration changed source")
			}
		})
	}
}

func assertLegacyFilesRemoved(t *testing.T, m *CredentialMigrator) {
	t.Helper()
	for _, path := range []string{m.keyPath, m.backupPath(), m.backupKeyPath()} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("legacy material retained")
		}
	}

}

func TestMigrationAgentOnlyCanUseNone(t *testing.T) {
	m, backend, _ := migrationFixture(t)
	cfg, err := NewDefaultStore(m.path, m.keyPath).Load()
	if err != nil {
		t.Fatal(err)
	}
	clearMigrationConfiguration(cfg)
	cfg.Credential = &CredentialConfig{DefaultStore: "none", Stores: map[string]StoreConfig{"none": {Type: StoreTypeNone}}}
	if err := NewDefaultStore(m.path, m.keyPath).Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "none", DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "none"}); err != nil || report.Credentials != 0 {
		t.Fatalf("metadata migration: %+v, %v", report, err)
	}
	if backend.puts != 0 {
		t.Fatal("agent-only migration wrote credentials")
	}
}

// The failure matrix uses a cheap key fixture; verify encrypted-key unlock
// separately so race runs do not repeat bcrypt hundreds of times.
func TestMigrationEncryptedPrivateKeyFingerprint(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		name := "valid passphrase"
		if wrong {
			name = "wrong passphrase"
		}
		t.Run(name, func(t *testing.T) {
			m, backend, _ := migrationFixture(t)
			cfg, err := NewDefaultStore(m.path, m.keyPath).Load()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := cfg.Identities.Get("ops")
			data, err := os.ReadFile(id.KeyPath)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(data)
			private, err := sshcrypto.ParseRawPrivateKey(data)
			if err != nil {
				t.Fatal(err)
			}
			block, err := sshcrypto.MarshalPrivateKeyWithPassphrase(private, "", []byte("key-passphrase"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(id.KeyPath, pem.EncodeToMemory(block), 0600); err != nil {
				t.Fatal(err)
			}
			if wrong {
				id.Passphrase = "wrong-passphrase"
				cfg.Identities.Set("ops", id)
				if err := NewDefaultStore(m.path, m.keyPath).Save(cfg); err != nil {
					t.Fatal(err)
				}
			}
			_, err = m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"})
			if wrong {
				if err == nil || backend.puts != 0 {
					t.Fatal("wrong private-key passphrase accepted")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMigrationPreservesV1ReferencesAndCompletesFingerprint(t *testing.T) {
	m, backend, _ := migrationFixture(t)
	cfg, err := NewDefaultStore(m.path, m.keyPath).Load()
	if err != nil {
		t.Fatal(err)
	}
	clearMigrationConfiguration(cfg)
	ref := credential.Ref{StoreID: "vault", ItemID: "phase6-passphrase"}
	id, _ := cfg.Identities.Get("ops")
	id.PassphraseRef = &ref
	id.KeyFingerprint = ""
	cfg.Identities.Set("ops", id)
	backend.values[ref] = []byte("existing-passphrase")
	if err := NewDefaultStore(m.path, m.keyPath).Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault", DryRun: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = NewDefaultStore(m.path, m.keyPath).Load()
	if err != nil {
		t.Fatal(err)
	}
	id, _ = cfg.Identities.Get("ops")
	if id.PassphraseRef == nil || *id.PassphraseRef != ref || id.KeyFingerprint == "" || backend.puts != 0 {
		t.Fatal("existing ref was replaced or not bound to key")
	}
	if _, err := m.Finalize(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// macOS exposes its temporary directory through /var -> /private/var.
// Vault tests must use the physical path without weakening symlink rejection.
func physicalCredentialTestDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}
