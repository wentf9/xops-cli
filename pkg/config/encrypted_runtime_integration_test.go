//go:build integration && linux && amd64

package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/internal/credentialfile"
	"github.com/wentf9/xops-cli/internal/kdfhelper"
	"github.com/wentf9/xops-cli/pkg/credential"
)

func TestEncryptedRuntimeRegistry(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, bytes.Repeat([]byte{42}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	owner := NewEncryptedRuntime(t.Context(), filepath.Join(dir, "config.yaml"), nil)
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	cfg := StoreConfig{Type: StoreTypeEncryptedFile, Path: "vault", Unlock: "key-file", KeyFile: "key", CacheTTL: time.Minute}
	registry, err := owner.Registry(&CredentialConfig{Stores: map[string]StoreConfig{"offline": cfg}})
	if err != nil {
		t.Fatal(err)
	}
	// Registry creation neither opens nor initializes an absent vault.
	if _, err := os.Stat(filepath.Join(dir, "vault")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	material := credentialfile.Wrapping{Mode: "key-file", KeyFile: key}
	if _, err := owner.Vaults().Init(t.Context(), filepath.Join(dir, "vault"), "offline", material); err != nil {
		if errors.Is(err, credentialfile.ErrUnsupported) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	store, err := registry.GetStore("offline")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(*credential.CachedStore); ok {
		t.Fatal("generic cache wraps offline vault")
	}
	ref := credential.Ref{StoreID: "offline", ItemID: "test"}
	secret := credential.NewSecret([]byte("public-registry-value"))
	defer secret.Zero()
	ctx := credential.WithoutInteraction(t.Context())
	if err := store.Put(ctx, ref, secret); err != nil {
		t.Fatal(err)
	}
	got, err := registry.Resolve(ctx, ref)
	got.Zero()
	if err != nil {
		t.Fatal(err)
	}
	same, err := owner.Store(ctx, "offline", cfg)
	if err != nil {
		t.Fatal(err)
	}
	again, err := owner.Store(ctx, "offline", cfg)
	if err != nil || same != again {
		t.Fatal("duplicate handles", err)
	}
	if err := owner.Lock(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	got, err = registry.Resolve(ctx, ref)
	got.Zero()
	if err == nil {
		t.Fatal("cache bypassed lock and missing key")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	got, err = registry.Resolve(context.Background(), ref)
	got.Zero()
	if err == nil {
		t.Fatal("closed owner allowed read")
	}
}

type fileTestPrompt struct{ calls int }

func (p *fileTestPrompt) Password(context.Context, string) ([]byte, error) {
	p.calls++
	return []byte("public-master-password"), nil
}

type fileTestDeriver struct{}

func (fileTestDeriver) Derive(context.Context, kdfhelper.Request) ([]byte, error) {
	return bytes.Repeat([]byte{19}, 32), nil
}

func TestEncryptedRuntimeNonInteractivePromptCache(t *testing.T) {
	dir := t.TempDir()
	prompt := &fileTestPrompt{}
	owner := &EncryptedRuntime{vaults: credentialfile.NewRuntime(t.Context(), prompt, fileTestDeriver{}), stores: make(map[encryptedBackendKey]*encryptedBackend)}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(dir, "vault")
	material := credentialfile.Wrapping{Mode: "prompt", Password: []byte("public-master-password")}
	if _, err := owner.Vaults().Init(t.Context(), path, "offline", material); err != nil {
		if errors.Is(err, credentialfile.ErrUnsupported) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	cfg := StoreConfig{Type: StoreTypeEncryptedFile, Path: path, Unlock: "prompt", CacheTTL: time.Minute}
	registry, err := owner.Registry(&CredentialConfig{Stores: map[string]StoreConfig{"offline": cfg}})
	if err != nil {
		t.Fatal(err)
	}
	st, err := registry.GetStore("offline")
	if err != nil {
		t.Fatal(err)
	}
	ref := credential.Ref{StoreID: "offline", ItemID: "example"}
	got, err := registry.Resolve(credential.WithoutInteraction(t.Context()), ref)
	got.Zero()
	if !errors.Is(err, credential.ErrCredentialStoreLocked) || prompt.calls != 0 {
		t.Fatal("cold noninteractive prompted", err)
	}
	secret := credential.NewSecret([]byte("public-value"))
	defer secret.Zero()
	if err := st.Put(t.Context(), ref, secret); err != nil {
		t.Fatal(err)
	}
	got, err = registry.Resolve(t.Context(), ref)
	got.Zero()
	if err != nil {
		t.Fatal(err)
	}
	calls := prompt.calls
	got, err = registry.Resolve(credential.WithoutInteraction(t.Context()), ref)
	got.Zero()
	if err != nil || prompt.calls != calls {
		t.Fatal("already unlocked noninteractive access failed", err)
	}
	if err := owner.Lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, err = registry.Resolve(credential.WithoutInteraction(t.Context()), ref)
	got.Zero()
	if !errors.Is(err, credential.ErrCredentialStoreLocked) || prompt.calls != calls {
		t.Fatal("locked session prompted or returned cached data", err)
	}
}

func TestEncryptedMigrationAndFinalize(t *testing.T) {
	migrator, _, _ := migrationFixture(t)
	disk := NewDefaultStore(migrator.path, migrator.keyPath)
	cfg, err := disk.Load()
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(filepath.Dir(migrator.path), "offline.key")
	if err := os.WriteFile(key, bytes.Repeat([]byte{63}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(filepath.Dir(migrator.path), "vault")
	cfg.Credential.Stores["vault"] = StoreConfig{Type: StoreTypeEncryptedFile, Path: vault, Unlock: "key-file", KeyFile: key}
	if err := disk.Save(cfg); err != nil {
		t.Fatal(err)
	}
	owner := NewEncryptedRuntime(t.Context(), migrator.path, nil)
	defer func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := owner.Vaults().Init(t.Context(), vault, "vault", credentialfile.Wrapping{Mode: "key-file", KeyFile: key}); err != nil {
		if errors.Is(err, credentialfile.ErrUnsupported) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	migrator.WithRegistryFactory(owner.Registry)
	report, err := migrator.Migrate(credential.WithoutInteraction(t.Context()), MigrationOptions{ToStore: "vault"})
	if err != nil || !report.Verified || report.Credentials != 3 {
		t.Fatalf("migration: %+v %v", report, err)
	}
	if _, err := migrator.Finalize(credential.WithoutInteraction(t.Context())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(key); err != nil {
		t.Fatal("finalize removed offline key", err)
	}
	if _, err := os.Stat(filepath.Join(vault, "CURRENT")); err != nil {
		t.Fatal("finalize removed vault", err)
	}
}

func TestEncryptedMigrationRejectsLegacyKeyBeforeWrites(t *testing.T) {
	m, _, _ := migrationFixture(t)
	disk := NewDefaultStore(m.path, m.keyPath)
	cfg, err := disk.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Credential.Stores["vault"] = StoreConfig{Type: StoreTypeEncryptedFile, Path: filepath.Join(filepath.Dir(m.path), "vault"), Unlock: "key-file", KeyFile: m.keyPath}
	if err := disk.Save(cfg); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); !errors.Is(err, ErrConfigConflict) {
		t.Fatal("overlap not rejected", err)
	}
	after, err := os.ReadFile(m.path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("configuration changed", err)
	}
	if _, err := os.Stat(m.statePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("intent created", err)
	}
	if _, err := os.Stat(m.keyPath); err != nil {
		t.Fatal("legacy key lost", err)
	}
}

func TestEncryptedFinalizeProtectsChangedKeyConfiguration(t *testing.T) {
	m, _, _ := migrationFixture(t)
	disk := NewDefaultStore(m.path, m.keyPath)
	cfg, err := disk.Load()
	if err != nil {
		t.Fatal(err)
	}
	keyData, err := os.ReadFile(m.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyData)
	path := filepath.Join(filepath.Dir(m.path), "vault")
	key := filepath.Join(filepath.Dir(m.path), "independent.key")
	if err := os.WriteFile(key, keyData, 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Credential.Stores["vault"] = StoreConfig{Type: StoreTypeEncryptedFile, Path: path, Unlock: "key-file", KeyFile: key}
	if err := disk.Save(cfg); err != nil {
		t.Fatal(err)
	}
	owner := NewEncryptedRuntime(t.Context(), m.path, nil)
	defer func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := owner.Vaults().Init(t.Context(), path, "vault", credentialfile.Wrapping{Mode: "key-file", KeyFile: key}); err != nil {
		if errors.Is(err, credentialfile.ErrUnsupported) {
			t.Skip(err)
		}
		t.Fatal(err)
	}
	m.WithRegistryFactory(owner.Registry)
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = disk.Load()
	if err != nil {
		t.Fatal(err)
	}
	selected := cfg.Credential.Stores["vault"]
	selected.KeyFile = m.keyPath
	cfg.Credential.Stores["vault"] = selected
	if err := disk.Save(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Finalize(t.Context()); !errors.Is(err, ErrConfigConflict) {
		t.Fatal("finalize accepted changed overlap", err)
	}
	for _, file := range []string{m.keyPath, m.backupPath(), m.backupKeyPath()} {
		if _, err := os.Stat(file); err != nil {
			t.Fatal("cleanup deleted protected material", err)
		}
	}
}
