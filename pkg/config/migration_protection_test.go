package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationRejectsBackendKeyOverlap(t *testing.T) {
	dir := t.TempDir()
	m, err := NewCredentialMigrator(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.keyPath, make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{m.keyPath, "secret.key", m.backupKeyPath(), m.backupPath()} {
		cfg := &CredentialConfig{Stores: map[string]StoreConfig{"offline": {Type: StoreTypeEncryptedFile, Path: filepath.Join(dir, "vault"), Unlock: "key-file", KeyFile: key}}}
		if err := m.protectBackendKeys(cfg); !errors.Is(err, ErrConfigConflict) {
			t.Fatalf("overlap accepted %q: %v", key, err)
		}
	}
	for _, kind := range []string{"symlink", "hardlink"} {
		path := filepath.Join(dir, kind)
		var err error
		if kind == "symlink" {
			err = os.Symlink(m.keyPath, path)
		} else {
			err = os.Link(m.keyPath, path)
		}
		if err != nil {
			t.Logf("%s unavailable: %v", kind, err)
			continue
		}
		cfg := &CredentialConfig{Stores: map[string]StoreConfig{"offline": {Type: StoreTypeEncryptedFile, Path: filepath.Join(dir, "vault"), Unlock: "key-file", KeyFile: path}}}
		if err := m.protectBackendKeys(cfg); !errors.Is(err, ErrConfigConflict) {
			t.Fatalf("alias accepted %s: %v", kind, err)
		}
	}
}
