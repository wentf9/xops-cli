//go:build integration && (linux || windows || darwin)

package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/pkg/credential"
	"gopkg.in/yaml.v3"
)

func TestBackendMigrationOfflineRoundTrip(t *testing.T) {
	m, store, raw := backendMigrationFixture(t)
	cfg, err := UnmarshalV2(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Credential.Stores["file"] = DefaultCredentialConfig().Stores["file"]
	raw, err = yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	owner := NewEncryptedRuntime(t.Context(), m.path, nil)
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	m.registry = func(cfg *CredentialConfig) (*credential.Registry, error) {
		registry, err := owner.Registry(cfg)
		if err != nil {
			return nil, err
		}
		for _, id := range []string{"vault", "other"} {
			registry.Unregister(id)
			if err := registry.Register(id, store); err != nil {
				return nil, err
			}
		}
		return registry, nil
	}
	if report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "file", DryRun: true}); err != nil || report.Credentials != 3 {
		t.Fatalf("offline dry-run: %+v %v", report, err)
	}
	keyPath := filepath.Join(filepath.Dir(m.path), "credentials.key")
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry-run generated key")
	}
	var originalKey []byte
	for _, target := range []string{"file", "other", "file"} {
		report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: target})
		if err != nil || !report.Verified {
			t.Fatalf("target %s: %+v %v", target, report, err)
		}
		key, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if originalKey == nil {
			originalKey = key
		} else if !bytes.Equal(key, originalKey) {
			t.Fatal("existing offline key replaced")
		}
	}
}
