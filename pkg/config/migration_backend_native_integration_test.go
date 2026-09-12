//go:build integration && (linux || windows || darwin) && (amd64 || arm64)

package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
	"gopkg.in/yaml.v3"
)

// This opt-in test writes disposable random references to the real system
// backend. Native CI supplies an isolated, unlocked service and requires success.
func TestBackendMigrationNativeSystemRoundTrip(t *testing.T) {
	if os.Getenv("XOPS_TEST_NATIVE_MIGRATION") != "1" {
		t.Skip("requires an explicitly provisioned native credential service")
	}
	m, nativeID, native := nativeBackendMigrationFixture(t)
	var nativeRefs []credential.Ref
	defer func() { cleanNativeMigrationRefs(t, m, nativeID, native, nativeRefs) }()
	keyPath := filepath.Join(filepath.Dir(m.path), "credentials.key")
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyBefore)
	for _, target := range []string{nativeID, "file"} {
		if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: target, DryRun: true}); err != nil {
			t.Fatal(err)
		}
		report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: target})
		if err != nil || !report.Verified || report.Credentials != 3 {
			t.Fatalf("native migration to %s: %+v, %v", target, report, err)
		}
		state, err := m.loadBackendState()
		if err != nil {
			t.Fatal(err)
		}
		if target == nativeID {
			for _, entry := range state.Entries {
				nativeRefs = append(nativeRefs, entry.Target)
			}
		}
	}
	keyAfter, err := os.ReadFile(keyPath)
	defer clear(keyAfter)
	if err != nil || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatalf("native round-trip replaced offline key: %v", err)
	}
	for _, ref := range nativeRefs {
		secret, err := native.Get(t.Context(), ref)
		secret.Zero()
		if err != nil {
			t.Fatalf("migration deleted native source: %v", err)
		}
	}
}

func nativeBackendMigrationFixture(t *testing.T) (*CredentialMigrator, string, credential.Store) {
	t.Helper()
	m, source, raw := backendMigrationFixture(t)
	cfg, err := UnmarshalV2(raw)
	if err != nil {
		t.Fatal(err)
	}
	nativeID := "native-" + credential.GenerateItemID()
	cfg.Credential.Stores["file"] = DefaultCredentialConfig().Stores["file"]
	cfg.Credential.Stores[nativeID] = StoreConfig{Type: StoreTypeSystem, Timeout: 10 * time.Second}
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
	// Seed the offline source using the existing three-purpose fixture.
	m.registry = func(cfg *CredentialConfig) (*credential.Registry, error) {
		registry, err := owner.Registry(cfg)
		if err != nil {
			return nil, err
		}
		for _, id := range []string{"vault", "other"} {
			registry.Unregister(id)
			if err := registry.Register(id, source); err != nil {
				return nil, err
			}
		}
		return registry, nil
	}
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "file"}); err != nil {
		t.Fatal(err)
	}
	// All subsequent copying, read-back verification and recovery use real
	// backends, with no replacement of the native system store.
	m.registry = owner.Registry
	registry, err := owner.Registry(&cfg.Credential)
	if err != nil {
		t.Fatal(err)
	}
	native, err := registry.GetStore(nativeID)
	if err != nil {
		t.Fatal(err)
	}
	return m, nativeID, native
}

func cleanNativeMigrationRefs(t *testing.T, m *CredentialMigrator, nativeID string, native credential.Store, refs []credential.Ref) {
	t.Helper()

	// Recover the intended targets too if migration stopped before commit.
	state, err := m.loadBackendState()
	if err != nil {
		t.Error(err)
	} else if state != nil && state.Store == nativeID {
		for _, entry := range state.Entries {
			refs = append(refs, entry.Target)
		}
	}
	for _, ref := range refs {
		if err := native.Delete(t.Context(), ref); err != nil && !errors.Is(err, credential.ErrCredentialNotFound) {
			t.Errorf("clean native test reference: %v", err)
		}
	}
}
