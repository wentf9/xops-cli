package config

import (
	"bytes"
	"context"
	"errors"
	"github.com/wentf9/xops-cli/pkg/credential"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func backendMigrationFixture(t *testing.T) (*CredentialMigrator, *migrationTestStore, []byte) {
	t.Helper()
	m, store, _ := migrationFixture(t)
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := UnmarshalV2(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Credential.Stores["other"] = StoreConfig{Type: StoreTypeHelper, Command: "/test/other", Timeout: time.Second}
	cfg.Credential.RememberPrompted = "never"
	cfg.Identities["shared"] = cfg.Identities["ops"]
	raw, err = yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return m, store, raw
}

func TestBackendMigrationRoundTripPreservesLegacyAndSharedRefs(t *testing.T) {
	m, store, _ := backendMigrationFixture(t)
	legacy := make(map[string][]byte)
	for _, path := range []string{m.statePath(), m.backupPath(), m.backupKeyPath(), m.keyPath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		legacy[path] = raw
	}
	for _, target := range []string{"other", "vault"} {
		report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: target})
		if err != nil || !report.Verified || !report.BackendMigration || report.Credentials != 3 {
			t.Fatalf("report=%+v err=%v", report, err)
		}
		raw, err := os.ReadFile(m.path)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := UnmarshalV2(raw)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Credential.DefaultStore != target || cfg.Credential.RememberPrompted != "never" {
			t.Fatal("default or recording policy incorrect")
		}
		if !reflect.DeepEqual(cfg.Identities["ops"], cfg.Identities["shared"]) {
			t.Fatal("shared refs split")
		}
		for _, ref := range backendRefs(cfg) {
			if ref.StoreID != target {
				t.Fatal("reference not migrated")
			}
		}
	}
	if len(store.values) != 9 {
		t.Fatalf("source items lost or duplicate writes: %d", len(store.values))
	}
	for path, expected := range legacy {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, expected) {
			t.Fatalf("legacy artifact changed: %s: %v", path, err)
		}
	}
	if _, err := m.Finalize(t.Context()); err != nil {
		t.Fatalf("legacy finalization after backend migration: %v", err)
	}
}

func TestBackendMigrationInterruptionsResumeImmutableRefs(t *testing.T) {
	for _, point := range []string{"backend_intent", "backend_backup", "backend_put:0", "backend_readback:0", "backend_put:2", "backend_readback:2", "backend_before_commit", "backend_committed", "backend_verified"} {
		t.Run(point, func(t *testing.T) {
			m, store, _ := backendMigrationFixture(t)
			stop := errors.New("injected interruption")
			m.checkpoint = func(step string) error {
				if step == point {
					return stop
				}
				return nil
			}
			if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "other"}); !errors.Is(err, stop) {
				t.Fatalf("checkpoint: %v", err)
			}
			before, err := m.loadBackendState()
			if err != nil {
				t.Fatal(err)
			}
			fresh := newTestMigrator(t, m.path, m.keyPath, store)
			report, err := fresh.Migrate(t.Context(), MigrationOptions{ToStore: "other"})
			if err != nil || !report.Verified {
				t.Fatalf("resume: %+v %v", report, err)
			}
			after, err := fresh.loadBackendState()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before.Entries, after.Entries) || store.puts != 6 {
				t.Fatal("resume replaced immutable refs")
			}
		})
	}
}

func TestBackendMigrationDryRunReadOnly(t *testing.T) {
	m, store, raw := backendMigrationFixture(t)
	report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "other", DryRun: true})
	if err != nil || !report.DryRun || report.Credentials != 3 {
		t.Fatalf("dry run: %+v %v", report, err)
	}
	got, err := os.ReadFile(m.path)
	if err != nil || !bytes.Equal(raw, got) {
		t.Fatal("dry run changed config")
	}
	if _, err := os.Stat(m.backendStatePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run wrote state")
	}
	if _, err := os.Stat(report.BackupPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run wrote backup")
	}
	if store.puts != 3 {
		t.Fatal("dry run wrote credentials")
	}
}

func TestBackendMigrationConflictAndCancellation(t *testing.T) {
	for _, mode := range []string{"conflict", "cancel", "uncertain"} {
		t.Run(mode, func(t *testing.T) {
			m, store, raw := backendMigrationFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			changed := append(bytes.Clone(raw), []byte("\n# concurrent edit\n")...)
			m.checkpoint = func(step string) error {
				if step == "backend_before_commit" && mode == "conflict" {
					return os.WriteFile(m.path, changed, 0600)
				}
				if step == "backend_backup" && mode == "cancel" {
					cancel()
					return ctx.Err()
				}
				return nil
			}
			if mode == "uncertain" {
				store.uncertain = true
			}
			_, err := m.Migrate(ctx, MigrationOptions{ToStore: "other"})
			if err == nil {
				t.Fatal("failure accepted")
			}
			got, readErr := os.ReadFile(m.path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			expected := raw
			if mode == "conflict" {
				expected = changed
				if !errors.Is(err, ErrConfigConflict) {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(got, expected) {
				t.Fatal("failed migration replaced configuration")
			}
			if mode == "uncertain" {
				store.uncertain = false
				if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "other"}); err != nil {
					t.Fatal(err)
				}
				if store.puts != 6 {
					t.Fatal("uncertain put repeated")
				}
			}
		})
	}
}

func TestBackendMigrationRestartAfterConcurrentEdit(t *testing.T) {
	m, store, raw := backendMigrationFixture(t)
	changed := append(bytes.Clone(raw), []byte("\n# concurrent edit\n")...)
	m.checkpoint = func(step string) error {
		if step == "backend_before_commit" {
			return os.WriteFile(m.path, changed, 0600)
		}
		return nil
	}
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "other"}); !errors.Is(err, ErrConfigConflict) {
		t.Fatal(err)
	}
	prior, err := os.ReadFile(m.backendStatePath())
	if err != nil {
		t.Fatal(err)
	}
	m.checkpoint = nil
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "other"}); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("conflict silently replaced: %v", err)
	}
	report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "other", Restart: true})
	if err != nil || !report.Verified {
		t.Fatalf("restart: %+v %v", report, err)
	}
	archived, err := os.ReadFile(m.backendStatePath() + "." + migrationDigest(prior) + ".bak")
	if err != nil || !bytes.Equal(archived, prior) {
		t.Fatal("previous plan lost")
	}
	if store.puts != 9 {
		t.Fatal("restart did not retain pending credentials")
	}
}

func TestBackendMigrationUncertainConfigurationWriteResumes(t *testing.T) {
	m, store, _ := backendMigrationFixture(t)
	original := m.write
	m.write = func(path string, data []byte, mode os.FileMode) (PersistResult, error) {
		result, err := original(path, data, mode)
		if err == nil && path == m.path {
			return PersistResult{Applied: true}, errors.New("injected directory sync failure")
		}
		return result, err
	}
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "other"}); err == nil {
		t.Fatal("uncertain commit accepted")
	}
	m.write = original
	report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "other"})
	if err != nil || !report.Verified || store.puts != 6 {
		t.Fatalf("resume: %+v %v puts=%d", report, err, store.puts)
	}
}

func TestBackendMigrationRejectsChangedDestination(t *testing.T) {
	m, store, raw := backendMigrationFixture(t)
	m.checkpoint = func(step string) error {
		if step == "backend_put:0" {
			store.mu.Lock()
			defer store.mu.Unlock()
			for ref := range store.values {
				if ref.StoreID == "other" {
					store.values[ref] = []byte("wrong value")
				}
			}
		}
		return nil
	}
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "other"}); err == nil {
		t.Fatal("read-back corruption accepted")
	}
	got, err := os.ReadFile(m.path)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("corrupt destination published")
	}
}

func TestBackendMigrationRecoveryFileFailures(t *testing.T) {
	for _, point := range []string{"intent", "backup", "configuration", "verification"} {
		t.Run(point, func(t *testing.T) {
			m, store, _ := backendMigrationFixture(t)
			original := m.write
			stateWrites := 0
			injected := errors.New("injected persistence failure")
			m.write = func(path string, data []byte, mode os.FileMode) (PersistResult, error) {
				if path == m.backendStatePath() {
					stateWrites++
				}
				fail := point == "intent" && path == m.backendStatePath() && stateWrites == 1 || point == "verification" && path == m.backendStatePath() && stateWrites == 2 || point == "configuration" && path == m.path || point == "backup" && strings.HasSuffix(path, ".bak")
				if fail {
					return PersistResult{}, injected
				}
				return original(path, data, mode)
			}
			if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "other"}); !errors.Is(err, injected) {
				t.Fatalf("failure not observed: %v", err)
			}
			m.write = original
			report, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "other"})
			if err != nil || !report.Verified || store.puts != 6 {
				t.Fatalf("recovery: %+v %v puts=%d", report, err, store.puts)
			}
		})
	}
}

func TestBackendMigrationRejectsUnavailableSourceAndReadOnlyTarget(t *testing.T) {
	for _, mode := range []string{"source", "readonly"} {
		t.Run(mode, func(t *testing.T) {
			m, store, raw := backendMigrationFixture(t)
			if mode == "source" {
				store.locked = true
			} else {
				cfg, err := UnmarshalV2(raw)
				if err != nil {
					t.Fatal(err)
				}
				target := cfg.Credential.Stores["other"]
				target.ReadOnly = true
				cfg.Credential.Stores["other"] = target
				raw, err = yaml.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(m.path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, dry := range []bool{true, false} {
				if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "other", DryRun: dry}); err == nil {
					t.Fatal("unavailable migration accepted")
				}
			}
			got, err := os.ReadFile(m.path)
			if err != nil || !bytes.Equal(raw, got) || store.puts != 3 {
				t.Fatal("failed migration changed config or credentials")
			}
		})
	}
}

func TestBackendMigrationExpiryComparison(t *testing.T) {
	expiry := time.Now().Add(time.Hour)
	a := credential.NewSecretWithExpiry([]byte("test-value"), expiry)
	defer a.Zero()
	b := credential.NewSecret([]byte("test-value"))
	defer b.Zero()
	if sameMigrationSecret(a, b) {
		t.Fatal("loss of expiry accepted")
	}
	b.ExpiresAt = &expiry
	if !sameMigrationSecret(a, b) {
		t.Fatal("preserved expiry rejected")
	}
	changed := expiry.Add(time.Second)
	b.ExpiresAt = &changed
	if sameMigrationSecret(a, b) {
		t.Fatal("changed expiry accepted")
	}
}
