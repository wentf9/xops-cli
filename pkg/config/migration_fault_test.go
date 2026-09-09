package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

func TestMigrationFileWriteFailuresAreRecoverable(t *testing.T) {
	for _, stage := range []string{"intent", "backup", "key_backup", "commit", "applied_not_durable", "mark_committed"} {
		t.Run(stage, func(t *testing.T) {
			m, store, _ := migrationFixture(t)
			failure := errors.New("injected storage failure")
			m.write = func(path string, data []byte, mode os.FileMode) (PersistResult, error) {
				fail := stage == "intent" && path == m.statePath() || stage == "backup" && path == m.backupPath() || stage == "key_backup" && path == m.backupKeyPath() || stage == "commit" && path == m.path || stage == "mark_committed" && path == m.statePath() && bytes.Contains(data, []byte(`"phase": "committed"`))
				if fail {
					return PersistResult{}, failure
				}
				result, err := atomicWriteFile(path, data, mode)
				if err == nil && stage == "applied_not_durable" && path == m.path {
					return PersistResult{Applied: true}, failure
				}
				return result, err
			}
			if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); !errors.Is(err, failure) {
				t.Fatalf("fault not reached: %v", err)
			}
			assertLegacyRecoverable(t, m, store)
			if _, err := newTestMigrator(t, m.path, m.keyPath, store).Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFinalizeCrashBoundariesResume(t *testing.T) {
	for _, point := range []string{"finalize_verified", "finalizing", "remove_key", "remove_backup", "remove_backup_key"} {
		t.Run(point, func(t *testing.T) {
			m, store, _ := migrationFixture(t)
			if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil {
				t.Fatal(err)
			}
			crash := errors.New("simulated finalize exit")
			m.checkpoint = func(step string) error {
				if step == point {
					return crash
				}
				return nil
			}
			if _, err := m.Finalize(t.Context()); !errors.Is(err, crash) {
				t.Fatalf("checkpoint not reached: %v", err)
			}
			assertLegacyRecoverable(t, m, store)
			fresh := newTestMigrator(t, m.path, m.keyPath, store)
			if report, err := fresh.Finalize(t.Context()); err != nil || !report.Finalized {
				t.Fatalf("resume: %+v, %v", report, err)
			}
		})
	}
}

func TestFinalizeRejectsMissingOrIncorrectCredentials(t *testing.T) {
	for _, mode := range []string{"locked", "corrupt", "missing", "changed_key", "changed_config"} {
		t.Run(mode, func(t *testing.T) {
			m, store, _ := migrationFixture(t)
			if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "locked":
				store.locked = true
			case "corrupt":
				store.corrupt = true
			case "missing":
				for ref := range store.values {
					delete(store.values, ref)
					break
				}
			case "changed_key":
				if err := os.WriteFile(m.keyPath, bytes.Repeat([]byte{7}, 32), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed_config":
				m.checkpoint = func(step string) error {
					if step == "finalize_verified" {
						data, err := os.ReadFile(m.path)
						if err != nil {
							return err
						}
						return os.WriteFile(m.path, append(data, []byte("\n# concurrent\n")...), 0600)
					}
					return nil
				}
			}
			if _, err := m.Finalize(t.Context()); err == nil {
				t.Fatal("unsafe finalization succeeded")
			}
			for _, path := range []string{m.keyPath, m.backupPath(), m.backupKeyPath()} {
				if _, err := os.Stat(path); err != nil {
					t.Fatal("failed finalize removed legacy materials")
				}
			}
		})
	}
}

func TestV2LoadAndSaveNeverRequireLegacyKey(t *testing.T) {
	m, _, _ := migrationFixture(t)
	if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.keyPath); err != nil {
		t.Fatal(err)
	}
	store := NewDefaultStore(m.path, m.keyPath)
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := cfg.Identities.Get("ops")
	id.Password = "must-not-persist"
	cfg.Identities.Set("ops", id)
	if err := store.Save(cfg); err == nil {
		t.Fatal("v2 accepted a plaintext write")
	}
	if _, err := os.Stat(m.keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("v2 path created a key")
	}
}

func TestMigrationCancellationPreservesSourceAndPendingRefs(t *testing.T) {
	m, backend, raw := migrationFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	m.checkpoint = func(step string) error {
		if step == "put:0" {
			cancel()
		}
		return nil
	}
	if _, err := m.Migrate(ctx, MigrationOptions{ToStore: "vault"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	current, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, current) {
		t.Fatal("canceled migration changed configuration")
	}
	if _, err := newTestMigrator(t, m.path, m.keyPath, backend).Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil {
		t.Fatal(err)
	}
	if backend.puts != 3 {
		t.Fatal("resume after cancellation rewrote a credential")
	}
}
