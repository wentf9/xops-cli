package config

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/credential"
)

// This fake backend is outside the migrator process and survives os.Exit.
type durableMigrationBackend struct{ dir string }

func (s durableMigrationBackend) Get(_ context.Context, ref credential.Ref) (credential.Secret, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, ref.ItemID))
	if errors.Is(err, os.ErrNotExist) {
		return credential.Secret{}, credential.ErrCredentialNotFound
	}
	if err != nil {
		return credential.Secret{}, err
	}
	return credential.Secret{Value: data}, nil
}
func (s durableMigrationBackend) Put(_ context.Context, ref credential.Ref, secret credential.Secret) error {
	_, err := atomicWriteFile(filepath.Join(s.dir, ref.ItemID), secret.Value, 0600)
	return err
}
func (s durableMigrationBackend) Delete(context.Context, credential.Ref) error {
	return errors.New("unexpected migration credential deletion")
}

func crashMigrator(path, key, backend string) (*CredentialMigrator, error) {
	m, err := NewCredentialMigrator(path, key)
	if err != nil {
		return nil, err
	}
	m.registry = func(*CredentialConfig) (*credential.Registry, error) {
		registry := credential.NewRegistry()
		if err := registry.Register("vault", durableMigrationBackend{dir: backend}); err != nil {
			return nil, err
		}
		return registry, nil
	}
	return m, nil
}

func TestMigrationCrashProcess(t *testing.T) {
	if os.Getenv("XOPS_TEST_MIGRATION_CRASH") != "1" {
		return
	}
	m, err := crashMigrator(os.Getenv("XOPS_TEST_MIGRATION_PATH"), os.Getenv("XOPS_TEST_MIGRATION_KEY"), os.Getenv("XOPS_TEST_MIGRATION_BACKEND"))
	if err != nil {
		t.Fatal(err)
	}
	m.checkpoint = func(step string) error {
		if step == os.Getenv("XOPS_TEST_MIGRATION_POINT") {
			os.Exit(86)
		}
		return nil
	}
	if os.Getenv("XOPS_TEST_MIGRATION_FINALIZE") == "1" {
		_, err = m.Finalize(t.Context())
	} else {
		_, err = m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"})
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("crash checkpoint was not reached")
}

func TestMigrationActualProcessCrashRecovery(t *testing.T) {
	points := []string{"target_validated", "intent", "backup", "key_backup", "decoded", "put:0", "readback:0", "put:1", "readback:1", "put:2", "readback:2", "before_commit", "committed", "verified", "finalize_verified", "finalizing", "remove_key", "remove_backup", "remove_backup_key"}
	for i, point := range points {
		t.Run(point, func(t *testing.T) {
			fixture, _, _ := migrationFixture(t)
			backend := t.TempDir()
			m, err := crashMigrator(fixture.path, fixture.keyPath, backend)
			if err != nil {
				t.Fatal(err)
			}
			finalize := i >= 14
			if finalize {
				if _, err := m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil {
					t.Fatal(err)
				}
			}
			runMigrationCrash(t, m, backend, point, finalize)
			fresh, err := crashMigrator(m.path, m.keyPath, backend)
			if err != nil {
				t.Fatal(err)
			}
			if finalize {
				if report, err := fresh.Finalize(t.Context()); err != nil || !report.Finalized {
					t.Fatalf("finalize recovery: %+v, %v", report, err)
				}
			} else {
				if report, err := fresh.Migrate(t.Context(), MigrationOptions{ToStore: "vault"}); err != nil || !report.Verified {
					t.Fatalf("migration recovery: %+v, %v", report, err)
				}
			}
			raw, err := os.ReadFile(m.path)
			if err != nil {
				t.Fatal(err)
			}
			if err := fresh.verifyV2(t.Context(), raw, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func runMigrationCrash(t *testing.T, m *CredentialMigrator, backend, point string, finalize bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMigrationCrashProcess$")
	cmd.Env = append(os.Environ(), "XOPS_TEST_MIGRATION_CRASH=1", "XOPS_TEST_MIGRATION_PATH="+m.path, "XOPS_TEST_MIGRATION_KEY="+m.keyPath, "XOPS_TEST_MIGRATION_BACKEND="+backend, "XOPS_TEST_MIGRATION_POINT="+point)
	if finalize {
		cmd.Env = append(cmd.Env, "XOPS_TEST_MIGRATION_FINALIZE=1")
	}
	output, err := cmd.CombinedOutput()
	var exited *exec.ExitError
	if !errors.As(err, &exited) || exited.ExitCode() != 86 {
		t.Fatalf("child did not crash at requested boundary: %v, %s", err, output)
	}
}
