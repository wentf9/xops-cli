package config

import (
	"bytes"
	"os"
	"testing"
)

func TestAutomaticMigrationPreservesSelectedBackend(t *testing.T) {
	m, _, _ := migrationFixture(t)
	report, err := m.AutoMigrate(t.Context())
	if err != nil || !report.Verified || report.Store != "vault" {
		t.Fatalf("automatic migration: %+v, %v", report, err)
	}
	report, err = m.AutoMigrate(t.Context())
	if err != nil || report.Verified {
		t.Fatalf("already migrated: %+v, %v", report, err)
	}
	if _, err := os.Stat(m.backupPath()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.keyPath); err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticMigrationNeverStillAllowsExplicitMigration(t *testing.T) {
	m, backend, raw := migrationFixture(t)
	raw = bytes.Replace(raw, []byte("remember_prompted: ask"), []byte("remember_prompted: never"), 1)
	if !bytes.Contains(raw, []byte("remember_prompted: never")) {
		t.Fatal("missing policy fixture")
	}
	if err := os.WriteFile(m.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := m.AutoMigrate(t.Context())
	if err != nil || report.Verified || backend.puts != 0 {
		t.Fatalf("never migrated: %+v, %v", report, err)
	}
	after, err := os.ReadFile(m.path)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("opt out changed configuration")
	}
	report, err = m.Migrate(t.Context(), MigrationOptions{ToStore: "vault"})
	if err != nil || !report.Verified {
		t.Fatalf("explicit migration rejected: %+v, %v", report, err)
	}
}

func TestAutomaticMigrationFailureRetainsSource(t *testing.T) {
	m, backend, raw := migrationFixture(t)
	backend.putFailure = true
	if _, err := m.AutoMigrate(t.Context()); err == nil {
		t.Fatal("failed backend accepted")
	}
	after, err := os.ReadFile(m.path)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("failed upgrade changed legacy source")
	}
	backend.putFailure = false
	report, err := m.AutoMigrate(t.Context())
	if err != nil || !report.Verified {
		t.Fatalf("retry: %+v, %v", report, err)
	}
}
