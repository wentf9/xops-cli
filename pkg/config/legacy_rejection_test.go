package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPSettingsSchemaErrorDoesNotExposeValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("schema_version: must-not-leak\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := ReadMCPSettings(path)
	if !errors.Is(err, ErrSchemaValidation) || strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("unsafe schema diagnostic: %v", err)
	}
}

func TestRuntimeRejectsLegacyConfigurationWithoutChangingFiles(t *testing.T) {
	for _, raw := range []string{"", "identities: {}\n", "schema_version: 1\nidentities: {}\n", "schema_version: 1\nidentities:\n  admin:\n    password: must-not-be-published\n", "schema_version: 1\nidentities:\n  admin:\n    password: ENC:invalid\n"} {
		for _, keyExists := range []bool{false, true} {
			dir := t.TempDir()
			path, key := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "secret.key")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			if keyExists {
				if err := os.WriteFile(key, []byte("existing-legacy-key"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			store := NewDefaultStore(path, key).(TransactionStore)
			for _, load := range []func() error{
				func() error { _, err := NewDefaultStore(path, key).Load(); return err },
				func() error { _, err := store.LoadSnapshot(t.Context()); return err },
				func() error { _, err := ReadOnlyConfiguration(path, key); return err },
				func() error { _, _, err := ReadMCPSettings(path); return err },
				func() error {
					_, err := store.Transact(t.Context(), func(Snapshot) (*Configuration, error) { t.Error("legacy transaction ran mutator"); return nil, nil })
					return err
				},
			} {
				if err := load(); !errors.Is(err, ErrLegacyConfiguration) {
					t.Fatalf("legacy load accepted or misclassified: %v", err)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, []byte(raw)) {
				t.Fatalf("legacy source changed: %v", err)
			}
			data, err := os.ReadFile(key)
			if keyExists {
				if err != nil || string(data) != "existing-legacy-key" {
					t.Fatalf("legacy key changed: %v", err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("legacy key created: %v", err)
			}
		}
	}
}

func TestStoreRejectsLegacyWritesWithoutCreatingKey(t *testing.T) {
	for _, version := range []int{0, 1} {
		dir := t.TempDir()
		path, key := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "secret.key")
		before := []byte("schema_version: 2\n")
		if err := os.WriteFile(path, before, 0600); err != nil {
			t.Fatal(err)
		}
		cfg := cloneConfiguration(nil)
		cfg.SchemaVersion = version
		if err := NewDefaultStore(path, key).Save(cfg); !errors.Is(err, ErrLegacyConfiguration) {
			t.Fatalf("legacy save accepted: %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, before) {
			t.Fatalf("rejected save changed source: %v", err)
		}
		if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("legacy key created: %v", err)
		}
	}
}
