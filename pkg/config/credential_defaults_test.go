package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialDefaultsAreIndependent(t *testing.T) {
	first, second := DefaultCredentialConfig(), DefaultCredentialConfig()
	delete(first.Stores, "file")
	store, ok := second.Stores["file"]
	if !ok || store.Unlock != "key-file" || store.Path != "credentials" || store.KeyFile != "credentials.key" {
		t.Fatal("defaults share state or have unexpected paths")
	}
}

func TestExistingCredentialChoiceIsPreserved(t *testing.T) {
	for _, choice := range []string{"none", "custom"} {
		t.Run(choice, func(t *testing.T) {
			dir := t.TempDir()
			disk := NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "secret.key"))
			cfg, err := disk.Load()
			if err != nil {
				t.Fatal(err)
			}
			cfg.Credential = &CredentialConfig{DefaultStore: choice, RememberPrompted: "never", Stores: map[string]StoreConfig{choice: {Type: StoreTypeNone}}}
			if err := disk.Save(cfg); err != nil {
				t.Fatal(err)
			}
			got, err := disk.Load()
			if err != nil {
				t.Fatal(err)
			}
			if got.Credential.DefaultStore != choice || got.Credential.RememberPrompted != "never" {
				t.Fatal("explicit choice replaced")
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() == "credentials" || entry.Name() == "credentials.key" {
					t.Fatal("configuration load initialized vault")
				}
			}
		})
	}
}
