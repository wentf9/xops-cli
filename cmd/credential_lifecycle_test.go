package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func TestOfflineDoctorLifecycle(t *testing.T) {
	for _, state := range []string{"new", "referenced", "key-only", "partial", "read-only"} {
		t.Run(state, func(t *testing.T) {
			// Canonicalize the fixture: macOS /var and custom TMPDIR paths can
			// contain symlinks, which the production layout inspector rejects.
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatalf("resolve lifecycle test directory: %v", err)
			}
			t.Setenv("XOPS_CONFIG_DIR", dir)
			cfg := config.FileStoreDefaults(config.StoreConfig{Type: config.StoreTypeEncryptedFile, Path: filepath.Join(dir, "vault"), KeyFile: filepath.Join(dir, "key"), Unlock: "key-file"})
			inventory := &config.Configuration{Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString)}
			switch state {
			case "referenced":
				inventory.Identities.Set("test", models.Identity{LoginPasswordRef: &credential.Ref{StoreID: "file", ItemID: "existing"}})
			case "key-only":
				if err := os.WriteFile(cfg.KeyFile, []byte("existing"), 0600); err != nil {
					t.Fatal(err)
				}
			case "partial":
				if err := os.Mkdir(cfg.Path, 0700); err != nil {
					t.Fatal(err)
				}
			case "read-only":
				cfg.ReadOnly = true
			}
			item := checkOfflineDoctor(t.Context(), "file", cfg, inventory)
			want := "FAIL"
			if state == "new" {
				want = "WARN"
			}
			if item.Status != want {
				t.Fatalf("%+v want %s", item, want)
			}
			if state == "new" {
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("doctor modified directory: %v %v", entries, err)
				}
			}
		})
	}
}
