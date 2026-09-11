package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wentf9/xops-cli/pkg/models"
)

func TestNewInstallationDefaultsToV2(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path, key := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "secret.key")
	store := NewDefaultStore(path, key)
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SchemaVersion != 2 || cfg.Credential == nil || cfg.Credential.DefaultStore != "file" || cfg.Credential.RememberPrompted != "always" || cfg.Credential.Stores["file"].Type != StoreTypeEncryptedFile {
		t.Fatal("missing v2 new-install defaults")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("loading absent configuration wrote a file: %v", err)
	}
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalV2(data); err != nil {
		t.Fatalf("new configuration is not strict v2: %v", err)
	}
	// All secret kinds must fail closed, without falling back to AES writes.
	for _, kind := range []string{"password", "passphrase", "privilege"} {
		t.Run(kind, func(t *testing.T) {
			modified := cloneConfiguration(cfg)
			id := models.Identity{User: "ops", AuthType: "password"}
			node := models.Node{HostRef: "h", IdentityRef: "i"}
			switch kind {
			case "password":
				id.Password = "must-not-persist"
			case "passphrase":
				id.Passphrase = "must-not-persist"
			case "privilege":
				node.SuPwd = "must-not-persist"
			}
			modified.Identities.Set("i", id)
			modified.Hosts.Set("h", models.Host{Address: "localhost", Port: 22})
			modified.Nodes.Set("n", node)
			if err := store.Save(modified); !errors.Is(err, ErrSchemaValidation) {
				t.Fatalf("expected secret rejection, got %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(data) {
				t.Fatalf("rejected save changed disk contents: %v", err)
			}
		})
	}
	if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("v2 created legacy key: %v", err)
	}
}

func TestExampleConfigurationIsStrictV2(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "xops_config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalV2(data); err != nil {
		t.Fatalf("example configuration must be valid v2: %v", err)
	}
}
