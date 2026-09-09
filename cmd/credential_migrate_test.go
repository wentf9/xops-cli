package cmd

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestCredentialMigrationCLI(t *testing.T) {
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0]})
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := cfg.Identities.Get("admin")
	id.Password = "migration-cli-secret"
	cfg.Identities.Set("admin", id)
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	path, key, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := NewCmdCredential()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"migrate", "--to", "test", "--dry-run"})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("dry run modified configuration")
	}
	if _, err := os.Stat(path + ".migration.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run created a migration state")
	}
	cmd = NewCmdCredential()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"migrate", "--to", "test"})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	cfg, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	id, _ = cfg.Identities.Get("admin")
	if cfg.SchemaVersion != 2 || id.Password != "" || id.LoginPasswordRef == nil {
		t.Fatal("CLI did not migrate credentials")
	}
	if strings.Contains(output.String(), "migration-cli-secret") {
		t.Fatal("command leaked a secret")
	}
	cmd = NewCmdCredential()
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"finalize-migration"})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("finalized configuration still requires key")
	}
}

func TestCredentialMigrationRequiresExplicitDestination(t *testing.T) {
	setupTestEnvironment(t)
	cmd := NewCmdCredential()
	cmd.SetArgs([]string{"migrate"})
	if err := cmd.ExecuteContext(t.Context()); err == nil {
		t.Fatal("missing destination accepted")
	}
	path, _, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing destination created a configuration")
	}
}
