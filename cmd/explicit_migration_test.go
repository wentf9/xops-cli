package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"gopkg.in/yaml.v3"
)

func TestLegacyStartupNeverInvokesMigrationBackend(t *testing.T) {
	path, before, marker := explicitMigrationHelperFixture(t, true)
	root := newRootCmd()
	initRootFlags(root)
	registerCommands(root)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"exec", "--host", "node", "-c", "uptime"})
	if err := root.ExecuteContext(t.Context()); !errors.Is(err, config.ErrLegacyConfiguration) {
		t.Fatalf("legacy startup accepted: %v", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy startup invoked credential backend: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("legacy startup changed config: %v", err)
	}
	if strings.Contains(out.String(), "startup-migration-secret") {
		t.Fatal("startup leaked credentials")
	}
}

func TestExplicitMigrationStillAllowsInteractiveHelper(t *testing.T) {
	_, _, marker := explicitMigrationHelperFixture(t, false)
	command := NewCmdCredential()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"migrate", "--to", "test"})
	if err := command.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("explicit migration did not invoke helper: %v", err)
	}
}

func explicitMigrationHelperFixture(t *testing.T, nonInteractive bool) (string, []byte, string) {
	t.Helper()
	initCredentialPolicyTestI18n(t)
	store := phase6Config(t, config.StoreConfig{Type: config.StoreTypeHelper, Command: os.Args[0], NonInteractive: nonInteractive})
	cfg, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Credential.RememberPrompted = "always"
	id, _ := cfg.Identities.Get("admin")
	id.Password = "startup-migration-secret"
	cfg.Identities.Set("admin", id)
	cfg.SchemaVersion = 1
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path, _, err := utils.GetConfigFilePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "helper-called")
	t.Setenv("TEST_HELPER_CALL_FILE", marker)
	return path, before, marker
}
