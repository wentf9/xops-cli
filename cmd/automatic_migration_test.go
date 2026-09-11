package cmd

import (
	"bytes"
	"errors"
	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAutomaticMigrationEligibility(t *testing.T) {
	for _, tc := range []struct {
		name             string
		never, dry, want bool
	}{
		{name: "ssh", want: true}, {name: "sftp", want: true}, {name: "exec", want: true},
		{name: "mcp", want: true}, {name: "credential"}, {name: "help"}, {name: "completion"},
		{name: "ssh", never: true}, {name: "play", dry: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := &cobra.Command{Use: "xops"}
			child := &cobra.Command{Use: tc.name}
			root.AddCommand(child)
			policy := ""
			if tc.never {
				policy = "never"
			}
			child.Flags().String("remember", policy, "")
			child.Flags().Bool("dry-run", tc.dry, "")
			if got := automaticMigrationEligible(child); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// Exercise the actual startup migrator and helper capability guard, before
// MCP/Playbook/connector code has a chance to restrict credential interaction.
func TestAutomaticMigrationStartupDoesNotInvokeInteractiveHelper(t *testing.T) {
	for _, name := range []string{"mcp", "mcp serve", "play", "exec", "scp", "tui", "ssh"} {
		t.Run(name, func(t *testing.T) {
			path, before, marker := automaticMigrationHelperFixture(t, false)
			root := &cobra.Command{Use: "xops"}
			command := &cobra.Command{Use: strings.Fields(name)[0]}
			root.AddCommand(command)
			if name == "mcp serve" {
				child := &cobra.Command{Use: "serve"}
				command.AddCommand(child)
				command = child
			}
			command.SetContext(t.Context())
			var stdout, stderr bytes.Buffer
			command.SetOut(&stdout)
			command.SetErr(&stderr)
			if err := autoMigrateConfiguration(command); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("startup invoked interactive helper: %v", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("failed automatic migration changed source: %v", err)
			}
			if stdout.Len() != 0 || !strings.Contains(stderr.String(), i18n.T("credential_auto_migration_failed")) {
				t.Fatalf("incorrect startup warning: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), "startup-migration-secret") {
				t.Fatal("startup warning leaked a credential")
			}
		})
	}
}

func TestAutomaticMigrationStartupAllowsNonInteractiveHelper(t *testing.T) {
	path, _, marker := automaticMigrationHelperFixture(t, true)
	command := &cobra.Command{Use: "mcp"}
	command.SetContext(t.Context())
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	if err := autoMigrateConfiguration(command); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("non-interactive helper not invoked: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.UnmarshalV2(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ref := cfg.Identities["admin"].LoginPasswordRef; ref == nil || ref.StoreID != "test" {
		t.Fatal("startup did not migrate credentials")
	}
	if !strings.Contains(output.String(), i18n.T("credential_auto_migration_complete")) || strings.Contains(output.String(), "startup-migration-secret") {
		t.Fatalf("incorrect migration output: %q", output.String())
	}
}

func TestExplicitMigrationStillAllowsInteractiveHelper(t *testing.T) {
	_, _, marker := automaticMigrationHelperFixture(t, false)
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

func automaticMigrationHelperFixture(t *testing.T, nonInteractive bool) (string, []byte, string) {
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
	if err := store.Save(cfg); err != nil {
		t.Fatal(err)
	}
	path, _, err := utils.GetConfigFilePath()
	if err != nil {
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
