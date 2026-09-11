package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

// automaticMigrationEligible deliberately excludes inspection and maintenance
// commands. A no-save override also prevents implicit legacy secret writes.
func automaticMigrationEligible(cmd *cobra.Command) bool {
	for _, name := range []string{"dry-run", "help", "version"} {
		if flag := cmd.Flags().Lookup(name); flag != nil && flag.Value.String() == "true" {
			return false
		}
	}
	if flag := cmd.Flags().Lookup("remember"); flag != nil {
		policy := strings.ToLower(strings.TrimSpace(flag.Value.String()))
		if utils.ValidateRememberPolicy(policy) != nil || policy == "never" {
			return false
		}
	}
	top := cmd
	for top.Parent() != nil && top.Parent().Parent() != nil {
		top = top.Parent()
	}
	switch top.Name() {
	case "ssh", "sftp", "scp", "exec", "tui", "mcp", "play", "forward", "sudo":
		return true
	default:
		return false
	}
}

func autoMigrateConfiguration(cmd *cobra.Command) error {
	if !automaticMigrationEligible(cmd) {
		return nil
	}
	path, key, err := utils.GetConfigFilePath()
	if err != nil {
		return err
	}
	migrator, err := config.NewCredentialMigrator(path, key)
	if err != nil {
		return err
	}
	// Startup runs before command-specific interaction policies and before TUI
	// terminal handoff. Automatic migration must never open credential prompts;
	// users can unlock the store and retry, or explicitly invoke migration.
	ctx := credential.WithoutInteraction(cmd.Context())
	report, err := migrator.WithRegistryFactory(utils.BuildCredentialRegistry).AutoMigrate(ctx)
	if err != nil {
		// Keep operational errors out of stdout (including MCP's protocol stream).
		// Do not print backend errors: external helpers may include secret material.
		_, writeErr := fmt.Fprintln(cmd.ErrOrStderr(), i18n.T("credential_auto_migration_failed"))
		return writeErr
	}
	if report.Verified {
		_, err = fmt.Fprintln(cmd.ErrOrStderr(), i18n.T("credential_auto_migration_complete"))
	}
	return err
}
