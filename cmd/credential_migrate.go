package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func newCmdCredentialMigrate() *cobra.Command {
	var opts config.MigrationOptions
	cmd := &cobra.Command{
		Use: "migrate --to <store>", Short: i18n.T("credential_migrate_short"), Long: i18n.T("credential_migrate_long"), Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.ToStore == "" {
				return fmt.Errorf("--to must name a configured writable credential store")
			}
			migrator, err := commandCredentialMigrator()
			if err != nil {
				return err
			}
			report, err := migrator.Migrate(cmd.Context(), opts)
			if err != nil {
				return fmt.Errorf("migrate credentials: %w", err)
			}
			if report.DryRun {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Dry run: %d credentials would migrate to %s; no files or credentials written\n", report.Credentials, report.Store)
			} else {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "Verified schema v2: %d credentials migrated to %s\nLegacy backup: %s\nValidate your connections, then run xops credential finalize-migration\n", report.Credentials, report.Store, report.BackupPath)
			}
			if err != nil {
				return fmt.Errorf("write migration result: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.ToStore, "to", "", i18n.T("credential_migrate_to"))
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, i18n.T("credential_migrate_dry_run"))
	return cmd
}

func newCmdCredentialFinalizeMigration() *cobra.Command {
	return &cobra.Command{
		Use: "finalize-migration", Short: i18n.T("credential_finalize_short"), Long: i18n.T("credential_finalize_long"), Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			migrator, err := commandCredentialMigrator()
			if err != nil {
				return err
			}
			if _, err := migrator.Finalize(cmd.Context()); err != nil {
				return fmt.Errorf("finalize credential migration: %w", err)
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), "Migration finalized; legacy configuration backup and encryption keys removed"); err != nil {
				return fmt.Errorf("write finalization result: %w", err)
			}
			return nil
		},
	}
}

func commandCredentialMigrator() (*config.CredentialMigrator, error) {
	// Never call GetConfigStore here: its v1 compatibility loader publishes
	// plaintext and may rewrite the source or create a key before backup.
	path, key, err := utils.GetConfigFilePath()
	if err != nil {
		return nil, err
	}
	return config.NewCredentialMigrator(path, key)
}
