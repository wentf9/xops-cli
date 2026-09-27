package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/mcpserver"
)

func newCmdMCPRecover() *cobra.Command {
	options := mcpserver.RecoveryOptions{MaxRecords: 4096}
	cmd := &cobra.Command{Use: "recover", Short: i18n.T("mcp_recover_short"), Long: i18n.T("mcp_recover_long"), Args: cobra.NoArgs}
	cmd.Flags().StringVar(&options.TransferID, "id", "", i18n.T("mcp_recover_id_flag"))
	cmd.Flags().BoolVar(&options.Verify, "verify", false, i18n.T("mcp_recover_verify_flag"))
	cmd.Flags().BoolVar(&options.Cleanup, "cleanup", false, i18n.T("mcp_recover_cleanup_flag"))
	cmd.Flags().BoolVar(&options.ResolveUnknown, "resolve-unknown", false, i18n.T("mcp_recover_resolve_flag"))
	cmd.Flags().StringVar(&options.Reason, "reason", "", i18n.T("mcp_recover_reason_flag"))
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		for _, flag := range []string{"transport", "listen", "public-url", "token-file", "token-env", "allowed-hosts", "allowed-origins"} {
			if cmd.Flags().Changed(flag) {
				return fmt.Errorf("--%s is a server option; recovery only uses --state-dir", flag)
			}
		}
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		path, keyPath, err := utils.GetConfigFilePath()
		if err != nil {
			return err
		}
		settings, policy, err := config.ReadMCPSettings(path)
		if err != nil {
			return err
		}
		options.StateDir = filepath.Join(filepath.Dir(path), "mcp-transfers")
		if err := applyMCPRecoverySettings(&options, settings); err != nil {
			return err
		}
		if cmd.Flags().Changed("state-dir") {
			options.StateDir, err = cmd.Flags().GetString("state-dir")
			if err != nil {
				return err
			}
		}
		provider := config.ConfigProvider(config.NewProviderWithoutOpenSSH(&config.Configuration{Guardrail: policy}))
		serveOpts := []mcpserver.Option{mcpserver.WithLogger(logger.DefaultLogger())}
		if options.Verify || options.Cleanup {
			cfg, err := config.ReadOnlyConfiguration(path, keyPath)
			if err != nil {
				return err
			}
			provider, err = config.NewProvider(cfg)
			if err != nil {
				return err
			}
			registry, err := utils.GetCredentialRegistry(cfg)
			if err != nil {
				return err
			}
			if registry != nil {
				serveOpts = append(serveOpts, mcpserver.WithCredentialRegistry(registry))
			}
		}
		serveOpts = append(serveOpts, mcpserver.WithConfigProvider(provider))
		entries, recoverErr := mcpserver.RecoverTransfers(credential.WithoutInteraction(ctx), options, serveOpts...)
		if entries != nil {
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(entries); err != nil {
				return errors.Join(recoverErr, fmt.Errorf("write transfer recovery report: %w", err))
			}
		}
		return recoverErr
	}
	return cmd
}

// Recovery reads its own limits without requiring listener or token settings.
func applyMCPRecoverySettings(options *mcpserver.RecoveryOptions, settings *config.MCPConfig) error {
	if settings == nil {
		return nil
	}
	if settings.StateDir != "" {
		options.StateDir = settings.StateDir
	}
	if settings.MaxRecords != nil {
		options.MaxRecords = *settings.MaxRecords
	}
	if settings.MaxFileBytes != nil {
		if *settings.MaxFileBytes <= 0 || *settings.MaxFileBytes > 1<<50 {
			return errors.New("mcp.max_file_bytes is outside the permitted range")
		}
		options.MaxFileBytes = *settings.MaxFileBytes
	}
	return nil
}
