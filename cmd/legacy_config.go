package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

// warnLegacyConfiguration inspects only the schema, without loading secrets or
// creating files. Migration remains independent of the ordinary load policy.
// Warnings go to stderr so MCP stdout remains reserved for JSON-RPC.
func warnLegacyConfiguration(cmd *cobra.Command) error {
	if cmd.Name() == "migrate" || cmd.Name() == "finalize-migration" {
		return nil
	}
	top := cmd
	for top.Parent() != nil && top.Parent().Parent() != nil {
		top = top.Parent()
	}
	switch top.Name() {
	case "init", "host", "identity", "credential", "ssh", "sftp", "scp", "exec", "tui", "mcp", "play", "sudo", "firewall", "forward", "loadHost":
	default:
		return nil
	}
	path, _, err := utils.GetConfigFilePath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect configuration schema: %w", err)
	}
	version, err := config.DetectSchemaVersion(data)
	if err != nil {
		return fmt.Errorf("inspect configuration schema: %w", err)
	}
	if version == 1 {
		if _, err := fmt.Fprintln(cmd.ErrOrStderr(), i18n.T("legacy_config_warning")); err != nil {
			return fmt.Errorf("write legacy configuration warning: %w", err)
		}
	}
	return nil
}
