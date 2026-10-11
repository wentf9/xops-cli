package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
)

// checkConfigurationSchema rejects legacy runtime use without loading secrets.
// Explicit migration and finalization remain independent of ordinary loading.
func checkConfigurationSchema(cmd *cobra.Command) error {
	if cmd.Name() == "migrate" || cmd.Name() == "finalize-migration" {
		return nil
	}
	top := cmd
	for top.Parent() != nil && top.Parent().Parent() != nil {
		top = top.Parent()
	}
	switch top.Name() {
	case "init", "host", "identity", "credential", "ssh", "sftp", "scp", "exec", "tui", "mcp", "play", "sudo", "firewall", "forward":
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
	return config.ValidateRuntimeSchema(version)
}
