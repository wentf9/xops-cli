package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/internal/mcphost"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func addMCPFlags(cmd *cobra.Command) {
	f := cmd.PersistentFlags()
	f.String("transport", "stdio", i18n.T("mcp_transport_flag"))
	f.String("listen", "", i18n.T("mcp_listen_flag"))
	f.String("public-url", "", i18n.T("mcp_public_url_flag"))
	f.String("token-file", "", i18n.T("mcp_token_file_flag"))
	f.String("token-env", "", i18n.T("mcp_token_env_flag"))
	f.String("state-dir", "", i18n.T("mcp_state_dir_flag"))
	f.StringSlice("allowed-hosts", nil, i18n.T("mcp_allowed_hosts_flag"))
	f.StringSlice("allowed-origins", nil, i18n.T("mcp_allowed_origins_flag"))
}

func resolveMCPOptions(cmd *cobra.Command, configuration *config.Configuration, configPath string) (string, mcpruntime.HTTPOptions, error) {
	settings := &config.MCPConfig{}
	if configuration != nil && configuration.MCP != nil {
		settings = configuration.MCP.Clone()
	}
	if err := overrideMCPFlags(cmd, settings); err != nil {
		return "", mcpruntime.HTTPOptions{}, err
	}
	if settings.Transport == "" {
		settings.Transport = "stdio"
	}
	switch settings.Transport {
	case "stdio":
		for _, flag := range []string{"listen", "public-url", "token-file", "token-env", "state-dir", "allowed-hosts", "allowed-origins"} {
			if cmd.Flags().Changed(flag) {
				return "", mcpruntime.HTTPOptions{}, errors.New("HTTP options require --transport http")
			}
		}
		return "stdio", mcpruntime.HTTPOptions{}, nil
	case "http":
		o, err := mcphost.HTTPOptionsFromConfig(settings)
		if err != nil {
			return "", o, err
		}
		if o.StateDir == "" {
			o.StateDir = filepath.Join(filepath.Dir(configPath), "mcp-transfers")
		}
		o.Token, err = readMCPToken(settings.TokenFile, settings.TokenEnv)
		return "http", o, err
	default:
		return "", mcpruntime.HTTPOptions{}, errors.New("MCP transport must be stdio or http")
	}
}

func overrideMCPFlags(cmd *cobra.Command, settings *config.MCPConfig) error {
	f := cmd.Flags()
	if f.Changed("token-file") && f.Changed("token-env") {
		return errors.New("--token-file and --token-env cannot be combined")
	}
	for _, o := range []struct {
		name  string
		value *string
	}{
		{"transport", &settings.Transport}, {"listen", &settings.Listen}, {"public-url", &settings.PublicURL},
		{"token-file", &settings.TokenFile}, {"token-env", &settings.TokenEnv}, {"state-dir", &settings.StateDir},
	} {
		if f.Changed(o.name) {
			value, err := f.GetString(o.name)
			if err != nil {
				return fmt.Errorf("read MCP option: %w", err)
			}
			*o.value = value
		}
	}
	if f.Changed("token-file") {
		settings.TokenEnv = ""
	} else if f.Changed("token-env") {
		settings.TokenFile = ""
	}
	for _, o := range []struct {
		name  string
		value *[]string
	}{
		{"allowed-hosts", &settings.AllowedHosts}, {"allowed-origins", &settings.AllowedOrigins},
	} {
		if f.Changed(o.name) {
			value, err := f.GetStringSlice(o.name)
			if err != nil {
				return fmt.Errorf("read MCP option: %w", err)
			}
			*o.value = value
		}
	}
	return nil
}

func readMCPToken(filePath, envName string) (_ string, retErr error) {
	if (filePath == "") == (envName == "") {
		return "", errors.New("HTTP MCP requires exactly one token file or token environment variable")
	}
	if envName != "" {
		token, exists := os.LookupEnv(envName)
		if !exists || token == "" {
			return "", errors.New("MCP token environment variable is not set or is empty")
		}
		return token, nil
	}
	info, err := os.Lstat(filePath)
	if err != nil {
		return "", fmt.Errorf("inspect MCP token file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 4098 {
		return "", errors.New("MCP token file must be a regular file of at most 4098 bytes")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open MCP token file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close MCP token file: %w", err))
		}
	}()
	data, err := io.ReadAll(io.LimitReader(file, 4099))
	if err != nil {
		return "", fmt.Errorf("read MCP token file: %w", err)
	}
	if len(data) > 4098 {
		return "", errors.New("MCP token file exceeds size limit")
	}
	return strings.TrimSpace(string(data)), nil
}
