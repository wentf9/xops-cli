package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

// InitOptions contains the filesystem-only settings for xops init.
type InitOptions struct {
	ConfigPath       string
	KeyPath          string
	SSHConfigPath    string
	SSHConfigChanged bool
	SkipSSHImport    bool
}

type initResult struct {
	configCreated bool
	imported      int
	skipped       int
}

// NewInitOptions creates initialization options with the default OpenSSH path.
func NewInitOptions() *InitOptions {
	return &InitOptions{SSHConfigPath: defaultSSHConfigPath()}
}

// NewCmdInit creates the command that initializes local XOps configuration.
func NewCmdInit() *cobra.Command {
	o := NewInitOptions()
	cmd := &cobra.Command{
		Use:   "init",
		Short: i18n.T("init_short"),
		Long:  i18n.T("init_long"),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.SSHConfigChanged = cmd.Flags().Changed("ssh-config")
			result, err := o.Run()
			if err != nil {
				return err
			}
			return o.printResult(cmd, result)
		},
	}

	cmd.Flags().StringVar(&o.SSHConfigPath, "ssh-config", o.SSHConfigPath, i18n.T("flag_init_ssh_config"))
	cmd.Flags().BoolVar(&o.SkipSSHImport, "skip-ssh-import", false, i18n.T("flag_init_skip_ssh_import"))
	cmd.MarkFlagsMutuallyExclusive("ssh-config", "skip-ssh-import")
	return cmd
}

// Run creates the local configuration and imports concrete OpenSSH hosts.
// It never performs network operations and never overwrites existing nodes.
func (o *InitOptions) Run() (initResult, error) {
	if o.ConfigPath == "" || o.KeyPath == "" {
		o.ConfigPath, o.KeyPath = utils.GetConfigFilePath()
	}
	if o.ConfigPath == "" || o.KeyPath == "" {
		return initResult{}, fmt.Errorf("resolve xops configuration paths")
	}

	configCreated, err := configurationNeedsCreation(o.ConfigPath)
	if err != nil {
		return initResult{}, err
	}

	store := config.NewDefaultStore(o.ConfigPath, o.KeyPath)
	cfg, err := store.Load()
	if err != nil {
		return initResult{}, fmt.Errorf("load xops configuration: %w", err)
	}
	provider := config.NewProvider(cfg)

	result := initResult{configCreated: configCreated}
	if !o.SkipSSHImport && o.SSHConfigPath != "" {
		hosts, loadErr := loadOpenSSHHosts(o.SSHConfigPath, utils.GetCurrentUser())
		if loadErr != nil {
			if !errors.Is(loadErr, os.ErrNotExist) || o.SSHConfigChanged {
				return initResult{}, loadErr
			}
		} else {
			result.imported, result.skipped = importOpenSSHHosts(provider, hosts)
		}
	}

	if result.configCreated || result.imported > 0 {
		if err := store.Save(cfg); err != nil {
			return initResult{}, fmt.Errorf("save xops configuration: %w", err)
		}
	}
	return result, nil
}

func (o *InitOptions) printResult(cmd *cobra.Command, result initResult) error {
	statusKey := "init_status_existing"
	if result.configCreated {
		statusKey = "init_status_created"
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), i18n.T(statusKey)); err != nil {
		return fmt.Errorf("write initialization status: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), i18n.Tf("init_config_path", map[string]any{"Path": o.ConfigPath})); err != nil {
		return fmt.Errorf("write configuration path: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), i18n.Tf("init_key_path", map[string]any{"Path": o.KeyPath})); err != nil {
		return fmt.Errorf("write key path: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), i18n.Tf("init_import_summary", map[string]any{
		"Imported": result.imported,
		"Skipped":  result.skipped,
	})); err != nil {
		return fmt.Errorf("write openssh import summary: %w", err)
	}
	if _, err := fmt.Fprintln(cmd.OutOrStdout(), i18n.T("init_next_steps")); err != nil {
		return fmt.Errorf("write initialization next steps: %w", err)
	}
	return nil
}

func configurationNeedsCreation(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return false, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	return false, fmt.Errorf("inspect xops configuration %q: %w", path, err)
}

func loadOpenSSHHosts(path, defaultUser string) (hosts []config.OpenSSHHost, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open openssh configuration %q: %w", path, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close openssh configuration %q: %w", path, closeErr))
		}
	}()

	hosts, err = config.ParseOpenSSHHosts(f, defaultUser)
	if err != nil {
		return nil, fmt.Errorf("load openssh configuration %q: %w", path, err)
	}
	return hosts, nil
}

func importOpenSSHHosts(provider config.ConfigProvider, hosts []config.OpenSSHHost) (imported, skipped int) {
	added := make([]string, 0, len(hosts))
	for _, item := range hosts {
		if provider.Find(item.Name) != "" {
			skipped++
			continue
		}

		hostRef := "openssh-host:" + item.Name
		identityRef := "openssh-identity:" + item.Name
		item.Node.HostRef = hostRef
		item.Node.IdentityRef = identityRef
		provider.AddHost(hostRef, item.Host)
		provider.AddIdentity(identityRef, item.Identity)
		provider.AddNode(item.Name, item.Node)
		added = append(added, item.Name)
		imported++
	}

	for _, nodeID := range added {
		node, ok := provider.GetNode(nodeID)
		if !ok || node.ProxyJump == "" {
			continue
		}
		if jumpNodeID := findProxyJumpNode(provider, node.ProxyJump); jumpNodeID != "" {
			node.ProxyJump = jumpNodeID
			provider.AddNode(nodeID, node)
		}
	}
	return imported, skipped
}

func findProxyJumpNode(provider config.ConfigProvider, value string) string {
	if nodeID := provider.Find(value); nodeID != "" {
		return nodeID
	}
	_, host, _ := utils.ParseAddr(value)
	return provider.Find(host)
}

func defaultSSHConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".ssh", "config")
}
