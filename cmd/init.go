package cmd

import (
	"context"
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
	issues        []config.ImportIssue
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
			result, err := o.RunContext(cmd.Context())
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
	return o.RunContext(context.Background())
}

// RunContext creates local configuration while preserving caller cancellation
// through durable configuration writes.
func (o *InitOptions) RunContext(ctx context.Context) (initResult, error) {
	if o.ConfigPath == "" || o.KeyPath == "" {
		var pathErr error
		o.ConfigPath, o.KeyPath, pathErr = utils.GetConfigFilePath()
		if pathErr != nil {
			return initResult{}, fmt.Errorf("resolve xops configuration paths: %w", pathErr)
		}
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
	repository, repositoryErr := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if repositoryErr != nil {
		return initResult{}, fmt.Errorf("create configuration repository: %w", repositoryErr)
	}

	result := initResult{configCreated: configCreated}
	if !o.SkipSSHImport && o.SSHConfigPath != "" {
		currUser, userErr := utils.GetCurrentUser()
		if userErr != nil {
			return initResult{}, fmt.Errorf("get current user failed: %w", userErr)
		}
		hosts, loadErr := loadOpenSSHHosts(o.SSHConfigPath, currUser)
		if loadErr != nil {
			if !errors.Is(loadErr, os.ErrNotExist) || o.SSHConfigChanged {
				return initResult{}, loadErr
			}
		} else {
			importResult, importErr := repository.ImportOpenSSHHostsContext(ctx, hosts)
			if importErr != nil {
				return initResult{}, fmt.Errorf("import openssh hosts: %w", importErr)
			}
			result.imported = importResult.Imported
			result.skipped = importResult.Skipped
			result.issues = importResult.Issues
		}
	}
	if result.configCreated && result.imported == 0 {
		if err := repository.InitializeContext(ctx); err != nil {
			return initResult{}, fmt.Errorf("initialize xops configuration: %w", err)
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
	for _, issue := range result.issues {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), i18n.Tf("init_import_issue", map[string]any{
			"Name":  issue.Name,
			"Error": issue.Err,
		})); err != nil {
			return fmt.Errorf("write openssh import issue: %w", err)
		}
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

func defaultSSHConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".ssh", "config")
}
