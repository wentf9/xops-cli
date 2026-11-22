package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/fsx"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

const maxInitOpenSSHConfigBytes int64 = 16 * 1024 * 1024 // 16 MiB

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
	var (
		hosts         []config.OpenSSHHost
		openSSHParser *config.OpenSSHParser
		shouldImport  bool
	)
	if !o.SkipSSHImport && o.SSHConfigPath != "" {
		currUser, userErr := utils.GetCurrentUser()
		if userErr != nil {
			return initResult{}, fmt.Errorf("get current user failed: %w", userErr)
		}
		var loadErr error
		hosts, openSSHParser, loadErr = loadOpenSSHHostsAndParser(o.SSHConfigPath, currUser)
		if loadErr != nil {
			if !errors.Is(loadErr, os.ErrNotExist) || o.SSHConfigChanged {
				return initResult{}, loadErr
			}
		} else {
			shouldImport = true
		}
	}

	repository, repositoryErr := config.NewRepositoryWithOpenSSHParser(cfg, store, openSSHParser)
	if repositoryErr != nil {
		return initResult{}, fmt.Errorf("create configuration repository: %w", repositoryErr)
	}

	result := initResult{configCreated: configCreated}
	if shouldImport {
		importResult, importErr := repository.ImportOpenSSHHostsContext(ctx, hosts)
		if importErr != nil {
			return initResult{}, fmt.Errorf("import openssh hosts: %w", importErr)
		}
		result.imported = importResult.Imported
		result.skipped = importResult.Skipped
		result.issues = importResult.Issues
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
	if result.configCreated {
		if _, err := fmt.Fprintln(cmd.OutOrStdout(), i18n.T("init_credential_policy")); err != nil {
			return fmt.Errorf("write credential policy: %w", err)
		}
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

type namedOpenSSHReader struct {
	io.Reader
	name string
}

func (r namedOpenSSHReader) Name() string { return r.name }

func loadOpenSSHHosts(path, defaultUser string) ([]config.OpenSSHHost, error) {
	return loadOpenSSHHostsWithLimit(path, defaultUser, maxInitOpenSSHConfigBytes)
}

func loadOpenSSHHostsWithLimit(path, defaultUser string, maxBytes int64) ([]config.OpenSSHHost, error) {
	hosts, _, err := loadOpenSSHHostsAndParserWithLimit(path, defaultUser, maxBytes)
	return hosts, err
}

func loadOpenSSHHostsAndParser(path, defaultUser string) ([]config.OpenSSHHost, *config.OpenSSHParser, error) {
	return loadOpenSSHHostsAndParserWithLimit(path, defaultUser, maxInitOpenSSHConfigBytes)
}

func loadOpenSSHHostsAndParserWithLimit(path, defaultUser string, maxBytes int64) (hosts []config.OpenSSHHost, parser *config.OpenSSHParser, err error) {
	// OpenSSH follows symlinks for ~/.ssh/config and allows /dev/null as an
	// empty config; fsx.OpenRegular opens handle-first without Stat-then-Open.
	rf, openErr := fsx.OpenRegular(path, fsx.Limits{MaxBytes: maxBytes}, fsx.AllowDevNull(), fsx.FollowSymlinks())
	if openErr != nil {
		return nil, nil, formatInitOpenSSHOpenError(path, maxBytes, openErr)
	}
	defer func() {
		if closeErr := rf.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close openssh configuration %q: %w", path, closeErr))
		}
	}()
	if rf.IsDevNull() {
		return nil, nil, nil
	}
	data, readErr := rf.ReadAll()
	if readErr != nil {
		if errors.Is(readErr, fsx.ErrTooLarge) {
			return nil, nil, fmt.Errorf("openssh configuration %q exceeds maximum size of %d bytes: %w", path, maxBytes, readErr)
		}
		return nil, nil, fmt.Errorf("read openssh configuration %q: %w", path, readErr)
	}

	hosts, err = config.ParseOpenSSHHosts(namedOpenSSHReader{Reader: bytes.NewReader(data), name: rf.Name()}, defaultUser)
	if err != nil {
		return nil, nil, fmt.Errorf("load openssh configuration %q: %w", path, err)
	}
	parser, err = config.NewOpenSSHParserFromReader(namedOpenSSHReader{Reader: bytes.NewReader(data), name: rf.Name()})
	if err != nil {
		return nil, nil, fmt.Errorf("load openssh configuration %q: %w", path, err)
	}
	return hosts, parser, nil
}

func formatInitOpenSSHOpenError(path string, maxBytes int64, err error) error {
	if errors.Is(err, fsx.ErrTooLarge) {
		return fmt.Errorf("openssh configuration %q exceeds maximum size of %d bytes: %w", path, maxBytes, err)
	}
	if errors.Is(err, fsx.ErrNonRegular) {
		// Post-rejection diagnostic only (handle open already failed closed).
		if info, statErr := os.Stat(path); statErr == nil && info.IsDir() {
			return fmt.Errorf("openssh configuration %q is a directory, expected a regular file: %w", path, err)
		}
		return fmt.Errorf("openssh configuration %q must be a regular file: %w", path, err)
	}
	return fmt.Errorf("open openssh configuration %q: %w", path, err)
}

func defaultSSHConfigPath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".ssh", "config")
}
