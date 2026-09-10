package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/tui"
)

func NewCmdTui() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: i18n.T("tui_short"),
		Long:  i18n.T("tui_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			configPath, keyPath, pathErr := utils.GetConfigFilePath()
			if pathErr != nil {
				return fmt.Errorf("get config file path failed: %w", pathErr)
			}
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				return fmt.Errorf("%s: %w", i18n.T("config_load_error"), err)
			}
			repository, err := config.NewRepository(cfg, configStore)
			if err != nil {
				return fmt.Errorf("create configuration repository: %w", err)
			}

			credSvc, credErr := utils.GetCredentialService(repository, cfg)
			if credErr != nil {
				return fmt.Errorf("initialize credential persistence: %w", credErr)
			}
			credReg, regErr := utils.GetCredentialRegistry(cfg)
			if regErr != nil {
				return fmt.Errorf("initialize credential resolver: %w", regErr)
			}

			interaction := newCLIInteractionHandler()
			model, err := tui.NewModel(
				repository,
				tui.WithContext(credential.WithoutInteraction(ctx)),
				tui.WithLogger(logger.DefaultLogger()),
				tui.WithInteractionHandler(interaction),
				tui.WithRememberConfirmation(interaction.confirmRemember),
				tui.WithCredentialService(credSvc),
				tui.WithCredentialRegistry(credReg),
				tui.WithVaultControl(func(work context.Context, unlock bool) error {
					owner, err := utils.CredentialRuntime()
					if err != nil {
						return err
					}
					if !unlock {
						return owner.Lock(work)
					}
					if cfg.Credential == nil {
						return fmt.Errorf("no default offline store configured")
					}
					id := cfg.Credential.DefaultStore
					selected, err := offlineConfig(cfg, id, configPath)
					if err != nil {
						return err
					}
					s, err := owner.Store(work, id, selected)
					if err != nil {
						return err
					}
					return s.Unlock(ctx)
				}),
			)
			if err != nil {
				return fmt.Errorf("create TUI model: %w", err)
			}
			p := tea.NewProgram(&model, tea.WithAltScreen(), tea.WithContext(ctx))
			_, runErr := p.Run()
			stop()
			closeErr := model.Close()
			if runErr != nil {
				runErr = fmt.Errorf("%s: %w", i18n.T("tui_run_failed"), runErr)
			}
			if closeErr != nil {
				closeErr = fmt.Errorf("close TUI resources failed: %w", closeErr)
			}
			return errors.Join(runErr, closeErr)
		},
	}
	return cmd
}
