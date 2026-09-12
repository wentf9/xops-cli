package cmd

import (
	"context"
	"errors"
	"fmt"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/version"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func Execute() (err error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	path, _, err := utils.GetConfigFilePath()
	if err != nil {
		return err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	owner := config.NewEncryptedRuntime(ctx, path, newCLIInteractionHandler())
	defer func() { err = errors.Join(err, owner.Close()) }()
	detach, err := utils.InstallCredentialRuntime(owner)
	if err != nil {
		return err
	}
	defer detach()
	rootCmd := newRootCmd()

	// 初始化 root 命令的 flags
	initRootFlags(rootCmd)
	// 注册所有子命令
	registerCommands(rootCmd)

	rootCmd.SetArgs(normalizeCommandArgs(rootCmd, os.Args[1:]))

	return rootCmd.ExecuteContext(ctx)
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "xops [command] [flags]",
		Short:         i18n.T("root_short"),
		Long:          i18n.T("root_long"),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			versionFlag, err := cmd.Flags().GetBool("version")
			if err != nil {
				return fmt.Errorf("read version flag failed: %w", err)
			}
			if versionFlag {
				version.PrintFullVersion()
				return nil
			}
			return cmd.Help()
		},
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			lang, err := cmd.Flags().GetString("lang")
			if err != nil {
				return fmt.Errorf("read language flag failed: %w", err)
			}
			if lang != "" {
				i18n.SetLang(lang)
			}

			colorMode, err := cmd.Flags().GetString("color")
			if err != nil {
				return fmt.Errorf("read color flag failed: %w", err)
			}
			if colorMode != "" {
				logger.SetColorMode(colorMode)
			}

			logLevel, err := cmd.Flags().GetString("log-level")
			if err != nil {
				return fmt.Errorf("read log level flag failed: %w", err)
			}
			debugFlag, err := cmd.Flags().GetBool("debug")
			if err != nil {
				return fmt.Errorf("read debug flag failed: %w", err)
			}

			if debugFlag {
				logLevel = "debug"
			}

			logger.SetLogLevel(logLevel)
			if logLevel == "debug" {
				logger.Debug(i18n.T("debug_mode_enabled"))
			}
			if err := autoMigrateConfiguration(cmd); err != nil {
				return err
			}
			return warnLegacyConfiguration(cmd)
		},
	}
}

func initRootFlags(rootCmd *cobra.Command) {
	rootCmd.Flags().BoolP("version", "v", false, i18n.T("flag_version"))
	rootCmd.PersistentFlags().String("log-level", "", i18n.T("flag_log_level"))
	rootCmd.PersistentFlags().Bool("debug", false, i18n.T("flag_debug"))
	rootCmd.PersistentFlags().String("lang", "", i18n.T("flag_lang"))
	rootCmd.PersistentFlags().String("color", "", i18n.T("flag_color"))
}

func registerCommands(rootCmd *cobra.Command) {
	// 注册各子命令
	rootCmd.AddCommand(NewCmdInit())
	rootCmd.AddCommand(host.NewCmdInventory())
	rootCmd.AddCommand(newCmdVersion())
	rootCmd.AddCommand(NewCmdSsh())
	rootCmd.AddCommand(NewCmdMcp())
	rootCmd.AddCommand(NewCmdTui())
	rootCmd.AddCommand(NewCmdSftp())
	rootCmd.AddCommand(NewCmdScp())
	rootCmd.AddCommand(NewCmdExec())
	rootCmd.AddCommand(NewCmdPlay())
	rootCmd.AddCommand(NewCmdIdentity())
	rootCmd.AddCommand(NewCmdCredential())
	rootCmd.AddCommand(newCmdNc())
	rootCmd.AddCommand(newCmdDns())
	rootCmd.AddCommand(newCmdPing())
	rootCmd.AddCommand(newCmdFirewall())
	rootCmd.AddCommand(newCmdSudo())
	rootCmd.AddCommand(newCmdEncode())
	rootCmd.AddCommand(newCmdLoadHost())
	rootCmd.AddCommand(newCmdForward())
}

func newCmdVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: i18n.T("version_short"),
		Run: func(cmd *cobra.Command, args []string) {
			version.PrintFullVersion()
		},
	}
}
