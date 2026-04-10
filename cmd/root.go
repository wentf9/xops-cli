package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/version"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func Execute() {
	rootCmd := newRootCmd()

	// 初始化 root 命令的 flags
	initRootFlags(rootCmd)
	// 注册所有子命令
	registerCommands(rootCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "xops [command] [flags]",
		Short: i18n.T("root_short"),
		Long:  i18n.T("root_long"),
		Run: func(cmd *cobra.Command, args []string) {
			versionFlag, _ := cmd.Flags().GetBool("version")
			if versionFlag {
				version.PrintFullVersion()
				os.Exit(0)
			}
			_ = cmd.Help()
			os.Exit(0)
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if lang, _ := cmd.Flags().GetString("lang"); lang != "" {
				i18n.SetLang(lang)
			}

			if colorMode, _ := cmd.Flags().GetString("color"); colorMode != "" {
				logger.SetColorMode(colorMode)
			}

			logLevel, _ := cmd.Flags().GetString("log-level")
			debugFlag, _ := cmd.Flags().GetBool("debug")

			if debugFlag {
				logLevel = "debug"
			}

			logger.SetLogLevel(logLevel)
			if logLevel == "debug" {
				logger.Debug(i18n.T("debug_mode_enabled"))
			}
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
	rootCmd.AddCommand(host.NewCmdInventory())
	rootCmd.AddCommand(newCmdVersion())
	rootCmd.AddCommand(NewCmdSsh())
	rootCmd.AddCommand(NewCmdMcp())
	rootCmd.AddCommand(NewCmdTui())
	rootCmd.AddCommand(NewCmdSftp())
	rootCmd.AddCommand(NewCmdScp())
	rootCmd.AddCommand(NewCmdExec())
	rootCmd.AddCommand(NewCmdIdentity())
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
