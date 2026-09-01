package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/cmd/version"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func Execute() error {
	rootCmd := newRootCmd()

	// 初始化 root 命令的 flags
	initRootFlags(rootCmd)
	// 注册所有子命令
	registerCommands(rootCmd)

	// 动态路由分发，只在 ssh/exec 命令下触发，并将反射限制在分支内部
	if cmd, flagsArgs, err := rootCmd.Find(os.Args[1:]); err == nil {
		if cmd.Name() == "ssh" || cmd.Name() == "exec" {
			newFlagsArgs := preprocessSubArgs(flagsArgs, cmd)
			if len(flagsArgs) > 0 {
				tailStart := len(os.Args) - len(flagsArgs)
				os.Args = append(os.Args[:tailStart], newFlagsArgs...)
			}
		}
	}

	return rootCmd.Execute()
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
			return nil
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

func preprocessSubArgs(subArgs []string, cmd *cobra.Command) []string {
	// 动态收集已知 flags
	knownFlags := make(map[string]bool)
	hasValueFlags := make(map[string]bool)

	collectFlags := func(fs *pflag.FlagSet) {
		fs.VisitAll(func(f *pflag.Flag) {
			knownFlags["--"+f.Name] = true
			if f.Shorthand != "" {
				knownFlags["-"+f.Shorthand] = true
			}
			if f.Value.Type() != "bool" {
				hasValueFlags["--"+f.Name] = true
				if f.Shorthand != "" {
					hasValueFlags["-"+f.Shorthand] = true
				}
			}
		})
	}

	collectFlags(cmd.Flags())
	collectFlags(cmd.PersistentFlags())

	// 1. 寻找第一个位置参数 (host / host_pattern)
	hostIdx := -1
	i := 0
	for i < len(subArgs) {
		arg := subArgs[i]
		if strings.HasPrefix(arg, "-") {
			flagName := arg
			if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				flagName = parts[0]
			}
			// 如果是已知 flag 且需要带值，且不是用 = 赋值，则跳过下一个作为其值
			if hasValueFlags[flagName] && !strings.Contains(arg, "=") {
				i += 2
			} else {
				i += 1
			}
		} else {
			hostIdx = i
			break
		}
	}

	if hostIdx == -1 {
		return subArgs
	}

	afterHostIdx := hostIdx + 1
	if afterHostIdx >= len(subArgs) {
		return subArgs
	}

	remoteCmdStartIdx := -1
	j := afterHostIdx
	for j < len(subArgs) {
		arg := subArgs[j]
		if arg == "--" {
			// 如果已经包含了分界符，直接不作处理返回
			return subArgs
		}
		if strings.HasPrefix(arg, "-") {
			flagName := arg
			if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				flagName = parts[0]
			}
			if knownFlags[flagName] {
				if hasValueFlags[flagName] && !strings.Contains(arg, "=") {
					j += 2
				} else {
					j += 1
				}
			} else {
				// 未知 flag (例如 -tlpn) -> 远程命令开始
				remoteCmdStartIdx = j
				break
			}
		} else {
			// 普通参数 (例如 ss) -> 远程命令开始
			remoteCmdStartIdx = j
			break
		}
	}

	if remoteCmdStartIdx != -1 {
		newSubArgs := make([]string, 0, len(subArgs)+1)
		newSubArgs = append(newSubArgs, subArgs[:remoteCmdStartIdx]...)
		newSubArgs = append(newSubArgs, "--")
		newSubArgs = append(newSubArgs, subArgs[remoteCmdStartIdx:]...)
		return newSubArgs
	}

	return subArgs
}
