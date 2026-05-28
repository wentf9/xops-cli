package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/executor"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func newCmdSudo() *cobra.Command {
	var sudoPassword string
	var sudoShell bool

	cmd := &cobra.Command{
		Use:                "sudo [command]",
		Short:              i18n.T("sudo_short"),
		Long:               i18n.T("sudo_long"),
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: false, // 我们仍然需要解析 sudo 自身的 -p 和 -s
		RunE: func(cmd *cobra.Command, args []string) error {
			// 1. 获取密码
			pwd := sudoPassword
			isManual := false
			if pwd == "" {
				// 尝试从配置文件中联动
				pwd = utils.GetLocalSudoPassword()
			}
			if pwd == "" {
				p, err := utils.ReadPasswordFromTerminal(i18n.T("prompt_sudo_password"))
				if err != nil {
					return err
				}
				pwd = p
				isManual = true
			}

			// 2. 初始化执行器
			exec := executor.NewLocalExecutor(pwd)

			// 3. 执行命令
			var err error
			var output string
			if sudoShell || len(args) == 0 {
				// 如果指定了 -s 或者没有任何参数，则进入交互式 shell
				err = exec.InteractiveWithSudo(context.Background(), args)
			} else {
				// 执行单条命令
				fullCmd := strings.Join(args, " ")
				output, err = exec.RunWithSudo(context.Background(), fullCmd)
				if err == nil {
					// sudo 输出保持纯净，因为直接展示目标机回显
					logger.Print(output)
				}
			}

			if err != nil {
				return fmt.Errorf("%s", i18n.Tf("sudo_exec_failed", map[string]any{"Error": err}))
			}

			// 4. 执行成功后，如果是手动输入的密码，保存到配置文件
			if isManual && pwd != "" {
				if saveErr := utils.SaveLocalSudoPassword(pwd); saveErr != nil {
					logger.Debug(fmt.Sprintf("Failed to save sudo password: %v", saveErr))
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&sudoPassword, "passwd", "p", "", i18n.T("flag_sudo_passwd"))
	cmd.Flags().BoolVarP(&sudoShell, "shell", "s", false, i18n.T("flag_sudo_shell"))
	cmd.Flags().SetInterspersed(false)

	return cmd
}
