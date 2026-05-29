package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/playbook"
)

// PlayOptions 保存 xops play 命令的所有选项
type PlayOptions struct {
	FilePath    string
	Vars        []string // 格式: "key=value"
	Concurrency uint
	DryRun      bool
	Limit       string // 逗号分隔的节点名称，覆盖 Playbook 的 targets
	Sudo        bool
}

func NewPlayOptions() *PlayOptions {
	return &PlayOptions{}
}

func NewCmdPlay() *cobra.Command {
	o := NewPlayOptions()
	cmd := &cobra.Command{
		Use:   "play <playbook-file>",
		Short: i18n.T("play_short"),
		Long:  i18n.T("play_long"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.FilePath = args[0]
			return o.Run()
		},
	}

	cmd.Flags().StringArrayVar(&o.Vars, "var", nil, i18n.T("flag_play_var"))
	cmd.Flags().UintVarP(&o.Concurrency, "concurrency", "j", 0, i18n.T("flag_play_concurrency"))
	cmd.Flags().BoolVar(&o.DryRun, "dry-run", false, i18n.T("flag_play_dry_run"))
	cmd.Flags().StringVar(&o.Limit, "limit", "", i18n.T("flag_play_limit"))
	cmd.Flags().BoolVar(&o.Sudo, "sudo", false, i18n.T("flag_play_sudo"))

	return cmd
}

// Run 执行 Playbook。
func (o *PlayOptions) Run() error {
	// 解析 --var 选项
	extraVars, err := parseVars(o.Vars)
	if err != nil {
		return err
	}

	// 加载 Playbook
	pb, err := playbook.Load(o.FilePath, extraVars)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("play_err_parse"), err)
	}

	// 应用 CLI 覆盖选项
	if o.Concurrency > 0 {
		pb.Settings.Concurrency = o.Concurrency
	}
	if o.Sudo {
		pb.Settings.Sudo = true
	}
	if o.Limit != "" {
		pb.Targets = playbook.Targets{
			Nodes: strings.Split(o.Limit, ","),
		}
	}

	// Dry Run 模式：打印 Playbook 内容后退出
	if o.DryRun {
		return o.printDryRun(pb)
	}

	// 加载配置与 SSH 连接器
	_, provider, _, err := utils.GetConfigStore()
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("config_load_error"), err)
	}

	connector := adapter.NewConnector(provider)
	defer connector.CloseAll()

	// 创建并运行引擎
	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(context.Background())
	if err != nil {
		return err
	}

	report.Print()

	// 如果有失败的主机，以非零退出码退出
	for _, h := range report.Hosts {
		if h.Status != playbook.HostStatusSuccess {
			return fmt.Errorf("%s", i18n.T("play_err_some_failed"))
		}
	}

	return nil
}

// printDryRun 在 Dry Run 模式下打印 Playbook 摘要。
func (o *PlayOptions) printDryRun(pb *playbook.Playbook) error {
	fmt.Printf("🔍 %s\n\n", i18n.T("play_dry_run"))
	fmt.Printf("Playbook : %s\n", pb.Name)
	if pb.Description != "" {
		fmt.Printf("Desc     : %s\n", pb.Description)
	}
	fmt.Printf("Targets  : tags=%v nodes=%v hosts=%v\n",
		pb.Targets.Tags, pb.Targets.Nodes, pb.Targets.Hosts)
	fmt.Printf("Settings : concurrency=%d, sudo=%v, on_error=%s\n",
		pb.Settings.Concurrency, pb.Settings.Sudo, pb.Settings.OnError)
	fmt.Printf("Steps    : %d\n\n", len(pb.Steps))

	for i, s := range pb.Steps {
		stepType := stepTypeName(s)
		fmt.Printf("  [%d] %-20s (%s)\n", i+1, s.Name, stepType)
	}
	return nil
}

// stepTypeName 返回步骤的类型名称字符串。
func stepTypeName(s playbook.Step) string {
	switch {
	case s.Shell != "":
		return "shell"
	case s.Script != "":
		return "script"
	case s.Copy != nil:
		return "copy"
	case s.Ensure != nil:
		return "ensure"
	case s.Template != nil:
		return "template"
	default:
		return "unknown"
	}
}

// parseVars 解析 --var key=value 参数为 map。
func parseVars(vars []string) (map[string]string, error) {
	result := make(map[string]string, len(vars))
	for _, v := range vars {
		k, val, ok := strings.Cut(v, "=")
		if !ok {
			return nil, fmt.Errorf("invalid --var format %q, expected key=value", v)
		}
		result[strings.TrimSpace(k)] = val
	}
	return result, nil
}
