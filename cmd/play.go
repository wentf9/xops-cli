package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/playbook"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type cliEventListener struct{}

func (cliEventListener) OnTargetsResolved(count int) {
	logger.Info(i18n.Tf("play_target_resolved", map[string]any{"Count": count}))
}

func (cliEventListener) OnTagEmpty(tag string) {
	logger.Warn(i18n.Tf("play_warn_tag_empty", map[string]any{"Tag": tag}))
}

func (cliEventListener) OnStepRunning(host, stepName string) {
	logger.Info(i18n.Tf("play_step_running", map[string]any{
		"Host": host, "Step": stepName,
	}))
}

func (cliEventListener) OnStepResult(host, stepName string, r playbook.StepResult) {
	switch r.Status {
	case playbook.StatusOK, playbook.StatusChanged:
		logger.PrintSuccess(i18n.Tf("play_step_ok", map[string]any{
			"Host": host, "Step": stepName,
		}))
	case playbook.StatusSkipped:
		logger.Info(i18n.Tf("play_step_skipped", map[string]any{
			"Host": host, "Step": stepName,
		}))
	case playbook.StatusFailed:
		logger.Info(i18n.Tf("play_step_failed", map[string]any{
			"Host": host, "Step": stepName,
		}))
	}
}

// PlayOptions 保存 xops play 命令的所有选项
type PlayOptions struct {
	FilePath    string
	Vars        []string // 格式: "key=value"
	Concurrency uint
	DryRun      bool
	Limit       string // 逗号分隔的节点名称，覆盖 Playbook 的 targets
	Sudo        bool
	Out         io.Writer
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
			o.Out = cmd.OutOrStdout()
			return o.RunContext(cmd.Context())
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
	return o.RunContext(context.Background())
}

// RunContext executes the Playbook and propagates caller cancellation through
// target resolution, SSH connections, and step execution.
func (o *PlayOptions) RunContext(ctx context.Context) (retErr error) {
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

	connector := newCLIConnector(provider, ssh.WithLogger(logger.DefaultLogger()))
	defer func() {
		joinConnectorCloseError(&retErr, connector)
	}()

	// 创建并运行引擎
	engine := playbook.NewEngine(pb, provider, connector, playbook.WithEventListener(cliEventListener{}))
	report, runErr := engine.Run(ctx)
	if runErr != nil && report == nil {
		var targetErr *playbook.TargetNotFoundError
		if errors.Is(runErr, playbook.ErrNoTargets) {
			return fmt.Errorf("%s: %w", i18n.T("play_err_no_targets"), runErr)
		} else if errors.As(runErr, &targetErr) {
			return fmt.Errorf("%s: %w", i18n.Tf("play_err_node_not_found", map[string]any{"Node": targetErr.Target}), runErr)
		}
		return runErr
	}

	if err := report.RenderTo(o.outputWriter()); err != nil {
		return fmt.Errorf("write playbook report failed: %w", err)
	}

	executionErr := playbookExecutionError(report)
	if runErr != nil || executionErr != nil {
		return fmt.Errorf("%s: %w", i18n.T("play_err_some_failed"), errors.Join(runErr, executionErr))
	}

	return nil
}

func playbookExecutionError(report *playbook.Report) error {
	if report == nil {
		return nil
	}

	var executionErrs []error
	for _, host := range report.Hosts {
		hostHasDetailedError := false
		for _, step := range host.Steps {
			if step.Status != playbook.StatusFailed || step.Err == nil {
				continue
			}
			hostHasDetailedError = true
			executionErrs = append(executionErrs, fmt.Errorf("host %s step %s failed: %w", host.NodeID, step.StepName, step.Err))
		}
		if host.Status != playbook.HostStatusSuccess && !hostHasDetailedError {
			executionErrs = append(executionErrs, fmt.Errorf("host %s execution %s", host.NodeID, host.Status))
		}
	}
	return errors.Join(executionErrs...)
}

// printDryRun 在 Dry Run 模式下打印 Playbook 摘要。
func (o *PlayOptions) printDryRun(pb *playbook.Playbook) error {
	w := o.outputWriter()
	if _, err := fmt.Fprintf(w, "🔍 %s\n\n", i18n.T("play_dry_run")); err != nil {
		return fmt.Errorf("write dry-run header failed: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Playbook : %s\n", pb.Name); err != nil {
		return fmt.Errorf("write dry-run playbook name failed: %w", err)
	}
	if pb.Description != "" {
		if _, err := fmt.Fprintf(w, "Desc     : %s\n", pb.Description); err != nil {
			return fmt.Errorf("write dry-run description failed: %w", err)
		}
	}
	if _, err := fmt.Fprintf(w, "Targets  : tags=%v nodes=%v hosts=%v\n",
		pb.Targets.Tags, pb.Targets.Nodes, pb.Targets.Hosts); err != nil {
		return fmt.Errorf("write dry-run targets failed: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Settings : concurrency=%d, sudo=%v, on_error=%s\n",
		pb.Settings.Concurrency, pb.Settings.Sudo, pb.Settings.OnError); err != nil {
		return fmt.Errorf("write dry-run settings failed: %w", err)
	}
	if _, err := fmt.Fprintf(w, "Steps    : %d\n\n", len(pb.Steps)); err != nil {
		return fmt.Errorf("write dry-run step count failed: %w", err)
	}

	for i, s := range pb.Steps {
		stepType := stepTypeName(s)
		if _, err := fmt.Fprintf(w, "  [%d] %-20s (%s)\n", i+1, s.Name, stepType); err != nil {
			return fmt.Errorf("write dry-run step failed: %w", err)
		}
	}
	return nil
}

func (o *PlayOptions) outputWriter() io.Writer {
	if o.Out != nil {
		return o.Out
	}
	return os.Stdout
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
