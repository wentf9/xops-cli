package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
	pkgutils "github.com/wentf9/xops-cli/pkg/utils"
)

const maxBatchTaskCount = 1024

type ExecOptions struct {
	interaction *cliInteractionHandler
	SshOptions
	HostFile       string
	ShellFile      string
	Command        string
	Tag            string
	Exclude        []string
	rawExcludeArgs []string
	excludeSet     bool
	TaskCount      int
	Interactive    bool
	Stream         bool
	OutDir         string

	ScriptArgs []string

	stdinScript bool

	stdout io.Writer
	stderr io.Writer
}

func NewExecOptions() *ExecOptions {
	sshOpts := *NewSshOptions()
	sshOpts.nonHostArgs = true
	return &ExecOptions{
		SshOptions: sshOpts,
		TaskCount:  1,
	}
}

func NewCmdExec() *cobra.Command {
	return newCmdExecWithOptions(NewExecOptions())
}

func newCmdExecWithOptions(o *ExecOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exec [flags] [command] [-- [arg...]]",
		Short: i18n.T("exec_short"),

		Long: i18n.T("exec_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.stdout = cmd.OutOrStdout()
			o.stderr = cmd.ErrOrStderr()
			if err := o.Complete(cmd, args); err != nil {
				return err
			}
			if err := o.Validate(); err != nil {
				return err
			}
			return o.RunContext(cmd.Context())
		},
	}

	// OpenSSH-compatible flags
	cmd.Flags().Uint16VarP(&o.Port, "port", "p", 0, i18n.T("flag_port"))
	cmd.Flags().StringVarP(&o.User, "login", "l", "", i18n.T("flag_login"))
	cmd.Flags().StringArrayVarP(&o.IdentityFiles, "identity", "i", nil, i18n.T("flag_identity"))
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "J", "", i18n.T("flag_jump"))
	o.control.RegisterCommonFlags(cmd)

	// xops-enhanced flags (long-form only, no short flags to avoid OpenSSH conflicts)
	cmd.Flags().StringVar(&o.Host, "host", "", i18n.T("flag_hosts"))
	cmd.Flags().BoolVar(&o.PasswordStdin, "password-stdin", false, i18n.T("flag_password_stdin"))
	cmd.Flags().BoolVar(&o.PassphraseStdin, "passphrase-stdin", false, i18n.T("flag_passphrase_stdin"))
	cmd.Flags().StringVar(&o.OTP, "otp", "", i18n.T("flag_otp"))
	cmd.Flags().BoolVar(&o.OTPStdin, "otp-stdin", false, i18n.T("flag_otp_stdin"))
	cmd.Flags().StringVar(&o.Remember, "remember", "", i18n.T("flag_remember"))
	cmd.Flags().StringVar(&o.Alias, "alias", "", i18n.T("flag_alias"))
	cmd.Flags().BoolVar(&o.Sudo, "sudo", false, i18n.T("flag_exec_sudo"))

	// exec-specific flags
	cmd.Flags().StringVarP(&o.Command, "cmd", "c", "", i18n.T("flag_exec_cmd"))
	cmd.Flags().StringVarP(&o.HostFile, "ifile", "I", "", i18n.T("flag_exec_ifile"))
	cmd.Flags().StringVar(&o.Tag, "tag", "", i18n.T("flag_exec_tag"))
	utils.RegisterExcludeFlag(cmd.Flags(), &o.Exclude, &o.rawExcludeArgs, i18n.T("flag_exclude"))
	cmd.Flags().StringVar(&o.ShellFile, "shell", "", i18n.T("flag_exec_shell"))
	cmd.Flags().IntVar(&o.TaskCount, "task", 3, i18n.T("flag_exec_task"))
	cmd.Flags().BoolVarP(&o.Interactive, "interactive", "x", false, i18n.T("flag_exec_interactive"))
	cmd.Flags().BoolVar(&o.NoLoginShell, "no-login", false, i18n.T("flag_exec_no_login"))
	o.execution.register(cmd)
	cmd.Flags().BoolVar(&o.Stream, "stream", false, i18n.T("flag_exec_stream"))
	cmd.Flags().StringVar(&o.OutDir, "out-dir", "", i18n.T("flag_exec_out_dir"))

	cmd.MarkFlagsMutuallyExclusive("host", "ifile", "tag")
	cmd.MarkFlagsMutuallyExclusive("cmd", "shell")
	cmd.MarkFlagsMutuallyExclusive("stream", "out-dir")
	cmd.MarkFlagsMutuallyExclusive("otp", "otp-stdin")

	return cmd
}

func (o *ExecOptions) extractCommandFromArgs(args []string) error {
	hostPart := args[0]
	cmdIdx := 1
	if o.Host != "" || o.HostFile != "" || o.Tag != "" {
		o.Command = strings.Join(args, " ")
		return nil
	}
	if len(args) > 1 && strings.HasPrefix(args[1], "@") {
		hostPart = args[0] + args[1]
		cmdIdx = 2
	}
	u, h, p, err := utils.ParseAddr(hostPart)
	if err != nil {
		if strings.Contains(hostPart, "@") || strings.Contains(hostPart, ":") {
			return fmt.Errorf("invalid host address %q: %w", hostPart, err)
		}
		if o.Command == "" {
			o.Command = strings.Join(args, " ")
		}
		return nil
	}
	if h != "" && (strings.Contains(hostPart, "@") || !strings.Contains(hostPart, " ")) {
		if o.Host == "" {
			o.Host = h
		}
		if o.User == "" {
			o.User = u
		}
		if o.Port == 0 {
			o.Port = p
		}
		if o.Command == "" && len(args) > cmdIdx {
			o.Command = strings.Join(args[cmdIdx:], " ")
		}
	} else {
		if o.Command == "" {
			o.Command = strings.Join(args, " ")
		}
	}
	return nil
}

func parsePositionalHost(args []string) (host, user string, port uint16, consumed int, err error) {
	if len(args) == 0 {
		return "", "", 0, 0, nil
	}
	hostPart := args[0]
	consumed = 1
	if len(args) > 1 && strings.HasPrefix(args[1], "@") {
		hostPart = args[0] + args[1]
		consumed = 2
	}
	u, h, p, err := utils.ParseAddr(hostPart)
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("invalid host address %q: %w", hostPart, err)
	}
	return h, u, p, consumed, nil
}

func (o *ExecOptions) applySinglePositionalHost(args []string, extraArgErr func(string) error) error {
	if o.Host != "" || o.HostFile != "" || o.Tag != "" {
		if len(args) > 0 {
			return extraArgErr(args[0])
		}
		return nil
	}
	h, u, p, consumed, err := parsePositionalHost(args)
	if err != nil {
		return err
	}
	if h != "" {
		o.Host = h
		if o.User == "" {
			o.User = u
		}
		if o.Port == 0 {
			o.Port = p
		}
	}
	if len(args) > consumed {
		return extraArgErr(args[consumed])
	}
	return nil
}

func (o *ExecOptions) completeDashArgs(cmd *cobra.Command, args []string, dashIdx int) error {
	preDashArgs := args[:dashIdx]
	postDashArgs := args[dashIdx:]

	if err := o.applySinglePositionalHost(preDashArgs, func(arg string) error {
		return fmt.Errorf("unexpected positional argument %q before '--'", arg)
	}); err != nil {
		return err
	}

	if o.ShellFile != "" {
		o.ScriptArgs = append([]string(nil), postDashArgs...)
		return nil
	}

	if (cmd != nil && cmd.Flags().Changed("cmd")) || o.Command != "" {
		return fmt.Errorf("cannot specify both -c/--cmd and command after '--'")
	}
	o.Command = strings.Join(postDashArgs, " ")
	if len(postDashArgs) == 0 || o.Command == "" {
		return fmt.Errorf("explicit command must not be empty")
	}
	return nil
}

func (o *ExecOptions) completeNonDashArgs(cmd *cobra.Command, args []string) error {
	if o.ShellFile != "" {
		return o.applySinglePositionalHost(args, func(arg string) error {
			return fmt.Errorf("script arguments must be passed after '--', unexpected positional argument %q", arg)
		})
	}

	if (cmd != nil && cmd.Flags().Changed("cmd")) || o.Command != "" {
		return o.applySinglePositionalHost(args, func(arg string) error {
			return fmt.Errorf("unexpected positional argument %q when -c/--cmd is specified", arg)
		})
	}

	if len(args) > 0 {
		if err := o.extractCommandFromArgs(args); err != nil {
			return err
		}
		if o.Command == "" && args[len(args)-1] == "" {
			return fmt.Errorf("explicit command must not be empty")
		}
	}
	return nil
}

func validateExplicitEmptySelectors(cmd *cobra.Command) error {
	if cmd == nil {
		return nil
	}
	for _, name := range []string{"host", "tag", "ifile"} {
		if !cmd.Flags().Changed(name) {
			continue
		}
		value, err := cmd.Flags().GetString(name)
		if err != nil {
			return err
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("flag --%s must not be empty", name)
		}
	}
	return nil
}

func (o *ExecOptions) validateNonBlankSelectors() error {
	for _, sel := range []struct {
		name string
		val  string
	}{
		{"host", o.Host},
		{"tag", o.Tag},
		{"ifile", o.HostFile},
	} {
		if sel.val != "" && strings.TrimSpace(sel.val) == "" {
			return fmt.Errorf("flag --%s must not be empty", sel.name)
		}
	}
	return nil
}

func (o *ExecOptions) Complete(cmd *cobra.Command, args []string) error {
	o.args = args
	o.nonHostArgs = true
	o.appliedGeneralOpts = false
	var flags *pflag.FlagSet
	if cmd != nil {
		flags = cmd.Flags()
	}
	if err := ApplyGeneralOptions(&o.SshOptions, o.control.Options, flags); err != nil {
		return err
	}
	if err := validateExplicitZeroPort(flags); err != nil {
		return err
	}
	if err := validateExplicitEmptySelectors(cmd); err != nil {
		return err
	}
	if _, err := o.toSessionControlOptions(); err != nil {
		return err
	}
	o.execution.capturePresence(cmd)
	if cmd != nil && cmd.Flags().Changed("exclude") {
		o.excludeSet = true
	}
	if _, err := o.validatedExcludes(); err != nil {
		return err
	}
	if cmd != nil && cmd.Flags().Changed("cmd") && o.Command == "" {
		return fmt.Errorf("explicit command must not be empty")
	}

	dashIdx := -1
	if cmd != nil {
		dashIdx = cmd.ArgsLenAtDash()
	}

	if dashIdx >= 0 {
		if err := o.completeDashArgs(cmd, args, dashIdx); err != nil {
			return err
		}
	} else {
		if err := o.completeNonDashArgs(cmd, args); err != nil {
			return err
		}
	}

	if err := o.prepareCommandPlan(); err != nil {
		return err
	}
	if err := o.validateInteractiveOptions(); err != nil {
		return err
	}
	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}
	return o.completeInput(ctx)
}

func (o *ExecOptions) readStdinIfRequired(ctx context.Context) error {
	if o.Interactive {
		return nil
	}
	if o.Command == "" && o.ShellFile == "" {
		stat, err := os.Stdin.Stat()
		if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
			var limit int64
			if o.execution.enabled() {
				limit = ssh.MaxCommandInputBytes
			}
			content, err := readExecScriptInput(ctx, os.Stdin, limit)
			if err != nil {
				return fmt.Errorf("read stdin script: %w", err)
			}
			if len(content) > 0 {
				o.Command = string(content)
				o.stdinScript = true
			}
		}
	}
	return nil
}

func (o *ExecOptions) hasExcludeFlags() bool {
	return o.excludeSet || len(o.Exclude) > 0 || len(o.rawExcludeArgs) > 0
}

func (o *ExecOptions) validatedExcludes() ([]string, error) {
	if !o.hasExcludeFlags() {
		return nil, nil
	}
	if len(o.rawExcludeArgs) > 0 {
		parsed, err := utils.ValidateExcludeFlagValues(o.rawExcludeArgs)
		if err != nil {
			return nil, err
		}
		if len(o.Exclude) > 0 {
			return utils.ValidateExcludeFlagValues(o.Exclude)
		}
		return parsed, nil
	}
	return utils.ValidateExcludeFlagValues(o.Exclude)
}

func (o *ExecOptions) Validate() error {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return err
	}
	if err := o.control.Validate(); err != nil {
		return err
	}
	if err := validateCommonSSHBaseOptions(&o.SshOptions); err != nil {
		return err
	}
	if _, err := o.validatedExcludes(); err != nil {
		return err
	}
	if o.TaskCount < 1 || o.TaskCount > maxBatchTaskCount {
		return fmt.Errorf("invalid --task value %d: must be between 1 and %d", o.TaskCount, maxBatchTaskCount)
	}
	if err := o.prepareCommandPlan(); err != nil {
		return err
	}
	if o.Command == "" && o.ShellFile == "" {
		return fmt.Errorf("%s", i18n.T("exec_err_no_cmd"))
	}
	if o.Command != "" && o.ShellFile != "" {
		return fmt.Errorf("cannot specify both command and --shell script")
	}
	if err := o.validateNonBlankSelectors(); err != nil {
		return err
	}
	if o.Host == "" && o.HostFile == "" && o.Tag == "" {
		return fmt.Errorf("%s", i18n.T("err_no_host"))
	}
	return o.validateInteractiveOptions()
}

func (o *ExecOptions) validateInteractiveOptions() error {
	if !o.Interactive {
		return nil
	}
	if o.Command == "" && o.ShellFile == "" {
		return fmt.Errorf("%s", i18n.T("exec_err_no_cmd"))
	}
	if o.Stream || o.OutDir != "" {
		return fmt.Errorf("PTY output cannot be combined with --stream or --out-dir")
	}
	if o.stdinScript {
		return fmt.Errorf("PTY commands cannot use stdin scripts")
	}
	if o.Sudo && o.NoLoginShell && !o.execution.enabled() {
		return fmt.Errorf("--no-login with privileged PTY commands requires an explicit interpreter")
	}
	if o.ShellFile != "" {
		return fmt.Errorf("%s", i18n.T("exec_err_interactive_shell"))
	}
	if o.HostFile != "" || o.Tag != "" || strings.Contains(o.Host, ",") {
		return fmt.Errorf("%s", i18n.T("exec_err_interactive_multi_host"))
	}
	return nil
}

type execHostTask struct {
	nodeID        string
	matchedNodeID string
	baseNodeID    string
	openSSHAlias  string
	canonicalHost string
	resolvedHost  string
	rawHost       string
	host          string
	originalHost  string
	expandHost    string
	port          uint16
	user          string
	pass          string
	passphrase    string
	keyPath       string
	pendingTarget *config.ConnectionTarget
	pendingAddr   *utils.HostInfo
	isTaggedTask  bool
	outLogName    string
}

func (o *ExecOptions) Run() error {
	return o.RunContext(context.Background())
}

// RunContext executes the command on all selected hosts and propagates caller cancellation.
//
//nolint:gocyclo
func (o *ExecOptions) RunContext(ctx context.Context) (retErr error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return err
	}
	configPath, keyPath, pathErr := utils.GetConfigFilePath()
	if pathErr != nil {
		return fmt.Errorf("get config file path failed: %w", pathErr)
	}
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("config_load_error"), err)
	}
	repo, err := config.NewRepository(cfg, configStore)
	if err != nil {
		return fmt.Errorf("create configuration repository: %w", err)
	}
	provider, err := config.WithOpenSSHConfigOverride(repo, o.control.ConfigFile)
	if err != nil {
		return err
	}
	// 准备执行内容
	var execCmd string
	var isScript bool
	if o.ShellFile != "" {
		var limit int64
		if o.execution.enabled() {
			limit = ssh.MaxCommandInputBytes
		}
		content, err := readExecScriptFile(ctx, o.ShellFile, limit)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("exec_err_read_script"), err)
		}
		execCmd = string(content)
		isScript = true
	} else {
		execCmd = o.Command
		if o.stdinScript {
			isScript = true
		}
	}

	if isScript && o.execution.enabled() {
		if len(execCmd) > ssh.MaxCommandInputBytes {
			return fmt.Errorf("script exceeds %d bytes", ssh.MaxCommandInputBytes)
		}
	}

	var (
		tasks    []execHostTask
		hostErrs []error
		errTask  error
	)

	if o.Tag != "" {
		tasks, errTask = o.planTasksFromTags(ctx, provider)
	} else {
		tasks, hostErrs, errTask = o.planTasksFromHosts(ctx, provider)
	}

	if errTask != nil {
		return errTask
	}

	// 应用 --exclude 排除规则（在只读规划阶段完成过滤，避免被排除节点触碰磁盘或待定状态）
	if o.hasExcludeFlags() {
		parsedExcludes, err := o.validatedExcludes()
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("exec_err_exclude"), err)
		}
		candidates := make([]utils.ExcludeTargetInfo, 0, len(tasks))
		for _, t := range tasks {
			candidates = append(candidates, o.execTaskExcludeInfo(t))
		}
		excludes, err := utils.ResolveExcludesForTargetsWithOptions(provider, parsedExcludes, candidates, o.control.Options, o.effectiveCLIJumpHost())
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("exec_err_exclude"), err)
		}
		filtered := tasks[:0]
		for i, t := range tasks {
			if !utils.IsTargetExcluded(excludes, candidates[i]) {
				filtered = append(filtered, t)
			}
		}
		tasks = filtered
	}

	if len(tasks) == 0 {
		if len(hostErrs) > 0 {
			return errors.Join(hostErrs...)
		}
		return fmt.Errorf("%s", i18n.T("err_no_nodes_found"))
	}

	var matErrs []error
	var matErr error
	tasks, matErrs, matErr = o.materializeExecTasks(ctx, provider, tasks)
	if matErr != nil {
		return matErr
	}
	hostErrs = append(hostErrs, matErrs...)
	if len(tasks) == 0 {
		if len(hostErrs) > 0 {
			return errors.Join(hostErrs...)
		}
		return fmt.Errorf("%s", i18n.T("err_no_nodes_found"))
	}

	adpOpts, optErr := o.buildAdapterOptions(tasks, cfg, provider)
	if optErr != nil {
		return optErr
	}
	var connector *ssh.Connector
	if o.Interactive {
		connector = newCLIConnectorWithAdapterOptions(provider, o.interaction, adpOpts, ssh.WithLogger(logger.DefaultLogger()))
	} else {
		connector = newNonInteractiveConnector(provider, adpOpts, ssh.WithLogger(logger.DefaultLogger()))
	}
	defer func() {
		if handoffErr := o.handoffConnectorMasters(ctx, provider, connector); handoffErr != nil {
			logger.DefaultLogger().Debugf("mux: master handoff failed: %v", handoffErr)
		}
		joinConnectorCloseError(&retErr, connector)
	}()

	// 交互模式：单主机 PTY 执行
	if o.Interactive {
		return o.runInteractive(ctx, connector, tasks[0], execCmd)
	}

	// 落盘模式：在 Worker Pool 启动前一次性创建目录并分配无冲突日志文件名
	if o.OutDir != "" {
		if err := os.MkdirAll(o.OutDir, 0750); err != nil {
			return fmt.Errorf("failed to create output directory %s: %w", o.OutDir, err)
		}
		assignExecTaskLogNames(tasks)
	}

	// 流式模式下多个 goroutine 共享 os.Stdout，需要用 lockedWriter 保证写入原子性
	var stdoutMu sync.Mutex
	var errMu sync.Mutex
	var taskErrs []error

	// 批量模式：原有逻辑
	if o.TaskCount < 0 || o.TaskCount > maxBatchTaskCount {
		return fmt.Errorf("invalid --task value %d: must be between 1 and %d", o.TaskCount, maxBatchTaskCount)
	}
	wp := pkgutils.NewWorkerPool(uint(o.TaskCount))
	for _, task := range tasks {
		t := task // capture range variable
		wp.Execute(func() {
			if taskErr := o.executeTask(ctx, connector, t, execCmd, isScript, len(tasks), &stdoutMu); taskErr != nil {
				errMu.Lock()
				taskErrs = append(taskErrs, taskErr)
				errMu.Unlock()
			}
		})
	}

	wp.Wait()

	allErrs := append(taskErrs, hostErrs...)
	return errors.Join(allErrs...)
}

func (o *ExecOptions) runInteractive(
	ctx context.Context,
	connector *ssh.Connector,
	task execHostTask,
	cmd string,
) (retErr error) {
	if o.commandPlan != nil && o.commandPlan.Command() != cmd {
		return fmt.Errorf("[%s] command changed after execution planning", task.host)
	}
	client, err := connector.Connect(ctx, task.nodeID)
	if err != nil {
		return fmt.Errorf("[%s] %s: %w", task.host, i18n.T("fw_connect_failed"), err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("[%s] close ssh client failed: %w", task.host, closeErr))
		}
	}()

	var execErr error
	if o.Sudo && o.execution.enabled() {
		cliExec, optErr := o.cliExecutionConfig()
		if optErr != nil {
			return optErr
		}
		execution, optErr := ssh.ResolveExecution(cliExec, client.Execution())
		if optErr != nil {
			return optErr
		}
		execErr = client.RunInteractiveWithSudoExecution(ctx, cmd, execution)
	} else if o.commandPlan != nil || o.execution.enabled() {
		plan, planErr := o.resolveCommandPlan(cmd, client.Execution())
		if planErr != nil {
			return fmt.Errorf("[%s] %w", task.host, planErr)
		}
		execErr = client.RunInteractivePlan(ctx, plan)
	} else if o.Sudo {
		execErr = client.RunInteractiveWithSudo(ctx, cmd)
	} else {
		opts := client.Execution().CommandOptions()
		if o.execution.enabled() || o.execution.noLoginSet {
			cliOpts, optErr := o.execution.commandOptions(o.NoLoginShell)
			if optErr != nil {
				return optErr
			}
			opts = cliOpts
		}
		plan, planErr := ssh.PlanCommand(cmd, opts)
		if planErr != nil {
			return fmt.Errorf("[%s] plan interactive command: %w", task.host, planErr)
		}
		execErr = client.RunInteractiveCmd(ctx, plan.Payload())
	}

	return execErr
}

func (o *ExecOptions) buildAdapterOptions(tasks []execHostTask, cfg *config.Configuration, repository config.ConfigProvider) ([]adapter.Option, error) {
	if o.interaction == nil {
		o.interaction = newCLIInteractionHandler()
	}
	policy := utils.EffectiveRememberPolicy(o.Remember, cfg)
	remember, adpOpts := o.interaction.rememberOptions(policy, cfg)
	if !o.Interactive {
		remember = false
		// Batch execution must fail closed instead of waiting for a terminal
		// prompt, and must never record automatically discovered credentials.
		adpOpts = append(adpOpts, adapter.WithNonInteractive(true))
	}
	suppressConfirm := policy == utils.RememberPolicyNever || !o.Interactive
	if suppressConfirm {
		adpOpts = append(adpOpts, adapter.WithSuppressNodeConfirmation(true))
	}
	// A global policy applies to proxy-jump nodes, which do not have a task
	// specific override. Explicit task credentials remain scoped to their target.
	adpOpts = append(adpOpts, adapter.WithForwardOptions(false), adapter.WithGlobalSessionAuth(adapter.SessionAuth{
		Remember:                 remember,
		SuppressNodeConfirmation: suppressConfirm,
	}))
	cliAbsKeys := o.absIdentityFiles()
	if err := o.validateMultiHostStaticHostName(tasks); err != nil {
		return nil, err
	}
	o.targetNodeIDs = make([]string, 0, len(tasks))
	for _, task := range tasks {
		o.targetNodeIDs = append(o.targetNodeIDs, task.nodeID)
		auth, err := o.buildTaskSessionAuth(task, cliAbsKeys, remember, suppressConfirm)
		if err != nil {
			return nil, err
		}
		adpOpts = append(adpOpts, adapter.WithSessionAuthOverride(task.nodeID, auth))
	}

	// Session Control Overrides (Tier 1)
	sessionCtrlOpts, err := o.toSessionControlOptions()
	if err != nil {
		return nil, err
	}
	if !sessionCtrlOpts.IsEmpty() {
		if globalCtrl := sessionCtrlOpts.ConnectionWideOptions(); !globalCtrl.IsEmpty() {
			adpOpts = append(adpOpts, adapter.WithGlobalSessionControl(globalCtrl))
		}
		for _, task := range tasks {
			adpOpts = append(adpOpts, adapter.WithSessionControlOverride(task.nodeID, sessionCtrlOpts))
		}
	}
	if reg, regErr := utils.GetCredentialRegistry(cfg); regErr != nil {
		return nil, fmt.Errorf("initialize credential resolver: %w", regErr)
	} else if reg != nil {
		adpOpts = append(adpOpts, adapter.WithCredentialSource(reg))
	}
	if repo, isRepo := repository.(*config.Repository); !isRepo {
		adpOpts = append(adpOpts, adapter.WithCredentialRecording(false), adapter.WithSuppressNodeConfirmation(true))
	} else if remember {
		adpOpts = append(adpOpts, enrollmentProbeOption())
		if o.execution.enabled() || o.execution.noLoginSet {
			for _, task := range tasks {
				adpOpts = append(adpOpts, adapter.WithEnrollmentProbeExclusions(task.nodeID))
			}
		}
		persistence, err := o.interaction.automaticPersistenceOptions(repo, cfg)
		if err != nil {
			return nil, err
		}
		adpOpts = append(adpOpts, persistence...)
	}
	return adpOpts, nil
}

func (o *ExecOptions) validateMultiHostStaticHostName(tasks []execHostTask) error {
	if len(tasks) <= 1 {
		return nil
	}
	staticHostName := o.staticHostNameOverride()
	if staticHostName == "" {
		return nil
	}
	distinctHosts := make(map[string]struct{}, len(tasks))
	for _, task := range tasks {
		h := strings.TrimSpace(task.originalHost)
		if h == "" {
			h = strings.TrimSpace(task.expandHost)
		}
		if h == "" {
			h = strings.TrimSpace(task.host)
		}
		if h == "" {
			h = strings.TrimSpace(task.nodeID)
		}
		distinctHosts[h] = struct{}{}
	}
	if len(distinctHosts) > 1 {
		return fmt.Errorf("static HostName %q cannot be used with multiple distinct remote hosts; use %%h or omit -o HostName", staticHostName)
	}
	return nil
}

func (o *ExecOptions) buildTaskSessionAuth(task execHostTask, cliAbsKeys []string, remember, suppressConfirm bool) (adapter.SessionAuth, error) {
	hostForExpansion := task.expandHost
	if hostForExpansion == "" {
		hostForExpansion = task.originalHost
	}
	if hostForExpansion == "" {
		hostForExpansion = task.host
	}
	hostNameOverride, hostErr := o.effectiveHostNameForHost(hostForExpansion)
	if hostErr != nil {
		return adapter.SessionAuth{}, hostErr
	}
	taskKeys := cliAbsKeys
	if task.keyPath != "" && (len(taskKeys) == 0 || taskKeys[0] != task.keyPath) {
		taskKeys = append([]string{task.keyPath}, taskKeys...)
	}
	keyPath := task.keyPath
	if keyPath == "" && len(taskKeys) > 0 {
		keyPath = taskKeys[0]
	}
	return adapter.SessionAuth{
		Password:                 task.pass,
		Passphrase:               task.passphrase,
		KeyPath:                  keyPath,
		KeyPaths:                 taskKeys,
		HostName:                 hostNameOverride,
		OriginalHost:             task.originalHost,
		CanonicalHost:            task.canonicalHost,
		Remember:                 remember,
		SuppressNodeConfirmation: suppressConfirm,
		OTP:                      o.OTP,
		ProxyJump:                o.JumpHost,
	}, nil
}

func (o *ExecOptions) shouldRememberCredential(target string, cfg *config.Configuration) bool {
	if !o.Interactive {
		return false
	}
	return utils.ShouldRememberConfiguredCredential(utils.EffectiveRememberPolicy(o.Remember, cfg), target, cfg)
}

func (o *ExecOptions) getOrCreateNode(ctx context.Context, provider config.ConfigProvider, target config.ConnectionTarget, addr utils.HostInfo) (string, bool, error) {
	o.syncIdentityFiles()
	preparer, isPreparer := provider.(interface {
		PrepareNodeContext(context.Context, config.EnsureNodeOptions) (config.EnsureNodeResult, error)
	})
	if !isPreparer {
		resolved, err := config.ResolveTarget(provider, target)
		if err != nil {
			return "", false, err
		}
		if resolved.MatchedNodeID != "" {
			return resolved.MatchedNodeID, false, nil
		}
		return resolved.NodeID, false, nil
	}
	identityFile := addr.KeyPath
	if identityFile == "" {
		identityFile = o.IdentityFile
	}
	alias := addr.Alias
	if alias == "" {
		alias = o.Alias
	}

	sudoMode := models.SudoModeAuto
	if o.Sudo {
		sudoMode = models.SudoModeSudo
	}
	res, err := preparer.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target:       target,
		Password:     "",
		IdentityFile: identityFile,
		Passphrase:   "",
		Alias:        alias,
		SudoMode:     sudoMode,
		SuPwd:        "",
	})
	if err != nil {
		return "", false, err
	}

	if res.Created {
		return res.NodeID, true, nil
	}

	updated, updateErr := o.updateNodeFromHostInfo(ctx, res.NodeID, provider, addr)
	if updateErr != nil {
		return "", false, updateErr
	}
	return res.NodeID, updated, nil
}

func (o *ExecOptions) isPlannedCommandMismatch(execCmd string, isScript bool) bool {
	return isScript ||
		(o.commandPlan != nil && o.commandPlan.Command() != execCmd) ||
		(o.commandPlan == nil && o.Command != execCmd)
}

func (o *ExecOptions) executeTask(ctx context.Context, connector *ssh.Connector, t execHostTask, execCmd string, isScript bool, totalTasks int, stdoutMu *sync.Mutex) (retErr error) {
	if o.commandPlan != nil || (!isScript && o.execution.enabled()) {
		if o.isPlannedCommandMismatch(execCmd, isScript) {
			return fmt.Errorf("[%s] command changed after execution planning", t.host)
		}
		if !o.Sudo && !o.Stream && o.OutDir == "" {
			return o.executePlannedTask(ctx, connector, t, execCmd, isScript, stdoutMu)
		}
	}
	if o.execution.enabled() {
		// This task owns cancellation; output and privilege workers finish before return.
		work, cancel := context.WithTimeout(ctx, ssh.DefaultCommandTimeout)
		defer cancel()
		ctx = work
	}
	client, err := connector.Connect(ctx, t.nodeID)
	if err != nil {
		return fmt.Errorf("[%s] connect failed: %w", t.host, err)
	}

	var outputOpts []ssh.RunOption

	if o.OutDir != "" {
		logFile := resolveTaskLogPath(o.OutDir, t)
		f, openErr := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if openErr != nil {
			return fmt.Errorf("[%s] open log file %s failed: %w", t.host, logFile, openErr)
		}
		defer func() {
			joinExecLogCloseError(&retErr, f, t.host, logFile)
		}()
		outputOpts = append(outputOpts, ssh.WithOutFile(f))
	} else if o.Stream || (totalTasks == 1 && !o.execution.enabled()) {
		prefix := ""
		if totalTasks > 1 {
			if logger.ColorEnabled() {
				prefix = logger.Cyan(fmt.Sprintf("[%s] ", t.host))
			} else {
				prefix = fmt.Sprintf("[%s] ", t.host)
			}
		}
		// 使用 lockedWriter 包装 os.Stdout，防止多 goroutine 写入交错
		outputOpts = append(outputOpts, ssh.WithStream(ssh.NewLockedWriter(stdoutMu, o.stdoutWriter()), prefix))
	} else {
		outputOpts = append(outputOpts, ssh.WithRingBuffer(5*1024*1024))
	}

	output, execErr := o.dispatchTaskExecution(ctx, client, execCmd, isScript, outputOpts)

	printErr := o.printTaskResult(ctx, t, output, execErr, stdoutMu)
	if execErr != nil {
		return errors.Join(fmt.Errorf("[%s] %w", t.host, execErr), printErr)
	}
	return printErr
}

func (o *ExecOptions) cliExecutionConfig() (*ssh.ExecutionConfig, error) {
	return o.execution.toExecutionConfig(o.NoLoginShell)
}

func usesWindowsCommandPlanAdapter(execCfg *ssh.ExecutionConfig) bool {
	if execCfg == nil {
		return false
	}
	switch execCfg.Interpreter {
	case ssh.InterpreterPowerShell, ssh.InterpreterPwsh, ssh.InterpreterCmd:
		return true
	default:
		return false
	}
}

func (o *ExecOptions) dispatchTaskExecution(ctx context.Context, client *ssh.Client, execCmd string, isScript bool, outputOpts []ssh.RunOption) (string, error) {
	if isScript {
		cliExec, err := o.cliExecutionConfig()
		if err != nil {
			return "", err
		}
		resolvedExec, err := ssh.ResolveScriptExecution(cliExec, nil, client.Execution(), nil, []byte(execCmd))
		if err != nil {
			return "", err
		}
		scriptOpts := outputOpts
		if len(o.ScriptArgs) > 0 {
			scriptOpts = append(append([]ssh.RunOption(nil), outputOpts...), ssh.WithScriptArgs(o.ScriptArgs...))
		}
		if o.Sudo {
			return client.RunScriptWithSudoExecution(ctx, execCmd, resolvedExec, scriptOpts...)
		}
		return client.RunScriptWithExecution(ctx, execCmd, resolvedExec, scriptOpts...)

	}
	if o.commandPlan != nil || o.execution.enabled() {
		if o.Sudo {
			cliExec, err := o.cliExecutionConfig()
			if err != nil {
				return "", err
			}
			execution, err := ssh.ResolveExecution(cliExec, client.Execution())
			if err != nil {
				return "", err
			}
			return client.RunWithSudoExecution(ctx, execCmd, execution, outputOpts...)
		}
		plan, err := o.resolveCommandPlan(execCmd, client.Execution())
		if err != nil {
			return "", err
		}
		// The interpreter has already been applied by PlanCommand. Send its
		// frozen payload unchanged through the existing output-mode adapters.
		opts := append([]ssh.RunOption{}, outputOpts...)
		opts = append(opts, ssh.WithInterpreter(ssh.InterpreterServer), ssh.WithLaunchDialect(ssh.LaunchUnknown))
		return client.Run(ctx, plan.Payload(), opts...)
	}
	if !o.Sudo && !o.execution.noLoginSet && !o.NoLoginShell && usesWindowsCommandPlanAdapter(client.Execution()) {
		plan, err := ssh.PlanCommand(execCmd, client.Execution().CommandOptions())
		if err != nil {
			return "", fmt.Errorf("plan command: %w", err)
		}
		opts := append([]ssh.RunOption{}, outputOpts...)
		opts = append(opts, ssh.WithInterpreter(ssh.InterpreterServer), ssh.WithLaunchDialect(ssh.LaunchUnknown))
		return client.Run(ctx, plan.Payload(), opts...)
	}
	cmdOpts := o.commandRunOptions(client.Execution(), outputOpts)
	if o.Sudo {
		return client.RunWithSudo(ctx, execCmd, cmdOpts...)
	}
	return client.Run(ctx, execCmd, cmdOpts...)
}

// commandRunOptions retains legacy Bash defaults while respecting configured
// zsh/fish login modes unless the caller explicitly selects --no-login.
func (o *ExecOptions) commandRunOptions(execution *ssh.ExecutionConfig, outputOpts []ssh.RunOption) []ssh.RunOption {
	var options []ssh.RunOption
	portable := execution != nil && (execution.Interpreter == ssh.InterpreterZsh || execution.Interpreter == ssh.InterpreterFish || execution.Interpreter == ssh.InterpreterCsh || execution.Interpreter == ssh.InterpreterTcsh || execution.LaunchDialect == ssh.LaunchFish || execution.LaunchDialect == ssh.LaunchCsh)
	if !portable || o.execution.noLoginSet || o.NoLoginShell {
		options = append(options, ssh.WithLoginShell(!o.NoLoginShell))
	}
	options = append(options, outputOpts...)
	if o.execution.noLoginSet || o.NoLoginShell {
		options = append(options, ssh.WithInterpreter(ssh.InterpreterBash))
	}
	return options
}

func joinExecLogCloseError(retErr *error, closer io.Closer, host, logFile string) {
	if closeErr := closer.Close(); closeErr != nil {
		*retErr = errors.Join(*retErr, fmt.Errorf("[%s] close log file %s failed: %w", host, logFile, closeErr))
	}
}

func (o *ExecOptions) stdoutWriter() io.Writer {
	if o.stdout != nil {
		return o.stdout
	}
	return os.Stdout
}

func (o *ExecOptions) stderrWriter() io.Writer {
	if o.stderr != nil {
		return o.stderr
	}
	return os.Stderr
}

func writeExecResult(ctx context.Context, mu *sync.Mutex, writer io.Writer, format string, args ...any) error {
	return writeCommandOutput(ctx, ssh.NewLockedWriter(mu, writer), func(bound io.Writer) error {
		_, err := fmt.Fprintf(bound, format, args...)
		return err
	})
}

func (o *ExecOptions) printTaskResult(ctx context.Context, t execHostTask, output string, execErr error, stdoutMu *sync.Mutex) error {
	if HasStandardOutputError(execErr) {
		return nil
	}

	if execErr != nil {
		// 仅在有部分输出时将标准输出打印出来（错误本身交给根命令统一汇报）
		if output != "" {
			if logger.ColorEnabled() {
				header := logger.Cyan(fmt.Sprintf("%s\n------------", t.host))
				return writeExecResult(ctx, stdoutMu, o.stderrWriter(), "%s\n%s\n", header, output)
			} else {
				return writeExecResult(ctx, stdoutMu, o.stderrWriter(), "[%s]\n%s\n", t.host, output)
			}
		}
		return nil
	}
	if output != "" {
		if logger.ColorEnabled() {
			header := logger.Cyan(fmt.Sprintf("%s\n------------", t.host))
			return writeExecResult(ctx, stdoutMu, o.stdoutWriter(), "%s\n%s\n", header, output)
		}
		return writeExecResult(ctx, stdoutMu, o.stdoutWriter(), "%s\n", i18n.Tf("exec_result_success", map[string]any{"Host": t.host, "Output": output}))
	}
	if o.OutDir != "" {
		logFile := resolveTaskLogPath(o.OutDir, t)
		message := fmt.Sprintf("[%s] Executed successfully (output saved to %s)", t.host, logFile)
		if logger.ColorEnabled() {
			hostPart := logger.Cyan(fmt.Sprintf("[%s] ", t.host))
			successPart := logger.Green(fmt.Sprintf("Executed successfully (output saved to %s)", logFile))
			message = hostPart + successPart
		}
		return writeExecResult(ctx, stdoutMu, o.stdoutWriter(), "%s\n", message)
	}
	message := fmt.Sprintf("[%s] Executed successfully", t.host)
	if logger.ColorEnabled() {
		hostPart := logger.Cyan(fmt.Sprintf("[%s] ", t.host))
		successPart := logger.Green("Executed successfully")
		message = hostPart + successPart
	}
	return writeExecResult(ctx, stdoutMu, o.stdoutWriter(), "%s\n", message)
}

// sanitizeHostForFilename 清洗主机名，防止路径穿越、非法文件名与 Windows 保留设备名/NTFS ADS 问题。
func sanitizeHostForFilename(host string) string {
	safe := ssh.SanitizeFilenameComponent(host)
	if strings.Trim(safe, "_") == "" {
		return "unknown_host"
	}
	return safe
}

func resolveTaskLogPath(outDir string, t execHostTask) string {
	name := t.outLogName
	if name == "" {
		name = sanitizeHostForFilename(t.host) + ".log"
	}
	return filepath.Join(outDir, name)
}

func disambiguatedTaskLogBase(base string, t execHostTask) string {
	var candidate string
	switch {
	case t.nodeID != "":
		candidate = sanitizeHostForFilename(t.nodeID)
	case t.user != "" && t.port != 0:
		candidate = sanitizeHostForFilename(fmt.Sprintf("%s@%s:%d", t.user, t.host, t.port))
	case t.user != "":
		candidate = sanitizeHostForFilename(fmt.Sprintf("%s@%s", t.user, t.host))
	case t.port != 0:
		candidate = sanitizeHostForFilename(fmt.Sprintf("%s:%d", t.host, t.port))
	default:
		candidate = base
	}
	if candidate == "" {
		return base
	}
	return candidate
}

func assignExecTaskLogNames(tasks []execHostTask) {
	if len(tasks) == 0 {
		return
	}
	baseNames := make([]string, len(tasks))
	baseCounts := make(map[string]int, len(tasks))
	for i, t := range tasks {
		base := sanitizeHostForFilename(t.host)
		baseNames[i] = base
		baseCounts[strings.ToLower(base)]++
	}

	used := make(map[string]struct{}, len(tasks))
	for i, base := range baseNames {
		key := strings.ToLower(base)
		if baseCounts[key] == 1 {
			tasks[i].outLogName = base + ".log"
			used[key] = struct{}{}
		}
	}

	for i, t := range tasks {
		if tasks[i].outLogName != "" {
			continue
		}
		candidate := disambiguatedTaskLogBase(baseNames[i], t)
		finalBase := candidate
		if _, exists := used[strings.ToLower(finalBase)]; exists {
			for n := 2; ; n++ {
				numbered := fmt.Sprintf("%s_%d", candidate, n)
				if _, taken := used[strings.ToLower(numbered)]; !taken {
					finalBase = numbered
					break
				}
			}
		}
		used[strings.ToLower(finalBase)] = struct{}{}
		tasks[i].outLogName = finalBase + ".log"
	}
}

func (o *ExecOptions) buildTasksFromTags(ctx context.Context, provider config.ConfigProvider) ([]execHostTask, error) {
	tasks, err := o.planTasksFromTags(ctx, provider)
	if err != nil || len(o.Exclude) > 0 {
		return tasks, err
	}
	materialized, _, mErr := o.materializeExecTasks(ctx, provider, tasks)
	return materialized, mErr
}

func (o *ExecOptions) planTasksFromTags(ctx context.Context, provider config.ConfigProvider) ([]execHostTask, error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return nil, err
	}
	o.syncIdentityFiles()
	nodes := provider.GetNodesByTag(o.Tag)
	if len(nodes) == 0 {
		return nil, fmt.Errorf("%s", i18n.Tf("err_tag_empty", map[string]any{"Tag": o.Tag}))
	}
	tasks := make([]execHostTask, 0, len(nodes))
	userOverride := strings.TrimSpace(o.User)
	keyPath := ""
	if o.IdentityFile != "" {
		keyPath = normalizeCLIIdentityPath(o.IdentityFile)
	}
	for _, nodeID := range slices.Sorted(maps.Keys(nodes)) {
		task, err := o.planTaggedHostTask(ctx, provider, nodeID, userOverride, keyPath)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, nil
}

func (o *ExecOptions) resolveTaggedCredentials(
	userOverride string,
	identity models.Identity,
	resolved config.ResolvedTarget,
	hasResolved bool,
) (effectiveUser, password string) {
	effectiveUser = userOverride
	if effectiveUser == "" {
		if hasResolved && resolved.User != "" {
			effectiveUser = resolved.User
		} else {
			effectiveUser = identity.User
		}
	}
	if o.Password != "" {
		password = o.Password
	} else if effectiveUser == "" || effectiveUser == identity.User {
		password = identity.Password
	}
	return effectiveUser, password
}

func resolveTaggedHostAndPort(
	portOverride uint16,
	nodeID, targetSelector string,
	hostObj models.Host,
	resolved config.ResolvedTarget,
	hasResolved bool,
) (taskHost string, taskPort uint16) {
	taskPort = portOverride
	if taskPort == 0 {
		if hasResolved && resolved.Port > 0 {
			taskPort = resolved.Port
		} else {
			taskPort = hostObj.Port
		}
	}
	if taskPort == 0 {
		taskPort = 22
	}
	taskHost = hostObj.Address
	if targetSelector != nodeID {
		taskHost = targetSelector
	} else if hasResolved && strings.TrimSpace(resolved.Host) != "" {
		taskHost = strings.TrimSpace(resolved.Host)
	}
	return taskHost, taskPort
}

func (o *ExecOptions) planTaggedHostTask(
	ctx context.Context,
	provider config.ConfigProvider,
	nodeID, userOverride, keyPath string,
) (execHostTask, error) {
	_, hostObj, identity, resolveErr := provider.Resolve(nodeID)
	if resolveErr != nil {
		return execHostTask{}, fmt.Errorf("resolve tagged node %q failed: %w", nodeID, resolveErr)
	}
	target := config.ConnectionTarget{
		Selector:     nodeID,
		User:         userOverride,
		HasUser:      o.User != "",
		Port:         o.Port,
		HasPort:      o.Port != 0,
		ProxyJump:    o.JumpHost,
		HasProxyJump: o.JumpHost != "",
	}
	target, resolved, hasResolved, originalHost, expandHost, cErr := o.resolveExecHostTargetWithHint(ctx, provider, target, true)
	if cErr != nil {
		return execHostTask{}, fmt.Errorf("canonicalize tagged host %q: %w", nodeID, cErr)
	}
	effectiveUser, password := o.resolveTaggedCredentials(userOverride, identity, resolved, hasResolved)
	hasOverrides := o.User != "" || o.Port != 0 || o.JumpHost != "" || target.Selector != nodeID
	taskNodeID := nodeID
	var pendingTarget *config.ConnectionTarget
	var pendingAddr *utils.HostInfo
	if hasOverrides {
		if hasResolved {
			if resolved.MatchedNodeID != "" {
				taskNodeID = resolved.MatchedNodeID
			} else if resolved.NodeID != "" {
				taskNodeID = resolved.NodeID
			}
		}
		targetCopy := target
		addrCopy := utils.HostInfo{
			Host:       target.Selector,
			Port:       o.Port,
			User:       userOverride,
			Password:   password,
			Alias:      o.Alias,
			KeyPath:    o.IdentityFile,
			Passphrase: o.Passphrase,
		}
		pendingTarget = &targetCopy
		pendingAddr = &addrCopy
	}
	taskHost, taskPort := resolveTaggedHostAndPort(o.Port, nodeID, target.Selector, hostObj, resolved, hasResolved)
	matchedNodeID, baseNodeID := resolved.MatchedNodeID, resolved.BaseNodeID
	resolvedHost := resolved.Host
	if !hasResolved {
		baseNodeID = nodeID
		if !hasOverrides {
			matchedNodeID = nodeID
		}
		if resolvedHost == "" {
			resolvedHost = config.StripHostBrackets(hostObj.Address)
		}
	}
	return execHostTask{
		nodeID:        taskNodeID,
		matchedNodeID: matchedNodeID,
		baseNodeID:    baseNodeID,
		openSSHAlias:  resolved.OpenSSHAlias,
		canonicalHost: resolved.CanonicalHost,
		resolvedHost:  resolvedHost,
		rawHost:       nodeID,
		host:          taskHost,
		originalHost:  originalHost,
		expandHost:    expandHost,
		port:          taskPort,
		user:          effectiveUser,
		pass:          password,
		passphrase:    o.Passphrase,
		keyPath:       keyPath,
		pendingTarget: pendingTarget,
		pendingAddr:   pendingAddr,
		isTaggedTask:  true,
	}, nil
}

func (o *ExecOptions) execTaskExcludeInfo(t execHostTask) utils.ExcludeTargetInfo {
	hostForExpansion := t.expandHost
	if hostForExpansion == "" {
		hostForExpansion = t.originalHost
	}
	if hostForExpansion == "" {
		hostForExpansion = t.host
	}
	var hostNameOverride string
	if o != nil {
		if v, err := o.effectiveHostNameForHost(hostForExpansion); err == nil {
			hostNameOverride = v
		}
	}
	return utils.BuildExcludeTargetInfo(utils.ExcludeTargetBuildInput{
		NodeID:           t.nodeID,
		MatchedNodeID:    t.matchedNodeID,
		BaseNodeID:       t.baseNodeID,
		OpenSSHAlias:     t.openSSHAlias,
		CanonicalHost:    t.canonicalHost,
		ResolvedHost:     t.resolvedHost,
		User:             t.user,
		Port:             t.port,
		UnmanagedHosts:   []string{t.rawHost, t.host, t.originalHost},
		HostNameOverride: hostNameOverride,
	})
}

func isResolvedSavedNode(r config.ResolvedTarget) bool {
	if strings.TrimSpace(r.Host) == "" {
		return false
	}
	return (r.MatchedNodeID != "" && !strings.HasPrefix(r.MatchedNodeID, config.OpenSSHNodePrefix)) ||
		(r.BaseNodeID != "" && !strings.HasPrefix(r.BaseNodeID, config.OpenSSHNodePrefix))
}

func resolveTargetOriginalAndExpandHosts(canonicalized bool, canonOriginalHost, selector string, resolved config.ResolvedTarget, hasResolved bool) (originalHost, expandHost string) {
	if canonicalized {
		return canonOriginalHost, canonOriginalHost
	}
	if hasResolved && isResolvedSavedNode(resolved) {
		return "", strings.TrimSpace(resolved.Host)
	}
	originalHost = config.UnwrapOpenSSHSelector(selector)
	if originalHost == "" && hasResolved && resolved.OpenSSHAlias != "" {
		originalHost = resolved.OpenSSHAlias
	}
	return originalHost, originalHost
}

func (o *ExecOptions) resolveExecHostTarget(ctx context.Context, repository config.ConfigProvider, target config.ConnectionTarget) (config.ConnectionTarget, config.ResolvedTarget, bool, string, string, error) {
	return o.resolveExecHostTargetWithHint(ctx, repository, target, false)
}

func (o *ExecOptions) resolveExecHostTargetWithHint(ctx context.Context, repository config.ConfigProvider, target config.ConnectionTarget, knownSavedNode bool) (config.ConnectionTarget, config.ResolvedTarget, bool, string, string, error) {
	var (
		matchedSavedNode  = knownSavedNode
		canonicalized     bool
		canonOriginalHost string
		resolved          config.ResolvedTarget
		hasResolved       bool
	)
	if r, rErr := config.ResolveTarget(repository, target); rErr == nil {
		resolved = r
		hasResolved = true
		matchedSavedNode = matchedSavedNode || isResolvedSavedNode(r)
	}
	if target.Selector != "" && !strings.HasPrefix(target.Selector, config.OpenSSHNodePrefix) {
		canonRes, cErr := config.CanonicalizeHost(ctx, config.CanonicalizeInput{
			Provider:         repository,
			Host:             target.Selector,
			RawCLIOptions:    o.control.Options,
			CLIProxyJump:     o.effectiveCLIJumpHost(),
			MatchedSavedNode: matchedSavedNode,
			Resolver:         o.canonicalResolver,
		})
		if cErr != nil {
			return target, resolved, hasResolved, "", "", cErr
		}
		if canonRes.Canonicalized {
			canonicalized = true
			canonOriginalHost = canonRes.OriginalHost
			target.Selector = canonRes.CanonicalHost
			target.OriginalHost = canonRes.OriginalHost
			if r, rErr := config.ResolveTarget(repository, target); rErr == nil {
				resolved = r
				hasResolved = true
			}
		}
	}
	originalHost, expandHost := resolveTargetOriginalAndExpandHosts(canonicalized, canonOriginalHost, target.Selector, resolved, hasResolved)
	return target, resolved, hasResolved, originalHost, expandHost, nil
}

func (o *ExecOptions) resolveExecEntryCredentials(h utils.HostInfo, isBatchHosts bool) (user string, hasUser bool, port uint16, hasPort bool, password string) {
	hasUser = o.User != "" || h.User != ""
	hasPort = o.Port != 0 || h.Port != 0
	if isBatchHosts {
		user = h.User
		if user == "" {
			user = o.User
		}
		port = h.Port
		if port == 0 {
			port = o.Port
		}
	} else {
		user = o.User
		if user == "" {
			user = h.User
		}
		port = o.Port
		if port == 0 {
			port = h.Port
		}
	}
	if !isBatchHosts && o.User != "" && h.User != "" && strings.TrimSpace(o.User) != strings.TrimSpace(h.User) {
		password = o.Password
	} else {
		password = h.Password
		if password == "" {
			password = o.Password
		}
	}
	return user, hasUser, port, hasPort, password
}

func (o *ExecOptions) buildTasksFromHosts(ctx context.Context, repository config.ConfigProvider) ([]execHostTask, []error, error) {
	tasks, hostErrs, err := o.planTasksFromHosts(ctx, repository)
	if err != nil || len(o.Exclude) > 0 {
		return tasks, hostErrs, err
	}
	materialized, matErrs, matErr := o.materializeExecTasks(ctx, repository, tasks)
	if matErr != nil {
		return nil, append(hostErrs, matErrs...), matErr
	}
	return materialized, append(hostErrs, matErrs...), nil
}

func (o *ExecOptions) planTasksFromHosts(ctx context.Context, repository config.ConfigProvider) ([]execHostTask, []error, error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return nil, nil, err
	}
	var tasks []execHostTask
	var hostErrs []error
	hosts, err := utils.ParseHosts(o.Host, o.HostFile, "")
	if err != nil {
		return nil, nil, err
	}
	isBatchHosts := o.HostFile != "" || len(hosts) > 1 || strings.Contains(o.Host, ",")
	for _, h := range hosts {
		user, hasUser, port, hasPort, password := o.resolveExecEntryCredentials(h, isBatchHosts)
		passphrase := h.Passphrase
		if passphrase == "" {
			passphrase = o.Passphrase
		}
		keyPath := h.KeyPath
		if keyPath == "" {
			keyPath = o.IdentityFile
		}
		alias := h.Alias
		if alias == "" {
			alias = o.Alias
		}

		rawHost := strings.TrimSpace(h.Host)
		target := config.ConnectionTarget{
			Selector:     rawHost,
			User:         strings.TrimSpace(user),
			HasUser:      hasUser,
			Port:         port,
			HasPort:      hasPort,
			ProxyJump:    o.JumpHost,
			HasProxyJump: o.JumpHost != "",
		}
		var resolved config.ResolvedTarget
		var hasResolved bool
		var originalHost, expandHost string
		var cErr error
		target, resolved, hasResolved, originalHost, expandHost, cErr = o.resolveExecHostTarget(ctx, repository, target)
		if cErr != nil {
			hostErrs = append(hostErrs, fmt.Errorf("[%s] %w", h.Host, cErr))
			continue
		}
		h.Host = target.Selector

		targetCopy := target
		addrCopy := utils.HostInfo{
			Host:       h.Host,
			Port:       port,
			User:       user,
			Password:   password,
			Alias:      alias,
			KeyPath:    keyPath,
			Passphrase: passphrase,
		}
		taskUser := user
		if taskUser == "" && hasResolved {
			taskUser = resolved.User
		}
		taskPort := port
		if taskPort == 0 && hasResolved {
			taskPort = resolved.Port
		}
		if taskPort == 0 {
			taskPort = 22
		}
		nodeID := ""
		if hasResolved {
			if resolved.MatchedNodeID != "" {
				nodeID = resolved.MatchedNodeID
			} else {
				nodeID = resolved.NodeID
			}
		} else if taskUser != "" {
			nodeID = config.FormatNodeID(taskUser, h.Host, taskPort)
		}
		tasks = append(tasks, execHostTask{
			nodeID:        nodeID,
			matchedNodeID: resolved.MatchedNodeID,
			baseNodeID:    resolved.BaseNodeID,
			openSSHAlias:  resolved.OpenSSHAlias,
			canonicalHost: resolved.CanonicalHost,
			resolvedHost:  resolved.Host,
			rawHost:       rawHost,
			host:          h.Host,
			originalHost:  originalHost,
			expandHost:    expandHost,
			port:          taskPort,
			user:          taskUser,
			pass:          password,
			passphrase:    passphrase,
			keyPath:       normalizeCLIIdentityPath(keyPath),
			pendingTarget: &targetCopy,
			pendingAddr:   &addrCopy,
		})
	}
	return tasks, hostErrs, nil
}

func (o *ExecOptions) materializeExecTasks(ctx context.Context, provider config.ConfigProvider, tasks []execHostTask) ([]execHostTask, []error, error) {
	materialized := make([]execHostTask, 0, len(tasks))
	var hostErrs []error
	for _, t := range tasks {
		if t.pendingTarget != nil && t.pendingAddr != nil {
			nodeID, _, err := o.getOrCreateNode(ctx, provider, *t.pendingTarget, *t.pendingAddr)
			if err != nil {
				if t.isTaggedTask {
					return nil, nil, fmt.Errorf("prepare tagged node %q failed: %w", t.rawHost, err)
				}
				hostErrs = append(hostErrs, fmt.Errorf("[%s] %w", t.host, err))
				continue
			}
			t.nodeID = nodeID
			t.pendingTarget = nil
			t.pendingAddr = nil
		}
		materialized = append(materialized, t)
	}
	return materialized, hostErrs, nil
}

func appendExecAlias(slice []string, val string) ([]string, bool) {
	if val == "" {
		return slice, false
	}
	for _, item := range slice {
		if item == val {
			return slice, false
		}
	}
	return append(slice, val), true
}

func (o *ExecOptions) updateNodeFromHostInfo(ctx context.Context, nodeID string, provider config.ConfigProvider, addr utils.HostInfo) (bool, error) {
	var resolvedJump string
	if o.JumpHost != "" && provider != nil {
		var err error
		resolvedJump, err = provider.ResolveProxyJumpChain(o.JumpHost)
		if err != nil {
			return false, fmt.Errorf("resolve exec proxy jump %q failed: %w", o.JumpHost, err)
		}
	}
	repository, ok := provider.(*config.Repository)
	if !o.Interactive || !ok || strings.HasPrefix(nodeID, config.OpenSSHNodePrefix) ||
		utils.EffectiveRememberPolicy(o.Remember, repository.Snapshot()) == utils.RememberPolicyNever {
		return false, nil
	}
	view := repository.View()
	ref, ok := view.NodeRefs[nodeID]
	if !ok {
		return false, fmt.Errorf("resolve exec node %q reference: %w", nodeID, config.ErrNodeNotFound)
	}
	node, host, identity, err := repository.Resolve(nodeID)
	if err != nil {
		return false, fmt.Errorf("resolve exec node %q for update failed: %w", nodeID, err)
	}
	updated := false
	shouldRemember := utils.EffectiveRememberPolicy(o.Remember, repository.Snapshot()) == utils.RememberPolicyAlways
	if shouldRemember {
		updated = o.updateIdentity(&identity, addr) || updated
		updated = o.updateNodeSudo(&node) || updated
	}
	updated = o.updateNodeAlias(nodeID, &node, addr.Alias, repository) || updated

	if resolvedJump != "" && resolvedJump != node.ProxyJump {
		node.ProxyJump = resolvedJump
		updated = true
	}

	if updated {
		if err := repository.ReplaceNodeAtRefContext(ctx, ref, nodeID, node, host, identity); err != nil {
			return false, fmt.Errorf("update exec node %q failed: %w", nodeID, err)
		}
	}

	return updated, nil
}

// updateIdentity updates identity credentials and returns true if changed
func (o *ExecOptions) updateIdentity(identity *models.Identity, addr utils.HostInfo) bool {
	updated := false

	if addr.Password != "" {
		// Secret persistence is handled by adapter + credential.Service after
		// store write/readback/CAS. Do not copy it into the configuration.
		if identity.AuthType != "password" {
			identity.AuthType = "password"
			updated = true
		}
	} else if absKeyPath := config.NormalizePersistableIdentityPath(addr.KeyPath); absKeyPath != "" {
		if identity.KeyPath != absKeyPath || identity.AuthType != "key" {
			identity.KeyPath = absKeyPath
			identity.AuthType = "key"
			updated = true
		}
	}

	return updated
}

// updateNodeAlias updates node alias and returns true if changed
func (o *ExecOptions) updateNodeAlias(nodeID string, node *models.Node, alias string, provider config.ConfigProvider) bool {
	if alias == "" || config.ValidateNodeAlias(alias) != nil {
		return false
	}
	// 检查别名是否已被其他节点使用
	if existingNode := provider.FindAlias(alias); existingNode != "" && existingNode != nodeID {
		return false
	}
	aliases, changed := appendExecAlias(node.Alias, alias)
	if changed {
		node.Alias = aliases
	}
	return changed
}

// updateNodeSudo updates sudo settings and returns true if changed
func (o *ExecOptions) updateNodeSudo(node *models.Node) bool {
	updated := false

	sudoMode := models.SudoModeNone
	if o.Sudo {
		sudoMode = models.SudoModeSudo
	}

	if sudoMode != models.SudoModeNone && node.SudoMode != sudoMode {
		node.SudoMode = sudoMode
		updated = true
	}

	return updated
}

// putConfiguredNodeContext is retained for SCP's shared node preparation
// path. It accepts only Repository and chooses a create-only or exact-ref
// replacement transaction; there is deliberately no Provider fallback.
func putConfiguredNodeContext(ctx context.Context, provider config.ConfigProvider, nodeID string, node models.Node, host models.Host, identity models.Identity) error {
	repository, ok := provider.(*config.Repository)
	if !ok {
		return fmt.Errorf("configuration mutation requires repository")
	}
	if ref, exists := repository.View().NodeRefs[nodeID]; exists {
		return repository.ReplaceNodeAtRefContext(ctx, ref, nodeID, node, host, identity)
	}
	_, err := repository.CreateNodeContext(ctx, nodeID, node, host, identity)
	return err
}

type connectorCloser interface {
	CloseAll() error
}

func joinConnectorCloseError(retErr *error, closer connectorCloser) {
	if closeErr := closer.CloseAll(); closeErr != nil {
		*retErr = errors.Join(*retErr, fmt.Errorf("close SSH connector failed: %w", closeErr))
	}
}
