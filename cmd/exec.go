package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	pkgutils "github.com/wentf9/xops-cli/pkg/utils"
)

type ExecOptions struct {
	SshOptions
	HostFile     string
	ShellFile    string
	Command      string
	Tag          string
	Exclude      []string
	TaskCount    int
	SuPwd        string
	Interactive  bool
	NoLoginShell bool
	Stream       bool
	OutDir       string

	stdinScript bool

	tempNodesMu    sync.Mutex
	tempNodes      map[string]config.NodeRef
	savedTempNodes int
	nodeUpdated    bool
	stdout         io.Writer
	stderr         io.Writer
}

func NewExecOptions() *ExecOptions {
	return &ExecOptions{
		SshOptions:   *NewSshOptions(),
		TaskCount:    1,
		NoLoginShell: false,
	}
}

func NewCmdExec() *cobra.Command {
	o := NewExecOptions()
	cmd := &cobra.Command{
		Use:   "exec [flags] [command]",
		Short: i18n.T("exec_short"),
		Long:  i18n.T("exec_long"),
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
	cmd.Flags().StringVarP(&o.IdentityFile, "identity", "i", "", i18n.T("flag_identity"))
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "J", "", i18n.T("flag_jump"))

	// xops-enhanced flags (long-form only, no short flags to avoid OpenSSH conflicts)
	cmd.Flags().StringVar(&o.Host, "host", "", i18n.T("flag_hosts"))
	cmd.Flags().StringVar(&o.Password, "password", "", i18n.T("flag_password"))
	cmd.Flags().StringVar(&o.Passphrase, "passphrase", "", i18n.T("flag_passphrase"))
	cmd.Flags().StringVar(&o.Alias, "alias", "", i18n.T("flag_alias"))
	cmd.Flags().BoolVar(&o.Sudo, "sudo", false, i18n.T("flag_exec_sudo"))
	cmd.Flags().StringVar(&o.SuPwd, "suPwd", "", i18n.T("flag_exec_su_pwd"))

	// exec-specific flags
	cmd.Flags().StringVarP(&o.Command, "cmd", "c", "", i18n.T("flag_exec_cmd"))
	cmd.Flags().StringVarP(&o.HostFile, "ifile", "I", "", i18n.T("flag_exec_ifile"))
	cmd.Flags().StringVar(&o.Tag, "tag", "", i18n.T("flag_exec_tag"))
	cmd.Flags().StringSliceVar(&o.Exclude, "exclude", nil, i18n.T("flag_exclude"))
	cmd.Flags().StringVar(&o.ShellFile, "shell", "", i18n.T("flag_exec_shell"))
	cmd.Flags().IntVar(&o.TaskCount, "task", 3, i18n.T("flag_exec_task"))
	cmd.Flags().BoolVarP(&o.Interactive, "interactive", "x", false, i18n.T("flag_exec_interactive"))
	cmd.Flags().BoolVar(&o.NoLoginShell, "no-login", false, i18n.T("flag_exec_no_login"))
	cmd.Flags().BoolVar(&o.Stream, "stream", false, i18n.T("flag_exec_stream"))
	cmd.Flags().StringVar(&o.OutDir, "out-dir", "", i18n.T("flag_exec_out_dir"))

	cmd.MarkFlagsMutuallyExclusive("password", "identity")
	cmd.MarkFlagsMutuallyExclusive("host", "ifile", "tag")
	cmd.MarkFlagsMutuallyExclusive("cmd", "shell")
	cmd.MarkFlagsMutuallyExclusive("stream", "out-dir")

	return cmd
}

func (o *ExecOptions) extractCommandFromArgs(args []string) error {
	hostPart := args[0]
	cmdIdx := 1
	if o.Tag != "" {
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

func (o *ExecOptions) extractHostFromArgs(args []string) error {
	if o.Host == "" && o.Tag == "" && len(args) > 0 {
		hostPart := args[0]
		if len(args) > 1 && strings.HasPrefix(args[1], "@") {
			hostPart = args[0] + args[1]
		}
		u, h, p, err := utils.ParseAddr(hostPart)
		if err != nil {
			return fmt.Errorf("invalid host address %q: %w", hostPart, err)
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
	}
	return nil
}

func (o *ExecOptions) Complete(cmd *cobra.Command, args []string) error {
	o.args = args
	if len(args) == 0 {
		o.readStdinIfRequired()
		return nil
	}
	var err error
	if o.Command == "" && o.ShellFile == "" {
		err = o.extractCommandFromArgs(args)
	} else {
		err = o.extractHostFromArgs(args)
	}
	if err != nil {
		return err
	}
	o.readStdinIfRequired()
	return nil
}

func (o *ExecOptions) readStdinIfRequired() {
	if o.Command == "" && o.ShellFile == "" {
		stat, err := os.Stdin.Stat()
		if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
			content, err := io.ReadAll(os.Stdin)
			if err == nil && len(content) > 0 {
				o.Command = string(content)
				o.stdinScript = true
			}
		}
	}
}

func (o *ExecOptions) Validate() error {
	if o.Command == "" && o.ShellFile == "" {
		return fmt.Errorf("%s", i18n.T("exec_err_no_cmd"))
	}
	if o.Host == "" && o.HostFile == "" && o.Tag == "" {
		return fmt.Errorf("%s", i18n.T("err_no_host"))
	}
	if o.Interactive {
		if o.ShellFile != "" {
			return fmt.Errorf("%s", i18n.T("exec_err_interactive_shell"))
		}
		if o.HostFile != "" || o.Tag != "" || strings.Contains(o.Host, ",") {
			return fmt.Errorf("%s", i18n.T("exec_err_interactive_multi_host"))
		}
	}
	return nil
}

type execHostTask struct {
	nodeID string
	host   string
	port   uint16
	user   string
	pass   string
}

func (o *ExecOptions) Run() error {
	return o.RunContext(context.Background())
}

// RunContext executes the command on all selected hosts and propagates caller cancellation.
//
//nolint:gocyclo
func (o *ExecOptions) RunContext(ctx context.Context) (retErr error) {
	configPath, keyPath, pathErr := utils.GetConfigFilePath()
	if pathErr != nil {
		return fmt.Errorf("get config file path failed: %w", pathErr)
	}
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("config_load_error"), err)
	}
	provider, err := config.NewRepository(cfg, configStore)
	if err != nil {
		return fmt.Errorf("create configuration repository: %w", err)
	}
	defer func() {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancelCleanup()
		if cleanupErr := o.cleanUnusedTempNodesContext(cleanupCtx, provider); cleanupErr != nil {
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()
	connector := newCLIConnector(provider, ssh.WithLogger(logger.DefaultLogger()))
	defer func() {
		joinConnectorCloseError(&retErr, connector)
	}()

	// 准备执行内容
	var execCmd string
	var isScript bool
	if o.ShellFile != "" {
		content, err := os.ReadFile(o.ShellFile)
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

	var (
		tasks    []execHostTask
		hostErrs []error
		errTask  error
	)

	if o.Tag != "" {
		tasks, errTask = o.buildTasksFromTags(provider)
	} else {
		tasks, hostErrs, errTask = o.buildTasksFromHosts(ctx, provider)
	}

	if errTask != nil {
		return errTask
	}

	// 应用 --exclude 排除规则
	if len(o.Exclude) > 0 {
		excludes, err := utils.ResolveExcludes(provider, utils.ParseExcludeFlag(o.Exclude))
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("exec_err_exclude"), err)
		}
		filtered := tasks[:0]
		for _, t := range tasks {
			if _, excluded := excludes[t.nodeID]; !excluded {
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

	// 交互模式：单主机 PTY 执行
	if o.Interactive {
		return o.runInteractive(ctx, connector, tasks[0], execCmd)
	}

	// 落盘模式：在 Worker Pool 启动前一次性创建目录
	if o.OutDir != "" {
		if err := os.MkdirAll(o.OutDir, 0750); err != nil {
			return fmt.Errorf("failed to create output directory %s: %w", o.OutDir, err)
		}
	}

	// 流式模式下多个 goroutine 共享 os.Stdout，需要用 lockedWriter 保证写入原子性
	var stdoutMu sync.Mutex
	var errMu sync.Mutex
	var taskErrs []error

	// 批量模式：原有逻辑
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
	client, err := connector.Connect(ctx, task.nodeID)
	if err == nil {
		o.verifyTempNode(task.nodeID)
	}
	if err != nil {
		return fmt.Errorf("[%s] %s: %w", task.host, i18n.T("fw_connect_failed"), err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("[%s] close ssh client failed: %w", task.host, closeErr))
		}
	}()

	var execErr error
	if o.Sudo {
		execErr = client.RunInteractiveWithSudo(ctx, cmd)
	} else {
		execErr = client.RunInteractive(ctx, cmd)
	}

	return execErr
}

func (o *ExecOptions) getOrCreateNode(ctx context.Context, repository *config.Repository, addr utils.HostInfo) (string, bool, error) {
	host := strings.TrimSpace(addr.Host)
	user := strings.TrimSpace(addr.User)
	port := addr.Port

	if user == "" {
		var userErr error
		user, userErr = utils.GetCurrentUser()
		if userErr != nil {
			return "", false, fmt.Errorf("get current user failed: %w", userErr)
		}
	}
	if port == 0 {
		port = 22
	}

	nodeID, err := repository.ResolveSelector(fmt.Sprintf("%s@%s:%d", user, host, port))
	if err != nil {
		return "", false, fmt.Errorf("resolve execution address %q failed: %w", host, err)
	}
	if nodeID == "" {
		nodeID, err = repository.ResolveSelector(host)
		if err != nil {
			return "", false, fmt.Errorf("resolve execution host %q failed: %w", host, err)
		}
	}

	if nodeID != "" {
		updated, updateErr := o.updateNodeFromHostInfo(ctx, nodeID, repository, addr)
		if updateErr != nil {
			return "", false, updateErr
		}
		if updated {
			o.nodeUpdated = true
		}
		return nodeID, updated, nil
	}

	addr.Host = host
	addr.User = user
	addr.Port = port
	nodeID, mutation, err := o.execCreateNewNode(ctx, repository, addr)
	if shouldTrackTemporaryNode(mutation, err) {
		o.addTempNode(mutation.Ref)
	}
	return nodeID, true, err
}

// shouldTrackTemporaryNode admits only a successfully durable creation to the
// cleanup set. An applied-but-undurable mutation is already authoritative in
// the repository and must never be rolled back automatically.
func shouldTrackTemporaryNode(mutation config.NodeMutation, createErr error) bool {
	return createErr == nil && mutation.Outcome.Applied && mutation.Outcome.Durable && mutation.Ref.ID != ""
}

func (o *ExecOptions) executeTask(ctx context.Context, connector *ssh.Connector, t execHostTask, execCmd string, isScript bool, totalTasks int, stdoutMu *sync.Mutex) (retErr error) {
	client, err := connector.Connect(ctx, t.nodeID)
	if err == nil {
		o.verifyTempNode(t.nodeID)
	}
	if err != nil {
		return fmt.Errorf("[%s] connect failed: %w", t.host, err)
	}

	var output string
	var execErr error

	var runOpts []ssh.RunOption
	runOpts = append(runOpts, ssh.WithLoginShell(!o.NoLoginShell))

	if o.OutDir != "" {
		// 清洗主机名，防止路径穿越
		safeHost := sanitizeHostForFilename(t.host)
		logFile := filepath.Join(o.OutDir, safeHost+".log")
		f, openErr := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if openErr != nil {
			return fmt.Errorf("[%s] open log file %s failed: %w", t.host, logFile, openErr)
		}
		defer func() {
			joinExecLogCloseError(&retErr, f, t.host, logFile)
		}()
		runOpts = append(runOpts, ssh.WithOutFile(f))
	} else if o.Stream || totalTasks == 1 {
		prefix := ""
		if totalTasks > 1 {
			if logger.ColorEnabled() {
				prefix = logger.Cyan(fmt.Sprintf("[%s] ", t.host))
			} else {
				prefix = fmt.Sprintf("[%s] ", t.host)
			}
		}
		// 使用 lockedWriter 包装 os.Stdout，防止多 goroutine 写入交错
		runOpts = append(runOpts, ssh.WithStream(ssh.NewLockedWriter(stdoutMu, o.stdoutWriter()), prefix))
	} else {
		runOpts = append(runOpts, ssh.WithRingBuffer(5*1024*1024))
	}

	if isScript {
		if o.Sudo {
			output, execErr = client.RunScriptWithSudo(ctx, execCmd, runOpts...)
		} else {
			output, execErr = client.RunScript(ctx, execCmd, runOpts...)
		}
	} else {
		if o.Sudo {
			output, execErr = client.RunWithSudo(ctx, execCmd, runOpts...)
		} else {
			output, execErr = client.Run(ctx, execCmd, runOpts...)
		}
	}

	printErr := o.printTaskResult(t, output, execErr, stdoutMu)
	if execErr != nil {
		return errors.Join(fmt.Errorf("[%s] %w", t.host, execErr), printErr)
	}
	return printErr
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

func writeExecResult(mu *sync.Mutex, writer io.Writer, format string, args ...any) error {
	mu.Lock()
	defer mu.Unlock()
	if _, err := fmt.Fprintf(writer, format, args...); err != nil {
		return fmt.Errorf("write command result failed: %w", err)
	}
	return nil
}

func (o *ExecOptions) printTaskResult(t execHostTask, output string, execErr error, stdoutMu *sync.Mutex) error {
	if execErr != nil {
		// 仅在有部分输出时将标准输出打印出来（错误本身交给根命令统一汇报）
		if output != "" {
			if logger.ColorEnabled() {
				header := logger.Cyan(fmt.Sprintf("%s\n------------", t.host))
				return writeExecResult(stdoutMu, o.stderrWriter(), "%s\n%s\n", header, output)
			} else {
				return writeExecResult(stdoutMu, o.stderrWriter(), "[%s]\n%s\n", t.host, output)
			}
		}
		return nil
	}
	if output != "" {
		if logger.ColorEnabled() {
			header := logger.Cyan(fmt.Sprintf("%s\n------------", t.host))
			return writeExecResult(stdoutMu, o.stdoutWriter(), "%s\n%s\n", header, output)
		}
		return writeExecResult(stdoutMu, o.stdoutWriter(), "%s\n", i18n.Tf("exec_result_success", map[string]any{"Host": t.host, "Output": output}))
	}
	if o.OutDir != "" {
		safeHost := sanitizeHostForFilename(t.host)
		message := fmt.Sprintf("[%s] Executed successfully (output saved to %s)", t.host, filepath.Join(o.OutDir, safeHost+".log"))
		if logger.ColorEnabled() {
			hostPart := logger.Cyan(fmt.Sprintf("[%s] ", t.host))
			successPart := logger.Green(fmt.Sprintf("Executed successfully (output saved to %s)", filepath.Join(o.OutDir, safeHost+".log")))
			message = hostPart + successPart
		}
		return writeExecResult(stdoutMu, o.stdoutWriter(), "%s\n", message)
	}
	message := fmt.Sprintf("[%s] Executed successfully", t.host)
	if logger.ColorEnabled() {
		hostPart := logger.Cyan(fmt.Sprintf("[%s] ", t.host))
		successPart := logger.Green("Executed successfully")
		message = hostPart + successPart
	}
	return writeExecResult(stdoutMu, o.stdoutWriter(), "%s\n", message)
}

// sanitizeHostForFilename 清洗主机名，防止路径穿越攻击。
// 移除目录分隔符和 ".." 等危险字符，仅保留文件名安全字符。
func sanitizeHostForFilename(host string) string {
	// 取 base 防止含路径分隔符
	host = filepath.Base(host)
	// 替换不安全字符
	host = strings.ReplaceAll(host, "..", "_")
	if host == "." || host == "" {
		host = "unknown_host"
	}
	return host
}

func (o *ExecOptions) buildTasksFromTags(provider config.ConfigProvider) ([]execHostTask, error) {
	var tasks []execHostTask
	nodes := provider.GetNodesByTag(o.Tag)
	if len(nodes) == 0 {
		return nil, fmt.Errorf("%s", i18n.Tf("err_tag_empty", map[string]any{"Tag": o.Tag}))
	}
	for nodeID := range nodes {
		_, hostObj, identity, resolveErr := provider.Resolve(nodeID)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve tagged node %q failed: %w", nodeID, resolveErr)
		}
		tasks = append(tasks, execHostTask{
			nodeID: nodeID,
			host:   hostObj.Address,
			port:   hostObj.Port,
			user:   identity.User,
			pass:   identity.Password,
		})
	}
	return tasks, nil
}

func (o *ExecOptions) buildTasksFromHosts(ctx context.Context, repository *config.Repository) ([]execHostTask, []error, error) {
	var tasks []execHostTask
	var hostErrs []error
	hosts, err := utils.ParseHosts(o.Host, o.HostFile, "")
	if err != nil {
		return nil, nil, err
	}
	for _, h := range hosts {
		if h.User == "" {
			h.User = o.User
		}
		if h.Password == "" {
			h.Password = o.Password
		}
		if h.Port == 0 {
			h.Port = o.Port
		}
		if h.Alias == "" {
			h.Alias = o.Alias
		}
		addr := utils.HostInfo{
			Host:       h.Host,
			Port:       h.Port,
			User:       h.User,
			Password:   h.Password,
			Alias:      h.Alias,
			KeyPath:    h.KeyPath,
			Passphrase: h.Passphrase,
		}
		nodeID, _, err := o.getOrCreateNode(ctx, repository, addr)
		if err != nil {
			hostErrs = append(hostErrs, fmt.Errorf("[%s] %w", h.Host, err))
			continue
		}
		tasks = append(tasks, execHostTask{
			nodeID: nodeID,
			host:   h.Host,
			port:   h.Port,
			user:   h.User,
			pass:   h.Password,
		})
	}
	return tasks, hostErrs, nil
}

func (o *ExecOptions) execCreateNewNode(ctx context.Context, repository *config.Repository, addr utils.HostInfo) (string, config.NodeMutation, error) {
	host := addr.Host
	user := addr.User
	port := addr.Port

	nodeID := fmt.Sprintf("%s@%s:%d", user, host, port)
	sudoMode := models.SudoModeNone
	if o.Sudo {
		sudoMode = models.SudoModeSudo
	}

	node := models.Node{
		HostRef:     fmt.Sprintf("%s:%d", host, port),
		IdentityRef: fmt.Sprintf("%s@%s", user, host),
		ProxyJump:   o.JumpHost,
		SudoMode:    sudoMode,
		SuPwd:       o.SuPwd,
	}

	if err := o.setNodeAlias(repository, &node, addr.Alias); err != nil {
		return "", config.NodeMutation{}, err
	}

	if node.ProxyJump != "" {
		jumpHost, err := repository.ResolveSelector(node.ProxyJump)
		if err != nil {
			return "", config.NodeMutation{}, fmt.Errorf("resolve execution proxy jump %q failed: %w", node.ProxyJump, err)
		}
		if jumpHost == "" {
			return "", config.NodeMutation{}, fmt.Errorf("%s", i18n.Tf("err_proxy_not_found", map[string]any{"Proxy": node.ProxyJump}))
		}
		node.ProxyJump = jumpHost
	}

	identity := o.buildIdentity(addr)

	mutation, err := repository.CreateNodeContext(ctx, nodeID, node, models.Host{Address: host, Port: port}, identity)
	if err != nil {
		return "", mutation, fmt.Errorf("create exec node %q failed: %w", nodeID, err)
	}

	return nodeID, mutation, nil
}

// setNodeAlias sets the node alias with duplicate check
func (o *ExecOptions) setNodeAlias(provider config.ConfigProvider, node *models.Node, alias string) error {
	aliasToSet := alias
	if aliasToSet == "" {
		aliasToSet = o.Alias
	}
	if aliasToSet == "" {
		return nil
	}
	if existingNode := provider.FindAlias(aliasToSet); existingNode != "" {
		return fmt.Errorf("%s", i18n.Tf("alias_err_exists", map[string]any{"Alias": aliasToSet, "Node": existingNode}))
	}
	node.Alias = []string{aliasToSet}
	return nil
}

// buildIdentity creates an identity from the given parameters
func (o *ExecOptions) buildIdentity(addr utils.HostInfo) models.Identity {
	identity := models.Identity{User: addr.User}

	password := addr.Password
	if password == "" && o.Password != "" {
		password = o.Password
	}

	keyPath := addr.KeyPath
	if keyPath == "" {
		keyPath = o.IdentityFile
	}
	keyPass := addr.Passphrase
	if keyPass == "" {
		keyPass = o.Passphrase
	}

	if password == "" && keyPath == "" {
		identity.AuthType = "auto"
	} else if password != "" {
		identity.Password = password
		identity.AuthType = "password"
	} else if keyPath != "" {
		identity.KeyPath = utils.ToAbsolutePath(keyPath)
		identity.Passphrase = keyPass
		identity.AuthType = "key"
	}

	return identity
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

func (o *ExecOptions) updateNodeFromHostInfo(ctx context.Context, nodeID string, repository *config.Repository, addr utils.HostInfo) (bool, error) {
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

	updated = o.updateIdentity(&identity, addr) || updated
	updated = o.updateNodeAlias(nodeID, &node, addr.Alias, repository) || updated
	updated = o.updateNodeSudo(&node) || updated

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
		if identity.Password != addr.Password || identity.AuthType != "password" {
			identity.Password = addr.Password
			identity.AuthType = "password"
			updated = true
		}
	} else if addr.KeyPath != "" {
		absKeyPath := utils.ToAbsolutePath(addr.KeyPath)
		if identity.KeyPath != absKeyPath || identity.Passphrase != addr.Passphrase || identity.AuthType != "key" {
			identity.KeyPath = absKeyPath
			identity.Passphrase = addr.Passphrase
			identity.AuthType = "key"
			updated = true
		}
	}

	return updated
}

// updateNodeAlias updates node alias and returns true if changed
func (o *ExecOptions) updateNodeAlias(nodeID string, node *models.Node, alias string, provider config.ConfigProvider) bool {
	if alias == "" {
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

	if o.SuPwd != "" && node.SuPwd != o.SuPwd {
		node.SuPwd = o.SuPwd
		updated = true
	}

	return updated
}

func (o *ExecOptions) addTempNode(ref config.NodeRef) {
	if ref.ID == "" {
		return
	}
	o.tempNodesMu.Lock()
	defer o.tempNodesMu.Unlock()
	if o.tempNodes == nil {
		o.tempNodes = make(map[string]config.NodeRef)
	}
	o.tempNodes[ref.ID] = ref
}

func (o *ExecOptions) verifyTempNode(nodeID string) {
	o.tempNodesMu.Lock()
	defer o.tempNodesMu.Unlock()
	if _, ok := o.tempNodes[nodeID]; ok {
		delete(o.tempNodes, nodeID)
		o.savedTempNodes++
	}
}

type tempNodeDeleter interface {
	DeleteNodeAtRefContext(context.Context, config.NodeRef) (config.MutationOutcome, error)
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

// cleanUnusedTempNodes removes nodes that were created for this execution but
// never reached a successful connection. It deliberately keeps repository I/O
// outside tempNodesMu so a slow persistent store cannot block task bookkeeping.
func (o *ExecOptions) cleanUnusedTempNodes(provider tempNodeDeleter) error {
	return o.cleanUnusedTempNodesContext(context.Background(), provider)
}

func (o *ExecOptions) cleanUnusedTempNodesContext(ctx context.Context, provider tempNodeDeleter) error {
	o.tempNodesMu.Lock()
	pending := o.tempNodes
	o.tempNodes = nil
	o.tempNodesMu.Unlock()

	failed := make(map[string]config.NodeRef)
	var cleanupErr error
	for nodeID, ref := range pending {
		_, err := provider.DeleteNodeAtRefContext(ctx, ref)
		if err != nil {
			failed[nodeID] = ref
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("delete unused temporary node %q failed: %w", nodeID, err))
		}
	}
	if len(failed) == 0 {
		return cleanupErr
	}

	// Keep only failed deletions. Nodes added while cleanup was in progress are
	// already in o.tempNodes and must remain pending as well.
	o.tempNodesMu.Lock()
	if o.tempNodes == nil {
		o.tempNodes = make(map[string]config.NodeRef, len(failed))
	}
	for nodeID, ref := range failed {
		o.tempNodes[nodeID] = ref
	}
	o.tempNodesMu.Unlock()

	return cleanupErr
}

func (o *ExecOptions) hasChanges() bool {
	o.tempNodesMu.Lock()
	defer o.tempNodesMu.Unlock()
	return o.nodeUpdated || o.savedTempNodes > 0
}
