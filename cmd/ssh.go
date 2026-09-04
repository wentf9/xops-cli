package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type SshOptions struct {
	Host           string
	Port           uint16
	User           string
	Password       string
	IdentityFile   string
	Passphrase     string
	Sudo           bool
	Alias          string
	JumpHost       string
	Tags           []string
	LocalForwards  []string
	RemoteForwards []string
	NoCmd          bool
	DynamicForward string
	BgRun          bool
	StdinRedirect  bool
	args           []string

	Target config.ConnectionTarget

	Command     string
	stdinScript bool
}

func NewSshOptions() *SshOptions {
	return &SshOptions{
		Sudo: false,
	}
}

func NewCmdSsh() *cobra.Command {
	o := NewSshOptions()
	cmd := &cobra.Command{
		Use:   "ssh [user@]host[:port]",
		Short: i18n.T("ssh_short"),
		Long:  i18n.T("ssh_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Complete(cmd, args)
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
	cmd.Flags().StringSliceVarP(&o.LocalForwards, "local-forward", "L", []string{}, i18n.T("flag_local_forward"))
	cmd.Flags().StringSliceVarP(&o.RemoteForwards, "remote-forward", "R", []string{}, i18n.T("flag_remote_forward"))
	cmd.Flags().BoolVarP(&o.NoCmd, "no-cmd", "N", false, i18n.T("flag_no_cmd"))
	cmd.Flags().StringVarP(&o.DynamicForward, "dynamic-forward", "D", "", i18n.T("flag_dynamic_forward"))
	cmd.Flags().BoolVarP(&o.BgRun, "background", "f", false, i18n.T("flag_background"))
	cmd.Flags().BoolVarP(&o.StdinRedirect, "stdin-redirect", "n", false, i18n.T("flag_stdin_redirect"))

	// xops-enhanced flags (long-form only, no short flags to avoid OpenSSH conflicts)
	cmd.Flags().StringVar(&o.Host, "host", "", i18n.T("flag_host"))
	cmd.Flags().StringVar(&o.Password, "password", "", i18n.T("flag_password"))
	cmd.Flags().StringVar(&o.Passphrase, "passphrase", "", i18n.T("flag_passphrase"))
	cmd.Flags().BoolVar(&o.Sudo, "sudo", false, i18n.T("flag_sudo"))
	cmd.Flags().StringVar(&o.Alias, "alias", "", i18n.T("flag_alias"))
	cmd.Flags().StringSliceVar(&o.Tags, "tag", []string{}, i18n.T("flag_tag"))

	cmd.MarkFlagsMutuallyExclusive("password", "identity")
	return cmd
}

func (o *SshOptions) Complete(cmd *cobra.Command, args []string) {
	o.args = args
	if !o.StdinRedirect {
		stat, err := os.Stdin.Stat()
		if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
			o.stdinScript = true
		}
	}
}

func (o *SshOptions) parseArgs() error {
	hasUser := false
	var finalUser string
	hasPort := false
	var finalPort uint16
	finalHost := o.Host

	if o.User != "" {
		hasUser = true
		finalUser = o.User
	}
	if o.Port != 0 {
		hasPort = true
		finalPort = o.Port
	}

	if len(o.args) == 0 && finalHost == "" {
		return errors.New(i18n.T("ssh_err_no_host"))
	} else if len(o.args) >= 1 {
		u, h, p, err := utils.ParseAddr(o.args[0])
		if err != nil {
			return err
		}
		if finalHost == "" && h != "" {
			finalHost = h
		}
		if !hasUser && u != "" {
			hasUser = true
			finalUser = u
		}
		if !hasPort && p != 0 {
			hasPort = true
			finalPort = p
		}
	}

	o.Host = finalHost
	o.User = finalUser
	o.Port = finalPort

	o.Target = config.ConnectionTarget{
		Selector:     finalHost,
		User:         finalUser,
		HasUser:      hasUser,
		Port:         finalPort,
		HasPort:      hasPort,
		ProxyJump:    o.JumpHost,
		HasProxyJump: o.JumpHost != "",
	}
	return nil
}

func (o *SshOptions) Validate() error {
	if err := o.parseArgs(); err != nil {
		return err
	}
	if len(o.args) > 1 {
		o.Command = strings.Join(o.args[1:], " ")
	}
	if o.BgRun && !o.NoCmd {
		return errors.New(i18n.T("ssh_err_background_requires_nocmd"))
	}
	if strings.Contains(o.Alias, "@") || strings.Contains(o.Alias, ":") {
		return errors.New(i18n.T("ssh_err_alias_invalid"))
	}
	return nil
}

func (o *SshOptions) Run() error {
	return o.RunContext(context.Background())
}

// RunContext starts the SSH operation and propagates caller cancellation.
func (o *SshOptions) RunContext(ctx context.Context) (err error) {
	isChild := os.Getenv("XOPS_CLI_SSH_BG_CHILD") == "true"

	// -n 功能：如果是非后台运行或已是后台子进程，且指定了 -n，直接重定向标准输入到 /dev/null
	if o.StdinRedirect && (!o.BgRun || isChild) {
		devNull, err := os.Open(os.DevNull)
		if err != nil {
			return fmt.Errorf("open %s for SSH stdin failed: %w", os.DevNull, err)
		}
		oldStdin := os.Stdin
		os.Stdin = devNull
		defer func() {
			os.Stdin = oldStdin
			if closeErr := devNull.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close SSH stdin redirect failed: %w", closeErr))
			}
		}()
	}

	if o.BgRun && !isChild {
		return o.runParentDaemon(ctx)
	}

	return o.runConnection(ctx, isChild)
}

func (o *SshOptions) runParentDaemon(ctx context.Context) (err error) {
	configPath, keyPath, pathErr := utils.GetConfigFilePath()
	if pathErr != nil {
		return fmt.Errorf("get config file path failed: %w", pathErr)
	}
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ssh_err_load_config"), err)
	}

	provider, err := config.NewRepository(cfg, configStore)
	if err != nil {
		return fmt.Errorf("create configuration repository: %w", err)
	}

	nodeID, _, err := o.resolveNode(ctx, provider)
	if err != nil {
		return err
	}
	connector := newCLIConnector(provider, ssh.WithLogger(logger.DefaultLogger()))
	defer func() {
		joinConnectorCloseError(&err, connector)
	}()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		promptErr := promptPressEnterIfTUI(os.Stdin, os.Stdout)
		return errors.Join(fmt.Errorf("%s: %w", i18n.T("fw_connect_failed"), err), promptErr)
	}

	// 无论如何，在 runParentDaemon 退出时，或者有任何 panic 发生时，确保 client 必被关闭
	var clientClosed bool
	defer func() {
		if !clientClosed {
			if closeErr := client.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close SSH daemon validation client failed: %w", closeErr))
			}
		}
	}()

	// 测试端口绑定/隧道是否正常工作
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	tunnels, err := o.startTunnels(runCtx, runCancel, client)
	if err != nil {
		return err
	}
	if closeErr := tunnels.Close(); closeErr != nil {
		return fmt.Errorf("stop SSH daemon validation tunnels failed: %w", closeErr)
	}

	// 验证无误，可以断开，接下来由后台进程重新连接
	if err := client.Close(); err != nil {
		return fmt.Errorf("close SSH daemon validation client failed: %w", err)
	}
	clientClosed = true

	// 启动后台子进程
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "XOPS_CLI_SSH_BG_CHILD=true")

	// 子进程的 stdin/stdout/stderr 均重定向到 /dev/null
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("failed to open /dev/null: %w", err)
	}
	defer func() {
		if closeErr := devNull.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close SSH daemon stdio redirect failed: %w", closeErr))
		}
	}()
	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull

	if err := startDaemonProcess(cmd); err != nil {
		return fmt.Errorf("failed to start background daemon: %w", err)
	}

	return nil
}

func (o *SshOptions) runConnection(ctx context.Context, isChild bool) (err error) {
	configPath, keyPath, pathErr := utils.GetConfigFilePath()
	if pathErr != nil {
		return fmt.Errorf("get config file path failed: %w", pathErr)
	}
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ssh_err_load_config"), err)
	}

	provider, err := config.NewRepository(cfg, configStore)
	if err != nil {
		return fmt.Errorf("create configuration repository: %w", err)
	}

	nodeID, _, err := o.resolveNode(ctx, provider)
	if err != nil {
		return err
	}
	connector := newCLIConnector(provider, ssh.WithLogger(logger.DefaultLogger()))
	defer func() {
		joinConnectorCloseError(&err, connector)
	}()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		if isChild {
			// 子进程静默退出或记录错误，不进行交互式阻塞
			return fmt.Errorf("%s: %w", i18n.T("fw_connect_failed"), err)
		}
		promptErr := promptPressEnterIfTUI(os.Stdin, os.Stdout)
		return errors.Join(fmt.Errorf("%s: %w", i18n.T("fw_connect_failed"), err), promptErr)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close SSH client failed: %w", closeErr))
		}
	}()
	// Setup background context for tunnels and execution (runs until SigInt or command exit)
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	tunnels, err := o.startTunnels(runCtx, runCancel, client)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := tunnels.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("stop SSH tunnels failed: %w", closeErr))
		}
	}()

	if o.NoCmd {
		if !isChild {
			fmt.Printf("SSH tunnels established to %s. Press Ctrl+C to exit.\n", nodeID)
		}
		<-runCtx.Done()
		return nil
	}

	if o.Command != "" || o.stdinScript {
		return o.runCommand(runCtx, client, o.Command)
	}

	return o.runShell(runCtx, client)
}

func (o *SshOptions) runShell(ctx context.Context, client *ssh.Client) error {
	if o.Sudo {
		if err := client.ShellWithSudo(ctx); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("sudo_exec_failed"), err)
		}
	} else {
		if err := client.Shell(ctx); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ssh_err_shell"), err)
		}
	}
	return nil
}

// parseForwardArg parses standard SSH forward argument limits.
// Expected format: [bind_address:]port:host:hostport
// E.g: 8080:localhost:80 -> bind_address="127.0.0.1", port="8080", host="localhost", hostport="80"
func parseForwardArg(arg string) (bindAddr, destAddr string, err error) {
	parts := splitTunnels(arg)
	if len(parts) < 3 || len(parts) > 4 {
		return "", "", fmt.Errorf("invalid forward format '%s', expected [bind_address:]port:host:hostport", arg)
	}
	destPort := parts[len(parts)-1]
	destHost := strings.Trim(parts[len(parts)-2], "[]")
	destAddr = net.JoinHostPort(destHost, destPort)

	if len(parts) == 3 {
		bindAddr = net.JoinHostPort("127.0.0.1", parts[0])
	} else {
		bindHost := strings.Trim(parts[0], "[]")
		bindAddr = net.JoinHostPort(bindHost, parts[1])
	}
	return bindAddr, destAddr, nil
}

func splitTunnels(s string) []string {
	var parts []string
	var current string
	inBracket := false
	for _, r := range s {
		if r == '[' {
			inBracket = true
			current += string(r)
		} else if r == ']' {
			inBracket = false
			current += string(r)
		} else if r == ':' && !inBracket {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(r)
		}
	}
	parts = append(parts, current)
	return parts
}

func (o *SshOptions) resolveNode(ctx context.Context, provider *config.Repository) (string, bool, error) {
	var defaultUser string
	if !o.Target.HasUser {
		var err error
		defaultUser, err = utils.GetCurrentUser()
		if err != nil {
			return "", false, fmt.Errorf("get current user failed: %w", err)
		}
	}

	res, err := provider.EnsureNodeContext(ctx, config.EnsureNodeOptions{
		Target:       o.Target,
		DefaultUser:  defaultUser,
		Password:     o.Password,
		IdentityFile: o.IdentityFile,
		Passphrase:   o.Passphrase,
		Alias:        o.Alias,
		Tags:         o.Tags,
	})
	if err != nil {
		return "", false, err
	}
	if res.Created {
		return res.NodeID, true, nil
	}
	updated, err := update(ctx, res.NodeID, o, provider)
	return res.NodeID, updated, err
}

type sshTunnelGroup struct {
	cancel context.CancelFunc
	done   sync.WaitGroup
	errMu  sync.Mutex
	err    error
}

func newSSHTunnelGroup(ctx context.Context, cancelParent context.CancelFunc) (*sshTunnelGroup, context.Context) {
	tunnelCtx, cancel := context.WithCancel(ctx)
	group := &sshTunnelGroup{cancel: cancel}
	if cancelParent == nil {
		cancelParent = func() {}
	}
	groupCancel := group.cancel
	group.cancel = func() {
		groupCancel()
		cancelParent()
	}
	return group, tunnelCtx
}

func (g *sshTunnelGroup) Add(forward *ssh.Forward) {
	g.done.Go(func() {
		if err := forward.Wait(); err != nil {
			g.errMu.Lock()
			g.err = errors.Join(g.err, err)
			g.errMu.Unlock()
			g.cancel()
		}
	})
}

func (g *sshTunnelGroup) Close() error {
	if g == nil {
		return nil
	}
	g.cancel()
	g.done.Wait()
	g.errMu.Lock()
	defer g.errMu.Unlock()
	return g.err
}

func (o *SshOptions) startTunnels(ctx context.Context, cancelParent context.CancelFunc, client *ssh.Client) (*sshTunnelGroup, error) {
	group, tunnelCtx := newSSHTunnelGroup(ctx, cancelParent)
	fail := func(err error) (*sshTunnelGroup, error) {
		return nil, errors.Join(err, group.Close())
	}
	for _, lArg := range o.LocalForwards {
		bAddr, dAddr, err := parseForwardArg(lArg)
		if err != nil {
			return fail(err)
		}
		forward, err := client.LocalForward(tunnelCtx, bAddr, dAddr, ssh.WithForwardErrorHandler(func(err error) {
			logger.Warnf("ssh local forward connection failed: %v", err)
		}))
		if err != nil {
			return fail(fmt.Errorf("setup local forward failed: %w", err))
		}
		group.Add(forward)
	}
	for _, rArg := range o.RemoteForwards {
		bAddr, dAddr, err := parseForwardArg(rArg)
		if err != nil {
			return fail(err)
		}
		forward, err := client.RemoteForward(tunnelCtx, bAddr, dAddr, ssh.WithForwardErrorHandler(func(err error) {
			logger.Warnf("ssh remote forward connection failed: %v", err)
		}))
		if err != nil {
			return fail(fmt.Errorf("setup remote forward failed: %w", err))
		}
		group.Add(forward)
	}
	if o.DynamicForward != "" {
		listenAddr, err := parseDynamicForwardArg(o.DynamicForward)
		if err != nil {
			return fail(err)
		}
		forward, err := client.Socks5Forward(tunnelCtx, listenAddr, ssh.WithForwardErrorHandler(func(err error) {
			logger.Warnf("ssh SOCKS5 forward connection failed: %v", err)
		}))
		if err != nil {
			return fail(fmt.Errorf("setup SOCKS5 proxy failed: %w", err))
		}
		group.Add(forward)
	}
	return group, nil
}

func parseDynamicForwardArg(arg string) (string, error) {
	// If only a port is specified (e.g. "1080")
	if _, err := strconv.Atoi(arg); err == nil {
		return net.JoinHostPort("127.0.0.1", arg), nil
	}

	host, port, err := net.SplitHostPort(arg)
	if err != nil {
		if strings.HasPrefix(arg, ":") {
			return net.JoinHostPort("127.0.0.1", arg[1:]), nil
		}
		return "", fmt.Errorf("invalid dynamic forward format '%s', expected [bind_address:]port", arg)
	}

	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

func updateNodeFields(node *models.Node, nodeID string, o *SshOptions, provider config.ConfigProvider) (bool, error) {
	nodeUpdated := false
	if o.JumpHost != "" {
		jumpHost, err := provider.ResolveProxyJumpChain(o.JumpHost)
		if err != nil {
			return false, fmt.Errorf("resolve SSH proxy jump %q failed: %w", o.JumpHost, err)
		}
		if jumpHost != "" && jumpHost != node.ProxyJump {
			node.ProxyJump = jumpHost
			nodeUpdated = true
		}
	}

	if o.Alias != "" {
		// 检查别名是否已被其他节点使用
		if existingNode := provider.FindAlias(o.Alias); existingNode != "" && existingNode != nodeID {
			// 别名已存在，跳过
		} else {
			node.Alias = append(node.Alias, o.Alias)
			nodeUpdated = true
		}
	}
	if len(o.Tags) > 0 {
		tagMap := make(map[string]bool)
		for _, t := range node.Tags {
			tagMap[t] = true
		}
		for _, t := range o.Tags {
			if !tagMap[t] {
				node.Tags = append(node.Tags, t)
				nodeUpdated = true
			}
		}
	}
	return nodeUpdated, nil
}

func updateIdentityFields(identity *models.Identity, o *SshOptions) bool {
	identityUpdated := false
	if o.Password != "" {
		identity.Password = o.Password
		identity.AuthType = "password"
		identityUpdated = true
	} else if o.IdentityFile != "" {
		identity.KeyPath = utils.ToAbsolutePath(o.IdentityFile)
		identity.AuthType = "key"
		identityUpdated = true
	}
	if o.Passphrase != "" {
		identity.Passphrase = o.Passphrase
		identityUpdated = true
	}
	return identityUpdated
}

func update(ctx context.Context, nodeID string, o *SshOptions, provider *config.Repository) (bool, error) {
	if o.Password == "" && o.IdentityFile == "" && o.JumpHost == "" && !o.Sudo && o.Alias == "" && len(o.Tags) == 0 {
		return false, nil
	}
	ref, ok := provider.View().NodeRefs[nodeID]
	if !ok {
		return false, fmt.Errorf("resolve SSH node %q reference: %w", nodeID, config.ErrNodeNotFound)
	}
	node, host, identity, err := provider.Resolve(nodeID)
	if err != nil {
		return false, fmt.Errorf("resolve SSH node %q for update failed: %w", nodeID, err)
	}

	nodeUpdated, err := updateNodeFields(&node, nodeID, o, provider)
	if err != nil {
		return false, err
	}
	identityUpdated := updateIdentityFields(&identity, o)

	if nodeUpdated || identityUpdated {
		if err := provider.ReplaceNodeAtRefContext(ctx, ref, nodeID, node, host, identity); err != nil {
			return false, fmt.Errorf("update SSH node %q failed: %w", nodeID, err)
		}
	}
	return nodeUpdated || identityUpdated, nil
}

// TODO(refactor): TUI 渲染边界与环境变量污染
// 这里的阻塞提示逻辑属于 TUI 层面的交互，目前交由子进程处理（依赖 XOPS_CLI_SSH_FROM_TUI 环境变量）并非最佳实践。
// 后续重构建议：移除子进程中的阻塞提示，改为子进程出错即退，由外层的 TUI 框架拦截退出状态码并绘制错误提示信息。
func promptPressEnterIfTUI(stdin io.Reader, stdout io.Writer) error {
	if os.Getenv("XOPS_CLI_SSH_FROM_TUI") == "true" {
		if _, err := fmt.Fprintln(stdout, i18n.T("tui_press_enter")); err != nil {
			return fmt.Errorf("prompt press enter write failed: %w", err)
		}
		var b [1]byte
		if _, err := stdin.Read(b[:]); err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read press enter failed: %w", err)
		}
	}
	return nil
}

func (o *SshOptions) runCommand(ctx context.Context, client *ssh.Client, command string) error {
	return client.RunCommandWithIO(ctx, command, o.Sudo, os.Stdin, os.Stdout, os.Stderr)
}
