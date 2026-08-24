package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

// sftp shell 连接监控参数：复用 pkg/ssh 层默认值（定义见 keepalive.go）
const (
	sftpKeepAliveInterval = ssh.DefaultKeepAliveInterval
	sftpKeepAliveTimeout  = ssh.DefaultKeepAliveTimeout
)

var errSFTPConnectionLost = errors.New("SSH connection lost")

func sftpConnectionLostError(waitErr error) error {
	if waitErr == nil {
		return errSFTPConnectionLost
	}
	return fmt.Errorf("%w: %w", errSFTPConnectionLost, waitErr)
}

type SftpOptions struct {
	SshOptions
	maxTask     int
	maxThread   int
	force       bool
	noOverwrite bool
}

func NewSftpOptions() *SftpOptions {
	return &SftpOptions{
		SshOptions: *NewSshOptions(),
	}
}

func NewCmdSftp() *cobra.Command {
	o := NewSftpOptions()
	cmd := &cobra.Command{
		Use:   "sftp [user@]host[:port]",
		Short: i18n.T("sftp_short"),
		Long:  i18n.T("sftp_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Complete(cmd, args)
			if err := o.Validate(); err != nil {
				return fmt.Errorf("%s: %w", i18n.T("err_invalid_args"), err)
			}
			return o.Run()
		},
	}
	cmd.Flags().IntVar(&o.maxTask, "task", 0, i18n.T("flag_sftp_task"))
	cmd.Flags().IntVar(&o.maxThread, "thread", 0, i18n.T("flag_sftp_thread"))
	cmd.Flags().BoolVarP(&o.force, "force", "f", false, i18n.T("flag_force"))
	cmd.Flags().BoolVarP(&o.noOverwrite, "no-clobber", "n", false, i18n.T("flag_no_overwrite"))

	// OpenSSH-compatible flags
	cmd.Flags().StringVarP(&o.IdentityFile, "identity", "i", "", i18n.T("flag_identity"))
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "J", "", i18n.T("flag_jump"))

	// xops-enhanced flags (long-form only, no short flags to avoid OpenSSH conflicts)
	cmd.Flags().StringVar(&o.Password, "password", "", i18n.T("flag_password"))
	cmd.Flags().StringVar(&o.Passphrase, "passphrase", "", i18n.T("flag_passphrase"))
	cmd.Flags().StringVar(&o.Alias, "alias", "", i18n.T("flag_alias"))
	cmd.Flags().StringSliceVar(&o.Tags, "tag", []string{}, i18n.T("flag_tag"))

	cmd.MarkFlagsMutuallyExclusive("password", "identity")
	cmd.MarkFlagsMutuallyExclusive("force", "no-clobber")
	return cmd
}

func (o *SftpOptions) Run() error {
	configStore := config.NewDefaultStore(utils.GetConfigFilePath())
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("config_load_error"), err)
	}

	provider := config.NewProvider(cfg)

	var nodeID string
	updated := false
	if nodeID = provider.Find(o.Host); nodeID != "" {
		updated = update(nodeID, &o.SshOptions, provider)
	} else if nodeID = provider.Find(fmt.Sprintf("%s@%s:%d", o.User, o.Host, o.Port)); nodeID != "" {
		updated = update(nodeID, &o.SshOptions, provider)
	} else {
		updated = true
		nodeID, err = o.createNewNode(provider)
		if err != nil {
			return err
		}
	}
	connector := adapter.NewConnector(provider)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	idBefore, _ := provider.GetIdentity(nodeID)
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("err_connect_failed"), err)
	}
	defer connector.CloseAll()
	if idAfter, _ := provider.GetIdentity(nodeID); idBefore.Password != idAfter.Password || idBefore.Passphrase != idAfter.Passphrase {
		updated = true
	}
	sftpClient, err := sftp.NewClient(
		client,
		sftp.WithConcurrentFiles(o.maxTask),
		sftp.WithThreadsPerFile(o.maxThread),
		sftp.WithForce(o.force),
		sftp.WithNoOverwrite(o.noOverwrite),
	)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("err_connect_failed"), err)
	}
	// 连接监控：
	// 1. KeepAlive 心跳探测网络黑洞型断连（探测失败或超时会关闭底层 SSH 连接）
	// 2. Wait watcher 感知任何原因的连接关闭（服务端断开 / 心跳主动 Close），
	//    连接断开后取消 runCtx、唤醒交互 Prompt 并自动退出
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	keepAliveDone := ssh.StartKeepAlive(runCtx, client.SSHClient(), sftpKeepAliveInterval, sftpKeepAliveTimeout, nil)
	shellDone := make(chan struct{})
	watcherDone := make(chan struct{})
	disconnectErr := make(chan error, 1)
	var shellDoneOnce sync.Once
	markShellDone := func() {
		shellDoneOnce.Do(func() { close(shellDone) })
	}
	defer func() {
		markShellDone()
		runCancel()
		if closeErr := sftpClient.Close(); closeErr != nil {
			logger.Warnf("close SFTP client failed: %v", closeErr)
		}
		if closeErr := client.Close(); closeErr != nil {
			logger.Warnf("close SSH client after SFTP shell failed: %v", closeErr)
		}
		<-keepAliveDone
		<-watcherDone
	}()

	go func() {
		defer close(watcherDone)
		waitErr := client.SSHClient().Wait()
		select {
		case <-shellDone:
			// shell 已正常退出（用户输入 exit/bye），连接关闭属于预期清理，无需提示
		default:
			// shell 仍在运行，说明是异常断连
			connectionErr := sftpConnectionLostError(waitErr)
			disconnectErr <- connectionErr
			if _, printErr := fmt.Fprintf(os.Stderr, "%s\n", i18n.Tf("sftp_conn_lost", map[string]any{"Error": connectionErr})); printErr != nil {
				logger.Warnf("print SFTP disconnect notice failed: %v", printErr)
			}
			runCancel()
		}
	}()

	// 启动 Shell
	// 使用 os.Stdin, os.Stdout 绑定到当前终端
	shell, err := sftpClient.NewShell(os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		markShellDone()
		return fmt.Errorf("%s: %w", i18n.T("sftp_shell_create_failed"), err)
	}
	if err := shell.Run(runCtx); err != nil {
		markShellDone()
		if errors.Is(err, context.Canceled) {
			// runCtx 仅由连接 watcher 取消；错误已在取消前写入带缓冲通道。
			return fmt.Errorf("%s: %w", i18n.T("sftp_shell_start_failed"), <-disconnectErr)
		}
		return fmt.Errorf("%s: %w", i18n.T("sftp_shell_start_failed"), err)
	}
	markShellDone()
	if updated {
		if err := configStore.Save(cfg); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("save_config_failed"), err)
		}
	}
	return nil
}

func (o *SftpOptions) createNewNode(provider config.ConfigProvider) (string, error) {
	nodeID := fmt.Sprintf("%s@%s:%d", o.User, o.Host, o.Port)
	node := models.Node{
		HostRef:     fmt.Sprintf("%s:%d", o.Host, o.Port),
		IdentityRef: fmt.Sprintf("%s@%s", o.User, o.Host),
		ProxyJump:   o.JumpHost,
		SudoMode:    models.SudoModeAuto,
		Tags:        o.Tags,
	}
	if node.ProxyJump != "" {
		jumpHost := provider.Find(node.ProxyJump)
		if jumpHost == "" {
			return "", fmt.Errorf("%s", i18n.Tf("err_proxy_not_found", map[string]any{"Proxy": node.ProxyJump}))
		}
		node.ProxyJump = jumpHost
	}
	hostObj := models.Host{
		Address: strings.TrimSpace(o.Host),
		Port:    o.Port,
	}
	if o.Alias != "" {
		// 检查别名是否已存在
		if existingNode := provider.FindAlias(o.Alias); existingNode != "" {
			return "", fmt.Errorf("%s", i18n.Tf("alias_err_exists", map[string]any{"Alias": o.Alias, "Node": existingNode}))
		}
		node.Alias = append(node.Alias, strings.TrimSpace(o.Alias))
	}
	identity := models.Identity{
		User: strings.TrimSpace(o.User),
	}
	if o.Password == "" && o.IdentityFile == "" {
		identity.AuthType = "auto"
	} else if o.Password != "" {
		identity.Password = o.Password
		identity.AuthType = "password"
	} else if o.IdentityFile != "" {
		identity.KeyPath = utils.ToAbsolutePath(o.IdentityFile)
		identity.Passphrase = o.Passphrase
		identity.AuthType = "key"
	}
	provider.AddHost(node.HostRef, hostObj)
	provider.AddIdentity(node.IdentityRef, identity)
	provider.AddNode(nodeID, node)
	return nodeID, nil
}
