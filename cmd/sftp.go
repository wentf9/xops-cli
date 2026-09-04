package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/sftpshell"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

// sftp shell 连接监控参数：复用 pkg/ssh 层默认值（定义见 keepalive.go）
const (
	sftpKeepAliveInterval = ssh.DefaultKeepAliveInterval
	sftpKeepAliveTimeout  = ssh.DefaultKeepAliveTimeout
)

var errSFTPConnectionLost = errors.New("ssh connection lost")

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
			return o.RunContext(cmd.Context())
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
	return o.RunContext(context.Background())
}

// RunContext starts the interactive SFTP session and propagates caller cancellation.
//
//nolint:gocyclo
func (o *SftpOptions) RunContext(ctx context.Context) (err error) {
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

	var nodeID string
	nodeID, _, err = o.resolveNode(ctx, provider)
	if err != nil {
		return err
	}
	connector := newCLIConnector(provider, ssh.WithLogger(logger.DefaultLogger()))
	defer func() {
		joinConnectorCloseError(&err, connector)
	}()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("err_connect_failed"), err)
	}
	sftpClient, err := sftp.NewClient(
		ctx,
		client,
		sftp.WithConcurrentFiles(o.maxTask),
		sftp.WithThreadsPerFile(o.maxThread),
		sftp.WithForce(o.force),
	)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("err_connect_failed"), err)
	}
	// 连接监控：
	// 1. KeepAlive 心跳探测网络黑洞型断连（探测失败或超时会关闭底层 SSH 连接）
	// 2. Wait watcher 感知任何原因的连接关闭（服务端断开 / 心跳主动 Close），
	//    连接断开后取消 runCtx、唤醒交互 Prompt 并自动退出
	runCtx, runCancel := context.WithCancel(ctx)
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
			err = errors.Join(err, fmt.Errorf("close SFTP client failed: %w", closeErr))
		}
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close SSH client after SFTP shell failed: %w", closeErr))
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
			runCancel()
		}
	}()

	// 启动 Shell
	shell, err := sftpshell.New(ctx, sftpClient, client, os.Stdin, os.Stdout, os.Stderr, sftpshell.WithLogger(logger.DefaultLogger()), sftpshell.WithNoOverwrite(o.noOverwrite))
	if err != nil {
		markShellDone()
		return fmt.Errorf("%s: %w", i18n.T("sftp_shell_create_failed"), err)
	}
	defer func() {
		closeCtx, cancelClose := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancelClose()
		if closeErr := shell.Close(closeCtx); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if err := shell.Run(runCtx); err != nil {
		markShellDone()
		if errors.Is(err, context.Canceled) {
			select {
			case connectionErr := <-disconnectErr:
				return fmt.Errorf("%s: %w", i18n.T("sftp_shell_start_failed"), connectionErr)
			default:
				if ctxErr := ctx.Err(); ctxErr != nil {
					return fmt.Errorf("%s: %w", i18n.T("sftp_shell_start_failed"), ctxErr)
				}
			}
		}
		return fmt.Errorf("%s: %w", i18n.T("sftp_shell_start_failed"), err)
	}
	markShellDone()
	return nil
}
