package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wentf9/xops-cli/cmd/sftpshell"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"golang.org/x/term"
)

// sftp shell 连接监控参数：复用 core/ssh 层默认值（定义见 keepalive.go）
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
	return newCmdSftpWithOptions(NewSftpOptions())
}

func newCmdSftpWithOptions(o *SftpOptions) *cobra.Command {
	if o == nil {
		o = NewSftpOptions()
	}
	cmd := &cobra.Command{
		Use:   "sftp [user@]host[:port]",
		Short: i18n.T("sftp_short"),
		Long:  i18n.T("sftp_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Complete(cmd, args); err != nil {
				return err
			}
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

	// OpenSSH-compatible flags (aligned with sftp(1): -P port, -c cipher)
	cmd.Flags().Uint16VarP(&o.Port, "port", "P", 0, i18n.T("flag_port"))
	cmd.Flags().StringVarP(&o.CipherSpec, "cipher", "c", "", i18n.T("flag_ssh_cipher"))
	cmd.Flags().StringArrayVarP(&o.IdentityFiles, "identity", "i", nil, i18n.T("flag_identity"))
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "J", "", i18n.T("flag_jump"))
	o.control.RegisterCommonFlags(cmd)
	o.control.RegisterAddressFamilyFlags(cmd)

	// xops-enhanced flags (long-form only, no short flags to avoid OpenSSH conflicts)
	cmd.Flags().StringVar(&o.Host, "host", "", i18n.T("flag_host"))
	cmd.Flags().BoolVar(&o.PasswordStdin, "password-stdin", false, i18n.T("flag_password_stdin"))
	cmd.Flags().BoolVar(&o.PassphraseStdin, "passphrase-stdin", false, i18n.T("flag_passphrase_stdin"))
	cmd.Flags().StringVar(&o.OTP, "otp", "", i18n.T("flag_otp"))
	cmd.Flags().BoolVar(&o.OTPStdin, "otp-stdin", false, i18n.T("flag_otp_stdin"))
	cmd.Flags().StringVar(&o.Remember, "remember", "", i18n.T("flag_remember"))
	cmd.Flags().StringVar(&o.Alias, "alias", "", i18n.T("flag_alias"))
	cmd.Flags().StringSliceVar(&o.Tags, "tag", []string{}, i18n.T("flag_tag"))
	cmd.Flags().BoolVar(&o.Sudo, "sudo", false, i18n.T("flag_sudo"))
	o.diagnostic.registerVerbose(cmd, "flag_sftp_verbose")

	cmd.MarkFlagsMutuallyExclusive("force", "no-clobber")
	cmd.MarkFlagsMutuallyExclusive("otp", "otp-stdin")
	return cmd
}

func (o *SftpOptions) Complete(cmd *cobra.Command, args []string) error {
	o.args = args
	o.dashIdx = -1
	o.parsedArgs = false
	o.hostFromPositional = false
	o.appliedGeneralOpts = false
	o.stdinScript = false

	var flags *pflag.FlagSet
	if cmd != nil {
		flags = cmd.Flags()
		o.dashIdx = cmd.ArgsLenAtDash()
	}
	o.control.ctlCmdSet = flags != nil && flags.Changed("control-command")
	if err := ApplyGeneralOptions(&o.SshOptions, o.control.Options, flags); err != nil {
		return o.control.controlUsageError(err)
	}
	if err := validateExplicitZeroPort(flags); err != nil {
		return o.control.controlUsageError(err)
	}
	if _, err := o.toSessionControlOptions(); err != nil {
		return o.control.controlUsageError(err)
	}

	if o.PasswordStdin || o.PassphraseStdin || o.OTPStdin {
		if err := o.Validate(); err != nil {
			return o.control.controlUsageError(err)
		}
	} else if o.OTP != "" {
		if err := o.validateSftpInvariants(); err != nil {
			return o.control.controlUsageError(err)
		}
	}

	bgRun, bgErr := o.effectiveBgRunChecked()
	if bgErr != nil {
		return o.control.controlUsageError(bgErr)
	}
	if bgRun {
		if err := o.ensureArgsParsed(); err != nil {
			return err
		}
		o.stdinScript = false
		return nil
	}

	o.execution.capturePresence(cmd)
	if err := o.completeStdinAndScriptInput(os.Getenv(sshBackgroundChildEnv) == "true", ""); err != nil {
		return err
	}
	o.stdinScript = false
	return nil
}

func (o *SftpOptions) extraPositionalArgs() []string {
	if len(o.args) == 0 {
		return nil
	}
	if !o.hostFromPositional && o.Host != "" {
		return o.args
	}
	return o.args[1:]
}

func (o *SftpOptions) validateSftpInvariants() error {
	if o.force && o.noOverwrite {
		return errors.New("flags --force (-f) and --no-clobber (-n) are mutually exclusive")
	}
	bgRun, err := o.effectiveBgRunChecked()
	if err != nil {
		return err
	}
	if bgRun {
		return errors.New("ForkAfterAuthentication (background mode) is not supported for sftp")
	}
	if extraArgs := o.extraPositionalArgs(); len(extraArgs) > 0 {
		return fmt.Errorf("unexpected positional argument %q", extraArgs[0])
	}
	return nil
}

func (o *SftpOptions) Validate() error {
	o.stdinScript = false
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return err
	}
	if err := o.validateSftpInvariants(); err != nil {
		return err
	}
	return o.SshOptions.Validate()
}

func (o *SftpOptions) Run() error {
	return o.RunContext(context.Background())
}

// RunContext starts the interactive SFTP session and propagates caller cancellation.
//
//nolint:gocyclo
func (o *SftpOptions) RunContext(ctx context.Context) (err error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return err
	}
	if err := o.validateSftpInvariants(); err != nil {
		return err
	}
	batch := !term.IsTerminal(int(os.Stdin.Fd()))
	connectionOptions := o.SshOptions
	if batch {
		ctx = credential.WithoutInteraction(ctx)
		connectionOptions.Remember = "never"
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
	provider, err := config.WithOpenSSHConfigOverride(repo, connectionOptions.control.ConfigFile)
	if err != nil {
		return err
	}

	var nodeID string
	nodeID, _, err = connectionOptions.resolveNode(ctx, provider)
	if err != nil {
		return err
	}
	adpOpts, optErr := connectionOptions.buildAdapterOptions(nodeID, cfg, provider)
	if optErr != nil {
		return optErr
	}
	adpOpts = append(adpOpts, adapter.WithLocalExecution(!batch), adapter.WithSessionAndForwardOptions(false), adapter.WithEnrollmentProbeExclusions(nodeID))
	var connector *ssh.Connector
	// The diagnostic sink must outlive the connector, SFTP client and shell, which
	// are the event producers. Deferring it first makes it the last cleanup to run.
	observer, finishDiagnostics, diagnosticErr := connectionOptions.startDiagnostics(ctx)
	if diagnosticErr != nil {
		return diagnosticErr
	}
	defer func() {
		err = errors.Join(err, finishDiagnostics())
	}()
	if batch {
		adpOpts = append(adpOpts, adapter.WithNonInteractive(true))
		connector = newNonInteractiveConnector(provider, adpOpts, ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(observer))
	} else {
		connector = newCLIConnectorWithAdapterOptions(provider, connectionOptions.interaction, adpOpts, ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(observer))
	}
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
		sftp.WithDiagnostics(observer),
		sftp.WithSudo(o.Sudo),
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
		if handoffErr := connectionOptions.handoffPersistentMaster(ctx, connector, provider, nodeID); handoffErr != nil {
			logger.DefaultLogger().Debugf("mux: master handoff failed: %v", handoffErr)
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
	shell, err := sftpshell.New(ctx, sftpClient, client, os.Stdin, os.Stdout, os.Stderr, sftpshell.WithLogger(logger.DefaultLogger()), sftpshell.WithNoOverwrite(o.noOverwrite), sftpshell.WithSudo(o.Sudo))
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
				return fmt.Errorf("%s: %w", i18n.T("sftp_shell_start_failed"), errors.Join(err, connectionErr))
			default:
				if ctxErr := ctx.Err(); ctxErr != nil {
					return fmt.Errorf("%s: %w", i18n.T("sftp_shell_start_failed"), errors.Join(err, ctxErr))
				}
			}
		}
		return fmt.Errorf("%s: %w", i18n.T("sftp_shell_start_failed"), err)
	}
	markShellDone()
	return nil
}
