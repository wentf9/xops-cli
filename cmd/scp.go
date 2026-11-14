package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	cmdutils "github.com/wentf9/xops-cli/cmd/utils"
	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/sftp"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
	pkgutils "github.com/wentf9/xops-cli/pkg/utils"
)

type ScpOptions struct {
	SshOptions
	Recursive      bool
	Quiet          bool
	Verbose        bool
	Force          bool
	NoOverwrite    bool
	TaskCount      int
	ThreadCount    int
	Source         string
	Dest           string
	HostFile       string
	Tag            string
	Exclude        []string
	sshLogLevel    int
	verboseSeen    bool
	verboseLevel   int
	diagnostics    corelog.DiagnosticObserver
	canonicalMu    sync.Mutex
	canonicalCache map[string]config.CanonicalizeResult
}

func NewScpOptions() *ScpOptions {
	sshOpts := *NewSshOptions()
	sshOpts.nonHostArgs = true
	return &ScpOptions{
		SshOptions:  sshOpts,
		sshLogLevel: sshLogInfo,
		TaskCount:   1,
		ThreadCount: sftp.DefaultThreadsPerFile,
	}
}

func NewCmdScp() *cobra.Command {
	o := NewScpOptions()
	cmd := &cobra.Command{
		Use:   "scp [flags] [[user@]host:]source [[user@]host:]dest",
		Short: i18n.T("scp_short"),
		Long:  i18n.T("scp_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
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
	cmd.Flags().Uint16VarP(&o.Port, "port", "P", 0, i18n.T("flag_port"))
	cmd.Flags().StringVarP(&o.User, "login", "l", "", i18n.T("flag_login"))
	cmd.Flags().StringArrayVarP(&o.IdentityFiles, "identity", "i", nil, i18n.T("flag_identity"))
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "J", "", i18n.T("flag_jump"))
	cmd.Flags().BoolVarP(&o.Recursive, "recursive", "r", false, i18n.T("flag_recursive"))
	o.control.RegisterCommonFlags(cmd)
	o.control.RegisterAddressFamilyFlags(cmd)

	// xops-enhanced flags (long-form only, no short flags to avoid OpenSSH conflicts)
	cmd.Flags().StringVar(&o.Host, "host", "", i18n.T("flag_hosts"))
	cmd.Flags().BoolVar(&o.PasswordStdin, "password-stdin", false, i18n.T("flag_password_stdin"))
	cmd.Flags().BoolVar(&o.PassphraseStdin, "passphrase-stdin", false, i18n.T("flag_passphrase_stdin"))
	cmd.Flags().StringVar(&o.OTP, "otp", "", i18n.T("flag_otp"))
	cmd.Flags().BoolVar(&o.OTPStdin, "otp-stdin", false, i18n.T("flag_otp_stdin"))
	cmd.Flags().StringVar(&o.Remember, "remember", "", i18n.T("flag_remember"))
	cmd.Flags().StringVar(&o.Alias, "alias", "", i18n.T("flag_alias"))
	cmd.Flags().BoolVar(&o.Sudo, "sudo", false, i18n.T("flag_sudo"))

	// scp-specific flags
	cmd.Flags().StringVar(&o.Source, "src", "", i18n.T("flag_scp_src"))
	cmd.Flags().StringVar(&o.Dest, "dest", "", i18n.T("flag_scp_dest"))
	cmd.Flags().StringVarP(&o.HostFile, "ifile", "I", "", i18n.T("flag_ifile"))
	cmd.Flags().StringVar(&o.Tag, "tag", "", i18n.T("flag_scp_tag"))
	cmd.Flags().StringSliceVar(&o.Exclude, "exclude", nil, i18n.T("flag_exclude"))
	o.registerOutputFlags(cmd)
	cmd.Flags().BoolVarP(&o.Force, "force", "f", false, i18n.T("flag_force"))
	cmd.Flags().BoolVarP(&o.NoOverwrite, "no-clobber", "n", false, i18n.T("flag_no_overwrite"))
	cmd.Flags().IntVar(&o.TaskCount, "task", 3, i18n.T("flag_task"))
	cmd.Flags().IntVar(&o.ThreadCount, "thread", 4, i18n.T("flag_thread"))

	cmd.MarkFlagsMutuallyExclusive("host", "ifile", "tag")
	cmd.MarkFlagsMutuallyExclusive("force", "no-clobber")
	cmd.MarkFlagsMutuallyExclusive("otp", "otp-stdin")
	cmd.MarkFlagsRequiredTogether("src", "dest")
	return cmd
}

func (o *ScpOptions) Complete(cmd *cobra.Command, args []string) error {
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
	if _, err := o.control.ToSessionControlOptions(); err != nil {
		return err
	}
	pathFlags := o.Source != "" || o.Dest != ""
	if cmd != nil {
		if cmd.Flags().Changed("port") && o.Port == 0 {
			return errors.New(i18n.T("scp_err_port_zero"))
		}
		pathFlags = pathFlags || cmd.Flags().Changed("src") || cmd.Flags().Changed("dest")
		for _, name := range []string{"host", "tag", "ifile"} {
			value, err := cmd.Flags().GetString(name)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed(name) && strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s: --%s", i18n.T("scp_err_empty_selector"), name)
			}
		}
	}
	if len(args) > 0 {
		if pathFlags {
			return errors.New(i18n.T("scp_err_mixed_paths"))
		}
		if len(args) != 2 {
			return errors.New(i18n.T("scp_err_path_count"))
		}
		o.Source, o.Dest = args[0], args[1]
	}
	if err := o.Validate(); err != nil {
		return err
	}
	// Reject invalid path arguments before reading caller-owned credential input.
	return o.completeStdinCredentials()
}

func (o *ScpOptions) completeStdinCredentials() error {
	if o.OTP != "" && o.OTPStdin {
		return errors.New(i18n.T("err_otp_mutually_exclusive"))
	}
	if o.OTPStdin {
		otp, err := cmdutils.ReadSecretLineFromStdin()
		if err != nil {
			return fmt.Errorf("read otp from stdin: %w", err)
		}
		o.OTP = otp
		o.OTPStdin = false
	}
	if o.PasswordStdin {
		pwd, err := cmdutils.ReadSecretFromStdin()
		if err != nil {
			return fmt.Errorf("read password from stdin: %w", err)
		}
		o.Password = pwd
	}
	if o.PassphraseStdin {
		pass, err := cmdutils.ReadSecretFromStdin()
		if err != nil {
			return fmt.Errorf("read passphrase from stdin: %w", err)
		}
		o.Passphrase = pass
	}
	return nil
}

func (o *ScpOptions) Validate() error {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return err
	}
	if err := o.control.Validate(); err != nil {
		return err
	}
	if o.OTP != "" && o.OTPStdin {
		return errors.New(i18n.T("err_otp_mutually_exclusive"))
	}
	if err := cmdutils.ValidateRememberPolicy(o.Remember); err != nil {
		return err
	}
	if o.Source == "" {
		return fmt.Errorf("%s", i18n.T("scp_err_no_src"))
	}
	if o.Dest == "" {
		return fmt.Errorf("%s", i18n.T("scp_err_no_dest"))
	}
	return nil
}

type PathInfo struct {
	IsRemote     bool
	User         string
	Host         string
	OriginalHost string
	Port         uint16
	Path         string
}

//nolint:gocyclo
func parsePath(p string) (PathInfo, error) {
	if p == "" {
		return PathInfo{IsRemote: false, Path: ""}, nil
	}

	// 检查是否是 Windows 盘符
	if len(p) >= 2 && p[1] == ':' && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) {
		if len(p) == 2 || p[2] == '\\' || p[2] == '/' {
			return PathInfo{IsRemote: false, Path: p}, nil
		}
	}

	firstColon := strings.Index(p, ":")
	if firstColon == -1 || strings.ContainsAny(p[:firstColon], "/\\") {
		return PathInfo{Path: p}, nil
	}

	separator := firstColon
	if openBracket := strings.Index(p, "["); openBracket != -1 && openBracket < firstColon {
		closeBracket := strings.Index(p[openBracket:], "]")
		if closeBracket == -1 {
			return PathInfo{}, fmt.Errorf("malformed bracketed address in %q", p)
		}
		separator = openBracket + closeBracket + 1
		if separator >= len(p) || p[separator] != ':' {
			return PathInfo{Path: p}, nil
		}
	}
	// The address/path delimiter is final: numeric prefixes are filenames, not ports.
	addrPart, pathPart := p[:separator], p[separator+1:]

	if addrPart != "" {
		if strings.Contains(addrPart, "/") || strings.Contains(addrPart, "\\") {
			return PathInfo{IsRemote: false, Path: p}, nil
		}

		u, h, port, err := cmdutils.ParseAddr(addrPart)
		if err != nil {
			return PathInfo{}, fmt.Errorf("invalid remote address %q in %q: %w", addrPart, p, err)
		}
		if h == "" {
			return PathInfo{}, fmt.Errorf("invalid remote address %q: host cannot be empty", addrPart)
		}
		return PathInfo{
			IsRemote: true,
			User:     u,
			Host:     h,
			Port:     port,
			Path:     pathPart,
		}, nil
	}
	return PathInfo{IsRemote: false, Path: p}, nil
}

func (o *ScpOptions) Run() error {
	return o.RunContext(context.Background())
}

// RunContext executes the transfer and propagates caller cancellation.

type transferProgressErrors struct {
	mu  sync.Mutex
	err error
}

func (e *transferProgressErrors) Add(operation string, err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	e.err = errors.Join(e.err, fmt.Errorf("%s failed: %w", operation, err))
	e.mu.Unlock()
}

func (e *transferProgressErrors) Err() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

func (o *ScpOptions) RunContext(ctx context.Context) (retErr error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return err
	}
	if o.interaction == nil {
		o.interaction = newCLIInteractionHandler()
	}
	if o.Verbose {
		diagnostics, err := newSCPDiagnostics(ctx, os.Stderr, "stderr", o.sshLogLevel >= sshLogDebug1, o.verboseLevel, o.interaction.promptGate)
		if err != nil {
			return err
		}
		o.diagnostics = diagnostics
		defer func() { o.diagnostics = nil; retErr = errors.Join(retErr, diagnostics.finish()) }()
	}
	configPath, keyPath, pathErr := cmdutils.GetConfigFilePath()
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
	if err := o.canonicalizeEndpoints(ctx, provider); err != nil {
		return err
	}
	connector, err := o.credentialConnector(provider, cfg)
	if err != nil {
		return err
	}

	defer func() {
		if handoffErr := o.handoffConnectorMasters(ctx, provider, connector); handoffErr != nil {
			logger.DefaultLogger().Debugf("mux: master handoff failed: %v", handoffErr)
		}
		joinConnectorCloseError(&retErr, connector)
	}()

	return o.runTransfer(ctx, provider, connector)
}

// runTransfer borrows the caller-owned connector for path routing and transfer.
func (o *ScpOptions) runTransfer(ctx context.Context, provider config.ConfigProvider, connector *ssh.Connector) (retErr error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return err
	}
	if diagnostics, ok := o.diagnostics.(*scpDiagnostics); ok {
		diagnostics.transfer(o.Source, o.Dest, "starting")
		defer func() {
			status := "completed"
			if retErr != nil {
				status = "failed"
			}
			diagnostics.transfer(o.Source, o.Dest, status)
		}()
	}
	// Selectors always mean upload. Paths are literal, including ':', '@' and '['.
	if o.Host != "" || o.Tag != "" || o.HostFile != "" {
		return o.runBatch(ctx, provider, connector)
	}
	src, srcErr := parsePath(o.Source)
	if srcErr != nil {
		return fmt.Errorf("parse source path failed: %w", srcErr)
	}
	var dst PathInfo
	if o.Dest != "" {
		var dstErr error
		dst, dstErr = parsePath(o.Dest)
		if dstErr != nil {
			return fmt.Errorf("parse dest path failed: %w", dstErr)
		}
	}

	// 2. 远程到远程
	if src.IsRemote && dst.IsRemote {
		return o.runRemoteToRemote(ctx, src, dst, provider, connector)
	}

	// 3. 单主机上传/下载
	if src.IsRemote {
		var localPath = o.Dest
		return o.runDownload(ctx, src, localPath, provider, connector)
	} else if dst.IsRemote {
		var localPath = o.Source
		return o.runUpload(ctx, localPath, dst, provider, connector)
	}

	return fmt.Errorf("%s", i18n.T("scp_err_both_local"))
}

func (o *ScpOptions) runUpload(ctx context.Context, localPath string, dst PathInfo, provider config.ConfigProvider, connector *ssh.Connector) (err error) {
	_, sftpCli, err := o.connectSftpForPath(ctx, dst, "", provider, connector)
	if err != nil {
		return fmt.Errorf("connect upload destination failed: %w", err)
	}
	defer joinCloseError(&err, "upload SFTP client", sftpCli.Close)

	remotePath, err := expandSCPRemotePath(ctx, sftpCli, dst.Path)
	if err != nil {
		return err
	}
	var remoteStat os.FileInfo
	err = sftpCli.Do(ctx, func(c *pkgsftp.Client) error {
		var statErr error
		remoteStat, statErr = c.Stat(remotePath)
		return statErr
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat destination failed: %w", err)
	}
	if err == nil && remoteStat.IsDir() {
		remotePath = sftpCli.JoinPath(remotePath, filepath.Base(localPath))
	}

	// 检查是否已存在
	err = sftpCli.Do(ctx, func(c *pkgsftp.Client) error {
		_, statErr := c.Stat(remotePath)
		return statErr
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat destination file failed: %w", err)
	}
	if err == nil {
		if o.NoOverwrite {
			return nil
		}
		if !o.Force {
			confirmed, confirmErr := cmdutils.AskConfirmation(i18n.Tf("prompt_overwrite", map[string]any{"Path": remotePath}))
			if confirmErr != nil {
				return confirmErr
			}
			if !confirmed {
				return nil
			}
			o.Force = true // 用户确认后开启强制覆盖
		}
	}

	var progress sftp.ProgressCallback
	finishProgress := func() error { return nil }
	if o.progressEnabled() {
		info, err := os.Stat(localPath)
		if err != nil {
			return err
		}
		size := info.Size()
		if info.IsDir() {
			size = -1
		}
		progress, finishProgress = o.createTransferProgress(ctx, size, "Uploading "+filepath.Base(localPath), 0)
	}
	uploadErr := sftpCli.WithForce(o.Force).Upload(ctx, localPath, remotePath, progress)
	return errors.Join(uploadErr, finishProgress())
}

func (o *ScpOptions) runDownload(ctx context.Context, src PathInfo, localPath string, provider config.ConfigProvider, connector *ssh.Connector) (err error) {
	_, sftpCli, err := o.connectSftpForPath(ctx, src, "", provider, connector)
	if err != nil {
		return fmt.Errorf("connect download source failed: %w", err)
	}
	defer joinCloseError(&err, "download SFTP client", sftpCli.Close)

	src.Path, err = expandSCPRemotePath(ctx, sftpCli, src.Path)
	if err != nil {
		return err
	}

	// Stat the source under ctx so a cancelled transfer does not block here.
	var stat os.FileInfo
	if err = sftpCli.Do(ctx, func(c *pkgsftp.Client) error {
		var statErr error
		stat, statErr = c.Stat(src.Path)
		return statErr
	}); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("scp_err_stat_remote"), err)
	}

	// 处理本地路径是目录的情况
	localDest := localPath
	if lStat, err := os.Stat(localPath); err == nil && lStat.IsDir() {
		localDest = filepath.Join(localPath, stat.Name())
	}

	// 检查本地文件是否已存在
	if _, err := os.Stat(localDest); err == nil {
		if o.NoOverwrite {
			return nil
		}
		if !o.Force {
			confirmed, confirmErr := cmdutils.AskConfirmation(i18n.Tf("prompt_overwrite", map[string]any{"Path": localDest}))
			if confirmErr != nil {
				return confirmErr
			}
			if !confirmed {
				return nil
			}
			o.Force = true // 用户确认后开启强制覆盖
		}
	}

	size := stat.Size()
	if stat.IsDir() {
		size = -1
	}
	progress, finishProgress := o.createTransferProgress(ctx, size, "Downloading "+filepath.Base(src.Path), 0)
	if stat.IsDir() {
		downloadErr := sftpCli.WithForce(o.Force).DownloadDirectory(ctx, src.Path, localPath, progress)
		return errors.Join(downloadErr, finishProgress())
	}
	downloadErr := sftpCli.WithForce(o.Force).DownloadFile(ctx, src.Path, localDest, stat.Size(), stat.Mode(), progress)
	return errors.Join(downloadErr, finishProgress())
}

//nolint:gocyclo
func (o *ScpOptions) runRemoteToRemote(ctx context.Context, src, dst PathInfo, provider config.ConfigProvider, connector *ssh.Connector) (retErr error) {
	_, srcSftp, err := o.connectSftpForPath(ctx, src, "", provider, connector)
	if err != nil {
		return fmt.Errorf("connect remote source failed: %w", err)
	}
	defer joinCloseError(&retErr, "source SFTP client", srcSftp.Close)

	_, dstSftp, err := o.connectSftpForPath(ctx, dst, "", provider, connector)
	if err != nil {
		return fmt.Errorf("connect remote destination failed: %w", err)
	}
	defer joinCloseError(&retErr, "destination SFTP client", dstSftp.Close)

	src.Path, err = expandSCPRemotePath(ctx, srcSftp, src.Path)
	if err != nil {
		return err
	}
	dst.Path, err = expandSCPRemotePath(ctx, dstSftp, dst.Path)
	if err != nil {
		return err
	}

	// The cancellation watcher closes srcSftp/dstSftp when the caller's ctx
	// is cancelled, unblocking any in-flight SFTP operations on those clients.
	// Correct defer LIFO order: register Wait FIRST so it executes LAST, then
	// register cancelCtx so it executes FIRST and unblocks the goroutine
	// before we wait for it. Reversing this order causes a guaranteed deadlock
	// on normal return.
	var cancelWg sync.WaitGroup
	cancelWg.Add(1)
	stopCtx, cancelCtx := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWg.Wait() // executes second (LIFO): waits after goroutine is signalled
	defer cancelCtx()     // executes first (LIFO): signals goroutine to exit
	go func() {
		defer cancelWg.Done()
		select {
		case <-stopCtx.Done():
			// normal return path: cancelCtx() was called, goroutine exits cleanly
		case <-ctx.Done():
			// cancellation path: close both clients to unblock in-flight ops
			if closeErr := srcSftp.Close(); closeErr != nil {
				logger.DefaultLogger().Debugf("async cancel source SFTP client failed: %v", closeErr)
			}
			if closeErr := dstSftp.Close(); closeErr != nil {
				logger.DefaultLogger().Debugf("async cancel destination SFTP client failed: %v", closeErr)
			}
		}
	}()

	var srcFile *pkgsftp.File
	err = srcSftp.Do(ctx, func(c *pkgsftp.Client) error {
		var err error
		srcFile, err = c.Open(src.Path)
		return err
	})
	if err != nil {
		return fmt.Errorf("open remote source %q failed: %w", src.Path, err)
	}
	defer joinCloseError(&retErr, "remote source file", srcFile.Close)

	srcStat, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat remote source %q failed: %w", src.Path, err)
	}

	dstPath := dst.Path
	var dstStat os.FileInfo
	err = dstSftp.Do(ctx, func(c *pkgsftp.Client) error {
		var err error
		dstStat, err = c.Stat(dstPath)
		return err
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat destination failed: %w", err)
	}
	if err == nil && dstStat.IsDir() {
		dstPath = dstSftp.JoinPath(dstPath, filepath.Base(src.Path))
	}

	// Decide overwrite once. Matching size/mtime cannot prove equal contents,
	// and a skipped destination must not render completed transfer progress.
	skipOverwrite, err := o.confirmRemoteToRemoteOverwrite(ctx, dstSftp, dstPath)
	if err != nil {
		return err
	}
	if skipOverwrite {
		return nil
	}

	// 2. 使用临时文件进行传输
	tempPath := dstPath + dstSftp.Config().TempSuffix
	startOffset, dstFile, err := o.prepareRemoteToRemoteFile(ctx, dstSftp, tempPath, srcStat.Size())
	if err != nil {
		return err
	}

	if startOffset > 0 && dstFile != nil {
		if valErr := o.validateRemoteRelayResumePrefix(ctx, srcFile, dstFile, startOffset); valErr != nil {
			if !errors.Is(valErr, errPrefixMismatch) {
				if closeErr := dstFile.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) && !errors.Is(closeErr, io.EOF) {
					return errors.Join(valErr, fmt.Errorf("close file failed: %w", closeErr))
				}
				return valErr
			}
			startOffset = 0
			if _, seekErr := dstFile.Seek(0, 0); seekErr != nil {
				if closeErr := dstFile.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) && !errors.Is(closeErr, io.EOF) {
					return errors.Join(fmt.Errorf("seek failed after mismatch: %w", seekErr), fmt.Errorf("close file failed: %w", closeErr))
				}
				return fmt.Errorf("seek failed after mismatch: %w", seekErr)
			}
			if truncErr := dstFile.Truncate(0); truncErr != nil {
				if closeErr := dstFile.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) && !errors.Is(closeErr, io.EOF) {
					return errors.Join(fmt.Errorf("truncate failed after mismatch: %w", truncErr), fmt.Errorf("close file failed: %w", closeErr))
				}
				return fmt.Errorf("truncate failed after mismatch: %w", truncErr)
			}
		}
	}

	progress, finishProgress := o.createTransferProgress(ctx, srcStat.Size(), "Relaying "+filepath.Base(srcStat.Name()), startOffset)
	defer func() {
		if pErr := finishProgress(); pErr != nil {
			retErr = errors.Join(retErr, pErr)
		}
	}()

	if err := o.doRemoteToRemote(ctx, srcSftp, srcFile, dstFile, startOffset, srcStat.Size(), dstSftp, progress); err != nil {
		retErr = err
		return retErr
	}

	// 3. 传输完成：同步修改时间并安全替换目标文件
	if err := dstSftp.Do(ctx, func(c *pkgsftp.Client) error {
		return c.Chtimes(tempPath, srcStat.ModTime(), srcStat.ModTime())
	}); err != nil {
		retErr = fmt.Errorf("sync modtime failed: %w", err)
		return retErr
	}
	retErr = dstSftp.ReplaceRemoteFile(ctx, tempPath, dstPath)
	return retErr
}

func (o *ScpOptions) confirmRemoteToRemoteOverwrite(ctx context.Context, dstSftp *sftp.Client, dstPath string) (bool, error) {
	if !o.Force {
		statErr := dstSftp.Do(ctx, func(c *pkgsftp.Client) error {
			_, err := c.Stat(dstPath)
			return err
		})
		switch {
		case statErr == nil:
			// Destination exists.
			if o.NoOverwrite {
				return true, nil
			}
			confirmed, confirmErr := cmdutils.AskConfirmation(i18n.Tf("prompt_overwrite", map[string]any{"Path": dstPath}))
			if confirmErr != nil {
				return false, confirmErr
			}
			if !confirmed {
				return true, nil
			}
			o.Force = true
		case errors.Is(statErr, os.ErrNotExist):
			// Destination does not exist — no overwrite confirmation needed.
		default:
			// Unexpected Stat error: propagate so the caller can decide.
			return false, fmt.Errorf("stat destination %q failed: %w", dstPath, statErr)
		}
	}
	return false, nil
}

// progressEnabled follows SCP terminal behavior; redirected output stays clean.
func (o *ScpOptions) progressEnabled() bool {
	return !o.Quiet && diagnosticTerminal(os.Stdout) && diagnosticTerminal(os.Stderr)
}

// createTransferProgress owns one bar per transfer. The caller must finish it
// after all progress callbacks have joined; the finish function never closes stderr.
func (o *ScpOptions) createTransferProgress(ctx context.Context, size int64, description string, startOffset int64) (sftp.ProgressCallback, func() error) {
	errs := &transferProgressErrors{}
	if !o.progressEnabled() {
		return nil, errs.Err
	}
	output, err := newSCPDiagnostics(ctx, os.Stderr, "stderr", false, 0)
	if err != nil {
		return nil, func() error { return err }
	}
	if output.disabled {
		return nil, output.finish
	}
	bar := progressbar.NewOptions64(size,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(output),
		progressbar.OptionEnableColorCodes(logger.ColorEnabled()),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(100*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			_, err := fmt.Fprintln(output)
			errs.Add("progress completion newline", err)
		}),
		progressbar.OptionSetTheme(progressbar.Theme{Saucer: "=", SaucerHead: ">", SaucerPadding: " ", BarStart: "[", BarEnd: "]"}),
	)
	progress := func(n int64) { errs.Add("update progress", bar.Add64(n)) }
	if startOffset > 0 {
		progress(startOffset)
	}
	return progress, func() error {
		// Interrupted or indeterminate bars do not run OptionOnCompletion.
		if !bar.IsFinished() {
			_, err := fmt.Fprintln(output)
			errs.Add("progress final newline", err)
		}
		return errors.Join(errs.Err(), output.finish())
	}
}

func (o *ScpOptions) doRemoteToRemote(ctx context.Context, srcSftp *sftp.Client, srcFile *pkgsftp.File, dstFile *pkgsftp.File, startOffset, size int64, dstSftp *sftp.Client, progress sftp.ProgressCallback) (err error) {
	if dstFile != nil {
		defer func() {
			if closeErr := dstFile.Close(); closeErr != nil && !errors.Is(closeErr, os.ErrClosed) && !errors.Is(closeErr, io.EOF) {
				err = errors.Join(err, fmt.Errorf("close destination file failed: %w", closeErr))
			}
		}()
	}
	if startOffset < size {
		if startOffset > 0 {
			if _, seekErr := srcFile.Seek(startOffset, io.SeekStart); seekErr != nil {
				return seekErr
			}
			if dstFile != nil {
				if _, seekErr := dstFile.Seek(startOffset, io.SeekStart); seekErr != nil {
					return seekErr
				}
			}
		}
		if dstFile != nil {
			transferErr := dstSftp.StreamTransfer(ctx, srcSftp, srcFile, dstFile, size-startOffset, progress)
			if transferErr != nil {
				return transferErr
			}
		}
	}
	return nil
}

func (o *ScpOptions) runBatch(ctx context.Context, provider config.ConfigProvider, connector *ssh.Connector) error {
	// 解析 --exclude 排除规则（在 Worker Pool 启动前完成，确保无歧义）
	var excludes map[string]struct{}
	if len(o.Exclude) > 0 {
		resolved, err := cmdutils.ResolveExcludes(provider, cmdutils.ParseExcludeFlag(o.Exclude))
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("scp_err_exclude"), err)
		}
		excludes = resolved
	}

	var (
		errMu        sync.Mutex
		transferErrs []error
	)
	wp := pkgutils.NewWorkerPool(uint(o.TaskCount))

	if o.Tag != "" {
		nodes := provider.GetNodesByTag(o.Tag)
		if len(nodes) == 0 {
			return fmt.Errorf("%s", i18n.Tf("err_tag_empty", map[string]any{"Tag": o.Tag}))
		}
		for nodeID := range nodes {
			if excludes != nil {
				if _, excluded := excludes[nodeID]; excluded {
					continue
				}
			}
			nid := nodeID // capture
			_, _, identity, resolveErr := provider.Resolve(nid)
			if resolveErr != nil {
				return fmt.Errorf("resolve tagged scp node %q failed: %w", nid, resolveErr)
			}
			wp.Execute(func() {
				addr := PathInfo{Host: nid, IsRemote: true}
				if tErr := o.executeTransfer(ctx, nid, addr, identity.Password, provider, connector); tErr != nil {
					errMu.Lock()
					transferErrs = append(transferErrs, fmt.Errorf("[%s] %w", nid, tErr))
					errMu.Unlock()
				}
			})
		}
	} else {
		hosts, err := cmdutils.ParseHosts(o.Host, o.HostFile, "")
		if err != nil {
			return err
		}

		// 处理 普通主机列表
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
			addr := PathInfo{Host: h.Host, User: h.User, Port: h.Port, IsRemote: true}
			canonAddr, canonErr := o.canonicalizePathInfo(ctx, provider, addr)
			if canonErr != nil {
				return fmt.Errorf("canonicalize host %q: %w", h.Host, canonErr)
			}
			// 若主机已映射到已知节点且在排除集合中，则跳过
			if excludes != nil {
				excluded, exclErr := o.isBatchHostExcluded(provider, excludes, h.Host, canonAddr)
				if exclErr != nil {
					return exclErr
				}
				if excluded {
					continue
				}
			}

			wp.Execute(func() {
				if tErr := o.executeTransfer(ctx, h.Host, canonAddr, h.Password, provider, connector); tErr != nil {
					errMu.Lock()
					transferErrs = append(transferErrs, fmt.Errorf("[%s] %w", h.Host, tErr))
					errMu.Unlock()
				}
			})
		}
	}

	wp.Wait()
	return errors.Join(transferErrs...)
}

func (o *ScpOptions) isBatchHostExcluded(provider config.ConfigProvider, excludes map[string]struct{}, rawHost string, canonAddr PathInfo) (bool, error) {
	if _, ok := excludes[rawHost]; ok {
		return true, nil
	}
	if _, ok := excludes[canonAddr.Host]; ok {
		return true, nil
	}
	if target, tErr := o.resolveTargetForPath(canonAddr); tErr == nil && target.Selector != "" {
		resolved, rErr := config.ResolveTarget(provider, target)
		if rErr != nil {
			return false, fmt.Errorf("resolve excluded host %q: %w", canonAddr.Host, rErr)
		}
		if resolved.NodeID != "" {
			if _, ok := excludes[resolved.NodeID]; ok {
				return true, nil
			}
		}
		if resolved.MatchedNodeID != "" {
			if _, ok := excludes[resolved.MatchedNodeID]; ok {
				return true, nil
			}
		}
		return false, nil
	}
	nid, resolveErr := provider.ResolveSelector(canonAddr.Host)
	if resolveErr != nil {
		return false, fmt.Errorf("resolve excluded host %q: %w", canonAddr.Host, resolveErr)
	}
	if nid != "" {
		if _, ok := excludes[nid]; ok {
			return true, nil
		}
	}
	return false, nil
}

func (o *ScpOptions) executeTransfer(ctx context.Context, label string, addr PathInfo, specificPassword string, provider config.ConfigProvider, connector *ssh.Connector) (err error) {
	_, sftpCli, err := o.connectSftpForPath(ctx, addr, specificPassword, provider, connector)
	if err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}
	defer joinCloseError(&err, "batch upload SFTP client", sftpCli.Close)

	remotePath, err := expandSCPRemotePath(ctx, sftpCli, o.Dest)
	if err != nil {
		return err
	}
	var remoteStat os.FileInfo
	if statErr := sftpCli.Do(ctx, func(c *pkgsftp.Client) error {
		var err error
		remoteStat, err = c.Stat(remotePath)
		return err
	}); statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("stat remote dest %q failed: %w", remotePath, statErr)
	}
	if remoteStat != nil && remoteStat.IsDir() {
		remotePath = sftpCli.JoinPath(remotePath, filepath.Base(o.Source))
	}

	var destStat os.FileInfo
	if statErr := sftpCli.Do(ctx, func(c *pkgsftp.Client) error {
		var err error
		destStat, err = c.Stat(remotePath)
		return err
	}); statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("stat upload target %q failed: %w", remotePath, statErr)
	}
	if destStat != nil {
		// Destination exists: skip if NoOverwrite, skip if not Force (user did
		// not explicitly request overwrite in batch mode).
		if o.NoOverwrite || !o.Force {
			return o.writeTransferStatus(ctx, os.Stderr, "stderr", logger.Yellow(i18n.Tf("scp_skip", map[string]any{"Label": label})))
		}
	}

	var progress sftp.ProgressCallback
	finishProgress := func() error { return nil }
	if o.progressEnabled() {
		info, statErr := os.Stat(o.Source)
		if statErr != nil {
			return fmt.Errorf("stat local source failed: %w", statErr)
		}
		size := info.Size()
		if info.IsDir() {
			size = -1
		}
		progress, finishProgress = o.createTransferProgress(ctx, size, "Uploading ["+label+"] "+filepath.Base(o.Source), 0)
	}
	err = errors.Join(sftpCli.Upload(ctx, o.Source, remotePath, progress), finishProgress())
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	return o.writeTransferStatus(ctx, os.Stdout, "stdout", logger.Green(i18n.Tf("scp_done", map[string]any{"Label": label})))
}

// writeTransferStatus owns and joins a single-message output queue. The sink is
// borrowed; unsupported sinks are skipped by the same policy as diagnostics.
func (o *ScpOptions) writeTransferStatus(ctx context.Context, target io.Writer, stream, message string) error {
	if o.Quiet {
		return nil
	}
	output, err := newSCPDiagnostics(ctx, target, stream, false, 0)
	if err != nil {
		return err
	}
	output.enqueue(message + "\n")
	return output.finish()
}

func joinCloseError(target *error, resource string, closeFn func() error) {
	if closeErr := closeFn(); closeErr != nil {
		*target = errors.Join(*target, fmt.Errorf("close %s failed: %w", resource, closeErr))
	}
}

func (o *ScpOptions) prepareRemoteToRemoteFile(ctx context.Context, dstSftp *sftp.Client, tempPath string, srcSize int64) (int64, *pkgsftp.File, error) {
	var startOffset int64
	var dstFile *pkgsftp.File
	var err error

	flags := os.O_RDWR | os.O_TRUNC | os.O_CREATE

	var ts os.FileInfo
	err = dstSftp.Do(ctx, func(c *pkgsftp.Client) error {
		var statErr error
		ts, statErr = c.Stat(tempPath)
		return statErr
	})
	if err == nil {
		if dstSftp.Config().EnableResume && ts.Size() <= srcSize {
			startOffset = ts.Size()
			flags = os.O_RDWR
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, nil, fmt.Errorf("stat temp file %q failed: %w", tempPath, err)
	}

	err = dstSftp.Do(ctx, func(c *pkgsftp.Client) error {
		var err error
		dstFile, err = c.OpenFile(tempPath, flags)
		return err
	})
	if err != nil {
		return 0, nil, err
	}

	return startOffset, dstFile, nil
}

func (o *ScpOptions) canonicalizeEndpoints(ctx context.Context, provider config.ConfigProvider) error {
	if provider == nil {
		return nil
	}
	for _, p := range o.collectTargetPaths(provider) {
		if _, err := o.canonicalizePathInfo(ctx, provider, p); err != nil {
			return err
		}
	}
	return nil
}

func (o *ScpOptions) canonicalCacheKey(p PathInfo) string {
	host := p.Host
	if host == "" && o.Host != "" && !strings.Contains(o.Host, ",") {
		host = o.Host
	}
	user := o.User
	if user == "" {
		user = p.User
	}
	port := o.Port
	if port == 0 {
		port = p.Port
	}
	if user == "" && port == 0 {
		return host
	}
	return fmt.Sprintf("%s\x00%s\x00%d", host, user, port)
}

func (o *ScpOptions) canonicalizePathInfo(ctx context.Context, provider config.ConfigProvider, p PathInfo) (PathInfo, error) {
	if p.Host == "" {
		return p, nil
	}
	if strings.HasPrefix(p.Host, config.OpenSSHNodePrefix) {
		if stripped, ok := config.OpenSSHOriginalHost(p.Host); ok && p.OriginalHost == "" {
			p.OriginalHost = stripped
		}
		return p, nil
	}
	cacheKey := o.canonicalCacheKey(p)
	o.canonicalMu.Lock()
	res, ok := o.canonicalCache[cacheKey]
	o.canonicalMu.Unlock()
	if ok {
		if res.Canonicalized {
			if p.OriginalHost == "" {
				p.OriginalHost = res.OriginalHost
			}
			p.Host = res.CanonicalHost
		}
		return p, nil
	}
	var matchedSavedNode bool
	if target, tErr := o.resolveTargetForPath(p); tErr == nil {
		if resolved, rErr := config.ResolveTarget(provider, target); rErr == nil {
			matchedSavedNode = resolved.MatchedNodeID != "" &&
				!strings.HasPrefix(resolved.MatchedNodeID, config.OpenSSHNodePrefix) &&
				strings.TrimSpace(resolved.Host) != ""
		}
	}
	res, cErr := config.CanonicalizeHost(ctx, config.CanonicalizeInput{
		Provider:         provider,
		Host:             p.Host,
		RawCLIOptions:    o.control.Options,
		CLIProxyJump:     o.JumpHost,
		MatchedSavedNode: matchedSavedNode,
	})
	if cErr != nil {
		return p, cErr
	}
	o.canonicalMu.Lock()
	if o.canonicalCache == nil {
		o.canonicalCache = make(map[string]config.CanonicalizeResult)
	}
	o.canonicalCache[cacheKey] = res
	o.canonicalMu.Unlock()
	if res.Canonicalized {
		if p.OriginalHost == "" {
			p.OriginalHost = res.OriginalHost
		}
		p.Host = res.CanonicalHost
	}
	return p, nil
}

func (o *ScpOptions) connectSftpForPath(ctx context.Context, p PathInfo, specificPassword string, provider config.ConfigProvider, connector *ssh.Connector) (string, *sftp.Client, error) {
	var cErr error
	p, cErr = o.canonicalizePathInfo(ctx, provider, p)
	if cErr != nil {
		return "", nil, cErr
	}
	nodeID, _, err := o.getOrCreateNodeForPath(ctx, provider, p, specificPassword)
	if err != nil {
		return "", nil, err
	}
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		return "", nil, err
	}
	sftpCli, err := sftp.NewClient(
		ctx,
		client,
		sftp.WithDiagnostics(o.diagnostics),
		sftp.WithThreadsPerFile(o.ThreadCount),
		sftp.WithForce(o.Force),
		sftp.WithSudo(o.Sudo),
	)
	if err != nil {
		return "", nil, err
	}
	return nodeID, sftpCli, nil
}

func (o *ScpOptions) resolvePathInfo(path PathInfo) (string, string, uint16, error) {
	target, err := o.resolveTargetForPath(path)
	if err != nil {
		return "", "", 0, err
	}
	user := target.User
	if user == "" {
		var userErr error
		user, userErr = cmdutils.GetCurrentUser()
		if userErr != nil {
			return "", "", 0, fmt.Errorf("get current user failed: %w", userErr)
		}
	}
	port := target.Port
	if port == 0 {
		port = 22
	}
	return target.Selector, user, port, nil
}

func (o *ScpOptions) resolveTargetForPath(path PathInfo) (config.ConnectionTarget, error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return config.ConnectionTarget{}, err
	}
	host := path.Host
	if host == "" && o.Host != "" && !strings.Contains(o.Host, ",") {
		host = o.Host
	}
	if host == "" {
		return config.ConnectionTarget{}, fmt.Errorf("%s", i18n.T("scp_err_no_host_addr"))
	}

	hasUser := false
	var user string
	if o.User != "" {
		hasUser = true
		user = o.User
	} else if path.User != "" {
		hasUser = true
		user = path.User
	}

	hasPort := false
	var port uint16
	if o.Port != 0 {
		hasPort = true
		port = o.Port
	} else if path.Port != 0 {
		hasPort = true
		port = path.Port
	}

	return config.ConnectionTarget{
		Selector:     strings.TrimSpace(host),
		User:         strings.TrimSpace(user),
		HasUser:      hasUser,
		Port:         port,
		HasPort:      hasPort,
		ProxyJump:    o.JumpHost,
		HasProxyJump: o.JumpHost != "",
	}, nil
}

func (o *ScpOptions) getOrCreateNodeForPath(ctx context.Context, provider config.ConfigProvider, path PathInfo, specificPassword string) (string, bool, error) {
	preparer, ok := provider.(interface {
		PrepareNodeContext(context.Context, config.EnsureNodeOptions) (config.EnsureNodeResult, error)
	})
	if !ok {
		return "", false, fmt.Errorf("provider does not support node preparation")
	}

	target, err := o.resolveTargetForPath(path)
	if err != nil {
		return "", false, err
	}

	shouldRemember := cmdutils.EffectiveRememberPolicy(o.Remember, provider.Snapshot()) == cmdutils.RememberPolicyAlways
	res, err := preparer.PrepareNodeContext(ctx, config.EnsureNodeOptions{
		Target:       target,
		Password:     "",
		IdentityFile: o.IdentityFile,
		Passphrase:   "",
		Alias:        o.Alias,
	})
	if err != nil {
		return "", false, err
	}

	if res.Created {
		return res.NodeID, true, nil
	}

	updated, updateErr := o.updateNode(ctx, res.NodeID, provider, specificPassword, shouldRemember)
	return res.NodeID, updated, updateErr
}

func (o *ScpOptions) updateNode(ctx context.Context, nodeID string, provider config.ConfigProvider, specificPassword string, shouldRemember bool) (bool, error) {
	if _, isRepo := provider.(*config.Repository); !isRepo ||
		strings.HasPrefix(nodeID, config.OpenSSHNodePrefix) ||
		cmdutils.EffectiveRememberPolicy(o.Remember, provider.Snapshot()) == cmdutils.RememberPolicyNever {
		if o.JumpHost != "" {
			if _, err := provider.ResolveProxyJumpChain(o.JumpHost); err != nil {
				return false, fmt.Errorf("resolve SCP proxy jump %q failed: %w", o.JumpHost, err)
			}
		}
		return false, nil
	}
	node, host, identity, err := provider.Resolve(nodeID)
	if err != nil {
		return false, fmt.Errorf("resolve scp node %q for update failed: %w", nodeID, err)
	}

	updated := o.updateNodeAuth(&identity, specificPassword, shouldRemember)

	if o.JumpHost != "" {
		jumpHost, jumpErr := provider.ResolveProxyJumpChain(o.JumpHost)
		if jumpErr != nil {
			return false, fmt.Errorf("resolve SCP proxy jump %q failed: %w", o.JumpHost, jumpErr)
		}
		if jumpHost != "" && jumpHost != node.ProxyJump {
			node.ProxyJump = jumpHost
			updated = true
		}
	}

	if updated {
		if err := putConfiguredNodeContext(ctx, provider, nodeID, node, host, identity); err != nil {
			return false, fmt.Errorf("update scp node %q failed: %w", nodeID, err)
		}
	}

	return updated, nil
}

func (o *ScpOptions) updateNodeAuth(identity *models.Identity, specificPassword string, shouldRemember bool) bool {
	updated := false
	password := specificPassword
	if password == "" && o.Password != "" {
		password = o.Password
	}

	if shouldRemember {
		if password != "" {
			if identity.AuthType != "password" {
				identity.AuthType = "password"
				updated = true
			}
		} else if o.IdentityFile != "" {
			absKeyPath := cmdutils.ToAbsolutePath(o.IdentityFile)
			if identity.KeyPath != absKeyPath || identity.AuthType != "key" {
				identity.KeyPath = absKeyPath
				identity.AuthType = "key"
				updated = true
			}
		}
	}

	return updated
}

func (o *ScpOptions) validateRemoteRelayResumePrefix(ctx context.Context, srcFile, dstFile *pkgsftp.File, startOffset int64) error {
	const chunkSize = 32 * 1024
	buf1 := make([]byte, chunkSize)
	buf2 := make([]byte, chunkSize)

	var offset int64
	for offset < startOffset {
		if err := ctx.Err(); err != nil {
			return err
		}
		readSize := int64(chunkSize)
		if startOffset-offset < readSize {
			readSize = startOffset - offset
		}

		n1, err1 := srcFile.ReadAt(buf1[:readSize], offset)
		if err1 != nil && !errors.Is(err1, io.EOF) {
			return fmt.Errorf("read source failed at offset %d: %w", offset, err1)
		}

		n2, err2 := dstFile.ReadAt(buf2[:readSize], offset)
		if err2 != nil && !errors.Is(err2, io.EOF) {
			return fmt.Errorf("read destination failed at offset %d: %w", offset, err2)
		}

		if n1 != n2 || string(buf1[:n1]) != string(buf2[:n2]) {
			return fmt.Errorf("%w at offset %d", errPrefixMismatch, offset)
		}
		if n1 == 0 {
			break
		}
		offset += int64(n1)
	}
	if offset != startOffset {
		return fmt.Errorf("%w: file shorter than expected", errPrefixMismatch)
	}
	return nil
}

var errPrefixMismatch = errors.New("resume prefix mismatch")

func (o *ScpOptions) credentialConnector(provider config.ConfigProvider, cfg *config.Configuration) (*ssh.Connector, error) {
	if o.interaction == nil {
		o.interaction = newCLIInteractionHandler()
	}
	return o.credentialConnectorWithInteraction(provider, cfg, o.interaction)
}

func (o *ScpOptions) credentialConnectorWithInteraction(provider config.ConfigProvider, cfg *config.Configuration, interaction *cliInteractionHandler) (*ssh.Connector, error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return nil, err
	}
	policy := cmdutils.EffectiveRememberPolicy(o.Remember, cfg)
	shouldRemember, adpOpts := interaction.rememberOptions(policy, cfg)
	batch := o.Tag != "" || strings.Contains(o.Host, ",") || o.HostFile != ""
	adpOpts = append(adpOpts, adapter.WithLocalExecution(!batch), adapter.WithSessionAndForwardOptions(false))
	shouldRemember = !batch && shouldRemember
	suppressConfirm := policy == cmdutils.RememberPolicyNever || batch
	if suppressConfirm {
		adpOpts = append(adpOpts, adapter.WithSuppressNodeConfirmation(true))
	}
	if batch {
		adpOpts = append(adpOpts, adapter.WithNonInteractive(true))
	}
	if err := o.appendScpSessionAuthOverrides(&adpOpts, provider, shouldRemember, suppressConfirm); err != nil {
		return nil, err
	}
	targetNodes := o.targetNodeIDs

	if err := o.appendScpSessionControlOptions(&adpOpts, targetNodes); err != nil {
		return nil, err
	}
	if repo, isRepo := provider.(*config.Repository); !isRepo {
		adpOpts = append(adpOpts, adapter.WithCredentialRecording(false), adapter.WithSuppressNodeConfirmation(true))
	} else if shouldRemember {
		persistence, serviceErr := interaction.automaticPersistenceOptions(repo, cfg)
		if serviceErr != nil {
			return nil, serviceErr
		}
		adpOpts = append(adpOpts, persistence...)
	}
	if reg, regErr := cmdutils.GetCredentialRegistry(cfg); regErr != nil {
		return nil, fmt.Errorf("initialize credential resolver: %w", regErr)
	} else if reg != nil {
		adpOpts = append(adpOpts, adapter.WithCredentialSource(reg))
	}
	var connector *ssh.Connector
	if batch {
		connector = newNonInteractiveConnector(provider, adpOpts, ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(o.diagnostics))
	} else {
		connector = newCLIConnectorWithAdapterOptions(provider, interaction, adpOpts, ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(o.diagnostics))
	}
	return connector, nil
}

func (o *ScpOptions) appendScpSessionControlOptions(adpOpts *[]adapter.Option, targetNodes []string) error {
	sessionCtrlOpts, err := o.controlSessionOptions()
	if err != nil {
		return err
	}
	if sessionCtrlOpts.IsEmpty() {
		return nil
	}
	if globalCtrl := sessionCtrlOpts.ConnectionWideOptions(); !globalCtrl.IsEmpty() {
		*adpOpts = append(*adpOpts, adapter.WithGlobalSessionControl(globalCtrl))
	}
	for _, nodeID := range targetNodes {
		*adpOpts = append(*adpOpts, adapter.WithSessionControlOverride(nodeID, sessionCtrlOpts))
	}
	return nil
}

func (o *ScpOptions) appendScpSessionAuthOverrides(adpOpts *[]adapter.Option, provider config.ConfigProvider, shouldRemember, suppressConfirm bool) error {
	targetNodes, nodeOriginalHosts, expandHosts := o.resolvedTargetNodeIDsWithHosts(provider)
	o.targetNodeIDs = targetNodes
	distinctHosts := o.distinctRemoteHosts(provider)
	if len(distinctHosts) > 1 {
		if staticHostName := o.staticHostNameOverride(); staticHostName != "" {
			return fmt.Errorf("static HostName %q cannot be used with multiple distinct remote hosts; use %%h or omit -o HostName", staticHostName)
		}
	}
	if len(targetNodes) > 0 {
		*adpOpts = append(*adpOpts, adapter.WithGlobalSessionAuth(adapter.SessionAuth{
			Remember:                 shouldRemember,
			SuppressNodeConfirmation: suppressConfirm,
		}))
		for _, nodeID := range targetNodes {
			expandHost := expandHosts[nodeID]
			if expandHost == "" {
				expandHost = nodeOriginalHosts[nodeID]
			}
			nodeHostName, hostErr := o.effectiveHostNameForHost(expandHost)
			if hostErr != nil {
				return hostErr
			}
			nodeAuth := o.buildSessionAuthOverride(nodeHostName, shouldRemember)
			nodeAuth.SuppressNodeConfirmation = suppressConfirm
			if origHost := nodeOriginalHosts[nodeID]; origHost != "" {
				nodeAuth.OriginalHost = origHost
			}
			*adpOpts = append(*adpOpts, adapter.WithSessionAuthOverride(nodeID, nodeAuth))
		}
		return nil
	}
	fallbackHost := ""
	if len(distinctHosts) == 1 {
		fallbackHost = distinctHosts[0]
	}
	var hostNameOverride string
	if o.cliHostName == "" || fallbackHost != "" || o.originalHostForExpansion() != "" {
		var hostErr error
		hostNameOverride, hostErr = o.effectiveHostNameForHost(fallbackHost)
		if hostErr != nil {
			return hostErr
		}
	}
	globalAuth := o.buildSessionAuthOverride(hostNameOverride, shouldRemember)
	globalAuth.SuppressNodeConfirmation = suppressConfirm
	globalAuth.ProxyJump = ""
	*adpOpts = append(*adpOpts, adapter.WithGlobalSessionAuth(globalAuth))
	return nil
}

func (o *SshOptions) staticHostNameOverride() string {
	if o == nil {
		return ""
	}
	if o.cliHostName != "" && !hostNameHasHostToken(o.cliHostName) {
		return o.cliHostName
	}
	if o.cliHostName == "" && strings.TrimSpace(o.HostName) != "" && !hostNameHasHostToken(strings.TrimSpace(o.HostName)) {
		return strings.TrimSpace(o.HostName)
	}
	return ""
}

func (o *ScpOptions) buildSessionAuthOverride(hostNameOverride string, shouldRemember bool) adapter.SessionAuth {
	absKeys := o.absIdentityFiles()
	keyPath := normalizeCLIIdentityPath(o.IdentityFile)
	if keyPath == "" && len(absKeys) > 0 {
		keyPath = absKeys[0]
	}
	return adapter.SessionAuth{
		Password:   o.Password,
		Passphrase: o.Passphrase,
		KeyPath:    keyPath,
		KeyPaths:   absKeys,
		HostName:   hostNameOverride,
		Remember:   shouldRemember,
		OTP:        o.OTP,
		ProxyJump:  o.JumpHost,
	}
}

func (o *ScpOptions) resolvedTargetNodeIDs(provider config.ConfigProvider) []string {
	nodeIDs, _ := o.resolvedTargetNodeIDsWithOriginals(provider)
	return nodeIDs
}

func hostNameHasHostToken(pattern string) bool {
	a, errA := ssh.ExpandHostName(pattern, "a")
	b, errB := ssh.ExpandHostName(pattern, "b")
	return errA == nil && errB == nil && a != b
}

func (o *ScpOptions) distinctRemoteHosts(provider config.ConfigProvider) []string {
	seen := make(map[string]struct{})
	var hosts []string
	for _, p := range o.collectTargetPaths(provider) {
		h := strings.TrimSpace(p.OriginalHost)
		if h == "" && provider != nil && p.Host != "" && !strings.HasPrefix(p.Host, config.OpenSSHNodePrefix) {
			if _, hostObj, _, rErr := provider.Resolve(p.Host); rErr == nil && strings.TrimSpace(hostObj.Address) != "" {
				h = strings.TrimSpace(hostObj.Address)
			}
		}
		if h == "" {
			h = strings.TrimSpace(strings.TrimPrefix(p.Host, config.OpenSSHNodePrefix))
		}
		if h == "" {
			continue
		}
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func (o *ScpOptions) resolvedTargetNodeIDsWithOriginals(provider config.ConfigProvider) ([]string, map[string]string) {
	nodeIDs, originals, _ := o.resolvedTargetNodeIDsWithHosts(provider)
	return nodeIDs, originals
}

func (o *ScpOptions) resolvedTargetNodeIDsWithHosts(provider config.ConfigProvider) ([]string, map[string]string, map[string]string) {
	if provider == nil {
		return nil, nil, nil
	}
	var nodeIDs []string
	originals := make(map[string]string)
	expandHosts := make(map[string]string)
	seen := make(map[string]struct{})
	for _, p := range o.collectTargetPaths(provider) {
		target, origHost, expandHost, ok := o.resolvePathTargetAndHosts(provider, p)
		if !ok {
			continue
		}
		for _, id := range targetCandidateNodeIDs(provider, target) {
			if id == "" {
				continue
			}
			if _, exists := seen[id]; !exists {
				seen[id] = struct{}{}
				nodeIDs = append(nodeIDs, id)
			}
			if expandHost != "" && expandHosts[id] == "" {
				expandHosts[id] = expandHost
			}
			if origHost != "" && originals[id] == "" {
				originals[id] = origHost
			} else if originals[id] == "" {
				if stripped, ok := config.OpenSSHOriginalHost(id); ok {
					originals[id] = stripped
				}
			}
		}
	}
	return nodeIDs, originals, expandHosts
}

func (o *ScpOptions) resolvePathTargetAndHosts(provider config.ConfigProvider, p PathInfo) (config.ConnectionTarget, string, string, bool) {
	origHost := p.OriginalHost
	o.canonicalMu.Lock()
	res, ok := o.canonicalCache[o.canonicalCacheKey(p)]
	o.canonicalMu.Unlock()
	if ok && res.Canonicalized {
		if origHost == "" {
			origHost = res.OriginalHost
		}
		p.Host = res.CanonicalHost
	}
	if origHost == "" {
		if stripped, ok := config.OpenSSHOriginalHost(p.Host); ok {
			origHost = stripped
		}
	}
	expandHost := origHost
	if expandHost == "" {
		if _, hostObj, _, rErr := provider.Resolve(p.Host); rErr == nil && strings.TrimSpace(hostObj.Address) != "" {
			expandHost = strings.TrimSpace(hostObj.Address)
		} else if p.Host != "" {
			expandHost = strings.TrimPrefix(p.Host, config.OpenSSHNodePrefix)
		}
	}
	target, err := o.resolveTargetForPath(p)
	if err != nil || target.Selector == "" {
		return config.ConnectionTarget{}, "", "", false
	}
	if origHost == "" {
		if resolved, rErr := config.ResolveTarget(provider, target); rErr == nil && resolved.MatchedNodeID == "" && resolved.OpenSSHAlias != "" {
			origHost = resolved.OpenSSHAlias
		}
	}
	return target, origHost, expandHost, true
}

func (o *ScpOptions) collectTargetPaths(provider config.ConfigProvider) []PathInfo {
	var paths []PathInfo
	if o.Tag != "" {
		for nodeID := range provider.GetNodesByTag(o.Tag) {
			paths = append(paths, PathInfo{Host: nodeID, IsRemote: true})
		}
	}
	if o.Host != "" || o.HostFile != "" {
		if hosts, err := cmdutils.ParseHosts(o.Host, o.HostFile, ""); err == nil {
			for _, h := range hosts {
				if h.Host != "" {
					paths = append(paths, PathInfo{Host: h.Host, User: h.User, Port: h.Port, IsRemote: true})
				}
			}
		} else if o.Host != "" {
			for h := range strings.SplitSeq(o.Host, ",") {
				h = strings.TrimSpace(h)
				if h != "" {
					paths = append(paths, PathInfo{Host: h, IsRemote: true})
				}
			}
		}
	}
	if o.Host == "" && o.Tag == "" && o.HostFile == "" {
		if src, err := parsePath(o.Source); err == nil && src.IsRemote {
			paths = append(paths, src)
		}
		if dst, err := parsePath(o.Dest); err == nil && dst.IsRemote {
			paths = append(paths, dst)
		}
	}
	return paths
}

func targetCandidateNodeIDs(provider config.ConfigProvider, target config.ConnectionTarget) []string {
	if resolved, err := config.ResolveTarget(provider, target); err == nil && resolved.NodeID != "" {
		ids := []string{resolved.NodeID}
		if resolved.MatchedNodeID != "" && resolved.Host != "" && resolved.User != "" && resolved.Port > 0 {
			derivedID := config.FormatNodeID(resolved.User, resolved.Host, resolved.Port)
			if derivedID != resolved.NodeID {
				ids = append(ids, derivedID)
			}
		}
		if resolved.OpenSSHAlias != "" && resolved.User != "" && resolved.Port > 0 {
			aliasID := config.OpenSSHNodePrefix + config.FormatNodeID(resolved.User, resolved.OpenSSHAlias, resolved.Port)
			if !slices.Contains(ids, aliasID) {
				ids = append(ids, aliasID)
			}
		}
		return ids
	}
	user := target.User
	if user == "" {
		if u, uErr := cmdutils.GetCurrentUser(); uErr == nil {
			user = u
		}
	}
	port := target.Port
	if port == 0 {
		port = 22
	}
	if user == "" {
		return nil
	}
	return []string{config.FormatNodeID(user, target.Selector, port)}
}
