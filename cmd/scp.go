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
	adapterMu      sync.Mutex
	activeAdapter  *adapter.SSHAdapter
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
	cmd.Flags().StringVarP(&o.CipherSpec, "cipher", "c", "", i18n.T("flag_ssh_cipher"))
	cmd.Flags().StringArrayVarP(&o.IdentityFiles, "identity", "i", nil, i18n.T("flag_identity"))
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "J", "", i18n.T("flag_jump"))
	cmd.Flags().BoolVarP(&o.Recursive, "recursive", "r", false, i18n.T("flag_recursive"))
	o.control.RegisterCommonFlags(cmd)
	o.control.RegisterAddressFamilyFlags(cmd)

	// xops-enhanced flags (long-form only, no short flags to avoid OpenSSH conflicts)
	registerSelectorFlag(cmd.Flags(), &o.Host, "host", "", i18n.T("flag_hosts"))
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
	registerSelectorFlag(cmd.Flags(), &o.HostFile, "ifile", "I", i18n.T("flag_ifile"))
	registerSelectorFlag(cmd.Flags(), &o.Tag, "tag", "", i18n.T("flag_scp_tag"))
	cmdutils.RegisterExcludeFlag(cmd.Flags(), &o.Exclude, i18n.T("flag_exclude"))
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
	if _, err := o.toSessionControlOptions(); err != nil {
		return err
	}
	pathFlags := o.Source != "" || o.Dest != ""
	if cmd != nil {
		if err := validateExplicitZeroPort(cmd.Flags()); err != nil {
			return err
		}
		pathFlags = pathFlags || cmd.Flags().Changed("src") || cmd.Flags().Changed("dest")
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
	_, err := readCLISecretsFromStdin(&o.SshOptions)
	return err
}

func (o *ScpOptions) hasExcludeFlags() bool {
	return len(o.Exclude) > 0
}

func (o *ScpOptions) validatedExcludes() ([]string, error) {
	if !o.hasExcludeFlags() {
		return nil, nil
	}
	return cmdutils.ValidateExcludeFlagValues(o.Exclude)
}

func (o *ScpOptions) Validate() error {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return err
	}
	if err := o.control.Validate(); err != nil {
		return err
	}
	if _, err := o.toSessionControlOptions(); err != nil {
		return err
	}
	if err := validateCommonSSHBaseOptions(&o.SshOptions); err != nil {
		return err
	}
	if err := validateProgrammaticSelectors(
		selectorField{name: "host", val: o.Host},
		selectorField{name: "tag", val: o.Tag},
		selectorField{name: "ifile", val: o.HostFile},
	); err != nil {
		return err
	}
	if _, err := o.validatedExcludes(); err != nil {
		return err
	}
	if o.TaskCount < 1 || o.TaskCount > maxBatchTaskCount {
		return fmt.Errorf("invalid --task value %d: must be between 1 and %d", o.TaskCount, maxBatchTaskCount)
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

func isWindowsDrivePath(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	isLetter := (p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')
	return isLetter && (len(p) == 2 || p[2] == '\\' || p[2] == '/')
}

func parsePath(p string) (PathInfo, error) {
	if p == "" {
		return PathInfo{IsRemote: false, Path: ""}, nil
	}
	if strings.HasPrefix(p, config.OpenSSHNodePrefix) {
		return parseOpenSSHPath(p)
	}
	if isWindowsDrivePath(p) {
		return PathInfo{IsRemote: false, Path: p}, nil
	}
	return parsePlainScpPath(p)
}

func parsePlainScpPath(p string) (PathInfo, error) {
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
		return parseRemotePath(addrPart, pathPart, p)
	}
	return PathInfo{IsRemote: false, Path: p}, nil
}

func parseOpenSSHPath(p string) (PathInfo, error) {
	rest := p[len(config.OpenSSHNodePrefix):]
	if rest == "" || strings.HasPrefix(rest, config.OpenSSHNodePrefix) {
		return PathInfo{}, fmt.Errorf("invalid openssh remote path %q", p)
	}
	firstColon := strings.Index(rest, ":")
	if firstColon == -1 || strings.ContainsAny(rest[:firstColon], "/\\") {
		return PathInfo{}, fmt.Errorf("missing or invalid remote path delimiter ':' in %q", p)
	}
	separator := firstColon
	if openBracket := strings.Index(rest, "["); openBracket != -1 && openBracket < firstColon {
		closeBracket := strings.Index(rest[openBracket:], "]")
		if closeBracket == -1 {
			return PathInfo{}, fmt.Errorf("malformed bracketed address in %q", p)
		}
		separator = openBracket + closeBracket + 1
		if separator >= len(rest) || rest[separator] != ':' {
			return PathInfo{}, fmt.Errorf("missing or invalid remote path delimiter ':' in %q", p)
		}
	}
	addrRest, pathPart := rest[:separator], rest[separator+1:]
	if strings.ContainsAny(addrRest, "/\\") {
		return PathInfo{}, fmt.Errorf("invalid openssh remote address in %q", p)
	}
	return parseRemotePath(config.OpenSSHNodePrefix+addrRest, pathPart, p)
}

func parseRemotePath(addrPart, pathPart, raw string) (PathInfo, error) {
	u, h, port, err := cmdutils.ParseAddr(addrPart)
	if err != nil {
		return PathInfo{}, fmt.Errorf("invalid remote address %q in %q: %w", addrPart, raw, err)
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

func (o *ScpOptions) currentAdapter() *adapter.SSHAdapter {
	if o == nil {
		return nil
	}
	o.adapterMu.Lock()
	defer o.adapterMu.Unlock()
	return o.activeAdapter
}

func (o *ScpOptions) isScpNodeConfirmationSuppressed(provider config.ConfigProvider) bool {
	if _, isRepo := provider.(*config.Repository); !isRepo {
		return true
	}
	if o.isBatchMode() {
		return true
	}
	return cmdutils.EffectiveRememberPolicy(o.Remember, provider.Snapshot()) == cmdutils.RememberPolicyNever
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
	if err := o.canonicalizeEndpoints(ctx, provider); err != nil {
		return err
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

	if err := o.validateTransferExcludes(provider, src, dst); err != nil {
		return err
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

func (o *ScpOptions) validateTransferExcludes(provider config.ConfigProvider, src, dst PathInfo) error {
	if !o.hasExcludeFlags() || provider == nil {
		return nil
	}
	excludes, err := o.resolveExcludes(provider)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("scp_err_exclude"), err)
	}
	for _, p := range []PathInfo{src, dst} {
		if !p.IsRemote {
			continue
		}
		canonP := o.cachedCanonicalPathInfo(p)
		excluded, exErr := o.isBatchHostExcluded(provider, excludes, p.Host, canonP)
		if exErr != nil {
			return fmt.Errorf("%s: %w", i18n.T("scp_err_exclude"), exErr)
		}
		if excluded {
			return fmt.Errorf("%s: target host excluded", i18n.T("scp_err_exclude"))
		}
	}
	return nil
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
	remoteTarget, parseErr := sftp.ParseRemoteUploadTarget(remotePath, filepath.Base(localPath), err == nil && remoteStat.IsDir())
	if parseErr != nil {
		return fmt.Errorf("resolve upload destination %q failed: %w", remotePath, parseErr)
	}
	remotePath = remoteTarget.String()

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
	remotePath, contentsOnly, err := sftp.ParseRemoteDownloadPath(src.Path)
	if err != nil {
		return err
	}
	localDest, err := sftp.LocalDestInto(localPath)
	if err != nil {
		return err
	}

	return sftpCli.WithForce(o.Force).Download(ctx, remotePath, localDest, sftp.DownloadOptions{
		ContentsOnly: contentsOnly,
		ConfirmOverwrite: func(_ context.Context, target sftp.DownloadTargetInfo) (sftp.DownloadOverwriteDecision, error) {
			if o.NoOverwrite {
				return sftp.DownloadOverwriteSkip, nil
			}
			if !o.Force {
				confirmed, confirmErr := cmdutils.AskConfirmation(i18n.Tf("prompt_overwrite", map[string]any{"Path": target.LocalPath}))
				if confirmErr != nil {
					return sftp.DownloadOverwriteDefault, confirmErr
				}
				if !confirmed {
					return sftp.DownloadOverwriteSkip, nil
				}
				o.Force = true // 用户确认后开启强制覆盖
				return sftp.DownloadOverwriteForce, nil
			}
			return sftp.DownloadOverwriteDefault, nil
		},
		BeforeTransfer: func(transferCtx context.Context, target sftp.DownloadTargetInfo) (*sftp.DownloadTransferHooks, error) {
			size := target.Info.Size()
			if target.Info.IsDir() {
				size = -1
			}
			progress, finishProgress := o.createTransferProgress(transferCtx, size, "Downloading "+sftp.DisplayRemoteName(target.Remote), 0)
			return &sftp.DownloadTransferHooks{
				Progress: progress,
				Finish: func(error) error {
					return finishProgress()
				},
			}, nil
		},
	})
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
	srcRemote, _, err := sftp.ParseRemoteDownloadPath(src.Path)
	if err != nil {
		return err
	}
	dstRemote, err := sftp.ParseRemotePath(dst.Path)
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

	var preStat os.FileInfo
	if err = srcSftp.Do(ctx, func(c *pkgsftp.Client) error {
		var statErr error
		preStat, statErr = c.Stat(srcRemote.String())
		return statErr
	}); err != nil {
		return fmt.Errorf("stat remote source %q failed: %w", srcRemote.String(), err)
	}
	if preStat.IsDir() {
		return fmt.Errorf("remote-to-remote directory transfer is not supported for %q: download locally and upload instead", srcRemote.String())
	}

	var srcFile *pkgsftp.File
	err = srcSftp.Do(ctx, func(c *pkgsftp.Client) error {
		var err error
		srcFile, err = c.Open(srcRemote.String())
		return err
	})
	if err != nil {
		return fmt.Errorf("open remote source %q failed: %w", srcRemote.String(), err)
	}
	defer joinCloseError(&retErr, "remote source file", srcFile.Close)

	srcStat, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("stat remote source %q failed: %w", srcRemote.String(), err)
	}
	if srcStat.IsDir() {
		return fmt.Errorf("remote-to-remote directory transfer is not supported for %q: download locally and upload instead", srcRemote.String())
	}

	dstPath := dstRemote.String()
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
		srcBase := srcRemote.Base()
		if !srcBase.IsValid() {
			return fmt.Errorf("unsafe remote filename %q: invalid source basename", srcRemote.String())
		}
		statName, nameErr := sftp.ParseRemoteName(srcStat.Name())
		if nameErr != nil {
			return fmt.Errorf("unsafe remote filename %q: %w", srcStat.Name(), nameErr)
		}
		if !statName.Equal(srcBase) {
			return fmt.Errorf("unsafe remote filename %q: stat name does not match source basename %q", srcStat.Name(), srcBase.String())
		}
		dstRemote = dstRemote.Join(srcBase)
		dstPath = dstRemote.String()
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

	progress, finishProgress := o.createTransferProgress(ctx, srcStat.Size(), "Relaying "+sftp.DisplayRemoteName(srcRemote), startOffset)
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

func taggedNodePathInfo(nodeID string) PathInfo {
	return PathInfo{Host: nodeID, IsRemote: true}
}

func (o *ScpOptions) runBatch(ctx context.Context, provider config.ConfigProvider, connector *ssh.Connector) error {
	if err := o.canonicalizeEndpoints(ctx, provider); err != nil {
		return err
	}
	// 解析 --exclude 排除规则（在 Worker Pool 启动前完成，确保无歧义）
	var excludes map[string]struct{}
	if o.hasExcludeFlags() {
		resolved, err := o.resolveExcludes(provider)
		if err != nil {
			return fmt.Errorf("%s: %w", i18n.T("scp_err_exclude"), err)
		}
		excludes = resolved
	}

	if o.TaskCount < 0 || o.TaskCount > maxBatchTaskCount {
		return fmt.Errorf("invalid --task value %d: must be between 1 and %d", o.TaskCount, maxBatchTaskCount)
	}
	var (
		errMu        sync.Mutex
		transferErrs []error
	)
	wp := pkgutils.NewWorkerPool(uint(o.TaskCount))
	recordTransferErr := func(label string, err error) {
		errMu.Lock()
		transferErrs = append(transferErrs, fmt.Errorf("[%s] %w", label, err))
		errMu.Unlock()
	}

	var prepErr error
	if o.Tag != "" {
		prepErr = o.runBatchTagged(ctx, provider, connector, excludes, wp, recordTransferErr)
	} else {
		prepErr = o.runBatchHosts(ctx, provider, connector, excludes, wp, recordTransferErr)
	}

	wp.Wait()
	if prepErr != nil {
		return errors.Join(prepErr, errors.Join(transferErrs...))
	}
	return errors.Join(transferErrs...)
}

func (o *ScpOptions) runBatchTagged(
	ctx context.Context,
	provider config.ConfigProvider,
	connector *ssh.Connector,
	excludes map[string]struct{},
	wp pkgutils.WorkerPool,
	recordErr func(string, error),
) error {
	nodes := provider.GetNodesByTag(o.Tag)
	if len(nodes) == 0 {
		return fmt.Errorf("%s", i18n.Tf("err_tag_empty", map[string]any{"Tag": o.Tag}))
	}
	for _, nodeID := range slices.Sorted(maps.Keys(nodes)) {
		addr := taggedNodePathInfo(nodeID)
		canonAddr, canonErr := o.canonicalizePathInfo(ctx, provider, addr)
		if canonErr != nil {
			return fmt.Errorf("canonicalize tagged host %q: %w", nodeID, canonErr)
		}
		if excludes != nil {
			excluded, exclErr := o.isBatchHostExcluded(provider, excludes, nodeID, canonAddr)
			if exclErr != nil {
				return exclErr
			}
			if excluded {
				continue
			}
		}
		nid := nodeID // capture
		_, _, identity, resolveErr := provider.Resolve(nid)
		if resolveErr != nil {
			return fmt.Errorf("resolve tagged scp node %q failed: %w", nid, resolveErr)
		}
		specificPass := ""
		if o.Password != "" {
			specificPass = o.Password
		} else if o.User == "" || strings.TrimSpace(o.User) == identity.User {
			specificPass = identity.Password
		}
		wp.Execute(func() {
			if tErr := o.executeTransfer(ctx, nid, canonAddr, specificPass, provider, connector); tErr != nil {
				recordErr(nid, tErr)
			}
		})
	}
	return nil
}

func (o *ScpOptions) runBatchHosts(
	ctx context.Context,
	provider config.ConfigProvider,
	connector *ssh.Connector,
	excludes map[string]struct{},
	wp pkgutils.WorkerPool,
	recordErr func(string, error),
) error {
	hosts, err := cmdutils.ParseHosts(o.Host, o.HostFile, "")
	if err != nil {
		return err
	}

	// 处理 普通主机列表
	for _, h := range hosts {
		h.User, _, h.Port, _ = o.resolveUserAndPort(PathInfo{Host: h.Host, User: h.User, Port: h.Port, IsRemote: true})
		if h.Password == "" {
			h.Password = o.Password
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

		hostItem := h
		wp.Execute(func() {
			if tErr := o.executeTransfer(ctx, hostItem.Host, canonAddr, hostItem.Password, provider, connector); tErr != nil {
				recordErr(hostItem.Host, tErr)
			}
		})
	}
	return nil
}

func (o *ScpOptions) isBatchHostExcluded(provider config.ConfigProvider, excludes map[string]struct{}, rawHost string, canonAddr PathInfo) (bool, error) {
	if len(excludes) == 0 {
		return false, nil
	}
	info, err := o.excludeTargetInfoForPath(provider, rawHost, canonAddr)
	if err != nil {
		return false, err
	}
	return cmdutils.IsTargetExcluded(excludes, info), nil
}

func (o *ScpOptions) resolveUserAndPort(path PathInfo) (user string, hasUser bool, port uint16, hasPort bool) {
	if path.User != "" {
		user = path.User
		hasUser = true
	} else if o.User != "" {
		user = o.User
		hasUser = true
	}
	if path.Port != 0 {
		port = path.Port
		hasPort = true
	} else if o.Port != 0 {
		port = o.Port
		hasPort = true
	}
	return user, hasUser, port, hasPort
}

func (o *ScpOptions) overriddenExcludeHost(expandHost string) string {
	if o == nil {
		return ""
	}
	hostNameOverride, err := o.effectiveHostNameForHost(expandHost)
	if err != nil {
		return ""
	}
	return hostNameOverride
}

func (o *ScpOptions) excludeTargetInfoForPath(provider config.ConfigProvider, rawHost string, canonAddr PathInfo) (cmdutils.ExcludeTargetInfo, error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return cmdutils.ExcludeTargetInfo{}, err
	}
	user, _, port, _ := o.resolveUserAndPort(canonAddr)
	in := cmdutils.ExcludeTargetBuildInput{
		User:           user,
		Port:           port,
		UnmanagedHosts: []string{rawHost, canonAddr.Host, canonAddr.OriginalHost},
	}
	fallbackExpandHost := canonAddr.OriginalHost
	if fallbackExpandHost == "" {
		fallbackExpandHost = config.UnwrapOpenSSHSelector(canonAddr.Host)
	}
	if fallbackExpandHost == "" {
		fallbackExpandHost = config.UnwrapOpenSSHSelector(rawHost)
	}
	if provider == nil {
		in.HostNameOverride = o.overriddenExcludeHost(fallbackExpandHost)
		return cmdutils.BuildExcludeTargetInfo(in), nil
	}
	if target, tErr := o.resolveTargetForPath(canonAddr); tErr == nil && target.Selector != "" {
		resolved, rErr := config.ResolveTarget(provider, target)
		if rErr != nil {
			return cmdutils.BuildExcludeTargetInfo(in), fmt.Errorf("resolve excluded host %q: %w", canonAddr.Host, rErr)
		}
		in.NodeID = resolved.NodeID
		in.MatchedNodeID = resolved.MatchedNodeID
		in.BaseNodeID = resolved.BaseNodeID
		in.OpenSSHAlias = resolved.OpenSSHAlias
		in.CanonicalHost = resolved.CanonicalHost
		in.ResolvedHost = resolved.Host
		if resolved.User != "" {
			in.User = resolved.User
		}
		if resolved.Port > 0 {
			in.Port = resolved.Port
		}
		_, expandHost := resolveTargetOriginalAndExpandHosts(canonAddr.OriginalHost != "", canonAddr.OriginalHost, target.Selector, resolved, true)
		if expandHost == "" {
			expandHost = fallbackExpandHost
		}
		in.HostNameOverride = o.overriddenExcludeHost(expandHost)
		return cmdutils.BuildExcludeTargetInfo(in), nil
	}
	nid, resolveErr := provider.ResolveSelector(canonAddr.Host)
	if resolveErr != nil {
		return cmdutils.BuildExcludeTargetInfo(in), fmt.Errorf("resolve excluded host %q: %w", canonAddr.Host, resolveErr)
	}
	if nid != "" {
		in.NodeID = nid
	}
	in.HostNameOverride = o.overriddenExcludeHost(fallbackExpandHost)
	return cmdutils.BuildExcludeTargetInfo(in), nil
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
	remoteTarget, parseErr := sftp.ParseRemoteUploadTarget(remotePath, filepath.Base(o.Source), remoteStat != nil && remoteStat.IsDir())
	if parseErr != nil {
		return fmt.Errorf("resolve remote dest %q failed: %w", remotePath, parseErr)
	}
	remotePath = remoteTarget.String()

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
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return err
	}
	if provider == nil {
		return nil
	}
	rawPaths, err := o.rawTargetPaths(provider)
	if err != nil {
		return err
	}
	for _, p := range rawPaths {
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
	user, _, port, _ := o.resolveUserAndPort(p)
	if user == "" && port == 0 {
		return host
	}
	return fmt.Sprintf("%s\x00%s\x00%d", host, user, port)
}

func (o *ScpOptions) canonicalizePathInfo(ctx context.Context, provider config.ConfigProvider, p PathInfo) (PathInfo, error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return p, err
	}
	if p.Host == "" {
		return p, nil
	}
	if strings.HasPrefix(p.Host, config.OpenSSHNodePrefix) {
		if stripped, ok := config.OpenSSHOriginalHost(p.Host); ok && p.OriginalHost == "" {
			p.OriginalHost = stripped
		}
		return p, nil
	}
	if p.OriginalHost != "" {
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
			matchedSavedNode = isResolvedSavedNode(resolved)
		}
	}
	res, cErr := config.CanonicalizeHost(ctx, config.CanonicalizeInput{
		Provider:         provider,
		Host:             p.Host,
		RawCLIOptions:    o.control.Options,
		CLIProxyJump:     o.effectiveCLIJumpHost(),
		MatchedSavedNode: matchedSavedNode,
		Resolver:         o.canonicalResolver,
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
	req, err := o.buildScpEnsureOptions(provider, p, specificPassword)
	if err != nil {
		return "", nil, err
	}
	var (
		resolvedNodeID string
		sftpCli        *sftp.Client
	)
	err = config.WithPendingNode(ctx, provider, req, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		client, connErr := connector.Connect(ctx, nodeID)
		if connErr != nil {
			return connErr
		}
		if finalizeErr := o.finalizeScpPendingConnection(ctx, provider, lease, client); finalizeErr != nil {
			_ = connector.EvictClient(client)
			return finalizeErr
		}
		cli, sftpErr := sftp.NewClient(
			ctx,
			client,
			sftp.WithDiagnostics(o.diagnostics),
			sftp.WithThreadsPerFile(o.ThreadCount),
			sftp.WithForce(o.Force),
			sftp.WithSudo(o.Sudo),
		)
		if sftpErr != nil {
			return sftpErr
		}
		resolvedNodeID = nodeID
		sftpCli = cli
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return resolvedNodeID, sftpCli, nil
}

func (o *ScpOptions) finalizeScpPendingConnection(ctx context.Context, provider config.ConfigProvider, lease config.PendingLease, client *ssh.Client) error {
	if adp := o.currentAdapter(); adp != nil {
		return adp.FinalizePendingConnection(ctx, lease, client)
	}
	if o.isScpNodeConfirmationSuppressed(provider) {
		return nil
	}
	return lease.Confirm(ctx)
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

	user, hasUser, port, hasPort := o.resolveUserAndPort(path)

	return config.ConnectionTarget{
		Selector:     strings.TrimSpace(host),
		OriginalHost: strings.TrimSpace(path.OriginalHost),
		User:         strings.TrimSpace(user),
		HasUser:      hasUser,
		Port:         port,
		HasPort:      hasPort,
		ProxyJump:    o.JumpHost,
		HasProxyJump: o.JumpHost != "",
	}, nil
}

func (o *ScpOptions) isBatchMode() bool {
	return o != nil && (o.Tag != "" || o.Host != "" || o.HostFile != "")
}

func (o *ScpOptions) buildScpEnsureOptions(provider config.ConfigProvider, path PathInfo, specificPassword string) (config.EnsureNodeOptions, error) {
	target, err := o.resolveTargetForPath(path)
	if err != nil {
		return config.EnsureNodeOptions{}, err
	}
	var snap *config.Configuration
	if provider != nil {
		snap = provider.Snapshot()
	}
	batch := o.isBatchMode()
	suppressConfirm := o.isScpNodeConfirmationSuppressed(provider)
	shouldRemember := !batch && cmdutils.EffectiveRememberPolicy(o.Remember, snap) == cmdutils.RememberPolicyAlways
	hasPassword := specificPassword != "" || o.Password != ""
	return config.EnsureNodeOptions{
		Target:       target,
		Password:     "",
		IdentityFile: o.IdentityFile,
		Passphrase:   "",
		Alias:        o.Alias,
		ExistingUpdate: config.PendingNodeUpdate{
			Enabled:      !suppressConfirm,
			JumpHost:     o.JumpHost,
			RememberAuth: shouldRemember,
			HasPassword:  hasPassword,
			IdentityFile: o.IdentityFile,
		},
	}, nil
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
	batch := o.isBatchMode()
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
	var (
		connector *ssh.Connector
		adp       *adapter.SSHAdapter
	)
	if batch {
		connector, adp = newNonInteractiveConnectorAndAdapter(provider, adpOpts, ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(o.diagnostics))
	} else {
		connector, adp = newCLIConnectorAndAdapter(provider, interaction, adpOpts, ssh.WithLogger(logger.DefaultLogger()), ssh.WithDiagnostics(o.diagnostics))
	}
	o.adapterMu.Lock()
	o.activeAdapter = adp
	o.adapterMu.Unlock()
	return connector, nil
}

func (o *ScpOptions) appendScpSessionControlOptions(adpOpts *[]adapter.Option, targetNodes []string) error {
	sessionCtrlOpts, err := o.toSessionControlOptions()
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
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return err
	}
	targetPaths, err := o.collectTargetPaths(provider)
	if err != nil {
		return err
	}
	targetNodes, nodeOriginalHosts, expandHosts, nodeCanonHosts := o.resolvedTargetNodeIDsWithHostsAndCanonForPaths(provider, targetPaths)
	o.targetNodeIDs = targetNodes
	distinctHosts := o.distinctRemoteHostsForPaths(provider, targetPaths)
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
			if canonHost := nodeCanonHosts[nodeID]; canonHost != "" {
				nodeAuth.CanonicalHost = canonHost
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
	paths, err := o.collectTargetPaths(provider)
	if err != nil {
		return nil
	}
	return o.distinctRemoteHostsForPaths(provider, paths)
}

func (o *ScpOptions) distinctRemoteHostsForPaths(provider config.ConfigProvider, targetPaths []PathInfo) []string {
	seen := make(map[string]struct{})
	var hosts []string
	for _, p := range targetPaths {
		var h string
		if provider != nil {
			if _, origHost, expandHost, ok := o.resolvePathTargetAndHosts(provider, p); ok {
				h = strings.TrimSpace(origHost)
				if h == "" {
					h = strings.TrimSpace(expandHost)
				}
			}
		}
		if h == "" {
			h = strings.TrimSpace(p.OriginalHost)
		}
		if h == "" {
			h = config.UnwrapOpenSSHSelector(p.Host)
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
	paths, err := o.collectTargetPaths(provider)
	if err != nil {
		return nil, nil, nil
	}
	return o.resolvedTargetNodeIDsWithHostsForPaths(provider, paths)
}

func (o *ScpOptions) resolvedTargetNodeIDsWithHostsForPaths(provider config.ConfigProvider, targetPaths []PathInfo) ([]string, map[string]string, map[string]string) {
	nodeIDs, originals, expandHosts, _ := o.resolvedTargetNodeIDsWithHostsAndCanonForPaths(provider, targetPaths)
	return nodeIDs, originals, expandHosts
}

func (o *ScpOptions) resolvedTargetNodeIDsWithHostsAndCanonForPaths(provider config.ConfigProvider, targetPaths []PathInfo) ([]string, map[string]string, map[string]string, map[string]string) {
	if provider == nil {
		return nil, nil, nil, nil
	}
	var nodeIDs []string
	originals := make(map[string]string)
	expandHosts := make(map[string]string)
	canonHosts := make(map[string]string)
	seen := make(map[string]struct{})
	for _, p := range targetPaths {
		target, origHost, expandHost, canonHost, ok := o.resolvePathTargetDetails(provider, p)
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
			if canonHost != "" && canonHosts[id] == "" {
				canonHosts[id] = canonHost
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
	return nodeIDs, originals, expandHosts, canonHosts
}

func (o *ScpOptions) resolvePathTargetAndHosts(provider config.ConfigProvider, p PathInfo) (config.ConnectionTarget, string, string, bool) {
	target, origHost, expandHost, _, ok := o.resolvePathTargetDetails(provider, p)
	return target, origHost, expandHost, ok
}

func (o *ScpOptions) resolvePathTargetDetails(provider config.ConfigProvider, p PathInfo) (config.ConnectionTarget, string, string, string, bool) {
	canonOriginalHost := p.OriginalHost
	canonicalized := canonOriginalHost != ""
	canonHost := ""
	o.canonicalMu.Lock()
	res, ok := o.canonicalCache[o.canonicalCacheKey(p)]
	o.canonicalMu.Unlock()
	if ok && res.Canonicalized {
		canonicalized = true
		if canonOriginalHost == "" {
			canonOriginalHost = res.OriginalHost
		}
		canonHost = res.CanonicalHost
		p.OriginalHost = canonOriginalHost
		p.Host = res.CanonicalHost
	}
	target, err := o.resolveTargetForPath(p)
	if err != nil || target.Selector == "" {
		return config.ConnectionTarget{}, "", "", "", false
	}
	resolved, rErr := config.ResolveTarget(provider, target)
	origHost, expandHost := resolveTargetOriginalAndExpandHosts(canonicalized, canonOriginalHost, target.Selector, resolved, rErr == nil)
	if canonHost == "" && rErr == nil {
		canonHost = resolved.CanonicalHost
	}
	return target, origHost, expandHost, canonHost, true
}

func (o *ScpOptions) cachedCanonicalPathInfo(p PathInfo) PathInfo {
	canonP := p
	o.canonicalMu.Lock()
	res, ok := o.canonicalCache[o.canonicalCacheKey(p)]
	o.canonicalMu.Unlock()
	if ok && res.Canonicalized {
		if canonP.OriginalHost == "" {
			canonP.OriginalHost = res.OriginalHost
		}
		canonP.Host = res.CanonicalHost
	}
	return canonP
}

func (o *ScpOptions) isCollectedPathExcluded(provider config.ConfigProvider, excludes map[string]struct{}, p PathInfo) (bool, error) {
	if len(excludes) == 0 || provider == nil {
		return false, nil
	}
	canonP := o.cachedCanonicalPathInfo(p)
	return o.isBatchHostExcluded(provider, excludes, p.Host, canonP)
}

func (o *ScpOptions) rawHostTargetPaths() ([]PathInfo, error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return nil, err
	}
	hosts, err := cmdutils.ParseHosts(o.Host, o.HostFile, "")
	if err != nil {
		return nil, err
	}
	paths := make([]PathInfo, 0, len(hosts))
	for _, h := range hosts {
		p := PathInfo{Host: strings.TrimSpace(h.Host), User: h.User, Port: h.Port, IsRemote: true}
		if p.Host == "" {
			continue
		}
		p.User, _, p.Port, _ = o.resolveUserAndPort(p)
		paths = append(paths, p)
	}
	return paths, nil
}

func (o *ScpOptions) rawTargetPaths(provider config.ConfigProvider) ([]PathInfo, error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return nil, err
	}
	var paths []PathInfo
	if o.Tag != "" && provider != nil {
		for _, nodeID := range slices.Sorted(maps.Keys(provider.GetNodesByTag(o.Tag))) {
			paths = append(paths, taggedNodePathInfo(nodeID))
		}
	}
	if o.Host != "" || o.HostFile != "" {
		hostPaths, err := o.rawHostTargetPaths()
		if err != nil {
			return nil, err
		}
		paths = append(paths, hostPaths...)
	}
	if o.Host == "" && o.Tag == "" && o.HostFile == "" {
		if o.Source != "" {
			src, err := parsePath(o.Source)
			if err != nil {
				return nil, fmt.Errorf("parse source path failed: %w", err)
			}
			if src.IsRemote {
				paths = append(paths, src)
			}
		}
		if o.Dest != "" {
			dst, err := parsePath(o.Dest)
			if err != nil {
				return nil, fmt.Errorf("parse dest path failed: %w", err)
			}
			if dst.IsRemote {
				paths = append(paths, dst)
			}
		}
	}
	return paths, nil
}

func (o *ScpOptions) resolveExcludes(provider config.ConfigProvider) (map[string]struct{}, error) {
	if err := o.ensureGeneralOptionsApplied(); err != nil {
		return nil, err
	}
	if !o.hasExcludeFlags() {
		return nil, nil
	}
	parsedExcludes, err := o.validatedExcludes()
	if err != nil {
		return nil, err
	}
	candidates, err := o.buildExcludeCandidatesChecked(provider)
	if err != nil {
		return nil, err
	}
	return cmdutils.ResolveExcludesForTargetsWithOptions(provider, parsedExcludes, candidates, o.control.Options, o.effectiveCLIJumpHost())
}

func (o *ScpOptions) buildExcludeCandidates(provider config.ConfigProvider) []cmdutils.ExcludeTargetInfo {
	candidates, err := o.buildExcludeCandidatesChecked(provider)
	if err != nil {
		return nil
	}
	return candidates
}

func (o *ScpOptions) buildExcludeCandidatesChecked(provider config.ConfigProvider) ([]cmdutils.ExcludeTargetInfo, error) {
	rawPaths, err := o.rawTargetPaths(provider)
	if err != nil {
		return nil, err
	}
	candidates := make([]cmdutils.ExcludeTargetInfo, 0, len(rawPaths))
	for _, p := range rawPaths {
		if p.Host == "" {
			continue
		}
		canonP := o.cachedCanonicalPathInfo(p)
		info, infoErr := o.excludeTargetInfoForPath(provider, p.Host, canonP)
		if infoErr != nil {
			return nil, infoErr
		}
		candidates = append(candidates, info)
	}
	return candidates, nil
}

func (o *ScpOptions) collectTargetPaths(provider config.ConfigProvider) ([]PathInfo, error) {
	var excludes map[string]struct{}
	if provider != nil && o.hasExcludeFlags() {
		resolved, err := o.resolveExcludes(provider)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("scp_err_exclude"), err)
		}
		excludes = resolved
	}
	return o.collectTargetPathsWithExcludesChecked(provider, excludes)
}

func (o *ScpOptions) collectTargetPathsWithExcludesChecked(provider config.ConfigProvider, excludes map[string]struct{}) ([]PathInfo, error) {
	rawPaths, err := o.rawTargetPaths(provider)
	if err != nil {
		return nil, err
	}
	paths := make([]PathInfo, 0, len(rawPaths))
	for _, p := range rawPaths {
		excluded, exErr := o.isCollectedPathExcluded(provider, excludes, p)
		if exErr != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("scp_err_exclude"), exErr)
		}
		if !excluded {
			paths = append(paths, p)
		}
	}
	return paths, nil
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
