package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	cmdutils "github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/ssh"
	pkgutils "github.com/wentf9/xops-cli/pkg/utils"
)

type ScpOptions struct {
	SshOptions
	Recursive   bool
	Progress    bool
	Force       bool
	NoOverwrite bool
	TaskCount   int
	ThreadCount int
	Source      string
	Dest        string
	HostFile    string
	Tag         string
	Exclude     []string
}

func NewScpOptions() *ScpOptions {
	return &ScpOptions{
		SshOptions:  *NewSshOptions(),
		TaskCount:   1,
		ThreadCount: sftp.DefaultThreadsPerFile,
	}
}

func NewCmdScp() *cobra.Command {
	o := NewScpOptions()
	cmd := &cobra.Command{
		Use:   "scp [[user@]host:]source [[user@]host:]dest",
		Short: i18n.T("scp_short"),
		Long:  i18n.T("scp_long"),
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
	cmd.Flags().BoolVarP(&o.Recursive, "recursive", "r", false, i18n.T("flag_recursive"))

	// xops-enhanced flags (long-form only, no short flags to avoid OpenSSH conflicts)
	cmd.Flags().StringVar(&o.Host, "host", "", i18n.T("flag_hosts"))
	cmd.Flags().StringVar(&o.Password, "password", "", i18n.T("flag_password"))
	cmd.Flags().StringVar(&o.Passphrase, "passphrase", "", i18n.T("flag_passphrase"))
	cmd.Flags().StringVar(&o.Alias, "alias", "", i18n.T("flag_alias"))

	// scp-specific flags
	cmd.Flags().StringVar(&o.Source, "src", "", i18n.T("flag_scp_src"))
	cmd.Flags().StringVar(&o.Dest, "dest", "", i18n.T("flag_scp_dest"))
	cmd.Flags().StringVarP(&o.HostFile, "ifile", "I", "", i18n.T("flag_ifile"))
	cmd.Flags().StringVar(&o.Tag, "tag", "", i18n.T("flag_scp_tag"))
	cmd.Flags().StringSliceVar(&o.Exclude, "exclude", nil, i18n.T("flag_exclude"))
	cmd.Flags().BoolVarP(&o.Progress, "progress", "v", false, i18n.T("flag_progress"))
	cmd.Flags().BoolVarP(&o.Force, "force", "f", false, i18n.T("flag_force"))
	cmd.Flags().BoolVarP(&o.NoOverwrite, "no-clobber", "n", false, i18n.T("flag_no_overwrite"))
	cmd.Flags().IntVar(&o.TaskCount, "task", 3, i18n.T("flag_task"))
	cmd.Flags().IntVar(&o.ThreadCount, "thread", 4, i18n.T("flag_thread"))

	cmd.MarkFlagsMutuallyExclusive("password", "identity")
	cmd.MarkFlagsMutuallyExclusive("host", "ifile", "tag")
	cmd.MarkFlagsMutuallyExclusive("force", "no-clobber")
	return cmd
}

func (o *ScpOptions) Complete(_ *cobra.Command, args []string) {
	o.args = args
	if len(args) == 2 {
		if o.Source == "" {
			o.Source = args[0]
		}
		if o.Dest == "" {
			o.Dest = args[1]
		}
	} else if len(args) == 1 {
		if o.Source == "" {
			o.Source = args[0]
		}
	}
}

func (o *ScpOptions) Validate() error {
	if o.Source == "" {
		return fmt.Errorf("%s", i18n.T("scp_err_no_src"))
	}
	if o.Dest == "" && o.Host == "" && o.Tag == "" {
		return fmt.Errorf("%s", i18n.T("scp_err_no_dest"))
	}
	return nil
}

type PathInfo struct {
	IsRemote bool
	User     string
	Host     string
	Port     uint16
	Path     string
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

	var addrPart, pathPart string
	if openBracket := strings.Index(p, "["); openBracket != -1 {
		closeBracket := strings.Index(p[openBracket:], "]")
		if closeBracket == -1 {
			return PathInfo{}, fmt.Errorf("malformed bracketed address in %q", p)
		}
		afterBracket := openBracket + closeBracket + 1
		rest := p[afterBracket:]
		if strings.HasPrefix(rest, ":") {
			rest = rest[1:]
			if nextColon := strings.Index(rest, ":"); nextColon != -1 {
				portStr := rest[:nextColon]
				if _, err := strconv.ParseUint(portStr, 10, 16); err == nil {
					addrPart = p[:afterBracket] + ":" + portStr
					pathPart = rest[nextColon+1:]
				} else {
					addrPart = p[:afterBracket]
					pathPart = rest
				}
			} else {
				addrPart = p[:afterBracket]
				pathPart = rest
			}
		}
	} else if colonIdx := strings.Index(p, ":"); colonIdx != -1 {
		rest := p[colonIdx+1:]
		if nextColon := strings.Index(rest, ":"); nextColon != -1 {
			portCandidate := rest[:nextColon]
			afterSecondColon := rest[nextColon+1:]
			if strings.HasPrefix(afterSecondColon, "/") || strings.HasPrefix(afterSecondColon, "~") {
				addrPart = p[:colonIdx] + ":" + portCandidate
				pathPart = afterSecondColon
			} else {
				addrPart = p[:colonIdx]
				pathPart = rest
			}
		} else {
			addrPart = p[:colonIdx]
			pathPart = rest
		}
	}

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
	configPath, keyPath, pathErr := cmdutils.GetConfigFilePath()
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
	connector := newCLIConnector(provider, ssh.WithLogger(logger.DefaultLogger()))
	defer func() {
		joinConnectorCloseError(&retErr, connector)
	}()

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

	// 1. 批量上传模式 (-H host1,host2 或 -I hostfile 或 --tag tag)
	if o.Tag != "" || (o.Host != "" && strings.Contains(o.Host, ",")) || o.HostFile != "" {
		return o.runBatch(ctx, provider, connector)
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

	remotePath := dst.Path
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
	var progressErr error
	var progressMu sync.Mutex
	if o.Progress {
		info, err := os.Stat(localPath)
		if err != nil {
			return err
		}
		description := "Uploading " + filepath.Base(localPath)
		bar := progressbar.NewOptions64(
			info.Size(),
			progressbar.OptionSetDescription(description),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionEnableColorCodes(logger.ColorEnabled()),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(30),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionShowCount(),
			progressbar.OptionOnCompletion(func() {
				if _, err := fmt.Fprintln(os.Stderr); err != nil {
					progressMu.Lock()
					progressErr = errors.Join(progressErr, fmt.Errorf("progress completion newline failed: %w", err))
					progressMu.Unlock()
				}
			}),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
		)
		progress = func(n int64) {
			if barErr := bar.Add64(n); barErr != nil {
				progressMu.Lock()
				progressErr = errors.Join(progressErr, barErr)
				progressMu.Unlock()
			}
		}
	}

	uploadErr := sftpCli.Upload(ctx, localPath, remotePath, progress)
	return errors.Join(uploadErr, progressErr)
}

func (o *ScpOptions) runDownload(ctx context.Context, src PathInfo, localPath string, provider config.ConfigProvider, connector *ssh.Connector) (err error) {
	_, sftpCli, err := o.connectSftpForPath(ctx, src, "", provider, connector)
	if err != nil {
		return fmt.Errorf("connect download source failed: %w", err)
	}
	defer joinCloseError(&err, "download SFTP client", sftpCli.Close)

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

	var progress sftp.ProgressCallback
	var progressErr error
	var progressMu sync.Mutex
	if o.Progress {
		description := "Downloading " + filepath.Base(src.Path)
		bar := progressbar.NewOptions64(
			stat.Size(),
			progressbar.OptionSetDescription(description),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionEnableColorCodes(logger.ColorEnabled()),
			progressbar.OptionShowBytes(true),
			progressbar.OptionSetWidth(30),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionShowCount(),
			progressbar.OptionOnCompletion(func() {
				if _, err := fmt.Fprintln(os.Stderr); err != nil {
					progressMu.Lock()
					progressErr = errors.Join(progressErr, fmt.Errorf("progress completion newline failed: %w", err))
					progressMu.Unlock()
				}
			}),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
		)
		progress = func(n int64) {
			if barErr := bar.Add64(n); barErr != nil {
				progressMu.Lock()
				progressErr = errors.Join(progressErr, barErr)
				progressMu.Unlock()
			}
		}
	}

	if stat.IsDir() {
		downloadErr := sftpCli.DownloadDirectory(ctx, src.Path, localPath, progress)
		return errors.Join(downloadErr, progressErr)
	}

	downloadErr := sftpCli.DownloadFile(ctx, src.Path, localDest, stat.Size(), stat.Mode(), progress)
	return errors.Join(downloadErr, progressErr)
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

	// 1. 检查目标文件是否已存在且完全匹配 (用于直接跳过)
	if !o.Force {
		skip, err := o.shouldSkipRemoteToRemote(ctx, dstSftp, dstPath, srcStat)
		if err != nil {
			return err
		}
		if skip {
			return nil
		}
	}

	// 再次检查覆盖标志并询问用户 (如果 shouldSkip 没有跳过且没有 -f)
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

	progress, progressErrs := o.createRemoteToRemoteProgress(srcStat.Size(), srcStat.Name(), startOffset)
	defer func() {
		if pErr := progressErrs.Err(); pErr != nil {
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

func (o *ScpOptions) createRemoteToRemoteProgress(size int64, name string, startOffset int64) (sftp.ProgressCallback, *transferProgressErrors) {
	var progress sftp.ProgressCallback
	errs := &transferProgressErrors{}
	if o.Progress {
		bar := progressbar.DefaultBytes(size, "Relaying "+filepath.Base(name))
		progress = func(n int64) { errs.Add("update progress", bar.Add64(n)) }
		if startOffset > 0 {
			progress(startOffset)
		}
	}
	return progress, errs
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
			_, hostObj, identity, resolveErr := provider.Resolve(nid)
			if resolveErr != nil {
				return fmt.Errorf("resolve tagged scp node %q failed: %w", nid, resolveErr)
			}
			wp.Execute(func() {
				addr := PathInfo{Host: hostObj.Address, User: identity.User, Port: hostObj.Port, IsRemote: true}
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
			// 若主机已映射到已知节点且在排除集合中，则跳过
			if excludes != nil {
				nid, resolveErr := provider.ResolveSelector(h.Host)
				if resolveErr != nil {
					return fmt.Errorf("resolve excluded host %q: %w", h.Host, resolveErr)
				}
				if nid != "" {
					if _, excluded := excludes[nid]; excluded {
						continue
					}
				}
			}

			wp.Execute(func() {
				addr := PathInfo{Host: h.Host, User: h.User, Port: h.Port, IsRemote: true}
				if tErr := o.executeTransfer(ctx, h.Host, addr, h.Password, provider, connector); tErr != nil {
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

func (o *ScpOptions) executeTransfer(ctx context.Context, label string, addr PathInfo, specificPassword string, provider config.ConfigProvider, connector *ssh.Connector) (err error) {
	_, sftpCli, err := o.connectSftpForPath(ctx, addr, specificPassword, provider, connector)
	if err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}
	defer joinCloseError(&err, "batch upload SFTP client", sftpCli.Close)

	remotePath := o.Dest
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
			logger.PrintWarn(i18n.Tf("scp_skip", map[string]any{"Label": label}))
			return nil
		}
	}

	err = sftpCli.Upload(ctx, o.Source, remotePath, nil)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	logger.PrintSuccess(i18n.Tf("scp_done", map[string]any{"Label": label}))
	return nil
}

func joinCloseError(target *error, resource string, closeFn func() error) {
	if closeErr := closeFn(); closeErr != nil {
		*target = errors.Join(*target, fmt.Errorf("close %s failed: %w", resource, closeErr))
	}
}

func (o *ScpOptions) shouldSkipRemoteToRemote(ctx context.Context, dstSftp *sftp.Client, dstPath string, srcStat os.FileInfo) (bool, error) {
	var ds os.FileInfo
	err := dstSftp.Do(ctx, func(c *pkgsftp.Client) error {
		var err error
		ds, err = c.Stat(dstPath)
		return err
	})
	if err == nil {
		if ds.Size() == srcStat.Size() && ds.ModTime().Unix() == srcStat.ModTime().Unix() {
			if o.Progress {
				bar := progressbar.DefaultBytes(srcStat.Size(), "Relaying "+filepath.Base(srcStat.Name()))
				if progressErr := bar.Add64(srcStat.Size()); progressErr != nil {
					return false, fmt.Errorf("complete relay progress failed: %w", progressErr)
				}
			}
			return true, nil
		}

		// 检查标志位和询问用户
		if o.NoOverwrite {
			return true, nil
		}
		if !o.Force {
			confirmed, confirmErr := cmdutils.AskConfirmation(i18n.Tf("prompt_overwrite", map[string]any{"Path": dstPath}))
			if confirmErr != nil {
				return false, confirmErr
			}
			if !confirmed {
				return true, nil
			}
		}
	}
	return false, nil
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

func (o *ScpOptions) connectSftpForPath(ctx context.Context, p PathInfo, specificPassword string, provider config.ConfigProvider, connector *ssh.Connector) (string, *sftp.Client, error) {
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
		sftp.WithThreadsPerFile(o.ThreadCount),
		sftp.WithForce(o.Force),
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
	repo, ok := provider.(*config.Repository)
	if !ok {
		return "", false, fmt.Errorf("provider does not support node mutation")
	}

	target, err := o.resolveTargetForPath(path)
	if err != nil {
		return "", false, err
	}

	password := specificPassword
	if password == "" && o.Password != "" {
		password = o.Password
	}

	res, err := repo.EnsureNodeContext(ctx, config.EnsureNodeOptions{
		Target:       target,
		Password:     password,
		IdentityFile: o.IdentityFile,
		Passphrase:   o.Passphrase,
		Alias:        o.Alias,
	})
	if err != nil {
		return "", false, err
	}

	if res.Created {
		return res.NodeID, true, nil
	}

	updated, updateErr := o.updateNode(ctx, res.NodeID, provider, specificPassword)
	return res.NodeID, updated, updateErr
}

func (o *ScpOptions) updateNode(ctx context.Context, nodeID string, provider config.ConfigProvider, specificPassword string) (bool, error) {
	node, host, identity, err := provider.Resolve(nodeID)
	if err != nil {
		return false, fmt.Errorf("resolve scp node %q for update failed: %w", nodeID, err)
	}
	updated := false

	password := specificPassword
	if password == "" && o.Password != "" {
		password = o.Password
	}

	if password != "" {
		if identity.Password != password || identity.AuthType != "password" {
			identity.Password = password
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

	if o.Passphrase != "" {
		if identity.Passphrase != o.Passphrase {
			identity.Passphrase = o.Passphrase
			updated = true
		}
	}

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
