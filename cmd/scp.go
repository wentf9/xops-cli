package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	pkgsftp "github.com/pkg/sftp"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	cmdutils "github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
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
			return o.Run()
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

func parsePath(p string) PathInfo {
	if strings.Contains(p, ":") {
		// 检查是否是 Windows 盘符
		if len(p) >= 2 && p[1] == ':' && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) {
			// 如果冒号后面没有其他冒号，认为是本地路径
			if !strings.Contains(p[2:], ":") {
				return PathInfo{IsRemote: false, Path: p}
			}
		}

		parts := strings.SplitN(p, ":", 2)
		addr := parts[0]
		path := parts[1]
		u, h, port := cmdutils.ParseAddr(addr)
		return PathInfo{
			IsRemote: true,
			User:     u,
			Host:     h,
			Port:     port,
			Path:     path,
		}
	}
	return PathInfo{IsRemote: false, Path: p}
}

func (o *ScpOptions) Run() error {
	configPath, keyPath := cmdutils.GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("config_load_error"), err)
	}
	provider := config.NewProvider(cfg)
	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	src := parsePath(o.Source)
	var dst PathInfo
	if o.Dest != "" {
		dst = parsePath(o.Dest)
	}

	ctx := context.Background()

	// 1. 批量上传模式 (-H host1,host2 或 -I hostfile 或 --tag tag)
	if o.Tag != "" || (o.Host != "" && strings.Contains(o.Host, ",")) || o.HostFile != "" {
		return o.runBatch(ctx, provider, connector, configStore, cfg)
	}

	// 2. 远程到远程
	if src.IsRemote && dst.IsRemote {
		return o.runRemoteToRemote(ctx, src, dst, provider, connector, configStore, cfg)
	}

	// 3. 单主机上传/下载
	if src.IsRemote {
		return o.runDownload(ctx, src, o.Dest, provider, connector, configStore, cfg)
	} else if dst.IsRemote {
		return o.runUpload(ctx, o.Source, dst, provider, connector, configStore, cfg)
	}

	return fmt.Errorf("%s", i18n.T("scp_err_both_local"))
}

func (o *ScpOptions) runUpload(ctx context.Context, localPath string, dst PathInfo, provider config.ConfigProvider, connector *ssh.Connector, configStore config.Store, cfg *config.Configuration) error {
	_, sftpCli, err := o.connectSftpForPath(ctx, dst, "", provider, connector, configStore, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = sftpCli.Close() }()

	remotePath := dst.Path
	remoteStat, err := sftpCli.SFTPClient().Stat(remotePath)
	if err == nil && remoteStat.IsDir() {
		remotePath = sftpCli.JoinPath(remotePath, filepath.Base(localPath))
	}

	// 检查是否已存在
	if _, err := sftpCli.SFTPClient().Stat(remotePath); err == nil {
		if o.NoOverwrite {
			return nil
		}
		if !o.Force {
			if !cmdutils.AskConfirmation(i18n.Tf("prompt_overwrite", map[string]any{"Path": remotePath})) {
				return nil
			}
			o.Force = true // 用户确认后开启强制覆盖
			sftpCli.SetForce(true)
		}
	}

	var progress sftp.ProgressCallback
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
				fmt.Fprint(os.Stderr, "\n")
			}),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
		)
		progress = func(n int64) { _ = bar.Add64(n) }
	}

	return sftpCli.Upload(ctx, localPath, remotePath, progress)
}

func (o *ScpOptions) runDownload(ctx context.Context, src PathInfo, localPath string, provider config.ConfigProvider, connector *ssh.Connector, configStore config.Store, cfg *config.Configuration) error {
	_, sftpCli, err := o.connectSftpForPath(ctx, src, "", provider, connector, configStore, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = sftpCli.Close() }()

	// 只 Stat 一次
	stat, err := sftpCli.SFTPClient().Stat(src.Path)
	if err != nil {
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
			if !cmdutils.AskConfirmation(i18n.Tf("prompt_overwrite", map[string]any{"Path": localDest})) {
				return nil
			}
			o.Force = true // 用户确认后开启强制覆盖
			sftpCli.SetForce(true)
		}
	}

	var progress sftp.ProgressCallback
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
				fmt.Fprint(os.Stderr, "\n")
			}),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "=",
				SaucerHead:    ">",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
		)
		progress = func(n int64) { _ = bar.Add64(n) }
	}

	if stat.IsDir() {
		return sftpCli.DownloadDirectory(ctx, src.Path, localPath, progress)
	}

	return sftpCli.DownloadFile(ctx, src.Path, localDest, stat.Size(), stat.Mode(), progress)
}

func (o *ScpOptions) runRemoteToRemote(ctx context.Context, src, dst PathInfo, provider config.ConfigProvider, connector *ssh.Connector, configStore config.Store, cfg *config.Configuration) error {
	_, srcSftp, err := o.connectSftpForPath(ctx, src, "", provider, connector, configStore, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = srcSftp.Close() }()

	_, dstSftp, err := o.connectSftpForPath(ctx, dst, "", provider, connector, configStore, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = dstSftp.Close() }()

	srcFile, err := srcSftp.SFTPClient().Open(src.Path)
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()

	srcStat, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstPath := dst.Path
	dstStat, err := dstSftp.SFTPClient().Stat(dstPath)
	if err == nil && dstStat.IsDir() {
		dstPath = dstSftp.JoinPath(dstPath, filepath.Base(src.Path))
	}

	// 1. 检查目标文件是否已存在且完全匹配 (用于直接跳过)
	if !o.Force {
		skip, err := o.shouldSkipRemoteToRemote(dstSftp, dstPath, srcStat)
		if err != nil {
			return err
		}
		if skip {
			return nil
		}
	}

	// 再次检查覆盖标志并询问用户 (如果 shouldSkip 没有跳过且没有 -f)
	if err := o.confirmRemoteToRemoteOverwrite(dstSftp, dstPath); err != nil {
		if err.Error() == "skipped" {
			return nil
		}
		return err
	}

	// 2. 使用临时文件进行传输
	tempPath := dstPath + dstSftp.Config().TempSuffix
	startOffset, dstFile, err := o.prepareRemoteToRemoteFile(dstSftp, tempPath, srcStat.Size())
	if err != nil {
		return err
	}

	progress := o.createRemoteToRemoteProgress(srcStat.Size(), srcStat.Name(), startOffset)

	if err := o.doRemoteToRemote(srcFile, dstFile, startOffset, srcStat.Size(), dstSftp, progress); err != nil {
		return err
	}

	// 3. 传输完成：同步修改时间并重命名
	_ = dstSftp.SFTPClient().Chtimes(tempPath, srcStat.ModTime(), srcStat.ModTime())
	_ = dstSftp.SFTPClient().Remove(dstPath)
	return dstSftp.SFTPClient().Rename(tempPath, dstPath)
}

func (o *ScpOptions) confirmRemoteToRemoteOverwrite(dstSftp *sftp.Client, dstPath string) error {
	if !o.Force {
		if _, err := dstSftp.SFTPClient().Stat(dstPath); err == nil {
			if o.NoOverwrite {
				return fmt.Errorf("skipped") // handled by caller as nil if we change logic
			}
			if !cmdutils.AskConfirmation(i18n.Tf("prompt_overwrite", map[string]any{"Path": dstPath})) {
				return fmt.Errorf("skipped")
			}
			o.Force = true
			dstSftp.SetForce(true)
		}
	}
	return nil
}

func (o *ScpOptions) createRemoteToRemoteProgress(size int64, name string, startOffset int64) sftp.ProgressCallback {
	var progress sftp.ProgressCallback
	if o.Progress {
		bar := progressbar.DefaultBytes(size, "Relaying "+filepath.Base(name))
		progress = func(n int64) { _ = bar.Add64(n) }
		if startOffset > 0 {
			progress(startOffset)
		}
	}
	return progress
}

func (o *ScpOptions) doRemoteToRemote(srcFile *pkgsftp.File, dstFile *pkgsftp.File, startOffset, size int64, dstSftp *sftp.Client, progress sftp.ProgressCallback) error {
	if startOffset < size {
		if startOffset > 0 {
			if _, err := srcFile.Seek(startOffset, io.SeekStart); err != nil {
				return err
			}
		}
		if dstFile != nil {
			defer func() { _ = dstFile.Close() }()
			err := dstSftp.StreamTransfer(srcFile, dstFile, progress)
			if err != nil {
				return err
			}
			_ = dstFile.Close()
		}
	}
	return nil
}

func (o *ScpOptions) runBatch(ctx context.Context, provider config.ConfigProvider, connector *ssh.Connector, configStore config.Store, cfg *config.Configuration) error {
	wp := pkgutils.NewWorkerPool(uint(o.TaskCount))

	if o.Tag != "" {
		nodes := provider.GetNodesByTag(o.Tag)
		if len(nodes) == 0 {
			return fmt.Errorf("%s", i18n.Tf("err_tag_empty", map[string]any{"Tag": o.Tag}))
		}
		for nodeID := range nodes {
			nid := nodeID // capture
			hostObj, _ := provider.GetHost(nid)
			identity, _ := provider.GetIdentity(nid)
			wp.Execute(func() {
				addr := PathInfo{Host: hostObj.Address, User: identity.User, Port: hostObj.Port, IsRemote: true}
				o.executeTransfer(ctx, nid, addr, identity.Password, provider, connector, configStore, cfg)
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
			wp.Execute(func() {
				addr := PathInfo{Host: h.Host, User: h.User, Port: h.Port, IsRemote: true}
				o.executeTransfer(ctx, h.Host, addr, h.Password, provider, connector, configStore, cfg)
			})
		}
	}

	wp.Wait()
	return nil
}

func (o *ScpOptions) executeTransfer(ctx context.Context, label string, addr PathInfo, specificPassword string, provider config.ConfigProvider, connector *ssh.Connector, configStore config.Store, cfg *config.Configuration) {
	_, sftpCli, err := o.connectSftpForPath(ctx, addr, specificPassword, provider, connector, configStore, cfg)
	if err != nil {
		logger.PrintError(i18n.Tf("scp_error", map[string]any{"Label": label, "Error": err}))
		return
	}
	defer func() { _ = sftpCli.Close() }()

	remotePath := o.Dest
	remoteStat, err := sftpCli.SFTPClient().Stat(remotePath)
	if err == nil && remoteStat.IsDir() {
		remotePath = sftpCli.JoinPath(remotePath, filepath.Base(o.Source))
	}

	if _, err := sftpCli.SFTPClient().Stat(remotePath); err == nil {
		if o.NoOverwrite || !o.Force {
			logger.PrintWarn(i18n.Tf("scp_skip", map[string]any{"Label": label}))
			return
		}
	}

	err = sftpCli.Upload(ctx, o.Source, remotePath, nil)
	if err != nil {
		logger.PrintError(i18n.Tf("scp_transfer_failed", map[string]any{"Label": label, "Error": err}))
	} else {
		logger.PrintSuccess(i18n.Tf("scp_done", map[string]any{"Label": label}))
	}
}

func (o *ScpOptions) shouldSkipRemoteToRemote(dstSftp *sftp.Client, dstPath string, srcStat os.FileInfo) (bool, error) {
	if ds, err := dstSftp.SFTPClient().Stat(dstPath); err == nil {
		if ds.Size() == srcStat.Size() && ds.ModTime().Unix() == srcStat.ModTime().Unix() {
			if o.Progress {
				bar := progressbar.DefaultBytes(srcStat.Size(), "Relaying "+filepath.Base(srcStat.Name()))
				_ = bar.Add64(srcStat.Size())
			}
			return true, nil
		}

		// 检查标志位和询问用户
		if o.NoOverwrite {
			return true, nil
		}
		if !o.Force {
			if !cmdutils.AskConfirmation(i18n.Tf("prompt_overwrite", map[string]any{"Path": dstPath})) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (o *ScpOptions) prepareRemoteToRemoteFile(dstSftp *sftp.Client, tempPath string, srcSize int64) (int64, *pkgsftp.File, error) {
	var startOffset int64
	var dstFile *pkgsftp.File
	var err error

	if dstSftp.Config().EnableResume {
		if ts, err := dstSftp.SFTPClient().Stat(tempPath); err == nil {
			if ts.Size() < srcSize {
				startOffset = ts.Size()
				dstFile, err = dstSftp.SFTPClient().OpenFile(tempPath, os.O_RDWR)
				if err != nil {
					return 0, nil, err
				}
			} else if ts.Size() == srcSize {
				startOffset = srcSize
			}
		}
	}

	if dstFile == nil && startOffset < srcSize {
		dstFile, err = dstSftp.SFTPClient().Create(tempPath)
		if err != nil {
			return 0, nil, err
		}
	}
	return startOffset, dstFile, nil
}

func (o *ScpOptions) connectSftpForPath(ctx context.Context, p PathInfo, specificPassword string, provider config.ConfigProvider, connector *ssh.Connector, configStore config.Store, cfg *config.Configuration) (string, *sftp.Client, error) {
	nodeId, updated, err := o.getOrCreateNodeForPath(provider, p, specificPassword)
	if err != nil {
		return "", nil, err
	}
	if updated {
		if err := configStore.Save(cfg); err != nil {
			logger.PrintError(i18n.Tf("save_config_failed", map[string]any{"Error": err}))
		}
	}
	idBefore, _ := provider.GetIdentity(nodeId)
	client, err := connector.Connect(ctx, nodeId)
	if err != nil {
		return "", nil, err
	}
	if idAfter, _ := provider.GetIdentity(nodeId); idBefore.Password != idAfter.Password || idBefore.Passphrase != idAfter.Passphrase {
		if err := configStore.Save(cfg); err != nil {
			logger.PrintError(i18n.Tf("save_config_failed", map[string]any{"Error": err}))
		}
	}
	sftpCli, err := sftp.NewClient(
		client,
		sftp.WithThreadsPerFile(o.ThreadCount),
		sftp.WithForce(o.Force),
		sftp.WithNoOverwrite(o.NoOverwrite),
	)
	if err != nil {
		return "", nil, err
	}
	return nodeId, sftpCli, nil
}

func (o *ScpOptions) resolvePathInfo(path PathInfo) (string, string, uint16, error) {
	host := path.Host
	user := path.User
	port := path.Port

	if host == "" && o.Host != "" && !strings.Contains(o.Host, ",") {
		host = o.Host
	}
	if user == "" && o.User != "" {
		user = o.User
	}
	if port == 0 && o.Port != 0 {
		port = o.Port
	}

	if host == "" {
		return "", "", 0, fmt.Errorf("%s", i18n.T("scp_err_no_host_addr"))
	}
	if user == "" {
		user = cmdutils.GetCurrentUser()
	}
	if port == 0 {
		port = 22
	}

	return strings.TrimSpace(host), strings.TrimSpace(user), port, nil
}

func (o *ScpOptions) getOrCreateNodeForPath(provider config.ConfigProvider, path PathInfo, specificPassword string) (string, bool, error) {
	host, user, port, err := o.resolvePathInfo(path)
	if err != nil {
		return "", false, err
	}

	nodeID := provider.Find(host)
	if nodeID == "" {
		nodeID = provider.Find(fmt.Sprintf("%s@%s:%d", user, host, port))
	}

	if nodeID != "" {
		updated := o.updateNode(nodeID, provider, specificPassword)
		return nodeID, updated, nil
	}

	return o.createNewNode(provider, host, user, port, specificPassword)
}

func (o *ScpOptions) createNewNode(provider config.ConfigProvider, host, user string, port uint16, specificPassword string) (string, bool, error) {
	nodeID := fmt.Sprintf("%s@%s:%d", user, host, port)
	node := models.Node{
		HostRef:     fmt.Sprintf("%s:%d", host, port),
		IdentityRef: fmt.Sprintf("%s@%s", user, host),
		ProxyJump:   o.JumpHost,
		SudoMode:    models.SudoModeAuto,
	}

	if node.ProxyJump != "" {
		jumpHost := provider.Find(node.ProxyJump)
		if jumpHost == "" {
			return "", false, fmt.Errorf("%s", i18n.Tf("err_proxy_not_found", map[string]any{"Proxy": node.ProxyJump}))
		}
		node.ProxyJump = jumpHost
	}

	if o.Alias != "" {
		// 检查别名是否已存在
		if existingNode := provider.FindAlias(o.Alias); existingNode != "" {
			return "", false, fmt.Errorf("%s", i18n.Tf("alias_err_exists", map[string]any{"Alias": o.Alias, "Node": existingNode}))
		}
		node.Alias = append(node.Alias, strings.TrimSpace(o.Alias))
	}

	identity := models.Identity{
		User: user,
	}

	password := specificPassword
	if password == "" && o.Password != "" {
		password = o.Password
	}

	if password == "" && o.IdentityFile == "" {
		identity.AuthType = "auto"
	} else if password != "" {
		identity.Password = password
		identity.AuthType = "password"
	} else if o.IdentityFile != "" {
		identity.KeyPath = cmdutils.ToAbsolutePath(o.IdentityFile)
		identity.Passphrase = o.Passphrase
		identity.AuthType = "key"
	}

	provider.AddHost(node.HostRef, models.Host{Address: host, Port: port})
	provider.AddIdentity(node.IdentityRef, identity)
	provider.AddNode(nodeID, node)

	return nodeID, true, nil
}

func (o *ScpOptions) updateNode(nodeID string, provider config.ConfigProvider, specificPassword string) bool {
	node, _ := provider.GetNode(nodeID)
	identity, _ := provider.GetIdentity(nodeID)
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

	if updated {
		provider.AddIdentity(node.IdentityRef, identity)
	}

	return updated
}
