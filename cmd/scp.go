package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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

	cmd.Flags().StringVarP(&o.Host, "host", "H", "", i18n.T("flag_hosts"))
	cmd.Flags().Uint16VarP(&o.Port, "port", "p", 0, i18n.T("flag_port"))
	cmd.Flags().StringVarP(&o.User, "user", "u", "", i18n.T("flag_user"))
	cmd.Flags().StringVarP(&o.Password, "password", "P", "", i18n.T("flag_password"))
	cmd.Flags().StringVarP(&o.KeyFile, "key", "i", "", i18n.T("flag_key"))
	cmd.Flags().StringVarP(&o.KeyPass, "key_pass", "w", "", i18n.T("flag_key_pass"))
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "j", "", i18n.T("flag_jump"))
	cmd.Flags().StringVarP(&o.Alias, "alias", "a", "", i18n.T("flag_alias"))

	cmd.Flags().StringVar(&o.Source, "src", "", i18n.T("flag_scp_src"))
	cmd.Flags().StringVar(&o.Dest, "dest", "", i18n.T("flag_scp_dest"))
	cmd.Flags().StringVarP(&o.HostFile, "ifile", "I", "", i18n.T("flag_ifile"))
	cmd.Flags().StringVarP(&o.Tag, "tag", "t", "", i18n.T("flag_scp_tag"))
	cmd.Flags().BoolVarP(&o.Recursive, "recursive", "r", false, i18n.T("flag_recursive"))
	cmd.Flags().BoolVarP(&o.Progress, "progress", "v", false, i18n.T("flag_progress"))
	cmd.Flags().BoolVarP(&o.Force, "force", "f", false, i18n.T("flag_force"))
	cmd.Flags().IntVar(&o.TaskCount, "task", 3, i18n.T("flag_task"))
	cmd.Flags().IntVar(&o.ThreadCount, "thread", 4, i18n.T("flag_thread"))

	cmd.MarkFlagsMutuallyExclusive("password", "key")
	cmd.MarkFlagsMutuallyExclusive("host", "ifile", "tag")
	return cmd
}

func (o *ScpOptions) Complete(cmd *cobra.Command, args []string) {
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
		progress = func(n int) { _ = bar.Add(n) }
	}

	return sftpCli.Upload(ctx, localPath, dst.Path, progress)
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
		progress = func(n int) { _ = bar.Add(n) }
	}

	if stat.IsDir() {
		return sftpCli.DownloadDirectory(ctx, src.Path, localPath, progress)
	}

	// 处理本地路径是目录的情况
	localDest := localPath
	if lStat, err := os.Stat(localPath); err == nil && lStat.IsDir() {
		localDest = filepath.Join(localPath, stat.Name())
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

	stat, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstPath := dst.Path
	dstStat, err := dstSftp.SFTPClient().Stat(dstPath)
	if err == nil && dstStat.IsDir() {
		dstPath = dstSftp.JoinPath(dstPath, filepath.Base(src.Path))
	}

	dstFile, err := dstSftp.SFTPClient().Create(dstPath)
	if err != nil {
		return err
	}
	defer func() { _ = dstFile.Close() }()

	var progress sftp.ProgressCallback
	if o.Progress {
		bar := progressbar.DefaultBytes(stat.Size(), "Relaying "+filepath.Base(src.Path))
		progress = func(n int) { _ = bar.Add(n) }
	}

	return dstSftp.StreamTransfer(srcFile, dstFile, progress)
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

	err = sftpCli.Upload(ctx, o.Source, o.Dest, nil)
	if err != nil {
		logger.PrintError(i18n.Tf("scp_transfer_failed", map[string]any{"Label": label, "Error": err}))
	} else {
		logger.PrintSuccess(i18n.Tf("scp_done", map[string]any{"Label": label}))
	}
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
	if idAfter, _ := provider.GetIdentity(nodeId); idBefore.Password != idAfter.Password {
		if err := configStore.Save(cfg); err != nil {
			logger.PrintError(i18n.Tf("save_config_failed", map[string]any{"Error": err}))
		}
	}
	sftpCli, err := sftp.NewClient(client, sftp.WithThreadsPerFile(o.ThreadCount))
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

	if password == "" && o.KeyFile == "" {
		identity.AuthType = "auto"
	} else if password != "" {
		identity.Password = password
		identity.AuthType = "password"
	} else if o.KeyFile != "" {
		identity.KeyPath = cmdutils.ToAbsolutePath(o.KeyFile)
		identity.Passphrase = o.KeyPass
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
	} else if o.KeyFile != "" {
		absKeyPath := cmdutils.ToAbsolutePath(o.KeyFile)
		if identity.KeyPath != absKeyPath || identity.AuthType != "key" {
			identity.KeyPath = absKeyPath
			identity.AuthType = "key"
			updated = true
		}
	}

	if o.KeyPass != "" {
		if identity.Passphrase != o.KeyPass {
			identity.Passphrase = o.KeyPass
			updated = true
		}
	}

	if updated {
		provider.AddIdentity(node.IdentityRef, identity)
	}

	return updated
}
