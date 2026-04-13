package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
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
	args           []string
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
			return o.Run()
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
}

func (o *SshOptions) Validate() error {
	if len(o.args) > 1 {
		return errors.New(i18n.Tf("ssh_err_expected_one_arg", map[string]any{"Count": len(o.args)}))
	}
	if len(o.args) == 0 && o.Host == "" {
		return errors.New(i18n.T("ssh_err_no_host"))
	} else if len(o.args) == 1 {
		u, h, p := utils.ParseAddr(o.args[0])
		if h == "" && o.Host == "" {
			return errors.New(i18n.T("ssh_err_invalid_host"))
		}
		if o.Host == "" {
			o.Host = h
		}
		if o.User == "" {
			o.User = u
		}
		if o.Port == 0 {
			o.Port = p
		}
	}
	if o.User == "" {
		o.User = utils.GetCurrentUser()
	}
	if o.Port == 0 {
		o.Port = 22
	}
	if strings.Contains(o.Alias, "@") || strings.Contains(o.Alias, ":") {
		return errors.New(i18n.T("ssh_err_alias_invalid"))
	}
	return nil
}

func (o *SshOptions) Run() error {
	configStore := config.NewDefaultStore(utils.GetConfigFilePath())
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ssh_err_load_config"), err)
	}

	provider := config.NewProvider(cfg)

	nodeID, updated, err := o.resolveNode(provider)
	if err != nil {
		return err
	}
	connector := ssh.NewConnector(provider)
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 10*time.Second)
	idBefore, _ := provider.GetIdentity(nodeID)
	client, err := connector.Connect(connectCtx, nodeID)
	connectCancel()
	if err != nil {
		fmt.Printf("\n%s: %v\n", i18n.T("fw_connect_failed"), err)
		fmt.Println(i18n.T("tui_press_enter"))
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		return fmt.Errorf("%s: %w", i18n.T("fw_connect_failed"), err)
	}
	defer func() { _ = client.Close() }()
	// connector.Connect 可能通过交互式回调获取到新密码并写入提供者，我们需要标记更新以便保存
	if idAfter, _ := provider.GetIdentity(nodeID); idBefore.Password != idAfter.Password || idBefore.Passphrase != idAfter.Passphrase {
		updated = true
	}
	if updated {
		if err := configStore.Save(cfg); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ssh_err_save_config"), err)
		}
	}

	// Setup background context for tunnels and execution (runs until SigInt or command exit)
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	if err := o.startTunnels(runCtx, client); err != nil {
		return err
	}

	if o.NoCmd {
		fmt.Printf("SSH tunnels established to %s. Press Ctrl+C to exit.\n", nodeID)
		<-runCtx.Done()
		return nil
	}

	if o.Sudo {
		if err := client.ShellWithSudo(runCtx); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("sudo_exec_failed"), err)
		}
	} else {
		if err := client.Shell(runCtx); err != nil {
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

func (o *SshOptions) resolveNode(provider config.ConfigProvider) (string, bool, error) {
	if nodeID := provider.Find(o.Host); nodeID != "" {
		return nodeID, update(nodeID, o, provider), nil
	}
	if nodeID := provider.Find(fmt.Sprintf("%s@%s:%d", o.User, o.Host, o.Port)); nodeID != "" {
		return nodeID, update(nodeID, o, provider), nil
	}
	nodeID, err := o.createNewNode(provider)
	return nodeID, true, err
}

func (o *SshOptions) startTunnels(ctx context.Context, client *ssh.Client) error {
	for _, lArg := range o.LocalForwards {
		bAddr, dAddr, err := parseForwardArg(lArg)
		if err != nil {
			return err
		}
		if err := client.LocalForward(ctx, bAddr, dAddr); err != nil {
			return fmt.Errorf("failed to setup local forward: %w", err)
		}
	}
	for _, rArg := range o.RemoteForwards {
		bAddr, dAddr, err := parseForwardArg(rArg)
		if err != nil {
			return err
		}
		if err := client.RemoteForward(ctx, bAddr, dAddr); err != nil {
			return fmt.Errorf("failed to setup remote forward: %w", err)
		}
	}
	return nil
}

func updateNodeFields(node *models.Node, nodeID string, o *SshOptions, provider config.ConfigProvider) bool {
	nodeUpdated := false
	if o.JumpHost != "" {
		jumpHost := provider.Find(o.JumpHost)
		if jumpHost != "" && jumpHost != node.ProxyJump {
			node.ProxyJump = jumpHost
			nodeUpdated = true
		}
	}
	if o.Sudo {
		node.SudoMode = models.SudoModeSudo
		nodeUpdated = true
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
	return nodeUpdated
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

func (o *SshOptions) createNewNode(provider config.ConfigProvider) (string, error) {
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
			return "", errors.New(i18n.Tf("ssh_err_jump_not_found", map[string]any{"Host": node.ProxyJump}))
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

func update(nodeID string, o *SshOptions, provider config.ConfigProvider) bool {
	if o.Password == "" && o.IdentityFile == "" && o.JumpHost == "" && !o.Sudo && o.Alias == "" && len(o.Tags) == 0 {
		return false
	}
	node, _ := provider.GetNode(nodeID)
	identity, _ := provider.GetIdentity(nodeID)

	nodeUpdated := updateNodeFields(&node, nodeID, o, provider)
	identityUpdated := updateIdentityFields(&identity, o)

	if nodeUpdated {
		provider.AddNode(nodeID, node)
	}
	if identityUpdated {
		provider.AddIdentity(node.IdentityRef, identity)
	}
	return nodeUpdated || identityUpdated
}
