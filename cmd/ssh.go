package cmd

import (
	"context"
	"errors"
	"fmt"
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
	Host     string
	Port     uint16
	User     string
	Password string
	KeyFile  string
	KeyPass  string
	Sudo     bool
	Alias    string
	JumpHost string
	Tags     []string
	args     []string
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
	cmd.Flags().StringVarP(&o.Host, "host", "H", "", i18n.T("flag_host"))
	cmd.Flags().Uint16VarP(&o.Port, "port", "p", 0, i18n.T("flag_port"))
	cmd.Flags().StringVarP(&o.User, "user", "u", "", i18n.T("flag_user"))
	cmd.Flags().StringVarP(&o.Password, "password", "P", "", i18n.T("flag_password"))
	cmd.Flags().StringVarP(&o.KeyFile, "key", "i", "", i18n.T("flag_key"))
	cmd.Flags().StringVarP(&o.KeyPass, "key_pass", "w", "", i18n.T("flag_key_pass"))
	cmd.Flags().BoolVarP(&o.Sudo, "sudo", "s", false, i18n.T("flag_sudo"))
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "j", "", i18n.T("flag_jump"))
	cmd.Flags().StringVarP(&o.Alias, "alias", "a", "", i18n.T("flag_alias"))
	cmd.Flags().StringSliceVarP(&o.Tags, "tag", "t", []string{}, i18n.T("flag_tag"))
	cmd.MarkFlagsMutuallyExclusive("password", "key")
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

	var nodeID string
	updated := false
	if nodeID = provider.Find(o.Host); nodeID != "" {
		updated = update(nodeID, o, provider)
	} else if nodeID = provider.Find(fmt.Sprintf("%s@%s:%d", o.User, o.Host, o.Port)); nodeID != "" {
		updated = update(nodeID, o, provider)
	} else {
		updated = true
		nodeID, err = o.createNewNode(provider)
		if err != nil {
			return err
		}
	}
	connector := ssh.NewConnector(provider)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		fmt.Printf("\n%s: %v\n", i18n.T("fw_connect_failed"), err)
		fmt.Println(i18n.T("tui_press_enter"))
		var b [1]byte
		_, _ = os.Stdin.Read(b[:])
		return fmt.Errorf("%s: %w", i18n.T("fw_connect_failed"), err)
	}
	defer func() { _ = client.Close() }()
	if o.Sudo {
		if err := client.ShellWithSudo(ctx); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("sudo_exec_failed"), err)
		}
	} else {
		if err := client.Shell(ctx); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ssh_err_shell"), err)
		}
	}
	if updated {
		if err := configStore.Save(cfg); err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ssh_err_save_config"), err)
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
	} else if o.KeyFile != "" {
		identity.KeyPath = utils.ToAbsolutePath(o.KeyFile)
		identity.AuthType = "key"
		identityUpdated = true
	}
	if o.KeyPass != "" {
		identity.Passphrase = o.KeyPass
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
	if o.Password == "" && o.KeyFile == "" {
		pass, err := utils.ReadPasswordFromTerminal(i18n.T("prompt_enter_password"))
		if err != nil {
			return "", err
		}
		identity.Password = pass
		identity.AuthType = "password"
	} else if o.Password != "" {
		identity.Password = o.Password
		identity.AuthType = "password"
	} else if o.KeyFile != "" {
		identity.KeyPath = utils.ToAbsolutePath(o.KeyFile)
		identity.Passphrase = o.KeyPass
		identity.AuthType = "key"
	}
	provider.AddHost(node.HostRef, hostObj)
	provider.AddIdentity(node.IdentityRef, identity)
	provider.AddNode(nodeID, node)
	return nodeID, nil
}

func update(nodeID string, o *SshOptions, provider config.ConfigProvider) bool {
	if o.Password == "" && o.KeyFile == "" && o.JumpHost == "" && !o.Sudo && o.Alias == "" && len(o.Tags) == 0 {
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
