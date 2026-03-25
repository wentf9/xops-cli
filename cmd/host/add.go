package host

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
)

func NewCmdInventoryAdd() *cobra.Command {
	var (
		address       string
		port          uint16
		user          string
		password      string
		keyPath       string
		keyPass       string
		identityAlias string
		alias         []string
		tags          []string
		jump          string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: i18n.T("inventory_add_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if address == "" {
				return fmt.Errorf("必须指定主机地址 (--address)")
			}

			store, provider, cfg, err := utils.GetConfigStore()
			if err != nil {
				return fmt.Errorf("加载配置文件失败: %w", err)
			}

			if port == 0 {
				port = 22
			}

			var identity models.Identity
			var identityRef string

			if identityAlias != "" {
				var ok bool
				identity, ok = cfg.Identities.Get(identityAlias)
				if !ok {
					return fmt.Errorf("认证模板 %s 不存在", identityAlias)
				}
				identityRef = identityAlias
			} else {
				if user == "" {
					user = utils.GetCurrentUser()
				}
				identity = models.Identity{User: user}
				if keyPath != "" {
					identity.KeyPath, identity.Passphrase, identity.AuthType = utils.ToAbsolutePath(keyPath), keyPass, "key"
				} else if password != "" {
					identity.Password, identity.AuthType = password, "password"
				} else {
					pass, err := utils.ReadPasswordFromTerminal(i18n.Tf("prompt_enter_user_password", map[string]any{"User": user}))
					if err != nil {
						return err
					}
					identity.Password, identity.AuthType = pass, "password"
				}
				identityRef = fmt.Sprintf("id-%s@%s:%d", identity.User, address, port)
			}

			name := fmt.Sprintf("%s@%s:%d", identity.User, address, port)
			if _, ok := provider.GetNode(name); ok {
				return fmt.Errorf("节点 %s 已存在", name)
			}

			// 检查别名是否已存在
			for _, a := range alias {
				if existingNode := provider.FindAlias(a); existingNode != "" {
					return fmt.Errorf("%s", i18n.Tf("alias_err_exists", map[string]any{"Alias": a, "Node": existingNode}))
				}
			}

			hostObj := models.Host{Address: address, Port: port}
			node := models.Node{
				HostRef:     fmt.Sprintf("host-%s:%d", address, port),
				IdentityRef: identityRef,
				Alias:       alias,
				Tags:        tags,
				ProxyJump:   jump,
				SudoMode:    models.SudoModeAuto,
			}

			if identityAlias == "" {
				provider.AddIdentity(identityRef, identity)
			}
			provider.AddHost(node.HostRef, hostObj)
			provider.AddNode(name, node)

			if err := store.Save(cfg); err != nil {
				return fmt.Errorf("保存配置文件失败: %w", err)
			}

			logger.PrintSuccess(i18n.Tf("node_add_success", map[string]any{"Name": name}))
			return nil
		},
	}

	cmd.Flags().StringVarP(&address, "address", "H", "", i18n.T("flag_inv_address"))
	cmd.Flags().Uint16VarP(&port, "port", "p", 22, i18n.T("flag_inv_port"))
	cmd.Flags().StringVarP(&user, "user", "u", "", i18n.T("flag_inv_user"))
	cmd.Flags().StringVarP(&password, "password", "P", "", i18n.T("flag_inv_password"))
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", i18n.T("flag_inv_key"))
	cmd.Flags().StringVarP(&keyPass, "key-pass", "w", "", i18n.T("flag_inv_key_pass"))
	cmd.Flags().StringVarP(&identityAlias, "identity", "I", "", i18n.T("flag_inv_identity"))
	cmd.Flags().StringSliceVarP(&alias, "alias", "a", []string{}, i18n.T("flag_inv_alias"))
	cmd.Flags().StringSliceVarP(&tags, "tags", "t", []string{}, i18n.T("flag_inv_tags"))
	cmd.Flags().StringVarP(&jump, "jump", "j", "", i18n.T("flag_inv_jump"))

	return cmd
}
