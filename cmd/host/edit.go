package host

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
)

type editFlags struct {
	address, user, password, keyPath, keyPass, jump string
	port                                            uint16
	alias                                           []string
}

func NewCmdInventoryEdit() *cobra.Command {
	flags := &editFlags{}

	cmd := &cobra.Command{
		Use:   "edit [node_id]",
		Short: i18n.T("inventory_edit_short"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := args[0]
			store, provider, cfg, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			oldName := provider.Find(query)
			if oldName == "" {
				return fmt.Errorf("节点 %s 不存在", query)
			}

			node, _ := provider.GetNode(oldName)

			host, _ := provider.GetHost(oldName)
			identity, _ := provider.GetIdentity(oldName)

			updated, nameChanged := applyNodeUpdates(cmd, provider, oldName, &host, &identity, &node, flags)

			if updated {
				newName := oldName
				if nameChanged {
					newName = fmt.Sprintf("%s@%s:%d", identity.User, host.Address, host.Port)
					if newName != oldName {
						if _, exists := provider.GetNode(newName); exists {
							return fmt.Errorf("修改后的节点名称 %s 已存在", newName)
						}
						provider.DeleteNode(oldName)
					}
				}
				provider.AddHost(node.HostRef, host)
				provider.AddIdentity(node.IdentityRef, identity)
				provider.AddNode(newName, node)
				if err := store.Save(cfg); err != nil {
					return err
				}
				logger.PrintSuccess(i18n.Tf("node_update_success", map[string]any{"Name": newName}))
			} else {
				logger.PrintWarn(i18n.T("node_no_changes"))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&flags.address, "address", "H", "", i18n.T("flag_inv_edit_address"))
	cmd.Flags().Uint16VarP(&flags.port, "port", "p", 0, i18n.T("flag_inv_edit_port"))
	cmd.Flags().StringVarP(&flags.user, "user", "u", "", i18n.T("flag_inv_edit_user"))
	cmd.Flags().StringVarP(&flags.password, "password", "P", "", i18n.T("flag_inv_edit_password"))
	cmd.Flags().StringVarP(&flags.keyPath, "key", "k", "", i18n.T("flag_inv_edit_key"))
	cmd.Flags().StringVarP(&flags.keyPass, "key-pass", "w", "", i18n.T("flag_inv_edit_key_pass"))
	cmd.Flags().StringSliceVarP(&flags.alias, "alias", "a", []string{}, i18n.T("flag_inv_edit_alias"))
	cmd.Flags().StringVarP(&flags.jump, "jump", "j", "", i18n.T("flag_inv_edit_jump"))
	return cmd
}

func applyNodeUpdates(cmd *cobra.Command, provider config.ConfigProvider, oldName string, host *models.Host, identity *models.Identity, node *models.Node, flags *editFlags) (updated, nameChanged bool) {
	if flags.address != "" {
		host.Address, updated, nameChanged = flags.address, true, true
	}
	if flags.port != 0 {
		host.Port, updated, nameChanged = flags.port, true, true
	}
	if flags.user != "" {
		identity.User, updated, nameChanged = flags.user, true, true
	}
	if flags.keyPath != "" {
		identity.KeyPath, identity.AuthType, identity.Password, updated = utils.ToAbsolutePath(flags.keyPath), "key", "", true
	} else if flags.password != "" {
		identity.Password, identity.AuthType, identity.KeyPath, updated = flags.password, "password", "", true
	}
	if flags.keyPass != "" {
		identity.Passphrase, updated = flags.keyPass, true
	}
	if cmd.Flags().Changed("alias") {
		// 检查别名是否已被其他节点使用
		for _, a := range flags.alias {
			if existingNode := provider.FindAlias(a); existingNode != "" && existingNode != oldName {
				// 别名已存在，跳过该别名
				continue
			}
		}
		node.Alias, updated = flags.alias, true
	}
	if cmd.Flags().Changed("jump") {
		node.ProxyJump, updated = flags.jump, true
	}
	return updated, nameChanged
}

func NewCmdInventoryDelete() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [name]",
		Short: i18n.T("inventory_delete_short"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := args[0]
			store, provider, cfg, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			name := provider.Find(query)
			if name == "" {
				return fmt.Errorf("节点 %s 不存在", query)
			}
			provider.DeleteNode(name)
			if err := store.Save(cfg); err != nil {
				return err
			}
			logger.PrintSuccess(i18n.Tf("node_delete_success", map[string]any{"Name": name}))
			return nil
		},
	}
}
