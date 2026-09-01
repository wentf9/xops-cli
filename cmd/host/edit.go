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
			_, repository, _, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			view := repository.View()
			oldName, resolveErr := repository.ResolveSelector(query)
			if resolveErr != nil {
				return fmt.Errorf("resolve node %q for editing failed: %w", query, resolveErr)
			}
			if oldName == "" {
				return fmt.Errorf("节点 %s 不存在", query)
			}

			node, host, identity, resolveErr := repository.Resolve(oldName)
			if resolveErr != nil {
				return fmt.Errorf("resolve node %q for editing failed: %w", oldName, resolveErr)
			}

			updated, nameChanged := applyNodeUpdates(cmd, repository, oldName, &host, &identity, &node, flags)

			if updated {
				newName := oldName
				if nameChanged {
					newName = fmt.Sprintf("%s@%s:%d", identity.User, host.Address, host.Port)
					if newName != oldName {
						if _, exists := repository.GetNode(newName); exists {
							return fmt.Errorf("修改后的节点名称 %s 已存在", newName)
						}
					}
				}
				if err := repository.ReplaceNodeAtRefContext(cmd.Context(), view.NodeRefs[oldName], newName, node, host, identity); err != nil {
					return fmt.Errorf("update node %q failed: %w", oldName, err)
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

type aliasResolver interface {
	FindAlias(string) string
}

func applyNodeUpdates(cmd *cobra.Command, provider aliasResolver, oldName string, host *models.Host, identity *models.Identity, node *models.Node, flags *editFlags) (updated, nameChanged bool) {
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
			_, repository, _, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			view := repository.View()
			name, resolveErr := repository.ResolveSelector(query)
			if resolveErr != nil {
				return fmt.Errorf("resolve node %q for deletion failed: %w", query, resolveErr)
			}
			if name == "" {
				return fmt.Errorf("节点 %s 不存在", query)
			}
			if err := repository.DeleteNodesAtRefsContext(cmd.Context(), []config.NodeRef{view.NodeRefs[name]}); err != nil {
				return fmt.Errorf("delete node %q failed: %w", name, err)
			}
			logger.PrintSuccess(i18n.Tf("node_delete_success", map[string]any{"Name": name}))
			return nil
		},
	}
}
