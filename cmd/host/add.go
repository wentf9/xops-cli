package host

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
)

func NewCmdInventoryAdd() *cobra.Command {
	return newCmdInventoryAdd(verifyInventoryNode)
}

func newCmdInventoryAdd(verify inventoryVerifier) *cobra.Command {
	var (
		address       string
		port          uint16
		user          string
		keyPath       string
		identityAlias string
		alias         []string
		tags          []string
		jump          string
		skipVerify    bool
	)

	secretInput := &utils.InventorySecretInput{}
	cmd := &cobra.Command{
		Use:   "add",
		Short: i18n.T("inventory_add_short"),
		Long:  i18n.T("inventory_add_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, keyPass, err := secretInput.Read(cmd)
			if err != nil {
				return err
			}
			if address == "" {
				return fmt.Errorf("必须指定主机地址 (--address)")
			}

			_, repository, cfg, err := utils.GetConfigStore()
			if err != nil {
				return fmt.Errorf("加载配置文件失败: %w", err)
			}

			if port == 0 {
				port = 22
			}

			if keyPass != "" && keyPath == "" {
				return fmt.Errorf("private-key path is required for a passphrase (--key)")
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
				identity, password, err = newInventoryIdentity(user, password, keyPath, skipVerify)
				if err != nil {
					return err
				}
				identityRef = fmt.Sprintf("%s@%s", identity.User, address)
			}

			name := config.FormatNodeID(identity.User, address, port)
			if _, ok := repository.GetNode(name); ok {
				return fmt.Errorf("节点 %s 已存在", name)
			}

			if err := validateNewNodeAliases(repository, alias); err != nil {
				return err
			}

			hostObj := models.Host{Address: address, Port: port}
			resolvedJump, err := repository.ResolveProxyJumpChain(jump)
			if err != nil {
				return fmt.Errorf("resolve jump host for new node: %w", err)
			}
			node := models.Node{
				HostRef:     config.FormatHostPort(address, port),
				IdentityRef: identityRef,
				Alias:       alias,
				Tags:        tags,
				ProxyJump:   resolvedJump,
				SudoMode:    models.SudoModeAuto,
			}

			if !skipVerify {
				bundle := config.ConnectionSnapshot{Node: node, Host: hostObj, Identity: identity}
				auth := utils.HostInfo{Password: password, KeyPath: keyPath, Passphrase: keyPass}
				if err := verifyAndConfirmAddedNode(cmd, repository, name, bundle, auth, verify); err != nil {
					return err
				}
			}
			write, err := utils.PrepareInventoryCredential(repository, credential.Target{NodeID: name}, identity, password, keyPass, keyPath, nil)
			if err != nil {
				return err
			}
			defer write.Clear()
			mutation, err := repository.CreateNodeContext(cmd.Context(), name, node, hostObj, identity)
			if err != nil {
				return fmt.Errorf("create node %q failed: %w", name, err)
			}
			if err := write.Save(cmd.Context(), mutation.AuthVersion); err != nil {
				return err
			}

			logger.PrintSuccess(i18n.Tf("node_add_success", map[string]any{"Name": name}))
			return nil
		},
	}

	cmd.Flags().StringVarP(&address, "address", "H", "", i18n.T("flag_inv_address"))
	cmd.Flags().Uint16VarP(&port, "port", "p", 22, i18n.T("flag_inv_port"))
	cmd.Flags().StringVarP(&user, "user", "u", "", i18n.T("flag_inv_user"))
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", i18n.T("flag_inv_key"))
	cmd.Flags().StringVarP(&identityAlias, "identity", "I", "", i18n.T("flag_inv_identity"))
	cmd.Flags().StringSliceVarP(&alias, "alias", "a", []string{}, i18n.T("flag_inv_alias"))
	cmd.Flags().StringSliceVarP(&tags, "tags", "t", []string{}, i18n.T("flag_inv_tags"))
	cmd.Flags().StringVarP(&jump, "jump", "j", "", i18n.T("flag_inv_jump"))
	cmd.Flags().BoolVar(&skipVerify, "skip-verify", false, i18n.T("flag_skip_verify"))

	secretInput.RegisterFlags(cmd)
	cmd.MarkFlagsMutuallyExclusive("identity", "password-stdin", "passphrase-stdin")
	return cmd
}

func validateNewNodeAliases(repo *config.Repository, aliases []string) error {
	for _, alias := range aliases {
		if existing := repo.FindAlias(alias); existing != "" {
			return fmt.Errorf("%s", i18n.Tf("alias_err_exists", map[string]any{"Alias": alias, "Node": existing}))
		}
	}
	return nil
}

// newInventoryIdentity keeps prompted and stdin credentials outside the model.
func newInventoryIdentity(user, password, keyPath string, skipVerify bool) (models.Identity, string, error) {
	if user == "" {
		var err error
		user, err = utils.GetCurrentUser()
		if err != nil {
			return models.Identity{}, "", fmt.Errorf("get current user failed: %w", err)
		}
	}
	identity := models.Identity{User: user}
	switch {
	case keyPath != "":
		identity.KeyPath, identity.AuthType = utils.ToAbsolutePath(keyPath), "key"
	case password != "":
		identity.AuthType = "password"
	case skipVerify:
		identity.AuthType = "auto"
	default:
		pass, err := utils.ReadPasswordFromTerminal(i18n.Tf("prompt_enter_user_password", map[string]any{"User": user}))
		if err != nil {
			return models.Identity{}, "", err
		}
		password, identity.AuthType = pass, "password"
	}
	return identity, password, nil
}
