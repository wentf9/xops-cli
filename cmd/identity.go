package cmd

import (
	"errors"
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
)

func NewCmdIdentity() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "identity",
		Aliases: []string{"id", "auth"},
		Short:   i18n.T("identity_short"),
		Long:    i18n.T("identity_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(NewCmdIdentityList())
	cmd.AddCommand(NewCmdIdentityAdd())
	cmd.AddCommand(NewCmdIdentityEdit())
	cmd.AddCommand(NewCmdIdentityDelete())

	return cmd
}

func NewCmdIdentityEdit() *cobra.Command {
	var (
		user     string
		password string
		keyPath  string
		keyPass  string
	)

	cmd := &cobra.Command{
		Use:   "edit [name]",
		Short: i18n.T("identity_edit_short"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			_, repository, _, err := utils.GetConfigStore()
			if err != nil {
				return err
			}
			view := repository.View()
			identity, ok := view.Configuration.Identities.Get(name)
			if !ok {
				return fmt.Errorf("%s", i18n.Tf("identity_err_not_found", map[string]any{"Name": name}))
			}
			ref, ok := view.IdentityRefs[name]
			if !ok {
				return fmt.Errorf("resolve identity %q reference: %w", name, config.ErrIdentityNotFound)
			}

			updated := false
			if user != "" {
				identity.User = user
				updated = true
			}

			if keyPath != "" {
				identity.KeyPath = utils.ToAbsolutePath(keyPath)
				identity.AuthType = "key"
				identity.Password = "" // 切换到密钥时清空密码
				updated = true
			} else if password != "" {
				identity.Password = password
				identity.AuthType = "password"
				identity.KeyPath = "" // 切换到密码时清空密钥路径
				updated = true
			}

			if keyPass != "" {
				identity.Passphrase = keyPass
				updated = true
			}

			if updated {
				if _, err := repository.ReplaceIdentityAtRefContext(cmd.Context(), ref, identity); err != nil {
					return fmt.Errorf("update identity %q failed: %w", name, err)
				}

				logger.PrintSuccess(i18n.Tf("identity_update_success", map[string]any{"Name": name}))
			} else {
				logger.PrintWarn(i18n.T("identity_no_changes"))
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&user, "user", "u", "", i18n.T("flag_identity_user"))
	cmd.Flags().StringVarP(&password, "password", "p", "", i18n.T("flag_identity_password"))
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", i18n.T("flag_identity_key"))
	cmd.Flags().StringVarP(&keyPass, "key-pass", "w", "", i18n.T("flag_identity_key_pass"))

	return cmd
}

func NewCmdIdentityList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: i18n.T("identity_list_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath, keyPath, pathErr := utils.GetConfigFilePath()
			if pathErr != nil {
				return fmt.Errorf("get config file path failed: %w", pathErr)
			}
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				return fmt.Errorf("%s: %w", i18n.T("config_load_error"), err)
			}

			provider, repositoryErr := config.NewRepositoryWithoutOpenSSH(cfg, configStore)
			if repositoryErr != nil {
				return fmt.Errorf("create configuration repository: %w", repositoryErr)
			}
			identities := provider.ListIdentities()

			if len(identities) == 0 {
				logger.PrintWarn(i18n.T("identity_no_stored"))
				return nil
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			if _, err := fmt.Fprintln(w, i18n.T("identity_list_header")); err != nil {
				return fmt.Errorf("write identity list header failed: %w", err)
			}

			keys := make([]string, 0, len(identities))
			for k := range identities {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, name := range keys {
				id := identities[name]
				detail := ""
				switch id.AuthType {
				case "key":
					detail = id.KeyPath
				case "password":
					detail = "******"
				}

				if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					name,
					id.User,
					id.AuthType,
					detail,
				); err != nil {
					return fmt.Errorf("write identity %q failed: %w", name, err)
				}
			}
			if err := w.Flush(); err != nil {
				return fmt.Errorf("flush identity list failed: %w", err)
			}
			return nil
		},
	}
}

func NewCmdIdentityAdd() *cobra.Command {
	var (
		name     string
		user     string
		password string
		keyPath  string
		keyPass  string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: i18n.T("identity_add_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("%s", i18n.T("identity_err_no_name"))
			}

			_, repository, _, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			if user == "" {
				var userErr error
				user, userErr = utils.GetCurrentUser()
				if userErr != nil {
					return fmt.Errorf("get current user failed: %w", userErr)
				}
			}

			identity := models.Identity{
				User: user,
			}

			if keyPath != "" {
				identity.KeyPath = utils.ToAbsolutePath(keyPath)
				identity.Passphrase = keyPass
				identity.AuthType = "key"
			} else if password != "" {
				identity.Password = password
				identity.AuthType = "password"
			} else {
				pass, err := utils.ReadPasswordFromTerminal(i18n.Tf("prompt_enter_user_password", map[string]any{"User": user}))
				if err != nil {
					return err
				}
				identity.Password = pass
				identity.AuthType = "password"
			}

			if _, err := repository.CreateIdentityContext(cmd.Context(), name, identity); err != nil {
				if errors.Is(err, config.ErrConfigConflict) {
					return fmt.Errorf("%s", i18n.Tf("identity_err_exists", map[string]any{"Name": name}))
				}
				return fmt.Errorf("add identity %q failed: %w", name, err)
			}

			logger.PrintSuccess(i18n.Tf("identity_add_success", map[string]any{"Name": name}))
			return nil
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", i18n.T("identity_flag_name"))
	cmd.Flags().StringVarP(&user, "user", "u", "", i18n.T("identity_flag_user"))
	cmd.Flags().StringVarP(&password, "password", "p", "", i18n.T("identity_flag_password"))
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", i18n.T("identity_flag_key"))
	cmd.Flags().StringVarP(&keyPass, "key-pass", "K", "", i18n.T("identity_flag_key_pass"))

	return cmd
}

func NewCmdIdentityDelete() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [name]",
		Short: i18n.T("identity_delete_short"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			_, repository, _, err := utils.GetConfigStore()
			if err != nil {
				return err
			}
			view := repository.View()
			if _, ok := view.Configuration.Identities.Get(name); !ok {
				return fmt.Errorf("%s", i18n.Tf("identity_err_not_found", map[string]any{"Name": name}))
			}
			ref, ok := view.IdentityRefs[name]
			if !ok {
				return fmt.Errorf("resolve identity %q reference: %w", name, config.ErrIdentityNotFound)
			}

			if _, err := repository.DeleteIdentityAtRefContext(cmd.Context(), ref); err != nil {
				return fmt.Errorf("delete identity %q failed: %w", name, err)
			}

			logger.PrintSuccess(i18n.Tf("identity_delete_success", map[string]any{"Name": name}))
			return nil
		},
	}
}
