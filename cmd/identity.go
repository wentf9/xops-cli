package cmd

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
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
	cmd.AddCommand(NewCmdIdentityCredential())
	cmd.AddCommand(newCmdIdentitySetSecret())
	cmd.AddCommand(newCmdIdentityDeleteSecret())

	return cmd
}

func newCmdIdentitySetSecret() *cobra.Command {
	cmd := newCmdIdentityCredentialSet()
	cmd.Use = "set-secret [name]"
	cmd.Aliases = []string{"set", "set-cred"}
	cmd.Short = i18n.T("identity_set_secret_short")
	return cmd
}

func newCmdIdentityDeleteSecret() *cobra.Command {
	cmd := newCmdIdentityCredentialDelete()
	cmd.Use = "delete-secret [name]"
	cmd.Aliases = []string{"rm-secret", "unset-secret", "unset", "del-secret"}
	cmd.Short = i18n.T("identity_credential_delete_short")
	return cmd
}

func NewCmdIdentityEdit() *cobra.Command {
	var (
		user    string
		keyPath string
	)

	secretInput := &utils.InventorySecretInput{}
	cmd := &cobra.Command{
		Use:     "edit [name]",
		Aliases: []string{"ed", "update"},
		Short:   i18n.T("identity_edit_short"),
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			password, keyPass, err := secretInput.Read(cmd)
			if err != nil {
				return err
			}
			if keyPath != "" && keyPass == "" && password == "" && !secretInput.UsesStdin() {
				keyPass, err = utils.PromptPassphraseIfEncryptedKey(keyPath, keyPass)
				if err != nil {
					return err
				}
			}
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

			write, err := utils.PrepareInventoryCredential(repository, credential.Target{IdentityID: name}, identity, password, keyPass, keyPath, repository.IdentityCredentialEdit(ref, identity))
			if err != nil {
				return err
			}
			defer write.Clear()

			if updated && write == nil {
				if _, err := repository.ReplaceIdentityAtRefContext(cmd.Context(), ref, identity); err != nil {
					return fmt.Errorf("update identity %q failed: %w", name, err)
				}

				ref = repository.View().IdentityRefs[name]
			} else if write == nil {
				logger.PrintWarn(i18n.T("identity_no_changes"))
			}

			if err := write.Save(cmd.Context(), string(ref.Version[:])); err != nil {
				return err
			}
			if updated || write != nil {
				logger.PrintSuccess(i18n.Tf("identity_update_success", map[string]any{"Name": name}))
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&user, "user", "u", "", i18n.T("flag_identity_user"))
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", i18n.T("flag_identity_key"))

	secretInput.RegisterFlags(cmd)
	return cmd
}

func NewCmdIdentityList() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   i18n.T("identity_list_short"),
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
		name    string
		user    string
		keyPath string
	)

	secretInput := &utils.InventorySecretInput{}
	cmd := &cobra.Command{
		Use:     "add [name] [user]",
		Aliases: []string{"new", "create"},
		Short:   i18n.T("identity_add_short"),
		Args:    cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runIdentityAdd(cmd, args, name, user, keyPath, secretInput)
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", i18n.T("identity_flag_name"))
	cmd.Flags().StringVarP(&user, "user", "u", "", i18n.T("identity_flag_user"))
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", i18n.T("identity_flag_key"))

	secretInput.RegisterFlags(cmd)
	return cmd
}

func runIdentityAdd(cmd *cobra.Command, args []string, name, user, keyPath string, secretInput *utils.InventorySecretInput) error {
	password, keyPass, err := secretInput.Read(cmd)
	if err != nil {
		return err
	}
	name, user, err = resolveIdentityAddNameAndUser(args, name, user, secretInput.UsesStdin())
	if err != nil {
		return err
	}

	_, repository, _, err := utils.GetConfigStore()
	if err != nil {
		return err
	}
	if user == "" {
		user, err = utils.GetCurrentUser()
		if err != nil {
			return fmt.Errorf("get current user failed: %w", err)
		}
	}
	if keyPass != "" && keyPath == "" {
		return fmt.Errorf("private-key path is required for a passphrase (--key)")
	}
	if keyPath != "" && keyPass == "" && password == "" && !secretInput.UsesStdin() {
		keyPass, err = utils.PromptPassphraseIfEncryptedKey(keyPath, keyPass)
		if err != nil {
			return err
		}
	}

	identity, password, err := buildNewIdentityModel(user, keyPath, password)
	if err != nil {
		return err
	}

	write, err := utils.PrepareInventoryCredential(repository, credential.Target{IdentityID: name}, identity, password, keyPass, keyPath, nil)
	if err != nil {
		return err
	}
	defer write.Clear()

	if _, err := repository.CreateIdentityContext(cmd.Context(), name, identity); err != nil {
		if errors.Is(err, config.ErrConfigConflict) {
			return fmt.Errorf("%s", i18n.Tf("identity_err_exists", map[string]any{"Name": name}))
		}
		return fmt.Errorf("add identity %q failed: %w", name, err)
	}

	ref := repository.View().IdentityRefs[name]
	if err := write.Save(cmd.Context(), string(ref.Version[:])); err != nil {
		return err
	}

	logger.PrintSuccess(i18n.Tf("identity_add_success", map[string]any{"Name": name}))
	return nil
}

func resolveIdentityAddNameAndUser(args []string, name, user string, usesStdin bool) (string, string, error) {
	if len(args) >= 1 {
		posName := strings.TrimSpace(args[0])
		if name != "" && name != posName {
			return "", "", fmt.Errorf("conflicting identity names %q and %q", name, posName)
		}
		name = posName
	}
	if len(args) == 2 {
		posUser := strings.TrimSpace(args[1])
		if user != "" && user != posUser {
			return "", "", fmt.Errorf("conflicting identity users %q and %q", user, posUser)
		}
		user = posUser
	}
	if name == "" && !usesStdin && utils.IsInteractiveTerminal() {
		prompted, err := utils.ReadLineFromTerminal(i18n.T("prompt_enter_identity_name"))
		if err != nil {
			return "", "", err
		}
		name = prompted
	}
	if name == "" {
		return "", "", fmt.Errorf("%s", i18n.T("identity_err_no_name"))
	}
	return name, user, nil
}

func buildNewIdentityModel(user, keyPath, password string) (models.Identity, string, error) {
	identity := models.Identity{User: user}
	if keyPath != "" {
		identity.KeyPath = utils.ToAbsolutePath(keyPath)
		identity.AuthType = "key"
		return identity, password, nil
	}
	if password == "" {
		pass, err := utils.ReadPasswordFromTerminal(i18n.Tf("prompt_enter_user_password", map[string]any{"User": user}))
		if err != nil {
			return models.Identity{}, "", err
		}
		password = pass
	}
	identity.AuthType = "password"
	return identity, password, nil
}

func NewCmdIdentityDelete() *cobra.Command {
	return &cobra.Command{
		Use:     "delete <name> [name2...]",
		Aliases: []string{"rm", "del", "remove"},
		Short:   i18n.T("identity_delete_short"),
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var names []string
			seen := make(map[string]struct{})
			for _, raw := range args {
				for _, part := range strings.Split(raw, ",") {
					n := strings.TrimSpace(part)
					if n == "" {
						continue
					}
					if _, exists := seen[n]; !exists {
						seen[n] = struct{}{}
						names = append(names, n)
					}
				}
			}
			if len(names) == 0 {
				return fmt.Errorf("%s", i18n.T("identity_err_no_name"))
			}

			_, repository, _, err := utils.GetConfigStore()
			if err != nil {
				return err
			}
			view := repository.View()
			service, err := utils.GetCredentialService(repository, view.Configuration)
			if err != nil {
				return err
			}

			for _, name := range names {
				view = repository.View()
				if _, ok := view.Configuration.Identities.Get(name); !ok {
					return fmt.Errorf("%s", i18n.Tf("identity_err_not_found", map[string]any{"Name": name}))
				}
				ref, ok := view.IdentityRefs[name]
				if !ok {
					return fmt.Errorf("resolve identity %q reference: %w", name, config.ErrIdentityNotFound)
				}
				if err := repository.DeleteIdentityWithCredentialsContext(cmd.Context(), ref, service); err != nil {
					return fmt.Errorf("delete identity %q failed: %w", name, err)
				}
				logger.PrintSuccess(i18n.Tf("identity_delete_success", map[string]any{"Name": name}))
			}
			return nil
		},
	}
}

// NewCmdIdentityCredential 创建 identity credential 子命令
func NewCmdIdentityCredential() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "credential",
		Aliases: []string{"cred", "cr"},
		Short:   i18n.T("identity_credential_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newCmdIdentityCredentialSet())
	cmd.AddCommand(newCmdIdentityCredentialDelete())
	return cmd
}

func newCmdIdentityCredentialSet() *cobra.Command {
	opts := &utils.CredentialCommandOptions{Scope: utils.CredentialScopeIdentity}
	cmd := &cobra.Command{
		Use:     "set [name]",
		Aliases: []string{"s"},
		Short:   i18n.T("identity_credential_set_short"),
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.RunSet(cmd, args[0])
		},
	}
	opts.RegisterSetFlags(cmd)
	return cmd
}

func newCmdIdentityCredentialDelete() *cobra.Command {
	opts := &utils.CredentialCommandOptions{Scope: utils.CredentialScopeIdentity}
	cmd := &cobra.Command{
		Use:     "delete [name]",
		Aliases: []string{"rm", "del", "remove", "unset"},
		Short:   i18n.T("identity_credential_delete_short"),
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.RunDelete(cmd, args[0])
		},
	}
	opts.RegisterDeleteFlags(cmd)
	return cmd
}
