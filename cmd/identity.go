package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
	"golang.org/x/term"
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
			utils.WarnInventorySecretFlags(cmd)
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
			utils.WarnInventorySecretFlags(cmd)
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
				// Passphrase is saved through CredentialService after metadata creation.
				identity.AuthType = "key"
			} else if password != "" {
				// Password is never published in the inventory.
				identity.AuthType = "password"
			} else {
				pass, err := utils.ReadPasswordFromTerminal(i18n.Tf("prompt_enter_user_password", map[string]any{"User": user}))
				if err != nil {
					return err
				}
				password = pass
				identity.AuthType = "password"
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

// NewCmdIdentityCredential 创建 identity credential 子命令
func NewCmdIdentityCredential() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "credential",
		Aliases: []string{"cred"},
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
	var (
		kindStr       string
		storeID       string
		passwordStdin bool
	)

	cmd := &cobra.Command{
		Use:   "set [name]",
		Short: i18n.T("identity_credential_set_short"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			kind := credential.Kind(kindStr)
			if kind != credential.KindLoginPassword && kind != credential.KindPassphrase {
				return fmt.Errorf("invalid credential kind %q: must be login_password or passphrase", kindStr)
			}

			_, repo, cfg, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			view := repo.View()
			ident, ok := view.Configuration.Identities.Get(name)
			if !ok {
				return fmt.Errorf("%s", i18n.Tf("identity_err_not_found", map[string]any{"Name": name}))
			}
			ref, ok := view.IdentityRefs[name]
			if !ok {
				return fmt.Errorf("resolve identity %q reference: %w", name, config.ErrIdentityNotFound)
			}

			secretStr, err := resolveSecretInput(cmd.InOrStdin(), passwordStdin, kindStr)
			if err != nil {
				return err
			}

			targetStore := storeID
			if targetStore == "" {
				if cfg.Credential != nil && cfg.Credential.DefaultStore != "" {
					targetStore = cfg.Credential.DefaultStore
				} else {
					targetStore = "none"
				}
			}

			var oldRef *credential.Ref
			if kind == credential.KindLoginPassword {
				oldRef = ident.LoginPasswordRef
			} else {
				oldRef = ident.PassphraseRef
			}

			svc, err := utils.GetCredentialService(repo, cfg)
			if err != nil {
				return fmt.Errorf("initialize credential service: %w", err)
			}

			target := credential.Target{
				IdentityID: name,
				Kind:       kind,
			}
			target.KeyPath = ident.KeyPath
			target, err = config.BindPrivateKeyFingerprint(cfg, target, []byte(secretStr))
			if err != nil {
				return err
			}
			newRef, _, err := svc.Rotate(
				cmd.Context(),
				target,
				string(ref.Version[:]),
				oldRef,
				targetStore,
				credential.Secret{Value: []byte(secretStr)},
			)
			if err != nil {
				return fmt.Errorf("rotate credential in store failed: %w", err)
			}

			logger.PrintSuccessf("Set credential for identity %q (kind: %s, store: %s, itemID: %s)", name, kindStr, targetStore, newRef.ItemID)
			return nil
		},
	}

	cmd.Flags().StringVar(&kindStr, "kind", "login_password", i18n.T("flag_credential_kind"))
	cmd.Flags().StringVar(&storeID, "store", "", i18n.T("flag_credential_store"))
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, i18n.T("flag_password_stdin"))
	return cmd
}

func resolveSecretInput(r io.Reader, stdin bool, kindStr string) (string, error) {
	if stdin {
		return utils.ReadSecretFromReader(r)
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		prompt := fmt.Sprintf("Enter %s: ", kindStr)
		return utils.ReadPasswordFromTerminal(prompt)
	}
	return "", errors.New("terminal is not interactive, please provide secret via --password-stdin")
}

func newCmdIdentityCredentialDelete() *cobra.Command {
	var kindStr string

	cmd := &cobra.Command{
		Use:   "delete [name]",
		Short: i18n.T("identity_credential_delete_short"),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			kind := credential.Kind(kindStr)
			if kind != credential.KindLoginPassword && kind != credential.KindPassphrase {
				return fmt.Errorf("invalid credential kind %q: must be login_password or passphrase", kindStr)
			}

			_, repo, cfg, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			view := repo.View()
			ident, ok := view.Configuration.Identities.Get(name)
			if !ok {
				return fmt.Errorf("%s", i18n.Tf("identity_err_not_found", map[string]any{"Name": name}))
			}
			ref, ok := view.IdentityRefs[name]
			if !ok {
				return fmt.Errorf("resolve identity %q reference: %w", name, config.ErrIdentityNotFound)
			}

			var oldRef *credential.Ref
			if kind == credential.KindLoginPassword {
				oldRef = ident.LoginPasswordRef
			} else {
				oldRef = ident.PassphraseRef
			}

			target := credential.Target{
				IdentityID: name,
				Kind:       kind,
			}

			svc, err := utils.GetCredentialService(repo, cfg)
			if err != nil {
				return fmt.Errorf("initialize credential service: %w", err)
			}

			if oldRef != nil && !oldRef.IsEmpty() {
				if _, err := svc.Delete(cmd.Context(), target, string(ref.Version[:]), *oldRef); err != nil {
					return fmt.Errorf("delete credential for identity %q: %w", name, err)
				}
			} else {
				// 没有持久化引用，但可能存在明文，清空明文
				updater := repo.AsConfigUpdater()
				if _, _, err := updater.ApplyCredentialRefAtVersion(cmd.Context(), target, string(ref.Version[:]), nil); err != nil {
					return fmt.Errorf("clear credential for identity %q: %w", name, err)
				}
			}

			logger.PrintSuccessf("Successfully deleted %s credential for identity %q", kindStr, name)
			return nil
		},
	}

	cmd.Flags().StringVar(&kindStr, "kind", "login_password", i18n.T("flag_credential_kind"))
	return cmd
}
