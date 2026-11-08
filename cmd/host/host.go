package host

import (
	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func NewCmdInventory() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "host",
		Aliases: []string{"h", "hosts", "inventory", "inv"},
		Short:   i18n.T("inventory_short"),
		Long:    i18n.T("inventory_long"),
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(NewCmdInventoryList())
	cmd.AddCommand(NewCmdInventoryAdd())
	cmd.AddCommand(NewCmdInventoryProbe())
	cmd.AddCommand(NewCmdInventoryLoad())
	cmd.AddCommand(NewCmdInventoryEdit())
	cmd.AddCommand(NewCmdInventoryDelete())
	cmd.AddCommand(NewCmdInventoryTags())
	cmd.AddCommand(NewCmdInventoryTag())
	cmd.AddCommand(NewCmdInventoryCredential())
	cmd.AddCommand(NewCmdInventorySetSecret())
	cmd.AddCommand(NewCmdInventoryDeleteSecret())

	return cmd
}

func NewCmdInventoryTag() *cobra.Command {
	var removeTag bool
	cmd := &cobra.Command{
		Use:   "tag [tag_name] [node1] [node2...]",
		Short: i18n.T("inventory_tag_short"),
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			if len(args) < 2 {
				return cobra.MinimumNArgs(2)(cmd, args)
			}
			return runInventoryTagMutation(cmd, args, !removeTag)
		},
	}

	cmd.Flags().BoolVarP(&removeTag, "delete", "d", false, i18n.T("flag_inv_tag_delete"))
	cmd.Flags().BoolVar(&removeTag, "remove", false, i18n.T("flag_inv_tag_delete"))
	cmd.AddCommand(NewCmdInventoryTagAdd())
	cmd.AddCommand(NewCmdInventoryTagRemove())

	return cmd
}

func NewCmdInventoryCredential() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "credential",
		Aliases: []string{"cred", "cr"},
		Short:   i18n.T("host_credential_short"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newCmdHostCredentialSet())
	cmd.AddCommand(newCmdHostCredentialDelete())
	return cmd
}

func NewCmdInventorySetSecret() *cobra.Command {
	cmd := newCmdHostCredentialSet()
	cmd.Use = "set-secret <node>"
	cmd.Aliases = []string{"set-cred"}
	cmd.Short = i18n.T("host_set_secret_short")
	return cmd
}

func NewCmdInventoryDeleteSecret() *cobra.Command {
	cmd := newCmdHostCredentialDelete()
	cmd.Use = "delete-secret <node>"
	cmd.Aliases = []string{"rm-secret", "unset-secret", "del-secret", "unset-cred"}
	cmd.Short = i18n.T("host_delete_secret_short")
	return cmd
}

func newCmdHostCredentialSet() *cobra.Command {
	opts := &utils.CredentialCommandOptions{Scope: utils.CredentialScopeNode}
	cmd := &cobra.Command{
		Use:     "set <node>",
		Aliases: []string{"s"},
		Short:   i18n.T("host_set_secret_short"),
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.RunSet(cmd, args[0])
		},
	}
	opts.RegisterSetFlags(cmd)
	return cmd
}

func newCmdHostCredentialDelete() *cobra.Command {
	opts := &utils.CredentialCommandOptions{Scope: utils.CredentialScopeNode}
	cmd := &cobra.Command{
		Use:     "delete <node>",
		Aliases: []string{"rm", "del", "remove", "unset"},
		Short:   i18n.T("host_delete_secret_short"),
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return opts.RunDelete(cmd, args[0])
		},
	}
	opts.RegisterDeleteFlags(cmd)
	return cmd
}
