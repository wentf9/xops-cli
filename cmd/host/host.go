package host

import (
	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func NewCmdInventory() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "host",
		Aliases: []string{"hosts", "inventory", "inv"},
		Short:   i18n.T("inventory_short"),
		Long:    i18n.T("inventory_long"),
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(NewCmdInventoryList())
	cmd.AddCommand(NewCmdInventoryAdd())
	cmd.AddCommand(NewCmdInventoryLoad())
	cmd.AddCommand(NewCmdInventoryEdit())
	cmd.AddCommand(NewCmdInventoryDelete())
	cmd.AddCommand(NewCmdInventoryTags())
	cmd.AddCommand(NewCmdInventoryTag())

	return cmd
}

func NewCmdInventoryTag() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tag",
		Short: i18n.T("inventory_tag_short"),
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(NewCmdInventoryTagAdd())
	cmd.AddCommand(NewCmdInventoryTagRemove())

	return cmd
}
