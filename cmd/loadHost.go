package cmd

import (
	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/host"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func newCmdLoadHost() *cobra.Command {
	cmd := &cobra.Command{
		Use:        "loadHost [csv_file]",
		Short:      i18n.T("loadhost_short"),
		Long:       i18n.T("loadhost_long"),
		Args:       cobra.MaximumNArgs(1),
		RunE:       host.RunInventoryLoad,
		Hidden:     true,
		Deprecated: "use 'xops host import' instead",
	}

	cmd.Flags().StringVarP(&host.TemplateFile, "template", "T", "", i18n.T("flag_inv_template"))
	cmd.Flags().StringVarP(&host.Tag, "tag", "t", "", i18n.T("flag_inv_load_tag"))

	return cmd
}
