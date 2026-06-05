package cmd

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/mcpserver"
)

func NewCmdMcp() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: i18n.T("mcp_short"),
		Long:  i18n.T("mcp_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			// MCP server 必须完全静默，避免污染 stdout json-rpc 流
			logger.SetLogLevel("none")

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			err := mcpserver.Serve(ctx)
			if err != nil {
				if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "closing") {
					return nil
				}
				return err
			}
			return nil
		},
	}
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	return cmd
}
