package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/credential"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/mcpserver"
)

func NewCmdMcp() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: i18n.T("mcp_short"),
		Long:  i18n.T("mcp_long"),
		Args:  cobra.NoArgs,
		RunE:  runMCPServer,
	}
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.AddCommand(newCmdMCPServe())
	return cmd
}

func newCmdMCPServe() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: i18n.T("mcp_serve_short"),
		Long:  i18n.T("mcp_long"),
		Args:  cobra.NoArgs,
		RunE:  runMCPServer,
	}
}

func runMCPServer(cmd *cobra.Command, args []string) error {
	_, provider, cfg, err := utils.GetConfigStore()
	if err != nil {
		return fmt.Errorf("load mcp configuration failed: %w", err)
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveOpts := []mcpserver.Option{
		mcpserver.WithConfigProvider(provider),
		mcpserver.WithLogger(logger.DefaultLogger()),
	}
	if reg, regErr := utils.GetCredentialRegistry(cfg); regErr != nil {
		return fmt.Errorf("initialize credential resolver: %w", regErr)
	} else if reg != nil {
		serveOpts = append(serveOpts, mcpserver.WithCredentialRegistry(reg))
	}

	err = mcpserver.Serve(credential.WithoutInteraction(ctx), serveOpts...)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	return nil
}
