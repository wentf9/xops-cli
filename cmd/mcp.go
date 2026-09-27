package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

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
	addMCPFlags(cmd)
	cmd.AddCommand(newCmdMCPServe())
	cmd.AddCommand(newCmdMCPRecover())
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

func runMCPServer(cmd *cobra.Command, args []string) (retErr error) {
	_, provider, cfg, err := utils.GetConfigStore()
	if err != nil {
		return fmt.Errorf("load mcp configuration failed: %w", err)
	}

	configPath, _, err := utils.GetConfigFilePath()
	if err != nil {
		return fmt.Errorf("resolve MCP configuration path: %w", err)
	}
	transport, httpOptions, err := resolveMCPOptions(cmd, cfg, configPath)
	if err != nil {
		return err
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

	if transport == "http" {
		err = serveMCPHTTP(credential.WithoutInteraction(ctx), cmd, httpOptions, serveOpts)
	} else {
		err = mcpserver.Serve(credential.WithoutInteraction(ctx), serveOpts...)
	}
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
	return nil
}

// serveMCPHTTP owns both listener and runtime even when startup fails before
// the HTTP server takes over. Binding first resolves an ephemeral test port.
func serveMCPHTTP(ctx context.Context, cmd *cobra.Command, options mcpserver.HTTPOptions, serveOpts []mcpserver.Option) (retErr error) {
	listenCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	listener, err := (&net.ListenConfig{}).Listen(listenCtx, "tcp", options.Listen)
	if err != nil {
		return fmt.Errorf("listen for MCP HTTP: %w", err)
	}
	defer func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = errors.Join(retErr, fmt.Errorf("close MCP HTTP listener: %w", err))
		}
	}()
	host, _, err := net.SplitHostPort(options.Listen)
	if err != nil {
		return fmt.Errorf("parse MCP listener: %w", err)
	}
	if ip := net.ParseIP(host); options.PublicURL == "" && (host == "localhost" || (ip != nil && ip.IsLoopback())) {
		_, port, err := net.SplitHostPort(listener.Addr().String())
		if err != nil {
			return fmt.Errorf("parse bound MCP listener: %w", err)
		}
		options.PublicURL = "http://" + net.JoinHostPort(host, port)
	}
	serveOpts = append(serveOpts, mcpserver.WithHTTP(options))
	runtime, err := mcpserver.NewRuntime(ctx, serveOpts...)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := runtime.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close MCP runtime: %w", closeErr))
		}
	}()
	if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "MCP Streamable HTTP: %s/mcp\n", strings.TrimSuffix(options.PublicURL, "/")); err != nil {
		return fmt.Errorf("write MCP startup diagnostic: %w", err)
	}
	return runtime.ServeHTTP(listener)
}
