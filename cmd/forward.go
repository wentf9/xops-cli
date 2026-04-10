package cmd

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/forward"
	"github.com/wentf9/xops-cli/pkg/i18n"
)

func newCmdForward() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "forward <listen-addr> <target-addr>",
		Short: i18n.T("forward_short"),
		Long:  i18n.T("forward_long"),
		Example: `  xops forward :8080 192.168.1.10:80
  xops forward 127.0.0.1:5353 8.8.8.8:53 --udp`,
		Args: forwardArgsValidator,
		RunE: forwardRunE,
	}

	cmd.Flags().BoolP("udp", "u", false, i18n.T("flag_forward_udp"))

	return cmd
}

func forwardArgsValidator(_ *cobra.Command, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("%s", i18n.T("forward_err_args"))
	}
	if err := validateForwardAddr(args[0]); err != nil {
		return fmt.Errorf("%s: %w", i18n.Tf("forward_err_listen_addr", map[string]any{"Addr": args[0]}), err)
	}
	if err := validateForwardAddr(args[1]); err != nil {
		return fmt.Errorf("%s: %w", i18n.Tf("forward_err_target_addr", map[string]any{"Addr": args[1]}), err)
	}
	return nil
}

// validateForwardAddr checks that addr is a valid host:port or :port string.
func validateForwardAddr(addr string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if port == "" {
		return fmt.Errorf("%s", i18n.T("forward_err_port_required"))
	}
	return nil
}

func forwardRunE(cmd *cobra.Command, args []string) error {
	udp, _ := cmd.Flags().GetBool("udp")

	listenAddr := args[0]
	targetAddr := args[1]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// graceful shutdown on SIGINT / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\n%s\n", i18n.T("forward_stopping"))
		cancel()
	}()

	if udp {
		f := forward.NewUDPForwarder(listenAddr, targetAddr)
		return f.Run(ctx)
	}

	f := forward.NewTCPForwarder(listenAddr, targetAddr)
	return f.Run(ctx)
}
