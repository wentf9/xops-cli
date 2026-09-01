package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"
	cmdutils "github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"golang.org/x/term"
)

const (
	ncDialTimeout           = 10 * time.Second
	ncNetworkIOWriteTimeout = 10 * time.Second
	ncNetworkIOReadTimeout  = 60 * time.Second
)

func newCmdNc() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nc",
		Short: i18n.T("nc_short"),
		Long:  i18n.T("nc_long"),
		Example: `  xops nc -l 8080
  xops nc <ip> <port>`,
		Args: ncArgsValidator,
		RunE: ncRunE,
	}

	cmd.PersistentFlags().Uint16P("listen", "l", 0, i18n.T("flag_nc_listen"))
	cmd.PersistentFlags().BoolP("udp", "u", false, i18n.T("flag_nc_udp"))

	return cmd
}

func ncArgsValidator(cmd *cobra.Command, args []string) error {
	port, err := cmd.Flags().GetUint16("listen")
	if err == nil && port != 0 {
		return nil
	}
	if len(args) != 2 {
		return fmt.Errorf("%s", i18n.T("nc_err_args_missing"))
	}
	if net.ParseIP(args[0]) == nil {
		return fmt.Errorf("%s", i18n.Tf("nc_err_invalid_ip", map[string]any{"IP": args[0]}))
	}
	port, portErr := cmdutils.ParsePort(args[1])
	if portErr != nil || port == 0 {
		return fmt.Errorf("%s", i18n.Tf("nc_err_invalid_port", map[string]any{"Port": args[1]}))
	}
	return nil
}

func ncRunE(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetUint16("listen")
	udp, _ := cmd.Flags().GetBool("udp")

	network := "tcp"
	if udp {
		network = "udp"
	}

	if port != 0 {
		return ncListenMode(cmd.Context(), port, network)
	}
	return ncConnectMode(args, network)
}

func ncListenMode(ctx context.Context, port uint16, network string) (retErr error) {
	if ctx == nil {
		return fmt.Errorf("nc listen context is nil")
	}
	listener, err := net.Listen(network, fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.Tf("nc_err_listen", map[string]any{"Port": port}), err)
	}
	cancellationClose := make(chan error, 1)
	stopCancellation := context.AfterFunc(ctx, func() {
		cancellationClose <- listener.Close()
	})
	defer func() {
		var cancellationCloseErr error
		if !stopCancellation() {
			cancellationCloseErr = <-cancellationClose
		}
		closeErr := listener.Close()
		if errors.Is(cancellationCloseErr, net.ErrClosed) {
			cancellationCloseErr = nil
		}
		if errors.Is(closeErr, net.ErrClosed) {
			closeErr = nil
		}
		retErr = errors.Join(
			retErr,
			wrapNCResourceError(cancellationCloseErr, "close canceled listener"),
			wrapNCResourceError(closeErr, "close listener"),
		)
	}()

	if err := ncPrintStderr(i18n.Tf("nc_listening", map[string]any{"Port": port})); err != nil {
		return err
	}
	conn, err := listener.Accept()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("nc listen canceled: %w", ctxErr)
		}
		return fmt.Errorf("%s: %w", i18n.T("nc_err_accept"), err)
	}

	if err := handleConnection(conn); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("nc_err_handle"), err)
	}
	return nil
}

func wrapNCResourceError(err error, operation string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}

func ncConnectMode(args []string, network string) (retErr error) {
	addr := net.JoinHostPort(args[0], args[1])
	conn, err := net.DialTimeout(network, addr, ncDialTimeout)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.Tf("nc_err_connect", map[string]any{"Addr": addr}), err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			retErr = errors.Join(retErr, fmt.Errorf("close connection failed: %w", closeErr))
		}
	}()

	if err := ncPrintStderr(i18n.Tf("nc_connected", map[string]any{"Addr": addr})); err != nil {
		return err
	}

	if term.IsTerminal(0) {
		return ncPrintStderr(i18n.T("nc_interactive_warning"))
	}

	return ncSendFromStdin(conn)
}

func ncSendFromStdin(conn net.Conn) error {
	reader := bufio.NewReader(os.Stdin)
	buffer := make([]byte, 1024*1024*10) // 10MB 缓冲区

	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			if dlErr := conn.SetWriteDeadline(time.Now().Add(ncNetworkIOWriteTimeout)); dlErr != nil {
				return fmt.Errorf("set write deadline failed: %w", dlErr)
			}
			if _, writeErr := conn.Write(buffer[:n]); writeErr != nil {
				return fmt.Errorf("%s: %w", i18n.T("nc_err_write_conn"), writeErr)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("%s: %w", i18n.T("nc_err_read_input"), err)
		}
	}
	return nil
}

func handleConnection(conn net.Conn) (retErr error) {
	defer func() {
		if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			retErr = errors.Join(retErr, fmt.Errorf("close connection failed: %w", closeErr))
		}
	}()

	clientAddr := conn.RemoteAddr().String()
	if err := ncPrintStderr(i18n.Tf("nc_new_connection", map[string]any{"Addr": clientAddr})); err != nil {
		return err
	}
	if err := ncPrintStderr(i18n.Tf("nc_request_content", map[string]any{"Addr": clientAddr})); err != nil {
		return err
	}

	writer := bufio.NewWriter(os.Stdout)
	reader := bufio.NewReader(conn)
	buffer := make([]byte, 1024*1024*10) // 10MB 缓冲区

	for {
		if dlErr := conn.SetReadDeadline(time.Now().Add(ncNetworkIOReadTimeout)); dlErr != nil {
			return fmt.Errorf("set read deadline failed: %w", dlErr)
		}
		n, err := reader.Read(buffer)
		if n > 0 {
			if _, writeErr := writer.Write(buffer[:n]); writeErr != nil {
				return fmt.Errorf("%s: %w", i18n.T("nc_err_write_out"), writeErr)
			}
			if flushErr := writer.Flush(); flushErr != nil {
				return fmt.Errorf("flush stdout failed: %w", flushErr)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return ncPrintStderr(i18n.Tf("nc_connection_closed", map[string]any{"Addr": clientAddr}))
			}
			return fmt.Errorf("%s: %w", i18n.Tf("nc_err_conn_error", map[string]any{"Addr": clientAddr}), err)
		}
	}
}

func ncPrintStderr(msg string) error {
	if _, err := fmt.Fprint(os.Stderr, msg); err != nil {
		return fmt.Errorf("write stderr failed: %w", err)
	}
	return nil
}
