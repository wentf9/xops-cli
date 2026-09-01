/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"fmt"
	"net"
	"time"

	ping "github.com/prometheus-community/pro-bing"
	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
)

func newCmdPing() *cobra.Command {
	return &cobra.Command{
		Use:   "ping <ip> [port]",
		Short: i18n.T("ping_short"),
		Long:  i18n.T("ping_long"),
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ip := args[0]

			resolveCtx, cancelResolve := context.WithTimeout(cmd.Context(), 5*time.Second)
			resolved, err := net.DefaultResolver.LookupIPAddr(resolveCtx, ip)
			cancelResolve()
			if err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ping_err_resolve"), err)
			}
			if len(resolved) == 0 {
				return fmt.Errorf("%s: no IP address returned", i18n.T("ping_err_resolve"))
			}
			logger.PrintInfo(i18n.Tf("ping_resolve_info", map[string]any{"Host": args[0], "IP": resolved[0].String()}))
			ip = resolved[0].String()

			if len(args) == 2 {
				port := args[1]
				address := net.JoinHostPort(ip, port)
				logger.PrintInfo(i18n.Tf("ping_tcp_testing", map[string]any{"Address": address}))

				dialCtx, cancelDial := context.WithTimeout(cmd.Context(), 5*time.Second)
				conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
				cancelDial()
				if err != nil {
					return fmt.Errorf("port check failed on %s: %w", address, err)
				}
				if err := conn.Close(); err != nil {
					return fmt.Errorf("close port check connection to %s failed: %w", address, err)
				}
				logger.PrintSuccess(i18n.Tf("ping_port_open", map[string]any{"IP": ip, "Port": port}))
				return nil
			}

			logger.PrintInfo(i18n.Tf("ping_icmp_start", map[string]any{"IP": ip}))
			pinger, err := ping.NewPinger(ip)
			if err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ping_err_create_pinger"), err)
			}

			// 注意: 在 Linux/macOS 上，执行ICMP raw socket需要root权限。
			pinger.SetPrivileged(true)
			pinger.Count = 4
			pinger.Interval = time.Second
			pinger.Timeout = 4 * time.Second

			pinger.OnFinish = func(stats *ping.Statistics) {
				logger.PrintInfo(i18n.Tf("ping_stats_header", map[string]any{"Addr": stats.Addr}))
				logger.PrintInfo(i18n.Tf("ping_stats_packets", map[string]any{
					"Sent": stats.PacketsSent, "Recv": stats.PacketsRecv, "Loss": stats.PacketLoss,
				}))
				logger.PrintInfo(i18n.Tf("ping_stats_rtt", map[string]any{
					"Min": stats.MinRtt, "Avg": stats.AvgRtt, "Max": stats.MaxRtt, "StdDev": stats.StdDevRtt,
				}))
			}

			return pinger.RunWithContext(cmd.Context())
		},
	}
}
