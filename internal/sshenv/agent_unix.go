//go:build !windows

package sshenv

import (
	"context"
	"net"
	"os"
	"time"
)

func defaultAgentSocket() string {
	return os.Getenv("SSH_AUTH_SOCK")
}

func platformDialAgent() func(ctx context.Context, socket string) (net.Conn, error) {
	return func(ctx context.Context, socket string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: 2 * time.Second}
		return dialer.DialContext(ctx, "unix", socket)
	}
}
