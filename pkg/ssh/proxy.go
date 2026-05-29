package ssh

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
)

// SSHProxyDialer 实现了 Dialer 接口，通过 SSH 隧道转发流量
type SSHProxyDialer struct {
	Client *ssh.Client
}

func (s *SSHProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return s.Client.Dial(network, addr)
}

func (s *SSHProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := s.Client.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("proxy dial failed: %w", err)
	}
	return conn, nil
}
