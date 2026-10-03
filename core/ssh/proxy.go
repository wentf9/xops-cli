package ssh

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

// physicalSSHConn records the lifetime of one shared transport generation.
// A proxy dialer can outlive that generation while another caller probes or
// interrupts a downstream client, so socket closure must be observable locally.
type physicalSSHConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *physicalSSHConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// SSHProxyDialer 实现了 Dialer 接口，通过 SSH 隧道转发流量
type SSHProxyDialer struct {
	Client *ssh.Client
	// RootConn is the outermost transport, shared by every hop in the chain.
	// Retaining it lets cancellation abort nested reads without a peer response.
	RootConn net.Conn
}

func (s *SSHProxyDialer) transportClosed() bool {
	root, ok := s.RootConn.(*physicalSSHConn)
	return ok && root.closed.Load()
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
