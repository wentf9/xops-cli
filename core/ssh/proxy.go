package ssh

import (
	"context"
	"errors"
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
	// abortUpstream optionally aborts and evicts a wedged or blackholed upstream
	// hop when closing a multiplexed direct-tcpip channel stalls past
	// proxyChanCloseGrace.
	abortUpstream func(self net.Conn) error
	selfAborted   atomic.Bool
}

func (s *SSHProxyDialer) transportClosed() bool {
	if s == nil {
		return false
	}
	root, ok := s.RootConn.(*physicalSSHConn)
	return ok && root.closed.Load()
}

func (s *SSHProxyDialer) abortedBySelf() bool {
	return s != nil && s.selfAborted.Load()
}

func (s *SSHProxyDialer) validateClient() error {
	if s == nil || s.Client == nil || s.Client.Conn == nil {
		return errors.New("proxy dial failed: upstream SSH client is not connected")
	}
	return nil
}

func (s *SSHProxyDialer) wrapChanConn(conn net.Conn) net.Conn {
	if conn == nil {
		return nil
	}
	return newProxyChanConn(conn, func(self net.Conn) error {
		if s == nil {
			return nil
		}
		s.selfAborted.Store(true)
		if s.abortUpstream != nil {
			return s.abortUpstream(self)
		}
		if s.RootConn != nil {
			return closeResource(s.RootConn, "upstream root SSH transport")
		}
		if s.Client != nil && s.Client.Conn != nil {
			return closeResource(s.Client, "upstream SSH client")
		}
		return nil
	})
}

func (s *SSHProxyDialer) Dial(network, addr string) (net.Conn, error) {
	if err := s.validateClient(); err != nil {
		return nil, err
	}
	conn, err := s.Client.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return s.wrapChanConn(conn), nil
}

func (s *SSHProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if ctx == nil {
		return nil, errors.New("proxy dial context is nil")
	}
	if err := s.validateClient(); err != nil {
		return nil, err
	}
	conn, err := s.Client.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("proxy dial failed: %w", err)
	}
	return s.wrapChanConn(conn), nil
}
