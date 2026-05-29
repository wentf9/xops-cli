package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/wentf9/xops-cli/pkg/logger"
)

// LocalForward starts local port forwarding.
// Listens on localAddr, forwards connections to remoteAddr via SSH.
func (c *Client) LocalForward(ctx context.Context, localAddr, remoteAddr string) error {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on local addr %s: %w", localAddr, err)
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // Context canceled or listener closed
			}
			go c.handleLocalForward(conn, remoteAddr)
		}
	}()

	return nil
}

func (c *Client) handleLocalForward(localConn net.Conn, remoteAddr string) {
	defer func() { _ = localConn.Close() }()

	remoteConn, err := c.sshClient.Dial("tcp", remoteAddr)
	if err != nil {
		logger.Warnf("local forwarding failed to dial remote %s: %v", remoteAddr, err)
		return
	}
	defer func() { _ = remoteConn.Close() }()

	c.copyStream(localConn, remoteConn)
}

// RemoteForward starts remote port forwarding.
// Asks SSH server to listen on remoteAddr, forwards connections to localAddr.
func (c *Client) RemoteForward(ctx context.Context, remoteAddr, localAddr string) error {
	listener, err := c.sshClient.Listen("tcp", remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on remote addr %s: %w", remoteAddr, err)
	}

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go c.handleRemoteForward(conn, localAddr)
		}
	}()

	return nil
}

func (c *Client) handleRemoteForward(remoteConn net.Conn, localAddr string) {
	defer func() { _ = remoteConn.Close() }()

	localConn, err := net.DialTimeout("tcp", localAddr, 5*time.Second)
	if err != nil {
		logger.Warnf("remote forwarding failed to dial local %s: %v", localAddr, err)
		return
	}
	defer func() { _ = localConn.Close() }()

	c.copyStream(remoteConn, localConn)
}

func (c *Client) copyStream(conn1, conn2 net.Conn) {
	if tcpConn, ok := conn1.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			logger.Warnf("tunnel: failed to set keepalive on conn1: %v", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			logger.Warnf("tunnel: failed to set keepalive period on conn1: %v", err)
		}
	}
	if tcpConn, ok := conn2.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			logger.Warnf("tunnel: failed to set keepalive on conn2: %v", err)
		}
		if err := tcpConn.SetKeepAlivePeriod(30 * time.Second); err != nil {
			logger.Warnf("tunnel: failed to set keepalive period on conn2: %v", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn1, conn2)
		if cw, ok := conn1.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = conn1.Close()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn2, conn1)
		if cw, ok := conn2.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = conn2.Close()
		}
	}()

	wg.Wait()
}
