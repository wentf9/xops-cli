package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

// LocalForward starts local port forwarding.
// Listens on localAddr, forwards connections to remoteAddr via SSH.
func (c *Client) LocalForward(ctx context.Context, localAddr, remoteAddr string) error {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return err
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
		fmt.Fprintf(os.Stderr, "Local forwarding failed to dial remote %s: %v\n", remoteAddr, err)
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
		return err
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

	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Remote forwarding failed to dial local %s: %v\n", localAddr, err)
		return
	}
	defer func() { _ = localConn.Close() }()

	c.copyStream(remoteConn, localConn)
}

func (c *Client) copyStream(conn1, conn2 net.Conn) {
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
