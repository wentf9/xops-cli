package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	xssh "github.com/wentf9/xops-cli/pkg/ssh"
	"golang.org/x/crypto/ssh"
)

type tunnelTestProvider struct{ cfg *xssh.ClientConfig }

func (p tunnelTestProvider) GetConfig(string) (*xssh.ClientConfig, error) { return p.cfg, nil }

func closeTunnelTestResource(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Errorf("close test resource: %v", err)
	}
}

func newTunnelTestClient(t *testing.T) (*xssh.Client, net.Conn) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	serverDone := make(chan struct{})
	accepted := make(chan net.Conn, 1)
	t.Cleanup(func() {
		cancel()
		closeTunnelTestResource(t, listener)
		<-serverDone
	})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer closeTunnelTestResource(t, conn)
		closed := make(chan struct{})
		stopClose := context.AfterFunc(ctx, func() {
			defer close(closed)
			closeTunnelTestResource(t, conn)
		})
		defer func() {
			if !stopClose() {
				<-closed
			}
		}()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Error(err)
			return
		}
		server, channels, requests, handshakeErr := ssh.NewServerConn(conn, cfg)
		if handshakeErr != nil {
			t.Error(handshakeErr)
			return
		}
		defer closeTunnelTestResource(t, server)
		accepted <- conn
		var workers sync.WaitGroup
		workers.Go(func() {
			for channel := range channels {
				if err := channel.Reject(ssh.Prohibited, "test destination unavailable"); err != nil && ctx.Err() == nil {
					t.Errorf("reject test channel: %v", err)
				}
			}
		})
		ssh.DiscardRequests(requests)
		workers.Wait()
	}()
	addr := listener.Addr().(*net.TCPAddr)
	connector := xssh.NewConnector(tunnelTestProvider{&xssh.ClientConfig{
		NodeID: "test", Address: "127.0.0.1", Port: addr.Port,
		User: "test", AuthType: "password", Password: "test",
	}})
	connector.AcceptNewHostKey.Store(true)
	t.Cleanup(func() {
		if err := connector.CloseAll(); err != nil {
			t.Errorf("close connector: %v", err)
		}
	})
	client, err := connector.Connect(ctx, "test")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case conn := <-accepted:
		return client, conn
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return nil, nil
	}
}

func TestSSHTunnelsStopWithConnection(t *testing.T) {
	for _, mode := range []string{"local", "SOCKS5", "no command"} {
		for _, disconnect := range []bool{false, true} {
			t.Run(mode+"/disconnect="+strconv.FormatBool(disconnect), func(t *testing.T) {
				// Isolate each server's host key on Unix and Windows, including port reuse.
				home := t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("USERPROFILE", home)
				client, serverConn := newTunnelTestClient(t)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				options := &SshOptions{NoCmd: true}
				var localAddr string
				if mode != "no command" {
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					localAddr = listener.Addr().String()
					closeTunnelTestResource(t, listener)
					if mode == "local" {
						options.LocalForwards = []string{localAddr + ":127.0.0.1:20173"}
					} else {
						options.DynamicForward = localAddr
					}
				}
				group, err := options.startTunnels(ctx, cancel, client)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					cancel()
					// The expected disconnect error is asserted below.
					group.done.Wait()
				})
				if mode == "SOCKS5" {
					// An accepted client that never sends a SOCKS greeting must
					// not delay shutdown until the 15-second handshake timeout.
					conn, err := net.DialTimeout("tcp", localAddr, time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer closeTunnelTestResource(t, conn)
				}
				if disconnect {
					closeTunnelTestResource(t, serverConn)
				} else {
					cancel()
				}
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
					t.Fatal("SSH disconnect left -N waiting for Ctrl+C")
				}
				err = group.Close()
				if disconnect {
					if err == nil || !strings.Contains(err.Error(), "SSH connection lost") {
						t.Fatalf("tunnel close = %v, want connection loss", err)
					}
				} else if err != nil {
					t.Fatalf("normal cancellation failed: %v", err)
				}
				if localAddr != "" {
					listener, err := net.Listen("tcp", localAddr)
					if err != nil {
						t.Fatalf("forwarding port was not released: %v", err)
					}
					closeTunnelTestResource(t, listener)
				}
				closeTunnelTestResource(t, client)
			})
		}
	}
}
