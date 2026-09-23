package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type reconnectSSHServer struct {
	t          *testing.T
	ctx        context.Context
	cfg        *ssh.ServerConfig
	stall      atomic.Bool
	stallDepth int
	roots      atomic.Int32
}

func (s *reconnectSSHServer) serve(conn net.Conn, generation int32, depth int) {
	defer closeTestResource(s.t, conn)
	server, channels, requests, err := ssh.NewServerConn(conn, s.cfg)
	if err != nil {
		if s.ctx.Err() == nil {
			s.t.Errorf("nested handshake: %v", err)
		}
		return
	}
	defer closeTestResource(s.t, server)
	var workers sync.WaitGroup
	workers.Go(func() {
		for request := range requests {
			// Only the first connection's selected downstream server stops answering.
			// Its jump hosts keep answering, and replacement connections are healthy.
			if generation == 1 && depth == s.stallDepth && s.stall.Load() {
				continue
			}
			if request.WantReply {
				if err := request.Reply(false, nil); err != nil && s.ctx.Err() == nil {
					return
				}
			}
		}
	})
	for next := range channels {
		if next.ChannelType() != "direct-tcpip" {
			if err := next.Reject(ssh.UnknownChannelType, "unsupported"); err != nil && s.ctx.Err() == nil {
				s.t.Error(err)
			}
			continue
		}
		channel, reqs, err := next.Accept()
		if err != nil {
			continue
		}
		workers.Go(func() { ssh.DiscardRequests(reqs) })
		workers.Go(func() { s.serve(nestedServerConn{Channel: channel, addr: conn.LocalAddr()}, generation, depth+1) })
	}
	workers.Wait()
}

func newReconnectSSHServer(t *testing.T, ctx context.Context, stallDepth int) (*reconnectSSHServer, *net.TCPAddr) {
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
	server := &reconnectSSHServer{t: t, ctx: ctx, cfg: cfg, stallDepth: stallDepth}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var workers sync.WaitGroup
		defer workers.Wait()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			generation := server.roots.Add(1)
			workers.Go(func() {
				defer closeTestResource(t, conn)
				if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Error(err)
					return
				}
				closed := make(chan struct{})
				stop := context.AfterFunc(ctx, func() { defer close(closed); closeTestResource(t, conn) })
				defer func() {
					if !stop() {
						<-closed
					}
				}()
				server.serve(conn, generation, 0)
			})
		}
	}()
	t.Cleanup(func() { closeTestResource(t, listener); <-done })
	return server, listener.Addr().(*net.TCPAddr)
}

func TestConnectorRebuildsJumpChainAfterDownstreamTimeout(t *testing.T) {
	for _, tc := range []struct{ hops, stallDepth, callers int }{
		{1, 1, 1}, {2, 2, 1}, {2, 1, 1}, {2, 2, 8},
	} {
		t.Run(fmt.Sprintf("hops=%d/stall=%d/callers=%d", tc.hops, tc.stallDepth, tc.callers), func(t *testing.T) {
			// Share known_hosts within this reconnect scenario, not across server fixtures.
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			server, address := newReconnectSSHServer(t, ctx, tc.stallDepth)
			store := &mockProxyJumpStore{cfgs: make(map[string]*ClientConfig)}
			for index := 0; index <= tc.hops; index++ {
				name := fmt.Sprintf("node-%d", index)
				cfg := &ClientConfig{NodeID: name, Address: "127.0.0.1", Port: address.Port, User: "test", AuthType: "password", Password: "test"}
				if index > 0 {
					cfg.ProxyJump = fmt.Sprintf("node-%d", index-1)
				}
				store.cfgs[name] = cfg
			}
			connector := NewConnector(store, WithInteractionHandler(&mockUI{}))
			t.Cleanup(func() {
				if err := connector.CloseAll(); err != nil {
					t.Error(err)
				}
			})
			connector.EnableKeepAlive(ctx, time.Hour, 30*time.Millisecond)
			name := fmt.Sprintf("node-%d", tc.hops)
			initial, err := connector.Connect(ctx, name)
			if err != nil {
				t.Fatal(err)
			}
			server.stall.Store(true)
			type result struct {
				client *Client
				err    error
			}
			results := make(chan result, tc.callers)
			start := make(chan struct{})
			var workers sync.WaitGroup
			for range tc.callers {
				workers.Go(func() { <-start; client, err := connector.Connect(ctx, name); results <- result{client, err} })
			}
			close(start)
			workers.Wait()
			close(results)
			for result := range results {
				if result.err != nil {
					t.Errorf("replace cached downstream: %v", result.err)
					continue
				}
				if result.client.rootConn == initial.rootConn {
					t.Error("replacement reused invalidated root")
				}
				if err := probeWithTimeoutAndInterrupt(ctx, result.client.sshClient, time.Second, result.client.Interrupt); err != nil {
					t.Errorf("replacement unusable: %v", err)
				}
			}
			if roots := server.roots.Load(); roots != 2 {
				t.Errorf("physical connections = %d, want original plus one replacement", roots)
			}
		})
	}
}
