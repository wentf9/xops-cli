package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Dropping bytes after authentication leaves the peer and TCP connection open,
// reproducing a lost network without letting a peer close acknowledgement through.
type blackholeProxyConn struct {
	net.Conn
	drop      atomic.Bool
	writeSeen chan struct{}
	writeOnce sync.Once
}

func (c *blackholeProxyConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if err != nil || !c.drop.Load() {
			return n, err
		}
	}
}
func (c *blackholeProxyConn) Write(p []byte) (int, error) {
	if c.drop.Load() {
		c.writeOnce.Do(func() { close(c.writeSeen) })
		return len(p), nil
	}
	return c.Conn.Write(p)
}

type blackholeProxyDialer struct{ conn *blackholeProxyConn }

func (d *blackholeProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *blackholeProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	d.conn = &blackholeProxyConn{Conn: conn, writeSeen: make(chan struct{})}
	return d.conn, nil
}

// Nested SSH handshakes run over genuine direct-tcpip channels. Only the test
// server's channel-to-net.Conn adapter is synthetic; the client's proxy dialer,
// transport, authentication, pool, keepalive and waiter are production code.
type nestedServerConn struct {
	ssh.Channel
	addr net.Addr
}

func (c nestedServerConn) LocalAddr() net.Addr              { return c.addr }
func (c nestedServerConn) RemoteAddr() net.Addr             { return c.addr }
func (c nestedServerConn) SetDeadline(time.Time) error      { return nil }
func (c nestedServerConn) SetReadDeadline(time.Time) error  { return nil }
func (c nestedServerConn) SetWriteDeadline(time.Time) error { return nil }

func serveNestedWaitTest(t *testing.T, ctx context.Context, conn net.Conn, cfg *ssh.ServerConfig) {
	t.Helper()
	defer closeTestResource(t, conn)
	server, channels, requests, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		if ctx.Err() == nil {
			t.Errorf("nested handshake: %v", err)
		}
		return
	}
	defer closeTestResource(t, server)
	var workers sync.WaitGroup
	workers.Go(func() { ssh.DiscardRequests(requests) })
	for next := range channels {
		if next.ChannelType() != "direct-tcpip" {
			if err := next.Reject(ssh.UnknownChannelType, "unsupported"); err != nil && ctx.Err() == nil {
				t.Error(err)
			}
			continue
		}
		channel, reqs, err := next.Accept()
		if err != nil {
			if ctx.Err() == nil {
				t.Error(err)
			}
			continue
		}
		workers.Go(func() { ssh.DiscardRequests(reqs) })
		workers.Go(func() { serveNestedWaitTest(t, ctx, nestedServerConn{Channel: channel, addr: conn.LocalAddr()}, cfg) })
	}
	workers.Wait()
}

func newBlackholeProxyClient(t *testing.T, hops int) (*Connector, *Client, *blackholeProxyDialer) {
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
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
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
		serveNestedWaitTest(t, ctx, conn, cfg)
	}()
	t.Cleanup(func() { cancel(); closeTestResource(t, listener); <-done })
	address := listener.Addr().(*net.TCPAddr)
	store := &mockProxyJumpStore{cfgs: make(map[string]*ClientConfig)}
	for index := 0; index <= hops; index++ {
		name := fmt.Sprintf("node-%d", index)
		node := &ClientConfig{NodeID: name, Address: "127.0.0.1", Port: address.Port, User: "test", AuthType: "password", Password: "test"}
		if index > 0 {
			node.ProxyJump = fmt.Sprintf("node-%d", index-1)
		}
		store.cfgs[name] = node
	}
	dialer := &blackholeProxyDialer{}
	connector := NewConnector(store, WithDialer(dialer), WithInteractionHandler(&mockUI{}))
	t.Cleanup(func() {
		if dialer.conn != nil {
			closeTestResource(t, dialer.conn)
		}
		if err := connector.CloseAll(); err != nil {
			t.Errorf("close connector: %v", err)
		}
	})
	name := fmt.Sprintf("node-%d", hops)
	initialClient, err := connector.Connect(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the cached wrapper too: it must retain the same interrupt path.
	client, err := connector.Connect(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	root, ok := client.rootConn.(*physicalSSHConn)
	if !ok || root.Conn != dialer.conn || initialClient.rootConn != root {
		t.Fatal("fresh or cached client lost the physical transport")
	}
	return connector, client, dialer
}

func TestClientWaitBlackholedProxyJump(t *testing.T) {
	for _, hops := range []int{1, 2} {
		for _, mode := range []string{"cancel idle", "cancel probe", "probe timeout"} {
			t.Run(fmt.Sprintf("hops=%d/%s", hops, mode), func(t *testing.T) {
				// A reused ephemeral port must not inherit another fixture's host key.
				home := t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("USERPROFILE", home)
				_, client, dialer := newBlackholeProxyClient(t, hops)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				forward, err := client.LocalForward(ctx, "127.0.0.1:0", "127.0.0.1:20173")
				if err != nil {
					t.Fatal(err)
				}
				dialer.conn.drop.Store(true)
				interval, timeout := 5*time.Millisecond, 20*time.Millisecond
				if mode == "cancel idle" {
					interval = time.Hour
				}
				if mode == "cancel probe" {
					timeout = time.Hour
				}
				done := make(chan struct{})
				var waitErr error
				go func() { defer close(done); waitErr = client.wait(ctx, interval, timeout) }()
				t.Cleanup(func() {
					cancel()
					// Also release the pre-fix deadlock, so a failing test does not leak.
					closeTestResource(t, dialer.conn)
					<-done
					if err := forward.Wait(); err != nil {
						t.Errorf("close forward: %v", err)
					}
				})
				if mode == "cancel probe" {
					select {
					case <-dialer.conn.writeSeen:
					case <-time.After(time.Second):
						t.Fatal("probe did not enter blackholed transport")
					}
				}
				if mode != "probe timeout" {
					cancel()
				}
				select {
				case <-done:
					if mode == "probe timeout" {
						if !errors.Is(waitErr, errKeepaliveTimeout) {
							t.Fatalf("wait = %v, want probe timeout", waitErr)
						}
					} else if waitErr != nil {
						t.Fatalf("cancel wait: %v", waitErr)
					}
				case <-time.After(500 * time.Millisecond):
					t.Fatal("waiter did not exit before connector cleanup")
				}
			})
		}
	}
}

// Keep the fixture's connection interface assertion close to its implementation.
var _ net.Conn = (*blackholeProxyConn)(nil)

func TestClientWaitClosedTargetPreservesHealthyJump(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	connector, client, _ := newBlackholeProxyClient(t, 2)
	closeTestResource(t, client)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if err := client.Wait(ctx); err == nil {
		t.Fatal("expected closed target to report connection loss")
	}
	jump, ok := connector.clients.Get("node-1")
	if !ok {
		t.Fatal("jump client missing")
	}
	if err := probeWithTimeoutAndInterrupt(ctx, jump.SSHClient, time.Second, jump.interrupt); err != nil {
		t.Fatalf("closing target interrupted healthy jump: %v", err)
	}
	if _, err := connector.Connect(ctx, "node-2"); err != nil {
		t.Fatalf("replacing closed target over healthy jump: %v", err)
	}
}

func TestPoolCleanupBlackholedProxyJump(t *testing.T) {
	for _, mode := range []string{"close all", "keepalive timeout", "keepalive cancel"} {
		t.Run(mode, func(t *testing.T) {
			// Each server generates a new key, even if its port was used before.
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			connector, _, dialer := newBlackholeProxyClient(t, 2)
			dialer.conn.drop.Store(true)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode != "close all" {
				timeout := 20 * time.Millisecond
				if mode == "keepalive cancel" {
					timeout = time.Hour
				}
				connector.EnableKeepAlive(ctx, 5*time.Millisecond, timeout)
				target, ok := connector.clients.Get("node-2")
				if !ok {
					t.Fatal("target missing")
				}
				connector.startKeepAliveFor("node-2", target)
				entry, ok := connector.keepAlives.Get("node-2")
				if !ok {
					t.Fatal("keepalive missing")
				}
				t.Cleanup(func() { closeTestResource(t, dialer.conn); <-entry.done })
				select {
				case <-dialer.conn.writeSeen:
				case <-time.After(time.Second):
					t.Fatal("probe not sent")
				}
				if mode == "keepalive cancel" {
					cancel()
				}
				select {
				case <-entry.done:
				case <-time.After(time.Second):
					t.Fatal("pooled keepalive did not exit")
				}
			}
			done := make(chan error, 1)
			go func() { done <- connector.CloseAll() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("close pool: %v", err)
				}
			case <-time.After(time.Second):
				closeTestResource(t, dialer.conn)
				<-done
				t.Fatal("pool close blocked on nested transport")
			}
		})
	}
}
