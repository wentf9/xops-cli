package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Limit reads below the SSH packet layer. A single channel packet takes longer
// than the probe timeout to arrive, with the keepalive reply queued behind it.
// Counting only complete channel reads would still incorrectly drop this link.
type slowKeepaliveConn struct {
	net.Conn
	ctx  context.Context
	slow atomic.Bool
}

func (c *slowKeepaliveConn) Read(p []byte) (int, error) {
	if c.slow.Load() {
		timer := time.NewTimer(5 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-c.ctx.Done():
			return 0, c.ctx.Err()
		case <-timer.C:
		}
		p = p[:min(len(p), 256)]
	}
	return c.Conn.Read(p)
}

type slowKeepaliveDialer struct {
	ctx  context.Context
	conn *slowKeepaliveConn
}

func (d *slowKeepaliveDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(d.ctx, network, addr)
}

func (d *slowKeepaliveDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	d.conn = &slowKeepaliveConn{Conn: conn, ctx: d.ctx}
	return d.conn, nil
}

func newCongestedKeepaliveClient(t *testing.T, payload []byte) (*Client, *slowKeepaliveConn, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	listener, cfg := startKeepAliveTestSSHServer(t)
	ready := make(chan struct{})
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer closeTestResource(t, conn)
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
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
		server, channels, requests, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			if ctx.Err() == nil {
				t.Error(err)
			}
			return
		}
		defer closeTestResource(t, server)
		var next ssh.NewChannel
		select {
		case next = <-channels:
			if next == nil {
				return
			}
		case <-ctx.Done():
			return
		}
		if next.ChannelType() != "direct-tcpip" {
			t.Errorf("channel type = %s, want direct-tcpip", next.ChannelType())
			return
		}
		channel, channelRequests, err := next.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		var workers sync.WaitGroup
		workers.Go(func() { ssh.DiscardRequests(channelRequests) })
		defer workers.Wait()
		defer closeTestResource(t, channel)
		close(ready)
		for request := range requests {
			if len(payload) > 0 {
				if _, err := channel.Write(payload); err != nil {
					return // The pre-fix client closes in the middle of this packet.
				}
				payload = nil
			}
			if err := request.Reply(false, nil); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		closeTestResource(t, listener)
		<-serverDone
	})
	dialer := &slowKeepaliveDialer{ctx: ctx}
	address := listener.Addr().(*net.TCPAddr)
	connector := newTestConnector(&mockConfigStore{cfg: &ClientConfig{
		NodeID: "congested", Address: "127.0.0.1", Port: address.Port,
		User: "test", AuthType: "password", Password: "test",
	}}, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { closePlanConnector(t, connector) })
	client, err := connector.Connect(ctx, "congested")
	if err != nil {
		t.Fatal(err)
	}
	return client, dialer.conn, ready
}

func TestKeepAliveCongestedLocalForward(t *testing.T) {
	for _, mode := range []string{"wait", "periodic"} {
		t.Run(mode, func(t *testing.T) {
			payload := bytes.Repeat([]byte("low bandwidth tunnel\n"), 1600)
			client, transport, ready := newCongestedKeepaliveClient(t, payload)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			forward, err := client.LocalForward(ctx, "127.0.0.1:0", "127.0.0.1:20173")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				cancel()
				if err := forward.Wait(); err != nil {
					t.Error(err)
				}
			})
			conn, err := net.DialTimeout("tcp", forward.Addr().String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer closeTestResource(t, conn)
			if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-ready:
			case <-time.After(time.Second):
				t.Fatal("forwarding channel not opened")
			}
			transport.slow.Store(true)
			done := make(chan error, 1)
			monitorDone := make(chan struct{})
			go func() {
				defer close(monitorDone)
				if mode == "wait" {
					done <- client.wait(ctx, 30*time.Millisecond, 150*time.Millisecond)
					return
				}
				<-startKeepAlive(ctx, client.sshClient, 30*time.Millisecond, 150*time.Millisecond, func(err error) {
					done <- err
				}, client.Interrupt)
			}()
			t.Cleanup(func() { cancel(); <-monitorDone })
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, received); err != nil {
				select {
				case monitorErr := <-done:
					t.Fatalf("active tunnel was interrupted: %v (read: %v)", monitorErr, err)
				case <-time.After(time.Second):
					t.Fatalf("read forwarded payload: %v", err)
				}
			}
			if !bytes.Equal(received, payload) {
				t.Fatal("forwarded payload corrupted")
			}
			select {
			case err := <-done:
				t.Fatalf("monitor stopped during active forwarding: %v", err)
			default:
			}
			cancel()
			select {
			case <-monitorDone:
			case <-time.After(time.Second):
				t.Fatal("monitor did not stop after cancellation")
			}
			if mode == "wait" {
				if err := <-done; err != nil {
					t.Fatal(fmt.Errorf("cancel active tunnel: %w", err))
				}
			}
		})
	}
}

func TestKeepAliveJumpTrafficDoesNotHideStalledTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	server, address := newReconnectSSHServer(t, ctx, 1)
	store := &mockProxyJumpStore{cfgs: make(map[string]*ClientConfig)}
	for index := range 2 {
		name := fmt.Sprintf("node-%d", index)
		store.cfgs[name] = &ClientConfig{
			NodeID: name, Address: "127.0.0.1", Port: address.Port,
			User: "test", AuthType: "password", Password: "test",
		}
	}
	store.cfgs["node-1"].ProxyJump = "node-0"
	connector := newTestConnector(store, WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { closePlanConnector(t, connector) })
	client, err := connector.Connect(ctx, "node-1")
	if err != nil {
		t.Fatal(err)
	}
	jump, ok := connector.clients.Get("node-0")
	if !ok {
		t.Fatal("jump client missing")
	}
	server.stall.Store(true)
	var replies atomic.Int32
	jumpDone := make(chan struct{})
	go func() {
		defer close(jumpDone)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := probeWithTimeoutAndInterrupt(ctx, jump.SSHClient, time.Second, jump.interrupt); err != nil {
					return // Target timeout interrupts the shared physical transport.
				}
				replies.Add(1)
			}
		}
	}()
	t.Cleanup(func() { cancel(); <-jumpDone })
	done := runActivityTestMonitor(ctx, client, "wait", 30*time.Millisecond, 150*time.Millisecond)
	select {
	case err := <-done:
		if !errors.Is(err, errKeepaliveTimeout) {
			t.Fatalf("stalled target wait = %v, want receive timeout", err)
		}
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("jump traffic kept the stalled target alive")
	}
	if got := replies.Load(); got < 2 {
		t.Fatalf("jump replied %d times, want ongoing traffic during target probe", got)
	}
}
