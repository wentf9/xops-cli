package runtime

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
	config "github.com/wentf9/xops-cli/core/testutil/mcphost"
	"github.com/wentf9/xops-cli/core/testutil/mcphost/models"
	cryptossh "golang.org/x/crypto/ssh"
)

// This SSH fixture implements both forwarding directions, nested jump hosts,
// command sessions and in-memory SFTP over actual loopback sockets.
type tunnelSSHFixture struct {
	ctx           context.Context
	provider      *config.Provider
	address       string
	blockRemote   atomic.Bool
	remoteSeen    chan struct{}
	stallHost     string // configured before serving clients
	handshakeSeen chan struct{}
	mu            sync.Mutex
	connections   map[net.Conn]bool
}

func tunnelFixtureProvider(t *testing.T, address string, hops int) *config.Provider {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	cfg := runtimeTestProvider("node").Snapshot()
	cfg.Hosts.Set("host", models.Host{Address: host, Port: uint16(port)})
	cfg.Identities.Set("identity", models.Identity{User: "fixture", AuthType: "password", Password: "fixture-only"})
	jump := ""
	for i := range hops {
		id := "jump" + strconv.Itoa(i)
		cfg.Nodes.Set(id, models.Node{HostRef: "host", IdentityRef: "identity", ProxyJump: jump})
		jump = id
	}
	cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "identity", ProxyJump: jump, Alias: []string{"alias"}})
	return config.NewProviderWithoutOpenSSH(cfg)
}

func startTunnelSSHFixture(t *testing.T, hops int, configure ...func(*tunnelSSHFixture)) *tunnelSSHFixture {
	t.Helper()
	home := isolateMCPTestEnvironment(t)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &cryptossh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &tunnelSSHFixture{address: listener.Addr().String(), remoteSeen: make(chan struct{}, 1), connections: make(map[net.Conn]bool)}
	for _, option := range configure {
		option(f)
	}
	f.provider = tunnelFixtureProvider(t, f.address, hops)
	host, port, err := net.SplitHostPort(f.address)
	if err != nil {
		t.Fatal(err)
	}
	writeKnownHosts(t, home, host, port, signer.PublicKey())
	// testing cancels t.Context before running cleanup callbacks. Keep the
	// service alive until its own callback, after later-registered runtimes
	// have shut down, while retaining a timeout for every fixture worker.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Minute)
	f.ctx = ctx
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.connections[conn] = true
			f.mu.Unlock()
			workers.Go(func() {
				defer func() { f.mu.Lock(); delete(f.connections, conn); f.mu.Unlock() }()
				f.serve(t, ctx, conn, cfg)
			})
		}
	})
	t.Cleanup(func() { cancel(); closeTunnelFixtureResource(t, listener); workers.Wait() })
	return f
}

func TestTunnelSSHFixtureCleanupOrder(t *testing.T) {
	var fixture *tunnelSSHFixture
	t.Run("live tunnel at test exit", func(t *testing.T) {
		fixture = startTunnelSSHFixture(t, 0)
		r := newTunnelRuntime(t, fixture)
		record := seedTunnelListTask(t, r, "node", "cleanup-order")
		// testing cancels t.Context before invoking this callback. The SSH
		// service must still be alive while the runtime joins its workers.
		t.Cleanup(func() {
			if t.Context().Err() == nil {
				t.Error("test context was not canceled before cleanup")
			}
			if err := fixture.ctx.Err(); err != nil {
				t.Errorf("SSH fixture stopped before runtime cleanup: %v", err)
			}
			if err := r.Close(); err != nil {
				t.Error(err)
			}
			if status, err := r.tunnels.Status(record.TunnelID); err != nil || status.State != "stopped" {
				t.Errorf("cleanup state: %+v, %v", status, err)
			}
			if err := fixture.ctx.Err(); err != nil {
				t.Errorf("runtime cleanup stopped the SSH fixture: %v", err)
			}
		})
	})
	if fixture == nil || !errors.Is(fixture.ctx.Err(), context.Canceled) {
		t.Fatal("fixture cleanup did not cancel its context")
	}
}

func (f *tunnelSSHFixture) disconnect(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	conns := make([]net.Conn, 0, len(f.connections))
	for conn := range f.connections {
		conns = append(conns, conn)
	}
	f.mu.Unlock()
	for _, conn := range conns {
		closeTunnelFixtureResource(t, conn)
	}
}

func (f *tunnelSSHFixture) serve(t *testing.T, parent context.Context, raw net.Conn, cfg *cryptossh.ServerConfig) {
	defer closeTunnelFixtureResource(t, raw)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stopClose := context.AfterFunc(ctx, func() { closeTunnelFixtureResource(t, raw) })
	defer stopClose()
	if err := raw.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Error(err)
		return
	}
	server, channels, requests, err := cryptossh.NewServerConn(raw, cfg)
	if err != nil {
		return
	} // Canceled setup may close a jump before handshake.
	defer closeTunnelFixtureResource(t, server)
	var workers sync.WaitGroup
	defer workers.Wait()
	defer cancel()
	workers.Go(func() { f.serveRequests(t, ctx, server, requests, &workers) })
	handlers := pkgsftp.InMemHandler()
	for incoming := range channels {
		workers.Go(func() {
			switch incoming.ChannelType() {
			case "direct-tcpip":
				f.serveDirect(t, ctx, incoming)
			case "session":
				ch, reqs, err := incoming.Accept()
				if err != nil {
					return
				}
				serveTunnelSession(t, ctx, ch, reqs, handlers)
			default:
				if err := incoming.Reject(cryptossh.UnknownChannelType, "unsupported"); err != nil {
					tunnelFixtureError(t, ctx, err)
				}
			}
		})
	}
}

type tunnelWireAddress struct {
	Host string
	Port uint32
}
type tunnelWireChannel struct {
	Host       string
	Port       uint32
	OriginHost string
	OriginPort uint32
}

func (f *tunnelSSHFixture) serveRequests(t *testing.T, ctx context.Context, server *cryptossh.ServerConn, requests <-chan *cryptossh.Request, workers *sync.WaitGroup) {
	listeners := make(map[string]net.Listener)
	defer func() {
		for _, listener := range listeners {
			closeTunnelFixtureResource(t, listener)
		}
	}()
	for req := range requests {
		var address tunnelWireAddress
		var payload []byte
		accepted := false
		switch req.Type {
		case "tcpip-forward":
			select {
			case f.remoteSeen <- struct{}{}:
			default:
			}
			if f.blockRemote.Load() {
				<-ctx.Done()
				return
			}
			if err := cryptossh.Unmarshal(req.Payload, &address); err != nil {
				t.Error(err)
				return
			}
			listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(address.Host, strconv.Itoa(int(address.Port))))
			if err == nil {
				address.Port = uint32(listener.Addr().(*net.TCPAddr).Port)
				listeners[listener.Addr().String()] = listener
				payload, accepted = cryptossh.Marshal(struct{ Port uint32 }{address.Port}), true
				workers.Go(func() { serveTunnelRemote(t, ctx, server, listener, address, workers) })
			}
		case "cancel-tcpip-forward":
			if err := cryptossh.Unmarshal(req.Payload, &address); err != nil {
				t.Error(err)
				return
			}
			key := net.JoinHostPort(address.Host, strconv.Itoa(int(address.Port)))
			if listener := listeners[key]; listener != nil {
				closeTunnelFixtureResource(t, listener)
				delete(listeners, key)
				accepted = true
			}
		}
		if req.WantReply {
			if err := req.Reply(accepted, payload); err != nil {
				return
			}
		}
	}
}

func (f *tunnelSSHFixture) serveDirect(t *testing.T, ctx context.Context, incoming cryptossh.NewChannel) {
	var address tunnelWireChannel
	if err := cryptossh.Unmarshal(incoming.ExtraData(), &address); err != nil {
		t.Error(err)
		return
	}
	if f.stallHost != "" && address.Host == f.stallHost {
		f.stallHandshake(t, ctx, incoming)
		return
	}
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(address.Host, strconv.Itoa(int(address.Port))))
	if err != nil {
		if err := incoming.Reject(cryptossh.ConnectionFailed, "target unavailable"); err != nil {
			tunnelFixtureError(t, ctx, err)
		}
		return
	}
	defer closeTunnelFixtureResource(t, conn)
	ch, requests, err := incoming.Accept()
	if err != nil {
		return
	}
	defer closeTunnelFixtureResource(t, ch)
	relayTunnelFixture(t, ctx, ch, conn, requests)
}

// Read the client's SSH banner to prove the direct-tcpip channel has opened,
// then withhold the server banner. The parent SSH transport bounds this read
// and closes the channel when its context or physical connection ends.
func (f *tunnelSSHFixture) stallHandshake(t *testing.T, ctx context.Context, incoming cryptossh.NewChannel) {
	ch, requests, err := incoming.Accept()
	if err != nil {
		return
	}
	done := make(chan struct{})
	go func() { defer close(done); cryptossh.DiscardRequests(requests) }()
	defer func() { closeTunnelFixtureResource(t, ch); <-done }()
	var banner [256]byte
	if _, err := ch.Read(banner[:]); err != nil {
		return
	}
	select {
	case f.handshakeSeen <- struct{}{}:
	case <-ctx.Done():
		return
	}
	if _, err := io.Copy(io.Discard, ch); err != nil {
		tunnelFixtureError(t, ctx, err)
	}
}

func serveTunnelRemote(t *testing.T, ctx context.Context, server *cryptossh.ServerConn, listener net.Listener, address tunnelWireAddress, workers *sync.WaitGroup) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		workers.Go(func() {
			defer closeTunnelFixtureResource(t, conn)
			origin := conn.RemoteAddr().(*net.TCPAddr)
			ch, requests, err := server.OpenChannel("forwarded-tcpip", cryptossh.Marshal(tunnelWireChannel{address.Host, address.Port, origin.IP.String(), uint32(origin.Port)}))
			if err != nil {
				return
			}
			defer closeTunnelFixtureResource(t, ch)
			relayTunnelFixture(t, ctx, ch, conn, requests)
		})
	}
}

func relayTunnelFixture(t *testing.T, ctx context.Context, ch cryptossh.Channel, conn net.Conn, requests <-chan *cryptossh.Request) {
	if err := conn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Error(err)
		return
	}
	var workers sync.WaitGroup
	workers.Go(func() { cryptossh.DiscardRequests(requests) })
	stopClose := context.AfterFunc(ctx, func() { closeTunnelFixtureResource(t, conn); closeTunnelFixtureResource(t, ch) })
	defer stopClose()
	workers.Go(func() {
		if _, err := io.Copy(ch, conn); err != nil {
			tunnelFixtureError(t, ctx, err)
		}
		if err := ch.CloseWrite(); err != nil {
			tunnelFixtureError(t, ctx, err)
		}
	})
	if _, err := io.Copy(conn, ch); err != nil {
		tunnelFixtureError(t, ctx, err)
	}
	closeTunnelFixtureResource(t, conn)
	closeTunnelFixtureResource(t, ch)
	workers.Wait()
}

func tunnelFixtureError(t *testing.T, ctx context.Context, err error) {
	t.Helper()
	if ctx.Err() == nil && !expectedTunnelFixtureClose(err) {
		t.Error(err)
	}
}

func expectedTunnelFixtureClose(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) || platformTunnelFixtureClose(err)
}

func closeTunnelFixtureResource(t *testing.T, resource io.Closer) {
	t.Helper()
	if err := resource.Close(); !expectedTunnelFixtureClose(err) {
		t.Error(err)
	}
}

func serveTunnelSession(t *testing.T, ctx context.Context, ch cryptossh.Channel, requests <-chan *cryptossh.Request, handlers pkgsftp.Handlers) {
	defer closeTunnelFixtureResource(t, ch)
	for req := range requests {
		if req.Type == "subsystem" {
			if err := req.Reply(true, nil); err != nil {
				return
			}
			s := pkgsftp.NewRequestServer(ch, handlers)
			err := s.Serve()
			closeTunnelFixtureResource(t, s)
			tunnelFixtureError(t, ctx, err)
			return
		}
		if req.Type == "exec" {
			if err := req.Reply(true, nil); err != nil {
				return
			}
			if _, err := ch.Write([]byte("fixture command ok\n")); err != nil {
				return
			}
			if _, err := ch.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{0})); err != nil {
				tunnelFixtureError(t, ctx, err)
			}
			return
		}
		if req.WantReply {
			if err := req.Reply(false, nil); err != nil {
				return
			}
		}
	}
}
