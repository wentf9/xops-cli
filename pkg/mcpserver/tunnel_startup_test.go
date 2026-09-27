package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/mcpserver/tunnel"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"go.uber.org/goleak"
)

// Drop SSH packets without closing TCP, including channel-close acknowledgments.
type startupBlackholeConn struct {
	net.Conn
	drop      atomic.Bool
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *startupBlackholeConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if err != nil || !c.drop.Load() {
			return n, err
		}
	}
}

func (c *startupBlackholeConn) Write(p []byte) (int, error) {
	if c.drop.Load() {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *startupBlackholeConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return err
}

type startupBlackholeDialer struct{ created chan *startupBlackholeConn }

func (d *startupBlackholeDialer) Dial(network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return d.DialContext(ctx, network, address)
}

func (d *startupBlackholeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	root := &startupBlackholeConn{Conn: conn, closed: make(chan struct{})}
	select {
	case d.created <- root:
		return root, nil
	case <-ctx.Done():
		return nil, errors.Join(ctx.Err(), root.Close())
	}
}

func TestMCPTunnelCancelsBlackholedProxyStartup(t *testing.T) {
	for _, hops := range []int{1, 2} {
		for _, mode := range []string{"cancel", "deadline", "shutdown"} {
			t.Run(fmt.Sprintf("%d-jumps/%s", hops, mode), func(t *testing.T) { testBlackholedTunnelStartup(t, hops, mode) })
		}
	}
}

func newBlackholedTunnelRuntime(t *testing.T, hops int) (*Runtime, *tunnelSSHFixture, *startupBlackholeDialer) {
	t.Helper()
	f := startTunnelSSHFixture(t, hops, func(f *tunnelSSHFixture) {
		f.stallHost, f.handshakeSeen = "stall.invalid", make(chan struct{}, 1)
	})
	cfg := f.provider.Snapshot()
	cfg.Hosts.Set("stall", models.Host{Address: f.stallHost, Port: 22})
	node, ok := cfg.Nodes.Get("node")
	if !ok {
		t.Fatal("missing fixture node")
	}
	node.HostRef = "stall"
	cfg.Nodes.Set("node", node)
	f.provider = config.NewProviderWithoutOpenSSH(cfg)
	r := newTunnelRuntime(t, f)
	if err := r.tunnels.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	dialer := &startupBlackholeDialer{created: make(chan *startupBlackholeConn, 1)}
	r.tunnels = tunnel.New(r.ctx, func(ctx context.Context, spec tunnel.Spec, ready func(string) bool, report func(error)) error {
		connector := adapter.NewConnectorWithAdapterOptions(r.tunnelProvider, []adapter.Option{adapter.WithNonInteractive(true)}, ssh.WithDialer(dialer))
		return runMCPSSHTunnel(ctx, connector, spec, ready, report)
	}, r.auditTunnel)
	return r, f, dialer
}

func startBlackholedTunnelRequest(t *testing.T, r *Runtime, dialer *startupBlackholeDialer, mode string) (*startupBlackholeConn, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	var ctx context.Context
	var cancel context.CancelFunc
	if mode == "deadline" {
		ctx, cancel = context.WithTimeout(t.Context(), time.Second)
	} else {
		ctx, cancel = context.WithCancel(t.Context())
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		// Cancellation can return either the terminal record or a call error;
		// the assertions below inspect the task's final state and owned socket.
		if _, _, err := r.createTunnel(ctx, nil, CreateTunnelInput{RequestID: "startup", NodeID: "node", Mode: "local", TargetHost: "127.0.0.1", TargetPort: 80}); err != nil && ctx.Err() == nil && r.ctx.Err() == nil {
			t.Error(err)
		}
	}()
	var root *startupBlackholeConn
	// On regression, release the physical socket before Runtime's cleanup so
	// a failing assertion cannot leave the test process deadlocked.
	t.Cleanup(func() {
		cancel()
		if root != nil {
			closeTunnelFixtureResource(t, root)
		}
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("create call did not return")
		}
	})
	select {
	case root = <-dialer.created:
	case <-time.After(3 * time.Second):
		t.Fatal("root connection not dialed")
	}
	return root, cancel, finished
}

func testBlackholedTunnelStartup(t *testing.T, hops int, mode string) {
	t.Helper()
	t.Cleanup(func() { goleak.VerifyNone(t) })
	r, f, dialer := newBlackholedTunnelRuntime(t, hops)
	root, cancel, finished := startBlackholedTunnelRequest(t, r, dialer, mode)
	select {
	case <-f.handshakeSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("downstream SSH handshake not reached")
	}
	root.drop.Store(true)
	var shutdown chan error
	wantState := "failed"
	switch mode {
	case "cancel":
		cancel()
	case "shutdown":
		wantState = "stopped"
		shutdown = make(chan error, 1)
		go func() { shutdown <- r.Close() }()
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("create call hung")
	}
	records := r.tunnels.List("", "")
	if len(records) != 1 {
		t.Fatalf("records: %+v", records)
	}
	status := waitTunnelState(t, r, records[0].TunnelID, wantState)
	if wantState == "failed" && status.Error == "" {
		t.Fatal("startup cancellation was not reported")
	}
	select {
	case <-root.closed:
	case <-time.After(time.Second):
		t.Fatal("partial ProxyJump transport was not released")
	}
	if shutdown != nil {
		select {
		case err := <-shutdown:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("runtime shutdown hung")
		}
	}
}
