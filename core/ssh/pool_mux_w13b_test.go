package ssh

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func startW13bExternalControlMaster(
	t *testing.T,
	ctx context.Context,
	targetSrv *keepAliveBarrierServer,
	sockPath string,
	jumpHost string,
) (*MuxServer, *modeSwitchConn) {
	t.Helper()
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)
	rawTCP, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", targetSrv.addr)
	if err != nil {
		t.Fatalf("dial target SSH server for external master: %v", err)
	}
	rootConn := newModeSwitchConn(rawTCP)
	sshCfg := &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	cConn, chans, reqs, err := cryptoSSH.NewClientConn(rootConn, targetSrv.addr, sshCfg)
	if err != nil {
		_ = rootConn.Close()
		t.Fatalf("ssh NewClientConn for external master: %v", err)
	}
	sshCli := cryptoSSH.NewClient(cConn, chans, reqs)

	srv, err := StartMuxServer(ctx, sshCli, MuxMasterOptions{
		Path:     sockPath,
		RootConn: rootConn,
		Target: TargetContext{
			Host:     tHost,
			Port:     tPort,
			User:     "fixture",
			JumpHost: jumpHost,
			Control: &ControlConfig{
				Master:  ControlMasterYes,
				Path:    sockPath,
				Persist: "yes",
			},
		},
		InitialActiveSessions: 0,
	})
	if err != nil {
		_ = rootConn.Close()
		_ = sshCli.Close()
		if errors.Is(err, ErrUnsupportedMuxPlatform) {
			t.Skipf("mux control socket unsupported on platform: %v", err)
		}
		t.Fatalf("StartMuxServer(%q): %v", sockPath, err)
	}
	t.Cleanup(func() {
		_ = rootConn.Close()
		_ = srv.Shutdown()
		select {
		case <-srv.Wait():
		case <-time.After(2 * time.Second):
		}
	})
	return srv, rootConn
}

type w13bCountingDialer struct {
	mu      sync.Mutex
	counts  map[string]int
	conns   []*modeSwitchConn
	onDial  func(addr string)
	wrapped Dialer
}

func newW13bCountingDialer() *w13bCountingDialer {
	return &w13bCountingDialer{
		counts:  make(map[string]int),
		wrapped: &net.Dialer{Timeout: 5 * time.Second},
	}
}

func (d *w13bCountingDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *w13bCountingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.onDial != nil {
		d.onDial(addr)
	}
	raw, err := d.wrapped.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	mc := newModeSwitchConn(raw)
	d.mu.Lock()
	d.counts[addr]++
	d.conns = append(d.conns, mc)
	d.mu.Unlock()
	return mc, nil
}

func (d *w13bCountingDialer) countFor(addr string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.counts[addr]
}

func (d *w13bCountingDialer) closeAll() {
	d.mu.Lock()
	conns := append([]*modeSwitchConn(nil), d.conns...)
	d.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func newW13bJumpMuxFixture(t *testing.T, ctx context.Context, suffix string) (
	bastionSrv *keepAliveBarrierServer,
	targetSrv *keepAliveBarrierServer,
	sockPath string,
	dialer *w13bCountingDialer,
	connector *Connector,
) {
	t.Helper()
	bastionSrv = newKeepAliveBarrierServer(t, ctx)
	targetSrv = newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)
	sockPath = filepath.Join(shortSocketDir(t), "w13b-"+suffix+".sock")

	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
		ctrls: map[string]*ControlConfig{
			"target": {Master: ControlMasterAuto, Path: sockPath},
		},
	}
	dialer = newW13bCountingDialer()
	connector = newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})
	return bastionSrv, targetSrv, sockPath, dialer, connector
}

func newW13bThreeHopFixture(t *testing.T, ctx context.Context) (*Connector, *w13bCountingDialer, []*keepAliveBarrierServer) {
	t.Helper()
	srv0 := newKeepAliveBarrierServer(t, ctx)
	srv1 := newKeepAliveBarrierServer(t, ctx)
	srv2 := newKeepAliveBarrierServer(t, ctx)
	h0, p0 := fixtureEndpoint(t, srv0.addr)
	h1, p1 := fixtureEndpoint(t, srv1.addr)
	h2, p2 := fixtureEndpoint(t, srv2.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"hop0": {
				NodeID: "hop0", Address: h0, Port: p0,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"hop1": {
				NodeID: "hop1", Address: h1, Port: p1,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "hop0",
			},
			"hop2": {
				NodeID: "hop2", Address: h2, Port: p2,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "hop1",
			},
		},
	}
	dialer := newW13bCountingDialer()
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	t.Cleanup(cancelKA)
	connector.EnableKeepAlive(kaCtx, 30*time.Second, 500*time.Millisecond)
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})
	return connector, dialer, []*keepAliveBarrierServer{srv0, srv1, srv2}
}

func newW13bBastionSiblingsFixture(t *testing.T, ctx context.Context) (
	connector *Connector,
	dialer *w13bCountingDialer,
	bastionSrv *keepAliveBarrierServer,
	bastionCli, target1Cli, target2Cli *Client,
) {
	t.Helper()
	bastionSrv = newKeepAliveBarrierServer(t, ctx)
	t1Srv := newKeepAliveBarrierServer(t, ctx)
	t2Srv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	t1Host, t1Port := fixtureEndpoint(t, t1Srv.addr)
	t2Host, t2Port := fixtureEndpoint(t, t2Srv.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target1": {
				NodeID: "target1", Address: t1Host, Port: t1Port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
			"target2": {
				NodeID: "target2", Address: t2Host, Port: t2Port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
	}
	dialer = newW13bCountingDialer()
	connector = newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	t.Cleanup(cancelKA)
	connector.EnableKeepAlive(kaCtx, 30*time.Second, 500*time.Millisecond)
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	var err error
	target1Cli, err = connector.Connect(ctx, "target1")
	if err != nil {
		t.Fatalf("Connect(target1): %v", err)
	}
	target2Cli, err = connector.Connect(ctx, "target2")
	if err != nil {
		t.Fatalf("Connect(target2): %v", err)
	}
	bastionCli, err = connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	assertPoolInvariantsAndCounts(t, "initial bastion+siblings", connector.pool, 3, 0)
	return connector, dialer, bastionSrv, bastionCli, target1Cli, target2Cli
}

func assertW13bDirectCloseOrInterrupt(t *testing.T, useInterrupt bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	srv := newKeepAliveBarrierServer(t, ctx)
	host, port := fixtureEndpoint(t, srv.addr)
	mode := "cls"
	if useInterrupt {
		mode = "int"
	}
	sockPath := filepath.Join(shortSocketDir(t), "w13b-d-"+mode+".sock")

	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"node": {
				NodeID: "node", Address: host, Port: port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
		},
		ctrls: map[string]*ControlConfig{
			"node": {Master: ControlMasterAuto, Path: sockPath, Persist: "yes"},
		},
	}
	dialer := newW13bCountingDialer()
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 30*time.Second, 500*time.Millisecond)
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	c1, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect(node): %v", err)
	}
	_, kaDone := c1.pooled.keepAliveState()
	master := waitActiveMaster(t, sockPath, "direct master")
	assertPoolInvariantsAndCounts(t, "initial direct", connector.pool, 1, 0)

	if useInterrupt {
		if err := c1.Interrupt(); err != nil {
			t.Fatalf("c1.Interrupt(): %v", err)
		}
	} else {
		if err := c1.Close(); err != nil {
			t.Fatalf("c1.Close(): %v", err)
		}
	}

	// Pool invariants must hold immediately after Close/Interrupt, with the
	// control socket synchronously unlinked and keepalive terminated.
	assertPoolInvariantsAndCounts(t, "post direct close/interrupt", connector.pool, 0, -1)
	assertKeepAliveStopped(t, "direct", kaDone)
	if socketPathExists(sockPath) {
		t.Fatalf("control socket %q remained on disk after Close/Interrupt", sockPath)
	}
	select {
	case <-master.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("attached MuxServer did not complete Shutdown after Close/Interrupt")
	}
	assertPoolInvariantsAndCounts(t, "post master drain", connector.pool, 0, 0)

	// Second Close/Interrupt must be an idempotent no-op.
	if err := c1.Close(); err != nil {
		t.Fatalf("second c1.Close(): %v", err)
	}
	if err := c1.Interrupt(); err != nil {
		t.Fatalf("second c1.Interrupt(): %v", err)
	}
	assertPoolInvariantsAndCounts(t, "post idempotent repeat", connector.pool, 0, 0)

	c2, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("reconnect Connect(node): %v", err)
	}
	if c2.pooled == c1.pooled {
		t.Fatal("expected reconnect to publish a fresh PooledClient")
	}
	execBarrierCheck(t, c2)
	assertPoolInvariantsAndCounts(t, "post direct reconnect", connector.pool, 1, 0)
}

func assertW13bJumpChildClosePreservesBastion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	connector, dialer, bastionSrv, bastionCli, target1Cli, target2Cli := newW13bBastionSiblingsFixture(t, ctx)
	_, t1Done := target1Cli.pooled.keepAliveState()

	if err := target1Cli.Close(); err != nil {
		t.Fatalf("target1Cli.Close(): %v", err)
	}
	assertKeepAliveStopped(t, "target1", t1Done)
	assertPoolInvariantsAndCounts(t, "post target1.Close", connector.pool, 2, 0)

	if isRootConnClosed(bastionCli.rootConn) {
		t.Fatal("closing jump child target1 closed shared bastion RootConn")
	}
	execBarrierCheck(t, bastionCli)
	execBarrierCheck(t, target2Cli)

	beforeBastionDials := dialer.countFor(bastionSrv.addr)
	rebuilt, err := connector.Connect(ctx, "target1")
	if err != nil {
		t.Fatalf("reconnect target1 after Close(): %v", err)
	}
	if got := dialer.countFor(bastionSrv.addr); got != beforeBastionDials {
		t.Fatalf("reconnecting target1 re-dialed healthy bastion: dials=%d want=%d", got, beforeBastionDials)
	}
	if rebuilt.pooled == target1Cli.pooled {
		t.Fatal("expected fresh target1 PooledClient after Close()")
	}
	execBarrierCheck(t, rebuilt)
	assertPoolInvariantsAndCounts(t, "post target1 rebuild", connector.pool, 3, 0)
}

func assertW13bJumpIntermediateCloseCascades(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	connector, _, _ := newW13bThreeHopFixture(t, ctx)
	hop2Cli, err := connector.Connect(ctx, "hop2")
	if err != nil {
		t.Fatalf("Connect(hop2): %v", err)
	}
	hop1Cli, err := connector.Connect(ctx, "hop1")
	if err != nil {
		t.Fatalf("Connect(hop1): %v", err)
	}
	hop0Cli, err := connector.Connect(ctx, "hop0")
	if err != nil {
		t.Fatalf("Connect(hop0): %v", err)
	}
	assertPoolInvariantsAndCounts(t, "initial 3-hop", connector.pool, 3, 0)
	_, hop1Done := hop1Cli.pooled.keepAliveState()
	_, hop2Done := hop2Cli.pooled.keepAliveState()

	if err := hop1Cli.Close(); err != nil {
		t.Fatalf("hop1Cli.Close(): %v", err)
	}
	assertKeepAliveStopped(t, "hop1", hop1Done)
	assertKeepAliveStopped(t, "hop2", hop2Done)
	assertPoolInvariantsAndCounts(t, "post hop1.Close", connector.pool, 1, 0)
	if isRootConnClosed(hop0Cli.rootConn) {
		t.Fatal("closing intermediate hop1 closed root hop0 RootConn")
	}
	execBarrierCheck(t, hop0Cli)
}

func assertW13bParentCloseAndChildInterruptCascade(t *testing.T, interruptChild bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	connector, _, _, bastionCli, target1Cli, target2Cli := newW13bBastionSiblingsFixture(t, ctx)
	_, bDone := bastionCli.pooled.keepAliveState()
	_, t1Done := target1Cli.pooled.keepAliveState()
	_, t2Done := target2Cli.pooled.keepAliveState()

	if interruptChild {
		if err := target1Cli.Interrupt(); err != nil {
			t.Fatalf("target1Cli.Interrupt(): %v", err)
		}
	} else {
		if err := bastionCli.Close(); err != nil {
			t.Fatalf("bastionCli.Close(): %v", err)
		}
	}
	assertKeepAliveStopped(t, "bastion", bDone)
	assertKeepAliveStopped(t, "target1", t1Done)
	assertKeepAliveStopped(t, "target2", t2Done)
	assertPoolInvariantsAndCounts(t, "post cascade close/interrupt", connector.pool, 0, 0)
	if !isRootConnClosed(bastionCli.rootConn) {
		t.Fatal("expected bastion RootConn to be marked closed")
	}

	// Reconnecting must cleanly rebuild the chain.
	rebuilt, err := connector.Connect(ctx, "target1")
	if err != nil {
		t.Fatalf("Connect(target1) after cascade: %v", err)
	}
	execBarrierCheck(t, rebuilt)
	assertPoolInvariantsAndCounts(t, "post cascade rebuild", connector.pool, 2, 0)
}

func assertW13bChildInterruptUnblocksWedgedBastion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	connector, dialer, _, bastionCli, target1Cli, target2Cli := newW13bBastionSiblingsFixture(t, ctx)
	_, bDone := bastionCli.pooled.keepAliveState()
	_, t1Done := target1Cli.pooled.keepAliveState()
	_, t2Done := target2Cli.pooled.keepAliveState()

	// Wedge writes on bastion's physical transport so synchronous child channel
	// close before physical RootConn abort would stall indefinitely.
	dialer.mu.Lock()
	if len(dialer.conns) == 0 {
		dialer.mu.Unlock()
		t.Fatal("expected bastion physical conn in dialer")
	}
	dialer.conns[0].wedgeWrite.Store(true)
	dialer.mu.Unlock()

	waitWithin(t, "target1Cli.Interrupt() over wedged bastion", 500*time.Millisecond, func() {
		if err := target1Cli.Interrupt(); err != nil {
			t.Errorf("target1Cli.Interrupt(): %v", err)
		}
	})
	assertKeepAliveStopped(t, "bastion", bDone)
	assertKeepAliveStopped(t, "target1", t1Done)
	assertKeepAliveStopped(t, "target2", t2Done)
	assertPoolInvariantsAndCounts(t, "post wedged interrupt", connector.pool, 0, 0)
}

func assertW13bRetiredClientCloseAndInterrupt(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	connector, _, _, bastionCli, target1Cli, target2Cli := newW13bBastionSiblingsFixture(t, ctx)

	// Retire target1 non-disruptively: target1 moves to p.retired, bastion + target2 stay active.
	connector.pool.Retire(ZeroHopDigest, target1Cli.pooled)
	assertPoolInvariantsAndCounts(t, "post Retire(target1)", connector.pool, 2, 0)
	if got := connector.pool.RetiredCount(); got != 1 {
		t.Fatalf("RetiredCount after Retire(target1) = %d, want 1", got)
	}

	// Closing an already-retired jump child must NOT corrupt p.retired, p.closing,
	// or disturb active bastion/target2.
	if err := target1Cli.Close(); err != nil {
		t.Fatalf("retired target1Cli.Close(): %v", err)
	}
	if err := target1Cli.Close(); err != nil {
		t.Fatalf("second retired target1Cli.Close(): %v", err)
	}
	assertPoolInvariantsAndCounts(t, "post retired target1.Close", connector.pool, 2, 0)
	if got := connector.pool.RetiredCount(); got != 1 {
		t.Fatalf("RetiredCount after retired Close = %d, want 1", got)
	}
	execBarrierCheck(t, bastionCli)
	execBarrierCheck(t, target2Cli)

	// Interrupting the retired jump child aborts the shared physical RootConn,
	// so active bastion + target2 MUST be detached from p.active while p.retired
	// remains intact and p.closing returns to 0.
	if err := target1Cli.Interrupt(); err != nil {
		t.Fatalf("retired target1Cli.Interrupt(): %v", err)
	}
	assertPoolInvariantsAndCounts(t, "post retired target1.Interrupt", connector.pool, 0, 0)
	if got := connector.pool.RetiredCount(); got != 1 {
		t.Fatalf("RetiredCount after retired Interrupt = %d, want 1", got)
	}

	// Repeating Interrupt on already-retired/detached client must be a clean no-op.
	if err := target1Cli.Interrupt(); err != nil {
		t.Fatalf("second retired target1Cli.Interrupt(): %v", err)
	}
	assertPoolInvariantsAndCounts(t, "post second retired Interrupt", connector.pool, 0, 0)

	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll(): %v", err)
	}
	if got := connector.pool.RetiredCount(); got != 0 {
		t.Fatalf("RetiredCount after CloseAll = %d, want 0", got)
	}
	assertPoolInvariantsAndCounts(t, "post CloseAll", connector.pool, 0, 0)
}

func assertW13bPoolState(t *testing.T, label string, pool *connPool, requireKA bool, wantActive, wantClosing int) {
	t.Helper()
	if err := pool.CheckInvariants(false); err != nil {
		t.Fatalf("%s CheckInvariants(false) failed: %v", label, err)
	}
	if requireKA {
		if err := pool.CheckInvariants(true); err != nil {
			t.Fatalf("%s CheckInvariants(true) failed: %v", label, err)
		}
	}
	if got := pool.Count(); got != wantActive {
		t.Fatalf("%s active count = %d, want %d", label, got, wantActive)
	}
	if wantClosing >= 0 {
		if got := pool.ClosingCount(); got != wantClosing {
			t.Fatalf("%s closing count = %d, want %d", label, got, wantClosing)
		}
	}
}

func assertW13bStandaloneMuxProxyCloseAndInterrupt(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	targetSrv := newKeepAliveBarrierServer(t, ctx)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)
	sockPath := filepath.Join(shortSocketDir(t), "w13b-standalone-mux.sock")
	startW13bExternalControlMaster(t, ctx, targetSrv, sockPath, "")

	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
		},
		ctrls: map[string]*ControlConfig{
			"target": {Master: ControlMasterAuto, Path: sockPath},
		},
	}
	dialer := newW13bCountingDialer()
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 30*time.Second, 500*time.Millisecond)
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	for _, useInterrupt := range []bool{false, true} {
		cli, err := connector.Connect(ctx, "target")
		if err != nil {
			t.Fatalf("Connect(target via standalone mux, interrupt=%v): %v", useInterrupt, err)
		}
		if !cli.IsMultiplexed() {
			t.Fatal("expected MUX_C_PROXY client")
		}
		if got := dialer.countFor(targetSrv.addr); got != 0 {
			t.Fatalf("standalone mux attach dialed target TCP %d times, want 0", got)
		}
		_, kaDone := cli.pooled.keepAliveState()
		execBarrierCheck(t, cli)
		assertW13bPoolState(t, "standalone mux active", connector.pool, true, 1, 0)

		if useInterrupt {
			if err := cli.Interrupt(); err != nil {
				t.Fatalf("standalone mux Interrupt(): %v", err)
			}
		} else {
			if err := cli.Close(); err != nil {
				t.Fatalf("standalone mux Close(): %v", err)
			}
		}
		if !errors.Is(cli.TransportError(), net.ErrClosed) {
			t.Fatalf("TransportError() = %v, want net.ErrClosed", cli.TransportError())
		}
		assertKeepAliveStopped(t, "standalone mux", kaDone)
		assertW13bPoolState(t, "standalone mux post close/interrupt", connector.pool, true, 0, 0)
	}
}

// TestP7W13b_C13_M1_CloseAndInterruptDetachPooledClientsAndPreserveInvariants
// verifies C13-M1 Part 1 across direct, jump-child, intermediate-hop, jump-parent,
// wedged-bastion, retired, and standalone MUX_C_PROXY pooled clients.
func TestP7W13b_C13_M1_CloseAndInterruptDetachPooledClientsAndPreserveInvariants(t *testing.T) {
	t.Run("direct_close", func(t *testing.T) {
		assertW13bDirectCloseOrInterrupt(t, false)
	})
	t.Run("direct_interrupt", func(t *testing.T) {
		assertW13bDirectCloseOrInterrupt(t, true)
	})
	t.Run("jump_child_close_preserves_bastion", assertW13bJumpChildClosePreservesBastion)
	t.Run("jump_intermediate_close_cascades", assertW13bJumpIntermediateCloseCascades)
	t.Run("jump_parent_close_cascades", func(t *testing.T) {
		assertW13bParentCloseAndChildInterruptCascade(t, false)
	})
	t.Run("jump_child_interrupt_detaches_root_and_siblings", func(t *testing.T) {
		assertW13bParentCloseAndChildInterruptCascade(t, true)
	})
	t.Run("jump_child_interrupt_unblocks_wedged_bastion", assertW13bChildInterruptUnblocksWedgedBastion)
	t.Run("retired_client_close_and_interrupt", assertW13bRetiredClientCloseAndInterrupt)
	t.Run("standalone_mux_proxy_close_and_interrupt", assertW13bStandaloneMuxProxyCloseAndInterrupt)
}

type w13bJumpMuxReattachCase struct {
	name               string
	sockSuffix         string
	checkBeforeConnect bool
	trigger            func(t *testing.T, ctx context.Context, targetSrv *keepAliveBarrierServer, sockPath string, master1 *MuxServer, masterRoot1 *modeSwitchConn, c1 *Client) *MuxServer
}

func runW13bJumpMuxReattachCase(t *testing.T, tc w13bJumpMuxReattachCase) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv, targetSrv, sockPath, dialer, connector := newW13bJumpMuxFixture(t, ctx, tc.sockSuffix)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	master1, masterRoot1 := startW13bExternalControlMaster(t, ctx, targetSrv, sockPath, "bastion")

	c1, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("initial Connect(target): %v", err)
	}
	if !c1.IsMultiplexed() {
		t.Fatal("expected c1 to attach via MUX_C_PROXY")
	}
	if got := dialer.countFor(bastionSrv.addr); got != 0 {
		t.Fatalf("initial attach dialed bastion %d times, want 0", got)
	}
	execBarrierCheck(t, c1)
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("initial CheckInvariants(false): %v", err)
	}

	activeMaster := tc.trigger(t, ctx, targetSrv, sockPath, master1, masterRoot1, c1)

	if tc.checkBeforeConnect {
		if err := connector.pool.CheckInvariants(false); err != nil {
			t.Fatalf("post-trigger CheckInvariants(false): %v", err)
		}
	}

	c2, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("re-attach Connect(target): %v", err)
	}
	if !c2.IsMultiplexed() {
		t.Fatal("expected c2 to re-attach via MUX_C_PROXY")
	}
	if c2.pooled == c1.pooled {
		t.Fatal("expected c2 to use a fresh PooledClient after re-attach")
	}
	if got := dialer.countFor(bastionSrv.addr); got != 0 {
		t.Fatalf("re-attach dialed bastion %d times, want 0", got)
	}
	execBarrierCheck(t, c2)
	assertW13bPoolState(t, "post re-attach", connector.pool, false, 1, 0)

	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	if activeMaster != nil {
		_ = activeMaster.Shutdown()
		select {
		case <-activeMaster.Wait():
		case <-time.After(2 * time.Second):
			t.Fatal("activeMaster did not shut down")
		}
	}
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "w13b jump mux reattach goroutines")
}

func assertW13bCachedBastionPreservedOnMuxClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv, targetSrv, sockPath, dialer, connector := newW13bJumpMuxFixture(t, ctx, "cached-bastion")
	startW13bExternalControlMaster(t, ctx, targetSrv, sockPath, "bastion")

	bastionCli, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	if got := dialer.countFor(bastionSrv.addr); got != 1 {
		t.Fatalf("bastion dials = %d, want 1", got)
	}

	for _, useInterrupt := range []bool{false, true} {
		c1, err := connector.Connect(ctx, "target")
		if err != nil {
			t.Fatalf("Connect(target, interrupt=%v): %v", useInterrupt, err)
		}
		if !c1.IsMultiplexed() {
			t.Fatal("expected MUX_C_PROXY target")
		}
		assertW13bPoolState(t, "bastion+mux target", connector.pool, false, 2, 0)

		if useInterrupt {
			if err := c1.Interrupt(); err != nil {
				t.Fatalf("c1.Interrupt(): %v", err)
			}
		} else {
			if err := c1.Close(); err != nil {
				t.Fatalf("c1.Close(): %v", err)
			}
		}
		// Only the MUX_C_PROXY target detaches; cached bastion remains healthy.
		assertW13bPoolState(t, "post mux close/interrupt with cached bastion", connector.pool, false, 1, 0)
		execBarrierCheck(t, bastionCli)
		if got := dialer.countFor(bastionSrv.addr); got != 1 {
			t.Fatalf("bastion dials after mux close/interrupt = %d, want 1", got)
		}
	}
}

// TestP7W13b_C13_M1_JumpChainedControlMasterReattachZeroBastionDials verifies
// C13-M1 end-to-end for jump-chained ControlMaster attachment: after c1.Close(),
// c1.Interrupt(), external ControlMaster restart, or direct raw RootConn closure,
// subsequent Connect("target") re-attaches to the live ControlMaster socket with
// bastionDialCount == 0 and pool.CheckInvariants(false) == nil.
func TestP7W13b_C13_M1_JumpChainedControlMasterReattachZeroBastionDials(t *testing.T) {
	cases := []w13bJumpMuxReattachCase{
		{
			name:               "after_client_close",
			sockSuffix:         "cls",
			checkBeforeConnect: true,
			trigger: func(t *testing.T, _ context.Context, _ *keepAliveBarrierServer, _ string, master1 *MuxServer, _ *modeSwitchConn, c1 *Client) *MuxServer {
				if err := c1.Close(); err != nil {
					t.Fatalf("c1.Close(): %v", err)
				}
				return master1
			},
		},
		{
			name:               "after_client_interrupt",
			sockSuffix:         "int",
			checkBeforeConnect: true,
			trigger: func(t *testing.T, _ context.Context, _ *keepAliveBarrierServer, _ string, master1 *MuxServer, _ *modeSwitchConn, c1 *Client) *MuxServer {
				if err := c1.Interrupt(); err != nil {
					t.Fatalf("c1.Interrupt(): %v", err)
				}
				return master1
			},
		},
		{
			name:               "after_external_master_restart",
			sockSuffix:         "rst",
			checkBeforeConnect: false, // External master EOF asynchronously closes c1's Unix socket; connectPlan must still re-attach via tryAttachTargetControlMaster.
			trigger: func(t *testing.T, ctx context.Context, targetSrv *keepAliveBarrierServer, sockPath string, master1 *MuxServer, masterRoot1 *modeSwitchConn, c1 *Client) *MuxServer {
				_ = masterRoot1.Close()
				_ = master1.Shutdown()
				select {
				case <-master1.Wait():
				case <-time.After(2 * time.Second):
					t.Fatal("master1 did not shut down")
				}
				// Wait for x/crypto/ssh mux.loop peer EOF to close c1's RootConn
				// asynchronously so this subtest deterministically exercises
				// connectPlan's isRootConnClosed(snapshot[0].RootConn) path.
				waitForCondition(t, 2*time.Second, func() bool {
					return isRootConnClosed(c1.pooled.RootConn)
				}, "expected peer EOF from master1 shutdown to close c1 RootConn")
				master2, _ := startW13bExternalControlMaster(t, ctx, targetSrv, sockPath, "bastion")
				return master2
			},
		},
		{
			name:               "after_raw_rootconn_closed_in_place",
			sockSuffix:         "raw",
			checkBeforeConnect: false, // Intentionally bypasses Client.Close to test connectPlan fallback.
			trigger: func(t *testing.T, _ context.Context, _ *keepAliveBarrierServer, _ string, master1 *MuxServer, _ *modeSwitchConn, c1 *Client) *MuxServer {
				if c1.rootConn == nil {
					t.Fatal("expected non-nil c1.rootConn")
				}
				if err := c1.rootConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Fatalf("raw c1.rootConn.Close(): %v", err)
				}
				return master1
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runW13bJumpMuxReattachCase(t, tc)
		})
	}

	t.Run("cached_bastion_preserved_on_mux_proxy_close_and_interrupt", assertW13bCachedBastionPreservedOnMuxClose)
}

// TestP7W13b_C13_L1_DigestClientConfigRawMatchesNewClientConfig verifies C13-L1:
// DigestClientConfig(rawCfg, parent) == DigestClientConfig(NewClientConfig(*rawCfg), parent)
// across negative/zero ports, unset/set OriginalProxyJump/HasOriginalProxyJump,
// bracketed/uppercase/whitespace hosts, mixed-case AuthType, and disabled ControlConfig.
func TestP7W13b_C13_L1_DigestClientConfigRawMatchesNewClientConfig(t *testing.T) {
	t.Parallel()

	parentDigest := DigestClientConfig(&ClientConfig{
		NodeID:  "bastion",
		Address: "10.0.0.1",
		Port:    2222,
		User:    "ops",
	}, ZeroHopDigest)

	t.Run("port_non_positive_clamped_to_default", func(t *testing.T) {
		want := DigestClientConfig(&ClientConfig{NodeID: "n1", Address: "10.0.0.2", Port: int(DefaultSSHPort)}, parentDigest)
		for _, port := range []int{-65535, -22, -1, 0, 22} {
			raw := &ClientConfig{NodeID: "n1", Address: "10.0.0.2", Port: port}
			gotRaw := DigestClientConfig(raw, parentDigest)
			gotNorm := DigestClientConfig(NewClientConfig(*raw), parentDigest)
			if !gotRaw.Equal(want) {
				t.Errorf("port=%d raw digest %s != default port 22 digest %s", port, gotRaw, want)
			}
			if !gotRaw.Equal(gotNorm) {
				t.Errorf("port=%d raw digest %s != NewClientConfig digest %s", port, gotRaw, gotNorm)
			}
		}
		if got2222 := DigestClientConfig(&ClientConfig{NodeID: "n1", Address: "10.0.0.2", Port: 2222}, parentDigest); got2222.Equal(want) {
			t.Fatal("port=2222 unexpectedly matched default port 22 digest")
		}
	})

	t.Run("original_proxy_jump_normalization_parity", func(t *testing.T) {
		eqPairs := []struct {
			name string
			a, b ClientConfig
		}{
			{
				name: "unset_inherits_proxy_jump",
				a:    ClientConfig{NodeID: "t", Address: "10.0.0.2", ProxyJump: "b1"},
				b:    ClientConfig{NodeID: "t", Address: "10.0.0.2", ProxyJump: "b1", OriginalProxyJump: "b1", HasOriginalProxyJump: true},
			},
			{
				name: "unset_ignores_stale_original_proxy_jump",
				a:    ClientConfig{NodeID: "t", Address: "10.0.0.2", ProxyJump: "b1", OriginalProxyJump: "stale-ignored", HasOriginalProxyJump: false},
				b:    ClientConfig{NodeID: "t", Address: "10.0.0.2", ProxyJump: "b1", OriginalProxyJump: "b1", HasOriginalProxyJump: true},
			},
			{
				name: "unset_empty_proxy_jump_clears_stale_original",
				a:    ClientConfig{NodeID: "t", Address: "10.0.0.2", ProxyJump: "", OriginalProxyJump: "stale-ignored", HasOriginalProxyJump: false},
				b:    ClientConfig{NodeID: "t", Address: "10.0.0.2", ProxyJump: "", OriginalProxyJump: "", HasOriginalProxyJump: true},
			},
		}
		for _, tc := range eqPairs {
			t.Run(tc.name, func(t *testing.T) {
				dA := DigestClientConfig(&tc.a, parentDigest)
				dB := DigestClientConfig(&tc.b, parentDigest)
				dNormA := DigestClientConfig(NewClientConfig(tc.a), parentDigest)
				if !dA.Equal(dB) || !dA.Equal(dNormA) {
					t.Fatalf("%s: raw=%s explicit=%s norm=%s (want all equal)", tc.name, dA, dB, dNormA)
				}
			})
		}

		// Explicit HasOriginalProxyJump=true with OriginalProxyJump != ProxyJump
		// MUST remain distinct from unset HasOriginalProxyJump=false.
		explicitEmpty := ClientConfig{NodeID: "t", Address: "10.0.0.2", ProxyJump: "b1", OriginalProxyJump: "", HasOriginalProxyJump: true}
		unsetEmpty := ClientConfig{NodeID: "t", Address: "10.0.0.2", ProxyJump: "b1", OriginalProxyJump: "", HasOriginalProxyJump: false}
		if DigestClientConfig(&explicitEmpty, parentDigest).Equal(DigestClientConfig(&unsetEmpty, parentDigest)) {
			t.Fatal("explicit empty OriginalProxyJump (HasOriginalProxyJump=true) collided with unset HasOriginalProxyJump=false")
		}
		if !DigestClientConfig(&explicitEmpty, parentDigest).Equal(DigestClientConfig(NewClientConfig(explicitEmpty), parentDigest)) {
			t.Fatal("explicitEmpty raw digest != NewClientConfig digest")
		}

		explicitOther := ClientConfig{NodeID: "t", Address: "10.0.0.2", ProxyJump: "b1", OriginalProxyJump: "orig-b", HasOriginalProxyJump: true}
		unsetOther := ClientConfig{NodeID: "t", Address: "10.0.0.2", ProxyJump: "b1", OriginalProxyJump: "orig-b", HasOriginalProxyJump: false}
		if DigestClientConfig(&explicitOther, parentDigest).Equal(DigestClientConfig(&unsetOther, parentDigest)) {
			t.Fatal("explicit distinct OriginalProxyJump collided with unset HasOriginalProxyJump=false")
		}
	})

	t.Run("combinatoric_raw_vs_NewClientConfig_equivalence", func(t *testing.T) {
		hosts := []string{"", "   ", "Example.COM", "  [EXAMPLE.COM]  ", "  [2001:0DB8::1]  ", "[127.0.0.1]", "[[bad]]"}
		ports := []int{-100, -1, 0, 22, 2222}
		authTypes := []string{"", "  KEY ", "PaSsWoRd", "auto"}
		jumps := []struct {
			pj, orig string
			hasOrig  bool
		}{
			{"", "", false},
			{"", "stale", false},
			{"", "", true},
			{"b1", "", false},
			{"b1", "stale", false},
			{"b1", "", true},
			{"b1", "orig-b", true},
		}
		controls := []*ControlConfig{
			nil,
			{},
			{Master: ControlMasterNo, Path: "NONE", Persist: "no", ImplicitTier4: true},
			{Master: ControlMasterAuto, Path: "/tmp/cm-%C", Persist: "10m"},
		}
		parents := []HopDigest{ZeroHopDigest, parentDigest}

		for _, parent := range parents {
			for _, host := range hosts {
				for _, port := range ports {
					for _, auth := range authTypes {
						for _, jmp := range jumps {
							for _, ctrl := range controls {
								raw := &ClientConfig{
									NodeID:               "node",
									OriginalHost:         "  alias.local  ",
									CanonicalHost:        "  alias.example.com  ",
									Address:              host,
									BaseHost:             host,
									Port:                 port,
									User:                 "ops",
									AuthType:             auth,
									Password:             "secret-ignored",
									ProxyJump:            jmp.pj,
									OriginalProxyJump:    jmp.orig,
									HasOriginalProxyJump: jmp.hasOrig,
									Control:              ctrl,
								}
								dRaw := DigestClientConfig(raw, parent)
								dNorm := DigestClientConfig(NewClientConfig(*raw), parent)
								dConn := DigestClientConfig(raw.ToConnectionConfig().toClientConfig(), parent)
								if !dRaw.Equal(dNorm) {
									t.Fatalf("DigestClientConfig(raw) != DigestClientConfig(NewClientConfig(raw)) for host=%q port=%d auth=%q jmp=%+v ctrl=%+v",
										host, port, auth, jmp, ctrl)
								}
								if !dRaw.Equal(dConn) {
									t.Fatalf("DigestClientConfig(raw) != DigestClientConfig(ToConnectionConfig().toClientConfig()) for host=%q port=%d auth=%q jmp=%+v ctrl=%+v",
										host, port, auth, jmp, ctrl)
								}
							}
						}
					}
				}
			}
		}
	})
}

type w13bMuxStormState struct {
	connector    *Connector
	stop         chan struct{}
	invErrMu     sync.Mutex
	invErr       error
	connectOps   atomic.Int32
	closeOps     atomic.Int32
	interruptOps atomic.Int32
	retireOps    atomic.Int32
	evictOps     atomic.Int32
}

func (s *w13bMuxStormState) recordErr(err error) {
	if err == nil {
		return
	}
	s.invErrMu.Lock()
	if s.invErr == nil {
		s.invErr = err
	}
	s.invErrMu.Unlock()
}

func (s *w13bMuxStormState) runInvariantChecker() {
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		if err := s.connector.pool.CheckInvariants(false); err != nil {
			s.recordErr(err)
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func (s *w13bMuxStormState) runWorker(ctx context.Context, workerID int) {
	for i := 0; ; i++ {
		select {
		case <-s.stop:
			return
		default:
		}
		reqCtx, reqCancel := context.WithTimeout(ctx, 4*time.Second)
		cli, err := s.connector.Connect(reqCtx, "target")
		reqCancel()
		if err != nil || cli == nil {
			continue
		}
		s.connectOps.Add(1)
		if !cli.IsMultiplexed() {
			s.recordErr(errors.New("expected jump-chained target to stay attached via MUX_C_PROXY"))
			return
		}
		switch (workerID + i) % 4 {
		case 0:
			_ = cli.Close()
			s.closeOps.Add(1)
		case 1:
			_ = cli.Interrupt()
			s.interruptOps.Add(1)
		case 2:
			s.connector.pool.Retire(ZeroHopDigest, cli.pooled)
			_ = cli.Close()
			s.retireOps.Add(1)
		case 3:
			_ = s.connector.EvictClient(cli)
			s.evictOps.Add(1)
		}
	}
}

func (s *w13bMuxStormState) hasCoverage() bool {
	return s.connectOps.Load() >= 8 &&
		s.closeOps.Load() > 0 &&
		s.interruptOps.Load() > 0 &&
		s.retireOps.Load() > 0 &&
		s.evictOps.Load() > 0
}

// TestModel_ConnectorPool_CloseInterruptMuxInterleavings exercises concurrent
// Connect, Client.Close, Client.Interrupt, Retire, EvictClient, and CloseAll
// across jump-chained MUX_C_PROXY targets under -race, checking pool invariants
// continuously and confirming zero unintended bastion dials on re-attachments.
func TestModel_ConnectorPool_CloseInterruptMuxInterleavings(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	bastionSrv, targetSrv, sockPath, dialer, connector := newW13bJumpMuxFixture(t, ctx, "model-mux-storm")
	startW13bExternalControlMaster(t, ctx, targetSrv, sockPath, "bastion")

	storm := &w13bMuxStormState{
		connector: connector,
		stop:      make(chan struct{}),
	}

	var wg sync.WaitGroup
	wg.Go(storm.runInvariantChecker)
	for workerID := range 3 {
		wg.Go(func() { storm.runWorker(ctx, workerID) })
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !storm.hasCoverage() {
		time.Sleep(10 * time.Millisecond)
	}
	close(storm.stop)
	wg.Wait()

	storm.invErrMu.Lock()
	gotInvErr := storm.invErr
	storm.invErrMu.Unlock()
	if gotInvErr != nil {
		t.Fatalf("pool invariant violated during mux close/interrupt storm: %v", gotInvErr)
	}
	if !storm.hasCoverage() {
		t.Fatalf("insufficient op coverage: connect=%d close=%d interrupt=%d retire=%d evict=%d",
			storm.connectOps.Load(), storm.closeOps.Load(), storm.interruptOps.Load(), storm.retireOps.Load(), storm.evictOps.Load())
	}
	if got := dialer.countFor(bastionSrv.addr); got != 0 {
		t.Fatalf("mux close/interrupt storm dialed bastion %d times, want 0", got)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("post-storm CheckInvariants(false): %v", err)
	}
	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll(): %v", err)
	}
	assertW13bPoolState(t, "post mux storm CloseAll", connector.pool, false, 0, 0)
	if got := connector.pool.RetiredCount(); got != 0 {
		t.Fatalf("RetiredCount after CloseAll = %d, want 0", got)
	}
}
