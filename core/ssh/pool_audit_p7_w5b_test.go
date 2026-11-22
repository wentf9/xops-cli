package ssh

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// wedgedWriteConn wraps a real net.Conn and deterministically wedges Write()
// (simulating a full TCP SO_SNDBUF into a blackhole or a stalled SSH KEX write
// barrier) once armed, unblocking only when Close() is invoked.
type wedgedWriteConn struct {
	net.Conn
	wedge        atomic.Bool
	closedCh     chan struct{}
	closeOnce    sync.Once
	writeBlocked chan struct{}
	blockOnce    sync.Once
}

func newWedgedWriteConn(raw net.Conn) *wedgedWriteConn {
	return &wedgedWriteConn{
		Conn:         raw,
		closedCh:     make(chan struct{}),
		writeBlocked: make(chan struct{}),
	}
}

func (c *wedgedWriteConn) Write(p []byte) (int, error) {
	if c.wedge.Load() {
		c.blockOnce.Do(func() { close(c.writeBlocked) })
		<-c.closedCh
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}

func (c *wedgedWriteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closedCh) })
	return c.Conn.Close()
}

type wedgedWriteDialer struct {
	mu    sync.Mutex
	conns []*wedgedWriteConn
}

func (d *wedgedWriteDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *wedgedWriteDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	wc := newWedgedWriteConn(raw)
	d.mu.Lock()
	d.conns = append(d.conns, wc)
	d.mu.Unlock()
	return wc, nil
}

func (d *wedgedWriteDialer) firstConn() *wedgedWriteConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.conns) == 0 {
		return nil
	}
	return d.conns[0]
}

func waitWithin(t *testing.T, label string, limit time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s did not complete within %v (deadlock/hang reproduced)", label, limit)
	}
}

// TestC5_H1_TraceA_BastionKeepAliveTimeoutAndCloseAllUnderWedgedWrite verifies
// C5-H1 Trace A: when a parent bastion's TCP write path is wedged (full
// SO_SNDBUF / stalled KEX) and keepalive times out while jump children ride on
// that bastion, eviction MUST close bastion.RootConn BEFORE closing child hop
// channels and keep evicted transports tracked in connPool.closing so CloseAll()
// always unblocks and completes promptly with zero deadlock.
func TestC5_H1_TraceA_BastionKeepAliveTimeoutAndCloseAllUnderWedgedWrite(t *testing.T) {
	t.Run("bastion_timeout_closes_root_before_children", testC5H1TraceABastionTimeout)
	t.Run("child_timeout_first_then_closeall_unblocks", testC5H1TraceAChildTimeoutThenCloseAll)
	t.Run("evict_false_tracks_closing_for_closeall", testC5H1TraceAEvictFalseTracksClosing)
}

func testC5H1TraceABastionTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	midSrv := newKeepAliveBarrierServer(t, ctx)
	leafSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	mHost, mPort := fixtureEndpoint(t, midSrv.addr)
	lHost, lPort := fixtureEndpoint(t, leafSrv.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"mid": {
				NodeID: "mid", Address: mHost, Port: mPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
				Options:   MustOptions(OptionServerAliveCountMax, "100"),
			},
			"leaf": {
				NodeID: "leaf", Address: lHost, Port: lPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "mid",
				Options:   MustOptions(OptionServerAliveCountMax, "100"),
			},
		},
	}

	dialer := &wedgedWriteDialer{}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 15*time.Millisecond, 60*time.Millisecond)
	t.Cleanup(func() {
		if wc := dialer.firstConn(); wc != nil {
			_ = wc.Close()
		}
		_ = connector.CloseAll()
	})

	if _, err := connector.Connect(ctx, "leaf"); err != nil {
		t.Fatalf("Connect(leaf): %v", err)
	}
	bastionClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	if connector.pool.Count() != 3 {
		t.Fatalf("expected 3 active hops (bastion, mid, leaf), got %d", connector.pool.Count())
	}

	wc := dialer.firstConn()
	if wc == nil {
		t.Fatal("expected wedgedWriteDialer to capture bastion transport")
	}

	// Wedge bastion's TCP Write path so keepalive SendRequest blocks in Write
	// and any synchronous child (*ssh.channel).Close() BEFORE bastion.RootConn.Close()
	// would deadlock permanently.
	wc.wedge.Store(true)
	select {
	case <-wc.writeBlocked:
	case <-time.After(2 * time.Second):
		t.Fatal("bastion keepalive write never entered wedged state")
	}

	start := time.Now()
	waitForCondition(t, 500*time.Millisecond, func() bool {
		return connector.pool.Count() == 0 && connector.pool.ClosingCount() == 0 && isRootConnClosed(bastionClient.rootConn)
	}, "C5-H1 Trace A: wedged bastion keepalive timeout did not abort RootConn and cascade-evict within 500ms")

	var closeErr error
	waitWithin(t, "Connector.CloseAll() after wedged bastion keepalive timeout", 500*time.Millisecond, func() {
		closeErr = connector.CloseAll()
	})
	if closeErr != nil {
		t.Fatalf("CloseAll() returned unexpected error: %v", closeErr)
	}
	if elapsed := time.Since(start); elapsed >= 500*time.Millisecond {
		t.Fatalf("Trace A total teardown took %v, want <500ms", elapsed)
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("post-CloseAll CheckInvariants failed: %v", err)
	}
}

func testC5H1TraceAChildTimeoutThenCloseAll(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				// Long timeout on bastion so child times out first while bastion is wedged.
				Options: MustOptions(OptionServerAliveCountMax, "1000"),
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
	}

	dialer := &wedgedWriteDialer{}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 15*time.Millisecond, 50*time.Millisecond)
	t.Cleanup(func() {
		if wc := dialer.firstConn(); wc != nil {
			_ = wc.Close()
		}
		_ = connector.CloseAll()
	})

	targetClient, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	targetKey := connector.pool.DigestOf(targetClient.pooled)

	wc := dialer.firstConn()
	if wc == nil {
		t.Fatal("expected wedgedWriteDialer to capture bastion transport")
	}
	wc.wedge.Store(true)
	select {
	case <-wc.writeBlocked:
	case <-time.After(2 * time.Second):
		t.Fatal("child keepalive write never entered wedged state")
	}

	// Child's keepalive times out first: it detaches target from active into
	// closing without killing the shared bastion, and its boundedJoin returns
	// promptly while CloseAll() remains able to abort bastion.RootConn and join
	// every tracked keepalive/interrupt goroutine.
	waitForCondition(t, 500*time.Millisecond, func() bool {
		_, ok := connector.pool.Get(targetKey)
		return !ok
	}, "timed-out child over wedged bastion was not detached from active pool")

	var closeErr error
	waitWithin(t, "Connector.CloseAll() while child closeHopTransport is blocked on wedged bastion", 500*time.Millisecond, func() {
		closeErr = connector.CloseAll()
	})
	if closeErr != nil {
		t.Fatalf("CloseAll() returned error: %v", closeErr)
	}
	if connector.pool.Count() != 0 || connector.pool.ClosingCount() != 0 {
		t.Fatalf("pool not drained after CloseAll: active=%d closing=%d", connector.pool.Count(), connector.pool.ClosingCount())
	}
}

func testC5H1TraceAEvictFalseTracksClosing(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	provider := &mutableRouteProvider{
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
	}

	dialer := &wedgedWriteDialer{}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		if wc := dialer.firstConn(); wc != nil {
			_ = wc.Close()
		}
		_ = connector.CloseAll()
	})

	if _, err := connector.Connect(ctx, "target"); err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	bastionClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	wc := dialer.firstConn()
	wc.wedge.Store(true)

	// Calling Evict(..., bastion, false) on a write-wedged bastion MUST NOT
	// block synchronously in child.closeSelf() and MUST track both bastion and
	// target in pool.closing so CloseAll() interrupts bastion.RootConn.
	waitWithin(t, "pool.Evict(bastion, closeDead=false) over wedged write", 500*time.Millisecond, func() {
		connector.pool.Evict(ZeroHopDigest, bastionClient.pooled, false)
	})
	if connector.pool.Count() != 0 {
		t.Fatalf("expected active pool empty after Evict, got %d", connector.pool.Count())
	}
	if connector.pool.ClosingCount() != 2 {
		t.Fatalf("expected 2 clients tracked in pool.closing before CloseAll, got %d", connector.pool.ClosingCount())
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants failed with closing entries: %v", err)
	}

	var closeErr error
	waitWithin(t, "Connector.CloseAll() draining pool.closing", 500*time.Millisecond, func() {
		closeErr = connector.CloseAll()
	})
	if closeErr != nil {
		t.Fatalf("CloseAll() error: %v", closeErr)
	}
	if !isRootConnClosed(bastionClient.rootConn) {
		t.Fatal("CloseAll() did not abort RootConn of evicted-but-not-yet-closed bastion")
	}
	if connector.pool.ClosingCount() != 0 {
		t.Fatalf("pool.ClosingCount() = %d after CloseAll, want 0", connector.pool.ClosingCount())
	}
}

// TestC5_H1_TraceB_ProbeCachedChildOverWedgedBastionEscalates verifies C5-H1
// Trace B: when probeCachedClient runs on a jump child over a write-wedged
// bastion (so both child.SSHClient.SendRequest and child.closeHopTransport block
// on ch.writeMu / bastion.RootConn.Write), terminateKeepAliveProbe runs
// interrupt() asynchronously behind graceTimer, escalates to fallbackInterrupt
// (closing bastion.RootConn BEFORE closing sibling children), unblocks and joins
// both goroutines cleanly, and completes in <500ms.
func TestC5_H1_TraceB_ProbeCachedChildOverWedgedBastionEscalates(t *testing.T) {
	t.Run("wedged_bastion_escalates_and_unblocks_sibling", testC5H1TraceBWedgedBastionEscalates)
	t.Run("connect_singleflight_recovers_over_wedged_bastion", testC5H1TraceBConnectSingleflightRecovers)
	t.Run("grace_timer_escalates_before_abort_ctx_over_wedged_bastion", testC5H1TraceBGraceTimerEscalates)
	t.Run("healthy_bastion_grace_timer_does_not_escalate", testC5H1TraceBHealthyBastionNoEscalate)
}

func testC5H1TraceBWedgedBastionEscalates(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	target1Srv := newKeepAliveBarrierServer(t, ctx)
	target2Srv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	t1Host, t1Port := fixtureEndpoint(t, target1Srv.addr)
	t2Host, t2Port := fixtureEndpoint(t, target2Srv.addr)

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

	dialer := &wedgedWriteDialer{}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	// Huge interval so background keepalive does not interfere; short timeout
	// bounds probeCachedClient.
	connector.EnableKeepAlive(kaCtx, time.Hour, 80*time.Millisecond)
	t.Cleanup(func() {
		if wc := dialer.firstConn(); wc != nil {
			_ = wc.Close()
		}
		_ = connector.CloseAll()
	})

	c1, err := connector.Connect(ctx, "target1")
	if err != nil {
		t.Fatalf("Connect(target1): %v", err)
	}
	if _, err := connector.Connect(ctx, "target2"); err != nil {
		t.Fatalf("Connect(target2): %v", err)
	}
	bastionClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	if connector.pool.Count() != 3 {
		t.Fatalf("expected 3 active hops (bastion, target1, target2), got %d", connector.pool.Count())
	}

	wc := dialer.firstConn()
	if wc == nil {
		t.Fatal("expected wedgedWriteDialer to capture bastion transport")
	}
	wc.wedge.Store(true)

	start := time.Now()
	var probeErr error
	waitWithin(t, "probeCachedClient(child) over write-wedged bastion", 500*time.Millisecond, func() {
		probeErr = connector.probeCachedClient(ctx, c1.pooled)
	})
	elapsed := time.Since(start)
	if probeErr == nil {
		t.Fatal("expected probeCachedClient to fail over write-wedged bastion")
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("probeCachedClient took %v, want <500ms", elapsed)
	}
	select {
	case <-wc.writeBlocked:
	default:
		t.Fatal("expected probe SendRequest to hit wedged bastion Write path")
	}
	if !isRootConnClosed(bastionClient.rootConn) {
		t.Fatal("fallbackInterrupt did not abort wedged bastion RootConn")
	}
	if connector.pool.Count() != 0 {
		t.Fatalf("pool.Count() = %d after fallbackInterrupt escalation, want 0 (bastion + siblings evicted)", connector.pool.Count())
	}
	if connector.pool.ClosingCount() != 0 {
		t.Fatalf("pool.ClosingCount() = %d after probeCachedClient escalation, want 0", connector.pool.ClosingCount())
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("CheckInvariants(true) failed after escalation: %v", err)
	}

	var closeErr error
	waitWithin(t, "Connector.CloseAll() after Trace B escalation", 500*time.Millisecond, func() {
		closeErr = connector.CloseAll()
	})
	if closeErr != nil {
		t.Fatalf("CloseAll() error: %v", closeErr)
	}
}

func testC5H1TraceBConnectSingleflightRecovers(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	provider := &mutableRouteProvider{
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
	}

	dialer := &wedgedWriteDialer{}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, time.Hour, 60*time.Millisecond)
	t.Cleanup(func() {
		if wc := dialer.firstConn(); wc != nil {
			_ = wc.Close()
		}
		_ = connector.CloseAll()
	})

	c1, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("initial Connect(target): %v", err)
	}

	// Wedge only the first bastion connection so singleflight's cached probe
	// aborts it, releases singleflight, and transparently rebuilds on a fresh
	// second bastion connection in <500ms.
	wc := dialer.firstConn()
	wc.wedge.Store(true)

	var (
		c2         *Client
		connectErr error
	)
	waitWithin(t, "Connector.Connect(target) singleflight recovery over wedged bastion", 500*time.Millisecond, func() {
		c2, connectErr = connector.Connect(ctx, "target")
	})
	if connectErr != nil {
		t.Fatalf("Connect(target) after wedged bastion failed: %v", connectErr)
	}
	if c2.rootConn == c1.rootConn {
		t.Fatal("Connect(target) did not replace wedged bastion transport")
	}
	if !isRootConnClosed(c1.rootConn) {
		t.Fatal("wedged bastion RootConn was not closed during recovery")
	}
	if err := runBarrierExecCheck(c2); err != nil {
		t.Fatalf("recovered target client unusable: %v", err)
	}
	if err := connector.pool.CheckInvariants(true); err != nil {
		t.Fatalf("CheckInvariants(true) after recovery failed: %v", err)
	}
}

func testC5H1TraceBGraceTimerEscalates(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	provider := &mutableRouteProvider{
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
	}

	dialer := &wedgedWriteDialer{}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		if wc := dialer.firstConn(); wc != nil {
			_ = wc.Close()
		}
		_ = connector.CloseAll()
	})

	targetClient, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	bastionClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}

	wc := dialer.firstConn()
	wc.wedge.Store(true)

	// Keep abortCtx alive (10s) so ONLY timer.C (60ms) + graceTimer (50ms)
	// drive escalation — proving interrupt() runs asynchronously and does NOT
	// block graceTimer when child.closeHopTransport() wedges on ch.writeMu /
	// bastion.RootConn.Write!
	var fallbackCalled atomic.Bool
	beforeClose := func() func() {
		batch := connector.pool.detachForEvict(ZeroHopDigest, targetClient.pooled, true)
		return batch.closeDescendantsAndRelease
	}
	fallbackInterrupt := func() error {
		fallbackCalled.Store(true)
		batch := connector.pool.detachForEvict(ZeroHopDigest, bastionClient.pooled, true)
		err := targetClient.pooled.interrupt()
		if batch != nil {
			_ = batch.dead.closeSelf()
			batch.closeDescendantsAndRelease()
		}
		return err
	}

	start := time.Now()
	var probeErr error
	waitWithin(t, "probeWithContexts graceTimer escalation over wedged bastion", 500*time.Millisecond, func() {
		probeErr = probeWithContexts(
			ctx, ctx, targetClient.sshClient, 60*time.Millisecond,
			targetClient.pooled.closeHopTransport, fallbackInterrupt, beforeClose, true, nil,
		)
	})
	elapsed := time.Since(start)
	if probeErr == nil {
		t.Fatal("expected probeWithContexts to fail over write-wedged bastion")
	}
	if !fallbackCalled.Load() {
		t.Fatal("expected graceTimer to escalate to fallbackInterrupt while abortCtx remained open")
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("graceTimer escalation took %v, want <500ms", elapsed)
	}
	if !isRootConnClosed(bastionClient.rootConn) {
		t.Fatal("fallbackInterrupt did not close wedged bastion RootConn")
	}
	if connector.pool.Count() != 0 || connector.pool.ClosingCount() != 0 {
		t.Fatalf("pool not drained after graceTimer escalation: active=%d closing=%d",
			connector.pool.Count(), connector.pool.ClosingCount())
	}
}

func testC5H1TraceBHealthyBastionNoEscalate(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	// Use reconnectSSHServer with stallDepth=1 so node-0 (bastion) is healthy
	// and responds to SSH_MSG_CHANNEL_CLOSE promptly while node-1 stalls
	// keepalive@openssh.com replies.
	server, address := newReconnectSSHServer(t, ctx, 1)
	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: "127.0.0.1", Port: address.Port,
				User: "test", AuthType: "password", Password: "test",
			},
			"target1": {
				NodeID: "target1", Address: "127.0.0.1", Port: address.Port,
				User: "test", AuthType: "password", Password: "test",
				ProxyJump: "bastion",
			},
			"target2": {
				NodeID: "target2", Address: "127.0.0.1", Port: address.Port,
				User: "test", AuthType: "password", Password: "test",
				ProxyJump: "bastion",
			},
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { _ = connector.CloseAll() })

	c1, err := connector.Connect(ctx, "target1")
	if err != nil {
		t.Fatalf("Connect(target1): %v", err)
	}
	c2, err := connector.Connect(ctx, "target2")
	if err != nil {
		t.Fatalf("Connect(target2): %v", err)
	}
	bClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}

	// Stall keepalive replies on depth=1 (targets) while bastion stays healthy,
	// with abortCtx still open so only timer.C triggers terminateKeepAliveProbe.
	server.stall.Store(true)
	var fallbackCalled atomic.Bool
	beforeClose := func() func() {
		batch := connector.pool.detachForEvict(ZeroHopDigest, c1.pooled, true)
		return batch.closeDescendantsAndRelease
	}
	fallbackInterrupt := func() error {
		fallbackCalled.Store(true)
		return c1.pooled.interrupt()
	}

	var probeErr error
	waitWithin(t, "probeWithContexts(target1) over healthy bastion", 500*time.Millisecond, func() {
		probeErr = probeWithContexts(
			ctx, ctx, c1.sshClient, 60*time.Millisecond,
			c1.pooled.closeHopTransport, fallbackInterrupt, beforeClose, true, nil,
		)
	})
	if probeErr == nil {
		t.Fatal("expected probeWithContexts(target1) to fail on stalled target1")
	}
	if fallbackCalled.Load() || isRootConnClosed(bClient.rootConn) {
		t.Fatal("probeWithContexts(target1) over healthy bastion escalated and closed shared bastion RootConn")
	}
	if connector.pool.Count() != 2 || connector.pool.ClosingCount() != 0 {
		t.Fatalf("expected bastion and target2 active (count=2, closing=0), got active=%d closing=%d",
			connector.pool.Count(), connector.pool.ClosingCount())
	}
	if err := probeWithTimeoutAndInterrupt(ctx, bClient.sshClient, time.Second, bClient.Interrupt); err != nil {
		t.Fatalf("healthy bastion failed after child probe timeout: %v", err)
	}
	server.stall.Store(false)
	if err := probeWithTimeoutAndInterrupt(ctx, c2.sshClient, time.Second, c2.Interrupt); err != nil {
		t.Fatalf("healthy sibling target2 failed after child probe timeout: %v", err)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants(false) failed: %v", err)
	}
}

// TestC5_M1_ThreeHopIntermediateGenerationReplacementPreservesLiveGrandchild
// verifies C5-M1: in a 3-hop chain (bastion -> mid -> leaf) riding on a healthy
// shared bastion (same RootConn R1), replacing mid_Gen1 with mid_Gen2 -> leaf_Gen2
// and then calling EvictClient(mid_Gen1) or Retire(midKey, mid_Gen1) MUST NOT
// conflate mid_Gen1 and mid_Gen2 by HopDigest/RootConn and MUST preserve live
// bastion, mid_Gen2, and leaf_Gen2 in p.active.
func TestC5_M1_ThreeHopIntermediateGenerationReplacementPreservesLiveGrandchild(t *testing.T) {
	t.Run("end_to_end_3hop_evict_and_retire_stale_mid", testC5M1ThreeHopEndToEnd)
	t.Run("unit_4hop_pointer_lineage_and_root_cascade", testC5M1FourHopUnitLineage)
}

func assertThreeHopAlive(
	t *testing.T,
	label string,
	connector *Connector,
	bKey, mKey, lKey HopDigest,
	bastionClient, midGen2, leafGen2 *Client,
) {
	t.Helper()
	assertPoolHasExactEntry(t, connector.pool, "bastion "+label, bKey, bastionClient.pooled)
	assertPoolHasExactEntry(t, connector.pool, "mid_Gen2 "+label, mKey, midGen2.pooled)
	assertPoolHasExactEntry(t, connector.pool, "leaf_Gen2 "+label, lKey, leafGen2.pooled)
	for name, cli := range map[string]*Client{"bastion": bastionClient, "mid_Gen2": midGen2, "leaf_Gen2": leafGen2} {
		if err := runBarrierExecCheck(cli); err != nil {
			t.Fatalf("C5-M1 reproduced: live %s broken %s: %v", name, label, err)
		}
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants %s: %v", label, err)
	}
}

func testC5M1ThreeHopEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	midSrv := newKeepAliveBarrierServer(t, ctx)
	leafSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	mHost, mPort := fixtureEndpoint(t, midSrv.addr)
	lHost, lPort := fixtureEndpoint(t, leafSrv.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"mid": {
				NodeID: "mid", Address: mHost, Port: mPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
			"leaf": {
				NodeID: "leaf", Address: lHost, Port: lPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "mid",
			},
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { _ = connector.CloseAll() })

	// 1. Connect bastion -> mid_Gen1 (shares bastion's RootConn R1).
	midGen1, err := connector.Connect(ctx, "mid")
	if err != nil {
		t.Fatalf("Connect(mid) gen1: %v", err)
	}
	bastionClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	midKey := connector.pool.DigestOf(midGen1.pooled)

	// 2. Retire mid_Gen1 (bastion stays alive with RootConn R1), then connect
	// leaf so the pool installs mid_Gen2 at the EXACT same midKey and leaf_Gen2
	// riding on mid_Gen2 (all still sharing bastion's RootConn R1!).
	connector.pool.Retire(midKey, midGen1.pooled)

	leafGen2, err := connector.Connect(ctx, "leaf")
	if err != nil {
		t.Fatalf("Connect(leaf) gen2: %v", err)
	}
	midGen2, err := connector.Connect(ctx, "mid")
	if err != nil {
		t.Fatalf("Connect(mid) gen2: %v", err)
	}
	leafKey := connector.pool.DigestOf(leafGen2.pooled)
	bastionKey := connector.pool.DigestOf(bastionClient.pooled)

	if midGen2.pooled == midGen1.pooled {
		t.Fatal("precondition failed: expected fresh mid_Gen2 distinct from retired mid_Gen1")
	}
	if midGen1.rootConn != bastionClient.rootConn || midGen2.rootConn != bastionClient.rootConn || leafGen2.rootConn != bastionClient.rootConn {
		t.Fatal("precondition failed: expected bastion, mid_Gen1, mid_Gen2, and leaf_Gen2 to share RootConn R1")
	}
	if leafGen2.pooled.parent != midGen2.pooled || leafGen2.pooled.parentKey != midKey {
		t.Fatalf("precondition failed: leaf_Gen2 parent=%p (want mid_Gen2=%p), parentKey=%s (want %s)",
			leafGen2.pooled.parent, midGen2.pooled, leafGen2.pooled.parentKey, midKey)
	}

	// 3. EvictClient(mid_Gen1) MUST NOT evict or close live mid_Gen2 or leaf_Gen2!
	if err := connector.EvictClient(midGen1); err != nil {
		t.Fatalf("EvictClient(midGen1): %v", err)
	}
	assertThreeHopAlive(t, "after EvictClient(midGen1)", connector, bastionKey, midKey, leafKey, bastionClient, midGen2, leafGen2)

	// 4. Retire(midKey, midGen1) MUST ALSO preserve live bastion, mid_Gen2, and leaf_Gen2!
	connector.pool.Retire(midKey, midGen1.pooled)
	assertThreeHopAlive(t, "after Retire(midGen1)", connector, bastionKey, midKey, leafKey, bastionClient, midGen2, leafGen2)

	// 5. Positive control: EvictClient(mid_Gen2) MUST evict BOTH mid_Gen2 and
	// its true child leaf_Gen2 while keeping shared bastion alive!
	if err := connector.EvictClient(midGen2); err != nil {
		t.Fatalf("EvictClient(midGen2): %v", err)
	}
	if _, ok := connector.pool.Get(midKey); ok {
		t.Fatal("EvictClient(midGen2) did not remove mid_Gen2")
	}
	if _, ok := connector.pool.Get(leafKey); ok {
		t.Fatal("EvictClient(midGen2) did not cascade-evict its true child leaf_Gen2")
	}
	assertPoolHasExactEntry(t, connector.pool, "bastion after EvictClient(midGen2)", bastionKey, bastionClient.pooled)
	if isRootConnClosed(bastionClient.rootConn) {
		t.Fatal("EvictClient(midGen2) closed shared upstream bastion RootConn")
	}
	if err := runBarrierExecCheck(bastionClient); err != nil {
		t.Fatalf("bastion unusable after EvictClient(midGen2): %v", err)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after EvictClient(midGen2): %v", err)
	}
}

func testC5M1FourHopUnitLineage(t *testing.T) {
	t.Parallel()

	pool := newConnPool()
	rootConn := &physicalSSHConn{Conn: &stubCloseConn{}}

	bKey := DigestClientConfig(&ClientConfig{NodeID: "bastion"}, ZeroHopDigest)
	m1Key := DigestClientConfig(&ClientConfig{NodeID: "mid1", ProxyJump: "bastion"}, bKey)
	m2Key := DigestClientConfig(&ClientConfig{NodeID: "mid2", ProxyJump: "mid1"}, m1Key)
	lKey := DigestClientConfig(&ClientConfig{NodeID: "leaf", ProxyJump: "mid2"}, m2Key)

	bastion := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: rootConn, hopConn: rootConn}
	m1Gen1Hop := &stubCloseConn{}
	m1Gen1 := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: rootConn, hopConn: m1Gen1Hop, parentKey: bKey}
	m1Gen2Hop := &stubCloseConn{}
	m1Gen2 := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: rootConn, hopConn: m1Gen2Hop, parentKey: bKey}
	m2Gen2Hop := &stubCloseConn{}
	m2Gen2 := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: rootConn, hopConn: m2Gen2Hop, parentKey: m1Key}
	leafGen2Hop := &stubCloseConn{}
	leafGen2 := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: rootConn, hopConn: leafGen2Hop, parentKey: m2Key}

	if _, err := pool.Publish(bKey, bastion, nil, nil); err != nil {
		t.Fatalf("Publish(bastion): %v", err)
	}
	if _, err := pool.Publish(m1Key, m1Gen1, bastion, nil); err != nil {
		t.Fatalf("Publish(m1Gen1): %v", err)
	}
	// Replace m1Gen1 with m1Gen2 -> m2Gen2 -> leafGen2 on the SAME bastion RootConn.
	if _, err := pool.Publish(m1Key, m1Gen2, bastion, nil); err != nil {
		t.Fatalf("Publish(m1Gen2): %v", err)
	}
	if _, err := pool.Publish(m2Key, m2Gen2, m1Gen2, nil); err != nil {
		t.Fatalf("Publish(m2Gen2): %v", err)
	}
	if _, err := pool.Publish(lKey, leafGen2, m2Gen2, nil); err != nil {
		t.Fatalf("Publish(leafGen2): %v", err)
	}

	// Evicting stale m1Gen1 must NOT touch m1Gen2, m2Gen2, or leafGen2!
	evicted := pool.EvictByClient(m1Gen1)
	if len(evicted) != 0 {
		t.Fatalf("C5-M1 reproduced: EvictByClient(m1Gen1) evicted %d live Gen2 descendants", len(evicted))
	}
	if !m1Gen1Hop.closed.Load() {
		t.Fatal("EvictByClient(m1Gen1) did not close m1Gen1's own hopConn")
	}
	if m1Gen2Hop.closed.Load() || m2Gen2Hop.closed.Load() || leafGen2Hop.closed.Load() || rootConn.closed.Load() {
		t.Fatal("C5-M1 reproduced: EvictByClient(m1Gen1) closed live Gen2 or bastion transports")
	}
	assertPoolHasExactEntry(t, pool, "bastion", bKey, bastion)
	assertPoolHasExactEntry(t, pool, "m1Gen2", m1Key, m1Gen2)
	assertPoolHasExactEntry(t, pool, "m2Gen2", m2Key, m2Gen2)
	assertPoolHasExactEntry(t, pool, "leafGen2", lKey, leafGen2)

	// Evicting live root bastion cascades across all 3 downstream hops via
	// pointer lineage + RootConn ownership and closes rootConn first.
	evicted = pool.EvictByClient(bastion)
	if len(evicted) != 3 {
		t.Fatalf("EvictByClient(bastion) evicted %d descendants, want 3 (m1Gen2, m2Gen2, leafGen2)", len(evicted))
	}
	if !rootConn.closed.Load() || !m1Gen2Hop.closed.Load() || !m2Gen2Hop.closed.Load() || !leafGen2Hop.closed.Load() {
		t.Fatal("EvictByClient(bastion) did not close root and all descendant hopConns")
	}
	if pool.Count() != 0 || pool.ClosingCount() != 0 {
		t.Fatalf("pool not empty after root eviction: active=%d closing=%d", pool.Count(), pool.ClosingCount())
	}
}
