package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

func execBarrierCheck(t *testing.T, client *Client) {
	t.Helper()
	session, err := client.sshClient.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer func() { _ = session.Close() }()
	out, err := session.Output("check")
	if err != nil {
		t.Fatalf("session.Output failed: %v", err)
	}
	if string(out) != "barrier-ok" {
		t.Fatalf("session output = %q, want %q", string(out), "barrier-ok")
	}
}

func modeSwitchDialCount(d *modeSwitchDialer) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.conns)
}

func assertPoolInvariantsAndCounts(t *testing.T, label string, pool *connPool, wantActive, wantClosing int) {
	t.Helper()
	if err := pool.CheckInvariants(false); err != nil {
		t.Fatalf("%s CheckInvariants(false) failed: %v", label, err)
	}
	if err := pool.CheckInvariants(true); err != nil {
		t.Fatalf("%s CheckInvariants(true) failed: %v", label, err)
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

func assertKeepAliveStopped(t *testing.T, name string, doneCh <-chan struct{}) {
	t.Helper()
	if doneCh == nil {
		return
	}
	select {
	case <-doneCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("%s keepalive goroutine did not stop promptly", name)
	}
}

func waitActiveMaster(t *testing.T, sockPath, desc string) *MuxServer {
	t.Helper()
	var srv *MuxServer
	waitForCondition(t, 2*time.Second, func() bool {
		srv = GetActiveMuxServer(sockPath)
		return srv != nil
	}, desc+" did not start")
	return srv
}

func shutdownMasterDirectOrExit(t *testing.T, ctx context.Context, master *MuxServer, sockPath string, viaMuxExit bool) {
	t.Helper()
	if !viaMuxExit {
		waitWithin(t, "master.Shutdown()", 500*time.Millisecond, func() {
			if err := master.Shutdown(); err != nil {
				t.Errorf("master.Shutdown(): %v", err)
			}
		})
		return
	}
	muxCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient(-O exit): %v", err)
	}
	if err := muxCli.Terminate(ctx); err != nil {
		_ = muxCli.Close()
		t.Fatalf("MuxClient.Terminate(-O exit): %v", err)
	}
	_ = muxCli.Close()
	select {
	case <-master.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("master did not shut down after -O exit")
	}
}

type twoHopMuxHarness struct {
	bastionSrv  *keepAliveBarrierServer
	targetSrv   *keepAliveBarrierServer
	bastionSock string
	targetSock  string
	dialer      *modeSwitchDialer
	connector   *Connector
}

func newTwoHopMuxHarness(t *testing.T, ctx context.Context, suffix string, targetMuxEnabled bool, kaInterval, kaTimeout time.Duration) *twoHopMuxHarness {
	t.Helper()
	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	sockDir := shortSocketDir(t)
	bastionSock := filepath.Join(sockDir, "b-"+suffix+".sock")
	targetSock := filepath.Join(sockDir, "t-"+suffix+".sock")

	ctrls := map[string]*ControlConfig{
		"bastion": {Master: ControlMasterAuto, Path: bastionSock, Persist: "yes"},
	}
	if targetMuxEnabled {
		ctrls["target"] = &ControlConfig{Master: ControlMasterAuto, Path: targetSock, Persist: "yes"}
	}
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
		ctrls: ctrls,
	}

	dialer := &modeSwitchDialer{}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	t.Cleanup(cancelKA)
	connector.EnableKeepAlive(kaCtx, kaInterval, kaTimeout)
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})
	return &twoHopMuxHarness{
		bastionSrv:  bastionSrv,
		targetSrv:   targetSrv,
		bastionSock: bastionSock,
		targetSock:  targetSock,
		dialer:      dialer,
		connector:   connector,
	}
}

// TestW8b_C8_M1_DirectMasterShutdownEvictsPooledClient verifies C8-M1 for a
// direct Connector-owned MuxServer: shutting down the master directly or via
// -O exit while the Connector stays open immediately evicts its PooledClient,
// stops its keepalive, keeps connPool.CheckInvariants clean, and allows the
// next Connector.Connect to establish a fresh healthy connection.
func TestW8b_C8_M1_DirectMasterShutdownEvictsPooledClient(t *testing.T) {
	t.Run("direct_master_shutdown", func(t *testing.T) {
		testW8bC8M1DirectMaster(t, false)
	})
	t.Run("direct_master_exit_via_mux_client", func(t *testing.T) {
		testW8bC8M1DirectMaster(t, true)
	})
}

func testW8bC8M1DirectMaster(t *testing.T, viaMuxExit bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	srv := newKeepAliveBarrierServer(t, ctx)
	host, port := fixtureEndpoint(t, srv.addr)
	sockPath := filepath.Join(shortSocketDir(t), "direct-w8b.sock")

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

	dialer := &modeSwitchDialer{}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	defer cancelKA()
	connector.EnableKeepAlive(kaCtx, 50*time.Millisecond, 250*time.Millisecond)
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	firstCli, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("initial Connect(node): %v", err)
	}
	firstPooled := firstCli.pooled
	kaActive, kaDone := firstPooled.keepAliveState()
	if firstPooled == nil || !kaActive || kaDone == nil {
		t.Fatal("expected initial direct master client with active keepalive")
	}

	master := waitActiveMaster(t, sockPath, "direct control master")
	assertPoolInvariantsAndCounts(t, "pre-shutdown", connector.pool, 1, 0)

	shutdownMasterDirectOrExit(t, ctx, master, sockPath, viaMuxExit)

	// Immediately after Shutdown()/Wait() completes, pool invariants MUST hold
	// with active count == 0 and no stranded closed RootConn.
	assertPoolInvariantsAndCounts(t, "post-shutdown", connector.pool, 0, 0)
	assertKeepAliveStopped(t, "direct master", kaDone)
	waitForCondition(t, 2*time.Second, func() bool {
		return len(connector.Masters()) == 0
	}, "watchMasterShutdown did not prune closed direct master")

	secondCli, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("reconnect Connect(node): %v", err)
	}
	if secondCli.pooled == nil || secondCli.pooled == firstPooled {
		t.Fatal("expected reconnect to establish a fresh PooledClient")
	}
	assertPoolInvariantsAndCounts(t, "post-reconnect", connector.pool, 1, 0)
	execBarrierCheck(t, secondCli)
}

// TestW8b_C8_M1_ProxyJumpMasterShutdownPoolEviction verifies C8-M1 for a 2-hop
// bastion -> target chain with ControlMaster=auto:
//   - (a) targetMaster.Shutdown() over a healthy bastion evicts ONLY target,
//     preserves bastion alive & pooled, satisfies CheckInvariants immediately,
//     and next Connect(target) reuses bastion with a single probe.
//   - (b) bastionMaster.Shutdown() cascade-evicts BOTH bastion and target,
//     satisfies CheckInvariants immediately, and allows clean rebuild.
//   - (c) bastionMaster.Shutdown() also cascade-evicts a plain (non-mux) target.
func TestW8b_C8_M1_ProxyJumpMasterShutdownPoolEviction(t *testing.T) {
	t.Run("a_target_master_shutdown_preserves_healthy_bastion", testW8bC8M1TargetMasterShutdownPreservesBastion)
	t.Run("b_bastion_master_shutdown_cascades_target", func(t *testing.T) {
		testW8bC8M1BastionMasterShutdownCascadesTarget(t, true)
	})
	t.Run("c_bastion_master_shutdown_cascades_non_mux_target", func(t *testing.T) {
		testW8bC8M1BastionMasterShutdownCascadesTarget(t, false)
	})
}

func testW8bC8M1TargetMasterShutdownPreservesBastion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	// Long keepalive interval keeps keepalive active for CheckInvariants(true)
	// without injecting extra background ticks into bastionSrv.probeCount.
	h := newTwoHopMuxHarness(t, ctx, "w8b-a", true, 30*time.Second, 2*time.Second)

	firstTarget, err := h.connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("initial Connect(target): %v", err)
	}
	targetPooled := firstTarget.pooled
	if targetPooled == nil || targetPooled.parent == nil {
		t.Fatal("expected target PooledClient with active bastion parent")
	}
	bastionPooled := targetPooled.parent
	targetKAActive, targetKADone := targetPooled.keepAliveState()
	if !targetKAActive || targetKADone == nil {
		t.Fatal("expected keepalive active on target")
	}

	bastionMaster := waitActiveMaster(t, h.bastionSock, "bastion master")
	targetMaster := waitActiveMaster(t, h.targetSock, "target master")
	assertPoolInvariantsAndCounts(t, "initial 2-hop", h.connector.pool, 2, 0)

	dialsBefore := modeSwitchDialCount(h.dialer)
	probesBefore := h.bastionSrv.probeCount.Load()

	shutdownMasterDirectOrExit(t, ctx, targetMaster, h.targetSock, false)

	// Immediately after targetMaster.Shutdown(): target is evicted, bastion
	// stays active and healthy, and CheckInvariants passes.
	assertPoolInvariantsAndCounts(t, "post-target-shutdown", h.connector.pool, 1, 0)
	if got, ok := h.connector.pool.Get(bastionPooled.digest); !ok || got != bastionPooled || isRootConnClosed(bastionPooled.RootConn) {
		t.Fatal("healthy bastion did not stay active and open after targetMaster.Shutdown")
	}
	if GetActiveMuxServer(h.bastionSock) != bastionMaster {
		t.Fatal("healthy bastion master was unexpectedly shut down")
	}
	if _, ok := h.connector.pool.Get(targetPooled.digest); ok {
		t.Fatal("dead target remained in active pool after targetMaster.Shutdown")
	}
	assertKeepAliveStopped(t, "target", targetKADone)

	// Next Connect(target) MUST reuse the healthy bastion with a SINGLE probe.
	rebuiltTarget, err := h.connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("second Connect(target): %v", err)
	}
	if rebuiltTarget.pooled == nil || rebuiltTarget.pooled == targetPooled || rebuiltTarget.pooled.parent != bastionPooled {
		t.Fatal("expected second Connect(target) to create fresh target reusing existing bastion")
	}
	if got := modeSwitchDialCount(h.dialer); got != dialsBefore {
		t.Fatalf("bastion was redialed: dial count = %d, want %d", got, dialsBefore)
	}
	if gotProbes := h.bastionSrv.probeCount.Load() - probesBefore; gotProbes != 1 {
		t.Fatalf("bastion probe count on Connect(target) = %d, want 1", gotProbes)
	}
	assertPoolInvariantsAndCounts(t, "post-rebuild", h.connector.pool, 2, 0)
	execBarrierCheck(t, rebuiltTarget)
}

func testW8bC8M1BastionMasterShutdownCascadesTarget(t *testing.T, targetMuxEnabled bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	h := newTwoHopMuxHarness(t, ctx, "w8b-b", targetMuxEnabled, 50*time.Millisecond, 250*time.Millisecond)

	firstTarget, err := h.connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("initial Connect(target): %v", err)
	}
	targetPooled := firstTarget.pooled
	if targetPooled == nil || targetPooled.parent == nil {
		t.Fatal("expected target PooledClient with bastion parent")
	}
	_, bastionKADone := targetPooled.parent.keepAliveState()
	_, targetKADone := targetPooled.keepAliveState()

	bastionMaster := waitActiveMaster(t, h.bastionSock, "bastion master")
	var targetMaster *MuxServer
	if targetMuxEnabled {
		targetMaster = waitActiveMaster(t, h.targetSock, "target master")
	}

	shutdownMasterDirectOrExit(t, ctx, bastionMaster, h.bastionSock, false)

	// Immediately after bastionMaster.Shutdown(): BOTH bastion and target are
	// cascade-evicted and CheckInvariants passes.
	assertPoolInvariantsAndCounts(t, "post-bastion-shutdown", h.connector.pool, 0, -1)
	assertKeepAliveStopped(t, "bastion", bastionKADone)
	assertKeepAliveStopped(t, "target", targetKADone)
	if targetMaster != nil {
		select {
		case <-targetMaster.Wait():
		case <-time.After(2 * time.Second):
			t.Fatal("target master did not shut down after bastion master transport closed")
		}
	}

	rebuilt, err := h.connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("rebuild Connect(target): %v", err)
	}
	assertPoolInvariantsAndCounts(t, "post-full-rebuild", h.connector.pool, 2, 0)
	execBarrierCheck(t, rebuilt)
}

// lateStallingOpenSSHConn blocks OpenChannel until releaseCh is closed, then
// returns a channel whose Close() blocks until rootClosedCh is closed.
type lateStallingOpenSSHConn struct {
	dummyMuxGateConn
	openStarted  chan struct{}
	startOnce    sync.Once
	releaseCh    chan struct{}
	rootClosedCh chan struct{}
	closeDone    chan struct{}
	closeOnce    sync.Once
}

func (c *lateStallingOpenSSHConn) OpenChannel(string, []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	c.startOnce.Do(func() { close(c.openStarted) })
	<-c.releaseCh
	reqs := make(chan *cryptoSSH.Request)
	close(reqs)
	return &stalledUntilAbortChannel{
		rootClosedCh: c.rootClosedCh,
		closeDone:    c.closeDone,
		closeOnce:    &c.closeOnce,
	}, reqs, nil
}

type stalledUntilAbortChannel struct {
	rootClosedCh <-chan struct{}
	closeDone    chan struct{}
	closeOnce    *sync.Once
}

func (c *stalledUntilAbortChannel) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *stalledUntilAbortChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *stalledUntilAbortChannel) CloseWrite() error           { return nil }
func (c *stalledUntilAbortChannel) Stderr() io.ReadWriter       { return &nopRW{} }
func (c *stalledUntilAbortChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, io.EOF
}
func (c *stalledUntilAbortChannel) Close() error {
	<-c.rootClosedCh
	c.closeOnce.Do(func() { close(c.closeDone) })
	return net.ErrClosed
}

// TestW8b_C8_L1_OpenRemoteChannelAbandonedUsesBoundedClose verifies C8-L1 in
// proxySessionState.openRemoteChannelContext: when a late OpenChannel completes
// after abandonment over a write-wedged transport where ch.Close() stalls,
// closeMuxChannelBounded escalates to interruptTransportAndShutdown instead of
// hanging forever and leaking the goroutine.
func TestW8b_C8_L1_OpenRemoteChannelAbandonedUsesBoundedClose(t *testing.T) {
	rootClosedCh := make(chan struct{})
	var rootCloseOnce sync.Once
	rawHop := newSyntheticRawChanConn(true, false)
	physRoot := &physicalRootHookConn{
		Conn: newSyntheticRawChanConn(false, false),
		onClose: func() {
			rawHop.forceAbort()
			rootCloseOnce.Do(func() { close(rootClosedCh) })
		},
	}

	sshConn := &lateStallingOpenSSHConn{
		openStarted:  make(chan struct{}),
		releaseCh:    make(chan struct{}),
		rootClosedCh: rootClosedCh,
		closeDone:    make(chan struct{}),
	}
	chans := make(chan cryptoSSH.NewChannel)
	close(chans)
	reqs := make(chan *cryptoSSH.Request)
	close(reqs)
	sshCli := cryptoSSH.NewClient(sshConn, chans, reqs)

	sockPath := filepath.Join(shortSocketDir(t), "l1-proxy.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		PeerCheck:         PeerCheckDisabledForTesting,
		SSHClient:         sshCli,
		RootConn:          rawHop,
		PhysicalRootConn:  physRoot,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	t.Cleanup(func() {
		rootCloseOnce.Do(func() { close(rootClosedCh) })
		_ = srv.Shutdown()
	})

	baseline := runtime.NumGoroutine()

	ps := &proxySessionState{
		server:   srv,
		closedCh: make(chan struct{}),
	}

	openErrCh := make(chan error, 1)
	go func() {
		_, _, openErr := ps.openRemoteChannelContext("session", nil)
		openErrCh <- openErr
	}()

	select {
	case <-sshConn.openStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("OpenChannel did not start")
	}

	// Abandon the in-flight open by closing the proxy session.
	ps.closed.Store(true)
	close(ps.closedCh)

	select {
	case err := <-openErrCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("openRemoteChannelContext err = %v, want net.ErrClosed", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("openRemoteChannelContext did not return promptly after abandonment")
	}

	// Release the late OpenChannel so the abandoned goroutine enters
	// closeMuxChannelBounded(ch, nil) on a stalled channel close.
	close(sshConn.releaseCh)

	select {
	case <-srv.Wait():
	case <-time.After(sessionShutdownTimeout + 800*time.Millisecond):
		t.Fatal("abandoned late OpenChannel stalled without escalating via closeMuxChannelBounded")
	}
	if !physRoot.closed.Load() {
		t.Fatal("expected closeMuxChannelBounded escalation to close PhysicalRootConn")
	}
	select {
	case <-sshConn.closeDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("stalled channel Close did not unblock after PhysicalRootConn abort")
	}
	waitForGoroutinesAtMost(t, baseline+1, 500*time.Millisecond, "C8-L1 openRemoteChannelContext goroutine check")
}
