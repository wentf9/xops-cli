package ssh

import (
	"context"
	"errors"
	"io"
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

func newW14bJumpMuxFixtureWithMode(
	t *testing.T,
	ctx context.Context,
	suffix string,
	targetMaster ControlMasterMode,
) (
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
	sockPath = filepath.Join(shortSocketDir(t), "w14b-"+suffix+".sock")

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
			"target": {Master: targetMaster, Path: sockPath},
		},
	}
	dialer = newW13bCountingDialer()
	connector = newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	kaCtx, cancelKA := context.WithCancel(ctx)
	t.Cleanup(cancelKA)
	// Long interval prevents background keepalive races while bounding
	// probeCachedClient to 180ms when a cached hop blackholes.
	connector.EnableKeepAlive(kaCtx, 30*time.Second, 180*time.Millisecond)
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})
	return bastionSrv, targetSrv, sockPath, dialer, connector
}

func firstDialerConn(t *testing.T, dialer *w13bCountingDialer) *modeSwitchConn {
	t.Helper()
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	if len(dialer.conns) == 0 {
		t.Fatal("expected at least one recorded dialer connection")
	}
	return dialer.conns[0]
}

func assertW14bM1ValidateCachedMuxWithDeadBastion(t *testing.T) {
	for _, blackhole := range []bool{true, false} {
		name := "closed_bastion_rootconn"
		suffix := "m1-vc-cls"
		if blackhole {
			name = "blackholed_bastion"
			suffix = "m1-vc-bh"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()

			bastionSrv, targetSrv, sockPath, dialer, connector := newW14bJumpMuxFixtureWithMode(t, ctx, suffix, ControlMasterAuto)
			startW13bExternalControlMaster(t, ctx, targetSrv, sockPath, "bastion")

			bastionCli, err := connector.Connect(ctx, "bastion")
			if err != nil {
				t.Fatalf("Connect(bastion): %v", err)
			}
			c1, err := connector.Connect(ctx, "target")
			if err != nil {
				t.Fatalf("Connect(target): %v", err)
			}
			if !c1.IsMultiplexed() {
				t.Fatal("expected c1 to attach via MUX_C_PROXY")
			}
			if got := dialer.countFor(bastionSrv.addr); got != 1 {
				t.Fatalf("initial bastion dials = %d, want 1", got)
			}
			assertW13bPoolState(t, "initial cached bastion+mux target", connector.pool, true, 2, 0)

			// Kill cached bastion transport without touching external target ControlMaster.
			if blackhole {
				firstDialerConn(t, dialer).blackhole.Store(true)
			} else if err := bastionCli.rootConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("close bastion rootConn: %v", err)
			}

			c2, err := connector.Connect(ctx, "target")
			if err != nil {
				t.Fatalf("Connect(target) with dead cached bastion failed: %v", err)
			}
			if !c2.IsMultiplexed() {
				t.Fatal("expected c2 to remain attached via MUX_C_PROXY")
			}
			if got := dialer.countFor(bastionSrv.addr); got != 1 {
				t.Fatalf("bastion dials after dead-bastion reuse = %d, want 1 (0 new bastion dials)", got)
			}
			execBarrierCheck(t, c2)
			assertW13bPoolState(t, "post dead-bastion validateCachedChain", connector.pool, true, 1, 0)
		})
	}
}

func assertW14bM1TryAttachTargetMasterWithDeadBastion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv, targetSrv, sockPath, dialer, connector := newW14bJumpMuxFixtureWithMode(t, ctx, "m1-att", ControlMasterAuto)
	startW13bExternalControlMaster(t, ctx, targetSrv, sockPath, "bastion")

	// Cache ONLY bastion so snapshot[0] == nil and tryReuseMultiHopPlan enters
	// tryAttachTargetControlMaster with snapshot[1] != nil.
	if _, err := connector.Connect(ctx, "bastion"); err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	if got := dialer.countFor(bastionSrv.addr); got != 1 {
		t.Fatalf("initial bastion dials = %d, want 1", got)
	}
	firstDialerConn(t, dialer).blackhole.Store(true)

	cTarget, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target) via tryAttachTargetControlMaster failed: %v", err)
	}
	if !cTarget.IsMultiplexed() {
		t.Fatal("expected cTarget to attach via MUX_C_PROXY")
	}
	if got := dialer.countFor(bastionSrv.addr); got != 1 {
		t.Fatalf("bastion dials = %d, want 1 (0 new bastion dials)", got)
	}
	execBarrierCheck(t, cTarget)
	assertW13bPoolState(t, "post dead-bastion tryAttachTargetControlMaster", connector.pool, true, 1, 0)
}

func assertW14bM1DeadInMemoryChainFallsThroughToExternalMaster(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	// Use ControlMaster=no + ControlPath=sockPath so the initial Connect("target")
	// establishes an in-memory jump chain (without starting an in-process master)
	// while still allowing attachment once an external ControlMaster appears on sockPath.
	bastionSrv, targetSrv, sockPath, dialer, connector := newW14bJumpMuxFixtureWithMode(t, ctx, "m1-fall", ControlMasterNo)

	c1, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("initial in-memory Connect(target): %v", err)
	}
	if c1.IsMultiplexed() {
		t.Fatal("expected initial Connect(target) to use in-memory jump chain")
	}
	if got := dialer.countFor(bastionSrv.addr); got != 1 {
		t.Fatalf("initial bastion dials = %d, want 1", got)
	}
	assertW13bPoolState(t, "initial in-memory chain", connector.pool, true, 2, 0)

	// Blackhole bastion so isRootConnClosed == false pre-probe (canReuseCachedChain
	// returns true), then start an independent external ControlMaster on sockPath.
	firstDialerConn(t, dialer).blackhole.Store(true)
	startW13bExternalControlMaster(t, ctx, targetSrv, sockPath, "bastion")

	c2, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target) fallthrough to external ControlMaster failed: %v", err)
	}
	if !c2.IsMultiplexed() {
		t.Fatal("expected c2 to attach to external ControlMaster via MUX_C_PROXY")
	}
	if got := dialer.countFor(bastionSrv.addr); got != 1 {
		t.Fatalf("bastion dials = %d, want 1 (0 new bastion dials)", got)
	}
	execBarrierCheck(t, c2)
	assertW13bPoolState(t, "post dead in-memory chain fallthrough", connector.pool, true, 1, 0)
}

func assertW14bM1InProcessTargetMasterOnDeadBastionRebuildsCleanly(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	h := newTwoHopMuxHarness(t, ctx, "w14b-m1-inproc", true, 30*time.Second, 180*time.Millisecond)

	c1, err := h.connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("initial Connect(target): %v", err)
	}
	oldTarget := c1.pooled
	oldBastion := c1.pooled.parent
	oldTargetMaster := waitActiveMaster(t, h.targetSock, "initial in-process target master")
	assertPoolInvariantsAndCounts(t, "initial in-process 2-hop", h.connector.pool, 2, 0)

	// Blackhole bastion: probing bastion evicts bastion + cascades to target,
	// synchronously unlinking targetSock before tryReuseMultiHopPlan checks hasControlSocket.
	h.dialer.connAt(0).blackhole.Store(true)

	c2, err := h.connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target) after bastion blackhole failed: %v", err)
	}
	assertW9bRebuiltTwoHopClient(t, c2, oldTarget, oldBastion)
	select {
	case <-oldTargetMaster.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("evicted in-process target master did not shut down")
	}
	newTargetMaster := waitActiveMaster(t, h.targetSock, "rebuilt in-process target master")
	if newTargetMaster == oldTargetMaster {
		t.Fatal("expected fresh target master after bastion blackhole rebuild")
	}
	execBarrierCheck(t, c2)
	assertPoolInvariantsAndCounts(t, "post in-process rebuild", h.connector.pool, 2, 0)
}

func assertW14bM1IntermediateCancelAbortsFastPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv, targetSrv, sockPath, dialer, connector := newW14bJumpMuxFixtureWithMode(t, ctx, "m1-cancel", ControlMasterAuto)
	startW13bExternalControlMaster(t, ctx, targetSrv, sockPath, "bastion")

	if _, err := connector.Connect(ctx, "bastion"); err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	firstDialerConn(t, dialer).blackhole.Store(true)

	// Cancel caller ctx while probing the blackholed intermediate hop:
	// non-errJumpChainRequired errors must abort immediately, never silently proceed.
	reqCtx, reqCancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer reqCancel()
	if _, err := connector.Connect(reqCtx, "target"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Connect(target) with canceled intermediate probe = %v, want context.DeadlineExceeded", err)
	}
	if got := dialer.countFor(bastionSrv.addr); got != 1 {
		t.Fatalf("bastion dials on canceled probe = %d, want 1", got)
	}
}

// TestP7W14b_C14_M1_DeadCachedIntermediateHopKeepsControlMasterFastPath verifies
// all C14-M1 scenarios: dead cached intermediate hops are evicted without aborting
// a live external target ControlMaster fast-path (0 new bastion dials), while
// in-process target masters riding on the dead bastion still unlink synchronously
// and rebuild, and non-errJumpChainRequired errors propagate immediately.
func TestP7W14b_C14_M1_DeadCachedIntermediateHopKeepsControlMasterFastPath(t *testing.T) {
	t.Run("validate_cached_mux_target_with_dead_bastion", assertW14bM1ValidateCachedMuxWithDeadBastion)
	t.Run("try_attach_target_master_with_dead_bastion", assertW14bM1TryAttachTargetMasterWithDeadBastion)
	t.Run("dead_in_memory_chain_falls_through_to_external_master", assertW14bM1DeadInMemoryChainFallsThroughToExternalMaster)
	t.Run("in_process_target_master_on_dead_bastion_rebuilds", assertW14bM1InProcessTargetMasterOnDeadBastionRebuildsCleanly)
	t.Run("intermediate_hop_cancel_aborts_fast_path", assertW14bM1IntermediateCancelAbortsFastPath)
}

func closeOrInterruptClient(t *testing.T, label string, cli *Client, useInterrupt bool) {
	t.Helper()
	if useInterrupt {
		if err := cli.Interrupt(); err != nil {
			t.Fatalf("%s Interrupt(): %v", label, err)
		}
		return
	}
	if err := cli.Close(); err != nil {
		t.Fatalf("%s Close(): %v", label, err)
	}
}

func assertW14bSocketUnlinked(t *testing.T, label, sockPath string) {
	t.Helper()
	if socketPathExists(sockPath) {
		t.Fatalf("%s: control socket %q still on disk synchronously after teardown", label, sockPath)
	}
	if got := GetActiveMuxServer(sockPath); got != nil {
		t.Fatalf("%s: activeMuxServers still holds %v for %q", label, got, sockPath)
	}
}

func waitW14bMastersClosed(t *testing.T, label string, masters ...*MuxServer) {
	t.Helper()
	for _, m := range masters {
		select {
		case <-m.Wait():
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: MuxServer did not finish async Shutdown", label)
		}
	}
}

func assertW14bPoolRetiredAndValid(t *testing.T, label string, pool *connPool, wantRetired int) {
	t.Helper()
	if got := pool.RetiredCount(); got != wantRetired {
		t.Fatalf("%s: RetiredCount = %d, want %d", label, got, wantRetired)
	}
	if err := pool.CheckInvariants(false); err != nil {
		t.Fatalf("%s: CheckInvariants(false): %v", label, err)
	}
}

func assertW14bMasterSharesConnection(t *testing.T, ctx context.Context, cfg *ClientConfig, srvAddr, sockPath string) {
	t.Helper()
	shareProvider := &multiNodeMuxProvider{
		cfgs:  map[string]*ClientConfig{"node": cfg},
		ctrls: map[string]*ControlConfig{"node": {Master: ControlMasterAuto, Path: sockPath}},
	}
	shareDialer := newW13bCountingDialer()
	shareConn := newTestConnector(shareProvider, WithDialer(shareDialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		shareDialer.closeAll()
		_ = shareConn.CloseAll()
	})
	c3, err := shareConn.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("sharing Connect(node) via replacement master failed: %v", err)
	}
	if !c3.IsMultiplexed() {
		t.Fatal("expected c3 to share replacement master via MUX_C_PROXY")
	}
	if got := shareDialer.countFor(srvAddr); got != 0 {
		t.Fatalf("sharing connector dialed TCP %d times, want 0", got)
	}
	execBarrierCheck(t, c3)
}

func assertW14bM2SingleHopRetiredUnlinkAndShare(t *testing.T, mode ControlMasterMode, useInterrupt bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	srv := newKeepAliveBarrierServer(t, ctx)
	host, port := fixtureEndpoint(t, srv.addr)
	tag := "cls"
	if useInterrupt {
		tag = "int"
	}
	sockPath := filepath.Join(shortSocketDir(t), "w14b-m2-"+string(mode)+"-"+tag+".sock")
	nodeCfg := &ClientConfig{
		NodeID: "node", Address: host, Port: port,
		User: "fixture", AuthType: "password", Password: sshfixture.Password,
	}
	provider := &multiNodeMuxProvider{
		cfgs:  map[string]*ClientConfig{"node": nodeCfg},
		ctrls: map[string]*ControlConfig{"node": {Master: mode, Path: sockPath, Persist: "yes"}},
	}
	dialer := newW13bCountingDialer()
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	c1, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("initial Connect(node): %v", err)
	}
	master1 := waitActiveMaster(t, sockPath, "initial master1")

	// Non-disruptive Retire preserves master1 while moving c1 to p.retired.
	connector.pool.Retire(ZeroHopDigest, c1.pooled)
	assertW14bPoolRetiredAndValid(t, "post Retire", connector.pool, 1)
	if !socketPathExists(sockPath) || master1.currentPhase() != muxPhaseRunning {
		t.Fatal("non-disruptive Retire unexpectedly tore down master1")
	}

	// Closing/interrupting retired c1 must synchronously unlink sockPath BEFORE returning.
	closeOrInterruptClient(t, "retired c1", c1, useInterrupt)
	assertW14bSocketUnlinked(t, "retired single-hop", sockPath)
	assertW14bPoolRetiredAndValid(t, "post retired teardown", connector.pool, 1)

	// Immediate follow-up Connect WITHOUT waiting on <-master1.Wait() must
	// cleanly dial a fresh transport and bind a fresh ControlMaster for sharing.
	c2, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("immediate Connect(node) after retired Close/Interrupt failed: %v", err)
	}
	if c2.pooled == c1.pooled || c2.IsMultiplexed() {
		t.Fatalf("expected fresh non-proxy master client, got same=%v mux=%v", c2.pooled == c1.pooled, c2.IsMultiplexed())
	}
	master2 := waitActiveMaster(t, sockPath, "replacement master2")
	if master2 == master1 {
		t.Fatal("expected distinct replacement MuxServer instance")
	}
	waitW14bMastersClosed(t, "retired master1", master1)
	execBarrierCheck(t, c2)
	assertW14bMasterSharesConnection(t, ctx, nodeCfg, srv.addr, sockPath)

	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	assertW14bPoolRetiredAndValid(t, "post CloseAll", connector.pool, 0)
	assertW13bPoolState(t, "post CloseAll", connector.pool, false, 0, 0)
}

func assertW14bM2PublishDisplacedRetiredUnlink(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	srv := newKeepAliveBarrierServer(t, ctx)
	host, port := fixtureEndpoint(t, srv.addr)
	sockPath := filepath.Join(shortSocketDir(t), "w14b-m2-disp.sock")
	nodeCfg := &ClientConfig{
		NodeID: "node", Address: host, Port: port,
		User: "fixture", AuthType: "password", Password: sshfixture.Password,
	}
	provider := &multiNodeMuxProvider{
		cfgs:  map[string]*ClientConfig{"node": nodeCfg},
		ctrls: map[string]*ControlConfig{"node": {Master: ControlMasterAuto, Path: sockPath, Persist: "yes"}},
	}
	dialer := newW13bCountingDialer()
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	c1, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("Connect(node): %v", err)
	}
	master1 := waitActiveMaster(t, sockPath, "displaced master1")

	// Displace c1.pooled into p.retired via Publish on the same HopDigest key.
	replacement := &PooledClient{
		SSHClient:    &cryptoSSH.Client{},
		RootConn:     &physicalSSHConn{Conn: &stubCloseConn{}},
		publishedCfg: NewClientConfig(*c1.pooled.publishedCfg),
	}
	displaced, err := connector.pool.Publish(c1.pooled.digest, replacement, nil, nil)
	if err != nil || displaced != c1.pooled {
		t.Fatalf("Publish displacement = (%p, %v), want (%p, nil)", displaced, err, c1.pooled)
	}
	assertW14bPoolRetiredAndValid(t, "post Publish displacement", connector.pool, 1)

	if err := c1.Close(); err != nil {
		t.Fatalf("displaced c1.Close(): %v", err)
	}
	assertW14bSocketUnlinked(t, "displaced c1", sockPath)
	assertW14bPoolRetiredAndValid(t, "post displaced c1.Close", connector.pool, 1)
	if got := connector.pool.Count(); got != 1 {
		t.Fatalf("active count after displaced c1.Close = %d, want 1 (replacement preserved)", got)
	}
	waitW14bMastersClosed(t, "displaced master1", master1)
}

func assertW14bM2RetiredTwoHopUnlinksBothMasters(t *testing.T, interruptTarget bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	suffix := "w14b-m2-2h-cls"
	if interruptTarget {
		suffix = "w14b-m2-2h-int"
	}
	h := newTwoHopMuxHarness(t, ctx, suffix, true, 30*time.Second, 500*time.Millisecond)

	targetCli, err := h.connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	bastionCli, err := h.connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	oldBastionMaster := waitActiveMaster(t, h.bastionSock, "initial bastion master")
	oldTargetMaster := waitActiveMaster(t, h.targetSock, "initial target master")

	// Retire bastion: moves both bastion and target into p.retired while keeping masters alive.
	h.connector.pool.Retire(ZeroHopDigest, bastionCli.pooled)
	assertW14bPoolRetiredAndValid(t, "post Retire(bastion)", h.connector.pool, 2)
	if !socketPathExists(h.bastionSock) || !socketPathExists(h.targetSock) {
		t.Fatal("expected both control sockets to stay live after Retire")
	}

	if interruptTarget {
		closeOrInterruptClient(t, "retired targetCli", targetCli, true)
	} else {
		closeOrInterruptClient(t, "retired bastionCli", bastionCli, false)
	}

	// Both bastionSock and targetSock must be synchronously unlinked before return.
	assertW14bSocketUnlinked(t, "retired 2-hop bastion", h.bastionSock)
	assertW14bSocketUnlinked(t, "retired 2-hop target", h.targetSock)
	assertW14bPoolRetiredAndValid(t, "post retired 2-hop teardown", h.connector.pool, 2)

	// Immediate reconnect without waiting on old masters must succeed and bind fresh masters.
	rebuilt, err := h.connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("immediate Connect(target) after retired 2-hop teardown failed: %v", err)
	}
	assertW9bRebuiltTwoHopClient(t, rebuilt, targetCli.pooled, bastionCli.pooled)
	execBarrierCheck(t, rebuilt)
	waitW14bMastersClosed(t, "retired 2-hop old masters", oldBastionMaster, oldTargetMaster)

	newBastionMaster := waitActiveMaster(t, h.bastionSock, "new bastion master")
	newTargetMaster := waitActiveMaster(t, h.targetSock, "new target master")
	if newBastionMaster == oldBastionMaster || newTargetMaster == oldTargetMaster {
		t.Fatal("expected distinct replacement masters after retired 2-hop teardown")
	}
}

func assertW14bM2ActiveBastionWithRetiredChildCloseAndInterrupt(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	h := newTwoHopMuxHarness(t, ctx, "w14b-m2-mix", true, 30*time.Second, 500*time.Millisecond)

	target1, err := h.connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	bastionCli, err := h.connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	bastionMaster := waitActiveMaster(t, h.bastionSock, "bastion master")
	targetMaster1 := waitActiveMaster(t, h.targetSock, "target master 1")

	// Retire ONLY target1: bastion remains active.
	h.connector.pool.Retire(ZeroHopDigest, target1.pooled)
	assertW14bPoolRetiredAndValid(t, "post Retire(target1)", h.connector.pool, 1)

	// Closing retired target1 unlinks targetSock synchronously while preserving active bastion.
	closeOrInterruptClient(t, "retired target1", target1, false)
	assertW14bSocketUnlinked(t, "retired target1.Close", h.targetSock)
	if !socketPathExists(h.bastionSock) || GetActiveMuxServer(h.bastionSock) != bastionMaster {
		t.Fatal("active bastion master was unexpectedly torn down by retired target1.Close()")
	}
	execBarrierCheck(t, bastionCli)
	waitW14bMastersClosed(t, "targetMaster1", targetMaster1)

	// Reconnect target2 over the surviving bastion, retire target2, then Interrupt target2:
	// BOTH target2's retired master AND active bastion's master must unlink synchronously.
	target2, err := h.connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target) #2: %v", err)
	}
	targetMaster2 := waitActiveMaster(t, h.targetSock, "target master 2")
	h.connector.pool.Retire(ZeroHopDigest, target2.pooled)

	closeOrInterruptClient(t, "retired target2", target2, true)
	assertW14bSocketUnlinked(t, "retired target2.Interrupt target", h.targetSock)
	assertW14bSocketUnlinked(t, "retired target2.Interrupt bastion", h.bastionSock)
	if got := h.connector.pool.Count(); got != 0 {
		t.Fatalf("active count after retired target2.Interrupt() = %d, want 0", got)
	}
	assertW14bPoolRetiredAndValid(t, "post retired target2.Interrupt", h.connector.pool, 2)
	waitW14bMastersClosed(t, "retired target2.Interrupt masters", bastionMaster, targetMaster2)
}

func assertW14bM2RetiredNilSSHClientClosesHopTransport(t *testing.T) {
	pool := newConnPool()
	rootConn := &stubCloseConn{}
	rootCfg := NewClientConfig(ClientConfig{NodeID: "root"})
	rootKey := DigestClientConfig(rootCfg, ZeroHopDigest)
	rootPooled := &PooledClient{
		SSHClient:    &cryptoSSH.Client{}, // Conn == nil
		RootConn:     rootConn,
		publishedCfg: rootCfg,
	}
	if _, err := pool.Publish(rootKey, rootPooled, nil, nil); err != nil {
		t.Fatalf("Publish(root): %v", err)
	}

	hopConn := &stubCloseConn{}
	childCfg := NewClientConfig(ClientConfig{NodeID: "child", ProxyJump: "root"})
	childKey := DigestClientConfig(childCfg, rootKey)
	childPooled := &PooledClient{
		SSHClient:    nil,
		RootConn:     rootConn,
		hopConn:      hopConn,
		parentKey:    rootKey,
		publishedCfg: childCfg,
	}
	if _, err := pool.Publish(childKey, childPooled, rootPooled, nil); err != nil {
		t.Fatalf("Publish(child): %v", err)
	}

	var childHookCalls, rootHookCalls atomic.Int32
	childPooled.setEvictHook(func() { childHookCalls.Add(1) })
	rootPooled.setEvictHook(func() { rootHookCalls.Add(1) })

	// Retire child only: closing child with nil SSHClient must close hopConn and
	// fire child's evict hook without closing shared rootConn.
	pool.Retire(childKey, childPooled)
	childCli := &Client{sshClient: nil, rootConn: rootConn, pooled: childPooled}
	if err := childCli.Close(); err != nil {
		t.Fatalf("retired childCli.Close(): %v", err)
	}
	if !hopConn.closed.Load() {
		t.Fatal("retired childCli.Close() did not call closeHopTransport() on hopConn")
	}
	if rootConn.closed.Load() {
		t.Fatal("retired jump child Close() must not close shared bastion RootConn")
	}
	if childHookCalls.Load() != 1 || rootHookCalls.Load() != 0 {
		t.Fatalf("evict hooks after child Close = (child=%d, root=%d), want (1, 0)", childHookCalls.Load(), rootHookCalls.Load())
	}

	// Now retire root (SSHClient.Conn == nil) and close it: must close rootConn
	// and fire root's evict hook while preserving RetiredCount().
	pool.Retire(rootKey, rootPooled)
	rootCli := &Client{sshClient: &cryptoSSH.Client{}, rootConn: rootConn, pooled: rootPooled}
	if err := rootCli.Close(); err != nil {
		t.Fatalf("retired rootCli.Close(): %v", err)
	}
	if !rootConn.closed.Load() {
		t.Fatal("retired rootCli.Close() with SSHClient.Conn==nil did not close RootConn via closeHopTransport()")
	}
	if rootHookCalls.Load() != 1 {
		t.Fatalf("root evict hook calls = %d, want 1", rootHookCalls.Load())
	}
	if got := pool.RetiredCount(); got != 2 {
		t.Fatalf("RetiredCount = %d, want 2", got)
	}
}

// TestP7W14b_C14_M2_RetiredPooledClientSynchronouslyUnlinksMuxMasterAndClosesTransport
// verifies C14-M2: closing or interrupting an already-retired PooledClient (or
// retired jump lineage) synchronously triggers reverse MuxServer evict hooks
// without mutating p.retired/p.closing, restores immediate ControlMaster sharing,
// and closes hop transports even when sshClient or sshClient.Conn is nil.
func TestP7W14b_C14_M2_RetiredPooledClientSynchronouslyUnlinksMuxMasterAndClosesTransport(t *testing.T) {
	t.Run("single_hop_auto_close", func(t *testing.T) {
		assertW14bM2SingleHopRetiredUnlinkAndShare(t, ControlMasterAuto, false)
	})
	t.Run("single_hop_auto_interrupt", func(t *testing.T) {
		assertW14bM2SingleHopRetiredUnlinkAndShare(t, ControlMasterAuto, true)
	})
	t.Run("single_hop_yes_close", func(t *testing.T) {
		assertW14bM2SingleHopRetiredUnlinkAndShare(t, ControlMasterYes, false)
	})
	t.Run("single_hop_yes_interrupt", func(t *testing.T) {
		assertW14bM2SingleHopRetiredUnlinkAndShare(t, ControlMasterYes, true)
	})
	t.Run("single_hop_publish_displaced_close", assertW14bM2PublishDisplacedRetiredUnlink)
	t.Run("retired_two_hop_bastion_close", func(t *testing.T) {
		assertW14bM2RetiredTwoHopUnlinksBothMasters(t, false)
	})
	t.Run("retired_two_hop_target_interrupt", func(t *testing.T) {
		assertW14bM2RetiredTwoHopUnlinksBothMasters(t, true)
	})
	t.Run("active_bastion_retired_child_close_and_interrupt", assertW14bM2ActiveBastionWithRetiredChildCloseAndInterrupt)
	t.Run("retired_nil_ssh_client_closes_hop_transport", assertW14bM2RetiredNilSSHClientClosesHopTransport)
}

func startW14bAgentDialServer(t *testing.T, ctx context.Context, holdSession <-chan struct{}) *w10bSSHServer {
	t.Helper()
	return startW10bSSHServer(t, ctx, w10bSSHServerHooks{
		onSession: func(connCtx context.Context, sConn *cryptoSSH.ServerConn, newCh cryptoSSH.NewChannel) {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				return
			}
			var agentWG sync.WaitGroup
			defer agentWG.Wait()
			defer func() { _ = ch.Close() }()

			for req := range reqs {
				switch req.Type {
				case agentForwardRequestType:
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					agentWG.Go(func() {
						aCh, aReqs, openErr := sConn.OpenChannel(agentForwardChannelType, nil)
						if openErr != nil {
							return
						}
						go cryptoSSH.DiscardRequests(aReqs)
						_ = aCh.Close()
					})
				case "exec":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					select {
					case <-holdSession:
					case <-connCtx.Done():
					}
					go cryptoSSH.DiscardRequests(reqs)
					return
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		},
	})
}

// TestP7W14b_C14_L1_DispatchLoopExitCancelsInFlightAgentDialImmediately verifies
// C14-L1: when the underlying SSH transport tears down while a forwarded agent
// channel is blocked in a slow/hung local-agent dial (agentForwardDialTimeout=10s)
// and before lease.Release() is called, sshAgentChannelRouter.dispatchLoop's exit
// immediately cancels r.epoch so the dial aborts in milliseconds with zero leaks.
func TestP7W14b_C14_L1_DispatchLoopExitCancelsInFlightAgentDialImmediately(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	runtime.GC()
	baseline := runtime.NumGoroutine()

	holdSession := make(chan struct{})
	defer close(holdSession)
	sshSrv := startW14bAgentDialServer(t, ctx, holdSession)

	dialStarted := make(chan struct{}, 1)
	dialErrCh := make(chan error, 1)
	dialAgent := func(dialCtx context.Context, _ string) (net.Conn, error) {
		select {
		case dialStarted <- struct{}{}:
		default:
		}
		<-dialCtx.Done()
		dialErrCh <- dialCtx.Err()
		return nil, dialCtx.Err()
	}

	rawTCP, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", sshSrv.addr)
	if err != nil {
		t.Fatalf("dial sshSrv: %v", err)
	}
	cConn, chans, reqs, err := cryptoSSH.NewClientConn(rawTCP, sshSrv.addr, &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		_ = rawTCP.Close()
		t.Fatalf("NewClientConn: %v", err)
	}
	rawSSH := cryptoSSH.NewClient(cConn, chans, reqs)
	t.Cleanup(func() {
		_ = rawTCP.Close()
		_ = rawSSH.Close()
	})

	cli := newClient(rawSSH, rawTCP, &ClientConfig{
		NodeID:  "agent-node",
		Address: "127.0.0.1",
		Port:    22,
		User:    "fixture",
		Options: newW11bForwardAgentOptions(t),
	}, nil, "")
	cli.environment = Environment{
		AgentSocket: "/tmp/w14b-hung-agent.sock",
		DialAgent:   dialAgent,
	}

	// Acquire a live session lease and send auth-agent-req@openssh.com WITHOUT
	// releasing the lease yet, then wait for the remote peer's auth-agent channel
	// to enter our blocking dialAgent callback.
	sess, err := cli.newSessionContext(ctx)
	if err != nil {
		t.Fatalf("newSessionContext: %v", err)
	}
	releaseAgent, err := cli.enableSessionAgentForward(ctx, sess)
	if err != nil {
		_ = sess.Close()
		t.Fatalf("enableSessionAgentForward: %v", err)
	}
	defer releaseAgent()

	select {
	case <-dialStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for forwarded agent channel to start dialing local agent")
	}

	// Tear down the SSH transport while the lease is still held (simulating
	// abrupt remote/network teardown before session cleanup calls releaseAgent).
	start := time.Now()
	if err := rawTCP.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("rawTCP.Close(): %v", err)
	}
	_ = rawSSH.Close()

	select {
	case dialErr := <-dialErrCh:
		if !errors.Is(dialErr, context.Canceled) {
			t.Fatalf("dialAgent error = %v, want context.Canceled", dialErr)
		}
		if elapsed := time.Since(start); elapsed >= 2*time.Second {
			t.Fatalf("in-flight local agent dial took %s to cancel after transport close, want immediate cancellation", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight local agent dial did NOT cancel promptly on dispatchLoop exit (hung waiting for agentForwardDialTimeout)")
	}

	waitForCondition(t, 2*time.Second, func() bool {
		_, ok := sshAgentRouters.Load(rawSSH)
		return !ok
	}, "sshAgentRouters entry not cleaned up after transport close")

	_ = sess.Close()
	releaseAgent()
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "w14b agent dispatchLoop exit goroutines")
}

// TestP7W14b_SessionOutputErrorDeduplication verifies that when output.failed
// wins the wait select before ctx.Done(), neither resolveSessionErrors,
// finalizeSubsystemResult, nor runTerminalSession's wait/join path duplicates
// the sink's *OutputError, and startSessionOutput preserves FIFO failure order.
func TestP7W14b_SessionOutputErrorDeduplication(t *testing.T) {
	t.Parallel()

	t.Run("resolveSessionErrors_deduplicates_outputFailedErr", func(t *testing.T) {
		sink := &privilegeContextSink{}
		shared := errors.Join(&OutputError{Target: sink, Err: context.Canceled})
		outputErr := errors.Join(context.Canceled, shared)
		got := resolveSessionErrors(context.Canceled, context.Canceled, shared, nil, nil, outputErr)
		if count := countSinkOutputErrors(got, sink); count != 1 {
			t.Fatalf("resolveSessionErrors OutputError count = %d, want 1 in %v", count, got)
		}
		var outErr *OutputError
		if !errors.As(got, &outErr) || outErr.Target != sink {
			t.Fatalf("resolveSessionErrors lost OutputError target: %v", got)
		}

		// Distinct outputFailedErr (not present in outputErr) must still be preserved.
		otherErr := errors.New("distinct output failure")
		gotDistinct := resolveSessionErrors(nil, nil, otherErr, nil, nil, outputErr)
		if !errors.Is(gotDistinct, otherErr) || countSinkOutputErrors(gotDistinct, sink) != 1 {
			t.Fatalf("resolveSessionErrors dropped distinct error: %v", gotDistinct)
		}
	})

	t.Run("finalizeSubsystemResult_deduplicates_outputFailedErr", func(t *testing.T) {
		sink := &privilegeContextSink{}
		shared := errors.Join(&OutputError{Target: sink, Err: context.Canceled})
		outputErr := errors.Join(context.Canceled, shared)
		got := finalizeSubsystemResult(t.Context(), CommandResult{Outcome: ExecutionUnknown}, shared, nil, nil, outputErr)
		if count := countSinkOutputErrors(got, sink); count != 1 {
			t.Fatalf("finalizeSubsystemResult OutputError count = %d, want 1 in %v", count, got)
		}
		otherErr := errors.New("distinct subsystem output failure")
		gotDistinct := finalizeSubsystemResult(t.Context(), CommandResult{Outcome: ExecutionUnknown}, otherErr, nil, nil, outputErr)
		if !errors.Is(gotDistinct, otherErr) || countSinkOutputErrors(gotDistinct, sink) != 1 {
			t.Fatalf("finalizeSubsystemResult dropped distinct error: %v", gotDistinct)
		}
	})

	t.Run("startSessionOutput_outputFailed_is_contained_in_wait_without_duplication", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		sink := &privilegeContextSink{entered: make(chan struct{}), block: true}
		stdoutWriter, stderrWriter, closeOutput, err := bindStrictOutputs(ctx, sink, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = closeOutput() }()

		outR, outW := io.Pipe()
		defer func() {
			_ = outR.Close()
			_ = outW.Close()
		}()
		go func() {
			_, _ = io.WriteString(outW, "payload")
			_ = outW.Close()
		}()

		output := startSessionOutput(outR, nil, stdoutWriter, stderrWriter)
		<-sink.entered
		cancel()

		outputFailedErr := <-output.failed
		outputErr := waitSessionOutput(ctx, output.wait, cancel)
		if !errors.Is(outputErr, outputFailedErr) {
			t.Fatalf("expected waitSessionOutput error %v to contain outputFailedErr %v", outputErr, outputFailedErr)
		}
		// Joining with the deduplication guard must keep exactly 1 OutputError for sink.
		var combined error
		if outputFailedErr != nil {
			if outputErr != nil && errors.Is(outputErr, outputFailedErr) {
				combined = errors.Join(outputErr, context.Canceled)
			} else {
				combined = errors.Join(outputFailedErr, context.Canceled, outputErr)
			}
		}
		if count := countSinkOutputErrors(combined, sink); count != 1 {
			t.Fatalf("deduplicated terminal/session OutputError count = %d, want 1 in %v", count, combined)
		}
	})
}
