package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// TestW9b_C9_M1_SingleHopBlackholedProbeEvictsMuxMasterBeforeTryConnect verifies
// C9-M1 on a single-hop ControlMaster=auto connection: when the transport
// blackholes and Connect(ctx, node) triggers probeCachedClient timeout -> pool
// Evict, the reverse PooledClient -> MuxServer hook synchronously runs
// server.beginShutdown() (unlinking sockPath and closing the Unix listener)
// BEFORE connectNode reaches tryConnectMultiplex, so Connect cleanly dials a
// fresh connection and binds a fresh control socket instead of attaching a
// zombie proxy or failing with ErrControlProxyRejected.
func TestW9b_C9_M1_SingleHopBlackholedProbeEvictsMuxMasterBeforeTryConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	srv := newKeepAliveBarrierServer(t, ctx)
	host, port := fixtureEndpoint(t, srv.addr)
	sockPath := filepath.Join(shortSocketDir(t), "w9b-m1-single.sock")

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
	// Long interval avoids background keepalive interference while bounding
	// probeCachedClient to 180ms.
	connector.EnableKeepAlive(kaCtx, 30*time.Second, 180*time.Millisecond)
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	firstCli, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("initial Connect(node): %v", err)
	}
	firstPooled := firstCli.pooled
	if firstPooled == nil {
		t.Fatal("expected initial PooledClient")
	}
	firstMaster := waitActiveMaster(t, sockPath, "initial single-hop master")
	if !socketPathExists(sockPath) {
		t.Fatalf("expected initial control socket %q on disk", sockPath)
	}
	assertPoolInvariantsAndCounts(t, "initial single-hop", connector.pool, 1, 0)

	// Blackhole the initial physical transport so probeCachedClient times out.
	firstPhys := dialer.connAt(0)
	if firstPhys == nil {
		t.Fatal("expected dialer to record initial physical connection")
	}
	firstPhys.blackhole.Store(true)

	// Connect must synchronously unlink firstMaster's socket during probe/Evict
	// before tryConnectMultiplex runs, then dial a fresh connection + master.
	secondCli, err := connector.Connect(ctx, "node")
	if err != nil {
		t.Fatalf("reconnect Connect(node) after blackhole failed: %v", err)
	}
	if secondCli.pooled == nil || secondCli.pooled == firstPooled {
		t.Fatal("expected Connect after blackhole to establish a fresh PooledClient")
	}
	if secondCli.pooled.ControlSocketPath != "" {
		t.Fatalf("Connect attached zombie proxy to %q instead of dialing fresh master", secondCli.pooled.ControlSocketPath)
	}
	if gotDials := modeSwitchDialCount(dialer); gotDials != 2 {
		t.Fatalf("dial count = %d, want 2", gotDials)
	}

	select {
	case <-firstMaster.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("evicted firstMaster did not complete async Shutdown")
	}

	secondMaster := waitActiveMaster(t, sockPath, "replacement single-hop master")
	if secondMaster == firstMaster {
		t.Fatal("expected replacement master to be a distinct MuxServer instance")
	}
	assertPoolInvariantsAndCounts(t, "post-blackhole-reconnect", connector.pool, 1, 0)
	execBarrierCheck(t, secondCli)
}

// TestW9b_C9_M1_BastionShutdownCascadeUnlinksTargetSocketSynchronously verifies
// C9-M1 on a 2-hop bastion -> target chain with ControlMaster=auto on both
// hops: before bastionMaster.Shutdown() returns, targetMaster.beginShutdown()
// has ALREADY unlinked targetSock and closed targetMaster's listener, so an
// immediate Connector.Connect(ctx, "target") WITHOUT waiting on
// <-targetMaster.Wait() observes hasControlSocket==false and cleanly dials a
// fresh bastion -> target chain.
func TestW9b_C9_M1_BastionShutdownCascadeUnlinksTargetSocketSynchronously(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	h := newTwoHopMuxHarness(t, ctx, "w9b-m1-2hop", true, 30*time.Second, 500*time.Millisecond)

	firstTarget, err := h.connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("initial Connect(target): %v", err)
	}
	firstTargetPooled := firstTarget.pooled
	if firstTargetPooled == nil || firstTargetPooled.parent == nil {
		t.Fatal("expected initial target PooledClient with bastion parent")
	}
	firstBastionPooled := firstTargetPooled.parent

	bastionMaster := waitActiveMaster(t, h.bastionSock, "bastion master")
	targetMaster := waitActiveMaster(t, h.targetSock, "target master")
	if !socketPathExists(h.bastionSock) || !socketPathExists(h.targetSock) {
		t.Fatal("expected both bastion and target control sockets on disk")
	}
	assertPoolInvariantsAndCounts(t, "initial 2-hop", h.connector.pool, 2, 0)

	plan, err := h.connector.resolveConnectionPlan(ctx, "target")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(target): %v", err)
	}

	// Shut down bastionMaster directly and DO NOT wait on <-targetMaster.Wait().
	waitWithin(t, "bastionMaster.Shutdown()", 500*time.Millisecond, func() {
		if err := bastionMaster.Shutdown(); err != nil {
			t.Errorf("bastionMaster.Shutdown(): %v", err)
		}
	})

	// Synchronously upon bastionMaster.Shutdown() returning, targetSock MUST
	// already be unlinked and targetMaster removed from activeMuxServers.
	assertW9bCascadeTargetUnlinked(t, h, plan[0])

	// Immediate Connect(target) without waiting on <-targetMaster.Wait() must
	// cleanly dial a fresh bastion -> target chain and bind fresh masters.
	rebuilt, err := h.connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("immediate Connect(target) after bastionMaster.Shutdown() failed: %v", err)
	}
	assertW9bRebuiltTwoHopClient(t, rebuilt, firstTargetPooled, firstBastionPooled)

	select {
	case <-targetMaster.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("cascade-evicted targetMaster did not complete async Shutdown")
	}

	newTargetMaster := waitActiveMaster(t, h.targetSock, "replacement target master")
	if newTargetMaster == targetMaster {
		t.Fatal("expected fresh target master instance after rebuild")
	}
	assertPoolInvariantsAndCounts(t, "post-immediate-2hop-rebuild", h.connector.pool, 2, 0)
	execBarrierCheck(t, rebuilt)
}

func assertW9bCascadeTargetUnlinked(t *testing.T, h *twoHopMuxHarness, targetPlan connectionPlanNode) {
	t.Helper()
	if socketPathExists(h.bastionSock) {
		t.Fatalf("bastionSock %q survived bastionMaster.Shutdown()", h.bastionSock)
	}
	if socketPathExists(h.targetSock) {
		t.Fatalf("targetSock %q was NOT synchronously unlinked by cascade eviction", h.targetSock)
	}
	if got := GetActiveMuxServer(h.targetSock); got != nil {
		t.Fatalf("activeMuxServers still holds %v for targetSock after bastionMaster.Shutdown()", got)
	}
	if hasSock, sockErr := h.connector.hasControlSocket(targetPlan); sockErr != nil || hasSock {
		t.Fatalf("hasControlSocket(target) = (%v, %v), want (false, nil)", hasSock, sockErr)
	}
}

func assertW9bRebuiltTwoHopClient(t *testing.T, rebuilt *Client, oldTarget, oldBastion *PooledClient) {
	t.Helper()
	if rebuilt.pooled == nil || rebuilt.pooled == oldTarget {
		t.Fatal("expected rebuilt target to have a fresh PooledClient")
	}
	if rebuilt.pooled.ControlSocketPath != "" {
		t.Fatalf("rebuilt target unexpectedly attached to proxy socket %q", rebuilt.pooled.ControlSocketPath)
	}
	if rebuilt.pooled.parent == nil || rebuilt.pooled.parent == oldBastion {
		t.Fatal("expected rebuilt target to ride on a fresh bastion PooledClient")
	}
}

// TestW9b_C9_M1_PreEvictedHookFiresImmediatelyAndRetirePreservesMaster verifies
// two boundary invariants of the PooledClient -> MuxServer hook:
//  1. If a PooledClient was already evicted before setEvictHook runs (race
//     between publishPooled and maybeStartMasterListener), setEvictHook fires
//     immediately and unlinks the socket synchronously.
//  2. Non-disruptive Retire leaves an attached MuxServer running and listening.
func TestW9b_C9_M1_PreEvictedHookFiresImmediatelyAndRetirePreservesMaster(t *testing.T) {
	t.Run("pre_evicted_fires_synchronously_on_attach", func(t *testing.T) {
		sockPath := filepath.Join(shortSocketDir(t), "w9b-preevict.sock")
		srv, err := NewMuxServer(MuxServerOptions{
			ControlPath:       sockPath,
			PeerCheck:         PeerCheckDisabledForTesting,
			SSHClient:         newDummySSHClient(),
			PersistEnabled:    true,
			PersistIndefinite: true,
		})
		if err != nil {
			t.Fatalf("NewMuxServer: %v", err)
		}
		t.Cleanup(func() { _ = srv.Shutdown() })

		pool := newConnPool()
		pCfg := NewClientConfig(ClientConfig{NodeID: "pre"})
		key := DigestClientConfig(pCfg, ZeroHopDigest)
		pc := &PooledClient{
			SSHClient:    &cryptoSSH.Client{},
			RootConn:     &physicalSSHConn{Conn: &stubCloseConn{}},
			publishedCfg: pCfg,
		}
		if _, err := pool.Publish(key, pc, nil, nil); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		pool.Evict(key, pc, true)

		// Attach hook AFTER eviction already ran: socket must be unlinked
		// synchronously before setEvictHook returns.
		pc.setEvictHook(srv.evictFromPool)
		if socketPathExists(sockPath) {
			t.Fatalf("socket %q remained on disk after attaching hook to pre-evicted client", sockPath)
		}
		select {
		case <-srv.Wait():
		case <-time.After(2 * time.Second):
			t.Fatal("pre-evicted master did not complete Shutdown")
		}
	})

	t.Run("retire_does_not_shutdown_master", func(t *testing.T) {
		sockPath := filepath.Join(shortSocketDir(t), "w9b-retire.sock")
		srv, err := NewMuxServer(MuxServerOptions{
			ControlPath:       sockPath,
			PeerCheck:         PeerCheckDisabledForTesting,
			SSHClient:         newDummySSHClient(),
			PersistEnabled:    true,
			PersistIndefinite: true,
		})
		if err != nil {
			t.Fatalf("NewMuxServer: %v", err)
		}
		t.Cleanup(func() { _ = srv.Shutdown() })

		pool := newConnPool()
		pCfg := NewClientConfig(ClientConfig{NodeID: "ret"})
		key := DigestClientConfig(pCfg, ZeroHopDigest)
		pc := &PooledClient{
			SSHClient:    &cryptoSSH.Client{},
			RootConn:     &physicalSSHConn{Conn: &stubCloseConn{}},
			publishedCfg: pCfg,
		}
		if _, err := pool.Publish(key, pc, nil, nil); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		pc.setEvictHook(srv.evictFromPool)

		pool.Retire(key, pc)
		if !socketPathExists(sockPath) {
			t.Fatalf("non-disruptive Retire unexpectedly unlinked %q", sockPath)
		}
		if srv.currentPhase() != muxPhaseRunning {
			t.Fatalf("non-disruptive Retire changed master phase to %d, want muxPhaseRunning", srv.currentPhase())
		}
	})
}

// TestW9b_C9_M2_DialSSHMuxBoundedAbandonmentNoGoroutineLeak verifies C9-M2
// cross-platform: MuxServer.dialSSHMux (for both TCP direct-tcpip and Unix
// direct-streamlocal@openssh.com) uses bounded abandonment with
// closeMuxChannelBounded instead of ssh.Client.DialContext, so a late open
// returning over a write-wedged transport escalates to PhysicalRootConn and
// leaks zero goroutines.
func TestW9b_C9_M2_DialSSHMuxBoundedAbandonmentNoGoroutineLeak(t *testing.T) {
	cases := []struct {
		name    string
		network string
		addr    string
	}{
		{name: "tcp_direct_tcpip", network: "tcp", addr: "127.0.0.1:22"},
		{name: "unix_direct_streamlocal", network: "unix", addr: "/tmp/w9b-remote.sock"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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

			sockPath := filepath.Join(shortSocketDir(t), "w9b-dial-"+tc.network+".sock")
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
			srv.requestTimeout = 40 * time.Millisecond
			t.Cleanup(func() {
				rootCloseOnce.Do(func() { close(rootClosedCh) })
				_ = srv.Shutdown()
			})

			runtime.GC()
			baseline := runtime.NumGoroutine()

			conn, dialErr := srv.dialSSHMux(t.Context(), tc.network, tc.addr)
			if conn != nil {
				_ = conn.Close()
				t.Fatal("expected dialSSHMux to fail on timeout, got non-nil conn")
			}
			if !errors.Is(dialErr, context.DeadlineExceeded) {
				t.Fatalf("dialSSHMux(%s) err = %v, want context.DeadlineExceeded", tc.network, dialErr)
			}
			// Healthy master must stay running before late channel close stalls.
			if srv.isShuttingDown() {
				t.Fatal("dialSSHMux timeout tore down master before late channel close stalled")
			}

			// Release late OpenChannel so abandoned goroutine hits
			// closeMuxChannelBounded on the stalled channel close.
			close(sshConn.releaseCh)

			select {
			case <-srv.Wait():
			case <-time.After(sessionShutdownTimeout + 500*time.Millisecond):
				t.Fatal("abandoned dialSSHMux late channel close stalled without escalating")
			}
			if !physRoot.closed.Load() {
				t.Fatal("expected dialSSHMux abandonment escalation to close PhysicalRootConn")
			}
			select {
			case <-sshConn.closeDone:
			case <-time.After(500 * time.Millisecond):
				t.Fatal("stalled channel Close did not unblock after PhysicalRootConn abort")
			}
			waitForGoroutinesAtMost(t, baseline+1, 500*time.Millisecond, "C9-M2 dialSSHMux goroutine check")
		})
	}
}

func dialSocks5ThroughForward(t *testing.T, socksAddr, destHost string, destPort uint32) net.Conn {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(t.Context(), "tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial SOCKS5 listener %s: %v", socksAddr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	// Greeting: VER=5, NMETHODS=1, NO AUTH (0x00)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	var greetResp [2]byte
	if _, err := io.ReadFull(conn, greetResp[:]); err != nil || greetResp != [2]byte{0x05, 0x00} {
		_ = conn.Close()
		t.Fatalf("read SOCKS5 greeting reply: %v (%x)", err, greetResp)
	}
	ip4 := net.ParseIP(destHost).To4()
	if ip4 == nil {
		_ = conn.Close()
		t.Fatalf("expected IPv4 destHost, got %q", destHost)
	}
	req := make([]byte, 10)
	req[0] = 0x05
	req[1] = 0x01 // CONNECT
	req[2] = 0x00
	req[3] = 0x01 // IPv4
	copy(req[4:8], ip4)
	binary.BigEndian.PutUint16(req[8:10], uint16(destPort))
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		t.Fatalf("write SOCKS5 CONNECT: %v", err)
	}
	var rep [10]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil || rep[1] != 0x00 {
		_ = conn.Close()
		t.Fatalf("read SOCKS5 CONNECT reply: err=%v rep=%x", err, rep)
	}
	// Verify round-trip echo through SOCKS5 stream.
	const payload = "w9b-socks5-ping\n"
	if _, err := io.WriteString(conn, payload); err != nil {
		_ = conn.Close()
		t.Fatalf("write SOCKS5 payload: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != payload {
		_ = conn.Close()
		t.Fatalf("read SOCKS5 echo: got=%q err=%v", string(buf), err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn
}

func assertW9bWedgedDrainUnblocks(
	t *testing.T,
	ctx context.Context,
	srv *MuxServer,
	rootConn *modeSwitchConn,
	sockPath string,
	closeLocalTrigger func(),
	baselineGoroutines int,
	label string,
) {
	t.Helper()
	// Start WaitForDrain concurrently to verify activeForwardStreams unblocks it.
	drainDone := make(chan error, 1)
	go func() {
		drainDone <- srv.WaitForDrain(ctx, 0)
	}()

	// Wedge SSH transport writes BEFORE local side closes, while MuxServer is
	// draining after -O stop (waiting for activeForwardStreams to reach 0).
	rootConn.wedgeWrite.Store(true)
	closeLocalTrigger()

	waitWithin(t, label+": bounded CloseWrite/Close escalation", 600*time.Millisecond, func() {
		<-srv.Wait()
	})
	select {
	case drainErr := <-drainDone:
		if drainErr != nil {
			t.Fatalf("%s: WaitForDrain returned %v", label, drainErr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("%s: WaitForDrain remained wedged", label)
	}
	if !rootConn.closed.Load() {
		t.Fatalf("%s: expected escalation to abort write-wedged RootConn", label)
	}
	assertW7aMuxDrainedClosed(t, srv, sockPath)
	waitForGoroutinesAtMost(t, baselineGoroutines+2, time.Second, label+" goroutine check")
}

// TestW9b_C9_M2_ForwardStreamsBoundedCloseWriteAndCloseOnWedgedTransport
// verifies C9-M2 across all three MuxServer forward modes (-L, -D SOCKS5, -R)
// plus isolated stalled Close() after healthy CloseWrite(): closing the local
// stream over a write-wedged transport escalates within channelCloseTimeout,
// completes defer removeActiveForwardStream(), unblocks -O stop / WaitForDrain,
// and leaks zero goroutines.
func TestW9b_C9_M2_ForwardStreamsBoundedCloseWriteAndCloseOnWedgedTransport(t *testing.T) {
	t.Run("a_local_forward_L_closeWrite_unblocks_stop_and_drain", testW9bC9M2LocalForwardWedged)
	t.Run("b_dynamic_forward_D_socks5_closeWrite_and_close_unblock_drain", testW9bC9M2DynamicSocks5Wedged)
	t.Run("c_remote_forward_R_closeWrite_and_close_unblock_drain", testW9bC9M2RemoteForwardWedged)
	t.Run("d_stalled_close_after_healthy_closeWrite_escalates", testW9bC9M2StalledCloseAfterHealthyCloseWrite)
}

func testW9bC9M2LocalForwardWedged(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	echoBackend := startW7aEchoBackend(t)
	sshSrv := startW7aForwardSSHServer(t, ctx)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, rootConn, sockPath := dialW7aDirectMux(t, ctx, sshSrv, "w9b-m2-L.sock")
	srv.requestTimeout = 80 * time.Millisecond

	muxCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	localPort := pickFreeLocalTCPPort(t)
	if _, err := muxCli.OpenForward(ctx, ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  "127.0.0.1",
		ListenPort:  localPort,
		ConnectHost: echoBackend.host,
		ConnectPort: echoBackend.port,
	}); err != nil {
		t.Fatalf("OpenForward(-L): %v", err)
	}
	localStream := openW7aVerifiedTCPStream(t, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(localPort), 10)), "w9b-L\n")

	// -O stop while -L stream is active leaves server in StoppingListen waiting
	// for activeForwardStreams to drain to 0.
	if err := muxCli.StopListening(ctx); err != nil {
		t.Fatalf("StopListening: %v", err)
	}
	_ = muxCli.Close()
	assertMuxPhase(t, srv, muxPhaseStoppingListen, true)

	assertW9bWedgedDrainUnblocks(t, ctx, srv, rootConn, sockPath, func() {
		_ = localStream.Close()
	}, baseline, "-L forward")
}

func testW9bC9M2DynamicSocks5Wedged(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	echoBackend := startW7aEchoBackend(t)
	sshSrv := startW7aForwardSSHServer(t, ctx)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, rootConn, sockPath := dialW7aDirectMux(t, ctx, sshSrv, "w9b-m2-D.sock")
	srv.requestTimeout = 80 * time.Millisecond

	muxCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	socksPort := pickFreeLocalTCPPort(t)
	if _, err := muxCli.OpenForward(ctx, ForwardRequest{
		Type:       ForwardDynamic,
		ListenHost: "127.0.0.1",
		ListenPort: socksPort,
	}); err != nil {
		t.Fatalf("OpenForward(-D): %v", err)
	}
	socksStream := dialSocks5ThroughForward(
		t,
		net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(socksPort), 10)),
		echoBackend.host,
		echoBackend.port,
	)

	if err := muxCli.StopListening(ctx); err != nil {
		t.Fatalf("StopListening: %v", err)
	}
	_ = muxCli.Close()
	assertMuxPhase(t, srv, muxPhaseStoppingListen, true)

	assertW9bWedgedDrainUnblocks(t, ctx, srv, rootConn, sockPath, func() {
		_ = socksStream.Close()
	}, baseline, "-D SOCKS5 forward")
}

func testW9bC9M2RemoteForwardWedged(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	// Local backend for -R whose accepted server-side socket we can close
	// directly to trigger EOF on local -> remote.CloseWrite() inside serveRemoteForward.
	localLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen local -R backend: %v", err)
	}
	defer func() { _ = localLn.Close() }()
	localTCPAddr := localLn.Addr().(*net.TCPAddr)

	backendAccepted := make(chan net.Conn, 1)
	closeBackendCh := make(chan struct{})
	var backendWG sync.WaitGroup
	backendWG.Go(func() {
		c, accErr := localLn.Accept()
		if accErr != nil {
			return
		}
		backendAccepted <- c
		buf := make([]byte, 64)
		if n, rErr := c.Read(buf); rErr == nil && n > 0 {
			_, _ = c.Write(buf[:n])
		}
		<-closeBackendCh
		_ = c.Close()
	})
	t.Cleanup(func() {
		select {
		case <-closeBackendCh:
		default:
			close(closeBackendCh)
		}
		_ = localLn.Close()
		backendWG.Wait()
	})

	sshSrv := startW7aForwardSSHServer(t, ctx)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, rootConn, sockPath := dialW7aDirectMux(t, ctx, sshSrv, "w9b-m2-R.sock")
	srv.requestTimeout = 80 * time.Millisecond

	muxCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	remotePort, err := muxCli.OpenForward(ctx, ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: localTCPAddr.IP.String(),
		ConnectPort: uint32(localTCPAddr.Port),
	})
	if err != nil || remotePort == 0 {
		t.Fatalf("OpenForward(-R): port=%d err=%v", remotePort, err)
	}

	remoteClient := openW7aVerifiedTCPStream(t, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(remotePort), 10)), "w9b-R\n")
	defer func() { _ = remoteClient.Close() }()

	select {
	case <-backendAccepted:
	case <-time.After(2 * time.Second):
		t.Fatal("local -R backend did not accept forwarded connection")
	}

	if err := muxCli.StopListening(ctx); err != nil {
		t.Fatalf("StopListening: %v", err)
	}
	_ = muxCli.Close()
	assertMuxPhase(t, srv, muxPhaseStoppingListen, true)

	assertW9bWedgedDrainUnblocks(t, ctx, srv, rootConn, sockPath, func() {
		close(closeBackendCh)
	}, baseline, "-R remote forward")
}

func testW9bC9M2StalledCloseAfterHealthyCloseWrite(t *testing.T) {
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
	sockPath := filepath.Join(shortSocketDir(t), "w9b-m2-close-stall.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		PeerCheck:         PeerCheckDisabledForTesting,
		SSHClient:         newDummySSHClient(),
		RootConn:          rawHop,
		PhysicalRootConn:  physRoot,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	srv.requestTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		rootCloseOnce.Do(func() { close(rootClosedCh) })
		_ = srv.Shutdown()
	})

	closeDone := make(chan struct{})
	var closeOnce sync.Once
	stalledCh := &stalledUntilAbortChannel{
		rootClosedCh: rootClosedCh,
		closeDone:    closeDone,
		closeOnce:    &closeOnce,
	}
	reqsDone := make(chan struct{})
	close(reqsDone)
	wrapped := &muxForwardChannelConn{
		ch:         stalledCh,
		server:     srv,
		localAddr:  &net.TCPAddr{IP: net.IPv4zero, Port: 0},
		remoteAddr: forwardTCPAddr{addr: "127.0.0.1:80"},
		reqsDone:   reqsDone,
	}

	// CloseWrite succeeds on this channel, while Close stalls until abort.
	if err := wrapped.CloseWrite(); err != nil {
		t.Fatalf("healthy CloseWrite returned unexpected error: %v", err)
	}
	if srv.isShuttingDown() {
		t.Fatal("healthy CloseWrite unexpectedly triggered shutdown")
	}

	var closeErr error
	waitWithin(t, "bounded Close() escalation", 500*time.Millisecond, func() {
		closeErr = wrapped.Close()
	})
	if closeErr == nil {
		t.Fatal("expected timeout error from stalled Close()")
	}
	if !physRoot.closed.Load() {
		t.Fatal("stalled Close() did not escalate to PhysicalRootConn")
	}
	select {
	case <-closeDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("stalled channel Close did not unblock after escalation")
	}
}

// TestW9b_C9_L1_AliveCheckRejectsNonRunningAndClosedRoot verifies C9-L1 in
// MuxServer.handleAliveCheck: AliveCheck returns MUX_S_ALIVE only when the
// master is in muxPhaseRunning with an unclosed transport, and replies
// MUX_S_FAILURE in HandoffReserved, StoppingListen, ShuttingDown, Closed, or
// when RootConn/PhysicalRootConn is already closed.
func TestW9b_C9_L1_AliveCheckRejectsNonRunningAndClosedRoot(t *testing.T) {
	t.Run("running_replies_alive", func(t *testing.T) {
		srv := &MuxServer{
			phase:        muxPhaseRunning,
			rootConn:     &physicalSSHConn{Conn: &stubCloseConn{}},
			idleNotify:   make(chan struct{}),
			shutdownChan: make(chan struct{}),
		}
		pt := runSyncMuxPacketCall(t, func(c net.Conn) error {
			return srv.handleAliveCheck(c, 1)
		})
		if pt != MUX_S_ALIVE {
			t.Fatalf("handleAliveCheck(Running) = 0x%x, want MUX_S_ALIVE", pt)
		}
	})

	nonRunningPhases := []struct {
		name  string
		phase muxPhase
	}{
		{name: "handoff_reserved", phase: muxPhaseHandoffReserved},
		{name: "stopping_listen", phase: muxPhaseStoppingListen},
		{name: "shutting_down", phase: muxPhaseShuttingDown},
		{name: "closed", phase: muxPhaseClosed},
	}
	for _, tc := range nonRunningPhases {
		t.Run("phase_"+tc.name+"_replies_failure", func(t *testing.T) {
			srv := &MuxServer{
				phase:        tc.phase,
				idleNotify:   make(chan struct{}),
				shutdownChan: make(chan struct{}),
			}
			pt := runSyncMuxPacketCall(t, func(c net.Conn) error {
				return srv.handleAliveCheck(c, 2)
			})
			if pt != MUX_S_FAILURE {
				t.Fatalf("handleAliveCheck(%s) = 0x%x, want MUX_S_FAILURE", tc.name, pt)
			}
		})
	}

	t.Run("closed_rootConn_replies_failure", func(t *testing.T) {
		closedRoot := &physicalSSHConn{Conn: &stubCloseConn{}}
		_ = closedRoot.Close()
		srv := &MuxServer{
			phase:        muxPhaseRunning,
			rootConn:     closedRoot,
			idleNotify:   make(chan struct{}),
			shutdownChan: make(chan struct{}),
		}
		pt := runSyncMuxPacketCall(t, func(c net.Conn) error {
			return srv.handleAliveCheck(c, 3)
		})
		if pt != MUX_S_FAILURE {
			t.Fatalf("handleAliveCheck(closed rootConn) = 0x%x, want MUX_S_FAILURE", pt)
		}
	})

	t.Run("closed_physicalRoot_replies_failure", func(t *testing.T) {
		closedPhys := &physicalSSHConn{Conn: &stubCloseConn{}}
		_ = closedPhys.Close()
		srv := &MuxServer{
			phase:        muxPhaseRunning,
			rootConn:     &stubCloseConn{},
			physicalRoot: closedPhys,
			idleNotify:   make(chan struct{}),
			shutdownChan: make(chan struct{}),
		}
		pt := runSyncMuxPacketCall(t, func(c net.Conn) error {
			return srv.handleAliveCheck(c, 4)
		})
		if pt != MUX_S_FAILURE {
			t.Fatalf("handleAliveCheck(closed physicalRoot) = 0x%x, want MUX_S_FAILURE", pt)
		}
	})
}

func startFakeMuxProxyReplyServer(t *testing.T, sockPath string, target TargetContext, proxyReplyType uint32, reason string) {
	t.Helper()
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen fake mux socket %q: %v", sockPath, err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			conn, accErr := ln.Accept()
			if accErr != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = conn.Close() }()
				pktType, _, rErr := ReadMuxPacket(conn)
				if rErr != nil || pktType != MUX_MSG_HELLO {
					return
				}
				var exts []MuxExtension
				if id := target.CanonicalTargetIdentity(); id != "" {
					exts = append(exts, MuxExtension{Name: muxTargetExtensionName, Value: id})
				}
				if wErr := WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, exts)); wErr != nil {
					return
				}
				for {
					reqType, payload, err := ReadMuxPacket(conn)
					if err != nil {
						return
					}
					reqID, err := DecodeMuxRequestID(payload)
					if err != nil {
						return
					}
					switch reqType {
					case MUX_C_ALIVE_CHECK:
						_ = sendAlive(conn, reqID, 12345)
					case MUX_C_PROXY:
						_ = WriteMuxPacket(conn, proxyReplyType, EncodeMuxError(reqID, reason))
						return
					default:
						_ = sendFailure(conn, reqID, "unsupported")
						return
					}
				}
			})
		}
	})
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
}

// TestW9b_C9_L1_ProxyFailureFallsBackWhilePermissionDeniedFailsClosed verifies
// C9-L1 in DialControlProxy, DialMuxProxyStream, and Connector.Connect:
//   - MUX_S_FAILURE ("mux master is shutting down") maps to non-fatal
//     ErrControlMasterUnavailable so ControlMaster=auto falls back cleanly to
//     dialing a fresh SSH connection.
//   - MUX_S_PERMISSION_DENIED (ask/autoask denial) stays mapped to fatal
//     ErrControlProxyRejected and fails closed without dialing the backend.
func TestW9b_C9_L1_ProxyFailureFallsBackWhilePermissionDeniedFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	t.Run("a_dial_proxy_error_classification", func(t *testing.T) {
		failSock := filepath.Join(shortSocketDir(t), "w9b-l1-fail.sock")
		denySock := filepath.Join(shortSocketDir(t), "w9b-l1-deny.sock")
		target := TargetContext{Host: "127.0.0.1", Port: 2222, User: "fixture"}

		startFakeMuxProxyReplyServer(t, failSock, target, MUX_S_FAILURE, "mux master is shutting down")
		startFakeMuxProxyReplyServer(t, denySock, target, MUX_S_PERMISSION_DENIED, "connection sharing request was not approved")

		_, _, err := DialControlProxy(ctx, failSock, target)
		if !errors.Is(err, ErrControlMasterUnavailable) || errors.Is(err, ErrControlProxyRejected) {
			t.Fatalf("DialControlProxy(MUX_S_FAILURE) = %v, want ErrControlMasterUnavailable (not ErrControlProxyRejected)", err)
		}
		if isFatalMultiplexSecurityError(err) {
			t.Fatalf("isFatalMultiplexSecurityError(MUX_S_FAILURE err=%v) = true, want false", err)
		}

		_, err = DialMuxProxyStream(ctx, failSock)
		if !errors.Is(err, ErrControlMasterUnavailable) || errors.Is(err, ErrControlProxyRejected) {
			t.Fatalf("DialMuxProxyStream(MUX_S_FAILURE) = %v, want ErrControlMasterUnavailable (not ErrControlProxyRejected)", err)
		}

		_, _, err = DialControlProxy(ctx, denySock, target)
		if !errors.Is(err, ErrControlProxyRejected) || errors.Is(err, ErrControlMasterUnavailable) {
			t.Fatalf("DialControlProxy(MUX_S_PERMISSION_DENIED) = %v, want ErrControlProxyRejected (not ErrControlMasterUnavailable)", err)
		}
		if !isFatalMultiplexSecurityError(err) {
			t.Fatalf("isFatalMultiplexSecurityError(MUX_S_PERMISSION_DENIED err=%v) = false, want true", err)
		}

		_, err = DialMuxProxyStream(ctx, denySock)
		if !errors.Is(err, ErrControlProxyRejected) || errors.Is(err, ErrControlMasterUnavailable) {
			t.Fatalf("DialMuxProxyStream(MUX_S_PERMISSION_DENIED) = %v, want ErrControlProxyRejected (not ErrControlMasterUnavailable)", err)
		}
	})

	t.Run("b_connector_auto_falls_back_on_mux_s_failure_race", func(t *testing.T) {
		srv := newKeepAliveBarrierServer(t, ctx)
		host, port := fixtureEndpoint(t, srv.addr)
		sockPath := filepath.Join(shortSocketDir(t), "w9b-l1-race.sock")

		target := TargetContext{Host: host, Port: port, User: "fixture"}
		// AliveCheck succeeds, then MUX_C_PROXY races with shutdown and replies MUX_S_FAILURE.
		startFakeMuxProxyReplyServer(t, sockPath, target, MUX_S_FAILURE, "mux master is shutting down")

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
		t.Cleanup(func() {
			dialer.closeAll()
			_ = connector.CloseAll()
		})

		cli, err := connector.Connect(ctx, "node")
		if err != nil {
			t.Fatalf("Connector.Connect failed instead of falling back on MUX_S_FAILURE: %v", err)
		}
		if gotDials := modeSwitchDialCount(dialer); gotDials != 1 {
			t.Fatalf("expected direct SSH fallback dial count = 1, got %d", gotDials)
		}
		execBarrierCheck(t, cli)
	})

	t.Run("c_connector_auto_fails_closed_on_mux_s_permission_denied", func(t *testing.T) {
		srv := newKeepAliveBarrierServer(t, ctx)
		host, port := fixtureEndpoint(t, srv.addr)
		sockPath := filepath.Join(shortSocketDir(t), "w9b-l1-askdeny.sock")

		target := TargetContext{Host: host, Port: port, User: "fixture"}
		startFakeMuxProxyReplyServer(t, sockPath, target, MUX_S_PERMISSION_DENIED, "connection sharing request was not approved")

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
		t.Cleanup(func() {
			dialer.closeAll()
			_ = connector.CloseAll()
		})

		_, err := connector.Connect(ctx, "node")
		if !errors.Is(err, ErrControlProxyRejected) {
			t.Fatalf("Connector.Connect err = %v, want ErrControlProxyRejected", err)
		}
		if gotDials := modeSwitchDialCount(dialer); gotDials != 0 {
			t.Fatalf("Connector.Connect dialed backend %d times after MUX_S_PERMISSION_DENIED, want 0", gotDials)
		}
		if strings.Contains(err.Error(), ErrControlMasterUnavailable.Error()) {
			t.Fatalf("permission denied error unexpectedly referenced unavailable sentinel: %v", err)
		}
	})
}
