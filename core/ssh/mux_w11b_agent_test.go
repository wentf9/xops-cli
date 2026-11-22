package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type w11bSlowAgentServerState struct {
	agentLive         chan struct{}
	remoteSawAgentEOF chan struct{}
	execCount         atomic.Int32
}

// startW11bSlowCloseAgentSSHServer starts an in-process SSH server whose
// session handler accepts auth-agent-req@openssh.com, opens a real
// auth-agent@openssh.com channel, performs a 1-byte ping/ack to prove the
// forwarded agent pipe is active, observes outbound close/EOF from the client,
// and deliberately holds the remote agent channel open WITHOUT echoing
// SSH_MSG_CHANNEL_CLOSE until holdAgentOpen closes (even after the session
// itself exits and closes).
func startW11bSlowCloseAgentSSHServer(
	t *testing.T,
	ctx context.Context,
	holdAgentOpen <-chan struct{},
	holdSessionOpen <-chan struct{},
) (*w10bSSHServer, *w11bSlowAgentServerState) {
	t.Helper()
	state := &w11bSlowAgentServerState{
		agentLive:         make(chan struct{}, 4),
		remoteSawAgentEOF: make(chan struct{}, 4),
	}
	sshSrv := startW10bSSHServer(t, ctx, w10bSSHServerHooks{
		onSession: func(connCtx context.Context, sConn *cryptoSSH.ServerConn, newCh cryptoSSH.NewChannel) {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				return
			}
			var agentWG sync.WaitGroup
			// Register agentWG.Wait BEFORE ch.Close so LIFO defer order closes
			// the session channel immediately while keeping the background
			// agent channel accounted for until holdAgentOpen/connCtx ends.
			defer agentWG.Wait()
			defer func() { _ = ch.Close() }()

			for req := range reqs {
				switch req.Type {
				case agentForwardRequestType:
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					agentWG.Go(func() {
						runW11bRemoteSlowCloseAgentChannel(connCtx, sConn, holdAgentOpen, state)
					})
				case "exec":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					seq := state.execCount.Add(1)
					if holdSessionOpen != nil && seq == 1 {
						select {
						case <-holdSessionOpen:
						case <-connCtx.Done():
							go cryptoSSH.DiscardRequests(reqs)
							return
						}
					}
					_, _ = io.WriteString(ch, "exec-ok\n")
					_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
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
	return sshSrv, state
}

func runW11bRemoteSlowCloseAgentChannel(
	connCtx context.Context,
	sConn *cryptoSSH.ServerConn,
	holdAgentOpen <-chan struct{},
	state *w11bSlowAgentServerState,
) {
	aCh, aReqs, openErr := sConn.OpenChannel(agentForwardChannelType, nil)
	if openErr != nil {
		return
	}
	go cryptoSSH.DiscardRequests(aReqs)
	defer func() { _ = aCh.Close() }()

	if _, wErr := aCh.Write([]byte{'P'}); wErr != nil {
		return
	}
	var ack [1]byte
	if _, rErr := io.ReadFull(aCh, ack[:]); rErr != nil {
		return
	}
	select {
	case state.agentLive <- struct{}{}:
	default:
	}

	// Wait for the client's outbound SSH_MSG_CHANNEL_EOF / SSH_MSG_CHANNEL_CLOSE,
	// then withhold echoing SSH_MSG_CHANNEL_CLOSE until holdAgentOpen closes.
	_, _ = io.Copy(io.Discard, aCh)
	select {
	case state.remoteSawAgentEOF <- struct{}{}:
	default:
	}
	select {
	case <-holdAgentOpen:
	case <-connCtx.Done():
	}
}

func startW11bProxyJumpBastionServer(t *testing.T, ctx context.Context) *w10bSSHServer {
	t.Helper()
	return startW10bSSHServer(t, ctx, w10bSSHServerHooks{
		onDirectTCPIP: func(connCtx context.Context, newCh cryptoSSH.NewChannel) {
			var payload struct {
				Host       string
				Port       uint32
				OriginAddr string
				OriginPort uint32
			}
			if err := cryptoSSH.Unmarshal(newCh.ExtraData(), &payload); err != nil {
				_ = newCh.Reject(cryptoSSH.Prohibited, "invalid direct-tcpip payload")
				return
			}
			targetAddr := net.JoinHostPort(payload.Host, strconv.Itoa(int(payload.Port)))
			upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(connCtx, "tcp", targetAddr)
			if err != nil {
				_ = newCh.Reject(cryptoSSH.ConnectionFailed, err.Error())
				return
			}
			ch, reqs, err := newCh.Accept()
			if err != nil {
				_ = upstream.Close()
				return
			}
			go cryptoSSH.DiscardRequests(reqs)
			stopClose := context.AfterFunc(connCtx, func() {
				_ = upstream.Close()
				_ = ch.Close()
			})
			defer stopClose()

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				_, _ = io.Copy(upstream, ch)
				if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
					_ = cw.CloseWrite()
				}
			}()
			go func() {
				defer wg.Done()
				_, _ = io.Copy(ch, upstream)
				_ = ch.CloseWrite()
			}()
			wg.Wait()
			_ = ch.Close()
			_ = upstream.Close()
		},
		onSession: func(_ context.Context, _ *cryptoSSH.ServerConn, newCh cryptoSSH.NewChannel) {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				return
			}
			defer func() { _ = ch.Close() }()
			for req := range reqs {
				if req.Type == "exec" {
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					_, _ = io.WriteString(ch, "bastion-ok\n")
					_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
					go cryptoSSH.DiscardRequests(reqs)
					return
				}
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		},
	})
}

func setW11bRouterCloseTimeout(t *testing.T, sshCli *cryptoSSH.Client, d time.Duration) *sshAgentChannelRouter {
	t.Helper()
	router, err := getOrCreateAgentRouter(sshCli)
	if err != nil {
		t.Fatalf("getOrCreateAgentRouter: %v", err)
	}
	router.mu.Lock()
	router.closeTimeoutFn = func() time.Duration { return d }
	router.mu.Unlock()
	return router
}

func runW11bSimpleExec(t *testing.T, sshCli *cryptoSSH.Client, cmd string) string {
	t.Helper()
	sess, err := sshCli.NewSession()
	if err != nil {
		t.Fatalf("NewSession(%q): %v", cmd, err)
	}
	defer func() { _ = sess.Close() }()
	out, err := sess.Output(cmd)
	if err != nil {
		t.Fatalf("Session.Output(%q): %v", cmd, err)
	}
	return string(out)
}

func newW11bForwardAgentOptions(t *testing.T) *Options {
	t.Helper()
	opts := &Options{}
	if err := opts.Set(OptionForwardAgent, "yes"); err != nil {
		t.Fatalf("Set(ForwardAgent): %v", err)
	}
	return opts
}

// TestW11b_C11_M1_SlowRemoteAgentClosePreservesHealthyTransport verifies C11-M1:
// when a remote peer keeps an auth-agent@openssh.com channel open WITHOUT
// echoing SSH_MSG_CHANNEL_CLOSE past 2*drainTimeout after session exit over a
// healthy transport, releaseWithDeadline sees outbound closeWG finish promptly
// and NEVER calls interruptTransportNow(). Healthy shared MuxServer, pooled
// direct Client, and ProxyJump target+bastion remain 100% healthy and pooled,
// and once the remote side finally closes the agent channel, l.pumps exits
// cleanly with 0 leaked goroutines.
func TestW11b_C11_M1_SlowRemoteAgentClosePreservesHealthyTransport(t *testing.T) {
	t.Run("a_mux_proxy_slow_remote_agent_close_preserves_master", testW11bC11M1MuxProxySlowRemoteAgentClose)
	t.Run("b_direct_client_slow_remote_agent_close_preserves_pooled_client", testW11bC11M1DirectClientSlowRemoteAgentClose)
	t.Run("c_proxyjump_client_slow_remote_agent_close_preserves_target_and_bastion", testW11bC11M1ProxyJumpSlowRemoteAgentClose)
}

func testW11bC11M1MuxProxySlowRemoteAgentClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const closeTimeout = 80 * time.Millisecond
	holdAgent := make(chan struct{})
	releaseRemoteAgent := sync.OnceFunc(func() { close(holdAgent) })
	defer releaseRemoteAgent()

	agentHarness := newW10bFakeAgentHarness(t)
	sshSrv, state := startW11bSlowCloseAgentSSHServer(t, ctx, holdAgent, nil)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, rootConn, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w11b-m1-proxy.sock", w10bMuxOpts{
		requestTimeout:    closeTimeout,
		allowAgentForward: true,
		agentSocket:       "/w11b-mux-agent.sock",
		dialAgent:         agentHarness.dialAgent,
	})
	router, err := getOrCreateAgentRouter(srv.sshClient)
	if err != nil {
		t.Fatalf("getOrCreateAgentRouter: %v", err)
	}

	rawProxy, serverCh, closeProxy := openRawMuxProxyAgentSession(t, ctx, sockPath)
	select {
	case <-state.agentLive:
	case <-time.After(3 * time.Second):
		closeProxy()
		t.Fatal("auth-agent@openssh.com channel did not become live")
	}

	// Close the proxy session channel while the remote peer intentionally
	// withholds SSH_MSG_CHANNEL_CLOSE on auth-agent@openssh.com.
	w := newMuxWriter()
	w.buf = append(w.buf, msgChannelClose)
	w.WriteUint32(serverCh)
	if err := writeUnpaddedPacket(rawProxy, w.Bytes()); err != nil {
		closeProxy()
		t.Fatalf("write msgChannelClose: %v", err)
	}
	closeProxy()

	// Outbound close reaches remote promptly and ActiveSessions drains within
	// drainTimeout + scheduling slack without tearing down MuxServer.
	select {
	case <-state.remoteSawAgentEOF:
	case <-time.After(2 * time.Second):
		t.Fatal("remote agent channel did not observe outbound close/EOF")
	}
	waitForCondition(t, 2*closeTimeout+120*time.Millisecond, func() bool {
		return srv.ActiveSessions() == 0
	}, "MUX_C_PROXY session did not drain while remote held auth-agent channel open")

	// Hold past >2*drainTimeout while remote STILL withholds SSH_MSG_CHANNEL_CLOSE.
	time.Sleep(2*closeTimeout + 40*time.Millisecond)
	if srv.isShuttingDown() || srv.currentPhase() != muxPhaseRunning {
		t.Fatalf("healthy MuxServer torn down by slow remote agent close: phase=%d shuttingDown=%v", srv.currentPhase(), srv.isShuttingDown())
	}
	if rootConn.closed.Load() {
		t.Fatal("healthy MuxServer rootConn was closed during slow remote agent close")
	}

	muxCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient after slow remote agent close: %v", err)
	}
	if _, err := muxCli.AliveCheck(ctx); err != nil {
		_ = muxCli.Close()
		t.Fatalf("AliveCheck failed after slow remote agent close: %v", err)
	}
	_ = muxCli.Close()

	// Confirm the healthy MuxServer still serves a fresh session cleanly.
	if out := runW11bSimpleExec(t, srv.sshClient, "probe-after-slow-agent"); out != "exec-ok\n" {
		t.Fatalf("post-release exec output = %q, want %q", out, "exec-ok\n")
	}

	// Now let remote finally echo SSH_MSG_CHANNEL_CLOSE and confirm full drain
	// with 0 leaked goroutines.
	releaseRemoteAgent()
	waitForCondition(t, 2*time.Second, func() bool {
		return router.activeChannels.Load() == 0
	}, "agent channel slot did not drain after remote finally closed auth-agent channel")

	_ = srv.Shutdown()
	<-srv.Wait()
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C11-M1 MUX_C_PROXY slow remote close goroutine check")
}

func testW11bC11M1DirectClientSlowRemoteAgentClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const closeTimeout = 80 * time.Millisecond
	holdAgent := make(chan struct{})
	releaseRemoteAgent := sync.OnceFunc(func() { close(holdAgent) })
	defer releaseRemoteAgent()

	agentHarness := newW10bFakeAgentHarness(t)
	sshSrv, state := startW11bSlowCloseAgentSSHServer(t, ctx, holdAgent, nil)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"target": {
				NodeID: "target", Address: sshSrv.host, Port: sshSrv.port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				Options: newW11bForwardAgentOptions(t),
			},
		},
	}
	dialer := &modeSwitchDialer{}
	connector := newTestConnector(
		provider,
		WithDialer(dialer),
		WithHostKeyVerifier(&fixtureTrust{}),
		WithEnvironment(Environment{
			AgentSocket: "/w11b-direct-agent.sock",
			DialAgent:   agentHarness.dialAgent,
		}),
	)
	t.Cleanup(func() {
		releaseRemoteAgent()
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	client, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	router := setW11bRouterCloseTimeout(t, client.sshClient, closeTimeout)

	sess, err := client.sshClient.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	release, err := client.enableSessionAgentForward(ctx, sess)
	if err != nil {
		_ = sess.Close()
		t.Fatalf("enableSessionAgentForward: %v", err)
	}
	select {
	case <-state.agentLive:
	case <-time.After(3 * time.Second):
		release()
		_ = sess.Close()
		t.Fatal("direct client auth-agent@openssh.com channel did not become live")
	}

	out, err := sess.Output("run-with-bg-agent")
	if err != nil || string(out) != "exec-ok\n" {
		release()
		_ = sess.Close()
		t.Fatalf("Session.Output = (%q, %v), want (%q, nil)", string(out), err, "exec-ok\n")
	}
	_ = sess.Close()

	// Session exited while remote still withholds SSH_MSG_CHANNEL_CLOSE on the
	// agent channel. release() must return within drainTimeout (+ small slack)
	// and must NOT call client.Interrupt().
	start := time.Now()
	release()
	if elapsed := time.Since(start); elapsed > closeTimeout+150*time.Millisecond {
		t.Fatalf("direct client agent lease release took %v, want bounded near %v", elapsed, closeTimeout)
	}
	select {
	case <-state.remoteSawAgentEOF:
	case <-time.After(2 * time.Second):
		t.Fatal("remote agent channel did not observe outbound close/EOF")
	}

	time.Sleep(2*closeTimeout + 40*time.Millisecond)
	if dialer.connAt(0).closed.Load() {
		t.Fatal("healthy direct Client rootConn was interrupted by slow remote agent close")
	}
	if err := client.TransportError(); err != nil {
		t.Fatalf("healthy direct Client TransportError() = %v, want nil", err)
	}

	reused, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("re-Connect(target) after slow remote agent close: %v", err)
	}
	if reused.sshClient != client.sshClient {
		t.Fatal("expected pooled direct Client to be reused without reconnect")
	}
	if got := runW11bSimpleExec(t, reused.sshClient, "second-cmd"); got != "exec-ok\n" {
		t.Fatalf("second exec on reused pooled Client = %q, want %q", got, "exec-ok\n")
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after slow remote agent close: %v", err)
	}

	releaseRemoteAgent()
	waitForCondition(t, 2*time.Second, func() bool {
		return router.activeChannels.Load() == 0
	}, "direct client agent channel slot did not drain after remote closed agent channel")

	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C11-M1 direct Client slow remote close goroutine check")
}

func openW11bClientAgentSession(
	t *testing.T,
	ctx context.Context,
	client *Client,
	agentLive <-chan struct{},
) (*agentForwardLease, *cryptoSSH.Session) {
	t.Helper()
	lease := client.acquireSessionAgentLease(ctx)
	if lease == nil {
		t.Fatal("acquireSessionAgentLease returned nil")
	}
	sess, err := client.sshClient.NewSession()
	if err != nil {
		client.untrackAgentLease(lease)
		lease.Release()
		t.Fatalf("NewSession: %v", err)
	}
	ok, err := sess.SendRequest(agentForwardRequestType, true, nil)
	if err != nil || !ok {
		client.untrackAgentLease(lease)
		lease.Release()
		_ = sess.Close()
		t.Fatalf("SendRequest(%s) = (%v, %v), want (true, nil)", agentForwardRequestType, ok, err)
	}
	select {
	case <-agentLive:
	case <-time.After(3 * time.Second):
		client.untrackAgentLease(lease)
		lease.Release()
		_ = sess.Close()
		t.Fatal("auth-agent@openssh.com channel did not become live")
	}
	return lease, sess
}

func assertW11bPooledClientHealthy(
	t *testing.T,
	ctx context.Context,
	connector *Connector,
	nodeID string,
	orig *Client,
	cmd string,
	wantOut string,
) {
	t.Helper()
	reused, err := connector.Connect(ctx, nodeID)
	if err != nil || reused.sshClient != orig.sshClient {
		t.Fatalf("%s not preserved/pooled after slow remote agent close: reused=%v err=%v", nodeID, reused, err)
	}
	if got := runW11bSimpleExec(t, reused.sshClient, cmd); got != wantOut {
		t.Fatalf("%s post-release exec = %q, want %q", nodeID, got, wantOut)
	}
}

func testW11bC11M1ProxyJumpSlowRemoteAgentClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const closeTimeout = 80 * time.Millisecond
	holdAgent := make(chan struct{})
	releaseRemoteAgent := sync.OnceFunc(func() { close(holdAgent) })
	defer releaseRemoteAgent()

	agentHarness := newW10bFakeAgentHarness(t)
	bastionSrv := startW11bProxyJumpBastionServer(t, ctx)
	targetSrv, state := startW11bSlowCloseAgentSSHServer(t, ctx, holdAgent, nil)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bastionSrv.host, Port: bastionSrv.port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: targetSrv.host, Port: targetSrv.port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
				Options:   newW11bForwardAgentOptions(t),
			},
		},
	}
	dialer := &modeSwitchDialer{}
	connector := newTestConnector(
		provider,
		WithDialer(dialer),
		WithHostKeyVerifier(&fixtureTrust{}),
		WithEnvironment(Environment{
			AgentSocket: "/w11b-proxyjump-agent.sock",
			DialAgent:   agentHarness.dialAgent,
		}),
	)
	t.Cleanup(func() {
		releaseRemoteAgent()
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	targetClient, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target via ProxyJump): %v", err)
	}
	bastionClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	router := setW11bRouterCloseTimeout(t, targetClient.sshClient, closeTimeout)

	lease, sess := openW11bClientAgentSession(t, ctx, targetClient, state.agentLive)
	out, err := sess.Output("proxyjump-with-bg-agent")
	if err != nil || string(out) != "exec-ok\n" {
		targetClient.untrackAgentLease(lease)
		lease.Release()
		_ = sess.Close()
		t.Fatalf("ProxyJump Session.Output = (%q, %v), want (%q, nil)", string(out), err, "exec-ok\n")
	}
	_ = sess.Close()

	// Release lease while remote target still withholds SSH_MSG_CHANNEL_CLOSE
	// on auth-agent@openssh.com. Neither target nor ProxyJump bastion may be
	// interrupted.
	start := time.Now()
	targetClient.untrackAgentLease(lease)
	lease.Release()
	if elapsed := time.Since(start); elapsed > closeTimeout+200*time.Millisecond {
		t.Fatalf("ProxyJump lease.Release() took %v, want bounded near %v", elapsed, closeTimeout)
	}
	select {
	case <-state.remoteSawAgentEOF:
	case <-time.After(2 * time.Second):
		t.Fatal("remote ProxyJump target agent channel did not observe outbound close/EOF")
	}

	time.Sleep(2*closeTimeout + 40*time.Millisecond)
	bastionRoot := dialer.connAt(0)
	if bastionRoot == nil || bastionRoot.closed.Load() {
		t.Fatal("healthy ProxyJump bastion physical rootConn was closed during slow remote agent close")
	}

	assertW11bPooledClientHealthy(t, ctx, connector, "bastion", bastionClient, "bastion-check", "bastion-ok\n")
	assertW11bPooledClientHealthy(t, ctx, connector, "target", targetClient, "target-check", "exec-ok\n")
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after ProxyJump slow remote agent close: %v", err)
	}

	// Once remote finally closes the agent channel, l.pumps must finish cleanly
	// and release its channel slot with 0 leaked goroutines.
	releaseRemoteAgent()
	waitWithin(t, "ProxyJump lease.pumps drain after remote agent close", 2*time.Second, func() {
		lease.pumps.Wait()
	})
	waitForCondition(t, 2*time.Second, func() bool {
		return router.activeChannels.Load() == 0
	}, "ProxyJump agent channel slot did not drain after remote closed agent channel")

	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C11-M1 ProxyJump slow remote close goroutine check")
}

// TestW11b_C11_M1_WedgedWriteEscalationMuxAndClient re-verifies that separating
// closeWG from l.pumps preserves bounded <500ms escalation via
// interruptTransportNow() when outbound SSH_MSG_CHANNEL_CLOSE actually stalls on
// a write-wedged MuxServer, direct Client, or ProxyJump Client transport.
func TestW11b_C11_M1_WedgedWriteEscalationMuxAndClient(t *testing.T) {
	t.Run("a_mux_server_wedged_agent_close_escalates", testW11bC11M1WedgedMuxServer)
	t.Run("b_direct_client_wedged_agent_close_escalates", testW11bC11M1WedgedDirectClient)
	t.Run("c_proxyjump_client_wedged_agent_close_escalates", testW11bC11M1WedgedProxyJumpClient)
}

func testW11bC11M1WedgedMuxServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const closeTimeout = 80 * time.Millisecond
	holdAgent := make(chan struct{})
	defer close(holdAgent)

	agentHarness := newW10bFakeAgentHarness(t)
	sshSrv, state := startW11bSlowCloseAgentSSHServer(t, ctx, holdAgent, nil)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, rootConn, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w11b-m1-wedge-mux.sock", w10bMuxOpts{
		requestTimeout:    closeTimeout,
		allowAgentForward: true,
		agentSocket:       "/w11b-wedge-mux.sock",
		dialAgent:         agentHarness.dialAgent,
	})

	rawProxy, serverCh, closeProxy := openRawMuxProxyAgentSession(t, ctx, sockPath)
	defer closeProxy()
	select {
	case <-state.agentLive:
	case <-time.After(3 * time.Second):
		t.Fatal("mux auth-agent@openssh.com channel did not become live")
	}

	var wedgeOnce sync.Once
	agentHarness.setOnConnClose(func() {
		wedgeOnce.Do(func() { rootConn.wedgeWrite.Store(true) })
	})

	w := newMuxWriter()
	w.buf = append(w.buf, msgChannelClose)
	w.WriteUint32(serverCh)
	_ = writeUnpaddedPacket(rawProxy, w.Bytes())

	waitWithin(t, "C11-M1 wedged MuxServer agent closeWG escalation", 500*time.Millisecond, func() {
		<-srv.Wait()
	})
	if !rootConn.closed.Load() {
		t.Fatal("expected closeWG timeout to escalate via interruptTransportNow and abort MuxServer rootConn")
	}
	waitForCondition(t, time.Second, func() bool {
		return srv.ActiveSessions() == 0
	}, "MuxServer ActiveSessions did not drain to 0 after wedged agent close escalation")
	closeProxy()
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C11-M1 wedged MuxServer goroutine check")
}

func testW11bC11M1WedgedDirectClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const closeTimeout = 80 * time.Millisecond
	holdAgent := make(chan struct{})
	defer close(holdAgent)

	agentHarness := newW10bFakeAgentHarness(t)
	sshSrv, state := startW11bSlowCloseAgentSSHServer(t, ctx, holdAgent, nil)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"target": {
				NodeID: "target", Address: sshSrv.host, Port: sshSrv.port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				Options: newW11bForwardAgentOptions(t),
			},
		},
	}
	dialer := &modeSwitchDialer{}
	connector := newTestConnector(
		provider,
		WithDialer(dialer),
		WithHostKeyVerifier(&fixtureTrust{}),
		WithEnvironment(Environment{
			AgentSocket: "/w11b-wedge-direct.sock",
			DialAgent:   agentHarness.dialAgent,
		}),
	)
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	client, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	setW11bRouterCloseTimeout(t, client.sshClient, closeTimeout)

	lease := client.acquireSessionAgentLease(ctx)
	if lease == nil {
		t.Fatal("acquireSessionAgentLease returned nil")
	}
	sess, err := client.sshClient.NewSession()
	if err != nil {
		lease.Release()
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if ok, err := sess.SendRequest(agentForwardRequestType, true, nil); err != nil || !ok {
		lease.Release()
		t.Fatalf("SendRequest(%s) = (%v, %v), want (true, nil)", agentForwardRequestType, ok, err)
	}
	select {
	case <-state.agentLive:
	case <-time.After(3 * time.Second):
		lease.Release()
		t.Fatal("direct client auth-agent@openssh.com channel did not become live")
	}

	rootConn := dialer.connAt(0)
	rootConn.wedgeWrite.Store(true)
	waitWithin(t, "C11-M1 wedged direct Client closeWG escalation", 500*time.Millisecond, func() {
		client.untrackAgentLease(lease)
		lease.Release()
	})
	if !rootConn.closed.Load() {
		t.Fatal("expected closeWG timeout to escalate via Client.Interrupt and abort rootConn")
	}
	_ = sess.Close()
	_ = connector.CloseAll()
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C11-M1 wedged direct Client goroutine check")
}

func testW11bC11M1WedgedProxyJumpClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const closeTimeout = 80 * time.Millisecond
	holdAgent := make(chan struct{})
	defer close(holdAgent)

	agentHarness := newW10bFakeAgentHarness(t)
	bastionSrv := startW11bProxyJumpBastionServer(t, ctx)
	targetSrv, state := startW11bSlowCloseAgentSSHServer(t, ctx, holdAgent, nil)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bastionSrv.host, Port: bastionSrv.port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: targetSrv.host, Port: targetSrv.port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
				Options:   newW11bForwardAgentOptions(t),
			},
		},
	}
	dialer := &modeSwitchDialer{}
	connector := newTestConnector(
		provider,
		WithDialer(dialer),
		WithHostKeyVerifier(&fixtureTrust{}),
		WithEnvironment(Environment{
			AgentSocket: "/w11b-wedge-jump.sock",
			DialAgent:   agentHarness.dialAgent,
		}),
	)
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	targetClient, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target via ProxyJump): %v", err)
	}
	setW11bRouterCloseTimeout(t, targetClient.sshClient, closeTimeout)

	lease := targetClient.acquireSessionAgentLease(ctx)
	if lease == nil {
		t.Fatal("acquireSessionAgentLease returned nil")
	}
	sess, err := targetClient.sshClient.NewSession()
	if err != nil {
		lease.Release()
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = sess.Close() }()
	if ok, err := sess.SendRequest(agentForwardRequestType, true, nil); err != nil || !ok {
		lease.Release()
		t.Fatalf("SendRequest(%s) = (%v, %v), want (true, nil)", agentForwardRequestType, ok, err)
	}
	select {
	case <-state.agentLive:
	case <-time.After(3 * time.Second):
		lease.Release()
		t.Fatal("ProxyJump target auth-agent@openssh.com channel did not become live")
	}

	bastionRoot := dialer.connAt(0)
	bastionRoot.wedgeWrite.Store(true)
	waitWithin(t, "C11-M1 wedged ProxyJump closeWG escalation", 500*time.Millisecond, func() {
		targetClient.untrackAgentLease(lease)
		lease.Release()
	})
	if !bastionRoot.closed.Load() {
		t.Fatal("expected closeWG timeout to escalate via Client.Interrupt and abort bastion physical rootConn")
	}
	_ = sess.Close()
	_ = connector.CloseAll()
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C11-M1 wedged ProxyJump goroutine check")
}

// TestW11b_C11_L1_AgentChannelDrainsStderrExtendedDataBeyondWindow verifies
// C11-L1: serveLocalAgentChannel drains sshCh.Stderr() so sending >2.5 MiB of
// SSH_MSG_CHANNEL_EXTENDED_DATA on auth-agent@openssh.com cannot exhaust
// golang.org/x/crypto/ssh's shared 2 MiB channel receive window and stall a
// subsequent agent request/response round-trip.
func TestW11b_C11_L1_AgentChannelDrainsStderrExtendedDataBeyondWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const (
		stderrTotalBytes = 2600 * 1024 // > 2.5 MiB (exceeds 2 MiB SSH channel receive window)
		agentRequest     = "w11b-agent-sign-request-payload"
		agentReplyPrefix = "w11b-agent-sign-reply:"
	)

	roundTripErr := make(chan error, 1)
	sshSrv := startW10bSSHServer(t, ctx, w10bSSHServerHooks{
		onSession: func(_ context.Context, sConn *cryptoSSH.ServerConn, newCh cryptoSSH.NewChannel) {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				return
			}
			defer func() { _ = ch.Close() }()
			for req := range reqs {
				if req.Type != agentForwardRequestType {
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
					continue
				}
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				go func() {
					roundTripErr <- runW11bStderrFloodAndAgentRoundTrip(sConn, stderrTotalBytes, agentRequest, agentReplyPrefix+agentRequest)
				}()
			}
		},
	})

	runtime.GC()
	baseline := runtime.NumGoroutine()

	dialAgent := func(_ context.Context, _ string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		go func() {
			defer func() { _ = c2.Close() }()
			reqBuf := make([]byte, len(agentRequest))
			if _, err := io.ReadFull(c2, reqBuf); err != nil {
				return
			}
			_, _ = io.WriteString(c2, agentReplyPrefix+string(reqBuf))
		}()
		return c1, nil
	}

	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"target": {
				NodeID: "target", Address: sshSrv.host, Port: sshSrv.port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				Options: newW11bForwardAgentOptions(t),
			},
		},
	}
	connector := newTestConnector(
		provider,
		WithHostKeyVerifier(&fixtureTrust{}),
		WithEnvironment(Environment{
			AgentSocket: "/w11b-stderr-agent.sock",
			DialAgent:   dialAgent,
		}),
	)
	t.Cleanup(func() { _ = connector.CloseAll() })

	client, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	router, err := getOrCreateAgentRouter(client.sshClient)
	if err != nil {
		t.Fatalf("getOrCreateAgentRouter: %v", err)
	}

	sess, err := client.sshClient.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	release, err := client.enableSessionAgentForward(ctx, sess)
	if err != nil {
		_ = sess.Close()
		t.Fatalf("enableSessionAgentForward: %v", err)
	}

	select {
	case rtErr := <-roundTripErr:
		if rtErr != nil {
			release()
			_ = sess.Close()
			t.Fatalf("agent channel round-trip after >2.5 MiB extended data failed: %v", rtErr)
		}
	case <-time.After(8 * time.Second):
		release()
		_ = sess.Close()
		t.Fatal("agent channel stalled during >2.5 MiB SSH_MSG_CHANNEL_EXTENDED_DATA flood (window exhausted?)")
	}

	release()
	_ = sess.Close()
	waitForCondition(t, 2*time.Second, func() bool {
		return router.activeChannels.Load() == 0
	}, "C11-L1 agent channel slot did not drain to 0")

	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C11-L1 agent stderr drain goroutine check")
}

func runW11bStderrFloodAndAgentRoundTrip(
	sConn *cryptoSSH.ServerConn,
	stderrTotalBytes int,
	reqPayload string,
	wantReply string,
) error {
	aCh, aReqs, err := sConn.OpenChannel(agentForwardChannelType, nil)
	if err != nil {
		return err
	}
	go cryptoSSH.DiscardRequests(aReqs)
	defer func() { _ = aCh.Close() }()

	chunk := bytes.Repeat([]byte("X"), 32*1024)
	for sent := 0; sent < stderrTotalBytes; {
		n := min(len(chunk), stderrTotalBytes-sent)
		written, wErr := aCh.Stderr().Write(chunk[:n])
		sent += written
		if wErr != nil {
			return wErr
		}
	}
	if _, err := io.WriteString(aCh, reqPayload); err != nil {
		return err
	}
	reply := make([]byte, len(wantReply))
	if _, err := io.ReadFull(aCh, reply); err != nil {
		return err
	}
	if string(reply) != wantReply {
		return errors.New("unexpected agent reply: " + string(reply))
	}
	return nil
}
