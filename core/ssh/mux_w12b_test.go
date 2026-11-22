package ssh

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// w12bControlledAgentConn implements a fake local ssh-agent connection that
// blocks its first reply on allowFirstReply so a sibling lease can release
// while an agent signing request is actively in flight, then serves arbitrary
// subsequent line-delimited requests on the same open channel.
type w12bControlledAgent struct {
	nonHalfClose bool

	mu              sync.Mutex
	inFlightEntered chan struct{}
	allowFirstReply chan struct{}
	firstEntered    sync.Once
	allowOnce       sync.Once
	conns           []net.Conn
	dialCount       atomic.Int32
	closedCount     atomic.Int32
}

func newW12bControlledAgent(nonHalfClose bool) *w12bControlledAgent {
	return &w12bControlledAgent{
		nonHalfClose:    nonHalfClose,
		inFlightEntered: make(chan struct{}),
		allowFirstReply: make(chan struct{}),
	}
}

func (a *w12bControlledAgent) releaseFirstReply() {
	a.allowOnce.Do(func() { close(a.allowFirstReply) })
}

func (a *w12bControlledAgent) closeAll() {
	a.releaseFirstReply()
	a.mu.Lock()
	conns := append([]net.Conn(nil), a.conns...)
	a.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (a *w12bControlledAgent) dialAgent(_ context.Context, _ string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	callNum := a.dialCount.Add(1)
	a.mu.Lock()
	a.conns = append(a.conns, c1, c2)
	a.mu.Unlock()

	go func() {
		defer a.closedCount.Add(1)
		defer func() { _ = c2.Close() }()
		reader := bufio.NewReader(c2)
		for reqIdx := 1; ; reqIdx++ {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			trimmed := strings.TrimSpace(line)
			if callNum == 1 && reqIdx == 1 {
				a.firstEntered.Do(func() { close(a.inFlightEntered) })
				<-a.allowFirstReply
			}
			if _, wErr := io.WriteString(c2, "SIGNED:"+trimmed+"\n"); wErr != nil {
				return
			}
		}
	}()

	if a.nonHalfClose {
		return &noHalfCloseConn{Conn: c1}, nil
	}
	return c1, nil
}

type w12bServerConnCapture struct {
	mu    sync.Mutex
	sConn *cryptoSSH.ServerConn
	ready chan struct{}
	once  sync.Once
}

func newW12bServerConnCapture() *w12bServerConnCapture {
	return &w12bServerConnCapture{ready: make(chan struct{})}
}

func (c *w12bServerConnCapture) set(sConn *cryptoSSH.ServerConn) {
	c.mu.Lock()
	c.sConn = sConn
	c.mu.Unlock()
	c.once.Do(func() { close(c.ready) })
}

func (c *w12bServerConnCapture) wait(t *testing.T) *cryptoSSH.ServerConn {
	t.Helper()
	select {
	case <-c.ready:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.sConn
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server SSH connection")
		return nil
	}
}

func startW12bAgentEchoSSHServer(t *testing.T, ctx context.Context) (*w10bSSHServer, *w12bServerConnCapture) {
	t.Helper()
	capture := newW12bServerConnCapture()
	srv := startW10bSSHServer(t, ctx, w10bSSHServerHooks{
		onSession: func(connCtx context.Context, sConn *cryptoSSH.ServerConn, newCh cryptoSSH.NewChannel) {
			capture.set(sConn)
			ch, reqs, err := newCh.Accept()
			if err != nil {
				return
			}
			defer func() { _ = ch.Close() }()
			for req := range reqs {
				switch req.Type {
				case agentForwardRequestType:
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				case "exec":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					_, _ = io.WriteString(ch, "w12b-exec-ok\n")
					_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
					go cryptoSSH.DiscardRequests(reqs)
					return
				case "shell":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					// Wait for channel close (reqs closed) rather than stdin EOF so
					// Unix passenger sessions whose pipe stdin reaches EOF remain
					// open until the passenger explicitly closes its control conn.
					reqsDone := make(chan struct{})
					go func() {
						defer close(reqsDone)
						cryptoSSH.DiscardRequests(reqs)
					}()
					select {
					case <-reqsDone:
					case <-connCtx.Done():
					}
					return
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		},
	})
	return srv, capture
}

func openW12bRemoteAgentChannel(t *testing.T, sConn *cryptoSSH.ServerConn) (cryptoSSH.Channel, *bufio.Reader) {
	t.Helper()
	aCh, aReqs, err := sConn.OpenChannel(agentForwardChannelType, nil)
	if err != nil {
		t.Fatalf("server OpenChannel(%s): %v", agentForwardChannelType, err)
	}
	go cryptoSSH.DiscardRequests(aReqs)
	return aCh, bufio.NewReader(aCh)
}

func readW12bLineWithin(t *testing.T, r *bufio.Reader, timeout time.Duration, label string) string {
	t.Helper()
	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- res{line: line, err: err}
	}()
	select {
	case out := <-ch:
		if out.err != nil {
			t.Fatalf("%s: read failed: %v", label, out.err)
		}
		return strings.TrimSpace(out.line)
	case <-time.After(timeout):
		t.Fatalf("%s: timed out after %v", label, timeout)
		return ""
	}
}

func assertW12bAgentChannelClosesOnLastRelease(t *testing.T, r *bufio.Reader, timeout time.Duration, label string) {
	t.Helper()
	errCh := make(chan error, 1)
	go func() {
		_, err := r.ReadByte()
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatalf("%s: expected EOF/close after last lease release, got data", label)
		}
	case <-time.After(timeout):
		t.Fatalf("%s: open agent channel did not close after last lease release", label)
	}
}

func assertW12bFreshAgentRoundTrip(t *testing.T, sConn *cryptoSSH.ServerConn, payload string) {
	t.Helper()
	aCh, reader := openW12bRemoteAgentChannel(t, sConn)
	defer func() { _ = aCh.Close() }()
	if _, err := io.WriteString(aCh, payload+"\n"); err != nil {
		t.Fatalf("write fresh agent channel: %v", err)
	}
	if got := readW12bLineWithin(t, reader, 3*time.Second, "fresh agent round-trip"); got != "SIGNED:"+payload {
		t.Fatalf("fresh agent reply = %q, want %q", got, "SIGNED:"+payload)
	}
}

func assertW12bLiveChannelSurvivesSiblingRelease(
	t *testing.T,
	sConn *cryptoSSH.ServerConn,
	agent *w12bControlledAgent,
	releaseFirst func(),
	releaseLast func(),
	router *sshAgentChannelRouter,
	label string,
) {
	t.Helper()

	aCh, reader := openW12bRemoteAgentChannel(t, sConn)
	defer func() { _ = aCh.Close() }()

	if _, err := io.WriteString(aCh, "req-1\n"); err != nil {
		t.Fatalf("%s: write req-1: %v", label, err)
	}
	select {
	case <-agent.inFlightEntered:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: local agent did not receive req-1", label)
	}

	// Release one sibling lease while req-1 is actively blocked in the local agent.
	releaseFirst()

	if closed := agent.closedCount.Load(); closed != 0 {
		t.Fatalf("%s: sibling lease release closed %d live agent conn(s), want 0", label, closed)
	}

	// Unblock req-1 and verify both the in-flight request AND a second request on
	// the exact same open channel succeed with zero EOF/interruption.
	agent.releaseFirstReply()
	if got := readW12bLineWithin(t, reader, 3*time.Second, label+" req-1"); got != "SIGNED:req-1" {
		t.Fatalf("%s: req-1 reply = %q, want %q", label, got, "SIGNED:req-1")
	}

	if _, err := io.WriteString(aCh, "req-2\n"); err != nil {
		t.Fatalf("%s: write req-2 on surviving channel: %v", label, err)
	}
	if got := readW12bLineWithin(t, reader, 3*time.Second, label+" req-2"); got != "SIGNED:req-2" {
		t.Fatalf("%s: req-2 reply = %q, want %q", label, got, "SIGNED:req-2")
	}

	// Confirm a new auth-agent@openssh.com channel also succeeds while the surviving
	// lease remains active.
	assertW12bFreshAgentRoundTrip(t, sConn, "req-fresh")

	// Releasing the final lease must cleanly retire the epoch and close aCh.
	releaseLast()
	assertW12bAgentChannelClosesOnLastRelease(t, reader, 3*time.Second, label)
	_ = aCh.Close()
	waitForCondition(t, 2*time.Second, func() bool {
		return router.activeChannels.Load() == 0
	}, label+": agent activeChannels did not drain to 0 after last lease release")
}

// TestW12b_C12_M1_SharedEpochSurvivesSiblingLeaseRelease verifies C12-M1 across
// pooled Clients, MuxServer MUX_C_PROXY sessions, both lease release orders
// (lease2 first and lease1 first), individual session context cancellation,
// non-CloseWrite hardware-key agents, and fresh epoch creation after retirement.
func TestW12b_C12_M1_SharedEpochSurvivesSiblingLeaseRelease(t *testing.T) {
	t.Run("a_pooled_client_lease2_first", func(t *testing.T) {
		testW12bC12M1PooledClientSharedEpoch(t, false)
	})
	t.Run("b_pooled_client_lease1_first", func(t *testing.T) {
		testW12bC12M1PooledClientSharedEpoch(t, true)
	})
	t.Run("c_mux_proxy_lease2_first", func(t *testing.T) {
		testW12bC12M1MuxProxySharedEpoch(t, false)
	})
	t.Run("d_mux_proxy_lease1_first", func(t *testing.T) {
		testW12bC12M1MuxProxySharedEpoch(t, true)
	})
	t.Run("e_non_halfclose_hardware_key_survives_sibling_release", testW12bC12M1NonHalfCloseHardwareKey)
}

func testW12bC12M1PooledClientSharedEpoch(t *testing.T, releaseFirstLeaseFirst bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	agent := newW12bControlledAgent(false)
	defer agent.closeAll()
	sshSrv, capture := startW12bAgentEchoSSHServer(t, ctx)

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
	connector := newTestConnector(
		provider,
		WithHostKeyVerifier(&fixtureTrust{}),
		WithEnvironment(Environment{
			AgentSocket: "/w12b-shared-pooled.sock",
			DialAgent:   agent.dialAgent,
		}),
	)
	t.Cleanup(func() {
		agent.closeAll()
		_ = connector.CloseAll()
	})

	client1, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(1): %v", err)
	}
	client2, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(2): %v", err)
	}
	if client1.sshClient != client2.sshClient {
		t.Fatal("expected pooled clients to share underlying *ssh.Client")
	}

	router, err := getOrCreateAgentRouter(client1.sshClient)
	if err != nil {
		t.Fatalf("getOrCreateAgentRouter: %v", err)
	}

	// Acquire lease1 with its own cancelable context to verify canceling an
	// individual session context does not sever the shared epoch.
	sess1Ctx, cancelSess1Ctx := context.WithCancel(ctx)
	defer cancelSess1Ctx()
	sess1, err := client1.sshClient.NewSession()
	if err != nil {
		t.Fatalf("NewSession(1): %v", err)
	}
	defer func() { _ = sess1.Close() }()
	release1, err := client1.enableSessionAgentForward(sess1Ctx, sess1)
	if err != nil {
		t.Fatalf("enableSessionAgentForward(1): %v", err)
	}
	defer release1()

	sess2, err := client2.sshClient.NewSession()
	if err != nil {
		t.Fatalf("NewSession(2): %v", err)
	}
	defer func() { _ = sess2.Close() }()
	release2, err := client2.enableSessionAgentForward(ctx, sess2)
	if err != nil {
		t.Fatalf("enableSessionAgentForward(2): %v", err)
	}
	defer release2()

	sConn := capture.wait(t)
	router.mu.Lock()
	epoch1 := router.epoch
	leaseCount := len(router.leases)
	router.mu.Unlock()
	if epoch1 == nil || leaseCount != 2 {
		t.Fatalf("expected 1 shared epoch with 2 leases, got epoch=%v leases=%d", epoch1, leaseCount)
	}

	firstRel, lastRel := release2, release1
	if releaseFirstLeaseFirst {
		firstRel, lastRel = release1, release2
	}

	assertW12bLiveChannelSurvivesSiblingRelease(
		t,
		sConn,
		agent,
		func() {
			cancelSess1Ctx()
			firstRel()
			if epoch1.ctx.Err() != nil {
				t.Fatalf("epoch1.ctx canceled prematurely while sibling lease still active: %v", epoch1.ctx.Err())
			}
		},
		lastRel,
		router,
		"pooled-client",
	)

	if epoch1.ctx.Err() == nil {
		t.Fatal("expected epoch1.ctx to be canceled after final lease released")
	}

	// Subsequent acquisition after epoch1 retirement must create a fresh epoch
	// (and allow even a different socket path without conflict).
	lease3, err := router.acquireLocalLease(ctx, "/w12b-next-epoch.sock", agent.dialAgent, nil)
	if err != nil {
		t.Fatalf("acquireLocalLease for fresh epoch: %v", err)
	}
	if lease3.epoch == nil || lease3.epoch == epoch1 {
		t.Fatal("expected fresh epoch distinct from retired epoch1")
	}
	assertW12bFreshAgentRoundTrip(t, sConn, "req-epoch2")
	lease3.Release()
	waitForCondition(t, 2*time.Second, func() bool {
		return router.activeChannels.Load() == 0
	}, "epoch2 activeChannels did not drain to 0")

	_ = sess1.Close()
	_ = sess2.Close()
	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C12-M1 pooled client goroutine check")
}

func openW12bMuxProxyAgentSession(t *testing.T, ctx context.Context, sockPath string) (net.Conn, uint32, func()) {
	t.Helper()
	return openRawMuxProxyAgentSession(t, ctx, sockPath)
}

func closeW12bMuxProxyChannelAndWaitSessions(
	t *testing.T,
	srv *MuxServer,
	rawProxy net.Conn,
	serverCh uint32,
	closeProxy func(),
	wantActiveSessions int32,
	label string,
) {
	t.Helper()
	w := newMuxWriter()
	w.buf = append(w.buf, msgChannelClose)
	w.WriteUint32(serverCh)
	_ = writeUnpaddedPacket(rawProxy, w.Bytes())
	closeProxy()
	waitForCondition(t, 2*time.Second, func() bool {
		return srv.ActiveSessions() == wantActiveSessions
	}, label+": ActiveSessions did not reach expected count")
}

func testW12bC12M1MuxProxySharedEpoch(t *testing.T, releaseFirstProxyFirst bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	agent := newW12bControlledAgent(false)
	defer agent.closeAll()
	sshSrv, capture := startW12bAgentEchoSSHServer(t, ctx)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, _, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w12b-m1-proxy.sock", w10bMuxOpts{
		requestTimeout:    150 * time.Millisecond,
		allowAgentForward: true,
		agentSocket:       "/w12b-mux-agent.sock",
		dialAgent:         agent.dialAgent,
	})
	router, err := getOrCreateAgentRouter(srv.sshClient)
	if err != nil {
		t.Fatalf("getOrCreateAgentRouter: %v", err)
	}

	rawProxy1, serverCh1, closeProxy1 := openW12bMuxProxyAgentSession(t, ctx, sockPath)
	defer closeProxy1()
	rawProxy2, serverCh2, closeProxy2 := openW12bMuxProxyAgentSession(t, ctx, sockPath)
	defer closeProxy2()

	waitForCondition(t, 2*time.Second, func() bool {
		return srv.ActiveSessions() == 2
	}, "expected 2 active MUX_C_PROXY sessions")
	waitForCondition(t, 2*time.Second, func() bool {
		router.mu.Lock()
		defer router.mu.Unlock()
		return len(router.leases) == 2 && router.epoch != nil
	}, "expected 2 agentForwardLeases on MuxServer router")

	sConn := capture.wait(t)

	closeFirst := func() {
		closeW12bMuxProxyChannelAndWaitSessions(t, srv, rawProxy2, serverCh2, closeProxy2, 1, "close proxy2 first")
	}
	closeLast := func() {
		closeW12bMuxProxyChannelAndWaitSessions(t, srv, rawProxy1, serverCh1, closeProxy1, 0, "close proxy1 last")
	}
	if releaseFirstProxyFirst {
		closeFirst = func() {
			closeW12bMuxProxyChannelAndWaitSessions(t, srv, rawProxy1, serverCh1, closeProxy1, 1, "close proxy1 first")
		}
		closeLast = func() {
			closeW12bMuxProxyChannelAndWaitSessions(t, srv, rawProxy2, serverCh2, closeProxy2, 0, "close proxy2 last")
		}
	}

	assertW12bLiveChannelSurvivesSiblingRelease(t, sConn, agent, closeFirst, closeLast, router, "mux-proxy")

	if srv.isShuttingDown() || srv.currentPhase() != muxPhaseRunning {
		t.Fatalf("healthy MuxServer unexpectedly shut down: phase=%d", srv.currentPhase())
	}

	_ = srv.Shutdown()
	<-srv.Wait()
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C12-M1 MuxServer proxy goroutine check")
}

func testW12bC12M1NonHalfCloseHardwareKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	chans := make(chan cryptoSSH.NewChannel, 2)
	reqs := make(chan *cryptoSSH.Request)
	rawCli := cryptoSSH.NewClient(&dummyMuxGateConn{}, chans, reqs)
	defer func() {
		close(chans)
		close(reqs)
		_ = rawCli.Close()
	}()

	router, err := getOrCreateAgentRouter(rawCli)
	if err != nil {
		t.Fatalf("getOrCreateAgentRouter: %v", err)
	}

	inFlight := make(chan struct{})
	allowSign := make(chan struct{})
	var closeAllow sync.Once
	releaseSign := func() { closeAllow.Do(func() { close(allowSign) }) }
	defer releaseSign()

	const wantSig = "yubikey-fido2-signature"
	dialHW := func(context.Context, string) (net.Conn, error) {
		agentSide, clientSide := net.Pipe()
		go func() {
			defer func() { _ = agentSide.Close() }()
			buf := make([]byte, 32)
			_, _ = agentSide.Read(buf)
			close(inFlight)
			<-allowSign
			_, _ = agentSide.Write([]byte(wantSig))
		}()
		return &noHalfCloseConn{Conn: clientSide}, nil
	}

	lease1, err := router.acquireLocalLease(ctx, `\\.\pipe\openssh-ssh-agent`, dialHW, nil)
	if err != nil {
		t.Fatalf("acquireLocalLease(1): %v", err)
	}
	defer lease1.Release()
	lease2, err := router.acquireLocalLease(ctx, `\\.\pipe\openssh-ssh-agent`, dialHW, nil)
	if err != nil {
		t.Fatalf("acquireLocalLease(2): %v", err)
	}
	defer lease2.Release()

	// Remote sends request and immediately EOFs (half-closes), entering the
	// non-CloseWrite hardware-key select waiting on <-epoch.ctx.Done().
	remoteCh := newFakeRemoteAgentChannel([]byte("hw-sign-req"))
	chans <- &fakeIncomingAgentNewChannel{ch: remoteCh}

	select {
	case <-inFlight:
	case <-time.After(3 * time.Second):
		t.Fatal("hardware-key agent did not receive sign request")
	}

	// Sibling lease2 exits while touch/PIN prompt is pending; epoch.ctx must NOT cancel!
	lease2.Release()
	if lease1.epoch.ctx.Err() != nil {
		t.Fatalf("epoch.ctx canceled during hardware-key wait while lease1 still active: %v", lease1.epoch.ctx.Err())
	}

	releaseSign()
	select {
	case <-remoteCh.eofWriteCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for hardware-key signature after sibling lease release")
	}
	if got := string(remoteCh.writtenBytes()); got != wantSig {
		t.Fatalf("hardware-key response = %q, want %q", got, wantSig)
	}
	lease1.Release()
	waitForCondition(t, 2*time.Second, func() bool {
		return router.activeChannels.Load() == 0
	}, "hardware-key activeChannels did not drain to 0")
}

func startW12bProbeSeverSSHServer(
	t *testing.T,
	ctx context.Context,
	probeEntered chan<- struct{},
	severed <-chan struct{},
) *w10bSSHServer {
	t.Helper()
	var enteredOnce sync.Once
	return startW10bSSHServer(t, ctx, w10bSSHServerHooks{
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
					enteredOnce.Do(func() { close(probeEntered) })
					<-severed
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

func newW12bMuxProxyConnector(t *testing.T, sshSrv *w10bSSHServer, sockPath string) *Connector {
	t.Helper()
	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"target": {
				NodeID: "target", Address: sshSrv.host, Port: sshSrv.port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
		},
		ctrls: map[string]*ControlConfig{
			"target": {
				Master: ControlMasterNo,
				Path:   sockPath,
			},
		},
	}
	connector := newTestConnector(
		provider,
		WithControlProvider(provider),
		WithHostKeyVerifier(&fixtureTrust{}),
	)
	t.Cleanup(func() { _ = connector.CloseAll() })
	return connector
}

// TestW12b_C12_M2_ConnectorMuxProxyPeerEOFMidProbeSetsTransportError verifies
// C12-M2: when Connector.Connect attaches via MUX_C_PROXY to a ControlMaster
// that severs/EOFs mid-ProbeExecutionConfig, client.TransportError() reports a
// non-nil transport error (instead of nil), allowing FinalizePendingConnection
// and callers to detect and evict the dead PooledClient.
func TestW12b_C12_M2_ConnectorMuxProxyPeerEOFMidProbeSetsTransportError(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	probeEntered := make(chan struct{})
	severed := make(chan struct{})
	sshSrv := startW12bProbeSeverSSHServer(t, ctx, probeEntered, severed)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, masterRoot, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w12b-m2-probe.sock", w10bMuxOpts{
		requestTimeout: 150 * time.Millisecond,
	})
	connector := newW12bMuxProxyConnector(t, sshSrv, sockPath)

	client, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target via MUX_C_PROXY): %v", err)
	}
	assertW12bHealthyMuxProxyClient(t, client)

	probeDone := make(chan error, 1)
	go func() {
		_, pErr := client.ProbeExecutionConfig(ctx)
		probeDone <- pErr
	}()

	select {
	case <-probeEntered:
	case <-time.After(3 * time.Second):
		close(severed)
		t.Fatal("ProbeExecutionConfig did not reach server session")
	}

	// Sever the ControlMaster abruptly mid-ProbeExecutionConfig so the
	// MUX_C_PROXY client observes peer EOF on its Unix socket.
	_ = masterRoot.Close()
	_ = srv.Shutdown()
	<-srv.Wait()
	close(severed)

	select {
	case pErr := <-probeDone:
		if pErr == nil {
			t.Fatal("expected ProbeExecutionConfig to fail after ControlMaster EOF")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ProbeExecutionConfig hung after ControlMaster EOF")
	}

	waitForCondition(t, 2*time.Second, func() bool {
		return client.TransportError() != nil
	}, "expected client.TransportError() to become non-nil after peer EOF mid-ProbeExecutionConfig")

	if err := connector.EvictClient(client); err != nil {
		t.Fatalf("EvictClient: %v", err)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after evicting dead MUX_C_PROXY client: %v", err)
	}
	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C12-M2 mid-probe EOF goroutine check")
}

func assertW12bHealthyMuxProxyClient(t *testing.T, client *Client) {
	t.Helper()
	if !client.IsMultiplexed() || !client.isMultiplexedProxy() {
		t.Fatalf("expected multiplexed proxy client, got IsMultiplexed=%v isMultiplexedProxy=%v", client.IsMultiplexed(), client.isMultiplexedProxy())
	}
	proxyConn, ok := client.SSHClient().Conn.(*muxProxySSHConn)
	if !ok || proxyConn.activity == nil || proxyConn.physRoot == nil {
		t.Fatalf("expected *muxProxySSHConn with non-nil activity and physRoot, got %T", client.SSHClient().Conn)
	}
	if root, ok := client.rootConn.(*physicalSSHConn); !ok || root != proxyConn.physRoot {
		t.Fatalf("expected client.rootConn to be proxyConn.physRoot (*physicalSSHConn), got %T", client.rootConn)
	}
	if err := client.TransportError(); err != nil {
		t.Fatalf("healthy MUX_C_PROXY TransportError() = %v, want nil", err)
	}
}

// TestW12b_C12_M2_DialControlProxyClientTransportErrorLifecycle verifies C12-M2
// on DialControlProxyClient: TransportError() is nil while healthy and becomes
// non-nil after peer EOF, proxyConn.Close(), client.Close(), and client.Interrupt().
func TestW12b_C12_M2_DialControlProxyClientTransportErrorLifecycle(t *testing.T) {
	cases := []struct {
		name       string
		wantClosed bool
		trigger    func(t *testing.T, srv *MuxServer, masterRoot *modeSwitchConn, client *Client)
	}{
		{
			name: "peer_eof",
			trigger: func(_ *testing.T, srv *MuxServer, masterRoot *modeSwitchConn, client *Client) {
				_ = masterRoot.Close()
				_ = srv.Shutdown()
				<-srv.Wait()
				_ = client.SSHClient().Wait()
			},
		},
		{
			name:       "proxy_conn_close",
			wantClosed: true,
			trigger: func(t *testing.T, _ *MuxServer, _ *modeSwitchConn, client *Client) {
				proxyConn, ok := client.SSHClient().Conn.(*muxProxySSHConn)
				if !ok {
					t.Fatalf("expected *muxProxySSHConn, got %T", client.SSHClient().Conn)
				}
				_ = proxyConn.Close()
			},
		},
		{
			name:       "client_interrupt",
			wantClosed: true,
			trigger: func(_ *testing.T, _ *MuxServer, _ *modeSwitchConn, client *Client) {
				_ = client.Interrupt()
			},
		},
		{
			name:       "client_close",
			wantClosed: true,
			trigger: func(_ *testing.T, _ *MuxServer, _ *modeSwitchConn, client *Client) {
				_ = client.Close()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()

			sshSrv, _ := startW12bAgentEchoSSHServer(t, ctx)
			srv, masterRoot, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w12b-m2-"+tc.name+".sock", w10bMuxOpts{
				requestTimeout: 150 * time.Millisecond,
			})

			target := TargetContext{
				Host: sshSrv.host,
				Port: sshSrv.port,
				User: "fixture",
			}
			client, err := DialControlProxyClient(ctx, sockPath, target, Environment{}, nil, nil)
			if err != nil {
				t.Fatalf("DialControlProxyClient: %v", err)
			}
			defer func() { _ = client.Close() }()

			if _, ok := client.rootConn.(*physicalSSHConn); !ok {
				t.Fatalf("DialControlProxyClient rootConn = %T, want *physicalSSHConn", client.rootConn)
			}
			if err := client.TransportError(); err != nil {
				t.Fatalf("healthy DialControlProxyClient TransportError() = %v, want nil", err)
			}

			tc.trigger(t, srv, masterRoot, client)

			tErr := client.TransportError()
			if tErr == nil {
				t.Fatalf("DialControlProxyClient TransportError() = nil after %s, want non-nil", tc.name)
			}
			if tc.wantClosed && !errors.Is(tErr, net.ErrClosed) {
				t.Fatalf("DialControlProxyClient TransportError() = %v after %s, want net.ErrClosed", tErr, tc.name)
			}
		})
	}
}

func startW12bDownloadSSHServer(t *testing.T, ctx context.Context, payloadBytes int) *w10bSSHServer {
	t.Helper()
	return startW10bSSHServer(t, ctx, w10bSSHServerHooks{
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
					_, _ = io.WriteString(ch, strings.Repeat("D", payloadBytes))
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

// TestW12b_C12_M2_PooledMuxProxyKeepAliveReadTimeoutTracksReceiveTraffic
// verifies C12-M2: pooled MUX_C_PROXY clients wrap their socket in
// sshActivityConn so keepAliveReadTimeout(client.SSHClient(), ...) observes
// active receive progress during saturating downloads rather than returning 0.
func TestW12b_C12_M2_PooledMuxProxyKeepAliveReadTimeoutTracksReceiveTraffic(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	sshSrv := startW12bDownloadSSHServer(t, ctx, 4096)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, _, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w12b-m2-ka.sock", w10bMuxOpts{
		requestTimeout: 150 * time.Millisecond,
	})
	connector := newW12bMuxProxyConnector(t, sshSrv, sockPath)

	client, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target via MUX_C_PROXY): %v", err)
	}
	assertW12bHealthyMuxProxyClient(t, client)

	// Let initial handshake receive timestamp age past a short 40ms window.
	const shortWindow = 40 * time.Millisecond
	time.Sleep(shortWindow + 20*time.Millisecond)
	if idleRem := keepAliveReadTimeout(client.SSHClient(), shortWindow); idleRem > 0 {
		t.Fatalf("expected idle keepAliveReadTimeout <= 0 after %v idle, got %v", shortWindow+20*time.Millisecond, idleRem)
	}

	// Trigger real receive traffic over the multiplexed connection.
	out := runW11bSimpleExec(t, client.SSHClient(), "stream-download")
	if len(out) != 4096 {
		t.Fatalf("exec output len = %d, want 4096", len(out))
	}

	// Immediately after receive traffic, keepAliveReadTimeout must report
	// positive remaining budget (proving activity.lastRead updated).
	if rem := keepAliveReadTimeout(client.SSHClient(), 5*time.Second); rem <= 0 {
		t.Fatalf("keepAliveReadTimeout(client.SSHClient(), 5s) = %v, want > 0 after receive traffic", rem)
	}
	if remShort := keepAliveReadTimeout(client.SSHClient(), 500*time.Millisecond); remShort <= 0 {
		t.Fatalf("keepAliveReadTimeout(client.SSHClient(), 500ms) = %v, want > 0 after receive traffic", remShort)
	}

	// Verify DialControlProxy directly also wraps activity + physicalSSHConn.
	rawCli, proxyConn, err := DialControlProxy(ctx, sockPath, TargetContext{
		Host: sshSrv.host,
		Port: sshSrv.port,
		User: "fixture",
	})
	if err != nil {
		t.Fatalf("DialControlProxy: %v", err)
	}
	if _, ok := proxyConn.RawConn().(*physicalSSHConn); !ok {
		_ = rawCli.Close()
		t.Fatalf("DialControlProxy proxyConn.RawConn() = %T, want *physicalSSHConn", proxyConn.RawConn())
	}
	if rem := keepAliveReadTimeout(rawCli, 5*time.Second); rem <= 0 {
		_ = rawCli.Close()
		t.Fatalf("DialControlProxy keepAliveReadTimeout = %v, want > 0", rem)
	}
	_ = rawCli.Close()

	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants: %v", err)
	}
	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll: %v", err)
	}
	_ = srv.Shutdown()
	<-srv.Wait()
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C12-M2 keepAliveReadTimeout goroutine check")
}
