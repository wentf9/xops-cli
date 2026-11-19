package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

type pass6ConfigurableDynamicSSHConn struct {
	dummyMuxGateConn
	initOnce         sync.Once
	closeOnce        sync.Once
	closedCh         chan struct{}
	mu               sync.Mutex
	portQueue        []uint32
	fallbackPort     uint32
	tcpipFwdCalls    atomic.Int32
	cancelTcpipCalls atomic.Int32
}

func (m *pass6ConfigurableDynamicSSHConn) closed() chan struct{} {
	m.initOnce.Do(func() { m.closedCh = make(chan struct{}) })
	return m.closedCh
}

func (m *pass6ConfigurableDynamicSSHConn) Wait() error {
	<-m.closed()
	return io.EOF
}

func (m *pass6ConfigurableDynamicSSHConn) Close() error {
	ch := m.closed()
	m.closeOnce.Do(func() { close(ch) })
	return nil
}

func (m *pass6ConfigurableDynamicSSHConn) nextDynamicPort() uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.portQueue) > 0 {
		p := m.portQueue[0]
		m.portQueue = m.portQueue[1:]
		return p
	}
	return m.fallbackPort
}

func (m *pass6ConfigurableDynamicSSHConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	switch name {
	case "tcpip-forward":
		m.tcpipFwdCalls.Add(1)
		var req struct {
			BindAddr string
			BindPort uint32
		}
		_ = cryptoSSH.Unmarshal(payload, &req)
		if req.BindPort == 0 && wantReply {
			alloc := m.nextDynamicPort()
			return true, cryptoSSH.Marshal(struct{ Port uint32 }{Port: alloc}), nil
		}
		return true, nil, nil
	case "cancel-tcpip-forward":
		m.cancelTcpipCalls.Add(1)
		return true, nil, nil
	default:
		return false, nil, errors.New("unsupported global request: " + strconv.Quote(name))
	}
}

// TestPass6_M3_OpenRemoteForwardDynamicPortValidation verifies that when
// MUX_FWD_REMOTE requests dynamic port allocation (ListenPort == 0):
//   - server-returned allocatedPort outside 1..65535 (0, 65536, 70000, MaxUint32)
//     is rejected with MUX_S_FAILURE, cleans up the unpublished listener, and
//     leaves s.forwards and s.listenEndpoints empty;
//   - valid allocated ports (1, 45601, 65535) succeed with MUX_S_REMOTE_PORT and
//     clean up symmetrically on CloseForward.
func TestPass6_M3_OpenRemoteForwardDynamicPortValidation(t *testing.T) {
	setTestHome(t)

	invalidPorts := []uint32{0, 65536, 70000, 0xFFFFFFFF}
	validPorts := []uint32{1, 45601, 65535}

	queue := append([]uint32{}, invalidPorts...)
	queue = append(queue, validPorts...)
	mockConn := &pass6ConfigurableDynamicSSHConn{portQueue: queue}
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp4")
	defer cleanup()

	for i, badPort := range invalidPorts {
		req := MuxFwdRequest{
			RequestID:   uint32(10 + i),
			FwdType:     MUX_FWD_REMOTE,
			ListenHost:  "127.0.0.1",
			ListenPort:  0,
			ConnectHost: "127.0.0.1",
			ConnectPort: 8080,
		}
		pt, payload := runPass4MuxFwdCall(t, func(c net.Conn) error {
			return srv.handleOpenFwd(c, req)
		})
		_, reason, _ := DecodeMuxError(payload)
		if pt != MUX_S_FAILURE || !strings.Contains(reason, "invalid") {
			t.Fatalf("bad allocatedPort=%d: got (0x%x, %q), want MUX_S_FAILURE mentioning invalid port", badPort, pt, reason)
		}
		if gotCancels, wantCancels := mockConn.cancelTcpipCalls.Load(), int32(i+1); gotCancels != wantCancels {
			t.Fatalf("bad allocatedPort=%d: cancelTcpipCalls = %d, want %d (unpublished listener cleanup)", badPort, gotCancels, wantCancels)
		}
		assertPass4MuxForwardTablesEmpty(t, srv)
	}

	for i, wantPort := range validPorts {
		gotPort := mustPass4OpenRemotePortFwd(t, srv, MuxFwdRequest{
			RequestID:   uint32(100 + i),
			FwdType:     MUX_FWD_REMOTE,
			ListenHost:  "127.0.0.1",
			ListenPort:  0,
			ConnectHost: "127.0.0.1",
			ConnectPort: uint32(8100 + i),
		})
		if gotPort != wantPort {
			t.Fatalf("valid dynamic port #%d = %d, want %d", i, gotPort, wantPort)
		}
	}

	for i, wantPort := range validPorts {
		mustPass4CloseFwdOK(t, srv, MuxFwdRequest{
			RequestID:   uint32(200 + i),
			FwdType:     MUX_FWD_REMOTE,
			ListenHost:  "127.0.0.1",
			ListenPort:  wantPort,
			ConnectHost: "127.0.0.1",
			ConnectPort: uint32(8100 + i),
		})
	}
	assertPass4MuxForwardTablesEmpty(t, srv)
}

type pass6LiveRemoteForwardRig struct {
	serverConn       *cryptoSSH.ServerConn
	muxServer        *MuxServer
	mu               sync.Mutex
	dynamicPorts     []uint32
	blockStaticPort  uint32
	staticEntered    chan struct{}
	staticOnce       sync.Once
	releaseStatic    chan struct{}
	acceptStatic     bool
	cancelTcpipCalls atomic.Int32
}

func startPass6LiveRemoteForwardRig(t *testing.T, dialNet string) *pass6LiveRemoteForwardRig {
	t.Helper()
	listener, sshServerCfg := startKeepAliveTestSSHServer(t)
	rig := &pass6LiveRemoteForwardRig{
		staticEntered: make(chan struct{}),
		releaseStatic: make(chan struct{}),
		acceptStatic:  true,
	}

	srvReady := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		sConn, chans, reqs, err := cryptoSSH.NewServerConn(conn, sshServerCfg)
		if err != nil {
			return
		}
		rig.serverConn = sConn
		close(srvReady)
		wg.Go(func() { rig.handleGlobalRequests(reqs) })
		for newCh := range chans {
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unexpected client channel")
		}
	})

	rawConn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial test SSH server: %v", err)
	}
	cConn, chans, reqs, err := cryptoSSH.NewClientConn(rawConn, listener.Addr().String(), &cryptoSSH.ClientConfig{
		User:            "alice",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password("test")},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		_ = rawConn.Close()
		t.Fatalf("NewClientConn: %v", err)
	}
	<-srvReady

	rawCli := cryptoSSH.NewClient(&pass6HookedClientConn{Conn: cConn, rig: rig}, chans, reqs)
	ctx, cancel := context.WithCancel(context.Background())
	srv := &MuxServer{
		serverCtx:         ctx,
		serverCancel:      cancel,
		sshClient:         rawCli,
		rootConn:          rawConn,
		dialNetwork:       dialNet,
		persistEnabled:    true,
		persistIndefinite: true,
		idleNotify:        make(chan struct{}),
		shutdownChan:      make(chan struct{}),
	}
	rig.muxServer = srv

	t.Cleanup(func() {
		_ = srv.Shutdown()
		if rig.serverConn != nil {
			_ = rig.serverConn.Close()
		}
		_ = listener.Close()
		wg.Wait()
	})
	return rig
}

func (r *pass6LiveRemoteForwardRig) pushDynamicPorts(ports ...uint32) {
	r.mu.Lock()
	r.dynamicPorts = append(r.dynamicPorts, ports...)
	r.mu.Unlock()
}

func (r *pass6LiveRemoteForwardRig) popDynamicPort() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.dynamicPorts) == 0 {
		return 0
	}
	p := r.dynamicPorts[0]
	r.dynamicPorts = r.dynamicPorts[1:]
	return p
}

func (r *pass6LiveRemoteForwardRig) handleGlobalRequests(reqs <-chan *cryptoSSH.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			r.replyTcpipForward(req)
		case "cancel-tcpip-forward":
			r.cancelTcpipCalls.Add(1)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

type pass6HookedClientConn struct {
	cryptoSSH.Conn
	rig *pass6LiveRemoteForwardRig
}

func (c *pass6HookedClientConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	if name == "tcpip-forward" {
		var msg struct {
			BindAddr string
			BindPort uint32
		}
		_ = cryptoSSH.Unmarshal(payload, &msg)
		c.rig.mu.Lock()
		blockPort := c.rig.blockStaticPort
		accept := c.rig.acceptStatic
		c.rig.mu.Unlock()
		if blockPort != 0 && msg.BindPort == blockPort {
			if !accept {
				c.rig.staticOnce.Do(func() { close(c.rig.staticEntered) })
				<-c.rig.releaseStatic
				return false, nil, nil
			}
			ok, resp, err := c.Conn.SendRequest(name, wantReply, payload)
			c.rig.staticOnce.Do(func() { close(c.rig.staticEntered) })
			<-c.rig.releaseStatic
			return ok, resp, err
		}
	}
	return c.Conn.SendRequest(name, wantReply, payload)
}

func (r *pass6LiveRemoteForwardRig) replyTcpipForward(req *cryptoSSH.Request) {
	var msg struct {
		BindAddr string
		BindPort uint32
	}
	_ = cryptoSSH.Unmarshal(req.Payload, &msg)
	if msg.BindPort == 0 {
		port := r.popDynamicPort()
		if req.WantReply {
			_ = req.Reply(true, cryptoSSH.Marshal(struct{ Port uint32 }{Port: port}))
		}
		return
	}
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
}

func (r *pass6LiveRemoteForwardRig) probeForwardedTCP(t *testing.T, bindAddr string, bindPort uint32, msg string) string {
	t.Helper()
	payload := cryptoSSH.Marshal(struct {
		Addr       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}{
		Addr:       bindAddr,
		Port:       bindPort,
		OriginAddr: "127.0.0.1",
		OriginPort: 54321,
	})
	ch, reqs, err := r.serverConn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		t.Fatalf("OpenChannel(forwarded-tcpip %s:%d): %v", bindAddr, bindPort, err)
	}
	go cryptoSSH.DiscardRequests(reqs)
	defer func() { _ = ch.Close() }()

	if _, err := io.WriteString(ch, msg); err != nil {
		t.Fatalf("write forwarded-tcpip: %v", err)
	}
	_ = ch.CloseWrite()
	out, err := io.ReadAll(ch)
	if err != nil {
		t.Fatalf("read forwarded-tcpip: %v", err)
	}
	return string(out)
}

func startPass6TaggedLocalBackend(t *testing.T, tag string) uint32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen local backend %s: %v", tag, err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = c.Close() }()
				var buf bytes.Buffer
				_, _ = io.Copy(&buf, c)
				_, _ = fmt.Fprintf(c, "%s:%s", tag, buf.String())
			})
		}
	})
	return uint32(ln.Addr().(*net.TCPAddr).Port)
}

// TestPass6_M3_PublishForwardDynamicConflictPreservesActiveForward verifies M3:
//   - a dynamic -R 0 allocation colliding with a committed endpoint (both identical
//     forwardKey and distinct forwardKey / canonical host) fails with MUX_S_FAILURE
//     conflict without incrementing refs or replying MUX_S_OK;
//   - closing/retaining the unpublished duplicate remote listener does NOT send
//     cancel-tcpip-forward for an identical upstream bind or tear down the already
//     published forward on the shared *cryptoSSH.Client;
//   - a dynamic -R 0 allocation colliding with an inFlight static slot that already
//     has a fallbackEntry rejects the conflict cleanly without leaking inFlight slots.
func TestPass6_M3_PublishForwardDynamicConflictPreservesActiveForward(t *testing.T) {
	setTestHome(t)
	t.Run("same_forward_key_rejects_conflict_without_refs_merge_or_breaking_live_forward", assertPass6DynamicConflictSameKeyLive)
	t.Run("distinct_forward_key_and_canonical_host_reject_conflict_and_preserve_live_forward", assertPass6DynamicConflictDistinctKeyLive)
	t.Run("inflight_slot_with_existing_fallback_rejects_second_dynamic_without_slot_leak", assertPass6DynamicConflictDuringInFlightFallback)
}

func assertPass6DynamicConflictSameKeyLive(t *testing.T) {
	const portP = uint32(45610)
	rig := startPass6LiveRemoteForwardRig(t, "tcp4")
	portA := startPass6TaggedLocalBackend(t, "backendA")

	mustPass4OpenFwdOK(t, rig.muxServer, MuxFwdRequest{
		RequestID:   1,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "127.0.0.1",
		ConnectPort: portA,
	})
	if got := rig.probeForwardedTCP(t, "127.0.0.1", portP, "ping1"); got != "backendA:ping1" {
		t.Fatalf("initial forwarded traffic = %q, want %q", got, "backendA:ping1")
	}

	// Colliding dynamic -R 127.0.0.1:0:127.0.0.1:portA allocated portP (IDENTICAL forwardKey):
	// must fail with conflict (never MUX_S_OK / refs++), emit 0 cancel-tcpip-forward, and keep live forward working!
	rig.pushDynamicPorts(portP)
	assertPass4OpenFwdConflict(t, rig.muxServer, MuxFwdRequest{
		RequestID:   2,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: "127.0.0.1",
		ConnectPort: portA,
	})
	if gotCancels := rig.cancelTcpipCalls.Load(); gotCancels != 0 {
		t.Fatalf("cancelTcpipCalls after same-bind conflict = %d, want 0 while active forward lives", gotCancels)
	}
	if got := rig.probeForwardedTCP(t, "127.0.0.1", portP, "ping2"); got != "backendA:ping2" {
		t.Fatalf("post-conflict forwarded traffic = %q, want %q", got, "backendA:ping2")
	}

	// Single CloseForward must drop refs 1 -> 0, clean up both primary and shadow listeners, and empty tables!
	mustPass4CloseFwdOK(t, rig.muxServer, MuxFwdRequest{
		RequestID:   3,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "127.0.0.1",
		ConnectPort: portA,
	})
	assertPass4MuxForwardTablesEmpty(t, rig.muxServer)

	// Re-opening on the exact same bind address proves s.sshClient.forwards has zero leaked stale entries!
	mustPass4OpenFwdOK(t, rig.muxServer, MuxFwdRequest{
		RequestID:   4,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "127.0.0.1",
		ConnectPort: portA,
	})
	if got := rig.probeForwardedTCP(t, "127.0.0.1", portP, "ping3"); got != "backendA:ping3" {
		t.Fatalf("reopened forwarded traffic = %q, want %q", got, "backendA:ping3")
	}
	mustPass4CloseFwdOK(t, rig.muxServer, MuxFwdRequest{
		RequestID:   5,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "127.0.0.1",
		ConnectPort: portA,
	})
	assertPass4MuxForwardTablesEmpty(t, rig.muxServer)
}

func assertPass6DynamicConflictDistinctKeyLive(t *testing.T) {
	const portP = uint32(45611)
	rig := startPass6LiveRemoteForwardRig(t, "tcp4")
	portA := startPass6TaggedLocalBackend(t, "backendA")
	portB := startPass6TaggedLocalBackend(t, "backendB")

	mustPass4OpenFwdOK(t, rig.muxServer, MuxFwdRequest{
		RequestID:   10,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "127.0.0.1",
		ConnectPort: portA,
	})

	// 1) Same ListenHost ("127.0.0.1"), distinct destination (portB)
	rig.pushDynamicPorts(portP)
	assertPass4OpenFwdConflict(t, rig.muxServer, MuxFwdRequest{
		RequestID:   11,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: "127.0.0.1",
		ConnectPort: portB,
	})
	if gotCancels := rig.cancelTcpipCalls.Load(); gotCancels != 0 {
		t.Fatalf("cancelTcpipCalls on same-host conflict = %d, want 0", gotCancels)
	}

	// 2) Canonical equivalent ListenHost ("localhost" under tcp4), distinct destination (portB)
	rig.pushDynamicPorts(portP)
	assertPass4OpenFwdConflict(t, rig.muxServer, MuxFwdRequest{
		RequestID:   12,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "localhost",
		ListenPort:  0,
		ConnectHost: "127.0.0.1",
		ConnectPort: portB,
	})
	if gotCancels := rig.cancelTcpipCalls.Load(); gotCancels != 1 {
		t.Fatalf("cancelTcpipCalls after distinct-host (localhost) unpublished close = %d, want 1", gotCancels)
	}

	if got := rig.muxServer.forwardCount(); got != 1 {
		t.Fatalf("forwardCount = %d, want 1", got)
	}
	if got := rig.probeForwardedTCP(t, "127.0.0.1", portP, "check"); got != "backendA:check" {
		t.Fatalf("forwarded traffic routed to %q, want %q", got, "backendA:check")
	}

	mustPass4CloseFwdOK(t, rig.muxServer, MuxFwdRequest{
		RequestID:   13,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "127.0.0.1",
		ConnectPort: portA,
	})
	assertPass4MuxForwardTablesEmpty(t, rig.muxServer)
}

func assertPass6DynamicConflictDuringInFlightFallback(t *testing.T) {
	for _, acceptStatic := range []bool{false, true} {
		mode := "static_fails"
		if acceptStatic {
			mode = "permissive_static_succeeds"
		}
		t.Run(mode, func(t *testing.T) {
			const portP = uint32(45612)
			rig := startPass6LiveRemoteForwardRig(t, "tcp4")
			rig.mu.Lock()
			rig.blockStaticPort = portP
			rig.acceptStatic = acceptStatic
			rig.mu.Unlock()

			portDyn1 := startPass6TaggedLocalBackend(t, "dyn1")
			portDyn2 := startPass6TaggedLocalBackend(t, "dyn2")
			portStatic := startPass6TaggedLocalBackend(t, "static")

			staticDone := make(chan pass5MuxReply, 1)
			go func() {
				pt, payload := runPass4MuxFwdCall(t, func(c net.Conn) error {
					return rig.muxServer.handleOpenFwd(c, MuxFwdRequest{
						RequestID:   21,
						FwdType:     MUX_FWD_REMOTE,
						ListenHost:  "127.0.0.1",
						ListenPort:  portP,
						ConnectHost: "127.0.0.1",
						ConnectPort: portStatic,
					})
				})
				_, reason, _ := DecodeMuxError(payload)
				staticDone <- pass5MuxReply{pktType: pt, reason: reason}
			}()
			<-rig.staticEntered

			// Dynamic #1 claims fallbackEntry on portP while static is inFlight.
			rig.pushDynamicPorts(portP)
			gotPort := mustPass4OpenRemotePortFwd(t, rig.muxServer, MuxFwdRequest{
				RequestID:   22,
				FwdType:     MUX_FWD_REMOTE,
				ListenHost:  "127.0.0.1",
				ListenPort:  0,
				ConnectHost: "127.0.0.1",
				ConnectPort: portDyn1,
			})
			if gotPort != portP {
				t.Fatalf("dynamic #1 port = %d, want %d", gotPort, portP)
			}

			// Dynamic #2 also allocated portP while static is STILL inFlight: must fail with conflict!
			rig.pushDynamicPorts(portP)
			assertPass4OpenFwdConflict(t, rig.muxServer, MuxFwdRequest{
				RequestID:   23,
				FwdType:     MUX_FWD_REMOTE,
				ListenHost:  "127.0.0.1",
				ListenPort:  0,
				ConnectHost: "127.0.0.1",
				ConnectPort: portDyn2,
			})

			// Unblock inFlight static bind and verify no slot leak and dyn1 remains live!
			close(rig.releaseStatic)
			sRes := <-staticDone
			if sRes.pktType != MUX_S_FAILURE {
				t.Fatalf("static reply = (0x%x, %q), want MUX_S_FAILURE", sRes.pktType, sRes.reason)
			}
			if got := rig.probeForwardedTCP(t, "127.0.0.1", portP, "ok"); got != "dyn1:ok" {
				t.Fatalf("forwarded traffic = %q, want %q", got, "dyn1:ok")
			}

			mustPass4CloseFwdOK(t, rig.muxServer, MuxFwdRequest{
				RequestID:   24,
				FwdType:     MUX_FWD_REMOTE,
				ListenHost:  "127.0.0.1",
				ListenPort:  portP,
				ConnectHost: "127.0.0.1",
				ConnectPort: portDyn1,
			})
			assertPass4MuxForwardTablesEmpty(t, rig.muxServer)
		})
	}
}

func newPass6SocketMuxServer(t *testing.T, opts MuxServerOptions) *MuxServer {
	t.Helper()
	if opts.ControlPath == "" {
		opts.ControlPath = filepath.Join(shortSocketDir(t), "pass6.sock")
	}
	if opts.SSHClient == nil {
		opts.SSHClient = newDummySSHClient()
	}
	srv, err := NewMuxServer(opts)
	if err != nil {
		if errors.Is(err, ErrUnsupportedMuxPlatform) {
			t.Skipf("mux control socket unsupported on platform: %v", err)
		}
		t.Fatalf("NewMuxServer: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return srv
}

// TestPass6_M4_HandoffStopListeningAndIdleTimer verifies M4:
//   - PrepareHandoff prevents -O stop (handleStopListening) / shutdownWhenIdle
//     from tearing down a server mid-handoff;
//   - CancelHandoff after -O stop shuts down cleanly when idle, and keeps running
//     when active (clearing only handoff-set shuttingDown state) until sessions drain;
//   - CancelHandoff re-arms finite ControlPersist idle timer when rolled back idle;
//   - concurrent PrepareHandoff / CancelHandoff / -O stop / session churn is race-free.
func TestPass6_M4_HandoffStopListeningAndIdleTimer(t *testing.T) {
	t.Run("idle_stop_during_handoff_then_cancel_shuts_down", assertPass6HandoffStopIdleCancel)
	t.Run("active_stop_before_and_during_handoff", assertPass6HandoffStopActiveCancel)
	t.Run("cancel_handoff_rearms_finite_control_persist_timer", assertPass6CancelHandoffRearmsIdleTimer)
	t.Run("concurrent_handoff_stop_and_session_race", assertPass6ConcurrentHandoffStopRace)
}

func assertPass6HandoffStopIdleCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	srv := newPass6SocketMuxServer(t, MuxServerOptions{
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	cli, err := DialMuxClient(ctx, srv.ControlPath())
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	defer func() { _ = cli.Close() }()

	if !srv.PrepareHandoff() {
		t.Fatal("expected PrepareHandoff to succeed on idle server")
	}

	// Send -O stop over the pre-connected control client while mid-handoff.
	if err := cli.StopListening(ctx); err != nil {
		t.Fatalf("StopListening during handoff failed: %v", err)
	}
	if !srv.StoppedListening() {
		t.Fatal("expected StoppedListening() == true after -O stop")
	}

	// Server must NOT tear down mid-handoff before Shutdown or CancelHandoff!
	select {
	case <-srv.Wait():
		t.Fatal("server tore down mid-handoff on -O stop before CancelHandoff/Shutdown")
	case <-time.After(80 * time.Millisecond):
	}

	// Roll back handoff while idle: CancelHandoff must trigger clean shutdown!
	srv.CancelHandoff()
	select {
	case <-srv.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("CancelHandoff left stopped idle server wedged without shutting down")
	}
}

func assertPass6HandoffStopActiveCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	// Part 1: -O stop arrives BEFORE PrepareHandoff while an active session is running.
	srvBefore := newPass6SocketMuxServer(t, MuxServerOptions{
		PersistEnabled:        true,
		PersistIndefinite:     true,
		InitialActiveSessions: 1,
	})
	cliBefore, err := DialMuxClient(ctx, srvBefore.ControlPath())
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	if err := cliBefore.StopListening(ctx); err != nil {
		_ = cliBefore.Close()
		t.Fatalf("StopListening: %v", err)
	}
	_ = cliBefore.Close()

	if srvBefore.PrepareHandoff() {
		t.Fatal("PrepareHandoff must fail when stoppedListening and session is active")
	}
	// Spurious CancelHandoff when handoff was never reserved must be a no-op.
	srvBefore.CancelHandoff()
	select {
	case <-srvBefore.Wait():
		t.Fatal("server shut down while foreground session was still active")
	case <-time.After(50 * time.Millisecond):
	}
	srvBefore.RemoveForegroundSession()
	select {
	case <-srvBefore.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down after active session drained")
	}

	// Part 2: PrepareHandoff succeeds, -O stop arrives mid-handoff, and server has an active session at CancelHandoff.
	srvDuring := newPass6SocketMuxServer(t, MuxServerOptions{
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if !srvDuring.PrepareHandoff() {
		t.Fatal("PrepareHandoff failed")
	}
	runPass4MuxFwdCall(t, func(c net.Conn) error {
		return srvDuring.handleStopListening(c, 77)
	})
	srvDuring.idleMu.Lock()
	srvDuring.activeSessions++
	srvDuring.idleMu.Unlock()

	srvDuring.CancelHandoff()
	if srvDuring.isShuttingDown() {
		t.Fatal("CancelHandoff must clear handoff-set shuttingDown when activeSessions > 0")
	}
	select {
	case <-srvDuring.Wait():
		t.Fatal("CancelHandoff shut down server while activeSessions > 0")
	case <-time.After(60 * time.Millisecond):
	}

	srvDuring.RemoveForegroundSession()
	select {
	case <-srvDuring.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("server failed to shut down once active session released after CancelHandoff")
	}
}

func assertPass6CancelHandoffRearmsIdleTimer(t *testing.T) {
	srv := newPass6SocketMuxServer(t, MuxServerOptions{
		PersistEnabled:    true,
		PersistIndefinite: false,
		PersistDuration:   100 * time.Millisecond,
	})

	if !srv.PrepareHandoff() {
		t.Fatal("expected PrepareHandoff to succeed on idle finite ControlPersist master")
	}

	// Hold reservation past PersistDuration: idle timer must stay disarmed during handoff.
	select {
	case <-srv.Wait():
		t.Fatal("idle timer fired while PrepareHandoff held reservation")
	case <-time.After(220 * time.Millisecond):
	}

	// CancelHandoff while idle must re-arm PersistDuration so master expires cleanly.
	srv.CancelHandoff()
	select {
	case <-srv.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("CancelHandoff failed to re-arm finite ControlPersist idle timer (server became immortal)")
	}
}

func assertPass6ConcurrentHandoffStopRace(t *testing.T) {
	for i := range 25 {
		ctx, cancel := context.WithCancel(context.Background())
		srv := &MuxServer{
			serverCtx:         ctx,
			serverCancel:      cancel,
			sshClient:         newDummySSHClient(),
			persistEnabled:    true,
			persistIndefinite: false,
			persistDuration:   40 * time.Millisecond,
			idleNotify:        make(chan struct{}),
			shutdownChan:      make(chan struct{}),
		}

		var wg sync.WaitGroup
		wg.Go(func() {
			if srv.PrepareHandoff() {
				time.Sleep(time.Duration(i%3) * time.Millisecond)
				srv.CancelHandoff()
			} else {
				srv.CancelHandoff()
			}
		})
		wg.Go(func() {
			c1, c2 := net.Pipe()
			defer func() {
				_ = c1.Close()
				_ = c2.Close()
			}()
			go func() {
				_, _, _ = ReadMuxPacket(c2)
			}()
			_ = srv.handleStopListening(c1, uint32(i+1))
		})
		wg.Go(func() {
			if srv.AddForegroundSession() {
				time.Sleep(time.Millisecond)
				srv.RemoveForegroundSession()
			}
		})
		wg.Wait()

		select {
		case <-srv.Wait():
		case <-time.After(2 * time.Second):
			_ = srv.Shutdown()
			t.Fatalf("iteration %d: stopped server wedged after concurrent PrepareHandoff/CancelHandoff/StopListening", i)
		}
	}
}
