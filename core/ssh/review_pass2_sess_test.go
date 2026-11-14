package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// TestReviewPass2_H5_UnsupportedUnixControlSocketFailsClosed verifies that
// unsupported non-Windows Unix targets refuse to bind unauthenticated control
// sockets and fail closed with ErrUnauthorizedPeer on peer credential checks.
func TestReviewPass2_H5_UnsupportedUnixControlSocketFailsClosed(t *testing.T) {
	sockDir := filepath.Join(t.TempDir(), "nested")
	sockPath := filepath.Join(sockDir, "cm.sock")

	if _, err := unsupportedUnixBindControlSocket("", "openbsd"); err == nil {
		t.Fatal("expected empty control path to fail")
	}

	ln, err := unsupportedUnixBindControlSocket(sockPath, "openbsd")
	if err == nil || ln != nil {
		if ln != nil {
			_ = ln.Close()
		}
		t.Fatalf("expected unsupportedUnixBindControlSocket to fail closed, got ln=%v err=%v", ln, err)
	}
	if !errors.Is(err, ErrUnsupportedMuxPlatform) {
		t.Fatalf("expected ErrUnsupportedMuxPlatform, got %v", err)
	}
	if _, statErr := os.Stat(sockDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unsupportedUnixBindControlSocket must not create directories on disk, stat err=%v", statErr)
	}

	uidErr := unsupportedUnixCheckPeerUID("netbsd")
	if !errors.Is(uidErr, ErrUnauthorizedPeer) || !errors.Is(uidErr, ErrUnsupportedMuxPlatform) {
		t.Fatalf("expected ErrUnauthorizedPeer + ErrUnsupportedMuxPlatform, got %v", uidErr)
	}
	if !isFatalMultiplexSecurityError(uidErr) {
		t.Fatalf("expected unsupportedUnixCheckPeerUID error %v to be treated as fatal multiplex security error", uidErr)
	}
}

// TestReviewPass2_M6_RemoteForwardAddressFamilyHonorsTCP4AndTCP6 verifies that
// RemoteListenAddressForMode and MuxServer.resolveMuxForwardListen map default
// loopback and wildcard -R binds to family-specific IPv4/IPv6 addresses when
// dialNetwork is tcp4 or tcp6 (since x/crypto/ssh Listen ignores network).
func TestReviewPass2_M6_RemoteForwardAddressFamilyHonorsTCP4AndTCP6(t *testing.T) {
	assertRemoteEndpointListenMatrix(t)
	assertMuxRemoteForwardListenMatrix(t)
}

func assertRemoteEndpointListenMatrix(t *testing.T) {
	t.Helper()
	unixEp := ForwardEndpoint{SocketPath: "/tmp/remote.sock"}
	if gotNet, gotAddr := unixEp.RemoteListenAddressForMode(GatewayPortsYes, "tcp6"); gotNet != "unix" || gotAddr != "/tmp/remote.sock" {
		t.Fatalf("unix RemoteListenAddressForMode = (%q, %q), want (unix, /tmp/remote.sock)", gotNet, gotAddr)
	}

	cases := []struct {
		name     string
		ep       ForwardEndpoint
		mode     string
		netw     string
		wantNet  string
		wantAddr string
	}{
		{"default tcp4 cs", ForwardEndpoint{Port: 8080}, GatewayPortsClientSpecified, "tcp4", "tcp4", "127.0.0.1:8080"},
		{"default tcp6 cs", ForwardEndpoint{Port: 8080}, GatewayPortsClientSpecified, "tcp6", "tcp6", "[::1]:8080"},
		{"default tcp cs", ForwardEndpoint{Port: 8080}, GatewayPortsClientSpecified, "tcp", "tcp", "localhost:8080"},
		{"wildcard tcp4 cs", ForwardEndpoint{Port: 8080, Wildcard: true, HasHost: true}, GatewayPortsClientSpecified, "tcp4", "tcp4", "0.0.0.0:8080"},
		{"wildcard tcp6 cs", ForwardEndpoint{Port: 8080, Wildcard: true, HasHost: true}, GatewayPortsClientSpecified, "tcp6", "tcp6", "[::]:8080"},
		{"wildcard tcp cs", ForwardEndpoint{Port: 8080, Wildcard: true, HasHost: true}, GatewayPortsClientSpecified, "tcp", "tcp", ":8080"},
		{"gw=yes tcp4", ForwardEndpoint{Port: 9000}, GatewayPortsYes, "tcp4", "tcp4", "0.0.0.0:9000"},
		{"gw=yes tcp6", ForwardEndpoint{Port: 9000}, GatewayPortsYes, "tcp6", "tcp6", "[::]:9000"},
		{"gw=yes tcp", ForwardEndpoint{Port: 9000}, GatewayPortsYes, "tcp", "tcp", ":9000"},
		{"gw=no wildcard tcp4", ForwardEndpoint{Port: 9000, Wildcard: true, HasHost: true}, GatewayPortsNo, "tcp4", "tcp4", "127.0.0.1:9000"},
		{"gw=no wildcard tcp6", ForwardEndpoint{Port: 9000, Wildcard: true, HasHost: true}, GatewayPortsNo, "tcp6", "tcp6", "[::1]:9000"},
		{"gw=no explicit host", ForwardEndpoint{Host: "10.0.0.5", Port: 9000, HasHost: true}, GatewayPortsNo, "tcp4", "tcp4", "10.0.0.5:9000"},
	}
	for _, tc := range cases {
		gotNet, gotAddr := tc.ep.RemoteListenAddressForMode(tc.mode, tc.netw)
		if gotNet != tc.wantNet || gotAddr != tc.wantAddr {
			t.Fatalf("%s: RemoteListenAddressForMode(%q, %q) = (%q, %q), want (%q, %q)",
				tc.name, tc.mode, tc.netw, gotNet, gotAddr, tc.wantNet, tc.wantAddr)
		}
	}
}

func assertMuxRemoteForwardListenMatrix(t *testing.T) {
	t.Helper()
	cases := []struct {
		dialNet  string
		gwMode   string
		host     string
		wantNet  string
		wantAddr string
		wantKey  string
	}{
		{"tcp4", GatewayPortsClientSpecified, "", "tcp4", "127.0.0.1:7000", "localhost"},
		{"tcp6", GatewayPortsClientSpecified, "", "tcp6", "[::1]:7000", "localhost"},
		{"tcp", GatewayPortsClientSpecified, "", "tcp", "localhost:7000", "localhost"},
		{"tcp4", GatewayPortsClientSpecified, "*", "tcp4", "0.0.0.0:7000", "*"},
		{"tcp6", GatewayPortsClientSpecified, "*", "tcp6", "[::]:7000", "*"},
		{"tcp", GatewayPortsClientSpecified, "*", "tcp", ":7000", "*"},
		{"tcp4", GatewayPortsYes, "", "tcp4", "0.0.0.0:7000", "*"},
		{"tcp6", GatewayPortsYes, "", "tcp6", "[::]:7000", "*"},
		{"tcp4", GatewayPortsNo, "*", "tcp4", "127.0.0.1:7000", "localhost"},
		{"tcp6", GatewayPortsNo, "*", "tcp6", "[::1]:7000", "localhost"},
	}
	for _, tc := range cases {
		srv := &MuxServer{dialNetwork: tc.dialNet, gatewayPortsMode: tc.gwMode}
		gotNet, gotAddr, gotKey, err := srv.resolveMuxForwardListen(MUX_FWD_REMOTE, tc.host, 7000)
		if err != nil || gotNet != tc.wantNet || gotAddr != tc.wantAddr || gotKey != tc.wantKey {
			t.Fatalf("resolveMuxForwardListen(net=%q, gw=%q, host=%q) = (%q, %q, %q, %v), want (%q, %q, %q, nil)",
				tc.dialNet, tc.gwMode, tc.host, gotNet, gotAddr, gotKey, err, tc.wantNet, tc.wantAddr, tc.wantKey)
		}
	}

	// Verify actual wire tcpip-forward bind address sent via x/crypto/ssh.Client.Listen.
	wireHost := captureWireTCPIPForwardHost(t, "tcp6", GatewayPortsClientSpecified, ForwardEndpoint{Port: 8081})
	if wireHost != "::1" {
		t.Fatalf("wire tcpip-forward host for tcp6 default -R = %q, want \"::1\"", wireHost)
	}
	wireWild4 := captureWireTCPIPForwardHost(t, "tcp4", GatewayPortsClientSpecified, ForwardEndpoint{Port: 8082, Wildcard: true, HasHost: true})
	if wireWild4 != "0.0.0.0" {
		t.Fatalf("wire tcpip-forward host for tcp4 wildcard -R = %q, want \"0.0.0.0\"", wireWild4)
	}
}

func captureWireTCPIPForwardHost(t *testing.T, dialNet, gwMode string, ep ForwardEndpoint) string {
	t.Helper()
	var gotHost string
	var mu sync.Mutex
	conn := &pass2RecordingGlobalReqConn{
		onGlobalReq: func(name string, payload []byte) (bool, []byte) {
			if name == "tcpip-forward" {
				var msg struct {
					Addr  string
					RPort uint32
				}
				if err := cryptoSSH.Unmarshal(payload, &msg); err == nil {
					mu.Lock()
					gotHost = msg.Addr
					mu.Unlock()
				}
				return true, nil
			}
			return true, nil
		},
	}
	chans := make(chan cryptoSSH.NewChannel)
	close(chans)
	reqs := make(chan *cryptoSSH.Request)
	close(reqs)
	rawCli := cryptoSSH.NewClient(conn, chans, reqs)
	t.Cleanup(func() { _ = rawCli.Close() })

	netw, addr := ep.RemoteListenAddressForMode(gwMode, dialNet)
	ln, err := rawCli.Listen(netw, addr)
	if err != nil {
		t.Fatalf("rawCli.Listen(%q, %q): %v", netw, addr, err)
	}
	_ = ln.Close()
	mu.Lock()
	defer mu.Unlock()
	return gotHost
}

type pass2RecordingGlobalReqConn struct {
	dummyMuxGateConn
	onGlobalReq func(name string, payload []byte) (bool, []byte)
}

func (c *pass2RecordingGlobalReqConn) SendRequest(name string, _ bool, payload []byte) (bool, []byte, error) {
	if c.onGlobalReq != nil {
		ok, resp := c.onGlobalReq(name, payload)
		return ok, resp, nil
	}
	return false, nil, nil
}

// TestReviewPass2_M8_AgentForwardNormalizationMuxCoexistenceAndHardwareKeyLifetime
// covers agent socket path normalization, OpenSSH-aligned mux coexistence,
// proxy channel request bounding/draining, and non-half-close hardware-key latency.
func TestReviewPass2_M8_AgentForwardNormalizationMuxCoexistenceAndHardwareKeyLifetime(t *testing.T) {
	t.Run("ResolveForwardAgent normalizes SSH_AUTH_SOCK and yes paths", assertPass2AgentPathNormalization)
	t.Run("master local lease and authorized MUX_C_PROXY leases coexist unless sockets conflict", assertPass2MuxAgentCoexistence)
	t.Run("non-half-close local agent waits past 250ms for hardware key touch", assertPass2HardwareKeyAgentLatency)
	t.Run("serveChannelRequests bounds stalled remote SendRequest and closes cleanly", assertPass2BoundedProxyChannelRequest)
}

func assertPass2AgentPathNormalization(t *testing.T) {
	base := t.TempDir()
	dirtySock := filepath.Join(base, "nested", "..", "agent.sock")
	wantClean := filepath.Clean(dirtySock)
	env := Environment{
		AgentSocket: dirtySock,
	}

	gotSSHAuth, enabled, err := ResolveForwardAgent("SSH_AUTH_SOCK", "", env, TargetContext{})
	if err != nil || !enabled || gotSSHAuth != wantClean {
		t.Fatalf("ResolveForwardAgent(SSH_AUTH_SOCK) = (%q, %v, %v), want (%q, true, nil)", gotSSHAuth, enabled, err, wantClean)
	}

	gotYes, enabled, err := ResolveForwardAgent("yes", "", env, TargetContext{})
	if err != nil || !enabled || gotYes != wantClean {
		t.Fatalf("ResolveForwardAgent(yes) = (%q, %v, %v), want (%q, true, nil)", gotYes, enabled, err, wantClean)
	}

	relEnv := Environment{
		AgentSocket: "~/rel-agent.sock",
		ResolveKeyPath: func(p string) string {
			if after, ok := strings.CutPrefix(p, "~/"); ok {
				return filepath.Join(base, after)
			}
			return p
		},
	}
	wantRel := filepath.Join(base, "rel-agent.sock")
	gotRel, enabled, err := ResolveForwardAgent("yes", "", relEnv, TargetContext{})
	if err != nil || !enabled || gotRel != wantRel {
		t.Fatalf("ResolveForwardAgent(ResolveKeyPath env.AgentSocket) = (%q, %v, %v), want (%q, true, nil)", gotRel, enabled, err, wantRel)
	}
}

func assertPass2MuxAgentCoexistence(t *testing.T) {
	chans := make(chan cryptoSSH.NewChannel)
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

	base := t.TempDir()
	cleanSock := filepath.Join(base, "master-agent.sock")
	dialStub := func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("unused")
	}
	muxMaster := &MuxServer{
		sshClient:         rawCli,
		allowAgentForward: true,
		agentSocket:       normalizeExpandedAgentSocketPath(filepath.Join(base, "dir", "..", "master-agent.sock"), Environment{}),
		dialAgent:         dialStub,
	}

	// 1. Master holds local lease on cleanSock.
	localLease, err := router.acquireLocalLease(t.Context(), cleanSock, dialStub, nil)
	if err != nil {
		t.Fatalf("acquireLocalLease(master): %v", err)
	}
	defer localLease.Release()

	// 2. Two concurrent MUX_C_PROXY sessions on the same authorized master share Master's local lease!
	ps1 := &proxySessionState{server: muxMaster}
	ps2 := &proxySessionState{server: muxMaster}
	proxyLease1, ok := ps1.acquireChannelAgentLease()
	if !ok || proxyLease1 == nil {
		t.Fatal("expected authorized MUX_C_PROXY ps1 to coexist with master local lease")
	}
	defer proxyLease1.Release()

	proxyLease2, ok := ps2.acquireChannelAgentLease()
	if !ok || proxyLease2 == nil {
		t.Fatal("expected sibling MUX_C_PROXY ps2 to coexist on same master")
	}
	defer proxyLease2.Release()

	// 3. Another local session forwarding the SAME normalized socket also coexists.
	passengerLease, err := router.acquireLocalLease(t.Context(), cleanSock, dialStub, nil)
	if err != nil {
		t.Fatalf("expected passenger local lease on same socket to coexist, got: %v", err)
	}
	passengerLease.Release()

	// 4. Concurrent local lease attempting to route to a DIFFERENT socket MUST fail closed!
	otherSock := filepath.Join(base, "different-agent.sock")
	if conflictLease, err := router.acquireLocalLease(t.Context(), otherSock, dialStub, nil); !errors.Is(err, errAgentLeaseConflict) {
		if conflictLease != nil {
			conflictLease.Release()
		}
		t.Fatalf("expected conflicting socket %q to fail with errAgentLeaseConflict, got %v", otherSock, err)
	}

	// 5. Proxy session bound to a master with a DIFFERENT explicit agent socket or empty socket MUST fail closed!
	otherMaster := &MuxServer{
		sshClient:         rawCli,
		allowAgentForward: true,
		agentSocket:       otherSock,
		dialAgent:         dialStub,
	}
	psOther := &proxySessionState{server: otherMaster}
	if conflictProxy, ok := psOther.acquireChannelAgentLease(); ok || conflictProxy != nil {
		if conflictProxy != nil {
			conflictProxy.Release()
		}
		t.Fatal("expected proxy lease with different master socket to fail closed")
	}

	emptyMaster := &MuxServer{
		sshClient:         rawCli,
		allowAgentForward: true,
		agentSocket:       "",
		dialAgent:         dialStub,
	}
	psEmpty := &proxySessionState{server: emptyMaster}
	if emptyProxy, ok := psEmpty.acquireChannelAgentLease(); ok || emptyProxy != nil {
		if emptyProxy != nil {
			emptyProxy.Release()
		}
		t.Fatal("expected proxy lease on master with empty agentSocket to fail closed")
	}
}

func assertPass2HardwareKeyAgentLatency(t *testing.T) {
	chans := make(chan cryptoSSH.NewChannel, 1)
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

	// Simulate a Windows Named Pipe agent connection (no CloseWrite method!) that takes
	// 350ms (> old 250ms cutoff) to return a hardware-token signature after client EOF.
	const wantResp = "fido2-hardware-signature-ok"
	dialSlowPipeAgent := func(context.Context, string) (net.Conn, error) {
		agentSide, clientSide := net.Pipe()
		go func() {
			defer func() { _ = agentSide.Close() }()
			buf := make([]byte, 32)
			_, _ = agentSide.Read(buf)
			time.Sleep(350 * time.Millisecond)
			_, _ = agentSide.Write([]byte(wantResp))
		}()
		return &noHalfCloseConn{Conn: clientSide}, nil
	}

	lease, err := router.acquireLocalLease(t.Context(), `\\.\pipe\openssh-ssh-agent`, dialSlowPipeAgent, nil)
	if err != nil {
		t.Fatalf("acquireLocalLease: %v", err)
	}
	defer lease.Release()

	remoteCh := newFakeRemoteAgentChannel([]byte("sign-req"))
	chans <- &fakeIncomingAgentNewChannel{ch: remoteCh}

	select {
	case <-remoteCh.eofWriteCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for slow hardware-key agent response")
	}

	got := remoteCh.writtenBytes()
	if string(got) != wantResp {
		t.Fatalf("forwarded hardware-key agent response = %q, want %q (was aborted early!)", string(got), wantResp)
	}
}

type noHalfCloseConn struct {
	net.Conn
}

type fakeIncomingAgentNewChannel struct {
	ch *fakeRemoteAgentChannel
}

func (n *fakeIncomingAgentNewChannel) ChannelType() string { return agentForwardChannelType }
func (n *fakeIncomingAgentNewChannel) ExtraData() []byte   { return nil }
func (n *fakeIncomingAgentNewChannel) Reject(cryptoSSH.RejectionReason, string) error {
	return nil
}
func (n *fakeIncomingAgentNewChannel) Accept() (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	return n.ch, n.ch.reqs, nil
}

type fakeRemoteAgentChannel struct {
	readBuf    *bytes.Reader
	mu         sync.Mutex
	out        bytes.Buffer
	reqs       chan *cryptoSSH.Request
	eofOnce    sync.Once
	eofWriteCh chan struct{}
	closeOnce  sync.Once
}

func newFakeRemoteAgentChannel(input []byte) *fakeRemoteAgentChannel {
	return &fakeRemoteAgentChannel{
		readBuf:    bytes.NewReader(input),
		reqs:       make(chan *cryptoSSH.Request),
		eofWriteCh: make(chan struct{}),
	}
}

func (c *fakeRemoteAgentChannel) Read(p []byte) (int, error) { return c.readBuf.Read(p) }
func (c *fakeRemoteAgentChannel) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(p)
}
func (c *fakeRemoteAgentChannel) CloseWrite() error {
	c.eofOnce.Do(func() { close(c.eofWriteCh) })
	return nil
}
func (c *fakeRemoteAgentChannel) Close() error {
	c.closeOnce.Do(func() {
		c.eofOnce.Do(func() { close(c.eofWriteCh) })
		close(c.reqs)
	})
	return nil
}
func (c *fakeRemoteAgentChannel) Stderr() io.ReadWriter { return &nopRW{} }
func (c *fakeRemoteAgentChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (c *fakeRemoteAgentChannel) writtenBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.out.Bytes())
}

type pass2StalledChannel struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func (c *pass2StalledChannel) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *pass2StalledChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *pass2StalledChannel) CloseWrite() error           { return nil }
func (c *pass2StalledChannel) Stderr() io.ReadWriter       { return &nopRW{} }
func (c *pass2StalledChannel) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *pass2StalledChannel) SendRequest(string, bool, []byte) (bool, error) {
	<-c.closed
	return false, io.EOF
}

func assertPass2BoundedProxyChannelRequest(t *testing.T) {
	stalledCh := &pass2StalledChannel{
		closed: make(chan struct{}),
	}
	clientConn, serverConn := net.Pipe()
	defer func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	}()
	go func() {
		_, _ = io.Copy(io.Discard, clientConn)
	}()

	srv := &MuxServer{
		requestTimeout: 60 * time.Millisecond,
	}
	ps := &proxySessionState{
		server: srv,
		conn:   serverConn,
	}
	pc := &proxyChan{
		remoteCh:     stalledCh,
		clientCh:     7,
		requests:     newOrderedQueue[proxyChannelRequest](),
		requestsDone: make(chan struct{}),
	}
	go ps.serveChannelRequests(pc)

	pc.requests.push(proxyChannelRequest{
		requestType: "exec",
		wantReply:   true,
		payload:     cryptoSSH.Marshal(struct{ Command string }{"uptime"}),
	})
	pc.requests.close()

	select {
	case <-pc.requestsDone:
	case <-time.After(2 * time.Second):
		t.Fatal("serveChannelRequests hung on stalled remote SendRequest")
	}
}

// TestReviewPass2_M10_RunProbeStreamOmitsAgentForwardAndSessionEnv verifies
// that RunProbeStream never forwards ssh-agent or user SendEnv/SetEnv variables,
// whereas RunStream continues to include both for explicit user streams.
func TestReviewPass2_M10_RunProbeStreamOmitsAgentForwardAndSessionEnv(t *testing.T) {
	baseline := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, baseline) })

	var (
		mu          sync.Mutex
		seenAgent   int
		seenEnvKeys []string
		seenExecs   []string
	)
	resetRecorded := func() {
		mu.Lock()
		seenAgent = 0
		seenEnvKeys = nil
		seenExecs = nil
		mu.Unlock()
	}

	rawCli, cleanup := startPass2InMemorySSHServer(t, func(req *cryptoSSH.Request, ch cryptoSSH.Channel) {
		switch req.Type {
		case agentForwardRequestType:
			mu.Lock()
			seenAgent++
			mu.Unlock()
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "env":
			var kv struct {
				Name  string
				Value string
			}
			if cryptoSSH.Unmarshal(req.Payload, &kv) == nil {
				mu.Lock()
				seenEnvKeys = append(seenEnvKeys, kv.Name+"="+kv.Value)
				mu.Unlock()
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec":
			var cmd struct{ Command string }
			_ = cryptoSSH.Unmarshal(req.Payload, &cmd)
			mu.Lock()
			seenExecs = append(seenExecs, cmd.Command)
			mu.Unlock()
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			go func() {
				_, _ = ch.Write([]byte("probe-line-1\n"))
				_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
				_ = ch.Close()
			}()
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	})
	defer cleanup()

	agentSock := filepath.Join(t.TempDir(), "user-agent.sock")
	cli := NewTestClientWithRaw(rawCli, ConnectionConfig{
		Address: "monitor-host.example",
		Options: MustOptions(
			OptionForwardAgent, agentSock,
			OptionSetEnv, "APP_TOKEN=topsecret",
		),
	})
	cli.environment = Environment{
		AgentSocket: agentSock,
		DialAgent: func(context.Context, string) (net.Conn, error) {
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		},
	}

	// 1. RunProbeStream must omit both ForwardAgent and SetEnv/SendEnv.
	probeStream, err := cli.RunProbeStream(t.Context(), "tail -n 10 -f /var/log/syslog")
	if err != nil {
		t.Fatalf("RunProbeStream: %v", err)
	}
	data, err := io.ReadAll(probeStream)
	if err != nil || string(data) != "probe-line-1\n" {
		t.Fatalf("RunProbeStream output = %q (err=%v), want %q", string(data), err, "probe-line-1\n")
	}
	if err := probeStream.Close(); err != nil {
		t.Fatalf("probeStream.Close: %v", err)
	}

	mu.Lock()
	gotProbeAgent := seenAgent
	gotProbeEnvs := append([]string(nil), seenEnvKeys...)
	gotProbeExecs := append([]string(nil), seenExecs...)
	mu.Unlock()
	if gotProbeAgent != 0 || len(gotProbeEnvs) != 0 || len(gotProbeExecs) != 1 {
		t.Fatalf("RunProbeStream leaked credentials/env: agent=%d envs=%v execs=%v", gotProbeAgent, gotProbeEnvs, gotProbeExecs)
	}

	// 2. Contrast: user-facing RunStream still forwards agent and SetEnv.
	resetRecorded()
	userStream, err := cli.RunStream(t.Context(), "echo hi")
	if err != nil {
		t.Fatalf("RunStream: %v", err)
	}
	_, _ = io.ReadAll(userStream)
	_ = userStream.Close()

	mu.Lock()
	gotUserAgent := seenAgent
	gotUserEnvs := append([]string(nil), seenEnvKeys...)
	mu.Unlock()
	if gotUserAgent != 1 || len(gotUserEnvs) != 1 || gotUserEnvs[0] != "APP_TOKEN=topsecret" {
		t.Fatalf("RunStream expected agent=1 and APP_TOKEN=topsecret, got agent=%d envs=%v", gotUserAgent, gotUserEnvs)
	}
}

func pass2Ed25519TestSigner(t *testing.T) cryptoSSH.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer
}

func startPass2InMemorySSHServer(
	t *testing.T,
	onReq func(req *cryptoSSH.Request, ch cryptoSSH.Channel),
) (*cryptoSSH.Client, func()) {
	t.Helper()
	signer := pass2Ed25519TestSigner(t)
	srvCfg := &cryptoSSH.ServerConfig{NoClientAuth: true}
	srvCfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sConn, aErr := ln.Accept()
		if aErr != nil {
			return
		}
		sshSrv, chans, reqs, sErr := cryptoSSH.NewServerConn(sConn, srvCfg)
		if sErr != nil {
			_ = sConn.Close()
			return
		}
		go cryptoSSH.DiscardRequests(reqs)
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported")
				continue
			}
			ch, chReqs, chErr := newCh.Accept()
			if chErr != nil {
				continue
			}
			go func(c cryptoSSH.Channel, rCh <-chan *cryptoSSH.Request) {
				for req := range rCh {
					onReq(req, c)
				}
			}(ch, chReqs)
		}
		_ = sshSrv.Close()
	}()

	cConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("net.DialTimeout: %v", err)
	}
	cliConn, chans, reqs, err := cryptoSSH.NewClientConn(cConn, ln.Addr().String(), &cryptoSSH.ClientConfig{
		User:            "test",
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		_ = cConn.Close()
		_ = ln.Close()
		t.Fatalf("NewClientConn: %v", err)
	}
	rawCli := cryptoSSH.NewClient(cliConn, chans, reqs)
	return rawCli, func() {
		_ = rawCli.Close()
		_ = cConn.Close()
		_ = ln.Close()
		wg.Wait()
	}
}

// TestReviewPass2_L2_EscapeSuspendNonFatalWarningVsFatalRawRestore verifies
// that ~^Z prints a warning to localOut and keeps stdin open on non-fatal
// suspend failures, while still failing closed on fatal raw-mode restore failure.
func TestReviewPass2_L2_EscapeSuspendNonFatalWarningVsFatalRawRestore(t *testing.T) {
	var remoteIn bytes.Buffer
	var localOut bytes.Buffer
	var suspendCalls atomic.Int32

	w := newEscapeFilterWriter(&remoteIn, escapeFilterConfig{
		escapeByte: '~',
		host:       "sandbox-host",
		localOut:   &localOut,
		onSuspend: func() error {
			suspendCalls.Add(1)
			return errors.New("operation not permitted")
		},
	})

	// Send "~^Z" at line start followed by "ls\n": Write must succeed and forward "ls\n"!
	input := []byte{'~', 0x1a, 'l', 's', '\n'}
	n, err := w.Write(input)
	if err != nil || n != len(input) {
		t.Fatalf("escapeFilterWriter.Write on non-fatal suspend failure = (%d, %v), want (%d, nil)", n, err, len(input))
	}
	if suspendCalls.Load() != 1 {
		t.Fatalf("suspendCalls = %d, want 1", suspendCalls.Load())
	}
	if got := remoteIn.String(); got != "ls\n" {
		t.Fatalf("remote stdin received %q, want %q", got, "ls\n")
	}
	if !strings.Contains(localOut.String(), "[suspend failed: operation not permitted]") {
		t.Fatalf("expected [suspend failed: ...] warning in localOut, got %q", localOut.String())
	}

	// Contrast: fatalSuspendTerminalError (when term.MakeRaw fails after resume) MUST return an error.
	fatalErr := errors.New("termios EIO")
	wFatal := newEscapeFilterWriter(&remoteIn, escapeFilterConfig{
		escapeByte: '~',
		host:       "sandbox-host",
		localOut:   &localOut,
		onSuspend: func() error {
			return fatalSuspendTerminalError{err: fatalErr}
		},
	})
	if _, err := wFatal.Write([]byte{'~', 0x1a}); !errors.Is(err, fatalErr) {
		t.Fatalf("expected fatalSuspendTerminalError to surface %v, got %v", fatalErr, err)
	}
}
