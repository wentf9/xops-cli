package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

type captureDebugLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *captureDebugLogger) Debug(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, fmt.Sprint(append([]any{msg}, args...)...))
}

func (l *captureDebugLogger) Debugf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, fmt.Sprintf(format, args...))
}

func (l *captureDebugLogger) contains(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, m := range l.msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

func hasIPv6Loopback() bool {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

// TestReviewSess_M3_AddressFamilyDefaultLoopbackForwarding verifies default-bind
// loopback selection for tcp6 ([::1]), tcp4 (127.0.0.1), and tcp (127.0.0.1)
// across LocalListenAddressWithNetwork, formatSpecBindAddrForNetwork, -L, -D,
// and MuxServer.resolveMuxForwardListen.
func TestReviewSess_M3_AddressFamilyDefaultLoopbackForwarding(t *testing.T) {
	ep := ForwardEndpoint{Port: 8080}

	cases := []struct {
		netw     string
		wantNet  string
		wantAddr string
		wantHost string
	}{
		{netw: "tcp6", wantNet: "tcp6", wantAddr: "[::1]:8080", wantHost: "::1"},
		{netw: "tcp4", wantNet: "tcp4", wantAddr: "127.0.0.1:8080", wantHost: "127.0.0.1"},
		{netw: "tcp", wantNet: "tcp", wantAddr: "127.0.0.1:8080", wantHost: "127.0.0.1"},
	}
	for _, tc := range cases {
		gotNet, gotAddr := ep.LocalListenAddressWithNetwork(false, tc.netw)
		if gotNet != tc.wantNet || gotAddr != tc.wantAddr {
			t.Fatalf("LocalListenAddressWithNetwork(false, %q) = (%q, %q), want (%q, %q)",
				tc.netw, gotNet, gotAddr, tc.wantNet, tc.wantAddr)
		}
		if gotSpec := formatSpecBindAddrForNetwork(ep, tc.netw); gotSpec != tc.wantAddr {
			t.Fatalf("formatSpecBindAddrForNetwork(%q) = %q, want %q", tc.netw, gotSpec, tc.wantAddr)
		}
		for _, fwdType := range []uint32{MUX_FWD_LOCAL, MUX_FWD_DYNAMIC} {
			ms := &MuxServer{dialNetwork: tc.netw}
			mNet, mAddr, keyHost, err := ms.resolveMuxForwardListen(fwdType, "", 8080)
			if err != nil || mNet != tc.wantNet || mAddr != tc.wantAddr || keyHost != tc.wantHost {
				t.Fatalf("resolveMuxForwardListen(type=%d, net=%q) = (%q, %q, %q, %v), want (%q, %q, %q, nil)",
					fwdType, tc.netw, mNet, mAddr, keyHost, err, tc.wantNet, tc.wantAddr, tc.wantHost)
			}
		}
	}

	if !hasIPv6Loopback() {
		t.Skip("IPv6 loopback [::1] unavailable in this test environment")
	}

	opts := &Options{}
	if err := opts.Set(OptionAddressFamily, "inet6"); err != nil {
		t.Fatalf("Set(AddressFamily, inet6): %v", err)
	}
	cli := NewTestClient(ConnectionConfig{Options: opts})
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	rawCli := cryptoSSH.NewClient(&dummyMuxGateConn{}, chans, reqs)
	defer func() {
		close(chans)
		close(reqs)
		_ = rawCli.Close()
	}()
	cli.sshClient = rawCli

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// -6 -L default bind (no host) must listen on [::1]:port without error.
	localFwd, err := cli.LocalForwardEndpoint(
		ctx,
		ForwardEndpoint{Port: 0},
		ForwardEndpoint{HasHost: true, Host: "::1", Port: 22},
		false,
	)
	if err != nil {
		t.Fatalf("LocalForwardEndpoint under AddressFamily=inet6 failed: %v", err)
	}
	if !strings.HasPrefix(localFwd.Addr().String(), "[::1]:") {
		t.Fatalf("LocalForwardEndpoint(-6) Addr = %q, want [::1]:port", localFwd.Addr().String())
	}

	// -6 -D default bind (no host) must listen on [::1]:port without error.
	dynFwd, err := cli.DynamicForwardEndpoint(ctx, ForwardEndpoint{Port: 0}, false)
	if err != nil {
		t.Fatalf("DynamicForwardEndpoint under AddressFamily=inet6 failed: %v", err)
	}
	if !strings.HasPrefix(dynFwd.Addr().String(), "[::1]:") {
		t.Fatalf("DynamicForwardEndpoint(-6) Addr = %q, want [::1]:port", dynFwd.Addr().String())
	}
}

// TestReviewSess_M5_L4_AgentRouterConflictAndMuxProxyGate verifies:
//   - identical local socket paths share a connection router cleanly;
//   - empty socket paths and conflicting local/master socket paths are rejected with debug logs;
//   - MUX_C_PROXY with wantReply=false never attaches a lease when master AllowAgentForward=false.
func TestReviewSess_M5_L4_AgentRouterConflictAndMuxProxyGate(t *testing.T) {
	log := &captureDebugLogger{}
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
	dialStub := func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("unused")
	}

	// 0. Empty socket path MUST be rejected rather than acting as a wildcard!
	if emptyLease, err := router.acquireLocalLease(t.Context(), "", dialStub, log); !errors.Is(err, errEmptyAgentSocket) || emptyLease != nil {
		t.Fatalf("expected empty local socket lease to fail with errEmptyAgentSocket, got lease=%v err=%v", emptyLease, err)
	}

	// 1. Two local leases for the identical socket path may share.
	l1, err := router.acquireLocalLease(t.Context(), "/tmp/agent-a.sock", dialStub, log)
	if err != nil || l1 == nil {
		t.Fatalf("first local lease failed: %v", err)
	}
	l2, err := router.acquireLocalLease(t.Context(), "/tmp/agent-a.sock", dialStub, log)
	if err != nil || l2 == nil {
		t.Fatalf("second identical local lease should share, got err=%v", err)
	}

	// 2. Different local socket path while l1/l2 active MUST be rejected!
	if badLocal, err := router.acquireLocalLease(t.Context(), "/tmp/agent-b.sock", dialStub, log); !errors.Is(err, errAgentLeaseConflict) || badLocal != nil {
		t.Fatalf("expected conflicting local socket lease to be rejected, got lease=%v err=%v", badLocal, err)
	}
	if !log.contains("rejecting conflicting local agent lease") {
		t.Fatalf("expected debug log for conflicting local lease, got %v", log.msgs)
	}

	// 3. MUX_C_PROXY channel lease on a Master with a different socket while l1/l2 active MUST be rejected!
	srvB := &MuxServer{
		sshClient:         rawCli,
		allowAgentForward: true,
		agentSocket:       "/tmp/agent-b.sock",
		dialAgent:         dialStub,
		logger:            log,
	}
	ps1 := &proxySessionState{server: srvB}
	if badProxy, ok := ps1.acquireChannelAgentLease(); ok || badProxy != nil {
		t.Fatal("expected MUX_C_PROXY lease with conflicting master socket to be rejected")
	}

	// 4. Once l1/l2 release, MUX_C_PROXY channels on srvB share Master's local socket lease,
	// while a conflicting socket (/tmp/agent-a.sock) is rejected.
	l1.Release()
	l2.Release()

	pLease1, ok := ps1.acquireChannelAgentLease()
	if !ok || pLease1 == nil {
		t.Fatal("MUX_C_PROXY lease after local release failed")
	}
	ps2 := &proxySessionState{server: srvB}
	pLease2, ok := ps2.acquireChannelAgentLease()
	if !ok || pLease2 == nil {
		t.Fatal("second MUX_C_PROXY session on same master should share master socket lease")
	}
	if badLocal2, err := router.acquireLocalLease(t.Context(), "/tmp/agent-a.sock", dialStub, log); !errors.Is(err, errAgentLeaseConflict) || badLocal2 != nil {
		t.Fatal("expected conflicting local lease to be rejected while master proxy lease is active")
	}
	pLease1.Release()
	pLease2.Release()

	assertMuxProxyAgentGateWhenDisabled(t)
}

func assertMuxProxyAgentGateWhenDisabled(t *testing.T) {
	t.Helper()
	// L4: MUX_C_PROXY serveChannelRequests with AllowAgentForward=false and wantReply=false
	// must NOT forward auth-agent-req@openssh.com and must NOT attach any proxy lease!
	chans := make(chan cryptoSSH.NewChannel)
	close(chans)
	reqs := make(chan *cryptoSSH.Request)
	close(reqs)
	dummyCli := cryptoSSH.NewClient(&dummyMuxGateConn{}, chans, reqs)
	defer func() { _ = dummyCli.Close() }()

	srvLog := &captureDebugLogger{}
	srv := &MuxServer{
		sshClient:         dummyCli,
		allowAgentForward: false,
		logger:            srvLog,
	}
	recRemote := &recordingRemoteChannel{}
	psGate := &proxySessionState{server: srv}
	pc := &proxyChan{
		remoteCh:     recRemote,
		clientCh:     7,
		requests:     newOrderedQueue[proxyChannelRequest](),
		requestsDone: make(chan struct{}),
	}
	pc.requests.push(proxyChannelRequest{
		requestType: agentForwardRequestType,
		wantReply:   false,
	})
	pc.requests.close()
	psGate.serveChannelRequests(pc)

	if recRemote.calls.Load() != 0 {
		t.Fatalf("expected 0 remote SendRequest calls when AllowAgentForward=false, got %d", recRemote.calls.Load())
	}
	if pc.agentProxyLease != nil {
		t.Fatal("expected no proxy agent lease attached on !wantReply when AllowAgentForward=false")
	}
	if !srvLog.contains("AllowAgentForward is disabled") {
		t.Fatalf("expected debug log when MUX_C_PROXY agent request gated, got %v", srvLog.msgs)
	}
}

type dummyMuxGateConn struct {
	mu       sync.Mutex
	closed   bool
	closedCh chan struct{}
}

func (*dummyMuxGateConn) User() string          { return "u" }
func (*dummyMuxGateConn) SessionID() []byte     { return []byte("s") }
func (*dummyMuxGateConn) ClientVersion() []byte { return []byte("SSH-2.0-c") }
func (*dummyMuxGateConn) ServerVersion() []byte { return []byte("SSH-2.0-s") }
func (*dummyMuxGateConn) RemoteAddr() net.Addr  { return &net.TCPAddr{} }
func (*dummyMuxGateConn) LocalAddr() net.Addr   { return &net.TCPAddr{} }
func (*dummyMuxGateConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	return false, nil, nil
}
func (*dummyMuxGateConn) OpenChannel(string, []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	return nil, nil, errors.New("closed")
}
func (d *dummyMuxGateConn) closedChan() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closedCh == nil {
		d.closedCh = make(chan struct{})
	}
	return d.closedCh
}
func (d *dummyMuxGateConn) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		if d.closedCh == nil {
			d.closedCh = make(chan struct{})
		}
		close(d.closedCh)
	}
	return nil
}
func (d *dummyMuxGateConn) Wait() error {
	<-d.closedChan()
	return nil
}

type recordingRemoteChannel struct {
	calls atomic.Int32
}

func (r *recordingRemoteChannel) Read([]byte) (int, error)    { return 0, io.EOF }
func (r *recordingRemoteChannel) Write(b []byte) (int, error) { return len(b), nil }
func (r *recordingRemoteChannel) Close() error                { return nil }
func (r *recordingRemoteChannel) CloseWrite() error           { return nil }
func (r *recordingRemoteChannel) Stderr() io.ReadWriter       { return r }
func (r *recordingRemoteChannel) SendRequest(string, bool, []byte) (bool, error) {
	r.calls.Add(1)
	return true, nil
}

// TestReviewSess_M6_M7_L5_EnvDenylistAndCaps verifies:
//   - isDeniedSendEnvName table coverage (LD_* prefix, cloud/SCM/package tokens, case-insensitivity);
//   - SendEnv host vars exceeding 128 or 32KiB log Debugf and skip without error;
//   - explicit SetEnv exceeding 128 or 32KiB returns ErrSSHOptionsValidation;
//   - SetEnv dropped by denylist logs Debugf.
func TestReviewSess_M6_M7_L5_EnvDenylistAndCaps(t *testing.T) {
	table := []struct {
		name   string
		denied bool
	}{
		{"LD_PRELOAD", true},
		{"LD_LIBRARY_PATH", true},
		{"LD_AUDIT", true},
		{"ld_debug", true},
		{"LD_DYNAMIC_WEAK", true},
		{"DYLD_INSERT_LIBRARIES", true},
		{"AWS_SESSION_TOKEN", true},
		{"aws_session_token", true},
		{"AWS_ACCESS_KEY_ID", true},
		{"AWS_SECRET_ACCESS_KEY", true},
		{"GITHUB_TOKEN", true},
		{"GH_TOKEN", true},
		{"gh_token", true},
		{"GITLAB_TOKEN", true},
		{"VAULT_TOKEN", true},
		{"NPM_TOKEN", true},
		{"SSH_AUTH_SOCK", true},
		{"SSH_AGENT_PID", true},
		{"SSH_ASKPASS_REQUIRE", true},
		{"KRB5CCNAME", true},
		{"XOPS_MASTER_KEY", true},
		// Safe names must remain allowed:
		{"LANG", false},
		{"LC_ALL", false},
		{"PATH", false},
		{"LDFLAGS", false},
		{"AWS_DEFAULT_REGION", false},
		{"NPM_CONFIG_REGISTRY", false},
	}
	for _, tc := range table {
		if got := isDeniedSendEnvName(tc.name); got != tc.denied {
			t.Fatalf("isDeniedSendEnvName(%q) = %v, want %v", tc.name, got, tc.denied)
		}
	}

	log := &captureDebugLogger{}
	opts := &Options{}
	if err := opts.Append(OptionSendEnv, "*"); err != nil {
		t.Fatal(err)
	}
	if err := opts.Append(OptionSetEnv, "LD_AUDIT=/bad.so GH_TOKEN=secret EXPLICIT_KEEP=yes"); err != nil {
		t.Fatal(err)
	}

	hugeVal := strings.Repeat("x", MaxSessionEnvEntryBytes)
	hostVars := []string{"HUGE_HOST=" + hugeVal}
	for i := range MaxSessionEnvVars + 10 {
		hostVars = append(hostVars, fmt.Sprintf("HOST_%03d=v%d", i, i))
	}

	resolved, err := resolveSessionEnvWithLogger(opts, func() []string { return hostVars }, log)
	if err != nil {
		t.Fatalf("resolveSessionEnvWithLogger with SendEnv overflow failed: %v", err)
	}
	if len(resolved) != MaxSessionEnvVars {
		t.Fatalf("len(resolved) = %d, want %d", len(resolved), MaxSessionEnvVars)
	}
	foundExplicit := false
	for _, ev := range resolved {
		if ev.Name == "EXPLICIT_KEEP" && ev.Value == "yes" {
			foundExplicit = true
		}
		if ev.Name == "LD_AUDIT" || ev.Name == "GH_TOKEN" || ev.Name == "HUGE_HOST" {
			t.Fatalf("unexpected variable %q present in resolved env", ev.Name)
		}
	}
	if !foundExplicit {
		t.Fatal("expected EXPLICIT_KEEP=yes to survive SendEnv host overflow")
	}
	if !log.contains(`SetEnv "LD_AUDIT" blocked by denylist`) || !log.contains(`SetEnv "GH_TOKEN" blocked by denylist`) {
		t.Fatalf("expected Debugf for SetEnv denylist drops, got %v", log.msgs)
	}
	if !log.contains(`SendEnv: skipping host variable "HUGE_HOST"`) {
		t.Fatalf("expected Debugf for >32KiB SendEnv skip, got %v", log.msgs)
	}
	if !log.contains("session limit of 128 variables reached") {
		t.Fatalf("expected Debugf for >128 SendEnv skip, got %v", log.msgs)
	}

	// Explicit SetEnv >32KiB still fails closed at option validation / parse time.
	badSetOpts := &Options{}
	if err := badSetOpts.Append(OptionSetEnv, "BIG="+hugeVal); !errors.Is(err, ErrSSHOptionsValidation) {
		t.Fatalf("expected explicit SetEnv >32KiB to fail with ErrSSHOptionsValidation, got %v", err)
	}
}

// noHalfCloseAgentConn simulates a third-party/GUI ssh-agent whose CloseWrite is
// a no-op (ignoring client half-close) and that stays blocked in Read until a full Close.
type noHalfCloseAgentConn struct {
	net.Conn
}

func (c *noHalfCloseAgentConn) CloseWrite() error {
	return nil
}

// TestReviewSess_L1_L2_AgentHalfCloseNonCloseWriteAndConcurrentDrain verifies:
//   - L1a: an agent ignoring CloseWrite() exits promptly when the remote SSH channel closes (reqs closes);
//   - L1b: a non-CloseWrite conn (net.Pipe) preserves in-flight agent replies after remote half-close;
//   - L2: Client.Close() drains multiple stuck leases concurrently within a single 1s deadline.
func TestReviewSess_L1_L2_AgentHalfCloseNonCloseWriteAndConcurrentDrain(t *testing.T) {
	// L1a: Agent ignores CloseWrite; remote reads reply and sends full SSH channel close.
	var closedAgentConns atomic.Int32
	router := &sshAgentChannelRouter{}
	lease, err := router.acquireLocalLease(t.Context(), "stub-ignore-halfclose", func(context.Context, string) (net.Conn, error) {
		clientEnd, serverEnd := net.Pipe()
		go func() {
			defer closedAgentConns.Add(1)
			defer func() { _ = serverEnd.Close() }()
			buf := make([]byte, 4)
			if _, rErr := io.ReadFull(serverEnd, buf); rErr != nil {
				return
			}
			_, _ = serverEnd.Write([]byte("PONG"))
			// Keep connection open forever until clientEnd.Close()!
			_, _ = io.Copy(io.Discard, serverEnd)
		}()
		return &noHalfCloseAgentConn{Conn: clientEnd}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()

	if !router.tryAcquireChannelSlot() {
		t.Fatal("tryAcquireChannelSlot failed")
	}
	if !lease.tryBeginPump() {
		t.Fatal("tryBeginPump failed")
	}
	fakeNewCh, peerSSHCh, closeRemoteReqs := newFakeAgentNewChannel()
	pumpDone := make(chan struct{})
	go func() {
		defer lease.pumps.Done()
		defer close(pumpDone)
		router.serveLocalAgentChannel(lease, fakeNewCh)
	}()

	if _, err := peerSSHCh.Write([]byte("PING")); err != nil {
		t.Fatalf("write to ssh channel: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(peerSSHCh, reply); err != nil || string(reply) != "PONG" {
		t.Fatalf("read reply = %q, err = %v", string(reply), err)
	}
	// Remote closes the SSH channel completely (closing reqs and peerSSHCh).
	_ = peerSSHCh.Close()
	closeRemoteReqs()

	select {
	case <-pumpDone:
	case <-time.After(time.Second):
		t.Fatal("serveLocalAgentChannel hung when local agent ignored half-close")
	}
	if got := router.activeChannels.Load(); got != 0 {
		t.Fatalf("activeChannels = %d, want 0", got)
	}
	lease.Release()

	// L1b: Non-CloseWrite conn (plain net.Pipe has no CloseWrite) where remote half-closes
	// immediately after writing request, and agent replies 30ms later.
	leasePipe, err := router.acquireLocalLease(t.Context(), "stub-pipe", func(context.Context, string) (net.Conn, error) {
		clientEnd, serverEnd := net.Pipe()
		go func() {
			defer func() { _ = serverEnd.Close() }()
			req, _ := io.ReadAll(io.LimitReader(serverEnd, 4))
			time.Sleep(30 * time.Millisecond)
			_, _ = serverEnd.Write(append([]byte("OK:"), req...))
		}()
		return clientEnd, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer leasePipe.Release()

	if !router.tryAcquireChannelSlot() || !leasePipe.tryBeginPump() {
		t.Fatal("failed to start second pump")
	}
	fakeNewCh2, peerSSHCh2, closeRemoteReqs2 := newFakeAgentNewChannel()
	pumpDone2 := make(chan struct{})
	go func() {
		defer leasePipe.pumps.Done()
		defer close(pumpDone2)
		router.serveLocalAgentChannel(leasePipe, fakeNewCh2)
	}()

	_, _ = peerSSHCh2.Write([]byte("DATA"))
	peerSSHCh2.halfCloseClientToAgent()
	gotReply, err := io.ReadAll(peerSSHCh2)
	closeRemoteReqs2()
	_ = peerSSHCh2.Close()
	<-pumpDone2
	if err != nil || string(gotReply) != "OK:DATA" {
		t.Fatalf("non-CloseWrite agent reply = %q (err=%v), want %q", string(gotReply), err, "OK:DATA")
	}

	// L2: 4 leases with stuck pumps must drain concurrently in ~1s total, not 4s.
	cli := NewTestClient(ConnectionConfig{})
	stuckBlock := make(chan struct{})
	defer close(stuckBlock)
	for range 4 {
		l := &agentForwardLease{}
		l.pumps.Add(1)
		go func(lf *agentForwardLease) {
			<-stuckBlock
			lf.pumps.Done()
		}(l)
		cli.trackAgentLease(l)
	}
	start := time.Now()
	if err := cli.Close(); err != nil {
		t.Fatalf("Client.Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 1700*time.Millisecond {
		t.Fatalf("Client.Close with 4 stuck leases took %s, want concurrent ~1s shared deadline", elapsed)
	}
}

type fakeBidirectionalSSHChannel struct {
	r         io.ReadCloser
	w         io.WriteCloser
	closeOnce sync.Once
}

func (f *fakeBidirectionalSSHChannel) Read(p []byte) (int, error)  { return f.r.Read(p) }
func (f *fakeBidirectionalSSHChannel) Write(p []byte) (int, error) { return f.w.Write(p) }
func (f *fakeBidirectionalSSHChannel) CloseWrite() error           { return f.w.Close() }
func (f *fakeBidirectionalSSHChannel) Stderr() io.ReadWriter       { return &nopRW{} }
func (f *fakeBidirectionalSSHChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}
func (f *fakeBidirectionalSSHChannel) Close() error {
	f.closeOnce.Do(func() {
		_ = f.r.Close()
		_ = f.w.Close()
	})
	return nil
}
func (f *fakeBidirectionalSSHChannel) halfCloseClientToAgent() {
	_ = f.w.Close()
}

type fakeNewAgentChannel struct {
	ch   cryptoSSH.Channel
	reqs <-chan *cryptoSSH.Request
}

func (n *fakeNewAgentChannel) Accept() (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	return n.ch, n.reqs, nil
}
func (n *fakeNewAgentChannel) Reject(cryptoSSH.RejectionReason, string) error { return nil }
func (n *fakeNewAgentChannel) ChannelType() string                            { return agentForwardChannelType }
func (n *fakeNewAgentChannel) ExtraData() []byte                              { return nil }

func newFakeAgentNewChannel() (cryptoSSH.NewChannel, *fakeBidirectionalSSHChannel, func()) {
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	localSSHCh := &fakeBidirectionalSSHChannel{r: c2sR, w: s2cW}
	peerSSHCh := &fakeBidirectionalSSHChannel{r: s2cR, w: c2sW}
	reqs := make(chan *cryptoSSH.Request)
	var once sync.Once
	closeReqs := func() { once.Do(func() { close(reqs) }) }
	return &fakeNewAgentChannel{ch: localSSHCh, reqs: reqs}, peerSSHCh, closeReqs
}

// TestReviewSess_L6_RunProbeWithoutLoginSkipsEnvAndAgent verifies that
// (*Client).RunProbeWithoutLogin never sends auth-agent-req@openssh.com or
// SendEnv/SetEnv requests even when both are enabled in ConnectionConfig.Options.
func TestReviewSess_L6_RunProbeWithoutLoginSkipsEnvAndAgent(t *testing.T) {
	rec := &probeCheckSSHConn{}
	chans := make(chan cryptoSSH.NewChannel)
	close(chans)
	reqs := make(chan *cryptoSSH.Request)
	close(reqs)
	rawCli := cryptoSSH.NewClient(rec, chans, reqs)
	defer func() { _ = rawCli.Close() }()

	opts := &Options{}
	_ = opts.Set(OptionForwardAgent, "yes")
	_ = opts.Set(OptionIdentityAgent, "/tmp/fake-agent.sock")
	_ = opts.Append(OptionSetEnv, "APP_ENV=prod")

	cli := NewTestClientWithRaw(rawCli, ConnectionConfig{
		Address: "127.0.0.1",
		Port:    22,
		User:    "root",
		Options: opts,
	})
	cli.environment = Environment{
		DialAgent: func(context.Context, string) (net.Conn, error) {
			t.Error("RunProbeWithoutLogin must not dial ssh-agent")
			return nil, errors.New("unexpected agent dial")
		},
	}

	out, err := cli.RunProbeWithoutLogin(t.Context(), "uname -s")
	if err != nil {
		t.Fatalf("RunProbeWithoutLogin failed: %v", err)
	}
	if strings.TrimSpace(out) != "Linux" {
		t.Fatalf("RunProbeWithoutLogin output = %q, want Linux", out)
	}
	rec.mu.Lock()
	gotReqs := append([]string(nil), rec.reqTypes...)
	rec.mu.Unlock()
	for _, rt := range gotReqs {
		if rt == "env" || rt == agentForwardRequestType {
			t.Fatalf("RunProbeWithoutLogin unexpectedly sent session request %q (all=%v)", rt, gotReqs)
		}
	}
}

type probeCheckSSHConn struct {
	dummyMuxGateConn
	mu       sync.Mutex
	reqTypes []string
}

func (p *probeCheckSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if name != "session" {
		return nil, nil, errors.New("unsupported channel")
	}
	outR, outW := io.Pipe()
	reqs := make(chan *cryptoSSH.Request, 1)
	return &probeCheckChannel{parent: p, outR: outR, outW: outW, reqs: reqs}, reqs, nil
}

type probeCheckChannel struct {
	parent *probeCheckSSHConn
	outR   *io.PipeReader
	outW   *io.PipeWriter
	reqs   chan *cryptoSSH.Request
}

func (c *probeCheckChannel) Read(b []byte) (int, error)  { return c.outR.Read(b) }
func (c *probeCheckChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *probeCheckChannel) Close() error                { _ = c.outW.Close(); _ = c.outR.Close(); return nil }
func (c *probeCheckChannel) CloseWrite() error           { return nil }
func (c *probeCheckChannel) Stderr() io.ReadWriter       { return io.ReadWriter(&nopRW{}) }
func (c *probeCheckChannel) SendRequest(name string, _ bool, _ []byte) (bool, error) {
	c.parent.mu.Lock()
	c.parent.reqTypes = append(c.parent.reqTypes, name)
	c.parent.mu.Unlock()
	if name == "exec" {
		go func() {
			_, _ = c.outW.Write([]byte("Linux\n"))
			_ = c.outW.Close()
			c.reqs <- &cryptoSSH.Request{
				Type:    "exit-status",
				Payload: cryptoSSH.Marshal(struct{ Status uint32 }{0}),
			}
			close(c.reqs)
		}()
	}
	return true, nil
}

type nopRW struct{}

func (*nopRW) Read([]byte) (int, error)    { return 0, io.EOF }
func (*nopRW) Write(b []byte) (int, error) { return len(b), nil }

// TestReviewSess_L7_ErrEscapeDisconnectSentinel verifies ErrEscapeDisconnect
// exposes ExitCode() == 255 and AlreadyReported() == true both standalone and joined.
func TestReviewSess_L7_ErrEscapeDisconnectSentinel(t *testing.T) {
	type exitCoder interface{ ExitCode() int }
	type reportedErr interface{ AlreadyReported() bool }

	joined := errors.Join(ErrEscapeDisconnect, errors.New("close warning"))
	for _, candidate := range []error{ErrEscapeDisconnect, joined} {
		if !errors.Is(candidate, ErrEscapeDisconnect) {
			t.Fatalf("errors.Is(%v, ErrEscapeDisconnect) = false", candidate)
		}
		var ec exitCoder
		if !errors.As(candidate, &ec) || ec.ExitCode() != 255 {
			t.Fatalf("ExitCode from %v = (%v, %v), want 255", candidate, ec != nil, ec)
		}
		var rep reportedErr
		if !errors.As(candidate, &rep) || !rep.AlreadyReported() {
			t.Fatalf("AlreadyReported from %v = false, want true", candidate)
		}
	}
}
