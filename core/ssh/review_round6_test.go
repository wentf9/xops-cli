package ssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type round6EOFDrainChannel struct {
	stdout      *io.PipeReader
	stdoutW     *io.PipeWriter
	sendReqErr  error
	sendCalls   atomic.Int32
	closed      atomic.Bool
	closeSignal chan struct{}
	closeOnce   sync.Once
}

func newRound6EOFDrainChannel(sendReqErr error) *round6EOFDrainChannel {
	r, w := io.Pipe()
	return &round6EOFDrainChannel{
		stdout:      r,
		stdoutW:     w,
		sendReqErr:  sendReqErr,
		closeSignal: make(chan struct{}),
	}
}

func (c *round6EOFDrainChannel) Read(p []byte) (int, error)  { return c.stdout.Read(p) }
func (c *round6EOFDrainChannel) Write(p []byte) (int, error) { return len(p), nil }
func (c *round6EOFDrainChannel) CloseWrite() error           { return nil }
func (c *round6EOFDrainChannel) Stderr() io.ReadWriter       { return &bytes.Buffer{} }
func (c *round6EOFDrainChannel) Close() error {
	c.closed.Store(true)
	c.closeOnce.Do(func() {
		close(c.closeSignal)
		_ = c.stdoutW.Close()
	})
	return nil
}
func (c *round6EOFDrainChannel) SendRequest(string, bool, []byte) (bool, error) {
	c.sendCalls.Add(1)
	return false, c.sendReqErr
}

type round6CapturedPackets struct {
	stdout      bytes.Buffer
	exitStatus  bool
	eof         bool
	closed      bool
	reqFailures int
}

func collectRound6ProxyChannelPackets(conn net.Conn) (*round6CapturedPackets, <-chan struct{}) {
	out := &round6CapturedPackets{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			pkt, err := readUnpaddedPacket(conn)
			if err != nil {
				return
			}
			if len(pkt) < 5 {
				continue
			}
			switch pkt[0] {
			case msgChannelData:
				r := newMuxReader(pkt[5:])
				if data, err := r.ReadBytes(); err == nil {
					out.stdout.Write(data)
				}
			case msgChannelRequest:
				r := newMuxReader(pkt[5:])
				if reqType, err := r.ReadString(); err == nil && reqType == "exit-status" {
					out.exitStatus = true
				}
			case msgChannelFailure:
				out.reqFailures++
			case msgChannelEOF:
				out.eof = true
			case msgChannelClose:
				out.closed = true
				return
			}
		}
	}()
	return out, done
}

func TestRound6_P2_1_ProxyChannelRequestEOFDoesNotTruncateDrainingOutputAndExitStatus(t *testing.T) {
	t.Parallel()

	c1, c2 := net.Pipe()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()

	remoteCh := newRound6EOFDrainChannel(io.EOF)
	reqs := make(chan *cryptoSSH.Request, 1)

	ps := &proxySessionState{
		server: &MuxServer{
			requestTimeout: 2 * time.Second,
		},
		conn:     c1,
		closedCh: make(chan struct{}),
	}
	pc := &proxyChan{
		clientCh:          9,
		serverCh:          1,
		remoteCh:          remoteCh,
		clientMaxPacket:   32768,
		clientWindow:      newClientFlowWindow(1 << 20),
		pendingRemoteReqs: newRemoteRequestQueue(),
		input:             newOrderedQueue[proxyChannelInput](),
		requests:          newOrderedQueue[proxyChannelRequest](),
		reqsDone:          make(chan struct{}),
		requestsDone:      make(chan struct{}),
	}
	ps.channels.Store(pc.serverCh, pc)

	captured, readDone := collectRound6ProxyChannelPackets(c2)

	go ps.forwardRequests(pc, reqs)
	go ps.serveChannelRequests(pc)
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		ps.streamChannelData(pc)
	}()

	// Queue a benign client window-change + a subsequent wantReply request while
	// remoteCh.SendRequest returns io.EOF (simulating fast remote exit with buffered output).
	pc.requests.push(proxyChannelRequest{requestType: "window-change", wantReply: false})
	pc.requests.push(proxyChannelRequest{requestType: "signal", wantReply: true})
	pc.requests.push(proxyChannelRequest{requestType: agentForwardRequestType, wantReply: true})

	// Wait briefly until first request hits SendRequest -> io.EOF and latches remoteClosedEOF.
	deadline := time.Now().Add(2 * time.Second)
	for remoteCh.sendCalls.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if remoteCh.sendCalls.Load() != 1 {
		t.Fatalf("remoteCh.SendRequest calls = %d, want exactly 1 (subsequent requests must short-circuit on remoteClosedEOF)", remoteCh.sendCalls.Load())
	}

	// Now drain buffered stdout and exit-status from remote before EOF/close.
	if _, err := remoteCh.stdoutW.Write([]byte("full-output-after-eof")); err != nil {
		t.Fatalf("write remote stdout: %v", err)
	}
	_ = remoteCh.stdoutW.Close()

	exitPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(exitPayload, 0)
	reqs <- &cryptoSSH.Request{Type: "exit-status", WantReply: false, Payload: exitPayload}
	close(reqs)

	select {
	case <-streamDone:
	case <-time.After(3 * time.Second):
		t.Fatal("streamChannelData did not complete draining after remote EOF")
	}
	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("proxy client reader did not receive msgChannelClose")
	}

	if captured.stdout.String() != "full-output-after-eof" {
		t.Fatalf("stdout truncated by premature channel retirement: got %q, want %q", captured.stdout.String(), "full-output-after-eof")
	}
	if !captured.exitStatus || !captured.eof || !captured.closed {
		t.Fatalf("missing terminal frames: exitStatus=%v eof=%v close=%v", captured.exitStatus, captured.eof, captured.closed)
	}
	if captured.reqFailures != 2 {
		t.Fatalf("wantReply failures = %d, want 2", captured.reqFailures)
	}
	if remoteCh.sendCalls.Load() != 1 {
		t.Fatalf("SendRequest called %d times after EOF latch, want 1", remoteCh.sendCalls.Load())
	}
}

type round6SlowCloseChannel struct {
	*round6EOFDrainChannel
	closeEntered chan struct{}
	unblockClose chan struct{}
	enterOnce    sync.Once
}

func (c *round6SlowCloseChannel) Close() error {
	c.enterOnce.Do(func() { close(c.closeEntered) })
	<-c.unblockClose
	return c.round6EOFDrainChannel.Close()
}

func TestRound6_P2_2_HandleCloseSetsCloseSentBeforeRemoteCloseAndDrains(t *testing.T) {
	t.Parallel()

	c1, c2 := net.Pipe()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()

	slowCh := &round6SlowCloseChannel{
		round6EOFDrainChannel: newRound6EOFDrainChannel(io.EOF),
		closeEntered:          make(chan struct{}),
		unblockClose:          make(chan struct{}),
	}
	ps := &proxySessionState{
		server:   &MuxServer{},
		conn:     c1,
		closedCh: make(chan struct{}),
	}
	pc := &proxyChan{
		clientCh:          11,
		serverCh:          2,
		remoteCh:          slowCh,
		clientWindow:      newClientFlowWindow(0),
		pendingRemoteReqs: newRemoteRequestQueue(),
		input:             newOrderedQueue[proxyChannelInput](),
		requests:          newOrderedQueue[proxyChannelRequest](),
		reqsDone:          make(chan struct{}),
		requestsDone:      make(chan struct{}),
	}
	// Pre-populate queued items and start a blocked reserve(1) on pc itself so we
	// verify handleClose genuinely wakes pc.clientWindow and closes pc's queues.
	pc.input.push(proxyChannelInput{kind: msgChannelData, payload: []byte("pending")})
	pc.requests.push(proxyChannelRequest{requestType: "keepalive@test"})
	blockedReserve := make(chan error, 1)
	go func() {
		_, rErr := pc.clientWindow.reserve(1)
		blockedReserve <- rErr
	}()
	ps.channels.Store(pc.serverCh, pc)

	// Drain client side of net.Pipe and record when msgChannelClose arrives.
	gotCloseCh := make(chan struct{})
	go func() {
		for {
			pkt, err := readUnpaddedPacket(c2)
			if err != nil {
				return
			}
			if len(pkt) >= 1 && pkt[0] == msgChannelClose {
				close(gotCloseCh)
				return
			}
		}
	}()

	w := newMuxWriter()
	w.WriteUint32(pc.serverCh)
	handleDone := make(chan struct{})
	go func() {
		defer close(handleDone)
		ps.handleClose(w.Bytes())
	}()

	// msgChannelClose MUST be emitted BEFORE remoteCh.Close() finishes (and closeSent
	// must already reject new writeChannelPacket calls before remoteCh.Close() runs).
	select {
	case <-gotCloseCh:
	case <-time.After(2 * time.Second):
		close(slowCh.unblockClose)
		t.Fatal("handleClose blocked msgChannelClose behind remoteCh.Close()")
	}
	select {
	case <-slowCh.closeEntered:
	case <-time.After(2 * time.Second):
		close(slowCh.unblockClose)
		t.Fatal("handleClose did not invoke remoteCh.Close()")
	}
	if err := ps.writeChannelPacket(pc, []byte{msgChannelData}); !errors.Is(err, io.EOF) {
		close(slowCh.unblockClose)
		t.Fatalf("writeChannelPacket after handleClose closeChannel = %v, want io.EOF", err)
	}

	// Verify window/queues/channel table on pc are retired before remoteCh.Close() finishes.
	assertRound6RetireDrainsQueues(t, ps, pc, slowCh, blockedReserve)

	select {
	case <-handleDone:
	case <-time.After(2 * time.Second):
		close(slowCh.unblockClose)
		t.Fatal("handleClose blocked read loop behind slow remoteCh.Close()")
	}
	close(slowCh.unblockClose)
	ps.closeAll()

	verifyRound6LiveWantReplyDrainOnClose(t)
}

func assertRound6RetireDrainsQueues(
	t *testing.T,
	ps *proxySessionState,
	pc *proxyChan,
	slowCh *round6SlowCloseChannel,
	blockedReserve <-chan error,
) {
	t.Helper()
	select {
	case rErr := <-blockedReserve:
		if !errors.Is(rErr, io.EOF) {
			close(slowCh.unblockClose)
			t.Fatalf("blocked reserve on pc = %v, want io.EOF", rErr)
		}
	case <-time.After(2 * time.Second):
		close(slowCh.unblockClose)
		t.Fatal("blocked reserve on pc did not wake on retireChannel")
	}
	if _, err := pc.clientWindow.reserve(1); !errors.Is(err, io.EOF) {
		close(slowCh.unblockClose)
		t.Fatalf("clientWindow.reserve after retireChannel = %v, want io.EOF", err)
	}
	if item, ok := pc.input.pop(); !ok || string(item.payload) != "pending" {
		close(slowCh.unblockClose)
		t.Fatalf("expected pre-queued pc.input item, got (%v, %v)", item, ok)
	}
	if _, ok := pc.input.pop(); ok {
		close(slowCh.unblockClose)
		t.Fatal("pc.input was not closed on retireChannel")
	}
	if req, ok := pc.requests.pop(); !ok || req.requestType != "keepalive@test" {
		close(slowCh.unblockClose)
		t.Fatalf("expected pre-queued pc.requests item, got (%v, %v)", req, ok)
	}
	if _, ok := pc.requests.pop(); ok {
		close(slowCh.unblockClose)
		t.Fatal("pc.requests was not closed on retireChannel")
	}
	if _, ok := ps.channels.Load(pc.serverCh); ok {
		close(slowCh.unblockClose)
		t.Fatal("ps.channels still holds serverCh after closeChannel")
	}
}

func verifyRound6LiveWantReplyDrainOnClose(t *testing.T) {
	t.Helper()
	// Live MUX_C_PROXY verification: remote sends a WantReply=true channel request
	// and blocks until the proxy client closes the channel without answering.
	liveCtx, liveCancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer liveCancel()
	reqSent := make(chan struct{})
	type probeResult struct {
		accepted bool
		err      error
	}
	reqResult := make(chan probeResult, 1)
	fixture := startMuxFixture(t, liveCtx, sshfixture.Options{
		ExecHandler: func(_ string, ch cryptoSSH.Channel) {
			close(reqSent)
			accepted, err := ch.SendRequest("probe@xops", true, []byte("ping"))
			reqResult <- probeResult{accepted: accepted, err: err}
		},
	})
	rawConn, serverCh, closeRaw := openRawMuxProxyChannel(t, liveCtx, fixture.SocketPath, "exec-probe", 65536, 32768)
	defer closeRaw()

	<-reqSent
	// Wait until the master forwards msgChannelRequest("probe@xops", wantReply=true) onto rawConn,
	// then send msgChannelClose without answering so pendingRemoteReqs must drain it.
	seenProbe := false
	for !seenProbe {
		pkt, pErr := readUnpaddedPacket(rawConn)
		if pErr != nil {
			t.Fatalf("readUnpaddedPacket waiting for probe@xops: %v", pErr)
		}
		if len(pkt) >= 5 && pkt[0] == msgChannelRequest {
			r := newMuxReader(pkt[5:])
			if rType, rErr := r.ReadString(); rErr == nil && rType == "probe@xops" {
				seenProbe = true
			}
		}
	}
	closePkt := newMuxWriter()
	closePkt.buf = append(closePkt.buf, msgChannelClose)
	closePkt.WriteUint32(serverCh)
	if wErr := writeUnpaddedPacket(rawConn, closePkt.Bytes()); wErr != nil {
		t.Fatalf("write msgChannelClose: %v", wErr)
	}
	select {
	case res := <-reqResult:
		if res.err != nil {
			t.Fatalf("expected pending WantReply=true request to receive explicit SSH_MSG_CHANNEL_FAILURE (err==nil) from pendingRemoteReqs.drain(), got err=%v", res.err)
		}
		if res.accepted {
			t.Fatal("expected pending WantReply=true request to be rejected on channel close, got accepted=true")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("remote WantReply=true SendRequest remained blocked after proxy client closed channel")
	}
}

func verifyRound6ProxyJumpTable(t *testing.T) {
	t.Helper()
	for _, tc := range []struct {
		raw      string
		wantKind ProxyJumpKind
		wantNorm string
	}{
		{"", ProxyJumpUnset, ""},
		{"   ", ProxyJumpUnset, ""},
		{",", ProxyJumpDisabled, ""},
		{" , ", ProxyJumpDisabled, ""},
		{"none", ProxyJumpDisabled, ""},
		{"NONE,none", ProxyJumpDisabled, ""},
		{"bastion", ProxyJumpActive, "bastion"},
		{"none,bastion,", ProxyJumpActive, "bastion"},
		{"jump1, none , jump2", ProxyJumpActive, "jump1,jump2"},
	} {
		if got := ClassifyProxyJump(tc.raw); got != tc.wantKind {
			t.Errorf("ClassifyProxyJump(%q) = %v, want %v", tc.raw, got, tc.wantKind)
		}
		if got := NormalizeProxyJump(tc.raw); got != tc.wantNorm {
			t.Errorf("NormalizeProxyJump(%q) = %q, want %q", tc.raw, got, tc.wantNorm)
		}
	}
}

func TestRound6_P2_6_ClassifyNormalizeProxyJumpAndConnectorSingleHop(t *testing.T) {
	t.Parallel()
	verifyRound6ProxyJumpTable(t)

	// Verify resolveConnectionPlan filters "none" and trailing commas on single-hop, multi-hop,
	// and disabled chains and normalizes nodeCfg.ProxyJump for downstream connectPlan & TargetContext.
	store := &multiMockConfigStore{
		configs: map[string]*ClientConfig{
			"target-disabled": {NodeID: "target-disabled", Address: "10.0.0.2", Port: 22, User: "ops", ProxyJump: " , "},
			"target-none":     {NodeID: "target-none", Address: "10.0.0.2", Port: 22, User: "ops", ProxyJump: "none"},
			"target-mixed":    {NodeID: "target-mixed", Address: "10.0.0.2", Port: 22, User: "ops", ProxyJump: "none,bastion,"},
			"target-multi":    {NodeID: "target-multi", Address: "10.0.0.3", Port: 22, User: "ops", ProxyJump: "jump1, none , jump2"},
			"bastion":         {NodeID: "bastion", Address: "10.0.0.1", Port: 22, User: "ops"},
			"jump1":           {NodeID: "jump1", Address: "10.0.0.11", Port: 22, User: "ops"},
			"jump2":           {NodeID: "jump2", Address: "10.0.0.12", Port: 22, User: "ops"},
		},
	}
	conn := NewConnector(store)
	defer closePlanConnector(t, conn)

	for _, id := range []string{"target-disabled", "target-none"} {
		planDisabled, err := conn.resolveConnectionPlan(context.Background(), id)
		if err != nil {
			t.Fatalf("resolveConnectionPlan(%s): %v", id, err)
		}
		if len(planDisabled) != 1 || planDisabled[0].name != id {
			t.Fatalf("planDisabled(%s) = %d nodes, want 1 (direct)", id, len(planDisabled))
		}
		if planDisabled[0].cfg.ProxyJump != "" {
			t.Fatalf("%s normalized ProxyJump = %q, want empty", id, planDisabled[0].cfg.ProxyJump)
		}
		if !planDisabled[0].cfg.HasOriginalProxyJump || planDisabled[0].cfg.OriginalProxyJump != store.configs[id].ProxyJump {
			t.Fatalf("%s OriginalProxyJump = (%q, %v), want (%q, true)", id,
				planDisabled[0].cfg.OriginalProxyJump, planDisabled[0].cfg.HasOriginalProxyJump, store.configs[id].ProxyJump)
		}
	}

	planMixed, err := conn.resolveConnectionPlan(context.Background(), "target-mixed")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(target-mixed): %v", err)
	}
	if len(planMixed) != 2 || planMixed[0].name != "target-mixed" || planMixed[1].name != "bastion" {
		t.Fatalf("planMixed = %+v, want [target-mixed, bastion]", planMixed)
	}
	if planMixed[0].cfg.ProxyJump != "bastion" || planMixed[0].cfg.OriginalProxyJump != "none,bastion," {
		t.Fatalf("planMixed[0] = (ProxyJump=%q Orig=%q), want (bastion, none,bastion,)",
			planMixed[0].cfg.ProxyJump, planMixed[0].cfg.OriginalProxyJump)
	}

	planMulti, err := conn.resolveConnectionPlan(context.Background(), "target-multi")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(target-multi): %v", err)
	}
	if len(planMulti) != 3 || planMulti[0].cfg.ProxyJump != "jump1,jump2" ||
		planMulti[0].cfg.OriginalProxyJump != "jump1, none , jump2" ||
		planMulti[1].cfg.ProxyJump != "jump1" || planMulti[2].cfg.ProxyJump != "" {
		t.Fatalf("planMulti jumps = [(%q,%q), %q, %q]",
			planMulti[0].cfg.ProxyJump, planMulti[0].cfg.OriginalProxyJump,
			planMulti[1].cfg.ProxyJump, planMulti[2].cfg.ProxyJump)
	}

	verifyRound6ConnectorLiveDisabledJump(t)
}

func verifyRound6ConnectorLiveDisabledJump(t *testing.T) {
	t.Helper()
	// Verify real Connector.Connect against sshfixture succeeds when ProxyJump is " , " or "none".
	fixCtx, fixCancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer fixCancel()
	fix, err := sshfixture.New(fixCtx)
	if err != nil {
		t.Fatalf("sshfixture.New: %v", err)
	}
	defer func() { _ = fix.Close() }()
	fixHost, fixPort, err := sshfixtureSplitHostPort(fix.Address)
	if err != nil {
		t.Fatalf("sshfixtureSplitHostPort: %v", err)
	}
	for _, rawJump := range []string{" , ", "none"} {
		liveConn := NewConnector(&multiMockConfigStore{
			configs: map[string]*ClientConfig{
				"live-disabled": {
					NodeID:    "live-disabled",
					Address:   fixHost,
					Port:      fixPort,
					User:      "tester",
					AuthType:  "password",
					Password:  sshfixture.Password,
					ProxyJump: rawJump,
				},
			},
		}, WithHostKeyVerifier(trustAnyFixtureHostKey{}))
		client, connErr := liveConn.Connect(fixCtx, "live-disabled")
		if connErr != nil {
			_ = liveConn.CloseAll()
			t.Fatalf("Connector.Connect(ProxyJump=%q) failed: %v", rawJump, connErr)
		}
		_ = client.Close()
		_ = liveConn.CloseAll()
	}
}

type multiMockConfigStore struct {
	configs map[string]*ClientConfig
}

func (m *multiMockConfigStore) GetConfig(nodeName string) (*ClientConfig, error) {
	cfg, ok := m.configs[nodeName]
	if !ok {
		return nil, io.EOF
	}
	return cfg, nil
}

func TestRound6_P3_1_OptionsValidatorsAndControlPathRejectControlsBeforeTrimSpace(t *testing.T) {
	t.Parallel()

	var opts Options
	for _, tc := range []struct {
		key string
		val string
	}{
		{OptionIdentityAgent, " /tmp/agent.sock\n"},
		{OptionIdentityAgent, "\t/tmp/agent.sock"},
		{OptionForwardAgent, "yes\r"},
		{OptionForwardAgent, "\tyes"},
		{OptionIdentityFile, "\t/tmp/id_ed25519"},
		{OptionIdentityFile, "/tmp/id_ed25519\r\n/tmp/id_rsa"},
		{OptionIdentityFile, "/tmp/id_ed25519\n"},
		{OptionCertificateFile, "\t/tmp/id-cert.pub"},
		{OptionCertificateFile, "\n/tmp/id-cert.pub"},
		{OptionControlPath, "\n/tmp/cm-%C"},
		{OptionControlPath, "/tmp/cm\x00evil"},
	} {
		if err := opts.Set(tc.key, tc.val); err == nil {
			t.Errorf("Options.Set(%q, %q) = nil, want control-char/empty-line error", tc.key, tc.val)
		}
	}
	if err := ValidateControlPathSyntax("/tmp/cm\x00evil"); err == nil {
		t.Error("ValidateControlPathSyntax accepted NUL byte")
	}
	if _, err := ExpandHostName(" %h.example.com\n", "app"); err == nil {
		t.Error("ExpandHostName accepted trailing LF in pattern")
	}
	if _, err := ExpandHostName("%h.example.com", "\tapp"); err == nil {
		t.Error("ExpandHostName accepted leading tab in originalHost")
	}

	// Valid multiline IdentityFile / CertificateFile and ASCII space padding remain accepted.
	if err := opts.Set(OptionIdentityFile, " /tmp/id_1 \n /tmp/id_2 "); err != nil {
		t.Fatalf("valid multiline IdentityFile rejected: %v", err)
	}
	if err := opts.Set(OptionCertificateFile, "/tmp/c1.pub\n/tmp/c2.pub"); err != nil {
		t.Fatalf("valid multiline CertificateFile rejected: %v", err)
	}
	if got, err := ExpandHostName(" %h.example.com ", " app "); err != nil || got != "app.example.com" {
		t.Fatalf("ExpandHostName(spaces) = (%q, %v), want (app.example.com, nil)", got, err)
	}

	// P3-6 additional coverage: env.AgentSocket and $VAR with trailing control char.
	envWithBadSock := Environment{
		AgentSocket: "/tmp/env.sock\n",
		LookupEnv: func(k string) (string, bool) {
			if k == "BAD_AGENT" {
				return "/tmp/var.sock\t", true
			}
			return "", false
		},
	}
	if _, _, err := ResolveIdentityAgent("SSH_AUTH_SOCK", envWithBadSock, TargetContext{}); err == nil {
		t.Error("ResolveIdentityAgent(SSH_AUTH_SOCK) accepted env.AgentSocket with trailing LF")
	}
	if _, err := expandAgentSocketPath("$BAD_AGENT", envWithBadSock, TargetContext{}, "IdentityAgent"); err == nil {
		t.Error("expandAgentSocketPath($BAD_AGENT) accepted expanded value with trailing tab")
	}
	if _, err := expandAgentSocketPath(" \t/tmp/clean ", envWithBadSock, TargetContext{}, "IdentityAgent"); err == nil {
		t.Error("expandAgentSocketPath accepted isolated leading tab")
	}
}

func TestRound6_P3_2_DialControlProxyClientBackfillsPartialConfig(t *testing.T) {
	t.Parallel()

	// Verify the backfill logic on partial non-nil ClientConfig by exercising DialControlProxyClient
	// against an in-process MuxServer proxy target.
	raw := newDummySSHClient()
	defer func() { _ = raw.Close() }()

	sock := shortMuxSocketTempDir(t) + "/mux.sock"
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath: sock,
		SSHClient:   raw,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.Serve() }()
	defer func() {
		_ = srv.Shutdown()
		<-srvDone
	}()

	partialCfg := &ClientConfig{
		Port: 2222,
		User: "ops",
	}
	target := TargetContext{
		Host:          "10.0.0.5",
		Port:          2222,
		User:          "ops",
		OriginalHost:  "short",
		CanonicalHost: "short.corp.example.com",
	}
	client, err := DialControlProxyClient(context.Background(), sock, target, Environment{}, partialCfg, nil)
	if err != nil {
		t.Fatalf("DialControlProxyClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	gotCfg := client.Config()
	if gotCfg.Address != "10.0.0.5" || gotCfg.OriginalHost != "short" || gotCfg.CanonicalHost != "short.corp.example.com" {
		t.Fatalf("backfilled config = (addr=%q orig=%q canon=%q), want (10.0.0.5, short, short.corp.example.com)",
			gotCfg.Address, gotCfg.OriginalHost, gotCfg.CanonicalHost)
	}
	// Caller's partialCfg must not have been mutated in place.
	if partialCfg.Address != "" || partialCfg.OriginalHost != "" || partialCfg.CanonicalHost != "" {
		t.Fatalf("DialControlProxyClient mutated caller's ClientConfig: %+v", partialCfg)
	}
}
