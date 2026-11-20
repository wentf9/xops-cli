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
		clientWindow:      newClientFlowWindow(1 << 20),
		pendingRemoteReqs: newRemoteRequestQueue(),
		input:             newOrderedQueue[proxyChannelInput](),
		requests:          newOrderedQueue[proxyChannelRequest](),
		reqsDone:          make(chan struct{}),
		requestsDone:      make(chan struct{}),
	}
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
	close(slowCh.unblockClose)
	select {
	case <-handleDone:
	case <-time.After(2 * time.Second):
		t.Fatal("handleClose did not exit after remoteCh.Close() unblocked")
	}
}

func TestRound6_P2_6_ClassifyNormalizeProxyJumpAndConnectorSingleHop(t *testing.T) {
	t.Parallel()

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

	// Verify resolveConnectionPlan filters "none" and trailing commas on single-hop and disabled chains.
	store := &multiMockConfigStore{
		configs: map[string]*ClientConfig{
			"target-disabled": {NodeID: "target-disabled", Address: "10.0.0.2", Port: 22, User: "ops", ProxyJump: " , "},
			"target-mixed":    {NodeID: "target-mixed", Address: "10.0.0.2", Port: 22, User: "ops", ProxyJump: "none,bastion,"},
			"bastion":         {NodeID: "bastion", Address: "10.0.0.1", Port: 22, User: "ops"},
		},
	}
	conn := NewConnector(store)
	defer closePlanConnector(t, conn)

	planDisabled, err := conn.resolveConnectionPlan(context.Background(), "target-disabled")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(target-disabled): %v", err)
	}
	if len(planDisabled) != 1 || planDisabled[0].name != "target-disabled" {
		t.Fatalf("planDisabled = %d nodes, want 1 (direct)", len(planDisabled))
	}

	planMixed, err := conn.resolveConnectionPlan(context.Background(), "target-mixed")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(target-mixed): %v", err)
	}
	if len(planMixed) != 2 || planMixed[0].name != "target-mixed" || planMixed[1].name != "bastion" {
		t.Fatalf("planMixed = %+v, want [target-mixed, bastion]", planMixed)
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
