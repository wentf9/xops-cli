package ssh

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestRound8_P1_1_AlgorithmScalarControlAndRebuiltOutput(t *testing.T) {
	t.Parallel()

	for _, opt := range []string{OptionCiphers, OptionMACs, OptionKexAlgorithms, OptionHostKeyAlgorithms} {
		for _, bad := range []string{
			"-aes128-ctr\x1b[31m",
			"-aes128-ctr\x00evil",
			"-aes128-ctr\nevil",
			"-aes128-ctr\revil",
			"-aes128-ctr\u0085",
			"-aes128-ctr\u2028",
			"-aes128-ctr\u2029",
			"-bad algo with spaces",
			"-bad;rm",
			"\t-aes128-ctr",
		} {
			o := &Options{}
			if err := o.Set(opt, bad); err == nil {
				t.Fatalf("Options.Set(%s, %q) unexpectedly succeeded with %q", opt, bad, o.Get(opt))
			}
		}

		// Valid minus-removal with internal whitespace must be rebuilt cleanly.
		o := &Options{}
		if err := o.Set(opt, " - fake-legacy-algo-1 , fake-legacy-algo-2 "); err != nil {
			t.Fatalf("Options.Set(%s, valid minus spec) failed: %v", opt, err)
		}
		if got := o.Get(opt); got != "-fake-legacy-algo-1,fake-legacy-algo-2" {
			t.Fatalf("Options.Get(%s) = %q, want clean rebuilt %q", opt, got, "-fake-legacy-algo-1,fake-legacy-algo-2")
		}
	}

	for _, bad := range []string{"\tpublickey", "publickey\x00", "publickey\r", "publickey\u0085", "publickey\u2028"} {
		o := &Options{}
		if err := o.Set(OptionPreferredAuthentications, bad); err == nil {
			t.Fatalf("Options.Set(PreferredAuthentications, %q) unexpectedly succeeded", bad)
		}
	}
}

func TestRound8_P1_2_StartMuxServerDoesNotReexpandExplicitAgentSocket(t *testing.T) {
	t.Parallel()

	resolvedHome := filepath.Join(t.TempDir(), "home")
	resolverCalls := 0
	env := Environment{
		HomeDir: resolvedHome,
		LookupEnv: func(key string) (string, bool) {
			if key == "MY_AGENT" {
				return "~/from-env-literal.sock", true
			}
			return "", false
		},
		ResolveKeyPath: func(p string) string {
			resolverCalls++
			if strings.HasPrefix(p, "~/") {
				return filepath.Join(resolvedHome, strings.TrimPrefix(p, "~/"))
			}
			return p
		},
	}
	target := TargetContext{Host: "app.example.com", Port: 22, User: "ops"}

	// ResolveForwardAgent expands ${MY_AGENT} in a single pass and intentionally
	// does NOT re-expand a ~ that originated from the env var value.
	sock, enabled, err := ResolveForwardAgent("${MY_AGENT}", "", env, target)
	if err != nil || !enabled {
		t.Fatalf("ResolveForwardAgent failed: sock=%q enabled=%v err=%v", sock, enabled, err)
	}
	if !strings.HasPrefix(sock, "~") {
		t.Fatalf("expected single-pass ResolveForwardAgent to preserve literal leading ~, got %q", sock)
	}

	// StartMuxServer must reject control chars in opts.AgentSocket before TrimSpace.
	if _, err := StartMuxServer(t.Context(), nil, MuxMasterOptions{
		Path:              filepath.Join(t.TempDir(), "ctrl.sock"),
		Target:            target,
		Environment:       env,
		AllowAgentForward: true,
		AgentSocket:       "\r/tmp/agent.sock",
	}); err == nil {
		t.Fatal("StartMuxServer unexpectedly accepted AgentSocket with leading CR")
	}

	// Verify StartMuxServer preserves explicit expanded AgentSocket without calling
	// env.ResolveKeyPath to re-expand leading ~.
	ctrlPath := filepath.Join(t.TempDir(), "m.sock")
	srv, err := StartMuxServer(t.Context(), &cryptoSSH.Client{}, MuxMasterOptions{
		Path:              ctrlPath,
		Target:            target,
		Environment:       env,
		AllowAgentForward: true,
		AgentSocket:       sock,
	})
	if err != nil {
		t.Fatalf("StartMuxServer failed: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()

	if srv.agentSocket != filepath.Clean(filepath.FromSlash(sock)) {
		t.Fatalf("StartMuxServer re-expanded explicit AgentSocket: got %q, want %q", srv.agentSocket, filepath.Clean(filepath.FromSlash(sock)))
	}
	if resolverCalls != 0 {
		t.Fatalf("ResolveKeyPath should not have been called for explicit tilde-prefixed AgentSocket, called %d times", resolverCalls)
	}
}

func TestRound8_P2_1_PreTrimControlRejectionAcrossOptionsAndIdentityPaths(t *testing.T) {
	t.Parallel()

	// Forward, StdioForward, SetEnv, SendEnv, RemoteCommand, Append.
	if _, _, err := ParseStdioForward("\r127.0.0.1:80"); err == nil {
		t.Fatal("ParseStdioForward accepted leading CR")
	}
	if _, err := unwrapForwardHost("[\x00foo]", false); err == nil {
		t.Fatal("unwrapForwardHost accepted NUL inside bracket")
	}
	for _, tc := range []struct {
		key string
		val string
	}{
		{OptionLocalForward, "\r8080 127.0.0.1:80"},
		{OptionLocalForward, "8080 127.0.0.1:80\u2028"},
		{OptionSetEnv, "FOO=bar\u2028"},
		{OptionSetEnv, "FOO=bar\u0085"},
		{OptionSendEnv, "\rLANG"},
		{OptionSendEnv, "LANG\u2029"},
		{OptionControlMaster, "\ryes"},
		{OptionControlPersist, "\t10m"},
		{OptionServerAliveCountMax, "\r3"},
		{OptionTCPKeepAlive, "\ryes"},
		{OptionAddressFamily, "\rinet"},
		{OptionGatewayPorts, "\ryes"},
		{OptionVerifyHostKeyDNS, "\ryes"},
		{OptionCanonicalizeHostname, "\ryes"},
		{OptionCanonicalizeMaxDots, "\r1"},
		{OptionCanonicalDomains, "corp.example.com\u2028"},
		{OptionCanonicalizePermittedCNAMEs, "*.a:*.b\r"},
		{OptionTunnel, "\ryes"},
		{OptionTunnelDevice, "\r0:1"},
		{OptionRequestTTY, "\ryes"},
		{OptionSessionType, "\rnone"},
		{OptionStreamLocalBindMask, "\r0177"},
		{OptionEscapeChar, "\r~"},
	} {
		o := &Options{}
		if err := o.Set(tc.key, tc.val); err == nil {
			t.Fatalf("Options.Set(%s, %q) unexpectedly succeeded", tc.key, tc.val)
		}
	}

	o := &Options{}
	if err := o.Append(OptionLocalForward, "8080 127.0.0.1:80\x1b"); err == nil {
		t.Fatal("Options.Append accepted ESC control character")
	}

	// ExpandRemoteCommand must reject CR/LF/LS/PS both in pattern and expanded tokens.
	env := Environment{LocalUser: "alice", LocalHost: "box"}
	if _, err := ExpandRemoteCommand("echo hi\nid", env, TargetContext{Host: "h"}); err == nil {
		t.Fatal("ExpandRemoteCommand accepted newline in pattern")
	}
	if _, err := ExpandRemoteCommand("echo %r", env, TargetContext{Host: "h", User: "bob\u2028evil"}); err == nil {
		t.Fatal("ExpandRemoteCommand accepted U+2028 in expanded token")
	}

	// collectExplicitKeyCandidates and collectExplicitUserCerts must reject leading/trailing CR/U+0085.
	keys, _ := collectExplicitKeyCandidates(
		[]string{"\r/tmp/key1", "/tmp/key2\u0085", "/tmp/good_key"},
		"",
		nil,
		env,
		TargetContext{Host: "h"},
		nil,
		nil,
	)
	if len(keys) != 1 || keys[0] != filepath.Clean("/tmp/good_key") {
		t.Fatalf("collectExplicitKeyCandidates = %v, want only [/tmp/good_key]", keys)
	}
}

func TestRound8_P2_2_P3_1_OptionsEqualDeleteIsNoneValueAndValidateControlPath(t *testing.T) {
	t.Parallel()

	// P2-2: Options.Equal must distinguish literal vs template ControlPath.
	a := &Options{}
	if err := a.Set(OptionControlPath, "/tmp/sock-%C"); err != nil {
		t.Fatal(err)
	}
	b := &Options{}
	if err := b.SetLiteralControlPath("/tmp/sock-%C"); err != nil {
		t.Fatal(err)
	}
	if a.Equal(b) {
		t.Fatal("Options.Equal returned true for template vs literal ControlPath with identical string")
	}

	// P3-1: Options.Delete must clear LiteralControlPath even when values map is empty.
	emptyLit := &Options{LiteralControlPath: true}
	emptyLit.Delete(OptionControlPath)
	if emptyLit.LiteralControlPath {
		t.Fatal("Options.Delete did not clear stale LiteralControlPath on empty Options")
	}

	// P3-1: IsNoneValue case-insensitivity across ControlConfig & Options.
	if !IsNoneValue(" NONE ") || IsNoneValue("none2") {
		t.Fatal("IsNoneValue behaved unexpectedly")
	}
	ctrl := &ControlConfig{Master: ControlMasterYes, Path: "NONE", LiteralPath: true}
	if ctrl.IsEnabled() {
		t.Fatal("ControlConfig.IsEnabled returned true for Path=NONE")
	}
	if resolved, err := ctrl.ResolvePath(Environment{}, TargetContext{}); err != nil || resolved != "none" {
		t.Fatalf("ControlConfig.ResolvePath(NONE) = (%q, %v), want (\"none\", nil)", resolved, err)
	}
	eff, err := MergeEffectiveOptions(
		OptionsFromControl(&ControlConfig{Path: "NONE"}),
		OptionsFromControl(&ControlConfig{Master: ControlMasterAuto, Path: "/tmp/m.sock", Persist: "10m"}),
	)
	if err != nil {
		t.Fatalf("MergeEffectiveOptions failed: %v", err)
	}
	merged, err := eff.ValidatedControlConfig()
	if err != nil {
		t.Fatalf("ValidatedControlConfig failed: %v", err)
	}
	if merged.Path != "none" || merged.Master != ControlMasterNo || merged.Persist != "" || merged.LiteralPath {
		t.Fatalf("ValidatedControlConfig(NONE child) = %+v, want disabled none", merged)
	}

	// P3-1: ValidateControlPath rejects whitespace-only string.
	if err := ValidateControlPath("   "); err == nil {
		t.Fatal("ValidateControlPath accepted whitespace-only path")
	}
}

func TestRound8_P2_3_P3_2_MuxProxyPacketBoundWindowOverflowAndNonBlockingClose(t *testing.T) {
	t.Parallel()

	// 1. handleOpen must reject clientMaxPacket == 1<<31 (> math.MaxInt32).
	c1, c2 := net.Pipe()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()
	ps := &proxySessionState{server: &MuxServer{}, conn: c1, closedCh: make(chan struct{})}
	openPkt := newMuxWriter()
	openPkt.WriteString("session")
	openPkt.WriteUint32(7)                 // clientChID
	openPkt.WriteUint32(65536)             // clientWindow
	openPkt.WriteUint32(math.MaxInt32 + 1) // 1<<31 overflows 32-bit int
	replyCh := make(chan []byte, 1)
	go func() {
		pkt, _ := readUnpaddedPacket(c2)
		replyCh <- pkt
	}()
	ps.handleOpen(openPkt.Bytes())
	select {
	case pkt := <-replyCh:
		if len(pkt) == 0 || pkt[0] != msgChannelOpenFailure {
			t.Fatalf("expected msgChannelOpenFailure for clientMaxPacket=1<<31, got %v", pkt)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for msgChannelOpenFailure")
	}

	// 2. handleWindowAdjust overflow must retire the offending channel instead of silently ignoring.
	c3, c4 := net.Pipe()
	defer func() {
		_ = c3.Close()
		_ = c4.Close()
	}()
	ps2 := &proxySessionState{server: &MuxServer{}, conn: c3, closedCh: make(chan struct{})}
	pc := &proxyChan{
		clientCh:          9,
		serverCh:          3,
		clientWindow:      newClientFlowWindow(uint32(maxFlowWindow - 10)),
		clientMaxPacket:   32768,
		input:             newOrderedQueue[proxyChannelInput](),
		requests:          newOrderedQueue[proxyChannelRequest](),
		pendingRemoteReqs: newRemoteRequestQueue(),
	}
	ps2.channels.Store(pc.serverCh, pc)
	gotClose := make(chan struct{})
	go func() {
		pkt, err := readUnpaddedPacket(c4)
		if err == nil && len(pkt) >= 1 && pkt[0] == msgChannelClose {
			close(gotClose)
		}
	}()
	adj := newMuxWriter()
	adj.WriteUint32(pc.serverCh)
	adj.WriteUint32(100) // overflows maxFlowWindow
	ps2.handleWindowAdjust(adj.Bytes())
	select {
	case <-gotClose:
	case <-time.After(2 * time.Second):
		t.Fatal("handleWindowAdjust overflow did not retire/close channel")
	}
	if _, stillPresent := ps2.channels.Load(pc.serverCh); stillPresent {
		t.Fatal("overflowed channel still present in ps2.channels")
	}
	ps2.closeAll()

	// 3. sendChannelData with clientMaxPacket <= 0 must close ps.conn and retire channel.
	c5, c6 := net.Pipe()
	defer func() { _ = c6.Close() }()
	ps3 := &proxySessionState{server: &MuxServer{}, conn: c5, closedCh: make(chan struct{})}
	badPC := &proxyChan{clientCh: 1, serverCh: 1, clientMaxPacket: -1, clientWindow: newClientFlowWindow(100)}
	if err := ps3.sendChannelData(badPC, false, []byte("x")); err == nil {
		t.Fatal("sendChannelData accepted clientMaxPacket <= 0")
	}
	// c5 must be closed so reading c6 fails immediately.
	var one [1]byte
	if _, err := c6.Read(one[:]); err == nil {
		t.Fatal("expected peer conn to be closed after fatal clientMaxPacket <= 0")
	}
	ps3.closeAll()
}

func TestRound8_P2_4_NormalizeProxyJumpAcrossTargetContexts(t *testing.T) {
	t.Parallel()

	cfg := &ClientConfig{
		NodeID:    "app",
		Address:   "10.0.0.1",
		Port:      22,
		User:      "ops",
		ProxyJump: " , none , ",
	}
	target := knownHostsTarget(cfg)
	if target.JumpHost != "" {
		t.Fatalf("knownHostsTarget JumpHost = %q, want empty", target.JumpHost)
	}
	c := &Connector{}
	if got := c.authTargetContext(cfg).JumpHost; got != "" {
		t.Fatalf("authTargetContext JumpHost = %q, want empty", got)
	}
	proxyCfg := effectiveControlProxyConfig(cfg, TargetContext{Host: "10.0.0.1", JumpHost: "none"})
	if proxyCfg.ProxyJump != "" {
		t.Fatalf("effectiveControlProxyConfig ProxyJump = %q, want empty", proxyCfg.ProxyJump)
	}
	// Explicit ProxyJump="none" in cfg must not inherit target.JumpHost="bastion".
	proxyCfgDisabled := effectiveControlProxyConfig(&ClientConfig{
		Address:   "10.0.0.1",
		Port:      22,
		User:      "ops",
		ProxyJump: "none",
	}, TargetContext{Host: "10.0.0.1", JumpHost: "bastion"})
	if proxyCfgDisabled.ProxyJump != "" {
		t.Fatalf("effectiveControlProxyConfig explicit none inherited JumpHost: %q", proxyCfgDisabled.ProxyJump)
	}
	// Direct TargetContext with JumpHost="none" expands %j as empty.
	expanded, err := ExpandControlPath("/tmp/%j-%C", Environment{LocalHost: "local"}, TargetContext{Host: "10.0.0.1", Port: 22, User: "ops", JumpHost: "none"})
	if err != nil {
		t.Fatalf("ExpandControlPath failed: %v", err)
	}
	wantExpanded, err := ExpandControlPath("/tmp/%j-%C", Environment{LocalHost: "local"}, TargetContext{Host: "10.0.0.1", Port: 22, User: "ops"})
	if err != nil {
		t.Fatalf("ExpandControlPath(empty jump) failed: %v", err)
	}
	if expanded != wantExpanded {
		t.Fatalf("ExpandControlPath JumpHost=\"none\" = %q, want %q", expanded, wantExpanded)
	}
}

func TestRound8_P2_5_P2_9_ExpandIdentityPathAndBaseHostPropagation(t *testing.T) {
	t.Parallel()

	env := Environment{
		HomeDir: "",
		LookupEnv: func(k string) (string, bool) {
			if k == "CERT_P" {
				return "  /etc/ssh/id_cert.pub  ", true
			}
			return "", false
		},
	}
	got, err := ExpandIdentityPath("${CERT_P}", env, TargetContext{Host: "h.example.com", Port: 22, User: "ops"})
	if err != nil {
		t.Fatalf("ExpandIdentityPath failed: %v", err)
	}
	if got != filepath.Clean("/etc/ssh/id_cert.pub") {
		t.Fatalf("ExpandIdentityPath = %q, want %q", got, filepath.Clean("/etc/ssh/id_cert.pub"))
	}
	if _, err := ExpandIdentityPath("${MISSING_VAR}", env, TargetContext{Host: "h"}); err == nil {
		t.Fatal("ExpandIdentityPath unexpectedly succeeded for unset env var")
	}

	// BaseHost must round-trip through ToConnectionConfig, freezeDialPolicy, clientConfigFromPlan, and SecretRequest.
	cc := &ClientConfig{
		NodeID:   "app",
		Address:  "override.example.com",
		BaseHost: "10.0.0.9",
		Port:     22,
		User:     "ops",
	}
	connCfg := cc.ToConnectionConfig()
	if connCfg.BaseHost != "10.0.0.9" {
		t.Fatalf("ToConnectionConfig().BaseHost = %q, want 10.0.0.9", connCfg.BaseHost)
	}
	planCfg := clientConfigFromPlan(connCfg)
	if planCfg.BaseHost != "10.0.0.9" {
		t.Fatalf("clientConfigFromPlan().BaseHost = %q, want 10.0.0.9", planCfg.BaseHost)
	}
	// ConnectionConfig JSON must omit base_host when empty, include when non-empty.
	rawEmpty, err := json.Marshal(ConnectionConfig{NodeID: "app"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawEmpty), "base_host") {
		t.Fatalf("expected empty BaseHost to be omitted from JSON, got %s", rawEmpty)
	}
	rawSet, err := json.Marshal(connCfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rawSet), `"base_host":"10.0.0.9"`) {
		t.Fatalf("expected non-empty BaseHost in JSON, got %s", rawSet)
	}
	// Verify autoSecretProvider populates SecretRequest.BaseHost.
	var captured SecretRequest
	p := &autoSecretProvider{
		lifecycleCtx: context.Background(),
		nodeID:       "app",
		user:         "ops",
		host:         "override.example.com",
		baseHost:     "10.0.0.9",
		port:         22,
		resolver: secretResolverFunc(func(_ context.Context, req SecretRequest) ([]byte, error) {
			captured = req
			return []byte("secret"), nil
		}),
	}
	if _, err := p.resolveOrPrompt(SecretRequest{Kind: SecretKindLoginPassword}); err != nil {
		t.Fatalf("resolveOrPrompt failed: %v", err)
	}
	if captured.BaseHost != "10.0.0.9" || captured.Host != "override.example.com" {
		t.Fatalf("captured SecretRequest = %+v, want Host=override.example.com BaseHost=10.0.0.9", captured)
	}
}

type secretResolverFunc func(context.Context, SecretRequest) ([]byte, error)

func (f secretResolverFunc) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	return f(ctx, req)
}

// Keep unused import check happy if io is referenced only in errors.Is.
var _ = errors.Is
var _ = io.EOF
