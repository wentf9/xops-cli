package ssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

func openRawMuxProxyChannel(t *testing.T, ctx context.Context, sockPath, command string, initWin, maxPkt uint32) (net.Conn, uint32, func()) {
	t.Helper()
	mc, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	unbind := bindConnContext(ctx, mc.conn, 10*time.Second)
	if err := WriteMuxPacket(mc.conn, MUX_C_PROXY, encodeChannelIDs(1)); err != nil {
		unbind()
		_ = mc.Close()
		t.Fatalf("WriteMuxPacket(MUX_C_PROXY): %v", err)
	}
	pktType, payload, err := ReadMuxPacket(mc.conn)
	unbind()
	if err != nil {
		_ = mc.Close()
		t.Fatalf("ReadMuxPacket(MUX_S_PROXY): %v", err)
	}
	if pktType != MUX_S_PROXY {
		_ = mc.Close()
		t.Fatalf("expected MUX_S_PROXY (0x%x), got 0x%x (payload=%q)", MUX_S_PROXY, pktType, payload)
	}
	// Consume initial hostkeys-00 global request.
	if _, err := readUnpaddedPacket(mc.conn); err != nil {
		_ = mc.Close()
		t.Fatalf("read initial proxy packet: %v", err)
	}

	const clientChID uint32 = 1
	openW := newMuxWriter()
	openW.buf = append(openW.buf, msgChannelOpen)
	openW.WriteString("session")
	openW.WriteUint32(clientChID)
	openW.WriteUint32(initWin)
	openW.WriteUint32(maxPkt)
	if err := writeUnpaddedPacket(mc.conn, openW.Bytes()); err != nil {
		_ = mc.Close()
		t.Fatalf("write msgChannelOpen: %v", err)
	}

	var serverChID uint32
	for {
		pkt, err := readUnpaddedPacket(mc.conn)
		if err != nil {
			_ = mc.Close()
			t.Fatalf("read open confirmation: %v", err)
		}
		if len(pkt) >= 9 && pkt[0] == msgChannelOpenConfirmation {
			serverChID = binary.BigEndian.Uint32(pkt[5:9])
			break
		}
	}

	execW := newMuxWriter()
	execW.buf = append(execW.buf, msgChannelRequest)
	execW.WriteUint32(serverChID)
	execW.WriteString("exec")
	execW.WriteBool(false)
	execW.WriteString(command)
	if err := writeUnpaddedPacket(mc.conn, execW.Bytes()); err != nil {
		_ = mc.Close()
		t.Fatalf("write exec request: %v", err)
	}
	return mc.conn, serverChID, func() { _ = mc.Close() }
}

func TestRound7_P1_1_FlowWindowPartialGrantAndWireMultiplex(t *testing.T) {
	t.Parallel()

	// 1. Unit contract: partial grant when 0 < credit < n; block only at 0; EOF when closed.
	win := newClientFlowWindow(10)
	got, err := win.reserve(100)
	if err != nil || got != 10 {
		t.Fatalf("reserve(100) on credit=10 = (%d, %v), want (10, nil)", got, err)
	}

	waitDone := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, rErr := win.reserve(5)
		waitDone <- struct {
			n   int
			err error
		}{n, rErr}
	}()
	time.Sleep(15 * time.Millisecond)
	select {
	case res := <-waitDone:
		t.Fatalf("reserve(5) returned early at credit=0: %+v", res)
	default:
	}

	if err := win.add(25); err != nil {
		t.Fatalf("win.add(25): %v", err)
	}
	select {
	case res := <-waitDone:
		if res.err != nil || res.n != 5 {
			t.Fatalf("woken reserve(5) = (%d, %v), want (5, nil)", res.n, res.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reserve(5) stayed blocked after win.add(25)")
	}
	if got, err := win.reserve(100); err != nil || got != 20 {
		t.Fatalf("reserve(100) remainder = (%d, %v), want (20, nil)", got, err)
	}

	// Closing must wake blocked senders and fail subsequent reserve even if add happened earlier.
	closeDone := make(chan error, 1)
	go func() {
		_, rErr := win.reserve(1)
		closeDone <- rErr
	}()
	time.Sleep(10 * time.Millisecond)
	win.close()
	if rErr := <-closeDone; !errors.Is(rErr, io.EOF) {
		t.Fatalf("closed reserve error = %v, want io.EOF", rErr)
	}
	if _, err := win.reserve(1); !errors.Is(err, io.EOF) {
		t.Fatalf("post-close reserve = %v, want io.EOF", err)
	}

	verifyRound7FlowWindowWireProxy(t)
}

func verifyRound7FlowWindowWireProxy(t *testing.T) {
	t.Helper()
	// 2. Wire-level MUX_C_PROXY test: initialWindow=1024 < maxPacket=32768 with concurrent
	// stdout + stderr streaming 64 KiB each (128 KiB total).
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	const perStream = 64 * 1024
	fixture := startMuxFixture(t, ctx, sshfixture.Options{
		ExecHandler: func(_ string, ch cryptoSSH.Channel) {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				_, _ = ch.Write(bytes.Repeat([]byte("O"), perStream))
			}()
			go func() {
				defer wg.Done()
				_, _ = ch.Stderr().Write(bytes.Repeat([]byte("E"), perStream))
			}()
			wg.Wait()
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})

	conn, serverCh, closeRaw := openRawMuxProxyChannel(t, ctx, fixture.SocketPath, "stream-both", 1024, 32768)
	defer closeRaw()

	var stdoutBytes, stderrBytes int
	var gotEOF, gotClose bool
	for !gotClose {
		pkt, pErr := readUnpaddedPacket(conn)
		if pErr != nil {
			t.Fatalf("readUnpaddedPacket failed after stdout=%d stderr=%d: %v", stdoutBytes, stderrBytes, pErr)
		}
		if len(pkt) < 5 {
			continue
		}
		switch pkt[0] {
		case msgChannelData:
			r := newMuxReader(pkt[5:])
			data, dErr := r.ReadBytes()
			if dErr != nil {
				t.Fatalf("decode msgChannelData: %v", dErr)
			}
			if len(data) == 0 || len(data) > 1024 {
				t.Fatalf("msgChannelData len=%d violates initialWindow=1024 ceiling", len(data))
			}
			stdoutBytes += len(data)
			adj := newMuxWriter()
			adj.buf = append(adj.buf, msgChannelWindowAdjust)
			adj.WriteUint32(serverCh)
			adj.WriteUint32(uint32(len(data)))
			if wErr := writeUnpaddedPacket(conn, adj.Bytes()); wErr != nil {
				t.Fatalf("write WINDOW_ADJUST: %v", wErr)
			}
		case msgChannelExtendedData:
			r := newMuxReader(pkt[5:])
			extType, _ := r.ReadUint32()
			data, dErr := r.ReadBytes()
			if dErr != nil || extType != extendedDataStderr {
				t.Fatalf("decode msgChannelExtendedData: type=%d err=%v", extType, dErr)
			}
			if len(data) == 0 || len(data) > 1024 {
				t.Fatalf("msgChannelExtendedData len=%d violates initialWindow=1024 ceiling", len(data))
			}
			stderrBytes += len(data)
			adj := newMuxWriter()
			adj.buf = append(adj.buf, msgChannelWindowAdjust)
			adj.WriteUint32(serverCh)
			adj.WriteUint32(uint32(len(data)))
			if wErr := writeUnpaddedPacket(conn, adj.Bytes()); wErr != nil {
				t.Fatalf("write WINDOW_ADJUST: %v", wErr)
			}
		case msgChannelEOF:
			gotEOF = true
		case msgChannelClose:
			gotClose = true
		}
	}
	if !gotEOF || stdoutBytes != perStream || stderrBytes != perStream {
		t.Fatalf("wire relay mismatch: gotEOF=%v stdout=%d stderr=%d, want true/%d/%d",
			gotEOF, stdoutBytes, stderrBytes, perStream, perStream)
	}
}

func TestRound7_P1_2_ConnectorRoutingCompatibilityAndCapturePlan(t *testing.T) {
	t.Parallel()

	// Pre-populated OriginalProxyJump on an intermediate hop must NOT be clobbered.
	store := &multiMockConfigStore{
		configs: map[string]*ClientConfig{
			"target": {
				NodeID:    "target",
				Address:   "10.0.0.2",
				Port:      22,
				User:      "ops",
				ProxyJump: " , ",
				Options:   MustOptions(OptionProxyCommand, "nc %h %p"),
			},
			"multi": {
				NodeID:    "multi",
				Address:   "10.0.0.3",
				Port:      22,
				User:      "ops",
				ProxyJump: "hop1, none , hop2",
			},
			"hop1": {
				NodeID:               "hop1",
				Address:              "10.0.0.10",
				Port:                 22,
				User:                 "ops",
				OriginalProxyJump:    "provider-orig",
				HasOriginalProxyJump: true,
			},
			"hop2": {
				NodeID:  "hop2",
				Address: "10.0.0.11",
				Port:    22,
				User:    "ops",
			},
		},
	}

	conn := NewConnector(store)
	defer closePlanConnector(t, conn)

	planMulti, err := conn.resolveConnectionPlan(t.Context(), "multi")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(multi): %v", err)
	}
	if planMulti[2].cfg.OriginalProxyJump != "provider-orig" || !planMulti[2].cfg.HasOriginalProxyJump {
		t.Fatalf("intermediate OriginalProxyJump clobbered: got (%q, %v)", planMulti[2].cfg.OriginalProxyJump, planMulti[2].cfg.HasOriginalProxyJump)
	}

	// TargetContext & checkTargetDigestCompatibility on " , " + ProxyCommand.
	planDisabled, err := conn.resolveConnectionPlan(t.Context(), "target")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(target): %v", err)
	}
	tc := conn.buildTargetContext(planDisabled[0])
	if tc.JumpHost != "" {
		t.Fatalf("buildTargetContext().JumpHost = %q, want empty after normalization", tc.JumpHost)
	}
	curCfg := planDisabled[0].cfg.ToConnectionConfig()
	if err := checkTargetDigestCompatibility(curCfg, store.configs["target"]); err != nil {
		t.Fatalf("unchanged disabled ProxyJump compatibility failed: %v", err)
	}
	driftedCmd := *store.configs["target"]
	driftedCmd.Options = MustOptions(OptionProxyCommand, "nc -X 5 %h %p")
	if err := checkTargetDigestCompatibility(curCfg, &driftedCmd); !errors.Is(err, ErrSnapshotMismatch) {
		t.Fatalf("expected ErrSnapshotMismatch on ProxyCommand drift under ProxyJump=' , ', got %v", err)
	}

	// CapturePlan must detect disabled ProxyJump + active ProxyCommand on hop 0 and fail closed.
	if _, err := CapturePlan(t.Context(), store, "target", "mcp-scope"); !errors.Is(err, ErrProxyCommandUnavailable) {
		t.Fatalf("CapturePlan(ProxyJump=' , ' + ProxyCommand) = %v, want ErrProxyCommandUnavailable", err)
	}
}

type round7InitDropProvider struct {
	mu         sync.Mutex
	configs    map[string]*ClientConfig
	onConfirmA func(client *Client)
}

func (p *round7InitDropProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cfg, ok := p.configs[nodeID]
	if !ok {
		return nil, fmt.Errorf("missing node %q", nodeID)
	}
	return cfg, nil
}

func (p *round7InitDropProvider) ConfirmAuthenticatedConnection(_ context.Context, nodeID string, client *Client) (*ExecutionConfig, error) {
	if nodeID == "targetA" && p.onConfirmA != nil {
		p.onConfirmA(client)
	}
	return nil, nil
}

func TestRound7_P2_1_InitDropOnJumpTargetDoesNotKillSharedBastion(t *testing.T) {
	bastionLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	startForwardingBastionSSHServer(t, bastionLn, "bastion-pw")
	bastionHost, bastionPort, err := sshfixtureSplitHostPort(bastionLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// TargetA drops its own accepted connection during ConfirmAuthenticatedConnection.
	targetALn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var acceptWG sync.WaitGroup
	t.Cleanup(func() {
		_ = targetALn.Close()
		acceptWG.Wait()
	})
	var targetAConnMu sync.Mutex
	var targetAConn net.Conn
	acceptWG.Add(1)
	go func() {
		defer acceptWG.Done()
		for {
			s, aErr := targetALn.Accept()
			if aErr != nil {
				return
			}
			targetAConnMu.Lock()
			targetAConn = s
			targetAConnMu.Unlock()
			startInMemoryPipeSSHServer(t, s, "target-pw")
		}
	}()
	targetAHost, targetAPort, _ := sshfixtureSplitHostPort(targetALn.Addr().String())

	// TargetB is a normal SSH server behind the same bastion.
	targetBCtx, targetBCancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer targetBCancel()
	targetBFix, err := sshfixture.New(targetBCtx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = targetBFix.Close() })
	targetBHost, targetBPort, _ := sshfixtureSplitHostPort(targetBFix.Address)

	provider := &round7InitDropProvider{
		configs: map[string]*ClientConfig{
			"bastion": {
				NodeID:   "bastion",
				Address:  bastionHost,
				Port:     bastionPort,
				User:     "jump",
				AuthType: "password",
				Password: "bastion-pw",
				Options:  MustOptions(OptionStrictHostKeyChecking, "no"),
			},
			"targetA": {
				NodeID:    "targetA",
				Address:   targetAHost,
				Port:      targetAPort,
				User:      "app",
				AuthType:  "password",
				Password:  "target-pw",
				ProxyJump: "bastion",
				Options:   MustOptions(OptionStrictHostKeyChecking, "no"),
			},
			"targetB": {
				NodeID:    "targetB",
				Address:   targetBHost,
				Port:      targetBPort,
				User:      "app",
				AuthType:  "password",
				Password:  sshfixture.Password,
				ProxyJump: "bastion",
				Options:   MustOptions(OptionStrictHostKeyChecking, "no"),
			},
		},
	}
	provider.onConfirmA = func(client *Client) {
		targetAConnMu.Lock()
		c := targetAConn
		targetAConnMu.Unlock()
		if c != nil {
			_ = c.Close()
		}
		if client != nil && client.SSHClient() != nil {
			waitCh := make(chan error, 1)
			go func() {
				waitCh <- client.SSHClient().Wait()
			}()
			select {
			case <-waitCh:
			case <-time.After(2 * time.Second):
				t.Error("timed out waiting for targetA SSH transport loop to observe close")
			}
		}
	}

	conn := NewConnector(provider, WithHostKeyVerifier(trustAnyFixtureHostKey{}))
	t.Cleanup(func() { _ = conn.CloseAll() })

	// Connect bastion and targetB first; keep bastion pooled client handle to assert its transport stays alive.
	bastionClient, err := conn.Connect(targetBCtx, "bastion")
	if err != nil {
		t.Fatalf("Connect bastion: %v", err)
	}
	targetBClient, err := conn.Connect(targetBCtx, "targetB")
	if err != nil {
		t.Fatalf("Connect targetB: %v", err)
	}

	// Connecting targetA triggers checkInitializedTransport failure after auth.
	_, errA := conn.Connect(targetBCtx, "targetA")
	var connErr *ConnectionError
	if !errors.As(errA, &connErr) {
		t.Fatalf("expected *ConnectionError from targetA init drop, got %v", errA)
	}
	if bastionClient.transportError() != nil {
		t.Fatalf("shared bastion transport was closed when targetA init dropped: %v", bastionClient.transportError())
	}
	if _, _, bErr := targetBClient.SSHClient().SendRequest("keepalive@openssh.com", true, nil); bErr != nil {
		t.Fatalf("sibling targetB failed after targetA init drop: %v", bErr)
	}
}

func TestRound7_P2_2_SinglePassPathExpansionAndNoTildeRescan(t *testing.T) {
	t.Parallel()

	env := Environment{
		HomeDir:   "/home/100%dev",
		LocalUser: "ops%20user",
		LocalHost: "box.example.com",
		LocalUID:  "1000",
		LookupEnv: func(k string) (string, bool) {
			switch k {
			case "PERCENT_DIR":
				return "/tmp/run%20dir", true
			case "TOKEN_DIR":
				return "/var/run/%r", true
			case "TILDE_VAR":
				return "~/injected", true
			default:
				return "", false
			}
		},
		ResolveKeyPath: func(p string) string {
			if strings.HasPrefix(p, "~") {
				return "/home/100%dev" + p[1:]
			}
			return p
		},
	}
	target := TargetContext{Host: "web%20node", Port: 2222, User: "deploy"}

	if got, err := ExpandControlPath("${PERCENT_DIR}/cm-%h", env, target); err != nil || got != "/tmp/run%20dir/cm-web%20node" {
		t.Fatalf("ExpandControlPath(PERCENT_DIR) = (%q, %v)", got, err)
	}
	if got, err := ExpandControlPath("~/.ssh/cm-%r", env, target); err != nil || got != filepath.Join("/home/100%dev", ".ssh/cm-deploy") {
		t.Fatalf("ExpandControlPath(HomeDir with %%) = (%q, %v)", got, err)
	}
	if got, err := ExpandControlPath("${TOKEN_DIR}/cm-%r", env, target); err != nil || got != "/var/run/%r/cm-deploy" {
		t.Fatalf("ExpandControlPath(TOKEN_DIR) rescanned %%r inside env: (%q, %v)", got, err)
	}
	if got, err := ExpandStreamLocalPath("${PERCENT_DIR}/sl-%r", env, target, true); err != nil || got != "/tmp/run%20dir/sl-deploy" {
		t.Fatalf("ExpandStreamLocalPath = (%q, %v)", got, err)
	}
	if got, err := expandIdentityKeyPath("${TILDE_VAR}/id_ed25519", env, target, env.ResolveKeyPath); err != nil || got != filepath.Clean("~/injected/id_ed25519") {
		t.Fatalf("expandIdentityKeyPath re-expanded ~/ from ${TILDE_VAR}: (%q, %v)", got, err)
	}
	if got, _, err := ResolveIdentityAgent("${TILDE_VAR}/agent.sock", env, target); err != nil || got != filepath.Clean("~/injected/agent.sock") {
		t.Fatalf("ResolveIdentityAgent re-expanded ~/ from ${TILDE_VAR}: (%q, %v)", got, err)
	}
	if got, err := expandKnownHostsPath("${PERCENT_DIR}/known_hosts", env, target); err != nil || got != filepath.Clean("/tmp/run%20dir/known_hosts") {
		t.Fatalf("expandKnownHostsPath = (%q, %v)", got, err)
	}
}

func TestRound7_P2_8_LiteralControlPathPreservedAcrossOptionsAndControl(t *testing.T) {
	t.Parallel()

	literalPath := "/tmp/cm-root@fe80::1%eth0:22-${KEEP}"
	var opts Options
	if err := opts.SetLiteralControlPath(literalPath); err != nil {
		t.Fatalf("SetLiteralControlPath: %v", err)
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("Options.Validate on LiteralControlPath failed: %v", err)
	}
	ctrl := opts.ControlConfig()
	if ctrl == nil || !ctrl.LiteralPath || ctrl.Path != literalPath {
		t.Fatalf("Options.ControlConfig = %+v, want LiteralPath=true Path=%q", ctrl, literalPath)
	}
	resolved, err := ctrl.ResolvePath(Environment{HomeDir: "/home/u"}, TargetContext{Host: "fe80::1%eth0", Port: 22, User: "root"})
	if err != nil || resolved != literalPath {
		t.Fatalf("ctrl.ResolvePath = (%q, %v), want %q", resolved, err, literalPath)
	}

	// MergeOptionLayers preserves LiteralControlPath when winning layer is literal, and clears
	// it when a higher layer overrides ControlPath with "none" or a non-literal template.
	lowMerged := MergeOptionLayers(nil, &opts)
	if lowMerged == nil || !lowMerged.LiteralControlPath || lowMerged.ControlPath() != literalPath {
		t.Fatalf("MergeOptionLayers did not preserve LiteralControlPath: %+v", lowMerged)
	}
	var highNone Options
	_ = highNone.Set(OptionControlPath, "none")
	effDisabled, err := EffectiveOptions(&highNone, &opts)
	if err != nil || effDisabled == nil || effDisabled.LiteralControlPath {
		t.Fatalf("EffectiveOptions(none override) left LiteralControlPath=true: %+v, %v", effDisabled, err)
	}
}

func TestRound7_P3_1_And_P3_2_UnicodeControlsAndMultiValueInjectionRejected(t *testing.T) {
	t.Parallel()

	// P3-1: Unicode C1 NEL (\u0085), LS (\u2028), PS (\u2029) must be rejected before TrimSpace.
	for _, sep := range []string{"\u0085", "\u2028", "\u2029"} {
		if _, _, err := ResolveIdentityAgent(sep+"/tmp/agent.sock", Environment{}, TargetContext{}); err == nil {
			t.Errorf("ResolveIdentityAgent accepted leading %q", sep)
		}
		if _, _, err := ResolveIdentityAgent("SSH_AUTH_SOCK", Environment{AgentSocket: sep}, TargetContext{}); err == nil {
			t.Errorf("ResolveIdentityAgent(SSH_AUTH_SOCK) accepted %q", sep)
		}
		if _, _, err := ResolveForwardAgent(sep+"yes", "", Environment{}, TargetContext{}); err == nil {
			t.Errorf("ResolveForwardAgent accepted %q", sep)
		}
		if _, err := ExpandControlPath(sep+"/tmp/cm-%C", Environment{}, TargetContext{Host: "h"}); err == nil {
			t.Errorf("ExpandControlPath accepted %q", sep)
		}
		if err := ValidateControlPath("/tmp/cm" + sep); err == nil {
			t.Errorf("ValidateControlPath accepted %q", sep)
		}
		if _, err := ExpandHostName(sep+"%h.example.com", "web"); err == nil {
			t.Errorf("ExpandHostName accepted %q", sep)
		}
		var opts Options
		if err := opts.Set(OptionControlPath, sep+"/tmp/cm-%C"); err == nil {
			t.Errorf("Options.Set(ControlPath) accepted %q", sep)
		}
		if err := opts.Set(OptionRemoteCommand, "echo"+sep+"hi"); err == nil {
			t.Errorf("Options.Set(RemoteCommand) accepted %q", sep)
		}
	}

	// Non-UTF-8 raw Unix path bytes remain accepted on Unix IdentityFile.
	var nonUTF8Opts Options
	if err := nonUTF8Opts.Set(OptionIdentityFile, "/tmp/key\xff"); err != nil {
		t.Fatalf("non-UTF-8 raw IdentityFile path should stay accepted on Unix, got: %v", err)
	}

	// P3-2: Embedded \n / \r / \u2028 inside single Options.Append or YAML/JSON list element must fail.
	var appOpts Options
	for _, tc := range []struct {
		key string
		val string
	}{
		{OptionIdentityFile, "/tmp/id_1\n/tmp/id_2"},
		{OptionCertificateFile, "/tmp/c1.pub\u2028/tmp/c2.pub"},
		{OptionLocalForward, "8080 127.0.0.1:80\n9090 127.0.0.1:90"},
		{OptionSendEnv, "LANG\nLC_ALL"},
	} {
		if err := appOpts.Append(tc.key, tc.val); err == nil {
			t.Errorf("Options.Append(%q, %q) accepted embedded line break", tc.key, tc.val)
		}
	}
	var yamlOpts Options
	if err := yaml.Unmarshal([]byte("identity_file:\n  - \"/tmp/id_1\\n/tmp/id_2\"\n"), &yamlOpts); err == nil {
		t.Error("yaml.Unmarshal accepted embedded newline inside multi-value list item")
	}
	var yamlAllowList Options
	if err := yaml.Unmarshal([]byte("ciphers:\n  - \"aes256-gcm@openssh.com\\u0085\"\n"), &yamlAllowList); err == nil {
		t.Error("yaml.Unmarshal accepted U+0085 inside AllowList item")
	}
	var jsonOpts Options
	if err := json.Unmarshal([]byte(`{"local_forward":["8080 127.0.0.1:80\n9090 127.0.0.1:90"]}`), &jsonOpts); err == nil {
		t.Error("json.Unmarshal accepted embedded newline inside multi-value list item")
	}
}
