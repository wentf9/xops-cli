//go:build linux || darwin || freebsd

package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TestReviewPass4_H1_M2_MuxProxyExecuteCommandAndSubsystemAgentForward verifies on Unix:
//   - (a) MUX_C_PROXY passenger with NO local SSH_AUTH_SOCK (AgentSocket == "", DialAgent == nil)
//     calling ExecuteCommand AND RunSubsystemWithIO against a ControlMaster with AllowAgentForward=true
//     both succeed and use Master's agent without registering any local router on passenger's sshClient;
//   - (b) MUX_C_PROXY passenger WITH a local SSH_AUTH_SOCK calling ExecuteCommand and RunSubsystemWithIO
//     still dials ONLY Master's agent and never registers a dead local router on passenger's sshClient;
//   - (c) Internal probes (executeCommand(..., false) and RunProbeStream) on MUX_C_PROXY do NOT
//     request agent forwarding;
//   - (d) MUX_C_PROXY passenger with IdentityAgent=none + ForwardAgent=/explicit/sock (or SSH_AUTH_SOCK)
//     requests forwarding, while IdentityAgent=none + ForwardAgent=yes, ForwardAgent=$UNSET_VAR, and
//     ForwardAgent=yes + IdentityAgent=$UNSET_VAR do NOT.
func TestReviewPass4_H1_M2_MuxProxyExecuteCommandAndSubsystemAgentForward(t *testing.T) {
	home := setTestHome(t)
	fix := newPhase3CertFixture(t)
	keyPath := filepath.Join(home, "id_ed25519")
	loginPriv, loginPub := writeEd25519KeyFile(t, keyPath, "")

	masterAgentSock, _ := startInMemoryAgentListener(t, loginPriv)
	attackerPriv, _ := writeEd25519KeyFile(t, filepath.Join(home, "attacker_ed25519"), "")
	attackerAgentSock, _ := startInMemoryAgentListener(t, attackerPriv)

	state := &pass4AgentExecSubsystemServer{hostSigner: fix.hostSigner, clientPub: loginPub}
	port := startPass4AgentExecSubsystemServer(t, state)

	baseEnv := fixtureEnvironment()
	baseEnv.HomeDir = home
	baseEnv.LookupEnv = func(string) (string, bool) { return "", false }

	var masterDials atomic.Int32
	masterEnv := baseEnv
	masterEnv.AgentSocket = masterAgentSock
	origMasterDial := masterEnv.DialAgent
	masterEnv.DialAgent = func(ctx context.Context, sock string) (net.Conn, error) {
		if sock != masterAgentSock {
			t.Errorf("master DialAgent dialed unexpected socket %q, want %q", sock, masterAgentSock)
		}
		masterDials.Add(1)
		return origMasterDial(ctx, sock)
	}

	sockPath := filepath.Join(shortSocketDir(t), "p4-master.sock")
	masterOpts := newPhase3TrustAllOptions(t, home)
	_ = masterOpts.Set(OptionControlMaster, "yes")
	_ = masterOpts.Set(OptionControlPath, sockPath)
	_ = masterOpts.Set(OptionControlPersist, "yes")
	_ = masterOpts.Set(OptionForwardAgent, "yes")
	_ = masterOpts.Set(OptionIdentityAgent, masterAgentSock)

	masterConn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"m": {NodeID: "m", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "key", KeyPath: keyPath, Options: masterOpts},
	}}, WithEnvironment(masterEnv))
	t.Cleanup(func() { _ = masterConn.CloseAll() })

	if _, err := masterConn.Connect(t.Context(), "m"); err != nil {
		t.Fatalf("start ControlMaster failed: %v", err)
	}

	assertPass4AgentlessPassengerExecAndSubsystem(t, home, port, keyPath, sockPath, baseEnv, &masterDials, state)
	assertPass4LocalAgentPassengerNeverRegistersRouter(t, home, port, keyPath, sockPath, attackerAgentSock, baseEnv, &masterDials)
	assertPass4PassengerOptionCombinations(t, home, port, keyPath, sockPath, baseEnv, &masterDials)
}

func assertPass4AgentlessPassengerExecAndSubsystem(
	t *testing.T,
	home string,
	port int,
	keyPath, sockPath string,
	baseEnv Environment,
	masterDials *atomic.Int32,
	state *pass4AgentExecSubsystemServer,
) {
	t.Helper()
	agentlessEnv := baseEnv
	agentlessEnv.AgentSocket = ""
	agentlessEnv.DialAgent = nil

	proxyOpts := newPhase3TrustAllOptions(t, home)
	_ = proxyOpts.Set(OptionControlMaster, "no")
	_ = proxyOpts.Set(OptionControlPath, sockPath)
	_ = proxyOpts.Set(OptionForwardAgent, "yes")

	proxyConn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"m": {NodeID: "m", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "key", KeyPath: keyPath, Options: proxyOpts},
	}}, WithEnvironment(agentlessEnv))
	defer func() { _ = proxyConn.CloseAll() }()

	proxyCli, err := proxyConn.Connect(t.Context(), "m")
	if err != nil {
		t.Fatalf("connect agentless MUX_C_PROXY passenger: %v", err)
	}

	// 1. ExecuteCommand on agentless passenger uses Master's agent.
	plan, err := PlanCommand("query-agent", CommandOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("PlanCommand: %v", err)
	}
	before := masterDials.Load()
	res := proxyCli.ExecuteCommand(t.Context(), plan)
	if res.Err() != nil || !strings.Contains(res.Output, "keys=1") {
		t.Fatalf("agentless ExecuteCommand(query-agent) = (%q, %v), want keys=1", res.Output, res.Err())
	}
	if masterDials.Load() != before+1 {
		t.Fatalf("masterDials after ExecuteCommand = %d, want %d", masterDials.Load(), before+1)
	}

	// 2. RunSubsystemWithIO on agentless passenger uses Master's agent.
	var subOut, subErr bytes.Buffer
	before = masterDials.Load()
	if err := proxyCli.RunSubsystemWithIO(t.Context(), "query-agent", strings.NewReader(""), &subOut, &subErr, false); err != nil {
		t.Fatalf("agentless RunSubsystemWithIO(query-agent) err = %v (out=%q err=%q)", err, subOut.String(), subErr.String())
	}
	if !strings.Contains(subOut.String(), "keys=1") {
		t.Fatalf("agentless RunSubsystemWithIO output = %q, want keys=1", subOut.String())
	}
	if masterDials.Load() != before+1 {
		t.Fatalf("masterDials after RunSubsystemWithIO = %d, want %d", masterDials.Load(), before+1)
	}

	// 3. Internal probes (executeCommand(..., false) and RunProbeStream) must NOT request agent forwarding.
	probePlan, err := PlanCommand("probe-check", CommandOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("PlanCommand(probe): %v", err)
	}
	beforeAgentReqs := state.agentReqCount.Load()
	probeRes := proxyCli.executeCommand(t.Context(), probePlan, false)
	if probeRes.Err() != nil || strings.Contains(probeRes.Output, "unexpected-agent") {
		t.Fatalf("executeCommand(..., false) = (%q, %v), want clean probe", probeRes.Output, probeRes.Err())
	}
	stream, err := proxyCli.RunProbeStream(t.Context(), "probe-check")
	if err != nil {
		t.Fatalf("RunProbeStream: %v", err)
	}
	streamOut, _ := io.ReadAll(stream)
	if err := stream.Close(); err != nil {
		t.Fatalf("RunProbeStream Close: %v", err)
	}
	if strings.Contains(string(streamOut), "unexpected-agent") {
		t.Fatalf("RunProbeStream unexpectedly forwarded agent: %q", string(streamOut))
	}
	if state.agentReqCount.Load() != beforeAgentReqs {
		t.Fatalf("internal probes sent %d auth-agent-req@openssh.com requests, want 0", state.agentReqCount.Load()-beforeAgentReqs)
	}
	if _, loaded := sshAgentRouters.Load(proxyCli.sshClient); loaded {
		t.Fatal("agentless passenger sshClient must not register a local agent router")
	}
}

func assertPass4LocalAgentPassengerNeverRegistersRouter(
	t *testing.T,
	home string,
	port int,
	keyPath, sockPath, attackerAgentSock string,
	baseEnv Environment,
	masterDials *atomic.Int32,
) {
	t.Helper()
	var attackerDials atomic.Int32
	passengerEnv := baseEnv
	passengerEnv.AgentSocket = attackerAgentSock
	origDial := passengerEnv.DialAgent
	passengerEnv.DialAgent = func(ctx context.Context, sock string) (net.Conn, error) {
		attackerDials.Add(1)
		return origDial(ctx, sock)
	}

	opts := newPhase3TrustAllOptions(t, home)
	_ = opts.Set(OptionControlMaster, "no")
	_ = opts.Set(OptionControlPath, sockPath)
	_ = opts.Set(OptionForwardAgent, "yes")

	conn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
		"m": {NodeID: "m", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "key", KeyPath: keyPath, Options: opts},
	}}, WithEnvironment(passengerEnv))
	defer func() { _ = conn.CloseAll() }()

	cli, err := conn.Connect(t.Context(), "m")
	if err != nil {
		t.Fatalf("connect passenger with local agent: %v", err)
	}
	plan, _ := PlanCommand("query-agent", CommandOptions{Timeout: 5 * time.Second})
	before := masterDials.Load()
	res := cli.ExecuteCommand(t.Context(), plan)
	if res.Err() != nil || !strings.Contains(res.Output, "keys=1") {
		t.Fatalf("ExecuteCommand = (%q, %v), want keys=1", res.Output, res.Err())
	}
	var subOut bytes.Buffer
	if err := cli.RunSubsystemWithIO(t.Context(), "query-agent", strings.NewReader(""), &subOut, io.Discard, false); err != nil {
		t.Fatalf("RunSubsystemWithIO: %v", err)
	}
	if attackerDials.Load() != 0 {
		t.Fatalf("passenger local socket dialed %d times, want 0", attackerDials.Load())
	}
	if masterDials.Load() != before+2 {
		t.Fatalf("masterDials = %d, want %d", masterDials.Load(), before+2)
	}
	if _, loaded := sshAgentRouters.Load(cli.sshClient); loaded {
		t.Fatal("passenger sshClient registered a dead local agent router")
	}
}

func assertPass4PassengerOptionCombinations(
	t *testing.T,
	home string,
	port int,
	keyPath, sockPath string,
	baseEnv Environment,
	masterDials *atomic.Int32,
) {
	t.Helper()
	agentlessEnv := baseEnv
	agentlessEnv.AgentSocket = ""
	agentlessEnv.DialAgent = nil

	explicitSock := filepath.Join(home, "forward-only.sock")
	cases := []struct {
		name        string
		fwdSpec     string
		idSpec      string
		wantForward bool
	}{
		{name: "IdentityAgent=none + ForwardAgent=/explicit/sock", fwdSpec: explicitSock, idSpec: "none", wantForward: true},
		{name: "IdentityAgent=none + ForwardAgent=SSH_AUTH_SOCK", fwdSpec: "SSH_AUTH_SOCK", idSpec: "none", wantForward: true},
		{name: "IdentityAgent=none + ForwardAgent=yes", fwdSpec: "yes", idSpec: "none", wantForward: false},
		{name: "ForwardAgent=$UNSET_VAR", fwdSpec: "$UNSET_VAR", idSpec: "", wantForward: false},
		{name: "ForwardAgent=yes + IdentityAgent=$UNSET_VAR", fwdSpec: "yes", idSpec: "$UNSET_VAR", wantForward: false},
	}

	plan, _ := PlanCommand("query-agent", CommandOptions{Timeout: 5 * time.Second})
	for _, tc := range cases {
		opts := newPhase3TrustAllOptions(t, home)
		_ = opts.Set(OptionControlMaster, "no")
		_ = opts.Set(OptionControlPath, sockPath)
		if err := opts.Set(OptionForwardAgent, tc.fwdSpec); err != nil {
			t.Fatalf("%s: Set(ForwardAgent): %v", tc.name, err)
		}
		if tc.idSpec != "" {
			if err := opts.Set(OptionIdentityAgent, tc.idSpec); err != nil {
				t.Fatalf("%s: Set(IdentityAgent): %v", tc.name, err)
			}
		}

		conn := NewConnector(&mapConfigProvider{configs: map[string]*ClientConfig{
			"m": {NodeID: "m", Address: "127.0.0.1", Port: port, User: "alice", AuthType: "key", KeyPath: keyPath, Options: opts},
		}}, WithEnvironment(agentlessEnv))
		cli, err := conn.Connect(t.Context(), "m")
		if err != nil {
			_ = conn.CloseAll()
			t.Fatalf("%s: Connect failed: %v", tc.name, err)
		}

		before := masterDials.Load()
		res := cli.ExecuteCommand(t.Context(), plan)
		_ = conn.CloseAll()

		if tc.wantForward {
			if res.Err() != nil || !strings.Contains(res.Output, "keys=1") || masterDials.Load() != before+1 {
				t.Fatalf("%s: expected forwarding (keys=1, dial+1), got out=%q err=%v dials=%d->%d",
					tc.name, res.Output, res.Err(), before, masterDials.Load())
			}
		} else {
			if !strings.Contains(res.Output, "no-agent-req") || masterDials.Load() != before {
				t.Fatalf("%s: expected NO forwarding (no-agent-req, dial+0), got out=%q err=%v dials=%d->%d",
					tc.name, res.Output, res.Err(), before, masterDials.Load())
			}
		}
	}
}

// TestReviewPass4_M3_M4_UnixMuxClientDynamicPortsAndStreamLocalCleanCancel verifies
// over a real Unix control socket with DialMuxClient:
//   - multiple -O forward -L 0:hostA:80, -L 0:hostB:80, and -D 0 all succeed with
//     distinct OS-allocated ports, forward traffic, reject static port conflicts,
//     and clean up via CloseForward;
//   - opening local StreamLocal -L <dir>/sub//a.sock:hostA:80 cleans the path and
//     cancels cleanly via canonical <dir>/sub/a.sock.
func TestReviewPass4_M3_M4_UnixMuxClientDynamicPortsAndStreamLocalCleanCancel(t *testing.T) {
	setTestHome(t)
	dialConn := &pass3MuxForwardDialSSHConn{}
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	rawCli := cryptoSSH.NewClient(dialConn, chans, reqs)
	defer func() {
		close(chans)
		close(reqs)
		_ = rawCli.Close()
	}()

	sockDir := shortSocketDir(t)
	ctrlSock := filepath.Join(sockDir, "p4-fwd-ctrl.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:           ctrlSock,
		SSHClient:             rawCli,
		PersistEnabled:        true,
		PersistIndefinite:     true,
		StreamLocalBindUnlink: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	go func() { _ = srv.Serve() }()

	muxCli, err := DialMuxClient(t.Context(), ctrlSock)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	assertPass4UnixClientDynamicPortForwards(t, muxCli, srv)
	assertPass4UnixClientStreamLocalDirtyCancel(t, muxCli, srv, sockDir)
}

func assertPass4UnixClientDynamicPortForwards(t *testing.T, muxCli *MuxClient, srv *MuxServer) {
	t.Helper()
	ctx := t.Context()
	reqLA := ForwardRequest{Type: ForwardLocal, ListenHost: "127.0.0.1", ListenPort: 0, ConnectHost: "hostA", ConnectPort: 80}
	reqLB := ForwardRequest{Type: ForwardLocal, ListenHost: "127.0.0.1", ListenPort: 0, ConnectHost: "hostB", ConnectPort: 80}
	reqD := ForwardRequest{Type: ForwardDynamic, ListenHost: "127.0.0.1", ListenPort: 0}

	if _, err := muxCli.OpenForward(ctx, reqLA); err != nil {
		t.Fatalf("OpenForward(-L 0:hostA:80): %v", err)
	}
	if _, err := muxCli.OpenForward(ctx, reqLB); err != nil {
		t.Fatalf("OpenForward(-L 0:hostB:80): %v", err)
	}
	if _, err := muxCli.OpenForward(ctx, reqD); err != nil {
		t.Fatalf("OpenForward(-D 0): %v", err)
	}

	info, err := muxCli.RequestInfo(ctx, "channels")
	if err != nil {
		t.Fatalf("RequestInfo(channels): %v", err)
	}
	portA := extractPass4PortFromChannelsInfo(t, info, "1:127.0.0.1:", ":hostA:80")
	portB := extractPass4PortFromChannelsInfo(t, info, "1:127.0.0.1:", ":hostB:80")
	portD := extractPass4PortFromChannelsInfo(t, info, "3:127.0.0.1:", "::0")
	if portA == portB || portA == portD || portB == portD {
		t.Fatalf("expected 3 distinct allocated ports, got portA=%d portB=%d portD=%d", portA, portB, portD)
	}

	assertPass4TCPForwardBanner(t, portA, "target=hostA:80")
	assertPass4TCPForwardBanner(t, portB, "target=hostB:80")

	// Static -L <portA>:hostC:80 MUST fail with conflict!
	_, err = muxCli.OpenForward(ctx, ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  "127.0.0.1",
		ListenPort:  portA,
		ConnectHost: "hostC",
		ConnectPort: 80,
	})
	if err == nil || !strings.Contains(err.Error(), "port forwarding conflict on listen endpoint") {
		t.Fatalf("static conflict on allocated port %d err = %v, want conflict", portA, err)
	}

	if err := muxCli.CloseForward(ctx, ForwardRequest{Type: ForwardLocal, ListenHost: "127.0.0.1", ListenPort: portA, ConnectHost: "hostA", ConnectPort: 80}); err != nil {
		t.Fatalf("CloseForward(portA): %v", err)
	}
	if err := muxCli.CloseForward(ctx, reqLB); err != nil {
		t.Fatalf("CloseForward(-L 0:hostB:80): %v", err)
	}
	if err := muxCli.CloseForward(ctx, reqD); err != nil {
		t.Fatalf("CloseForward(-D 0): %v", err)
	}
	assertPass4MuxForwardTablesEmpty(t, srv)
}

func assertPass4UnixClientStreamLocalDirtyCancel(t *testing.T, muxCli *MuxClient, srv *MuxServer, sockDir string) {
	t.Helper()
	subDir := filepath.Join(sockDir, "sub")
	if err := os.MkdirAll(subDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dirtySock := subDir + "//a.sock"
	cleanSock := filepath.Join(subDir, "a.sock")

	if _, err := muxCli.OpenForward(t.Context(), ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  dirtySock,
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: "hostA",
		ConnectPort: 80,
	}); err != nil {
		t.Fatalf("OpenForward(%q): %v", dirtySock, err)
	}
	assertPass3UnixForwardTarget(t, cleanSock, "target=hostA:80")

	// Cancel using canonical cleanSock!
	if err := muxCli.CloseForward(t.Context(), ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  cleanSock,
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: "hostA",
		ConnectPort: 80,
	}); err != nil {
		t.Fatalf("CloseForward(%q): %v", cleanSock, err)
	}
	assertPass4MuxForwardTablesEmpty(t, srv)
}

func extractPass4PortFromChannelsInfo(t *testing.T, info, prefix, suffix string) uint32 {
	t.Helper()
	for line := range strings.SplitSeq(info, "\n") {
		trimmed := strings.TrimPrefix(strings.TrimSpace(line), "- ")
		if strings.HasPrefix(trimmed, prefix) && strings.HasSuffix(trimmed, suffix) {
			mid := strings.TrimSuffix(strings.TrimPrefix(trimmed, prefix), suffix)
			p, err := strconv.ParseUint(mid, 10, 32)
			if err != nil || p == 0 {
				t.Fatalf("invalid allocated port %q in channels line %q", mid, line)
			}
			return uint32(p)
		}
	}
	t.Fatalf("missing forward matching %q...%q in channels info:\n%s", prefix, suffix, info)
	return 0
}

func assertPass4TCPForwardBanner(t *testing.T, port uint32, want string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), 2*time.Second)
	if err != nil {
		t.Fatalf("dial local forward port %d: %v", port, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != want {
		t.Fatalf("local forward port %d read = (%q, %v), want %q", port, string(got), err, want)
	}
}

type pass4AgentExecSubsystemServer struct {
	hostSigner    cryptoSSH.Signer
	clientPub     cryptoSSH.PublicKey
	agentReqCount atomic.Int32
}

func startPass4AgentExecSubsystemServer(t *testing.T, state *pass4AgentExecSubsystemServer) int {
	t.Helper()
	serverCfg := &cryptoSSH.ServerConfig{
		PublicKeyCallback: func(_ cryptoSSH.ConnMetadata, key cryptoSSH.PublicKey) (*cryptoSSH.Permissions, error) {
			if bytes.Equal(key.Marshal(), state.clientPub.Marshal()) {
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, errors.New("unauthorized")
		},
	}
	serverCfg.AddHostKey(state.hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Go(func() {
		for {
			raw, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = raw.Close() }()
				sConn, chans, reqs, hsErr := cryptoSSH.NewServerConn(raw, serverCfg)
				if hsErr != nil {
					return
				}
				defer func() { _ = sConn.Close() }()
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
					wg.Go(func() {
						handlePass4AgentSession(sConn, ch, chReqs, state)
					})
				}
			})
		}
	})
	return ln.Addr().(*net.TCPAddr).Port
}

func handlePass4AgentSession(
	sConn cryptoSSH.Conn,
	ch cryptoSSH.Channel,
	chReqs <-chan *cryptoSSH.Request,
	state *pass4AgentExecSubsystemServer,
) {
	defer func() { _ = ch.Close() }()
	agentRequested := false
	for req := range chReqs {
		switch req.Type {
		case agentForwardRequestType:
			state.agentReqCount.Add(1)
			agentRequested = true
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec", "subsystem":
			var payload struct{ Value string }
			_ = cryptoSSH.Unmarshal(req.Payload, &payload)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			runPass4AgentAction(sConn, ch, payload.Value, agentRequested)
			return
		default:
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}
}

func runPass4AgentAction(sConn cryptoSSH.Conn, ch cryptoSSH.Channel, action string, agentRequested bool) {
	if !strings.Contains(action, "query-agent") {
		if agentRequested {
			_, _ = io.WriteString(ch, "unexpected-agent\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
			return
		}
		_, _ = io.WriteString(ch, "probe-ok\n")
		_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		return
	}
	if !agentRequested {
		_, _ = io.WriteString(ch, "no-agent-req\n")
		_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
		return
	}
	agCh, agReqs, err := sConn.OpenChannel(agentForwardChannelType, nil)
	if err != nil {
		_, _ = fmt.Fprintf(ch, "open-err:%v\n", err)
		_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
		return
	}
	go cryptoSSH.DiscardRequests(agReqs)
	keys, listErr := agent.NewClient(agCh).List()
	_ = agCh.Close()
	if listErr != nil {
		_, _ = fmt.Fprintf(ch, "list-err:%v\n", listErr)
		_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{1}))
		return
	}
	_, _ = fmt.Fprintf(ch, "keys=%d\n", len(keys))
	_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
}
