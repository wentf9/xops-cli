package ssh

import (
	"bytes"
	"context"
	"errors"
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

	"github.com/creack/pty"
	corelog "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type pass5AgentServerConfig struct {
	acceptAgentForward bool
	stallAgentForward  bool
	acceptExecOrShell  bool
}

func startPass5AgentTestClient(t *testing.T, home string, srvCfg pass5AgentServerConfig) (*Client, *diagnosticRecorder) {
	t.Helper()
	listener, sshServerCfg := startKeepAliveTestSSHServer(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	var workers sync.WaitGroup

	workers.Go(func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		serverConn, chans, reqs, err := cryptoSSH.NewServerConn(conn, sshServerCfg)
		if err != nil {
			return
		}
		stop := context.AfterFunc(ctx, func() { _ = serverConn.Close() })
		defer stop()
		defer func() { _ = serverConn.Close() }()

		workers.Go(func() { cryptoSSH.DiscardRequests(reqs) })
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported channel")
				continue
			}
			ch, inReqs, err := newCh.Accept()
			if err != nil {
				return
			}
			workers.Go(func() { servePass5AgentSession(ctx, ch, inReqs, srvCfg) })
		}
	})

	rawConn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		cancel()
		t.Fatalf("dial test SSH server: %v", err)
	}
	_ = rawConn.SetDeadline(time.Now().Add(10 * time.Second))

	cConn, chans, reqs, err := cryptoSSH.NewClientConn(rawConn, listener.Addr().String(), &cryptoSSH.ClientConfig{
		User:            "alice",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password("test")},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		_ = rawConn.Close()
		cancel()
		t.Fatalf("NewClientConn: %v", err)
	}
	rawCli := cryptoSSH.NewClient(cConn, chans, reqs)

	opts := &Options{}
	if err := opts.Set(OptionForwardAgent, "yes"); err != nil {
		t.Fatalf("Set(ForwardAgent=yes): %v", err)
	}

	cli := newClient(rawCli, rawConn, &ClientConfig{
		NodeID:  "pass5-node",
		Address: "127.0.0.1",
		Port:    22,
		User:    "alice",
		Options: opts,
	}, nil, "")
	cli.environment = Environment{
		HomeDir:     home,
		LocalUser:   "localuser",
		AgentSocket: filepath.Join(home, "agent.sock"),
		DialAgent: func(context.Context, string) (net.Conn, error) {
			c1, c2 := net.Pipe()
			_ = c2.Close()
			return c1, nil
		},
	}
	cli.handshakeTimeout = 150 * time.Millisecond
	recorder := &diagnosticRecorder{}
	cli.diagnostics = recorder

	t.Cleanup(func() {
		cancel()
		_ = cli.Close()
		_ = listener.Close()
		workers.Wait()
	})
	return cli, recorder
}

func servePass5AgentSession(ctx context.Context, ch cryptoSSH.Channel, inReqs <-chan *cryptoSSH.Request, cfg pass5AgentServerConfig) {
	defer func() { _ = ch.Close() }()
	sawPTY := false
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-inReqs:
			if !ok {
				return
			}
			if req.Type == "pty-req" {
				sawPTY = true
			}
			if handlePass5SessionReq(ctx, ch, req, cfg, sawPTY) {
				return
			}
		}
	}
}

func handlePass5SessionReq(ctx context.Context, ch cryptoSSH.Channel, req *cryptoSSH.Request, cfg pass5AgentServerConfig, sawPTY bool) bool {
	switch req.Type {
	case agentForwardRequestType:
		if cfg.stallAgentForward {
			<-ctx.Done()
			return true
		}
		if req.WantReply {
			_ = req.Reply(cfg.acceptAgentForward, nil)
		}
		return false
	case "pty-req", "env", "window-change":
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
		return false
	case "shell", "exec":
		if req.WantReply {
			_ = req.Reply(cfg.acceptExecOrShell, nil)
		}
		if !cfg.acceptExecOrShell {
			return false
		}
		if !sawPTY && req.Type == "exec" {
			_, _ = io.Copy(io.Discard, ch)
		} else {
			go func() { _, _ = io.Copy(io.Discard, ch) }()
		}
		_, _ = io.WriteString(ch, "ok\n")
		_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{Status: 0}))
		return true
	default:
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return false
	}
}

func openPass5OptionalPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("pty.Open unavailable on this platform: %v", err)
	}
	t.Cleanup(func() {
		_ = master.Close()
		_ = slave.Close()
	})
	return master, slave
}

func assertPass5NoAgentLeasesRemain(t *testing.T, cli *Client) {
	t.Helper()
	cli.activeMu.Lock()
	activeCount := len(cli.activeAgentLeases)
	cli.activeMu.Unlock()
	if activeCount != 0 {
		t.Fatalf("activeAgentLeases count = %d, want 0", activeCount)
	}
	if rAny, ok := sshAgentRouters.Load(cli.sshClient); ok {
		r := rAny.(*sshAgentChannelRouter)
		r.mu.Lock()
		routerLeases := len(r.leases)
		r.mu.Unlock()
		if routerLeases != 0 {
			t.Fatalf("sshAgentChannelRouter leases = %d, want 0", routerLeases)
		}
	}
}

func summarizePass5AgentDiagnostics(events []corelog.Diagnostic) (agentReqOutcomes []string, startedOps []string) {
	for _, ev := range events {
		if ev.Kind == corelog.SessionRequest && ev.Operation == agentForwardRequestType {
			agentReqOutcomes = append(agentReqOutcomes, ev.Outcome)
		}
		if ev.Kind == corelog.SessionStarted {
			startedOps = append(startedOps, ev.Operation)
		}
	}
	return agentReqOutcomes, startedOps
}

// TestPass5_SessionAgentForwardDiagnosticsAndTimeout verifies M2:
//   - enableSessionAgentForward never emits a spurious SessionStarted event for
//     "auth-agent-req@openssh.com";
//   - SessionRequest records ["sending", "accepted"] when accepted and
//     ["sending", "rejected"] when rejected (with non-fatal continuation);
//   - zero SessionStarted events are emitted when subsequent "shell"/"exec" is rejected;
//   - stalling "auth-agent-req@openssh.com" past handshakeTimeout aborts setup
//     with context.DeadlineExceeded rather than an opaque EOF and cleans up the
//     session and agent lease across session execution paths.
func TestPass5_SessionAgentForwardDiagnosticsAndTimeout(t *testing.T) {
	home := setTestHome(t)

	for _, mode := range []string{"RunScript", "ShellWithIO", "RunInteractivePlanWithIO"} {
		t.Run(mode+"/accepted_agent_and_started", func(t *testing.T) {
			assertPass5SessionAgentOutcome(t, home, mode, pass5AgentServerConfig{
				acceptAgentForward: true,
				acceptExecOrShell:  true,
			}, "accepted", 1, false)
		})
		t.Run(mode+"/rejected_agent_continues_cleanly", func(t *testing.T) {
			assertPass5SessionAgentOutcome(t, home, mode, pass5AgentServerConfig{
				acceptAgentForward: false,
				acceptExecOrShell:  true,
			}, "rejected", 1, false)
		})
		t.Run(mode+"/rejected_exec_or_shell_emits_zero_started", func(t *testing.T) {
			assertPass5SessionAgentOutcome(t, home, mode, pass5AgentServerConfig{
				acceptAgentForward: true,
				acceptExecOrShell:  false,
			}, "accepted", 0, true)
		})
	}

	for _, mode := range []string{"RunScript", "ShellWithIO", "RunInteractivePlanWithIO", "RunStream", "RunCommandPlanWithIO"} {
		t.Run(mode+"/stalled_agent_request_returns_deadline_exceeded", func(t *testing.T) {
			assertPass5StalledAgentRequest(t, home, mode)
		})
	}
}

func invokePass5SessionMode(t *testing.T, cli *Client, mode string) error {
	t.Helper()
	ctx := t.Context()
	switch mode {
	case "RunScript":
		_, err := cli.RunScript(ctx, "echo hi\n")
		return err
	case "ShellWithIO":
		_, slave := openPass5OptionalPTY(t)
		var out, errBuf bytes.Buffer
		return cli.ShellWithIO(ctx, InteractiveIO{Stdin: slave, Stdout: &out, Stderr: &errBuf})
	case "RunInteractivePlanWithIO":
		plan, err := PlanCommand("echo hi", CommandOptions{})
		if err != nil {
			t.Fatalf("PlanCommand: %v", err)
		}
		_, slave := openPass5OptionalPTY(t)
		var out, errBuf bytes.Buffer
		return cli.RunInteractivePlanWithIO(ctx, plan, InteractiveIO{Stdin: slave, Stdout: &out, Stderr: &errBuf})
	case "RunStream":
		rc, err := cli.RunStream(ctx, "echo hi")
		if rc != nil {
			_ = rc.Close()
		}
		return err
	case "RunCommandPlanWithIO":
		plan, err := PlanCommand("echo hi", CommandOptions{})
		if err != nil {
			t.Fatalf("PlanCommand: %v", err)
		}
		var out, errBuf bytes.Buffer
		return cli.RunCommandPlanWithIO(ctx, plan, strings.NewReader(""), &out, &errBuf)
	default:
		t.Fatalf("unknown mode %q", mode)
		return nil
	}
}

func assertPass5SessionAgentOutcome(
	t *testing.T,
	home string,
	mode string,
	srvCfg pass5AgentServerConfig,
	wantAgentOutcome string,
	wantStartedCount int,
	wantErr bool,
) {
	t.Helper()
	cli, recorder := startPass5AgentTestClient(t, home, srvCfg)
	err := invokePass5SessionMode(t, cli, mode)
	if (err != nil) != wantErr {
		t.Fatalf("%s error = %v, wantErr=%v", mode, err, wantErr)
	}

	agentOutcomes, startedOps := summarizePass5AgentDiagnostics(recorder.snapshot())
	if len(agentOutcomes) != 2 || agentOutcomes[0] != "sending" || agentOutcomes[1] != wantAgentOutcome {
		t.Fatalf("%s agent SessionRequest outcomes = %v, want [sending %s]", mode, agentOutcomes, wantAgentOutcome)
	}
	for _, op := range startedOps {
		if op == agentForwardRequestType {
			t.Fatalf("%s emitted spurious SessionStarted for %s: %v", mode, agentForwardRequestType, startedOps)
		}
	}
	if len(startedOps) != wantStartedCount {
		t.Fatalf("%s SessionStarted ops = %v (len %d), want len %d", mode, startedOps, len(startedOps), wantStartedCount)
	}
	assertPass5NoAgentLeasesRemain(t, cli)
}

func assertPass5StalledAgentRequest(t *testing.T, home, mode string) {
	t.Helper()
	cli, recorder := startPass5AgentTestClient(t, home, pass5AgentServerConfig{
		stallAgentForward: true,
		acceptExecOrShell: true,
	})
	err := invokePass5SessionMode(t, cli, mode)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%s stalled agent request err = %v, want errors.Is(context.DeadlineExceeded)", mode, err)
	}

	agentOutcomes, startedOps := summarizePass5AgentDiagnostics(recorder.snapshot())
	if len(agentOutcomes) != 2 || agentOutcomes[0] != "sending" || agentOutcomes[1] != "failed or interrupted" {
		t.Fatalf("%s stalled agent SessionRequest outcomes = %v, want [sending failed or interrupted]", mode, agentOutcomes)
	}
	if len(startedOps) != 0 {
		t.Fatalf("%s stalled agent emitted SessionStarted = %v, want none", mode, startedOps)
	}
	assertPass5NoAgentLeasesRemain(t, cli)
}

// TestPass5_MuxDynamicForwardInFlightEndpointRace verifies M3:
// When a dynamic-port forward (-R 0 or -L 0) publishes an allocated port P while
// a concurrent static forward holds an inFlight reservation slot on port P:
//   - Case A (static bind fails -> abortReservedForward): s.listenEndpoints[dynKey]
//     promotes the dynamic fallbackEntry instead of deleting dynKey, preserving
//     conflict detection and canonical-host CloseForward (-O cancel -R 127.0.0.1:P:...);
//   - Case B (permissive server accepts static bind -> commitReservedForward):
//     static request fails with "port forwarding conflict on listen endpoint",
//     closes its unpublished listener, and preserves the dynamic entry unmerged
//     (both for distinct destination and identical forwardKey);
//   - Case C (dynamic forward canceled while static slot is still inFlight):
//     deleteEndpointEntryLocked clears slot.fallbackEntry so the static slot
//     commits cleanly once unblocked.
func TestPass5_MuxDynamicForwardInFlightEndpointRace(t *testing.T) {
	setTestHome(t)
	t.Run("case_a_static_bind_fails_promotes_dynamic_endpoint", assertPass5RaceAbortPromotesDynamic)
	t.Run("case_b1_permissive_static_bind_conflicts_and_preserves_dynamic", assertPass5RaceCommitConflictsAndPreservesDynamic)
	t.Run("case_b2_same_key_static_commit_does_not_merge_into_dynamic", assertPass5RaceSameKeyDoesNotMergeDynamic)
	t.Run("case_c_cancel_dynamic_during_inflight_clears_fallback", assertPass5RaceCancelDynamicWhileStaticInFlight)
}

func assertPass5RaceAbortPromotesDynamic(t *testing.T) {
	const portP = uint32(45101)
	mockConn := newPass5StagedMuxForwardSSHConn(portP, false)
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp4")
	defer cleanup()

	staticErrCh := startPass5StagedStaticRemoteFwd(srv, mockConn, 101, "127.0.0.1", portP, "hostB", 80)

	// Open dynamic -R localhost:0:hostA:80 while static 127.0.0.1:portP is inFlight!
	gotPort := mustPass4OpenRemotePortFwd(t, srv, MuxFwdRequest{
		RequestID:   102,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "localhost",
		ListenPort:  0,
		ConnectHost: "hostA",
		ConnectPort: 80,
	})
	if gotPort != portP {
		t.Fatalf("dynamic remote port = %d, want %d", gotPort, portP)
	}

	// Unblock static bind to fail -> triggers abortReservedForward(dynKey, slotB).
	close(mockConn.releaseStatic)
	res := <-staticErrCh
	if res.pktType != MUX_S_FAILURE {
		t.Fatalf("static bind failure reply = (0x%x, %q), want MUX_S_FAILURE", res.pktType, res.reason)
	}

	// Verify conflicting static -R 127.0.0.1:portP:hostC:80 fails fast in acquireForwardEndpoint!
	callsBeforeConflict := mockConn.tcpipFwdCalls.Load()
	assertPass4OpenFwdConflict(t, srv, MuxFwdRequest{
		RequestID:   103,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "hostC",
		ConnectPort: 80,
	})
	if mockConn.tcpipFwdCalls.Load() != callsBeforeConflict {
		t.Fatal("expected fast endpoint conflict before upstream tcpip-forward")
	}

	// Cancel dynamic forward via canonical equivalent host 127.0.0.1 (different keyHost from "localhost")!
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{
		RequestID:   104,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "hostA",
		ConnectPort: 80,
	})
	assertPass4MuxForwardTablesEmpty(t, srv)
}

func assertPass5RaceCommitConflictsAndPreservesDynamic(t *testing.T) {
	const portP = uint32(45102)
	mockConn := newPass5StagedMuxForwardSSHConn(portP, true)
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp4")
	defer cleanup()

	staticResCh := startPass5StagedStaticRemoteFwd(srv, mockConn, 201, "127.0.0.1", portP, "hostB", 80)

	gotPort := mustPass4OpenRemotePortFwd(t, srv, MuxFwdRequest{
		RequestID:   202,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "localhost",
		ListenPort:  0,
		ConnectHost: "hostA",
		ConnectPort: 80,
	})
	if gotPort != portP {
		t.Fatalf("dynamic remote port = %d, want %d", gotPort, portP)
	}

	// Unblock permissive static bind -> commitReservedForwardSlot must reject with conflict and close unpublished listener!
	close(mockConn.releaseStatic)
	res := <-staticResCh
	if res.pktType != MUX_S_FAILURE || !strings.Contains(res.reason, "port forwarding conflict on listen endpoint") {
		t.Fatalf("permissive static open = (0x%x, %q), want conflict MUX_S_FAILURE", res.pktType, res.reason)
	}
	if gotCancels := mockConn.cancelTcpipCalls.Load(); gotCancels != 1 {
		t.Fatalf("cancelTcpipCalls after unpublished static close = %d, want 1", gotCancels)
	}

	// Verify only the dynamic forward remains (1 entry) and cancels via canonical 127.0.0.1!
	if got := srv.forwardCount(); got != 1 {
		t.Fatalf("forwardCount = %d, want 1", got)
	}
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{
		RequestID:   203,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "hostA",
		ConnectPort: 80,
	})
	assertPass4MuxForwardTablesEmpty(t, srv)
}

func assertPass5RaceSameKeyDoesNotMergeDynamic(t *testing.T) {
	const portP = uint32(45103)
	mockConn := &pass4MuxForwardSSHConn{nextRemotePort: 45100}
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp4")
	defer cleanup()

	staticResolved, err := srv.resolveMuxForwardListenSpec(MUX_FWD_REMOTE, "127.0.0.1", portP)
	if err != nil {
		t.Fatalf("resolveMuxForwardListenSpec static: %v", err)
	}
	listenKey, ok := makeForwardListenKey(MUX_FWD_REMOTE, staticResolved)
	if !ok {
		t.Fatal("expected makeForwardListenKey ok=true")
	}
	slot, outcome := srv.acquireForwardEndpoint(listenKey, MUX_FWD_REMOTE, "hostA", 80)
	if outcome != muxEndpointReserved || slot == nil {
		t.Fatalf("acquireForwardEndpoint = (%v, %v), want reserved", slot, outcome)
	}

	dynResolved, err := srv.resolveMuxForwardListenSpec(MUX_FWD_REMOTE, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("resolveMuxForwardListenSpec dynamic: %v", err)
	}
	dynLn := &pass5FakeListener{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(portP)}}
	_, dynEntry, allocPort, dynAlloc, dup, conflict, shuttingDown := srv.registerBoundMuxForward(
		MUX_FWD_REMOTE, dynResolved, "hostA", 80, forwardListenKey{}, nil, dynLn,
	)
	if shuttingDown || conflict || dup || !dynAlloc || allocPort != portP || dynEntry == nil {
		t.Fatalf("dynamic registerBoundMuxForward unexpected result: alloc=%d dyn=%v dup=%v conflict=%v", allocPort, dynAlloc, dup, conflict)
	}

	// Now commit static candidate with IDENTICAL forwardKey ("127.0.0.1", portP, "hostA", 80):
	// must return conflict=true BEFORE LoadOrStore without incrementing dynEntry.refs!
	staticLn := &pass5FakeListener{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(portP)}}
	_, gotEntry, _, _, sDup, sConflict, sShut := srv.registerBoundMuxForward(
		MUX_FWD_REMOTE, staticResolved, "hostA", 80, listenKey, slot, staticLn,
	)
	if sShut || sDup || !sConflict || gotEntry != nil {
		t.Fatalf("static registerBoundMuxForward = (entry=%v, dup=%v, conflict=%v, shut=%v), want conflict=true", gotEntry, sDup, sConflict, sShut)
	}
	if !staticLn.closed.Load() {
		t.Fatal("expected unpublished static listener to be closed on conflict")
	}
	if dynLn.closed.Load() {
		t.Fatal("dynamic listener must remain open")
	}
	if dynEntry.refs != 1 {
		t.Fatalf("dynEntry.refs = %d, want 1 (must not merge static into dynamic)", dynEntry.refs)
	}

	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{
		RequestID:   301,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "hostA",
		ConnectPort: 80,
	})
	if !dynLn.closed.Load() {
		t.Fatal("expected dynamic listener closed after single CloseForward")
	}
	assertPass4MuxForwardTablesEmpty(t, srv)
}

func assertPass5RaceCancelDynamicWhileStaticInFlight(t *testing.T) {
	const portP = uint32(45104)
	mockConn := newPass5StagedMuxForwardSSHConn(portP, true)
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp4")
	defer cleanup()

	staticResCh := startPass5StagedStaticRemoteFwd(srv, mockConn, 401, "127.0.0.1", portP, "hostB", 80)

	gotPort := mustPass4OpenRemotePortFwd(t, srv, MuxFwdRequest{
		RequestID:   402,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "localhost",
		ListenPort:  0,
		ConnectHost: "hostA",
		ConnectPort: 80,
	})
	if gotPort != portP {
		t.Fatalf("dynamic remote port = %d, want %d", gotPort, portP)
	}

	// Cancel dynamic forward via canonical 127.0.0.1 WHILE static slot is still inFlight!
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{
		RequestID:   403,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "hostA",
		ConnectPort: 80,
	})

	// Now unblock static bind -> fallbackEntry was cleared, so static forward commits cleanly!
	close(mockConn.releaseStatic)
	res := <-staticResCh
	if res.pktType != MUX_S_OK {
		t.Fatalf("static open after dynamic cancel = (0x%x, %q), want MUX_S_OK", res.pktType, res.reason)
	}

	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{
		RequestID:   404,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "hostB",
		ConnectPort: 80,
	})
	assertPass4MuxForwardTablesEmpty(t, srv)
}

type pass5MuxReply struct {
	pktType uint32
	reason  string
}

func startPass5StagedStaticRemoteFwd(
	srv *MuxServer,
	mockConn *pass5StagedMuxForwardSSHConn,
	reqID uint32,
	listenHost string,
	listenPort uint32,
	connectHost string,
	connectPort uint32,
) <-chan pass5MuxReply {
	resCh := make(chan pass5MuxReply, 1)
	go func() {
		c1, c2 := net.Pipe()
		defer func() {
			_ = c1.Close()
			_ = c2.Close()
		}()
		go func() {
			_ = srv.handleOpenFwd(c1, MuxFwdRequest{
				RequestID:   reqID,
				FwdType:     MUX_FWD_REMOTE,
				ListenHost:  listenHost,
				ListenPort:  listenPort,
				ConnectHost: connectHost,
				ConnectPort: connectPort,
			})
		}()
		pt, payload, err := ReadMuxPacket(c2)
		if err != nil {
			resCh <- pass5MuxReply{pktType: 0, reason: err.Error()}
			return
		}
		_, reason, _ := DecodeMuxError(payload)
		resCh <- pass5MuxReply{pktType: pt, reason: reason}
	}()
	<-mockConn.staticInFlight
	return resCh
}

type pass5StagedMuxForwardSSHConn struct {
	dummyMuxGateConn
	initOnce         sync.Once
	closeOnce        sync.Once
	closedCh         chan struct{}
	dynamicPort      uint32
	acceptStaticBind bool
	staticInFlight   chan struct{}
	staticOnce       sync.Once
	releaseStatic    chan struct{}
	tcpipFwdCalls    atomic.Int32
	cancelTcpipCalls atomic.Int32
}

func newPass5StagedMuxForwardSSHConn(dynamicPort uint32, acceptStaticBind bool) *pass5StagedMuxForwardSSHConn {
	return &pass5StagedMuxForwardSSHConn{
		dynamicPort:      dynamicPort,
		acceptStaticBind: acceptStaticBind,
		staticInFlight:   make(chan struct{}),
		releaseStatic:    make(chan struct{}),
	}
}

func (m *pass5StagedMuxForwardSSHConn) closed() chan struct{} {
	m.initOnce.Do(func() { m.closedCh = make(chan struct{}) })
	return m.closedCh
}

func (m *pass5StagedMuxForwardSSHConn) Wait() error {
	<-m.closed()
	return io.EOF
}

func (m *pass5StagedMuxForwardSSHConn) Close() error {
	ch := m.closed()
	m.closeOnce.Do(func() { close(ch) })
	return nil
}

func (m *pass5StagedMuxForwardSSHConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	switch name {
	case "tcpip-forward":
		m.tcpipFwdCalls.Add(1)
		var req struct {
			BindAddr string
			BindPort uint32
		}
		_ = cryptoSSH.Unmarshal(payload, &req)
		if req.BindPort == 0 && wantReply {
			return true, cryptoSSH.Marshal(struct{ Port uint32 }{Port: m.dynamicPort}), nil
		}
		if req.BindPort == m.dynamicPort {
			m.staticOnce.Do(func() { close(m.staticInFlight) })
			select {
			case <-m.releaseStatic:
			case <-m.closed():
				return false, nil, io.EOF
			}
			return m.acceptStaticBind, nil, nil
		}
		return true, nil, nil
	case "cancel-tcpip-forward":
		m.cancelTcpipCalls.Add(1)
		return true, nil, nil
	default:
		return false, nil, errors.New("unsupported global request: " + strconv.Quote(name))
	}
}

type pass5FakeListener struct {
	addr   net.Addr
	closed atomic.Bool
}

func (l *pass5FakeListener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (l *pass5FakeListener) Close() error {
	l.closed.Store(true)
	return nil
}

func (l *pass5FakeListener) Addr() net.Addr {
	return l.addr
}
