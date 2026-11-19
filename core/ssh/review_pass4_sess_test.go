package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// TestReviewPass4_M2_ForwardAgentOptionEvaluatorUnification verifies that
// ResolveForwardAgent and Client.shouldRequestMuxProxyAgentForward share one
// unified option evaluator (resolveForwardAgentSpec):
//   - IdentityAgent="none" suppresses ForwardAgent="yes"/"true", but does NOT
//     suppress explicit ForwardAgent="/explicit/sock" or ForwardAgent="SSH_AUTH_SOCK";
//   - unset $VAR / ${VAR} in ForwardAgent or IdentityAgent fails closed (returns false);
//   - empty env.AgentSocket returns false in ResolveForwardAgent while returning true
//     for multiplexed proxy passengers (allowing Master's verified agent to be requested).
func TestReviewPass4_M2_ForwardAgentOptionEvaluatorUnification(t *testing.T) {
	home := setTestHome(t)
	envWithSock := Environment{
		HomeDir:     home,
		LocalUser:   "localbob",
		AgentSocket: filepath.Join(home, "default-env.sock"),
		LookupEnv: func(key string) (string, bool) {
			if key == "SET_AGENT_SOCK" {
				return filepath.Join(home, "from-env.sock"), true
			}
			return "", false
		},
	}
	envEmptySock := envWithSock
	envEmptySock.AgentSocket = ""

	assertPass4MuxProxyOptionMatrix(t, home, envWithSock, envEmptySock)
	assertPass4ResolveForwardAgentErrorCases(t, envWithSock)
}

func assertPass4MuxProxyOptionMatrix(t *testing.T, home string, envWithSock, envEmptySock Environment) {
	t.Helper()
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	rawCli := cryptoSSH.NewClient(&muxProxySSHConn{Conn: &dummyMuxGateConn{}}, chans, reqs)
	defer func() {
		close(chans)
		close(reqs)
		_ = rawCli.Close()
	}()

	explicitSock := filepath.Join(home, "explicit-forward.sock")
	cases := []struct {
		name         string
		fwdSpec      string
		idSpec       string
		env          Environment
		wantDirectOK bool
		wantProxyOK  bool
	}{
		{name: "empty ForwardAgent", fwdSpec: "", idSpec: "", env: envWithSock, wantDirectOK: false, wantProxyOK: false},
		{name: "ForwardAgent=no", fwdSpec: "no", idSpec: explicitSock, env: envWithSock, wantDirectOK: false, wantProxyOK: false},
		{name: "ForwardAgent=yes IdentityAgent=none", fwdSpec: "yes", idSpec: "none", env: envWithSock, wantDirectOK: false, wantProxyOK: false},
		{name: "ForwardAgent=yes empty env sock", fwdSpec: "yes", idSpec: "", env: envEmptySock, wantDirectOK: false, wantProxyOK: true},
		{name: "ForwardAgent=yes IdentityAgent=SSH_AUTH_SOCK empty env", fwdSpec: "yes", idSpec: "SSH_AUTH_SOCK", env: envEmptySock, wantDirectOK: false, wantProxyOK: true},
		{name: "ForwardAgent=SSH_AUTH_SOCK IdentityAgent=none empty env", fwdSpec: "SSH_AUTH_SOCK", idSpec: "none", env: envEmptySock, wantDirectOK: false, wantProxyOK: true},
		{name: "ForwardAgent=SSH_AUTH_SOCK IdentityAgent=none with env", fwdSpec: "SSH_AUTH_SOCK", idSpec: "none", env: envWithSock, wantDirectOK: true, wantProxyOK: true},
		{name: "ForwardAgent=explicit IdentityAgent=none", fwdSpec: explicitSock, idSpec: "none", env: envEmptySock, wantDirectOK: true, wantProxyOK: true},
		{name: "ForwardAgent=tilde IdentityAgent=none", fwdSpec: "~/fwd-%r.sock", idSpec: "none", env: envEmptySock, wantDirectOK: true, wantProxyOK: true},
		{name: "ForwardAgent=$SET_AGENT_SOCK IdentityAgent=none", fwdSpec: "$SET_AGENT_SOCK", idSpec: "none", env: envEmptySock, wantDirectOK: true, wantProxyOK: true},
		{name: "ForwardAgent=yes IdentityAgent=$SET_AGENT_SOCK", fwdSpec: "yes", idSpec: "$SET_AGENT_SOCK", env: envEmptySock, wantDirectOK: true, wantProxyOK: true},
		{name: "ForwardAgent=$UNSET_VAR", fwdSpec: "$UNSET_VAR", idSpec: "", env: envWithSock, wantDirectOK: false, wantProxyOK: false},
		{name: "ForwardAgent=${UNSET_VAR}/agent.sock", fwdSpec: "${UNSET_VAR}/agent.sock", idSpec: "none", env: envWithSock, wantDirectOK: false, wantProxyOK: false},
		{name: "ForwardAgent=yes IdentityAgent=$UNSET_VAR", fwdSpec: "yes", idSpec: "$UNSET_VAR", env: envWithSock, wantDirectOK: false, wantProxyOK: false},
		{name: "ForwardAgent=yes IdentityAgent=${UNSET_VAR}/id.sock", fwdSpec: "yes", idSpec: "${UNSET_VAR}/id.sock", env: envWithSock, wantDirectOK: false, wantProxyOK: false},
	}

	target := TargetContext{Host: "10.0.0.10", Port: 22, User: "alice", OriginalHost: "web"}
	for _, tc := range cases {
		_, gotDirect, _ := ResolveForwardAgent(tc.fwdSpec, tc.idSpec, tc.env, target)
		if gotDirect != tc.wantDirectOK {
			t.Fatalf("%s: ResolveForwardAgent(%q, %q) enabled=%v, want %v", tc.name, tc.fwdSpec, tc.idSpec, gotDirect, tc.wantDirectOK)
		}

		opts := &Options{}
		if tc.fwdSpec != "" {
			if err := opts.Set(OptionForwardAgent, tc.fwdSpec); err != nil {
				t.Fatalf("%s: Set(ForwardAgent=%q): %v", tc.name, tc.fwdSpec, err)
			}
		}
		if tc.idSpec != "" {
			if err := opts.Set(OptionIdentityAgent, tc.idSpec); err != nil {
				t.Fatalf("%s: Set(IdentityAgent=%q): %v", tc.name, tc.idSpec, err)
			}
		}
		cli := &Client{
			sshClient:     rawCli,
			muxSocketPath: "/tmp/mock-mux.sock",
			environment:   tc.env,
			connCfg: ConnectionConfig{
				NodeID:       "web",
				Address:      "10.0.0.10",
				Port:         22,
				User:         "alice",
				OriginalHost: "web",
				Options:      opts,
			},
		}
		wantAgent, release := cli.prepareChannelAgentForward(t.Context())
		release()
		if wantAgent != tc.wantProxyOK {
			t.Fatalf("%s: prepareChannelAgentForward(%q, %q) wantAgent=%v, want %v", tc.name, tc.fwdSpec, tc.idSpec, wantAgent, tc.wantProxyOK)
		}
		if _, loaded := sshAgentRouters.Load(rawCli); loaded {
			t.Fatalf("%s: mux proxy client must never register a local sshAgentChannelRouter", tc.name)
		}
	}
}

func assertPass4ResolveForwardAgentErrorCases(t *testing.T, env Environment) {
	t.Helper()
	target := TargetContext{Host: "10.0.0.10", Port: 22, User: "alice"}
	if _, ok, err := ResolveForwardAgent("$UNSET_FWD", "none", env, target); err == nil || ok {
		t.Fatalf("ResolveForwardAgent($UNSET_FWD) = (ok=%v, err=%v), want error", ok, err)
	}
	if _, ok, err := ResolveForwardAgent("yes", "$UNSET_ID", env, target); err == nil || ok {
		t.Fatalf("ResolveForwardAgent(yes, $UNSET_ID) = (ok=%v, err=%v), want error", ok, err)
	}
}

// TestReviewPass4_M3_DynamicPortZeroLocalDynamicAndRemoteForwards verifies that
// ephemeral port 0 forwards (-L 0, -D 0, -R 0) never reserve a singleton port 0
// slot in s.listenEndpoints, all succeed with distinct allocated ports, record
// their actual allocated ports in s.listenEndpoints to catch subsequent static
// conflicts, and clean up symmetrically on CloseForward.
func TestReviewPass4_M3_DynamicPortZeroLocalDynamicAndRemoteForwards(t *testing.T) {
	setTestHome(t)
	mockConn := &pass4MuxForwardSSHConn{nextRemotePort: 45000}
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp")
	defer cleanup()

	// Open two -L 0 forwards, two -D 0 forwards, and two -R 0 forwards on the same MuxServer.
	mustPass4OpenFwdOK(t, srv, MuxFwdRequest{RequestID: 1, FwdType: MUX_FWD_LOCAL, ListenHost: "127.0.0.1", ListenPort: 0, ConnectHost: "hostA", ConnectPort: 80})
	mustPass4OpenFwdOK(t, srv, MuxFwdRequest{RequestID: 2, FwdType: MUX_FWD_LOCAL, ListenHost: "127.0.0.1", ListenPort: 0, ConnectHost: "hostB", ConnectPort: 80})
	mustPass4OpenFwdOK(t, srv, MuxFwdRequest{RequestID: 3, FwdType: MUX_FWD_DYNAMIC, ListenHost: "127.0.0.1", ListenPort: 0})
	mustPass4OpenFwdOK(t, srv, MuxFwdRequest{RequestID: 4, FwdType: MUX_FWD_DYNAMIC, ListenHost: "127.0.0.1", ListenPort: 0})
	rPortA := mustPass4OpenRemotePortFwd(t, srv, MuxFwdRequest{RequestID: 5, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: 0, ConnectHost: "hostA", ConnectPort: 80})
	rPortB := mustPass4OpenRemotePortFwd(t, srv, MuxFwdRequest{RequestID: 6, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: 0, ConnectHost: "hostB", ConnectPort: 80})
	if rPortA == 0 || rPortB == 0 || rPortA == rPortB {
		t.Fatalf("allocated remote ports = (%d, %d), want distinct non-zero ports", rPortA, rPortB)
	}

	localPorts := collectPass4AllocatedPorts(t, srv)
	if len(localPorts) != 4 {
		t.Fatalf("allocated local/dynamic ports = %v, want 4 distinct ports", localPorts)
	}

	// Static -L <allocatedLocalPort>:hostC:80 and -R <rPortA>:hostC:80 MUST conflict immediately!
	assertPass4OpenFwdConflict(t, srv, MuxFwdRequest{
		RequestID:   10,
		FwdType:     MUX_FWD_LOCAL,
		ListenHost:  "127.0.0.1",
		ListenPort:  localPorts[0],
		ConnectHost: "hostC",
		ConnectPort: 80,
	})
	beforeRemoteCalls := mockConn.tcpipFwdCalls.Load()
	assertPass4OpenFwdConflict(t, srv, MuxFwdRequest{
		RequestID:   11,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  rPortA,
		ConnectHost: "hostC",
		ConnectPort: 80,
	})
	if mockConn.tcpipFwdCalls.Load() != beforeRemoteCalls {
		t.Fatal("conflicting static remote forward called upstream tcpip-forward")
	}

	// Cancel all 6 forwards (mixing ListenPort=0 and explicit allocated port cancels) and verify empty tables.
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{RequestID: 20, FwdType: MUX_FWD_LOCAL, ListenHost: "127.0.0.1", ListenPort: 0, ConnectHost: "hostA", ConnectPort: 80})
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{RequestID: 21, FwdType: MUX_FWD_LOCAL, ListenHost: "127.0.0.1", ListenPort: 0, ConnectHost: "hostB", ConnectPort: 80})
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{RequestID: 22, FwdType: MUX_FWD_DYNAMIC, ListenHost: "127.0.0.1", ListenPort: 0})
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{RequestID: 23, FwdType: MUX_FWD_DYNAMIC, ListenHost: "127.0.0.1", ListenPort: 0})
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{RequestID: 24, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: 0, ConnectHost: "hostA", ConnectPort: 80})
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{RequestID: 25, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: rPortB, ConnectHost: "hostB", ConnectPort: 80})

	assertPass4MuxForwardTablesEmpty(t, srv)
}

func collectPass4AllocatedPorts(t *testing.T, srv *MuxServer) []uint32 {
	t.Helper()
	srv.idleMu.Lock()
	defer srv.idleMu.Unlock()
	seen := make(map[uint32]struct{})
	var localPorts []uint32
	for k, state := range srv.forwardTable.endpoints {
		if k.listenPort == 0 {
			t.Fatalf("unexpected listenPort=0 singleton key in forwardTable.endpoints: %+v", k)
		}
		if state == nil || state.state != forwardSlotActive || state.entry == nil {
			t.Fatalf("unexpected invalid state in forwardTable.endpoints[%+v]: %+v", k, state)
		}
		if k.fwdScope == muxForwardScopeLocal {
			if _, dup := seen[k.listenPort]; dup {
				t.Fatalf("duplicate local port %d in listenEndpoints", k.listenPort)
			}
			seen[k.listenPort] = struct{}{}
			localPorts = append(localPorts, k.listenPort)
		}
	}
	return localPorts
}

// TestReviewPass4_M4_MuxForwardEndpointNormalizationAndCommitMetadata verifies:
//   - (a) -4 (tcp4) and -6 (tcp6) MuxServer normalize empty ListenHost, localhost,
//     and explicit 127.0.0.1 / ::1 onto the same forwardListenKey so conflicts fail
//     before calling sshClient.Listen and duplicate opens/cancels stay symmetric,
//     while dual-stack tcp keeps 127.0.0.1 and ::1 distinct;
//   - (b) remote Unix StreamLocal cleans /tmp/d//a.sock -> /tmp/d/a.sock in both
//     s.forwards and s.listenEndpoints so opening /tmp/d/a.sock + /tmp/d//a.sock
//     and canceling both paths decrements refs symmetrically to 0;
//   - (c) commitReservedForward populates listenKey/hasListenKey when LoadOrStore
//     hits an existing entry lacking hasListenKey.
func TestReviewPass4_M4_MuxForwardEndpointNormalizationAndCommitMetadata(t *testing.T) {
	setTestHome(t)
	t.Run("tcp4 and tcp6 loopback conflict and duplicate ref symmetry", assertPass4LoopbackFamilyConflictAndSymmetry)
	t.Run("dual-stack tcp keeps 127.0.0.1 and ::1 distinct while matching localhost", assertPass4DualStackLoopbackSemantics)
	t.Run("remote StreamLocal path cleaning symmetric refs and cancel", assertPass4RemoteStreamLocalPathCleanSymmetry)
	t.Run("commitReservedForward backfills missing listenKey metadata", assertPass4CommitReservedForwardBackfillsListenKey)
}

func assertPass4LoopbackFamilyConflictAndSymmetry(t *testing.T) {
	for _, tc := range []struct {
		dialNet      string
		explicitLoop string
	}{
		{dialNet: "tcp4", explicitLoop: "127.0.0.1"},
		{dialNet: "tcp6", explicitLoop: "[::1]"},
	} {
		t.Run(tc.dialNet, func(t *testing.T) {
			mockConn := &pass4MuxForwardSSHConn{nextRemotePort: 46000}
			srv, cleanup := newPass4TestMuxServer(t, mockConn, tc.dialNet)
			defer cleanup()

			// Open -R 18080:hostA:80 (ListenHost="")
			mustPass4OpenFwdOK(t, srv, MuxFwdRequest{
				RequestID:   1,
				FwdType:     MUX_FWD_REMOTE,
				ListenHost:  "",
				ListenPort:  18080,
				ConnectHost: "hostA",
				ConnectPort: 80,
			})
			if got := mockConn.tcpipFwdCalls.Load(); got != 1 {
				t.Fatalf("%s: tcpipFwdCalls after initial open = %d, want 1", tc.dialNet, got)
			}

			// Conflicting -R <explicitLoop>:18080:hostB:80 and -R localhost:18080:hostB:80 MUST fail before Listen!
			for _, conflictHost := range []string{tc.explicitLoop, "localhost"} {
				assertPass4OpenFwdConflict(t, srv, MuxFwdRequest{
					RequestID:   2,
					FwdType:     MUX_FWD_REMOTE,
					ListenHost:  conflictHost,
					ListenPort:  18080,
					ConnectHost: "hostB",
					ConnectPort: 80,
				})
			}
			if got := mockConn.tcpipFwdCalls.Load(); got != 1 {
				t.Fatalf("%s: conflicting loopback forward called upstream tcpip-forward (got %d, want 1)", tc.dialNet, got)
			}

			// Duplicate -R <explicitLoop>:18080:hostA:80 increments refs to 2; canceling both cleans up to 0!
			mustPass4OpenFwdOK(t, srv, MuxFwdRequest{
				RequestID:   3,
				FwdType:     MUX_FWD_REMOTE,
				ListenHost:  tc.explicitLoop,
				ListenPort:  18080,
				ConnectHost: "hostA",
				ConnectPort: 80,
			})
			assertPass4CloseFwdNotFound(t, srv, MuxFwdRequest{
				RequestID:   4,
				FwdType:     MUX_FWD_REMOTE,
				ListenHost:  tc.explicitLoop,
				ListenPort:  18080,
				ConnectHost: "hostB",
				ConnectPort: 80,
			})
			mustPass4CloseFwdOK(t, srv, MuxFwdRequest{
				RequestID:   5,
				FwdType:     MUX_FWD_REMOTE,
				ListenHost:  tc.explicitLoop,
				ListenPort:  18080,
				ConnectHost: "hostA",
				ConnectPort: 80,
			})
			if got := mockConn.cancelTcpipCalls.Load(); got != 0 {
				t.Fatalf("%s: first CloseForward sent cancel-tcpip-forward early (got %d)", tc.dialNet, got)
			}
			mustPass4CloseFwdOK(t, srv, MuxFwdRequest{
				RequestID:   6,
				FwdType:     MUX_FWD_REMOTE,
				ListenHost:  "",
				ListenPort:  18080,
				ConnectHost: "hostA",
				ConnectPort: 80,
			})
			if got := mockConn.cancelTcpipCalls.Load(); got < 1 {
				t.Fatalf("%s: final CloseForward cancelTcpipCalls = %d, want >= 1", tc.dialNet, got)
			}
			assertPass4MuxForwardTablesEmpty(t, srv)
		})
	}
}

func assertPass4DualStackLoopbackSemantics(t *testing.T) {
	mockConn := &pass4MuxForwardSSHConn{nextRemotePort: 47000}
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp")
	defer cleanup()

	// Under dual-stack tcp, explicit 127.0.0.1 and [::1] do NOT conflict.
	mustPass4OpenFwdOK(t, srv, MuxFwdRequest{RequestID: 1, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: 18081, ConnectHost: "hostA", ConnectPort: 80})
	mustPass4OpenFwdOK(t, srv, MuxFwdRequest{RequestID: 2, FwdType: MUX_FWD_REMOTE, ListenHost: "[::1]", ListenPort: 18081, ConnectHost: "hostB", ConnectPort: 80})

	// Empty ListenHost ("") and "LOCALHOST" both map to "localhost" and DO conflict.
	mustPass4OpenFwdOK(t, srv, MuxFwdRequest{RequestID: 3, FwdType: MUX_FWD_REMOTE, ListenHost: "", ListenPort: 18082, ConnectHost: "hostA", ConnectPort: 80})
	assertPass4OpenFwdConflict(t, srv, MuxFwdRequest{RequestID: 4, FwdType: MUX_FWD_REMOTE, ListenHost: "LOCALHOST", ListenPort: 18082, ConnectHost: "hostB", ConnectPort: 80})

	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{RequestID: 5, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: 18081, ConnectHost: "hostA", ConnectPort: 80})
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{RequestID: 6, FwdType: MUX_FWD_REMOTE, ListenHost: "::1", ListenPort: 18081, ConnectHost: "hostB", ConnectPort: 80})
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{RequestID: 7, FwdType: MUX_FWD_REMOTE, ListenHost: "localhost", ListenPort: 18082, ConnectHost: "hostA", ConnectPort: 80})
	assertPass4MuxForwardTablesEmpty(t, srv)
}

func assertPass4RemoteStreamLocalPathCleanSymmetry(t *testing.T) {
	mockConn := &pass4MuxForwardSSHConn{nextRemotePort: 48000}
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp")
	defer cleanup()

	// Empty whitespace StreamLocal path rejected cleanly.
	assertPass4OpenFwdFailure(t, srv, MuxFwdRequest{
		RequestID:   1,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "   ",
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: "127.0.0.1",
		ConnectPort: 80,
	})

	mustPass4OpenFwdOK(t, srv, MuxFwdRequest{
		RequestID:   2,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "/tmp/d/a.sock",
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: "127.0.0.1",
		ConnectPort: 80,
	})
	mustPass4OpenFwdOK(t, srv, MuxFwdRequest{
		RequestID:   3,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "/tmp/d//a.sock",
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: "127.0.0.1",
		ConnectPort: 80,
	})
	if got := mockConn.streamLocalFwdCalls.Load(); got != 1 {
		t.Fatalf("streamlocal-forward@openssh.com calls = %d, want 1", got)
	}

	// Conflicting target via /tmp/d/./a.sock fails before touching upstream.
	assertPass4OpenFwdConflict(t, srv, MuxFwdRequest{
		RequestID:   4,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "/tmp/d/./a.sock",
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: "127.0.0.1",
		ConnectPort: 8081,
	})

	// Cancel via non-canonical /tmp/d//a.sock decrements refs from 2 -> 1 without closing upstream.
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{
		RequestID:   5,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "/tmp/d//a.sock",
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: "127.0.0.1",
		ConnectPort: 80,
	})
	if got := mockConn.cancelStreamLocalCalls.Load(); got != 0 {
		t.Fatalf("cancelStreamLocalCalls after first cancel = %d, want 0", got)
	}

	// Second cancel via canonical /tmp/d/a.sock decrements refs 1 -> 0 and cleans up both maps!
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{
		RequestID:   6,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "/tmp/d/a.sock",
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: "127.0.0.1",
		ConnectPort: 80,
	})
	if got := mockConn.cancelStreamLocalCalls.Load(); got < 1 {
		t.Fatalf("cancelStreamLocalCalls after final cancel = %d, want >= 1", got)
	}
	assertPass4MuxForwardTablesEmpty(t, srv)
}

func assertPass4CommitReservedForwardBackfillsListenKey(t *testing.T) {
	mockConn := &pass4MuxForwardSSHConn{nextRemotePort: 49000}
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp")
	defer cleanup()

	resolved, err := srv.resolveMuxForwardListenSpec(MUX_FWD_REMOTE, "127.0.0.1", 49123)
	if err != nil {
		t.Fatalf("resolveMuxForwardListenSpec: %v", err)
	}
	listenKey, ok := makeForwardListenKey(MUX_FWD_REMOTE, resolved)
	if !ok {
		t.Fatal("expected makeForwardListenKey ok=true")
	}
	slot, outcome := srv.acquireForwardEndpoint(listenKey, MUX_FWD_REMOTE, "127.0.0.1", 80)
	if outcome != muxEndpointReserved || slot == nil {
		t.Fatalf("acquireForwardEndpoint = (%v, %v), want reserved", slot, outcome)
	}

	// Simulate an existing dynamic entry stored in s.forwards while slot was inFlight (hasListenKey == false).
	key := forwardKey(MUX_FWD_REMOTE, resolved.keyHost, 49123, "127.0.0.1", 80)
	existing := &muxForwardEntry{
		fwdType:      MUX_FWD_REMOTE,
		forwardKey:   key,
		keyHost:      resolved.keyHost,
		endpointHost: resolved.endpointHost,
		connectHost:  "127.0.0.1",
		connectPort:  80,
		dynamicAlloc: true,
		remote:       true,
		refs:         1,
	}
	srv.idleMu.Lock()
	srv.forwardTable.putEntryLocked(key, existing)
	srv.idleMu.Unlock()

	cand := &muxForwardEntry{
		fwdType:      MUX_FWD_REMOTE,
		forwardKey:   key,
		keyHost:      resolved.keyHost,
		endpointHost: resolved.endpointHost,
		connectHost:  "127.0.0.1",
		connectPort:  80,
		remote:       true,
		refs:         1,
	}
	gotEntry, dup, shuttingDown := srv.commitReservedForward(listenKey, slot, key, cand)
	if shuttingDown || !dup || gotEntry != existing {
		t.Fatalf("commitReservedForward = (entry=%v, dup=%v, shuttingDown=%v), want existing dup=true", gotEntry, dup, shuttingDown)
	}
	if !existing.hasListenKey || existing.listenKey != listenKey || existing.refs != 2 {
		t.Fatalf("existing metadata = (hasListenKey=%v, listenKey=%+v, refs=%d), want (true, %+v, 2)",
			existing.hasListenKey, existing.listenKey, existing.refs, listenKey)
	}

	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{RequestID: 1, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: 49123, ConnectHost: "127.0.0.1", ConnectPort: 80})
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{RequestID: 2, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: 49123, ConnectHost: "127.0.0.1", ConnectPort: 80})
	assertPass4MuxForwardTablesEmpty(t, srv)
}

func newPass4TestMuxServer(t *testing.T, mockConn cryptoSSH.Conn, dialNet string) (*MuxServer, func()) {
	t.Helper()
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	rawCli := cryptoSSH.NewClient(mockConn, chans, reqs)
	ctx, cancel := context.WithCancel(context.Background())
	srv := &MuxServer{
		serverCtx:         ctx,
		serverCancel:      cancel,
		sshClient:         rawCli,
		dialNetwork:       dialNet,
		persistEnabled:    true,
		persistIndefinite: true,
		idleNotify:        make(chan struct{}),
		shutdownChan:      make(chan struct{}),
	}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			_ = srv.Shutdown()
			close(chans)
			close(reqs)
			_ = rawCli.Close()
		})
	}
	t.Cleanup(cleanup)
	return srv, cleanup
}

func runPass4MuxFwdCall(t *testing.T, fn func(net.Conn) error) (uint32, []byte) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()
	done := make(chan error, 1)
	go func() {
		done <- fn(c1)
	}()
	pktType, payload, err := ReadMuxPacket(c2)
	if err != nil {
		t.Fatalf("ReadMuxPacket: %v", err)
	}
	if hErr := <-done; hErr != nil {
		t.Fatalf("mux handler error: %v", hErr)
	}
	return pktType, payload
}

func mustPass4OpenFwdOK(t *testing.T, srv *MuxServer, req MuxFwdRequest) {
	t.Helper()
	pt, payload := runPass4MuxFwdCall(t, func(c net.Conn) error { return srv.handleOpenFwd(c, req) })
	if pt != MUX_S_OK {
		_, reason, _ := DecodeMuxError(payload)
		t.Fatalf("handleOpenFwd(%+v) = 0x%x (%q), want MUX_S_OK", req, pt, reason)
	}
}

func mustPass4OpenRemotePortFwd(t *testing.T, srv *MuxServer, req MuxFwdRequest) uint32 {
	t.Helper()
	pt, payload := runPass4MuxFwdCall(t, func(c net.Conn) error { return srv.handleOpenFwd(c, req) })
	if pt != MUX_S_REMOTE_PORT || len(payload) < 8 {
		_, reason, _ := DecodeMuxError(payload)
		t.Fatalf("handleOpenFwd(%+v) = 0x%x (%q), want MUX_S_REMOTE_PORT", req, pt, reason)
	}
	return binary.BigEndian.Uint32(payload[4:8])
}

func assertPass4OpenFwdConflict(t *testing.T, srv *MuxServer, req MuxFwdRequest) {
	t.Helper()
	pt, payload := runPass4MuxFwdCall(t, func(c net.Conn) error { return srv.handleOpenFwd(c, req) })
	_, reason, _ := DecodeMuxError(payload)
	if pt != MUX_S_FAILURE || !strings.Contains(reason, "port forwarding conflict on listen endpoint") {
		t.Fatalf("handleOpenFwd(%+v) = (0x%x, %q), want MUX_S_FAILURE conflict", req, pt, reason)
	}
}

func assertPass4OpenFwdFailure(t *testing.T, srv *MuxServer, req MuxFwdRequest) {
	t.Helper()
	pt, _ := runPass4MuxFwdCall(t, func(c net.Conn) error { return srv.handleOpenFwd(c, req) })
	if pt != MUX_S_FAILURE {
		t.Fatalf("handleOpenFwd(%+v) = 0x%x, want MUX_S_FAILURE", req, pt)
	}
}

func mustPass4CloseFwdOK(t *testing.T, srv *MuxServer, req MuxFwdRequest) {
	t.Helper()
	pt, payload := runPass4MuxFwdCall(t, func(c net.Conn) error { return srv.handleCloseFwd(c, req) })
	if pt != MUX_S_OK {
		_, reason, _ := DecodeMuxError(payload)
		t.Fatalf("handleCloseFwd(%+v) = 0x%x (%q), want MUX_S_OK", req, pt, reason)
	}
}

func assertPass4CloseFwdNotFound(t *testing.T, srv *MuxServer, req MuxFwdRequest) {
	t.Helper()
	pt, payload := runPass4MuxFwdCall(t, func(c net.Conn) error { return srv.handleCloseFwd(c, req) })
	_, reason, _ := DecodeMuxError(payload)
	if pt != MUX_S_FAILURE || !strings.Contains(reason, "forwarding not found") {
		t.Fatalf("handleCloseFwd(%+v) = (0x%x, %q), want forwarding not found", req, pt, reason)
	}
}

func assertPass4MuxForwardTablesEmpty(t *testing.T, srv *MuxServer) {
	t.Helper()
	srv.idleMu.Lock()
	endpoints := srv.forwardTable.endpointCountLocked()
	forwards := srv.forwardTable.entryCountLocked()
	srv.idleMu.Unlock()
	if endpoints != 0 || forwards != 0 {
		t.Fatalf("MuxServer forward tables not empty: forwards=%d endpoints=%d", forwards, endpoints)
	}
}

type pass4MuxForwardSSHConn struct {
	dummyMuxGateConn
	initOnce               sync.Once
	closeOnce              sync.Once
	closedCh               chan struct{}
	nextRemotePort         uint32
	portSeq                atomic.Uint32
	tcpipFwdCalls          atomic.Int32
	cancelTcpipCalls       atomic.Int32
	streamLocalFwdCalls    atomic.Int32
	cancelStreamLocalCalls atomic.Int32
}

func (m *pass4MuxForwardSSHConn) closed() chan struct{} {
	m.initOnce.Do(func() {
		m.closedCh = make(chan struct{})
	})
	return m.closedCh
}

func (m *pass4MuxForwardSSHConn) Wait() error {
	<-m.closed()
	return io.EOF
}

func (m *pass4MuxForwardSSHConn) Close() error {
	ch := m.closed()
	m.closeOnce.Do(func() {
		close(ch)
	})
	return nil
}

func (m *pass4MuxForwardSSHConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	switch name {
	case "tcpip-forward":
		m.tcpipFwdCalls.Add(1)
		var req struct {
			BindAddr string
			BindPort uint32
		}
		_ = cryptoSSH.Unmarshal(payload, &req)
		if req.BindPort == 0 && wantReply {
			alloc := m.nextRemotePort + m.portSeq.Add(1)
			return true, cryptoSSH.Marshal(struct{ Port uint32 }{Port: alloc}), nil
		}
		return true, nil, nil
	case "cancel-tcpip-forward":
		m.cancelTcpipCalls.Add(1)
		return true, nil, nil
	case "streamlocal-forward@openssh.com":
		m.streamLocalFwdCalls.Add(1)
		return true, nil, nil
	case "cancel-streamlocal-forward@openssh.com":
		m.cancelStreamLocalCalls.Add(1)
		return true, nil, nil
	default:
		return false, nil, errors.New("unsupported global request: " + strconv.Quote(name))
	}
}
