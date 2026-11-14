package ssh

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// TestReviewPass3_H4_AgentRouterRejectsEmptyAndWildcardAndMasterOnlyProxy verifies:
//   - acquireLocalLease rejects empty "" and whitespace-only sockets with errEmptyAgentSocket;
//   - hasConflictingActiveLeaseLocked never treats "" as a wildcard on either side;
//   - proxySessionState.acquireChannelAgentLease rejects MUX_C_PROXY agent forwarding when
//     Master lacks allowAgentForward, agentSocket, or dialAgent, and serves strictly from
//     Master's verified local agentSocket when enabled.
func TestReviewPass3_H4_AgentRouterRejectsEmptyAndWildcardAndMasterOnlyProxy(t *testing.T) {
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

	for _, emptySpec := range []string{"", "   ", "\t\n"} {
		lease, lErr := router.acquireLocalLease(t.Context(), emptySpec, dialStub, nil)
		if !errors.Is(lErr, errEmptyAgentSocket) || lease != nil {
			t.Fatalf("acquireLocalLease(%q) = (%v, %v), want (nil, errEmptyAgentSocket)", emptySpec, lease, lErr)
		}
	}

	if sock, enabled, rErr := ResolveForwardAgent("SSH_AUTH_SOCK", "", Environment{}, TargetContext{}); rErr != nil || enabled || sock != "" {
		t.Fatalf("ResolveForwardAgent(SSH_AUTH_SOCK, empty env) = (%q, %v, %v), want (\"\", false, nil)", sock, enabled, rErr)
	}

	// Synthetic defensive check: even if an active lease ever held socket == "",
	// hasConflictingActiveLeaseLocked must treat both cand.socket == "" and socket == "" as conflicts.
	syntheticEmpty := &agentForwardLease{router: router, socket: ""}
	router.mu.Lock()
	router.leases = append(router.leases, syntheticEmpty)
	conflictWithValid := router.hasConflictingActiveLeaseLocked("/master.sock")
	conflictWithEmpty := router.hasConflictingActiveLeaseLocked("")
	router.leases = nil
	router.mu.Unlock()
	if !conflictWithValid || !conflictWithEmpty {
		t.Fatalf("hasConflictingActiveLeaseLocked wildcard check failed: valid=%v empty=%v, want both true", conflictWithValid, conflictWithEmpty)
	}

	validLease, err := router.acquireLocalLease(t.Context(), "/master.sock", dialStub, nil)
	if err != nil || validLease == nil {
		t.Fatalf("acquireLocalLease(/master.sock): %v", err)
	}
	router.mu.Lock()
	emptyQueryConflicts := router.hasConflictingActiveLeaseLocked("")
	diffQueryConflicts := router.hasConflictingActiveLeaseLocked("/other.sock")
	sameQueryAllowed := !router.hasConflictingActiveLeaseLocked("/master.sock")
	router.mu.Unlock()
	validLease.Release()

	if !emptyQueryConflicts || !diffQueryConflicts || !sameQueryAllowed {
		t.Fatalf("lease conflict matrix = (empty:%v, diff:%v, sameAllowed:%v), want (true, true, true)",
			emptyQueryConflicts, diffQueryConflicts, sameQueryAllowed)
	}

	assertPass3MuxProxyAcquireGateMatrix(t, rawCli, dialStub)
}

func assertPass3MuxProxyAcquireGateMatrix(
	t *testing.T,
	rawCli *cryptoSSH.Client,
	dialStub func(context.Context, string) (net.Conn, error),
) {
	t.Helper()
	// Verify Master gating matrix for MUX_C_PROXY acquireChannelAgentLease.
	cases := []struct {
		name      string
		allow     bool
		sock      string
		dialAgent func(context.Context, string) (net.Conn, error)
		wantOK    bool
	}{
		{name: "AllowAgentForward=false", allow: false, sock: "/master.sock", dialAgent: dialStub, wantOK: false},
		{name: "empty AgentSocket", allow: true, sock: "", dialAgent: dialStub, wantOK: false},
		{name: "nil DialAgent", allow: true, sock: "/master.sock", dialAgent: nil, wantOK: false},
		{name: "valid Master agent", allow: true, sock: "/master.sock", dialAgent: dialStub, wantOK: true},
	}
	for _, tc := range cases {
		srv := &MuxServer{
			sshClient:         rawCli,
			allowAgentForward: tc.allow,
			agentSocket:       tc.sock,
			dialAgent:         tc.dialAgent,
		}
		ps := &proxySessionState{server: srv}
		lease, ok := ps.acquireChannelAgentLease()
		if ok != tc.wantOK || (ok && lease == nil) || (!ok && lease != nil) {
			if lease != nil {
				lease.Release()
			}
			t.Fatalf("%s: acquireChannelAgentLease = (%v, %v), want ok=%v", tc.name, lease, ok, tc.wantOK)
		}
		if lease != nil {
			if lease.socket != "/master.sock" {
				lease.Release()
				t.Fatalf("%s: lease.socket = %q, want /master.sock", tc.name, lease.socket)
			}
			lease.Release()
		}
	}
}

// TestReviewPass3_M2_ConcurrentDuplicateRemoteForwardNoCancelTcpipForward verifies that
// concurrent identical MUX_C_OPEN_FWD (-R 127.0.0.1:18080:127.0.0.1:80) requests serialize
// on the pre-bind endpoint reservation under s.idleMu so sshClient.Listen is called ONCE,
// zero cancel-tcpip-forward global requests are emitted during open, and refs equals N.
func TestReviewPass3_M2_ConcurrentDuplicateRemoteForwardNoCancelTcpipForward(t *testing.T) {
	mockConn := &pass3RemoteFwdSSHConn{
		bindEntered: make(chan struct{}),
		releaseBind: make(chan struct{}),
	}
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	rawCli := cryptoSSH.NewClient(mockConn, chans, reqs)
	defer func() {
		close(chans)
		close(reqs)
		_ = rawCli.Close()
	}()

	srv := &MuxServer{
		sshClient:         rawCli,
		persistEnabled:    true,
		persistIndefinite: true,
		idleNotify:        make(chan struct{}),
		shutdownChan:      make(chan struct{}),
	}

	const workers = 6
	req := MuxFwdRequest{
		RequestID:   100,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  18080,
		ConnectHost: "127.0.0.1",
		ConnectPort: 80,
	}

	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	pktTypes := make([]uint32, workers)

	for i := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			c1, c2 := net.Pipe()
			defer func() {
				_ = c1.Close()
				_ = c2.Close()
			}()

			done := make(chan error, 1)
			go func() {
				r := req
				r.RequestID = uint32(100 + idx)
				done <- srv.handleOpenFwd(c1, r)
			}()

			pktType, _, readErr := ReadMuxPacket(c2)
			if readErr != nil {
				errCh <- readErr
				return
			}
			pktTypes[idx] = pktType
			if hErr := <-done; hErr != nil {
				errCh <- hErr
			}
		}(i)
	}

	select {
	case <-mockConn.bindEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for first goroutine to enter tcpip-forward")
	}
	// Allow sibling goroutines to reach acquireForwardEndpoint and park on slot.done.
	time.Sleep(40 * time.Millisecond)
	close(mockConn.releaseBind)

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent handleOpenFwd error: %v", err)
	}
	for i, pt := range pktTypes {
		if pt != MUX_S_OK {
			t.Fatalf("worker %d reply = 0x%x, want MUX_S_OK", i, pt)
		}
	}

	if got := mockConn.tcpipFwdCalls.Load(); got != 1 {
		t.Fatalf("tcpip-forward global requests = %d, want 1", got)
	}
	if got := mockConn.cancelFwdCalls.Load(); got != 0 {
		t.Fatalf("cancel-tcpip-forward global requests during concurrent open = %d, want 0", got)
	}

	// Conflicting destination on same remote listen endpoint MUST fail without touching upstream!
	cConf1, cConf2 := net.Pipe()
	defer func() {
		_ = cConf1.Close()
		_ = cConf2.Close()
	}()
	go func() {
		_ = srv.handleOpenFwd(cConf1, MuxFwdRequest{
			RequestID:   200,
			FwdType:     MUX_FWD_REMOTE,
			ListenHost:  "127.0.0.1",
			ListenPort:  18080,
			ConnectHost: "127.0.0.1",
			ConnectPort: 8081,
		})
	}()
	confType, _, err := ReadMuxPacket(cConf2)
	if err != nil || confType != MUX_S_FAILURE {
		t.Fatalf("conflicting remote OpenForward = (0x%x, %v), want MUX_S_FAILURE", confType, err)
	}
	if got := mockConn.tcpipFwdCalls.Load(); got != 1 {
		t.Fatalf("conflicting OpenForward sent upstream tcpip-forward: got %d, want 1", got)
	}

	// First (workers - 1) CloseForward calls decrement refs without canceling upstream.
	for i := range workers - 1 {
		pt := runPass3CloseFwd(t, srv, req, uint32(300+i))
		if pt != MUX_S_OK {
			t.Fatalf("CloseForward #%d = 0x%x, want MUX_S_OK", i+1, pt)
		}
		if got := mockConn.cancelFwdCalls.Load(); got != 0 {
			t.Fatalf("CloseForward #%d prematurely sent cancel-tcpip-forward (count=%d)", i+1, got)
		}
	}

	// Final CloseForward releases the endpoint and sends cancel-tcpip-forward.
	if pt := runPass3CloseFwd(t, srv, req, 399); pt != MUX_S_OK {
		t.Fatalf("final CloseForward = 0x%x, want MUX_S_OK", pt)
	}
	if got := mockConn.cancelFwdCalls.Load(); got < 1 {
		t.Fatalf("cancel-tcpip-forward after final CloseForward = %d, want >= 1", got)
	}
	srv.idleMu.Lock()
	remainingEndpoints := len(srv.listenEndpoints)
	srv.idleMu.Unlock()
	if remainingEndpoints != 0 {
		t.Fatalf("srv.listenEndpoints len = %d after close, want 0", remainingEndpoints)
	}
}

func runPass3CloseFwd(t *testing.T, srv *MuxServer, req MuxFwdRequest, reqID uint32) uint32 {
	t.Helper()
	c1, c2 := net.Pipe()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()
	done := make(chan error, 1)
	go func() {
		r := req
		r.RequestID = reqID
		done <- srv.handleCloseFwd(c1, r)
	}()
	pktType, _, err := ReadMuxPacket(c2)
	if err != nil {
		t.Fatalf("ReadMuxPacket(CloseFwd): %v", err)
	}
	if hErr := <-done; hErr != nil {
		t.Fatalf("handleCloseFwd: %v", hErr)
	}
	return pktType
}

type pass3RemoteFwdSSHConn struct {
	dummyMuxGateConn
	bindOnce       sync.Once
	bindEntered    chan struct{}
	releaseBind    chan struct{}
	tcpipFwdCalls  atomic.Int32
	cancelFwdCalls atomic.Int32
}

func (m *pass3RemoteFwdSSHConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	switch name {
	case "tcpip-forward":
		m.tcpipFwdCalls.Add(1)
		m.bindOnce.Do(func() { close(m.bindEntered) })
		<-m.releaseBind
		var req struct {
			BindAddr string
			BindPort uint32
		}
		_ = cryptoSSH.Unmarshal(payload, &req)
		if req.BindPort == 0 && wantReply {
			return true, cryptoSSH.Marshal(struct{ Port uint32 }{Port: 41234}), nil
		}
		return true, nil, nil
	case "cancel-tcpip-forward":
		m.cancelFwdCalls.Add(1)
		return true, nil, nil
	default:
		return false, nil, errors.New("unsupported global request: " + strconv.Quote(name))
	}
}
