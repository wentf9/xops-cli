//go:build linux || darwin || freebsd

package ssh

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestW11b_C11_M1_UnixPassengerSlowRemoteAgentClosePreservesHealthyMux verifies
// C11-M1 on Unix MUX_C_NEW_SESSION passenger sessions: when the passenger exits
// while a remote process keeps auth-agent@openssh.com open WITHOUT echoing
// SSH_MSG_CHANNEL_CLOSE past 2*drainTimeout, releasePassengerAgent() completes
// within drainTimeout without calling s.interruptTransportAndShutdown(). The
// healthy shared MuxServer stays alive (AliveCheck and subsequent passenger
// sessions succeed), and once the remote side finally closes the agent channel,
// l.pumps drains cleanly with 0 leaked goroutines.
func TestW11b_C11_M1_UnixPassengerSlowRemoteAgentClosePreservesHealthyMux(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const closeTimeout = 80 * time.Millisecond
	holdAgent := make(chan struct{})
	releaseRemoteAgent := sync.OnceFunc(func() { close(holdAgent) })
	defer releaseRemoteAgent()
	holdFirstSession := make(chan struct{})
	closeFirstSession := sync.OnceFunc(func() { close(holdFirstSession) })
	defer closeFirstSession()

	agentHarness := newW10bFakeAgentHarness(t)
	sshSrv, state := startW11bSlowCloseAgentSSHServer(t, ctx, holdAgent, holdFirstSession)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, rootConn, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w11b-m1-pass.sock", w10bMuxOpts{
		requestTimeout:    closeTimeout,
		allowAgentForward: true,
		agentSocket:       "/w11b-passenger-agent.sock",
		dialAgent:         agentHarness.dialAgent,
	})
	router, err := getOrCreateAgentRouter(srv.sshClient)
	if err != nil {
		t.Fatalf("getOrCreateAgentRouter: %v", err)
	}

	passengerConn := startW10bUnixPassengerSession(t, sockPath, MuxNewSessionRequest{
		RequestID: 11,
		WantAgent: true,
		Command:   "passenger-bg-agent",
	})
	select {
	case <-state.agentLive:
	case <-time.After(3 * time.Second):
		_ = passengerConn.Close()
		t.Fatal("passenger auth-agent@openssh.com channel did not become live")
	}

	// Let the first passenger session exit cleanly while remote still holds
	// auth-agent@openssh.com open without echoing SSH_MSG_CHANNEL_CLOSE.
	closeFirstSession()
	_ = passengerConn.Close()

	select {
	case <-state.remoteSawAgentEOF:
	case <-time.After(2 * time.Second):
		t.Fatal("remote agent channel did not observe outbound close/EOF")
	}
	waitForCondition(t, 2*closeTimeout+120*time.Millisecond, func() bool {
		return srv.ActiveSessions() == 0
	}, "Unix passenger session did not drain while remote held auth-agent channel open")

	// Sleep past 2*drainTimeout while remote still withholds SSH_MSG_CHANNEL_CLOSE.
	time.Sleep(2*closeTimeout + 40*time.Millisecond)
	if srv.isShuttingDown() || srv.currentPhase() != muxPhaseRunning {
		t.Fatalf("healthy MuxServer torn down by slow remote passenger agent close: phase=%d shuttingDown=%v", srv.currentPhase(), srv.isShuttingDown())
	}
	if rootConn.closed.Load() {
		t.Fatal("healthy MuxServer rootConn was closed during slow remote passenger agent close")
	}

	muxCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient after slow remote passenger agent close: %v", err)
	}
	if _, err := muxCli.AliveCheck(ctx); err != nil {
		_ = muxCli.Close()
		t.Fatalf("AliveCheck failed after slow remote passenger agent close: %v", err)
	}
	_ = muxCli.Close()

	// Confirm a 2nd Unix passenger session still succeeds on the preserved master.
	secondConn := startW10bUnixPassengerSession(t, sockPath, MuxNewSessionRequest{
		RequestID: 12,
		Command:   "second-passenger",
	})
	_ = secondConn.Close()
	waitForCondition(t, 2*time.Second, func() bool {
		return srv.ActiveSessions() == 0
	}, "second Unix passenger session did not drain to 0")

	// Release remote agent channel and confirm full drain + 0 leaked goroutines.
	releaseRemoteAgent()
	waitForCondition(t, 2*time.Second, func() bool {
		return router.activeChannels.Load() == 0
	}, "Unix passenger agent channel slot did not drain after remote closed agent channel")

	_ = srv.Shutdown()
	<-srv.Wait()
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C11-M1 Unix passenger slow remote close goroutine check")
}
