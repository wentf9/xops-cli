//go:build linux || darwin || freebsd

package ssh

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// TestW12b_C12_M1_MuxServerProxyAndUnixPassengerSharedEpoch verifies C12-M1
// when a MUX_C_PROXY session and a Unix MUX_C_NEW_SESSION (WantAgent=true)
// passenger session share the same MuxServer agent router epoch. Releasing
// either sibling (passenger first OR proxy first) while an auth-agent@openssh.com
// signing request is in flight must preserve the open agent channel for the
// surviving session, and releasing the last session must close it cleanly.
func TestW12b_C12_M1_MuxServerProxyAndUnixPassengerSharedEpoch(t *testing.T) {
	t.Run("passenger_releases_first", func(t *testing.T) {
		testW12bC12M1MuxProxyAndPassenger(t, false)
	})
	t.Run("proxy_releases_first", func(t *testing.T) {
		testW12bC12M1MuxProxyAndPassenger(t, true)
	})
}

func testW12bC12M1MuxProxyAndPassenger(t *testing.T, closeProxyFirst bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	agent := newW12bControlledAgent(false)
	defer agent.closeAll()
	sshSrv, capture := startW12bAgentEchoSSHServer(t, ctx)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, _, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w12b-m1-mixed.sock", w10bMuxOpts{
		requestTimeout:    150 * time.Millisecond,
		allowAgentForward: true,
		agentSocket:       "/w12b-mixed-agent.sock",
		dialAgent:         agent.dialAgent,
	})
	router, err := getOrCreateAgentRouter(srv.sshClient)
	if err != nil {
		t.Fatalf("getOrCreateAgentRouter: %v", err)
	}

	rawProxy, serverCh, closeProxy := openW12bMuxProxyAgentSession(t, ctx, sockPath)
	defer closeProxy()

	passengerConn := startW10bUnixPassengerSession(t, sockPath, MuxNewSessionRequest{
		RequestID: 21,
		WantAgent: true,
		Command:   "", // opens shell on our echo server so passenger stays open until closed
	})
	defer func() { _ = passengerConn.Close() }()

	waitForCondition(t, 2*time.Second, func() bool {
		return srv.ActiveSessions() == 2
	}, "expected 2 active sessions (MUX_C_PROXY + Unix passenger)")
	waitForCondition(t, 2*time.Second, func() bool {
		router.mu.Lock()
		defer router.mu.Unlock()
		return len(router.leases) == 2 && router.epoch != nil
	}, "expected 2 agent leases sharing one epoch on MuxServer")

	sConn := capture.wait(t)

	closePassenger := func(wantRemaining int32, label string) {
		_ = passengerConn.Close()
		waitForCondition(t, 2*time.Second, func() bool {
			return srv.ActiveSessions() == wantRemaining
		}, label+": ActiveSessions did not reach expected count")
	}

	releaseFirst := func() { closePassenger(1, "close passenger first") }
	releaseLast := func() {
		closeW12bMuxProxyChannelAndWaitSessions(t, srv, rawProxy, serverCh, closeProxy, 0, "close proxy last")
	}
	if closeProxyFirst {
		releaseFirst = func() {
			closeW12bMuxProxyChannelAndWaitSessions(t, srv, rawProxy, serverCh, closeProxy, 1, "close proxy first")
		}
		releaseLast = func() { closePassenger(0, "close passenger last") }
	}

	assertW12bLiveChannelSurvivesSiblingRelease(t, sConn, agent, releaseFirst, releaseLast, router, "mux-proxy+passenger")

	if srv.isShuttingDown() || srv.currentPhase() != muxPhaseRunning {
		t.Fatalf("healthy MuxServer unexpectedly shut down: phase=%d", srv.currentPhase())
	}

	_ = srv.Shutdown()
	<-srv.Wait()
	waitForGoroutinesAtMost(t, baseline+2, 2*time.Second, "C12-M1 proxy+passenger goroutine check")
}
