//go:build linux || darwin || freebsd

package ssh

import (
	"context"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func startW10bUnixPassengerSession(
	t *testing.T,
	sockPath string,
	req MuxNewSessionRequest,
) net.Conn {
	t.Helper()
	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial mux socket %q: %v", sockPath, err)
	}
	if err := performClientMuxHandshake(clientConn); err != nil {
		_ = clientConn.Close()
		t.Fatalf("mux handshake: %v", err)
	}
	if err := WriteMuxPacket(clientConn, MUX_C_NEW_SESSION, EncodeMuxNewSession(req)); err != nil {
		_ = clientConn.Close()
		t.Fatalf("WriteMuxPacket(MUX_C_NEW_SESSION): %v", err)
	}
	sendSessionPipeFDs(t, clientConn)

	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	pktType, payload, err := ReadMuxPacket(clientConn)
	_ = clientConn.SetReadDeadline(time.Time{})
	if err != nil || pktType != MUX_S_SESSION_OPENED {
		_ = clientConn.Close()
		t.Fatalf("ReadMuxPacket(MUX_S_SESSION_OPENED) = (0x%x, %q, %v)", pktType, payload, err)
	}
	return clientConn
}

// TestW10b_C10_M3_UnixPassengerAgentReleaseWedgedUnblocksStopAndDrain verifies
// C10-M3 on Unix MUX_C_NEW_SESSION passenger sessions: when an
// auth-agent@openssh.com channel is open and the SSH transport write-wedges,
// handlePassengerSession's defer releasePassengerAgent() runs BEFORE defer
// releaseSession(), escalates via s.interruptTransportAndShutdown(), drops
// activeSessions to 0, unblocks -O stop / WaitForDrain, and leaks 0 goroutines.
func TestW10b_C10_M3_UnixPassengerAgentReleaseWedgedUnblocksStopAndDrain(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const closeTimeout = 80 * time.Millisecond
	holdAgent := make(chan struct{})
	defer close(holdAgent)
	holdSession := make(chan struct{})
	defer close(holdSession)

	agentHarness := newW10bFakeAgentHarness(t)
	sshSrv, agentLive := startW10bAgentSSHServer(t, ctx, holdAgent, holdSession)

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, rootConn, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w10b-m3-pass.sock", w10bMuxOpts{
		requestTimeout:    closeTimeout,
		allowAgentForward: true,
		agentSocket:       "/w10b-passenger-agent.sock",
		dialAgent:         agentHarness.dialAgent,
	})

	passengerConn := startW10bUnixPassengerSession(t, sockPath, MuxNewSessionRequest{
		RequestID: 7,
		WantAgent: true,
		Command:   "hold-agent",
	})
	defer func() { _ = passengerConn.Close() }()

	select {
	case <-agentLive:
	case <-time.After(3 * time.Second):
		t.Fatal("passenger auth-agent@openssh.com channel did not become live")
	}

	muxCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	if err := muxCli.StopListening(ctx); err != nil {
		_ = muxCli.Close()
		t.Fatalf("StopListening: %v", err)
	}
	_ = muxCli.Close()
	assertMuxPhase(t, srv, muxPhaseStoppingListen, true)
	if got := srv.ActiveSessions(); got != 1 {
		t.Fatalf("ActiveSessions before wedged passenger close = %d, want 1", got)
	}

	// Wedge transport writes right when defer releasePassengerAgent() ->
	// releaseWithDeadline() closes entry.agentConn (AFTER the session channel
	// itself already closed cleanly via s.closeMuxChannelBounded), so ONLY
	// releasePassengerAgent() hits the write-wedged transport before defer
	// releaseSession().
	var wedgeOnce sync.Once
	agentHarness.setOnConnClose(func() {
		wedgeOnce.Do(func() { rootConn.wedgeWrite.Store(true) })
	})
	drainDone := make(chan error, 1)
	go func() {
		drainDone <- srv.WaitForDrain(ctx, 0)
	}()
	_ = passengerConn.Close()

	waitWithin(t, "C10-M3 Unix passenger agent release: bounded escalation shutdown", 600*time.Millisecond, func() {
		<-srv.Wait()
	})
	select {
	case drainErr := <-drainDone:
		if drainErr != nil {
			t.Fatalf("C10-M3 Unix passenger agent release: WaitForDrain returned %v", drainErr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("C10-M3 Unix passenger agent release: WaitForDrain remained wedged")
	}
	if !rootConn.closed.Load() {
		t.Fatal("C10-M3 Unix passenger agent release: expected escalation to abort write-wedged RootConn")
	}
	waitForCondition(t, time.Second, func() bool {
		return srv.ActiveSessions() == 0
	}, "C10-M3 Unix passenger agent release: ActiveSessions did not drain to 0")
	assertW7aMuxDrainedClosed(t, srv, sockPath)
	waitForGoroutinesAtMost(t, baseline+2, time.Second, "C10-M3 Unix passenger agent release goroutine check")
}

// TestW10b_Audit_UnixPassengerWantReplyRequestBoundedOnWedgedTransport verifies
// the channel-write audit fix in runPassengerChannelIO (mux_rights_unix.go):
// replying to a remote WantReply=true channel request over a write-wedged
// transport is bounded by replyMuxChannelRequestBounded and escalates cleanly.
func TestW10b_Audit_UnixPassengerWantReplyRequestBoundedOnWedgedTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const closeTimeout = 80 * time.Millisecond
	sendProbe := make(chan struct{})

	sshSrv := startW10bSSHServer(t, ctx, w10bSSHServerHooks{
		onSession: func(connCtx context.Context, _ *cryptoSSH.ServerConn, newCh cryptoSSH.NewChannel) {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				return
			}
			defer func() { _ = ch.Close() }()
			for req := range reqs {
				if req.Type == "exec" {
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					select {
					case <-sendProbe:
					case <-connCtx.Done():
						return
					}
					_, _ = ch.SendRequest("probe@w10b-passenger", true, nil)
					<-connCtx.Done()
					return
				}
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		},
	})

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, rootConn, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w10b-audit-pass.sock", w10bMuxOpts{
		requestTimeout: closeTimeout,
	})

	passengerConn := startW10bUnixPassengerSession(t, sockPath, MuxNewSessionRequest{
		RequestID: 9,
		Command:   "probe-want-reply",
	})
	defer func() { _ = passengerConn.Close() }()

	muxCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	if err := muxCli.StopListening(ctx); err != nil {
		_ = muxCli.Close()
		t.Fatalf("StopListening: %v", err)
	}
	_ = muxCli.Close()
	assertMuxPhase(t, srv, muxPhaseStoppingListen, true)

	assertW10bWedgedEscalationDrains(t, ctx, srv, rootConn, sockPath, func() {
		close(sendProbe)
	}, baseline, "Audit Unix passenger WantReply bounded")
}
