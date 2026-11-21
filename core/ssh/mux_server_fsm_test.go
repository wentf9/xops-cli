package ssh

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func assertMuxPhase(t *testing.T, srv *MuxServer, want muxPhase, wantStopped bool) {
	t.Helper()
	srv.idleMu.Lock()
	gotPhase := srv.phase
	gotStopped := srv.stoppedListening
	srv.idleMu.Unlock()
	if gotPhase != want || gotStopped != wantStopped {
		t.Fatalf("MuxServer state = (phase=%d, stoppedListening=%v), want (phase=%d, stoppedListening=%v)",
			gotPhase, gotStopped, want, wantStopped)
	}
}

func assertMuxShutdownCompleted(t *testing.T, srv *MuxServer, label string) {
	t.Helper()
	select {
	case <-srv.Wait():
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: MuxServer did not complete Shutdown within 2s", label)
	}
	assertMuxPhase(t, srv, muxPhaseClosed, srv.StoppedListening())
}

func assertMuxNotShutdownBriefly(t *testing.T, srv *MuxServer, d time.Duration, label string) {
	t.Helper()
	select {
	case <-srv.Wait():
		t.Fatalf("%s: MuxServer shut down unexpectedly", label)
	case <-time.After(d):
	}
}

func runSyncMuxPacketCall(t *testing.T, fn func(net.Conn) error) uint32 {
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
	pt, _, readErr := ReadMuxPacket(c2)
	callErr := <-done
	if readErr != nil {
		t.Fatalf("ReadMuxPacket: %v", readErr)
	}
	if callErr != nil {
		t.Fatalf("mux call error: %v", callErr)
	}
	return pt
}

func TestMuxServer_FSM_HandoffCancelTransitions(t *testing.T) {
	t.Run("IdleFinitePersistRearmsTimer", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled:  true,
			persistDuration: 60 * time.Millisecond,
			idleNotify:      make(chan struct{}),
			shutdownChan:    make(chan struct{}),
		}
		if !srv.PrepareHandoff() {
			t.Fatal("PrepareHandoff failed")
		}
		assertMuxPhase(t, srv, muxPhaseHandoffReserved, false)
		if !srv.CommitHandoffReady() {
			t.Fatal("CommitHandoffReady = false during reservation")
		}

		// Longer than persistDuration while reserved: timer must stay disarmed.
		assertMuxNotShutdownBriefly(t, srv, 90*time.Millisecond, "while handoff reserved")

		srv.CancelHandoff()
		assertMuxPhase(t, srv, muxPhaseRunning, false)
		assertMuxShutdownCompleted(t, srv, "finite persist idle timer after CancelHandoff")
	})

	t.Run("ActiveSessionStaysRunningOnCancel", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled: false,
			idleNotify:     make(chan struct{}),
			shutdownChan:   make(chan struct{}),
		}
		if !srv.addActiveSession() {
			t.Fatal("addActiveSession failed")
		}
		if !srv.PrepareHandoffWithSessions(1) {
			t.Fatal("PrepareHandoffWithSessions(1) failed")
		}
		assertMuxPhase(t, srv, muxPhaseHandoffReserved, false)

		srv.CancelHandoff()
		assertMuxPhase(t, srv, muxPhaseRunning, false)
		assertMuxNotShutdownBriefly(t, srv, 40*time.Millisecond, "non-persistent with active session")

		srv.removeActiveSession()
		assertMuxShutdownCompleted(t, srv, "after active session drained")
	})

	t.Run("NonPersistentHadActiveSessionShutsDownWhenIdleOnCancel", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled:   false,
			hadActiveSession: true,
			activeSessions:   1,
			idleNotify:       make(chan struct{}),
			shutdownChan:     make(chan struct{}),
		}
		if !srv.PrepareHandoffWithSessions(1) {
			t.Fatal("PrepareHandoffWithSessions(1) failed")
		}
		srv.removeActiveSession()
		assertMuxNotShutdownBriefly(t, srv, 30*time.Millisecond, "idle non-persistent while reserved")

		srv.CancelHandoff()
		assertMuxShutdownCompleted(t, srv, "idle non-persistent after CancelHandoff")
	})
}

func TestMuxServer_FSM_StopDuringHandoffTransitions(t *testing.T) {
	t.Run("IdleAtCancelTransitionsToClosed", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled:    true,
			persistIndefinite: true,
			idleNotify:        make(chan struct{}),
			shutdownChan:      make(chan struct{}),
		}
		if !srv.PrepareHandoff() {
			t.Fatal("PrepareHandoff failed")
		}
		if pt := runSyncMuxPacketCall(t, func(c net.Conn) error { return srv.handleStopListening(c, 1) }); pt != MUX_S_OK {
			t.Fatalf("handleStopListening = 0x%x, want MUX_S_OK", pt)
		}
		if srv.CommitHandoffReady() {
			t.Fatal("CommitHandoffReady must be false after -O stop")
		}
		if !srv.StoppedListening() {
			t.Fatal("StoppedListening must be true after -O stop")
		}
		assertMuxPhase(t, srv, muxPhaseHandoffReserved, true)

		srv.CancelHandoff()
		assertMuxShutdownCompleted(t, srv, "idle server after stop-during-handoff CancelHandoff")
	})

	t.Run("ActiveSessionAtCancelEntersStoppingListenThenDrains", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled:    true,
			persistIndefinite: true,
			idleNotify:        make(chan struct{}),
			shutdownChan:      make(chan struct{}),
		}
		if !srv.addActiveSession() {
			t.Fatal("addActiveSession failed")
		}
		if !srv.PrepareHandoffWithSessions(1) {
			t.Fatal("PrepareHandoffWithSessions(1) failed")
		}
		if pt := runSyncMuxPacketCall(t, func(c net.Conn) error { return srv.handleStopListening(c, 2) }); pt != MUX_S_OK {
			t.Fatalf("handleStopListening = 0x%x, want MUX_S_OK", pt)
		}
		if srv.CommitHandoffReady() {
			t.Fatal("CommitHandoffReady must be false after -O stop")
		}

		srv.CancelHandoff()
		assertMuxPhase(t, srv, muxPhaseStoppingListen, true)
		if srv.isShuttingDown() {
			t.Fatal("isShuttingDown must be false in StoppingListen while draining sessions")
		}
		if srv.addActiveSession() {
			t.Fatal("addActiveSession must be rejected in StoppingListen")
		}
		assertMuxNotShutdownBriefly(t, srv, 40*time.Millisecond, "draining StoppingListen")

		srv.removeActiveSession()
		assertMuxShutdownCompleted(t, srv, "StoppingListen drained")
	})
}

func TestMuxServer_FSM_StoppingListenGuards(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain mux sockets are unsupported on Windows")
	}

	srv, _, cleanup := startChaosMaster(t, 0x46534d, "yes", 1)
	defer cleanup()

	// Open a dynamic-port local forward while Running so we can verify
	// handleCloseFwd still succeeds after transitioning to StoppingListen.
	preOpenPt := runSyncMuxPacketCall(t, func(c net.Conn) error {
		return srv.handleOpenFwd(c, MuxFwdRequest{
			RequestID:   9,
			FwdType:     MUX_FWD_LOCAL,
			ListenHost:  "127.0.0.1",
			ListenPort:  0,
			ConnectHost: "127.0.0.1",
			ConnectPort: 22,
		})
	})
	if preOpenPt != MUX_S_OK {
		t.Fatalf("handleOpenFwd before stop = 0x%x, want MUX_S_OK", preOpenPt)
	}

	stopPty := runSyncMuxPacketCall(t, func(c net.Conn) error { return srv.handleStopListening(c, 10) })
	if stopPty != MUX_S_OK {
		t.Fatalf("handleStopListening = 0x%x, want MUX_S_OK", stopPty)
	}
	assertMuxPhase(t, srv, muxPhaseStoppingListen, true)

	// New sessions and new forwards are rejected once StoppingListen.
	if srv.canAdmitNewSession() || srv.addActiveSession() {
		t.Fatal("expected session admission rejected in StoppingListen")
	}
	openPt := runSyncMuxPacketCall(t, func(c net.Conn) error {
		return srv.handleOpenFwd(c, MuxFwdRequest{
			RequestID:   11,
			FwdType:     MUX_FWD_LOCAL,
			ListenHost:  "127.0.0.1",
			ListenPort:  0,
			ConnectHost: "127.0.0.1",
			ConnectPort: 22,
		})
	})
	if openPt != MUX_S_FAILURE {
		t.Fatalf("handleOpenFwd in StoppingListen = 0x%x, want MUX_S_FAILURE", openPt)
	}

	// Existing forward streams and handleCloseFwd still succeed during StoppingListen.
	if !srv.addActiveForwardStream() {
		t.Fatal("expected addActiveForwardStream allowed in StoppingListen")
	}
	closePt := runSyncMuxPacketCall(t, func(c net.Conn) error {
		return srv.handleCloseFwd(c, MuxFwdRequest{
			RequestID:   12,
			FwdType:     MUX_FWD_LOCAL,
			ListenHost:  "127.0.0.1",
			ListenPort:  0,
			ConnectHost: "127.0.0.1",
			ConnectPort: 22,
		})
	})
	if closePt != MUX_S_OK {
		t.Fatalf("handleCloseFwd in StoppingListen = 0x%x, want MUX_S_OK", closePt)
	}

	srv.RemoveForegroundSession()
	// Active forward stream still keeps the StoppingListen server alive until released.
	assertMuxNotShutdownBriefly(t, srv, 40*time.Millisecond, "StoppingListen with active forward stream")

	srv.removeActiveForwardStream()
	assertMuxShutdownCompleted(t, srv, "StoppingListen after forward stream finished")
}

func TestMuxServer_FSM_TerminateDuringHandoffAndShutdownIdempotency(t *testing.T) {
	t.Run("TerminateInvalidatesHandoffAndClosesOnce", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled:    true,
			persistIndefinite: true,
			idleNotify:        make(chan struct{}),
			shutdownChan:      make(chan struct{}),
		}
		if !srv.PrepareHandoff() {
			t.Fatal("PrepareHandoff failed")
		}
		if pt := runSyncMuxPacketCall(t, func(c net.Conn) error { return srv.handleTerminate(c, 20) }); pt != MUX_S_OK {
			t.Fatalf("handleTerminate = 0x%x, want MUX_S_OK", pt)
		}
		if srv.CommitHandoffReady() {
			t.Fatal("CommitHandoffReady must return false after handleTerminate")
		}
		// CancelHandoff is a safe no-op after terminate.
		srv.CancelHandoff()
		assertMuxShutdownCompleted(t, srv, "after handleTerminate")

		// Idempotent Shutdown calls never panic or block.
		_ = srv.Shutdown()
		_ = srv.Shutdown()
	})

	t.Run("ShutdownIdempotentFromEveryPhase", func(t *testing.T) {
		phases := []muxPhase{
			muxPhaseRunning,
			muxPhaseHandoffReserved,
			muxPhaseStoppingListen,
			muxPhaseShuttingDown,
			muxPhaseClosed,
		}
		for _, ph := range phases {
			ctx, cancel := context.WithCancel(t.Context())
			srv := &MuxServer{
				phase:        ph,
				idleNotify:   make(chan struct{}),
				shutdownChan: make(chan struct{}),
				serverCtx:    ctx,
				serverCancel: cancel,
			}
			_ = srv.Shutdown()
			_ = srv.Shutdown()
			assertMuxShutdownCompleted(t, srv, "Shutdown from phase")
		}
	})
}

func TestMuxServer_FSM_ForegroundReleaseThreeState(t *testing.T) {
	t.Run("ArmedBeforeStopNeverDoubleDecrements", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled:    true,
			persistIndefinite: true,
			activeSessions:    1,
			foregroundHeld:    1,
			hadActiveSession:  true,
			idleNotify:        make(chan struct{}),
			shutdownChan:      make(chan struct{}),
		}
		srv.ReleaseForegroundOnStop()
		if pt := runSyncMuxPacketCall(t, func(c net.Conn) error { return srv.handleStopListening(c, 30) }); pt != MUX_S_OK {
			t.Fatalf("handleStopListening = 0x%x, want MUX_S_OK", pt)
		}
		assertMuxShutdownCompleted(t, srv, "armed foreground released by -O stop")

		// Late cleanup paths must not drive activeSessions negative.
		srv.ReleaseForegroundOnStop()
		srv.RemoveForegroundSession()
		if got := srv.ActiveSessions(); got != 0 {
			t.Fatalf("ActiveSessions = %d after repeated cleanup, want 0", got)
		}
	})

	t.Run("StoppedBeforeArmReleasesOnceOnly", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled:    true,
			persistIndefinite: true,
			activeSessions:    1,
			foregroundHeld:    1,
			hadActiveSession:  true,
			idleNotify:        make(chan struct{}),
			shutdownChan:      make(chan struct{}),
		}
		if pt := runSyncMuxPacketCall(t, func(c net.Conn) error { return srv.handleStopListening(c, 31) }); pt != MUX_S_OK {
			t.Fatalf("handleStopListening = 0x%x, want MUX_S_OK", pt)
		}
		if got := srv.ActiveSessions(); got != 1 {
			t.Fatalf("ActiveSessions = %d before ReleaseForegroundOnStop, want 1", got)
		}
		srv.ReleaseForegroundOnStop()
		srv.ReleaseForegroundOnStop()
		if got := srv.ActiveSessions(); got != 0 {
			t.Fatalf("ActiveSessions = %d after repeated ReleaseForegroundOnStop, want 0", got)
		}
		assertMuxShutdownCompleted(t, srv, "post-stop ReleaseForegroundOnStop")

		srv.RemoveForegroundSession()
		if got := srv.ActiveSessions(); got != 0 {
			t.Fatalf("ActiveSessions = %d after late RemoveForegroundSession, want 0", got)
		}
	})

	t.Run("AddForegroundSessionRearmsStateCleanly", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled:    true,
			persistIndefinite: true,
			idleNotify:        make(chan struct{}),
			shutdownChan:      make(chan struct{}),
		}
		if !srv.AddForegroundSession() {
			t.Fatal("AddForegroundSession failed")
		}
		if got := srv.ActiveSessions(); got != 1 {
			t.Fatalf("ActiveSessions = %d, want 1", got)
		}
		srv.RemoveForegroundSession()
		if got := srv.ActiveSessions(); got != 0 {
			t.Fatalf("ActiveSessions = %d after RemoveForegroundSession, want 0", got)
		}
	})
}

func TestMuxServer_FSM_ForegroundSlotNeverUnderflowsOrKillsPassenger(t *testing.T) {
	t.Run("EarlyRemoveForegroundThenReleaseOnStopAndStopKeepsPassengerAlive", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled:    true,
			persistIndefinite: true,
			activeSessions:    1,
			foregroundHeld:    1,
			hadActiveSession:  true,
			idleNotify:        make(chan struct{}),
			shutdownChan:      make(chan struct{}),
		}
		if !srv.addActiveSession() {
			t.Fatal("addActiveSession (passenger) failed")
		}
		if got := srv.ActiveSessions(); got != 2 {
			t.Fatalf("ActiveSessions = %d, want 2", got)
		}

		// Foreground session releases early before ReleaseForegroundOnStop / -O stop.
		srv.RemoveForegroundSession()
		srv.ReleaseForegroundOnStop()
		if pt := runSyncMuxPacketCall(t, func(c net.Conn) error { return srv.handleStopListening(c, 41) }); pt != MUX_S_OK {
			t.Fatalf("handleStopListening = 0x%x, want MUX_S_OK", pt)
		}

		if got := srv.ActiveSessions(); got != 1 {
			t.Fatalf("ActiveSessions = %d, want 1 (must not double-decrement into active passenger)", got)
		}
		assertMuxNotShutdownBriefly(t, srv, 40*time.Millisecond, "passenger alive after -O stop")

		srv.removeActiveSession()
		assertMuxShutdownCompleted(t, srv, "after passenger drained")
	})

	t.Run("DuplicateRemoveForegroundNeverUnderflows", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled:    true,
			persistIndefinite: true,
			idleNotify:        make(chan struct{}),
			shutdownChan:      make(chan struct{}),
		}
		srv.RemoveForegroundSession()
		srv.ReleaseForegroundOnStop()
		if got := srv.ActiveSessions(); got != 0 {
			t.Fatalf("ActiveSessions = %d with InitialActiveSessions=0, want 0", got)
		}
	})
}

func TestMuxServer_FSM_ShutdownAlwaysUnlinksSocketAfterStopListening(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain mux sockets are unsupported on Windows")
	}

	sockPath := filepath.Join(shortSocketDir(t), "unlink-after-stop.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:           sockPath,
		PersistEnabled:        true,
		PersistIndefinite:     true,
		SSHClient:             newDummySSHClient(),
		InitialActiveSessions: 1,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()

	// Simulate race where another path set stoppedListening before unlink ran, then Shutdown() executes.
	srv.idleMu.Lock()
	srv.stoppedListening = true
	srv.idleMu.Unlock()

	if _, statErr := os.Lstat(sockPath); statErr != nil {
		t.Fatalf("expected socket %q to exist before Shutdown: %v", sockPath, statErr)
	}
	_ = srv.Shutdown()
	<-srv.Wait()
	if _, statErr := os.Lstat(sockPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected Shutdown() to unlink own control socket after stoppedListening, stat err=%v", statErr)
	}

	// Verify origFi == nil never blindly unlinks an unrelated socket at the same path.
	foreignSock := filepath.Join(shortSocketDir(t), "foreign.sock")
	if err := os.WriteFile(foreignSock, []byte("x"), 0o600); err != nil {
		t.Fatalf("write foreign marker: %v", err)
	}
	foreignSrv := &MuxServer{
		controlPath:  foreignSock,
		idleNotify:   make(chan struct{}),
		shutdownChan: make(chan struct{}),
	}
	_ = foreignSrv.Shutdown()
	<-foreignSrv.Wait()
	if _, statErr := os.Lstat(foreignSock); statErr != nil {
		t.Fatalf("Shutdown() with origFi==nil unlinked foreign file: %v", statErr)
	}
}

func TestMuxServer_FSM_MultiForegroundStopDoesNotUnderflowOrDeadlock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain mux sockets are unsupported on Windows")
	}

	srv, _, cleanup := startChaosMaster(t, 0x4d4647, "no", 1)
	defer cleanup()

	if !srv.AddForegroundSession() {
		t.Fatal("AddForegroundSession failed on active master")
	}

	if pt := runSyncMuxPacketCall(t, func(c net.Conn) error { return srv.handleStopListening(c, 1) }); pt != MUX_S_OK {
		t.Fatalf("handleStopListening = 0x%x, want MUX_S_OK", pt)
	}
	assertMuxPhase(t, srv, muxPhaseStoppingListen, true)
	assertMuxNotShutdownBriefly(t, srv, 40*time.Millisecond, "waiting on two foreground slots")

	// First ReleaseForegroundOnStop releases only the initial -N slot; repeated calls are idempotent.
	srv.ReleaseForegroundOnStop()
	srv.ReleaseForegroundOnStop()
	assertMuxNotShutdownBriefly(t, srv, 40*time.Millisecond, "waiting on second foreground slot")

	// Releasing the second foreground session drains remaining work and triggers clean shutdown.
	srv.RemoveForegroundSession()
	assertMuxShutdownCompleted(t, srv, "multi-foreground drained")
}

func TestMuxServer_FSM_ConcurrentShutdownAndStopListeningNeverUnlinksReplacementSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain mux sockets are unsupported on Windows")
	}

	for iter := range 10 {
		sockPath := filepath.Join(shortSocketDir(t), fmt.Sprintf("race-replace-%d.sock", iter))
		_ = os.Remove(sockPath)
		srv := &MuxServer{
			controlPath:       sockPath,
			persistEnabled:    true,
			persistIndefinite: true,
			idleNotify:        make(chan struct{}),
			shutdownChan:      make(chan struct{}),
		}
		slot, err := bindAndLinkSocket(sockPath)
		if err != nil {
			t.Fatalf("iter %d bindAndLinkSocket: %v", iter, err)
		}
		srv.listener = slot.Listener()
		srv.slot = slot

		// Replace sockPath with a fresh master's listener before stop/shutdown race.
		_ = os.Remove(sockPath)
		repSlot, err := bindAndLinkSocket(sockPath)
		if err != nil {
			_ = slot.Release()
			t.Fatalf("iter %d replacement bindAndLinkSocket: %v", iter, err)
		}
		repFi := repSlot.FileInfo()

		start := make(chan struct{})
		stopErrCh := make(chan error, 1)
		shutdownErrCh := make(chan error, 1)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, _, callErr := chaosMuxPacketCall(func(c net.Conn) error { return srv.handleStopListening(c, 1) })
			stopErrCh <- callErr
		}()
		go func() {
			defer wg.Done()
			<-start
			shutdownErrCh <- srv.Shutdown()
		}()
		close(start)

		wg.Wait()
		<-srv.Wait()
		if stopErr := <-stopErrCh; stopErr != nil {
			_ = repSlot.Release()
			t.Fatalf("iter %d handleStopListening: %v", iter, stopErr)
		}
		if shutErr := <-shutdownErrCh; shutErr != nil {
			_ = repSlot.Release()
			t.Fatalf("iter %d Shutdown: %v", iter, shutErr)
		}

		curFi, lstatErr := os.Lstat(sockPath)
		_ = repSlot.Release()
		if lstatErr != nil {
			t.Fatalf("iter %d replacement socket disappeared during Shutdown/StopListening race: %v", iter, lstatErr)
		}
		if !os.SameFile(repFi, curFi) {
			t.Fatalf("iter %d replacement socket identity changed unexpectedly", iter)
		}
	}
}
