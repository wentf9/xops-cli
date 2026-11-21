package ssh

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func startP4TestMuxServer(t *testing.T, opts MuxServerOptions) (*MuxServer, <-chan struct{}, func()) {
	t.Helper()
	srv, err := NewMuxServer(opts)
	if err != nil {
		if errors.Is(err, ErrUnsupportedMuxPlatform) {
			t.Skipf("mux control socket unsupported on platform: %v", err)
		}
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve()
	}()

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			_ = srv.Shutdown()
			<-srv.Wait()
			<-serveDone
		})
	}
	t.Cleanup(cleanup)
	return srv, serveDone, cleanup
}

func assertRawUnixPermissionDenied(t *testing.T, sockPath string) {
	t.Helper()
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		t.Fatalf("raw unix dial %q failed: %v", sockPath, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	msgType, payload, err := ReadMuxPacket(conn)
	if err != nil {
		t.Fatalf("ReadMuxPacket on rejected peer failed: %v", err)
	}
	if msgType != MUX_S_PERMISSION_DENIED {
		t.Fatalf("server response type = 0x%08x, want MUX_S_PERMISSION_DENIED (0x%08x)", msgType, MUX_S_PERMISSION_DENIED)
	}
	_, reason, err := DecodeMuxError(payload)
	if err != nil {
		t.Fatalf("DecodeMuxError failed: %v", err)
	}
	if !strings.Contains(reason, "peer UID check failed") {
		t.Fatalf("permission denied reason = %q, want substring %q", reason, "peer UID check failed")
	}
}

func TestP4_MuxServer_ZeroValuePeerCheckEnforced(t *testing.T) {
	t.Run("zero_value_options_accept_same_uid", assertP4ZeroValueAcceptsSameUID)
	t.Run("mismatched_expected_uid_without_check_peer_uid_rejects", assertP4MismatchedUIDWithoutFlagRejects)
	t.Run("explicit_expected_uid_zero_rejects_non_root", assertP4ExplicitUIDZeroRejectsNonRoot)
	t.Run("unknown_peer_check_mode_fails_closed", assertP4UnknownPeerCheckModeFailsClosed)
	t.Run("net_pipe_handle_client_requires_explicit_testing_opt_out", assertP4NetPipeRequiresTestingOptOut)
}

func assertP4ZeroValueAcceptsSameUID(t *testing.T) {
	sockPath := filepath.Join(shortSocketDir(t), "p4-zv-ok.sock")
	raw := newDummySSHClient()
	srv, _, cleanup := startP4TestMuxServer(t, MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   raw,
	})
	defer cleanup()

	if !srv.checkPeerUID {
		t.Fatal("zero-value MuxServerOptions must enable checkPeerUID")
	}
	if srv.expectedUID != localPeerUID() {
		t.Fatalf("zero-value expectedUID = %d, want localPeerUID() = %d", srv.expectedUID, localPeerUID())
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	cli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient on zero-value MuxServerOptions failed: %v", err)
	}
	defer func() { _ = cli.Close() }()

	pid, err := cli.AliveCheck(ctx)
	if err != nil {
		t.Fatalf("AliveCheck failed: %v", err)
	}
	if int(pid) != os.Getpid() {
		t.Fatalf("AliveCheck PID = %d, want %d", pid, os.Getpid())
	}
}

func assertP4MismatchedUIDWithoutFlagRejects(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX UID mismatch check not applicable on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("root bypasses UID mismatch in peer check")
	}

	sockPath := filepath.Join(shortSocketDir(t), "p4-zv-mismatch.sock")
	raw := newDummySSHClient()
	srv, _, cleanup := startP4TestMuxServer(t, MuxServerOptions{
		ControlPath: sockPath,
		ExpectedUID: uint32(os.Getuid()) + 9999,
		SSHClient:   raw,
	})
	defer cleanup()

	if !srv.checkPeerUID {
		t.Fatal("expected checkPeerUID == true when CheckPeerUID is omitted")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if cli, err := DialMuxClient(ctx, sockPath); err == nil {
		_ = cli.Close()
		t.Fatal("expected DialMuxClient to fail when ExpectedUID mismatches without CheckPeerUID")
	}
	assertRawUnixPermissionDenied(t, sockPath)
}

func assertP4ExplicitUIDZeroRejectsNonRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX UID 0 check not applicable on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("already running as root (UID 0)")
	}

	sockPath := filepath.Join(shortSocketDir(t), "p4-zv-root.sock")
	raw := newDummySSHClient()
	srv, _, cleanup := startP4TestMuxServer(t, MuxServerOptions{
		ControlPath:    sockPath,
		ExpectedUID:    0,
		HasExpectedUID: true,
		SSHClient:      raw,
	})
	defer cleanup()

	if !srv.checkPeerUID || srv.expectedUID != 0 {
		t.Fatalf("explicit UID 0 server = (checkPeerUID=%v, expectedUID=%d), want (true, 0)",
			srv.checkPeerUID, srv.expectedUID)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if cli, err := DialMuxClient(ctx, sockPath); err == nil {
		_ = cli.Close()
		t.Fatal("expected DialMuxClient to fail when HasExpectedUID=true ExpectedUID=0 for non-root process")
	}
	assertRawUnixPermissionDenied(t, sockPath)
}

func assertP4UnknownPeerCheckModeFailsClosed(t *testing.T) {
	sockPath := filepath.Join(shortSocketDir(t), "p4-zv-badmode.sock")
	raw := newDummySSHClient()
	defer func() { _ = raw.Close() }()

	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath: sockPath,
		PeerCheck:   PeerCheckMode(99),
		SSHClient:   raw,
	})
	if err == nil {
		_ = srv.Shutdown()
		t.Fatal("expected NewMuxServer with PeerCheckMode(99) to fail closed")
	}
	if _, statErr := os.Lstat(sockPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("invalid PeerCheckMode left socket artifact at %q (stat err=%v)", sockPath, statErr)
	}
}

func assertP4NetPipeRequiresTestingOptOut(t *testing.T) {
	assertP4NetPipeEnforcedRejects(t)
	assertP4NetPipeDisabledSucceeds(t)
}

func assertP4NetPipeEnforcedRejects(t *testing.T) {
	t.Helper()
	enforceSock := filepath.Join(shortSocketDir(t), "p4-pipe-enforce.sock")
	srvEnforce, err := NewMuxServer(MuxServerOptions{
		ControlPath: enforceSock,
		SSHClient:   newDummySSHClient(),
	})
	if err != nil {
		if errors.Is(err, ErrUnsupportedMuxPlatform) {
			t.Skipf("mux control socket unsupported on platform: %v", err)
		}
		t.Fatalf("NewMuxServer(enforce) failed: %v", err)
	}
	defer func() {
		_ = srvEnforce.Shutdown()
		<-srvEnforce.Wait()
	}()

	cliPipe, srvPipe := net.Pipe()
	doneEnforce := make(chan struct{})
	go func() {
		defer close(doneEnforce)
		srvEnforce.handleClient(srvPipe)
	}()

	_ = cliPipe.SetDeadline(time.Now().Add(2 * time.Second))
	msgType, payload, readErr := ReadMuxPacket(cliPipe)
	_ = cliPipe.Close()
	<-doneEnforce
	if readErr != nil {
		t.Fatalf("ReadMuxPacket on enforced net.Pipe failed: %v", readErr)
	}
	if msgType != MUX_S_PERMISSION_DENIED {
		t.Fatalf("enforced net.Pipe response = 0x%08x, want MUX_S_PERMISSION_DENIED (0x%08x)", msgType, MUX_S_PERMISSION_DENIED)
	}
	if _, reason, decErr := DecodeMuxError(payload); decErr != nil || !strings.Contains(reason, "peer UID check failed") {
		t.Fatalf("enforced net.Pipe error = (%q, %v), want peer UID check failure", reason, decErr)
	}
}

func assertP4NetPipeDisabledSucceeds(t *testing.T) {
	t.Helper()
	disabledSock := filepath.Join(shortSocketDir(t), "p4-pipe-disabled.sock")
	srvDisabled, err := NewMuxServer(MuxServerOptions{
		ControlPath: disabledSock,
		PeerCheck:   PeerCheckDisabledForTesting,
		SSHClient:   newDummySSHClient(),
	})
	if err != nil {
		t.Fatalf("NewMuxServer(disabled) failed: %v", err)
	}
	defer func() {
		_ = srvDisabled.Shutdown()
		<-srvDisabled.Wait()
	}()

	cliPipe, srvPipe := net.Pipe()
	doneDisabled := make(chan struct{})
	go func() {
		defer close(doneDisabled)
		srvDisabled.handleClient(srvPipe)
	}()

	_ = cliPipe.SetDeadline(time.Now().Add(2 * time.Second))
	if err := WriteMuxPacket(cliPipe, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, nil)); err != nil {
		t.Fatalf("send hello on net.Pipe failed: %v", err)
	}
	respType, respPayload, err := ReadMuxPacket(cliPipe)
	if err != nil || respType != MUX_MSG_HELLO {
		t.Fatalf("read hello response on disabled net.Pipe = (0x%08x, %v), want MUX_MSG_HELLO", respType, err)
	}
	if ver, _, decErr := DecodeMuxHello(respPayload); decErr != nil || ver != MuxProtoVersion {
		t.Fatalf("DecodeMuxHello = (ver=%d, err=%v), want version %d", ver, decErr, MuxProtoVersion)
	}

	const reqID uint32 = 7
	if err := WriteMuxPacket(cliPipe, MUX_C_ALIVE_CHECK, EncodeMuxRequestID(reqID)); err != nil {
		t.Fatalf("send alive check on net.Pipe failed: %v", err)
	}
	aliveType, alivePayload, err := ReadMuxPacket(cliPipe)
	if err != nil || aliveType != MUX_S_ALIVE {
		t.Fatalf("read alive response = (0x%08x, %v), want MUX_S_ALIVE", aliveType, err)
	}
	gotReqID, pid, err := DecodeMuxAlive(alivePayload)
	if err != nil || gotReqID != reqID || int(pid) != os.Getpid() {
		t.Fatalf("DecodeMuxAlive = (reqID=%d, pid=%d, err=%v), want (%d, %d, nil)", gotReqID, pid, err, reqID, os.Getpid())
	}

	_ = cliPipe.Close()
	<-doneDisabled
}

func TestP4_MuxServer_AdmitWorkStateMachineContracts(t *testing.T) {
	t.Run("idempotent_release_and_phase_guards", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled:    true,
			persistIndefinite: true,
			idleNotify:        make(chan struct{}),
			shutdownChan:      make(chan struct{}),
		}

		if _, ok := srv.admitMuxWork(muxWorkKind(99)); ok {
			t.Fatal("unknown muxWorkKind must fail closed")
		}

		relOpen, ok := srv.admitMuxWork(muxWorkOpenForward)
		if !ok {
			t.Fatal("admitMuxWork(muxWorkOpenForward) failed in Running")
		}
		relClose, ok := srv.admitMuxWork(muxWorkCloseForward)
		if !ok {
			t.Fatal("admitMuxWork(muxWorkCloseForward) failed in Running")
		}
		relSess, ok := srv.admitMuxWork(muxWorkSessionOpen)
		if !ok {
			t.Fatal("admitMuxWork(muxWorkSessionOpen) failed in Running")
		}

		// Repeated releases must be idempotent and never underflow.
		relOpen()
		relOpen()
		relClose()
		relClose()
		relSess()
		relSess()

		// Transition to StoppingListen via admitStopListening.
		first1, relStop1 := srv.admitStopListening()
		first2, relStop2 := srv.admitStopListening()
		if !first1 || first2 {
			t.Fatalf("admitStopListening firstStop = (%v, %v), want (true, false)", first1, first2)
		}
		if _, ok := srv.admitMuxWork(muxWorkOpenForward); ok {
			t.Fatal("muxWorkOpenForward must be rejected in StoppingListen")
		}
		if _, ok := srv.admitSessionOpen(); ok {
			t.Fatal("admitSessionOpen must be rejected in StoppingListen")
		}
		relCloseInStop, ok := srv.admitMuxWork(muxWorkCloseForward)
		if !ok {
			t.Fatal("muxWorkCloseForward must remain admitted in StoppingListen")
		}

		// Releasing stop replies while closeFwd is in flight must not shut down yet.
		relStop1()
		relStop1()
		relStop2()
		relStop2()
		assertMuxNotShutdownBriefly(t, srv, 25*time.Millisecond, "closeFwd still in flight during StoppingListen")

		// Releasing the last in-flight closeFwd transitions StoppingListen -> Closed.
		relCloseInStop()
		relCloseInStop()
		assertMuxShutdownCompleted(t, srv, "after final closeFwd released")

		if _, ok := srv.admitMuxWork(muxWorkCloseForward); ok {
			t.Fatal("muxWorkCloseForward must be rejected in Closed")
		}
		assertP4ZeroCounters(t, srv)
	})

	t.Run("session_ticket_promote_abort_and_race_rejection", func(t *testing.T) {
		srv := &MuxServer{
			persistEnabled:    true,
			persistIndefinite: true,
			idleNotify:        make(chan struct{}),
			shutdownChan:      make(chan struct{}),
		}

		// 1. Abort before Promote is idempotent and prevents later Promote.
		t1, ok := srv.admitSessionOpen()
		if !ok {
			t.Fatal("first admitSessionOpen failed")
		}
		t1.Abort()
		t1.Abort()
		if _, promoted := t1.Promote(); promoted {
			t.Fatal("Promote must fail after Abort")
		}

		// 2. Promote moves sessionOpensInFlight -> activeSessions; subsequent Abort is a no-op; releaseSession is idempotent.
		t2, ok := srv.admitSessionOpen()
		if !ok {
			t.Fatal("second admitSessionOpen failed")
		}
		rel2, promoted := t2.Promote()
		if !promoted {
			t.Fatal("t2.Promote failed")
		}
		if _, secondPromote := t2.Promote(); secondPromote {
			t.Fatal("second Promote on already-promoted ticket must fail")
		}
		t2.Abort() // Must be a no-op.
		if got := srv.ActiveSessions(); got != 1 {
			t.Fatalf("ActiveSessions after Promote + no-op Abort = %d, want 1", got)
		}

		// 3. StopListening racing between admitSessionOpen and Promote rejects Promote while keeping slot until Abort.
		t3, ok := srv.admitSessionOpen()
		if !ok {
			t.Fatal("third admitSessionOpen failed")
		}
		_, relStop := srv.admitStopListening()
		relStop()

		if _, promoted3 := t3.Promote(); promoted3 {
			t.Fatal("t3.Promote must fail after StopListening")
		}
		srv.idleMu.Lock()
		inFlightBeforeAbort := srv.sessionOpensInFlight
		srv.idleMu.Unlock()
		if inFlightBeforeAbort != 1 {
			t.Fatalf("sessionOpensInFlight before Abort = %d, want 1", inFlightBeforeAbort)
		}

		rel2()
		rel2()
		// Still kept alive by t3's un-aborted sessionOpensInFlight slot.
		assertMuxNotShutdownBriefly(t, srv, 25*time.Millisecond, "waiting on un-aborted rejected ticket")

		t3.Abort()
		t3.Abort()
		assertMuxShutdownCompleted(t, srv, "after rejected session ticket aborted")
		assertP4ZeroCounters(t, srv)
	})
}

func assertP4ZeroCounters(t *testing.T, srv *MuxServer) {
	t.Helper()
	srv.idleMu.Lock()
	defer srv.idleMu.Unlock()
	if srv.stopRepliesInFlight != 0 ||
		srv.sessionOpensInFlight != 0 ||
		srv.openFwdsInFlight != 0 ||
		srv.closeFwdsInFlight != 0 ||
		srv.activeSessions != 0 ||
		srv.activeForwardStreams != 0 ||
		srv.forwardTable.entryCountLocked() != 0 ||
		srv.forwardTable.endpointCountLocked() != 0 {
		t.Fatalf("counters did not settle to zero: stop=%d sessOpen=%d openFwd=%d closeFwd=%d activeSess=%d activeStreams=%d entries=%d endpoints=%d",
			srv.stopRepliesInFlight,
			srv.sessionOpensInFlight,
			srv.openFwdsInFlight,
			srv.closeFwdsInFlight,
			srv.activeSessions,
			srv.activeForwardStreams,
			srv.forwardTable.entryCountLocked(),
			srv.forwardTable.endpointCountLocked(),
		)
	}
}

func assertP4NonNegativeCounters(t *testing.T, srv *MuxServer) {
	t.Helper()
	srv.idleMu.Lock()
	stopReplies := srv.stopRepliesInFlight
	sessOpens := srv.sessionOpensInFlight
	openFwds := srv.openFwdsInFlight
	closeFwds := srv.closeFwdsInFlight
	activeSess := srv.activeSessions
	activeStreams := srv.activeForwardStreams
	srv.idleMu.Unlock()
	if stopReplies < 0 || sessOpens < 0 || openFwds < 0 || closeFwds < 0 || activeSess < 0 || activeStreams < 0 {
		t.Errorf("negative counter invariant violated: stop=%d sessOpen=%d openFwd=%d closeFwd=%d activeSess=%d activeStreams=%d",
			stopReplies, sessOpens, openFwds, closeFwds, activeSess, activeStreams)
	}
}

func runP4ChaosWorkerStep(ctx context.Context, srv *MuxServer, sockPath string, rng *rand.Rand, workerID int) {
	opCtx, opCancel := context.WithTimeout(ctx, 80*time.Millisecond)
	defer opCancel()

	localFwdReq := ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: "127.0.0.1",
		ConnectPort: uint32(18000 + workerID),
	}
	dynFwdReq := ForwardRequest{
		Type:       ForwardDynamic,
		ListenHost: "127.0.0.1",
		ListenPort: 0,
	}

	switch rng.IntN(6) {
	case 0:
		cli, err := DialMuxClient(opCtx, sockPath)
		if err == nil {
			_, _ = cli.AliveCheck(opCtx)
			_ = cli.Close()
		}
	case 1:
		cli, err := DialMuxClient(opCtx, sockPath)
		if err == nil {
			sshCli, proxyConn, proxyErr := cli.Proxy(opCtx, TargetContext{})
			if proxyErr == nil {
				time.Sleep(time.Duration(rng.IntN(3)) * time.Millisecond)
				_ = sshCli.Close()
				_ = proxyConn.Close()
			}
			_ = cli.Close()
		}
	case 2:
		cli, err := DialMuxClient(opCtx, sockPath)
		if err == nil {
			_, _ = cli.OpenForward(opCtx, localFwdReq)
			_ = cli.Close()
		}
	case 3:
		cli, err := DialMuxClient(opCtx, sockPath)
		if err == nil {
			_, _ = cli.OpenForward(opCtx, dynFwdReq)
			_ = cli.Close()
		}
	case 4:
		cli, err := DialMuxClient(opCtx, sockPath)
		if err == nil {
			if rng.IntN(2) == 0 {
				_ = cli.CloseForward(opCtx, localFwdReq)
			} else {
				_ = cli.CloseForward(opCtx, dynFwdReq)
			}
			_ = cli.Close()
		}
	case 5:
		if srv.PrepareHandoffWithSessions(1) {
			time.Sleep(time.Millisecond)
			srv.CancelHandoff()
		}
	}
}

func waitP4CountersSettled(t *testing.T, srv *MuxServer) {
	t.Helper()
	waitForCondition(t, 3*time.Second, func() bool {
		srv.idleMu.Lock()
		defer srv.idleMu.Unlock()
		return srv.phase == muxPhaseClosed &&
			srv.stopRepliesInFlight == 0 &&
			srv.sessionOpensInFlight == 0 &&
			srv.openFwdsInFlight == 0 &&
			srv.closeFwdsInFlight == 0 &&
			srv.activeSessions == 0 &&
			srv.activeForwardStreams == 0 &&
			srv.forwardTable.entryCountLocked() == 0 &&
			srv.forwardTable.endpointCountLocked() == 0
	}, "MuxServer counters did not settle to zero after Shutdown")
	assertP4ZeroCounters(t, srv)
}

func TestP4_MuxServer_AdmitWorkConcurrentChaosAndIdleTimer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain mux control socket chaos test skipped on Windows")
	}
	t.Cleanup(func() { goleak.VerifyNone(t) })

	t.Run("concurrent_workers_with_stop_listening_and_shutdown", func(t *testing.T) {
		sockPath := filepath.Join(shortSocketDir(t), "p4-chaos-stop.sock")
		srv, serveDone, cleanup := startP4TestMuxServer(t, MuxServerOptions{
			ControlPath:     sockPath,
			PersistEnabled:  true,
			PersistDuration: 25 * time.Millisecond,
			SSHClient:       newDummySSHClient(),
		})
		defer cleanup()

		chaosCtx, chaosCancel := context.WithTimeout(t.Context(), 140*time.Millisecond)
		defer chaosCancel()

		var wg sync.WaitGroup
		for workerID := range 8 {
			wg.Go(func() {
				rng := rand.New(rand.NewPCG(0x50344d5558, uint64(workerID+1)))
				for chaosCtx.Err() == nil {
					assertP4NonNegativeCounters(t, srv)
					runP4ChaosWorkerStep(chaosCtx, srv, sockPath, rng, workerID)
				}
			})
		}

		// Trigger StopListening mid-chaos so it races with active DialMuxClient workers.
		wg.Go(func() {
			timer := time.NewTimer(70 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-chaosCtx.Done():
				return
			}
			stopCtx, stopCancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
			defer stopCancel()
			if cli, err := DialMuxClient(stopCtx, sockPath); err == nil {
				_ = cli.StopListening(stopCtx)
				_ = cli.Close()
			}
		})

		wg.Wait()
		_ = srv.Shutdown()
		waitMasterShutdown(t, srv, 3*time.Second, "p4 chaos stop")
		<-serveDone
		waitP4CountersSettled(t, srv)
	})

	t.Run("concurrent_workers_and_idle_timer_auto_shutdown", func(t *testing.T) {
		sockPath := filepath.Join(shortSocketDir(t), "p4-chaos-idle.sock")
		srv, serveDone, cleanup := startP4TestMuxServer(t, MuxServerOptions{
			ControlPath:     sockPath,
			PersistEnabled:  true,
			PersistDuration: 25 * time.Millisecond,
			SSHClient:       newDummySSHClient(),
		})
		defer cleanup()

		chaosCtx, chaosCancel := context.WithTimeout(t.Context(), 110*time.Millisecond)
		defer chaosCancel()

		var wg sync.WaitGroup
		for workerID := range 6 {
			wg.Go(func() {
				rng := rand.New(rand.NewPCG(0x503449444c, uint64(workerID+1)))
				for chaosCtx.Err() == nil {
					assertP4NonNegativeCounters(t, srv)
					runP4ChaosWorkerStep(chaosCtx, srv, sockPath, rng, workerID)
				}
			})
		}
		wg.Wait()

		// Without calling Shutdown or StopListening, the 25ms ControlPersist idle
		// timer must fire and shut the server down cleanly once work drains.
		waitMasterShutdown(t, srv, 3*time.Second, "p4 chaos idle timer")
		<-serveDone
		waitP4CountersSettled(t, srv)
	})
}
