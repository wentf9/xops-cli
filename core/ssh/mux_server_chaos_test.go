package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

type chaosSSHConn struct {
	mu               sync.Mutex
	rng              *rand.Rand
	chans            chan cryptoSSH.NewChannel
	reqs             chan *cryptoSSH.Request
	closedCh         chan struct{}
	closeOnce        sync.Once
	nextPort         uint32
	tcpipFwdCalls    atomic.Int64
	cancelTcpipCalls atomic.Int64
}

func newChaosSSHConn(seed uint64) (*chaosSSHConn, *cryptoSSH.Client) {
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	c := &chaosSSHConn{
		rng:      rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15)),
		chans:    chans,
		reqs:     reqs,
		closedCh: make(chan struct{}),
		nextPort: 45100,
	}
	client := cryptoSSH.NewClient(c, chans, reqs)
	return c, client
}

func (c *chaosSSHConn) User() string          { return "chaos" }
func (c *chaosSSHConn) SessionID() []byte     { return []byte("chaos-session") }
func (c *chaosSSHConn) ClientVersion() []byte { return []byte("SSH-2.0-xops-chaos") }
func (c *chaosSSHConn) ServerVersion() []byte { return []byte("SSH-2.0-xops-chaos") }
func (c *chaosSSHConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 22}
}
func (c *chaosSSHConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000}
}

func (c *chaosSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	return nil, nil, errors.New("chaos OpenChannel not implemented: " + name)
}

func (c *chaosSSHConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	c.mu.Lock()
	jitter := time.Duration(c.rng.IntN(3)) * 500 * time.Microsecond
	roll := c.rng.IntN(10)
	c.mu.Unlock()
	if jitter > 0 {
		time.Sleep(jitter)
	}

	switch name {
	case "tcpip-forward":
		c.tcpipFwdCalls.Add(1)
		var req struct {
			BindAddr string
			BindPort uint32
		}
		_ = cryptoSSH.Unmarshal(payload, &req)
		if req.BindPort == 0 && wantReply {
			var alloc uint32
			c.mu.Lock()
			switch roll {
			case 0:
				alloc = 0 // invalid port 0
			case 1:
				alloc = 70000 // invalid port > 65535
			case 2:
				alloc = 45101 // intentional collision candidate
			default:
				alloc = c.nextPort
				c.nextPort++
				if c.nextPort > 60000 {
					c.nextPort = 45100
				}
			}
			c.mu.Unlock()
			return true, cryptoSSH.Marshal(struct{ Port uint32 }{Port: alloc}), nil
		}
		return true, nil, nil
	case "cancel-tcpip-forward":
		c.cancelTcpipCalls.Add(1)
		return true, nil, nil
	default:
		return false, nil, errors.New("unsupported global request: " + strconv.Quote(name))
	}
}

func (c *chaosSSHConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.chans)
		close(c.reqs)
		close(c.closedCh)
	})
	return nil
}

func (c *chaosSSHConn) Wait() error {
	<-c.closedCh
	return io.EOF
}

func startChaosMaster(t *testing.T, seed uint64, persist string, initSessions int32) (*MuxServer, *chaosSSHConn, func()) {
	t.Helper()
	sockPath := filepath.Join(shortSocketDir(t), "chaos.sock")
	conn, rawCli := newChaosSSHConn(seed)
	ctx, cancel := context.WithCancel(t.Context())
	srv, err := StartMuxServer(ctx, rawCli, MuxMasterOptions{
		Path: sockPath,
		Target: TargetContext{
			Host: "127.0.0.1",
			Port: 22,
			User: "chaos",
			Control: &ControlConfig{
				Master:  ControlMasterYes,
				Path:    sockPath,
				Persist: persist,
			},
		},
		InitialActiveSessions: initSessions,
	})
	if err != nil {
		cancel()
		_ = rawCli.Close()
		_ = conn.Close()
		if errors.Is(err, ErrUnsupportedMuxPlatform) {
			t.Skipf("mux control socket unsupported on platform: %v", err)
		}
		t.Fatalf("StartMuxServer: %v", err)
	}
	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			cancel()
			_ = srv.Shutdown()
			<-srv.Wait()
			_ = rawCli.Close()
			_ = conn.Close()
		})
	}
	t.Cleanup(cleanup)
	return srv, conn, cleanup
}

func chaosMuxPacketCall(fn func(net.Conn) error) (uint32, []byte, error) {
	c1, c2 := net.Pipe()
	defer func() {
		_ = c1.Close()
		_ = c2.Close()
	}()
	done := make(chan error, 1)
	go func() {
		done <- fn(c1)
	}()
	pt, payload, readErr := ReadMuxPacket(c2)
	hErr := <-done
	if readErr != nil {
		return 0, nil, readErr
	}
	return pt, payload, hErr
}

func checkMuxServerInvariants(t *testing.T, srv *MuxServer) bool {
	t.Helper()
	ok := true
	if got := srv.ActiveSessions(); got < 0 {
		t.Errorf("invariant violation: negative activeSessions = %d", got)
		ok = false
	}
	if got := srv.activeForwardStreams.Load(); got < 0 {
		t.Errorf("invariant violation: negative activeForwardStreams = %d", got)
		ok = false
	}
	return ok
}

func waitMasterShutdown(t *testing.T, srv *MuxServer, timeout time.Duration, label string) {
	t.Helper()
	select {
	case <-srv.Wait():
	case <-time.After(timeout):
		t.Fatalf("%s: MuxServer did not shut down within %v", label, timeout)
	}
}

func TestMuxServer_ChaosConcurrencyInvariants(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain mux control sockets are unsupported on Windows")
	}

	const baseSeed uint64 = 0x5eed20261119

	t.Run("ForwardOpenCloseAndHandoffRaces", func(t *testing.T) {
		for round := range 5 {
			runChaosForwardOpenCloseRound(t, baseSeed+uint64(round*100), round)
		}
	})

	t.Run("StopListeningPreservesActiveSessionsAndDoesNotDoubleDecrement", func(t *testing.T) {
		for iter := range 20 {
			runChaosStopListeningIter(t, baseSeed+1000+uint64(iter), iter)
		}
	})

	t.Run("TransportDropAndTerminateNeverLeaveZombieMaster", func(t *testing.T) {
		warmSrv, _, warmCleanup := startChaosMaster(t, baseSeed+2000, "yes", 0)
		_ = warmSrv.Shutdown()
		waitMasterShutdown(t, warmSrv, 2*time.Second, "warmup")
		warmCleanup()
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
		baseline := runtime.NumGoroutine()

		for iter := range 10 {
			runChaosTransportDropIter(t, baseSeed+2001+uint64(iter), iter)
		}

		waitForCondition(t, 2*time.Second, func() bool {
			return runtime.NumGoroutine() <= baseline+4
		}, "goroutines leaked across transport drops and terminates")
	})
}

func runChaosForwardOpenCloseRound(t *testing.T, roundSeed uint64, round int) {
	t.Helper()
	srv, _, cleanup := startChaosMaster(t, roundSeed, "50ms", 1)
	sockPath := srv.ControlPath()

	roundCtx, roundCancel := context.WithTimeout(t.Context(), 140*time.Millisecond)
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Go(func() {
			runChaosForwardWorker(t, roundCtx, srv, sockPath, roundSeed, round, w)
		})
	}

	wg.Wait()
	roundCancel()
	if !checkMuxServerInvariants(t, srv) {
		t.FailNow()
	}

	srv.RemoveForegroundSession()
	_ = srv.Shutdown()
	waitMasterShutdown(t, srv, 3*time.Second, "ForwardOpenCloseAndHandoffRaces")
	if !checkMuxServerInvariants(t, srv) {
		t.FailNow()
	}
	if GetActiveMuxServer(sockPath) != nil {
		t.Fatalf("seed=%#x round=%d: GetActiveMuxServer(%q) != nil after Shutdown", roundSeed, round, sockPath)
	}
	waitForCondition(t, 2*time.Second, func() bool {
		srv.idleMu.Lock()
		endpoints := len(srv.listenEndpoints)
		fwds := srv.forwardCount()
		srv.idleMu.Unlock()
		return endpoints == 0 && fwds == 0
	}, "forward tables did not drain to empty after Shutdown")
	cleanup()
}

type chaosForwardWorkerState struct {
	rng         *rand.Rand
	heldDynamic []uint32
	heldFixed   []uint16
	fgHeld      int
}

func runChaosForwardWorker(t *testing.T, roundCtx context.Context, srv *MuxServer, sockPath string, roundSeed uint64, round, worker int) {
	state := chaosForwardWorkerState{
		rng: rand.New(rand.NewPCG(roundSeed, uint64(worker+1))),
	}
	defer func() {
		for ; state.fgHeld > 0; state.fgHeld-- {
			srv.RemoveForegroundSession()
		}
	}()
	for reqSeq := uint32(1); roundCtx.Err() == nil; reqSeq++ {
		if !checkMuxServerInvariants(t, srv) {
			return
		}
		stepChaosForwardWorker(t, roundCtx, srv, sockPath, roundSeed, round, reqSeq, &state)
	}
}

func stepChaosForwardWorker(
	t *testing.T,
	roundCtx context.Context,
	srv *MuxServer,
	sockPath string,
	roundSeed uint64,
	round int,
	reqSeq uint32,
	state *chaosForwardWorkerState,
) {
	switch state.rng.IntN(7) {
	case 0, 1, 2, 3:
		stepChaosOpenForward(t, srv, roundSeed, round, reqSeq, state)
	case 4:
		closeHeldChaosForward(srv, reqSeq, state)
	case 5:
		stepChaosSessionAndHandoff(srv, state)
	case 6:
		dialCtx, dialCancel := context.WithTimeout(roundCtx, 50*time.Millisecond)
		if cli, err := DialMuxClient(dialCtx, sockPath); err == nil {
			_, _ = cli.AliveCheck(dialCtx)
			_ = cli.Close()
		}
		dialCancel()
	}
}

func stepChaosOpenForward(t *testing.T, srv *MuxServer, roundSeed uint64, round int, reqSeq uint32, state *chaosForwardWorkerState) {
	switch state.rng.IntN(4) {
	case 0:
		req := MuxFwdRequest{RequestID: reqSeq, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: 0, ConnectHost: "127.0.0.1", ConnectPort: 8080}
		pt, payload, err := chaosMuxPacketCall(func(c net.Conn) error { return srv.handleOpenFwd(c, req) })
		if err == nil && pt == MUX_S_REMOTE_PORT && len(payload) >= 8 {
			p := binary.BigEndian.Uint32(payload[4:8])
			if p == 0 || p > 65535 {
				t.Errorf("seed=%#x round=%d: server returned out-of-range dynamic port %d", roundSeed, round, p)
			}
			state.heldDynamic = append(state.heldDynamic, p)
		}
	case 1:
		port := uint16(46000 + state.rng.IntN(3))
		req := MuxFwdRequest{RequestID: reqSeq, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: uint32(port), ConnectHost: "127.0.0.1", ConnectPort: 8080}
		if pt, _, err := chaosMuxPacketCall(func(c net.Conn) error { return srv.handleOpenFwd(c, req) }); err == nil && pt == MUX_S_OK {
			state.heldFixed = append(state.heldFixed, port)
		}
	case 2:
		req := MuxFwdRequest{RequestID: reqSeq, FwdType: MUX_FWD_LOCAL, ListenHost: "127.0.0.1", ListenPort: 0, ConnectHost: "127.0.0.1", ConnectPort: 8080}
		_, _, _ = chaosMuxPacketCall(func(c net.Conn) error { return srv.handleOpenFwd(c, req) })
	case 3:
		req := MuxFwdRequest{RequestID: reqSeq, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: 70000, ConnectHost: "127.0.0.1", ConnectPort: 8080}
		if pt, _, err := chaosMuxPacketCall(func(c net.Conn) error { return srv.handleOpenFwd(c, req) }); err == nil && pt == MUX_S_OK {
			t.Errorf("seed=%#x round=%d: invalid port 70000 unexpectedly succeeded", roundSeed, round)
		}
	}
}

func stepChaosSessionAndHandoff(srv *MuxServer, state *chaosForwardWorkerState) {
	if srv.AddForegroundSession() {
		state.fgHeld++
	}
	if state.rng.IntN(2) == 0 && state.fgHeld > 0 {
		srv.RemoveForegroundSession()
		state.fgHeld--
	}
	if srv.PrepareHandoffWithSessions(2) {
		time.Sleep(time.Millisecond)
		srv.CancelHandoff()
	}
}

func closeHeldChaosForward(srv *MuxServer, reqSeq uint32, state *chaosForwardWorkerState) {
	var port uint32
	switch {
	case len(state.heldDynamic) > 0:
		port = state.heldDynamic[len(state.heldDynamic)-1]
		state.heldDynamic = state.heldDynamic[:len(state.heldDynamic)-1]
	case len(state.heldFixed) > 0:
		port = uint32(state.heldFixed[len(state.heldFixed)-1])
		state.heldFixed = state.heldFixed[:len(state.heldFixed)-1]
	default:
		return
	}
	_, _, _ = chaosMuxPacketCall(func(c net.Conn) error {
		return srv.handleCloseFwd(c, MuxFwdRequest{
			RequestID: reqSeq, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: port, ConnectHost: "127.0.0.1", ConnectPort: 8080,
		})
	})
}

func runChaosStopListeningIter(t *testing.T, iterSeed uint64, iter int) {
	t.Helper()
	srv, _, cleanup := startChaosMaster(t, iterSeed, "yes", 1)
	srv.ReleaseForegroundOnStop()
	if !srv.addActiveSession() {
		t.Fatalf("iter %d: failed to add passenger session", iter)
	}
	if got := srv.ActiveSessions(); got != 2 {
		t.Fatalf("iter %d: initial ActiveSessions = %d, want 2", iter, got)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _, _ = chaosMuxPacketCall(func(c net.Conn) error { return srv.handleStopListening(c, uint32(iter+1)) })
	})
	wg.Go(func() {
		if iter%2 == 0 {
			time.Sleep(time.Duration(iter%3) * 100 * time.Microsecond)
		}
		srv.RemoveForegroundSession()
	})
	wg.Go(func() {
		if srv.PrepareHandoffWithSessions(1) {
			srv.CancelHandoff()
		}
	})
	wg.Wait()

	time.Sleep(5 * time.Millisecond)
	if got := srv.ActiveSessions(); got != 1 {
		t.Fatalf("iter %d seed=%#x: ActiveSessions = %d, want 1", iter, iterSeed, got)
	}
	select {
	case <-srv.Wait():
		t.Fatalf("iter %d seed=%#x: MuxServer shut down early while passenger session active", iter, iterSeed)
	default:
	}

	srv.removeActiveSession()
	waitMasterShutdown(t, srv, 2*time.Second, "StopListeningPreservesActiveSessions")
	if GetActiveMuxServer(srv.ControlPath()) != nil {
		t.Fatalf("iter %d: activeMuxServers entry leaked after passenger drain", iter)
	}
	cleanup()
}

func runChaosTransportDropIter(t *testing.T, iterSeed uint64, iter int) {
	t.Helper()
	persist := "yes"
	if iter%2 == 1 {
		persist = "50ms"
	}
	srv, conn, cleanup := startChaosMaster(t, iterSeed, persist, 0)
	sockPath := srv.ControlPath()

	var wg sync.WaitGroup
	stopWorkers := make(chan struct{})
	for w := range 3 {
		wg.Go(func() {
			rng := rand.New(rand.NewPCG(iterSeed, uint64(w+1)))
			for seq := uint32(1); ; seq++ {
				select {
				case <-stopWorkers:
					return
				default:
				}
				req := MuxFwdRequest{
					RequestID: seq, FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1",
					ListenPort: uint32(47000 + rng.IntN(4)), ConnectHost: "127.0.0.1", ConnectPort: 8080,
				}
				_, _, _ = chaosMuxPacketCall(func(c net.Conn) error { return srv.handleOpenFwd(c, req) })
			}
		})
	}

	time.Sleep(15 * time.Millisecond)
	if iter%2 == 0 {
		_ = conn.Close()
	} else {
		rpcCtx, rpcCancel := context.WithTimeout(t.Context(), 2*time.Second)
		if cli, dialErr := DialMuxClient(rpcCtx, sockPath); dialErr == nil {
			_ = cli.Terminate(rpcCtx)
			_ = cli.Close()
		} else {
			_ = srv.Shutdown()
		}
		rpcCancel()
	}

	close(stopWorkers)
	wg.Wait()
	waitMasterShutdown(t, srv, 2*time.Second, "TransportDropAndTerminate")

	if GetActiveMuxServer(sockPath) != nil {
		t.Fatalf("iter %d seed=%#x: GetActiveMuxServer(%q) != nil after drop/terminate", iter, iterSeed, sockPath)
	}
	if _, statErr := os.Lstat(sockPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("iter %d seed=%#x: stale socket remains at %q (lstat err=%v)", iter, iterSeed, sockPath, statErr)
	}
	cleanup()
}
