package ssh

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// modeSwitchConn wraps a real TCP net.Conn and can deterministically switch
// into either write-wedged mode (Write blocks until Close, simulating a full
// TCP SO_SNDBUF or stalled SSH KEX barrier) or silent-blackhole mode (Write
// returns len(p), nil as if SO_SNDBUF had room while Read blocks forever until
// Close, never delivering SSH_MSG_CHANNEL_CLOSE back from the bastion).
type modeSwitchConn struct {
	net.Conn
	wedgeWrite   atomic.Bool
	blackhole    atomic.Bool
	closedCh     chan struct{}
	closeOnce    sync.Once
	writeBlocked chan struct{}
	blockOnce    sync.Once
	closed       atomic.Bool
}

func newModeSwitchConn(raw net.Conn) *modeSwitchConn {
	return &modeSwitchConn{
		Conn:         raw,
		closedCh:     make(chan struct{}),
		writeBlocked: make(chan struct{}),
	}
}

func (c *modeSwitchConn) Read(p []byte) (int, error) {
	for {
		if c.blackhole.Load() {
			<-c.closedCh
			return 0, net.ErrClosed
		}
		n, err := c.Conn.Read(p)
		if err != nil {
			return n, err
		}
		if !c.blackhole.Load() {
			return n, nil
		}
	}
}

func (c *modeSwitchConn) Write(p []byte) (int, error) {
	if c.wedgeWrite.Load() {
		c.blockOnce.Do(func() { close(c.writeBlocked) })
		<-c.closedCh
		return 0, net.ErrClosed
	}
	if c.blackhole.Load() {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *modeSwitchConn) Close() error {
	c.closed.Store(true)
	c.closeOnce.Do(func() { close(c.closedCh) })
	return c.Conn.Close()
}

type modeSwitchDialer struct {
	mu    sync.Mutex
	conns []*modeSwitchConn
}

func (d *modeSwitchDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *modeSwitchDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	mc := newModeSwitchConn(raw)
	d.mu.Lock()
	d.conns = append(d.conns, mc)
	d.mu.Unlock()
	return mc, nil
}

func (d *modeSwitchDialer) connAt(idx int) *modeSwitchConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	if idx < 0 || idx >= len(d.conns) {
		return nil
	}
	return d.conns[idx]
}

func (d *modeSwitchDialer) closeAll() {
	d.mu.Lock()
	snapshot := append([]*modeSwitchConn(nil), d.conns...)
	d.mu.Unlock()
	for _, c := range snapshot {
		_ = c.Close()
	}
}

// syntheticRawChanConn emulates an x/crypto/ssh *ssh.chanConn without deadline
// support and with configurable Close/Read/Write blocking modes.
type syntheticRawChanConn struct {
	net.Conn
	blockClose   bool
	blackholeEOF bool
	readCh       chan []byte
	writeBlockCh chan struct{}
	abortCh      chan struct{}
	abortOnce    sync.Once
	closeCalls   atomic.Int32
}

func newSyntheticRawChanConn(blockClose, blackholeEOF bool) *syntheticRawChanConn {
	return &syntheticRawChanConn{
		blockClose:   blockClose,
		blackholeEOF: blackholeEOF,
		readCh:       make(chan []byte, 4),
		abortCh:      make(chan struct{}),
	}
}

func (c *syntheticRawChanConn) forceAbort() {
	c.abortOnce.Do(func() { close(c.abortCh) })
}

func (c *syntheticRawChanConn) Read(p []byte) (int, error) {
	select {
	case data := <-c.readCh:
		return copy(p, data), nil
	case <-c.abortCh:
		return 0, io.EOF
	}
}

func (c *syntheticRawChanConn) Write(p []byte) (int, error) {
	if c.writeBlockCh != nil {
		select {
		case <-c.writeBlockCh:
		case <-c.abortCh:
			return 0, io.EOF
		}
	}
	select {
	case <-c.abortCh:
		return 0, io.EOF
	default:
		return len(p), nil
	}
}

func (c *syntheticRawChanConn) Close() error {
	c.closeCalls.Add(1)
	if c.blockClose {
		<-c.abortCh
		return net.ErrClosed
	}
	if !c.blackholeEOF {
		c.forceAbort()
	}
	return nil
}

func (c *syntheticRawChanConn) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (c *syntheticRawChanConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }
func (c *syntheticRawChanConn) SetDeadline(time.Time) error {
	return errors.New("ssh: tcpChan: deadline not supported")
}
func (c *syntheticRawChanConn) SetReadDeadline(time.Time) error {
	return errors.New("ssh: tcpChan: deadline not supported")
}
func (c *syntheticRawChanConn) SetWriteDeadline(time.Time) error {
	return errors.New("ssh: tcpChan: deadline not supported")
}

// hookedBannerTarget accepts TCP connections from the bastion, waits until the
// client's SSH version banner arrives (proving direct-tcpip is open and
// ssh.NewClientConn is active), invokes onFirstBanner once, and then optionally
// sends a server banner so the client enters KEXINIT Write before stalling.
type hookedBannerTarget struct {
	addr     string
	listener net.Listener
	wg       sync.WaitGroup
}

func startHookedBannerTarget(t *testing.T, sendBanner bool, onFirstBanner func()) *hookedBannerTarget {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen hooked target: %v", err)
	}
	ht := &hookedBannerTarget{addr: ln.Addr().String(), listener: ln}
	var triggerOnce sync.Once
	ht.wg.Go(func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			ht.wg.Go(func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 256)
				n, rErr := conn.Read(buf)
				if n > 0 && onFirstBanner != nil {
					triggerOnce.Do(onFirstBanner)
				}
				if rErr != nil {
					return
				}
				if sendBanner {
					_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
				}
				// Hold connection open without answering KEX until closed.
				_, _ = io.Copy(io.Discard, conn)
			})
		}
	})
	t.Cleanup(func() {
		_ = ln.Close()
		ht.wg.Wait()
	})
	return ht
}

func waitForGoroutinesAtMost(t *testing.T, maxCount int, timeout time.Duration, label string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		runtime.Gosched()
		if runtime.NumGoroutine() <= maxCount {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: goroutine count = %d, want <= %d (possible leak)", label, runtime.NumGoroutine(), maxCount)
}

// TestC6_ProxyChanConn_DeadlinesAndBoundedClose verifies the proxyChanConn
// foundation: real Read/Write deadlines, live deadline updates, idempotent
// close matching both io.EOF and net.ErrClosed, healthy non-escalation, and
// bounded escalation under both write-wedged and silent-blackhole raw channels.
func TestC6_ProxyChanConn_DeadlinesAndBoundedClose(t *testing.T) {
	t.Run("deadlines_and_live_updates", testC6ProxyChanConnDeadlines)
	t.Run("idempotent_concurrent_close", testC6ProxyChanConnIdempotentClose)
	t.Run("healthy_wedged_and_blackholed_close", testC6ProxyChanConnCloseEscalationModes)
}

func testC6ProxyChanConnDeadlines(t *testing.T) {
	raw := newSyntheticRawChanConn(false, false)
	raw.writeBlockCh = make(chan struct{})
	pc := newProxyChanConn(raw, func(net.Conn) error {
		raw.forceAbort()
		return nil
	})
	defer func() { _ = pc.Close() }()

	if err := pc.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	_, err := pc.Read(make([]byte, 16))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read after read deadline = %v, want os.ErrDeadlineExceeded", err)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("Read deadline error does not satisfy net.Error.Timeout(): %v", err)
	}
	if elapsed := time.Since(start); elapsed >= 300*time.Millisecond {
		t.Fatalf("Read deadline took %v, want prompt wakeup", elapsed)
	}

	// Clearing read deadline allows subsequent data to arrive cleanly.
	if err := pc.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear SetReadDeadline: %v", err)
	}
	raw.readCh <- []byte("hello-jump")
	buf := make([]byte, 5)
	n, err := pc.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("Read part 1 = (%q, %v), want (%q, nil)", buf[:n], err, "hello")
	}
	n, err = pc.Read(buf)
	if err != nil || string(buf[:n]) != "-jump" {
		t.Fatalf("Read part 2 = (%q, %v), want (%q, nil)", buf[:n], err, "-jump")
	}

	// Blocked Write wakes promptly on SetWriteDeadline and later unblocks cleanly.
	if err := pc.SetWriteDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	_, err = pc.Write([]byte("blocked-payload"))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write after write deadline = %v, want os.ErrDeadlineExceeded", err)
	}
	close(raw.writeBlockCh)
	if err := pc.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clear SetWriteDeadline: %v", err)
	}
	if n, err := pc.Write([]byte("ok")); err != nil || n != 2 {
		t.Fatalf("Write after unblock = (%d, %v), want (2, nil)", n, err)
	}
}

func testC6ProxyChanConnIdempotentClose(t *testing.T) {
	raw := newSyntheticRawChanConn(false, false)
	pc := newProxyChanConn(raw, nil)

	if err := pc.Close(); err != nil {
		t.Fatalf("first Close() = %v, want nil", err)
	}
	secondErr := pc.Close()
	if !errors.Is(secondErr, io.EOF) || !errors.Is(secondErr, net.ErrClosed) {
		t.Fatalf("second Close() = %v, want errors matching both io.EOF and net.ErrClosed", secondErr)
	}
	if raw.closeCalls.Load() != 1 {
		t.Fatalf("raw.Close() calls = %d, want 1", raw.closeCalls.Load())
	}
	if err := pc.SetDeadline(time.Now().Add(time.Second)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetDeadline on closed proxyChanConn = %v, want net.ErrClosed", err)
	}
}

func testC6ProxyChanConnCloseEscalationModes(t *testing.T) {
	for _, tc := range []struct {
		name         string
		blockClose   bool
		blackholeEOF bool
		wantEscalate bool
	}{
		{name: "healthy_bastion_no_escalate", blockClose: false, blackholeEOF: false, wantEscalate: false},
		{name: "write_wedged_bastion_escalates", blockClose: true, blackholeEOF: false, wantEscalate: true},
		{name: "silent_blackhole_bastion_escalates", blockClose: false, blackholeEOF: true, wantEscalate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := newSyntheticRawChanConn(tc.blockClose, tc.blackholeEOF)
			var aborted atomic.Bool
			pc := newProxyChanConn(raw, func(net.Conn) error {
				aborted.Store(true)
				raw.forceAbort()
				return nil
			})

			// Start an in-flight Read so readLoop is blocked inside raw.Read.
			readDone := make(chan error, 1)
			go func() {
				_, err := pc.Read(make([]byte, 16))
				readDone <- err
			}()
			time.Sleep(10 * time.Millisecond)

			waitWithin(t, "proxyChanConn.Close "+tc.name, 500*time.Millisecond, func() {
				if err := pc.Close(); err != nil {
					t.Errorf("Close() = %v, want nil", err)
				}
			})
			select {
			case err := <-readDone:
				if err == nil {
					t.Fatal("expected blocked Read to fail on Close")
				}
			case <-time.After(200 * time.Millisecond):
				t.Fatal("blocked Read did not wake on Close")
			}
			if aborted.Load() != tc.wantEscalate {
				t.Fatalf("abortUpstream called = %v, want %v", aborted.Load(), tc.wantEscalate)
			}
		})
	}
}

// TestC6_H1_CloseAllAndMuxServerUnderWedgedBastion verifies C6-H1:
// Connector.CloseAll (including concurrent second CloseAll waiters) and
// MuxServer.Shutdown / interruptTransportAndShutdown complete in <500ms with
// zero leaked goroutines when bastion's TCP Write path is wedged while
// ControlMaster=auto is active on target (or both hops).
func TestC6_H1_CloseAllAndMuxServerUnderWedgedBastion(t *testing.T) {
	t.Run("closeall_target_master_wedged_bastion", func(t *testing.T) {
		testC6H1CloseAllUnderWedgedBastion(t, false)
	})
	t.Run("closeall_both_masters_wedged_bastion", func(t *testing.T) {
		testC6H1CloseAllUnderWedgedBastion(t, true)
	})
	t.Run("mux_interrupt_transport_and_shutdown_wedged_bastion", testC6H1MuxInterruptUnderWedgedBastion)
	t.Run("mux_shutdown_physical_root_fallback", testC6H1MuxPhysicalRootFallback)
}

func testC6H1CloseAllUnderWedgedBastion(t *testing.T, bastionMasterEnabled bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	tmpDir := shortSocketDir(t)
	bastionSock := filepath.Join(tmpDir, "b.sock")
	targetSock := filepath.Join(tmpDir, "t.sock")

	ctrls := map[string]*ControlConfig{
		"target": {Master: ControlMasterAuto, Path: targetSock, Persist: "yes"},
	}
	if bastionMasterEnabled {
		ctrls["bastion"] = &ControlConfig{Master: ControlMasterAuto, Path: bastionSock, Persist: "yes"}
	}
	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
		ctrls: ctrls,
	}

	baselineGoroutines := runtime.NumGoroutine()
	dialer := &modeSwitchDialer{}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	if _, err := connector.Connect(ctx, "target"); err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	waitForCondition(t, 2*time.Second, func() bool {
		if GetActiveMuxServer(targetSock) == nil {
			return false
		}
		if bastionMasterEnabled && GetActiveMuxServer(bastionSock) == nil {
			return false
		}
		return true
	}, "expected control master(s) to start")

	bastionConn := dialer.connAt(0)
	if bastionConn == nil {
		t.Fatal("expected dialer to record bastion transport")
	}
	bastionConn.wedgeWrite.Store(true)

	// Invoke Connector.CloseAll() concurrently from two callers; BOTH must
	// complete in <500ms without hanging in targetMaster.Shutdown().
	var err1, err2 error
	waitWithin(t, "concurrent Connector.CloseAll over write-wedged bastion with ControlMaster", 500*time.Millisecond, func() {
		var wg sync.WaitGroup
		wg.Go(func() { err1 = connector.CloseAll() })
		wg.Go(func() { err2 = connector.CloseAll() })
		wg.Wait()
	})
	if err1 != nil || err2 != nil {
		t.Fatalf("CloseAll errors = (%v, %v), want (nil, nil)", err1, err2)
	}
	if !bastionConn.closed.Load() {
		t.Fatal("wedged bastion physical RootConn was not closed by CloseAll")
	}
	if GetActiveMuxServer(targetSock) != nil {
		t.Fatal("target control master still active after CloseAll")
	}
	if _, statErr := os.Lstat(targetSock); !os.IsNotExist(statErr) {
		t.Fatalf("target control socket not unlinked after CloseAll: statErr=%v", statErr)
	}
	if bastionMasterEnabled {
		if GetActiveMuxServer(bastionSock) != nil {
			t.Fatal("bastion control master still active after CloseAll")
		}
		if _, statErr := os.Lstat(bastionSock); !os.IsNotExist(statErr) {
			t.Fatalf("bastion control socket not unlinked after CloseAll: statErr=%v", statErr)
		}
	}
	if connector.pool.Count() != 0 || connector.pool.ClosingCount() != 0 || connector.pool.RetiredCount() != 0 {
		t.Fatalf("pool not drained after CloseAll: active=%d retired=%d closing=%d",
			connector.pool.Count(), connector.pool.RetiredCount(), connector.pool.ClosingCount())
	}
	// Allow tiny jitter for runtime/test server accept goroutines while verifying
	// no proxyChanConn / MuxServer / SSH transport goroutines leaked.
	waitForGoroutinesAtMost(t, baselineGoroutines+2, 500*time.Millisecond, "C6-H1 post-CloseAll goroutine check")
}

func testC6H1MuxInterruptUnderWedgedBastion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	targetSock := filepath.Join(shortSocketDir(t), "int-t.sock")
	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
		ctrls: map[string]*ControlConfig{
			"target": {Master: ControlMasterAuto, Path: targetSock, Persist: "yes"},
		},
	}

	dialer := &modeSwitchDialer{}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	if _, err := connector.Connect(ctx, "target"); err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	var targetMaster *MuxServer
	waitForCondition(t, 2*time.Second, func() bool {
		targetMaster = GetActiveMuxServer(targetSock)
		return targetMaster != nil
	}, "target master did not start")

	bastionConn := dialer.connAt(0)
	bastionConn.wedgeWrite.Store(true)

	waitWithin(t, "MuxServer.interruptTransportAndShutdown over wedged bastion", 500*time.Millisecond, func() {
		_ = targetMaster.interruptTransportAndShutdown()
	})
	if !bastionConn.closed.Load() {
		t.Fatal("interruptTransportAndShutdown did not abort wedged bastion physical transport")
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after mux interruptTransportAndShutdown: %v", err)
	}
}

func testC6H1MuxPhysicalRootFallback(t *testing.T) {
	rawHop := newSyntheticRawChanConn(true, false)
	physRoot := newSyntheticRawChanConn(false, false)
	// Simulate physicalRoot.Close() unblocking rawHop.Close() just like a TCP
	// bastion socket abort unblocks a multiplexed *ssh.chanConn.
	linkedRoot := &physicalRootHookConn{
		Conn:    physRoot,
		onClose: rawHop.forceAbort,
	}

	sockPath := filepath.Join(shortSocketDir(t), "raw-fb.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:      sockPath,
		PeerCheck:        PeerCheckDisabledForTesting,
		SSHClient:        newDummySSHClient(),
		RootConn:         rawHop,
		PhysicalRootConn: linkedRoot,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	go func() { _ = srv.Serve() }()

	waitWithin(t, "NewMuxServer.Shutdown with wedged raw RootConn and PhysicalRootConn fallback", 500*time.Millisecond, func() {
		_ = srv.Shutdown()
	})
	if !linkedRoot.closed.Load() {
		t.Fatal("MuxServer.Shutdown did not escalate to PhysicalRootConn")
	}
}

type physicalRootHookConn struct {
	net.Conn
	closed  atomic.Bool
	onClose func()
}

func (c *physicalRootHookConn) Close() error {
	c.closed.Store(true)
	if c.onClose != nil {
		c.onClose()
	}
	return c.Conn.Close()
}

// TestC6_H2_ProxyChanConnHandshakeAndCleanup verifies C6-H2:
//  1. Write-wedged bastion right after direct-tcpip open fails within
//     ConnectTimeout + grace (<500ms) and subsequent Connect(target) succeeds.
//  2. Post-handshake failure cleanup over a write-wedged bastion completes in
//     <500ms and does not wedge singleflight.
//  3. Silent blackholed bastion (empty SO_SNDBUF) right after direct-tcpip open
//     fails within ConnectTimeout + grace (<500ms) and subsequent Connect(target) succeeds.
//  4. Control: blackholed target behind a HEALTHY bastion times out cleanly
//     while keeping bastion alive and pooled.
func TestC6_H2_ProxyChanConnHandshakeAndCleanup(t *testing.T) {
	t.Run("2a_write_wedged_bastion_during_handshake", func(t *testing.T) {
		testC6H2BastionFailureDuringHandshake(t, true)
	})
	t.Run("2a_post_handshake_failure_cleanup_wedged_bastion", testC6H2PostHandshakeFailureWedgedBastion)
	t.Run("2b_silent_blackhole_bastion_during_handshake", func(t *testing.T) {
		testC6H2BastionFailureDuringHandshake(t, false)
	})
	t.Run("2c_control_blackholed_target_behind_healthy_bastion", testC6H2ControlBlackholedTargetHealthyBastion)
}

func testC6H2BastionFailureDuringHandshake(t *testing.T, wedgeWrite bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	healthyTargetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	healthyHost, healthyPort := fixtureEndpoint(t, healthyTargetSrv.addr)

	dialer := &modeSwitchDialer{}
	var armed atomic.Bool
	hookTarget := startHookedBannerTarget(t, wedgeWrite, func() {
		if bc := dialer.connAt(0); bc != nil {
			if wedgeWrite {
				bc.wedgeWrite.Store(true)
			} else {
				bc.blackhole.Store(true)
			}
			armed.Store(true)
		}
	})
	hHost, hPort := fixtureEndpoint(t, hookTarget.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: hHost, Port: hPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
	}

	connector := newTestConnector(
		provider,
		WithDialer(dialer),
		WithHostKeyVerifier(&fixtureTrust{}),
		WithHandshakeTimeout(80*time.Millisecond),
	)
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	start := time.Now()
	var firstErr error
	waitWithin(t, "Connect(target) over wedged/blackholed bastion", 500*time.Millisecond, func() {
		_, firstErr = connector.Connect(ctx, "target")
	})
	elapsed := time.Since(start)
	if firstErr == nil {
		t.Fatal("expected Connect(target) to fail when bastion wedged/blackholed after direct-tcpip open")
	}
	if !armed.Load() {
		t.Fatal("test precondition failed: bastion fault was never armed after direct-tcpip open")
	}
	if elapsed >= 500*time.Millisecond {
		t.Fatalf("Connect(target) took %v, want <500ms", elapsed)
	}
	bc0 := dialer.connAt(0)
	if bc0 == nil || !bc0.closed.Load() {
		t.Fatal("proxyChanConn escalation did not close dead bastion RootConn")
	}
	if connector.pool.Count() != 0 || connector.pool.ClosingCount() != 0 {
		t.Fatalf("pool not clean after bastion abort: active=%d closing=%d",
			connector.pool.Count(), connector.pool.ClosingCount())
	}

	// Point target at a healthy SSH server and verify singleflight is NOT wedged:
	// subsequent Connect(target) builds a fresh bastion and succeeds!
	provider.mu.Lock()
	provider.cfgs["target"] = &ClientConfig{
		NodeID: "target", Address: healthyHost, Port: healthyPort,
		User: "fixture", AuthType: "password", Password: sshfixture.Password,
		ProxyJump: "bastion",
	}
	provider.mu.Unlock()

	var recovered *Client
	var recoverErr error
	waitWithin(t, "subsequent Connect(target) recovery", 3*time.Second, func() {
		recovered, recoverErr = connector.Connect(ctx, "target")
	})
	if recoverErr != nil {
		t.Fatalf("subsequent Connect(target) failed: %v", recoverErr)
	}
	if err := runBarrierExecCheck(recovered); err != nil {
		t.Fatalf("recovered target client exec failed: %v", err)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after recovery: %v", err)
	}
}

type failingReloadProvider struct {
	mu           sync.Mutex
	cfgs         map[string]*ClientConfig
	targetReads  int
	failOnSecond bool
	onFailReload func()
}

func (p *failingReloadProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if nodeID == "target" {
		p.targetReads++
		if p.failOnSecond && p.targetReads == 2 {
			p.failOnSecond = false
			if p.onFailReload != nil {
				p.onFailReload()
			}
			return nil, errors.New("injected post-handshake config reload failure")
		}
	}
	cfg, ok := p.cfgs[nodeID]
	if !ok {
		return nil, errors.New("unknown node")
	}
	cloned := *cfg
	return &cloned, nil
}

func testC6H2PostHandshakeFailureWedgedBastion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	dialer := &modeSwitchDialer{}
	provider := &failingReloadProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
		failOnSecond: true,
		onFailReload: func() {
			if bc := dialer.connAt(0); bc != nil {
				bc.wedgeWrite.Store(true)
			}
		},
	}

	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	var firstErr error
	waitWithin(t, "post-handshake failure cleanup over write-wedged bastion", 500*time.Millisecond, func() {
		_, firstErr = connector.Connect(ctx, "target")
	})
	if firstErr == nil {
		t.Fatal("expected post-handshake reload error")
	}
	bc0 := dialer.connAt(0)
	if bc0 == nil || !bc0.closed.Load() {
		t.Fatal("post-handshake cleanup did not abort wedged bastion RootConn")
	}

	// Singleflight must be released and subsequent Connect(target) must succeed.
	recovered, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("subsequent Connect(target) failed: %v", err)
	}
	if err := runBarrierExecCheck(recovered); err != nil {
		t.Fatalf("recovered target client exec failed: %v", err)
	}
}

func testC6H2ControlBlackholedTargetHealthyBastion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	healthyTarget2Srv := newKeepAliveBarrierServer(t, ctx)
	deadTarget := startHookedBannerTarget(t, false, nil)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	dHost, dPort := fixtureEndpoint(t, deadTarget.addr)
	t2Host, t2Port := fixtureEndpoint(t, healthyTarget2Srv.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"dead-target": {
				NodeID: "dead-target", Address: dHost, Port: dPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
			"healthy-target": {
				NodeID: "healthy-target", Address: t2Host, Port: t2Port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
	}

	connector := newTestConnector(
		provider,
		WithHostKeyVerifier(&fixtureTrust{}),
		WithHandshakeTimeout(80*time.Millisecond),
	)
	t.Cleanup(func() { _ = connector.CloseAll() })

	bastionBefore, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	bKey := connector.pool.DigestOf(bastionBefore.pooled)

	var timeoutErr error
	waitWithin(t, "Connect(dead-target) over healthy bastion", 500*time.Millisecond, func() {
		_, timeoutErr = connector.Connect(ctx, "dead-target")
	})
	if timeoutErr == nil {
		t.Fatal("expected dead-target handshake to time out")
	}

	// Healthy bastion MUST remain alive, unclosed, and pooled!
	if isRootConnClosed(bastionBefore.rootConn) {
		t.Fatal("blackholed target closed healthy bastion RootConn")
	}
	gotBastion, ok := connector.pool.Get(bKey)
	if !ok || gotBastion != bastionBefore.pooled {
		t.Fatal("healthy bastion was evicted from pool after dead-target handshake timeout")
	}
	if err := runBarrierExecCheck(bastionBefore); err != nil {
		t.Fatalf("healthy bastion unusable after dead-target timeout: %v", err)
	}

	// Connecting healthy-target reuses the exact same bastion RootConn.
	t2Client, err := connector.Connect(ctx, "healthy-target")
	if err != nil {
		t.Fatalf("Connect(healthy-target): %v", err)
	}
	if t2Client.rootConn != bastionBefore.rootConn {
		t.Fatal("healthy-target did not reuse the live pooled bastion")
	}
	if err := runBarrierExecCheck(t2Client); err != nil {
		t.Fatalf("healthy-target exec failed: %v", err)
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants failed: %v", err)
	}
}

// TestC6_H3_BoundedEvictAndPublishStaleParent verifies C6-H3:
//  1. Connector.EvictClient(target) over write-wedged bastion completes in
//     <500ms while healthy-bastion EvictClient(target) preserves bastion.
//  2. connPool.Publish stale-parent rejection tracks next in p.closing while
//     tearing down, completes in <500ms over write-wedged bastion, and never
//     wedges singleflight.
func TestC6_H3_BoundedEvictAndPublishStaleParent(t *testing.T) {
	t.Run("evict_client_over_wedged_bastion", testC6H3EvictClientWedgedBastion)
	t.Run("evict_client_over_healthy_bastion_preserves_bastion", testC6H3EvictClientHealthyBastion)
	t.Run("publish_stale_parent_wedged_bastion_and_closing_tracking", testC6H3PublishStaleParentWedgedAndClosing)
	t.Run("connect_stale_parent_race_over_wedged_bastion_singleflight_unwedged", testC6H3ConnectStaleParentRaceOverWedgedBastion)
}

func testC6H3EvictClientWedgedBastion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
	}

	dialer := &modeSwitchDialer{}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	targetClient, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	bastionConn := dialer.connAt(0)
	bastionConn.wedgeWrite.Store(true)

	waitWithin(t, "Connector.EvictClient(target) over write-wedged bastion", 500*time.Millisecond, func() {
		if evictErr := connector.EvictClient(targetClient); evictErr != nil {
			t.Errorf("EvictClient(target): %v", evictErr)
		}
	})
	if !bastionConn.closed.Load() {
		t.Fatal("EvictClient(target) over wedged bastion did not abort dead bastion RootConn")
	}
	if connector.pool.Count() != 0 || connector.pool.ClosingCount() != 0 {
		t.Fatalf("pool not drained after wedged EvictClient: active=%d closing=%d",
			connector.pool.Count(), connector.pool.ClosingCount())
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after wedged EvictClient: %v", err)
	}
}

func testC6H3EvictClientHealthyBastion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { _ = connector.CloseAll() })

	targetClient, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	bastionClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}

	waitWithin(t, "Connector.EvictClient(target) over healthy bastion", 500*time.Millisecond, func() {
		if evictErr := connector.EvictClient(targetClient); evictErr != nil {
			t.Errorf("EvictClient(target): %v", evictErr)
		}
	})
	if isRootConnClosed(bastionClient.rootConn) {
		t.Fatal("EvictClient(target) closed healthy bastion RootConn")
	}
	if connector.pool.Count() != 1 || connector.pool.ClosingCount() != 0 {
		t.Fatalf("expected only bastion active (count=1, closing=0), got active=%d closing=%d",
			connector.pool.Count(), connector.pool.ClosingCount())
	}
	if err := runBarrierExecCheck(bastionClient); err != nil {
		t.Fatalf("healthy bastion failed after EvictClient(target): %v", err)
	}
}

type blockingTrackConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingTrackConn) Close() error {
	c.once.Do(func() { close(c.entered) })
	<-c.release
	return nil
}

func testC6H3PublishStaleParentWedgedAndClosing(t *testing.T) {
	// Part 1: Verify connPool.Publish tracks rejected stale-parent client in
	// p.closing while next.closeSelf() is running so connPool.Close() sees it.
	pool := newConnPool()
	rootConn := &physicalSSHConn{Conn: &stubCloseConn{}}
	bKey := DigestClientConfig(&ClientConfig{NodeID: "bastion"}, ZeroHopDigest)
	tKey := DigestClientConfig(&ClientConfig{NodeID: "target", ProxyJump: "bastion"}, bKey)
	staleParent := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: rootConn, hopConn: rootConn}

	blockHop := &blockingTrackConn{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	staleNext := &PooledClient{
		SSHClient: &cryptoSSH.Client{},
		RootConn:  rootConn,
		hopConn:   blockHop,
		parentKey: bKey,
	}

	pubDone := make(chan error, 1)
	go func() {
		_, err := pool.Publish(tKey, staleNext, staleParent, nil)
		pubDone <- err
	}()
	select {
	case <-blockHop.entered:
	case <-time.After(time.Second):
		t.Fatal("stale-parent Publish did not invoke next.closeSelf()")
	}
	if got := pool.ClosingCount(); got != 1 {
		close(blockHop.release)
		<-pubDone
		t.Fatalf("pool.ClosingCount() during stale-parent rejection = %d, want 1", got)
	}
	if err := pool.CheckInvariants(false); err != nil {
		close(blockHop.release)
		<-pubDone
		t.Fatalf("CheckInvariants during stale-parent rejection: %v", err)
	}
	// Close pool concurrently and verify it drains staleNext from p.closing!
	drained := pool.Close()
	foundStale := false
	for _, c := range drained {
		if c == staleNext {
			foundStale = true
		}
	}
	if !foundStale {
		close(blockHop.release)
		<-pubDone
		t.Fatal("connPool.Close() did not observe stale-parent next tracked in p.closing")
	}
	close(blockHop.release)
	if err := <-pubDone; !errors.Is(err, errStaleParentGeneration) {
		t.Fatalf("stale-parent Publish = %v, want errStaleParentGeneration", err)
	}
	if got := pool.ClosingCount(); got != 0 {
		t.Fatalf("pool.ClosingCount() after stale-parent Publish = %d, want 0", got)
	}

	// Part 2: Real 2-hop write-wedged bastion stale-parent Publish completes in <500ms!
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	provider := &mutableRouteProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
	}

	dialer := &modeSwitchDialer{}
	connector := newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	targetClient, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target): %v", err)
	}
	bastionClient, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	bKeyLive := connector.pool.DigestOf(bastionClient.pooled)
	tKeyLive := connector.pool.DigestOf(targetClient.pooled)

	// Retire bastion so expectParent is stale, then wedge bastion Write before
	// calling Publish on a real target PooledClient riding on proxyChanConn.
	connector.pool.Retire(bKeyLive, bastionClient.pooled)
	bastionConn := dialer.connAt(0)
	bastionConn.wedgeWrite.Store(true)

	var pubErr error
	waitWithin(t, "connPool.Publish stale-parent rejection over wedged bastion", 500*time.Millisecond, func() {
		_, pubErr = connector.pool.Publish(tKeyLive, targetClient.pooled, bastionClient.pooled, nil)
	})
	if !errors.Is(pubErr, errStaleParentGeneration) {
		t.Fatalf("Publish stale-parent = %v, want errStaleParentGeneration", pubErr)
	}
	if !bastionConn.closed.Load() {
		t.Fatal("stale-parent rejection over wedged bastion did not abort dead bastion RootConn")
	}
	if connector.pool.ClosingCount() != 0 {
		t.Fatalf("pool.ClosingCount() = %d after stale-parent rejection, want 0", connector.pool.ClosingCount())
	}
}

func testC6H3ConnectStaleParentRaceOverWedgedBastion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)

	dialer := &modeSwitchDialer{}
	var connector *Connector
	var retireOnce sync.Once
	var bastionPooled *PooledClient

	// Intercept the post-handshake reload for "target": retire bastion (causing
	// Publish to hit stale-parent rejection) AND wedge bastion's TCP Write right
	// before Publish runs!
	provider := &hookedReloadProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
		onTargetRead: func(count int) {
			if count == 2 {
				retireOnce.Do(func() {
					if bastionPooled != nil {
						connector.pool.Retire(connector.pool.DigestOf(bastionPooled), bastionPooled)
					}
					if bc := dialer.connAt(0); bc != nil {
						bc.wedgeWrite.Store(true)
					}
				})
			}
		},
	}

	connector = newTestConnector(provider, WithDialer(dialer), WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() {
		dialer.closeAll()
		_ = connector.CloseAll()
	})

	bCli, err := connector.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("Connect(bastion): %v", err)
	}
	bastionPooled = bCli.pooled

	// Connect(target) hits stale-parent Publish over wedged bastion, escalates
	// cleanly in <500ms, releases singleflight, and transparently rebuilds on a
	// fresh bastion (or succeeds on next Connect)!
	var targetCli *Client
	var connectErr error
	waitWithin(t, "Connect(target) racing stale-parent over wedged bastion", 500*time.Millisecond, func() {
		targetCli, connectErr = connector.Connect(ctx, "target")
	})
	if connectErr != nil {
		// If the attempt returned an error, verify subsequent Connect succeeds
		// immediately (proving singleflight was NOT wedged).
		waitWithin(t, "subsequent Connect(target) after stale-parent wedged race", 2*time.Second, func() {
			targetCli, connectErr = connector.Connect(ctx, "target")
		})
	}
	if connectErr != nil {
		t.Fatalf("Connect(target) recovery failed: %v", connectErr)
	}
	if err := runBarrierExecCheck(targetCli); err != nil {
		t.Fatalf("recovered target exec failed: %v", err)
	}
	if connector.pool.ClosingCount() != 0 {
		t.Fatalf("pool.ClosingCount() = %d, want 0", connector.pool.ClosingCount())
	}
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants failed: %v", err)
	}
}

type hookedReloadProvider struct {
	mu           sync.Mutex
	cfgs         map[string]*ClientConfig
	targetReads  int
	onTargetRead func(count int)
}

func (p *hookedReloadProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	p.mu.Lock()
	cfg, ok := p.cfgs[nodeID]
	var count int
	if nodeID == "target" {
		p.targetReads++
		count = p.targetReads
	}
	cb := p.onTargetRead
	p.mu.Unlock()
	if !ok {
		return nil, errors.New("unknown node")
	}
	if nodeID == "target" && cb != nil {
		cb(count)
	}
	cloned := *cfg
	return &cloned, nil
}

// TestC6_L1_ReindexCascadesToMuxProxyJumpChildren verifies C6-L1:
// When a jump child attaches via MUX_C_PROXY (ControlSocketPath != "" and
// parentKey != ZeroHopDigest), reindexing an upstream hop (bKey1 -> bKey2)
// atomically cascade-reindexes the MUX_C_PROXY child to
// DigestClientConfig(targetCfg, bKey2) so the next Connect(target) hits cache
// with 0 duplicate MUX_C_PROXY dials and CheckInvariants() passes.
func TestC6_L1_ReindexCascadesToMuxProxyJumpChildren(t *testing.T) {
	t.Run("two_hop_end_to_end_mux_proxy_cascade", testC6L1TwoHopMuxProxyCascade)
	t.Run("three_hop_cascade_and_collision_rollback", testC6L1ThreeHopAndCollisionRollback)
}

func testC6L1TwoHopMuxProxyCascade(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)
	targetSrv := newKeepAliveBarrierServer(t, ctx)
	bHost, bPort := fixtureEndpoint(t, bastionSrv.addr)
	tHost, tPort := fixtureEndpoint(t, targetSrv.addr)
	socketPath := filepath.Join(shortSocketDir(t), "c6l1-chain.sock")

	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bHost, Port: bPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				AuthUpdateToken: "b-tok-v1",
			},
			"target": {
				NodeID: "target", Address: tHost, Port: tPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
		ctrls: map[string]*ControlConfig{
			"target": {Master: ControlMasterAuto, Path: socketPath, Persist: "yes"},
		},
	}

	// First connector establishes bastion -> target and starts target's ControlMaster.
	first := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { _ = first.CloseAll() })
	if _, err := first.Connect(ctx, "target"); err != nil {
		t.Fatalf("first.Connect(target): %v", err)
	}
	var targetMaster *MuxServer
	waitForCondition(t, 5*time.Second, func() bool {
		targetMaster = GetActiveMuxServer(socketPath)
		return targetMaster != nil
	}, "target ControlMaster did not start")

	// Second connector caches BOTH bastion (at bKey1) and target attached via
	// MUX_C_PROXY (ControlSocketPath != "", parentKey == bKey1).
	second := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	t.Cleanup(func() { _ = second.CloseAll() })

	bastionClient, err := second.Connect(ctx, "bastion")
	if err != nil {
		t.Fatalf("second.Connect(bastion): %v", err)
	}
	bKey1 := second.pool.DigestOf(bastionClient.pooled)

	attachedTarget, err := second.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("second.Connect(target) via MUX_C_PROXY: %v", err)
	}
	if !attachedTarget.IsMultiplexed() || attachedTarget.pooled.ControlSocketPath == "" {
		t.Fatal("expected second.Connect(target) to attach via MUX_C_PROXY")
	}
	if attachedTarget.pooled.parentKey != bKey1 {
		t.Fatalf("attached target parentKey = %s, want %s", attachedTarget.pooled.parentKey, bKey1)
	}
	tKey1 := second.pool.DigestOf(attachedTarget.pooled)
	sessionsBefore := targetMaster.ActiveSessions()

	// Reindex bastion (bKey1 -> bKey2) via SetExecution + ApplyRecordedAuth!
	newExec := &ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX}
	bastionClient.SetExecution(newExec)
	bastionClient.ApplyRecordedAuth("b-tok-v2", "", nil)

	bKey2 := second.pool.DigestOf(bastionClient.pooled)
	if bKey2 == bKey1 || bKey2.IsZero() {
		t.Fatalf("bastion did not reindex: bKey1=%s bKey2=%s", bKey1, bKey2)
	}

	// Update provider's bastion config to reflect committed metadata.
	provider.cfgs["bastion"].Execution = newExec.Clone()
	provider.cfgs["bastion"].AuthUpdateToken = "b-tok-v2"

	planAfter, err := second.resolveConnectionPlan(ctx, "target")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(target) after bastion reindex: %v", err)
	}
	wantTKey2 := planAfter[0].hopDigest()
	if planAfter[1].hopDigest() != bKey2 {
		t.Fatalf("plan bastion digest = %s, want %s", planAfter[1].hopDigest(), bKey2)
	}

	// Verify target MUX_C_PROXY entry cascade-reindexed atomically from tKey1 -> wantTKey2!
	if _, stale := second.pool.Get(tKey1); stale {
		t.Fatal("C6-L1 reproduced: stale MUX_C_PROXY target key remained active after bastion reindex")
	}
	gotTarget, ok := second.pool.Get(wantTKey2)
	if !ok || gotTarget != attachedTarget.pooled {
		t.Fatalf("C6-L1 reproduced: MUX_C_PROXY target missed reindexed key %s (actual=%s)",
			wantTKey2, second.pool.DigestOf(attachedTarget.pooled))
	}
	if attachedTarget.pooled.parentKey != bKey2 {
		t.Fatalf("MUX_C_PROXY target parentKey = %s, want %s", attachedTarget.pooled.parentKey, bKey2)
	}
	if err := second.pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after bastion -> MUX_C_PROXY cascade reindex: %v", err)
	}

	// Next Connect(target) MUST hit cache with 0 duplicate MUX_C_PROXY dials!
	reused, err := second.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("second.Connect(target) after reindex: %v", err)
	}
	if reused.pooled != attachedTarget.pooled {
		t.Fatal("C6-L1 reproduced: Connect(target) did not reuse cascade-reindexed MUX_C_PROXY client")
	}
	if gotSessions := targetMaster.ActiveSessions(); gotSessions != sessionsBefore {
		t.Fatalf("C6-L1 reproduced: targetMaster.ActiveSessions() = %d, want %d (duplicate MUX_C_PROXY dial occurred)",
			gotSessions, sessionsBefore)
	}
	if err := runBarrierExecCheck(reused); err != nil {
		t.Fatalf("reused MUX_C_PROXY target exec failed: %v", err)
	}
}

func testC6L1ThreeHopAndCollisionRollback(t *testing.T) {
	t.Parallel()

	pool := newConnPool()
	rootConn := &physicalSSHConn{Conn: &stubCloseConn{}}
	muxRoot := &physicalSSHConn{Conn: &stubCloseConn{}}
	directMuxRoot := &physicalSSHConn{Conn: &stubCloseConn{}}

	bCfg := NewClientConfig(ClientConfig{NodeID: "bastion", AuthUpdateToken: "v1"})
	mCfg := NewClientConfig(ClientConfig{NodeID: "mid", ProxyJump: "bastion"})
	tCfg := NewClientConfig(ClientConfig{NodeID: "target", ProxyJump: "mid"})
	directMuxCfg := NewClientConfig(ClientConfig{NodeID: "direct-mux"})

	bKey1 := DigestClientConfig(bCfg, ZeroHopDigest)
	mKey1 := DigestClientConfig(mCfg, bKey1)
	tKey1 := DigestClientConfig(tCfg, mKey1)
	directMuxKey := DigestClientConfig(directMuxCfg, ZeroHopDigest)

	bastion := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: rootConn, hopConn: rootConn, publishedCfg: bCfg}
	mid := &PooledClient{SSHClient: &cryptoSSH.Client{}, RootConn: rootConn, hopConn: &stubCloseConn{}, parentKey: bKey1, publishedCfg: mCfg}
	targetMux := &PooledClient{
		SSHClient:         &cryptoSSH.Client{},
		RootConn:          muxRoot,
		hopConn:           muxRoot,
		parentKey:         mKey1,
		publishedCfg:      tCfg,
		ControlSocketPath: "/tmp/c6l1-target.sock",
	}
	directMux := &PooledClient{
		SSHClient:         &cryptoSSH.Client{},
		RootConn:          directMuxRoot,
		hopConn:           directMuxRoot,
		publishedCfg:      directMuxCfg,
		ControlSocketPath: "/tmp/c6l1-direct.sock",
	}

	if _, err := pool.Publish(bKey1, bastion, nil, nil); err != nil {
		t.Fatalf("Publish(bastion): %v", err)
	}
	if _, err := pool.Publish(mKey1, mid, bastion, nil); err != nil {
		t.Fatalf("Publish(mid): %v", err)
	}
	if _, err := pool.Publish(tKey1, targetMux, nil, nil); err != nil {
		t.Fatalf("Publish(targetMux): %v", err)
	}
	if _, err := pool.Publish(directMuxKey, directMux, nil, nil); err != nil {
		t.Fatalf("Publish(directMux): %v", err)
	}

	// 1. Reindex bastion v1 -> v2 cascades through in-memory mid AND MUX_C_PROXY target,
	// while leaving unrelated directMux (parentKey == ZeroHopDigest) untouched.
	if ok := pool.Reindex(bastion, func(cfg *ClientConfig) { cfg.AuthUpdateToken = "v2" }); !ok {
		t.Fatal("Reindex(bastion v1->v2) returned false")
	}
	bCfg2 := NewClientConfig(*bCfg)
	bCfg2.AuthUpdateToken = "v2"
	bKey2 := DigestClientConfig(bCfg2, ZeroHopDigest)
	mKey2 := DigestClientConfig(mCfg, bKey2)
	tKey2 := DigestClientConfig(tCfg, mKey2)

	assertPoolHasExactEntry(t, pool, "bastion v2", bKey2, bastion)
	assertPoolHasExactEntry(t, pool, "mid v2", mKey2, mid)
	assertPoolHasExactEntry(t, pool, "targetMux v2", tKey2, targetMux)
	assertPoolHasExactEntry(t, pool, "directMux untouched", directMuxKey, directMux)
	if targetMux.parentKey != mKey2 {
		t.Fatalf("targetMux.parentKey = %s, want %s", targetMux.parentKey, mKey2)
	}
	if err := pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after 3-hop mux cascade: %v", err)
	}

	// 2. Collision rollback: install an unrelated occupant at tKey3 (v3) and
	// verify Reindex(bastion v2->v3) rolls back cleanly without mutating any hop.
	bCfg3 := NewClientConfig(*bCfg)
	bCfg3.AuthUpdateToken = "v3"
	bKey3 := DigestClientConfig(bCfg3, ZeroHopDigest)
	mKey3 := DigestClientConfig(mCfg, bKey3)
	tKey3 := DigestClientConfig(tCfg, mKey3)
	occupant := &PooledClient{
		SSHClient:         &cryptoSSH.Client{},
		RootConn:          &physicalSSHConn{Conn: &stubCloseConn{}},
		ControlSocketPath: "/tmp/c6l1-occupant.sock",
	}
	if _, err := pool.Publish(tKey3, occupant, nil, nil); err != nil {
		t.Fatalf("Publish(occupant): %v", err)
	}
	if ok := pool.Reindex(bastion, func(cfg *ClientConfig) { cfg.AuthUpdateToken = "v3" }); ok {
		t.Fatal("Reindex unexpectedly succeeded despite MUX_C_PROXY target key collision")
	}
	assertPoolHasExactEntry(t, pool, "bastion rolled back", bKey2, bastion)
	assertPoolHasExactEntry(t, pool, "mid rolled back", mKey2, mid)
	assertPoolHasExactEntry(t, pool, "targetMux rolled back", tKey2, targetMux)
	if bastion.publishedCfg.AuthUpdateToken != "v2" {
		t.Fatalf("rolled-back bastion AuthUpdateToken = %q, want %q", bastion.publishedCfg.AuthUpdateToken, "v2")
	}
	if err := pool.CheckInvariants(false); err != nil {
		t.Fatalf("CheckInvariants after collision rollback: %v", err)
	}
}
