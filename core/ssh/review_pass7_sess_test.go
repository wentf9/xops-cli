package ssh

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

type pass7DeadlineSpyConn struct {
	net.Conn
	mu                  sync.Mutex
	sawNonZeroDeadline  bool
	activeReadDeadline  time.Time
	activeWriteDeadline time.Time
}

func (c *pass7DeadlineSpyConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	if !t.IsZero() {
		c.sawNonZeroDeadline = true
	}
	c.activeReadDeadline = t
	c.activeWriteDeadline = t
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func (c *pass7DeadlineSpyConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	if !t.IsZero() {
		c.sawNonZeroDeadline = true
	}
	c.activeReadDeadline = t
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *pass7DeadlineSpyConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	if !t.IsZero() {
		c.sawNonZeroDeadline = true
	}
	c.activeWriteDeadline = t
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

func (c *pass7DeadlineSpyConn) snapshot() (sawNonZero bool, readDL, writeDL time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sawNonZeroDeadline, c.activeReadDeadline, c.activeWriteDeadline
}

type pass7NoDeadlineStallReplyConn struct {
	readBuf    *bytes.Reader
	writeCalls atomic.Int32
	stallOnce  sync.Once
	stalledCh  chan struct{}
	closeOnce  sync.Once
	closedCh   chan struct{}
}

func newPass7NoDeadlineStallReplyConn(clientBytes []byte) *pass7NoDeadlineStallReplyConn {
	return &pass7NoDeadlineStallReplyConn{
		readBuf:   bytes.NewReader(clientBytes),
		stalledCh: make(chan struct{}),
		closedCh:  make(chan struct{}),
	}
}

func (c *pass7NoDeadlineStallReplyConn) Read(p []byte) (int, error) {
	select {
	case <-c.closedCh:
		return 0, net.ErrClosed
	default:
	}
	return c.readBuf.Read(p)
}

func (c *pass7NoDeadlineStallReplyConn) Write(p []byte) (int, error) {
	call := c.writeCalls.Add(1)
	if call == 1 {
		// Allow SOCKS5 method selection reply (0x05, 0x00) to succeed, then stall on grant reply.
		return len(p), nil
	}
	c.stallOnce.Do(func() { close(c.stalledCh) })
	<-c.closedCh
	return 0, net.ErrClosed
}

func (c *pass7NoDeadlineStallReplyConn) Close() error {
	c.closeOnce.Do(func() { close(c.closedCh) })
	return nil
}

func (c *pass7NoDeadlineStallReplyConn) LocalAddr() net.Addr  { return dummyAddr("local") }
func (c *pass7NoDeadlineStallReplyConn) RemoteAddr() net.Addr { return dummyAddr("remote") }
func (c *pass7NoDeadlineStallReplyConn) SetDeadline(time.Time) error {
	return errors.New("deadlines not supported on ssh channel")
}
func (c *pass7NoDeadlineStallReplyConn) SetReadDeadline(time.Time) error {
	return errors.New("deadlines not supported on ssh channel")
}
func (c *pass7NoDeadlineStallReplyConn) SetWriteDeadline(time.Time) error {
	return errors.New("deadlines not supported on ssh channel")
}

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

// TestPass7_H6_SocksHandshakeDeadlineAndAddressValidation verifies H6:
//   - serveSocksConn keeps the handshake deadline active through writeSocksReply
//     and clears both read and write deadlines on conn before entering pipeFn;
//   - reverse-SOCKS connections without SetDeadline support enforce the handshake
//     timeout when the final SOCKS reply write stalls;
//   - readSocks5Address and handleSocks4Handshake reject empty domains, NUL bytes
//     in domains, and port 0 without dialing upstream.
func TestPass7_H6_SocksHandshakeDeadlineAndAddressValidation(t *testing.T) {
	setTestHome(t)
	t.Run("clears_conn_deadlines_after_socks5_and_socks4_grant", assertPass7SocksClearsDeadlinesBeforePipe)
	t.Run("reverse_socks_stalled_reply_honors_handshake_timeout", assertPass7ReverseSocksStalledReplyTimesOut)
	t.Run("rejects_empty_domain_nul_domain_and_port_zero", assertPass7SocksAddressValidation)
}

func assertPass7SocksClearsDeadlinesBeforePipe(t *testing.T) {
	cases := []struct {
		name       string
		handshake  func(t *testing.T, client net.Conn)
		wantTarget string
	}{
		{
			name:       "socks5_connect",
			handshake:  performPass7Socks5ClientHandshake,
			wantTarget: "example.com:8080",
		},
		{
			name:       "socks4a_connect",
			handshake:  performPass7Socks4aClientHandshake,
			wantTarget: "example.com:8080",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen tcp: %v", err)
			}
			defer func() { _ = ln.Close() }()

			clientDone := make(chan error, 1)
			go func() {
				cli, dialErr := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
				if dialErr != nil {
					clientDone <- dialErr
					return
				}
				defer func() { _ = cli.Close() }()
				tc.handshake(t, cli)
				if _, wErr := cli.Write([]byte("ping")); wErr != nil {
					clientDone <- wErr
					return
				}
				var pong [4]byte
				if _, rErr := io.ReadFull(cli, pong[:]); rErr != nil {
					clientDone <- rErr
					return
				}
				if string(pong[:]) != "pong" {
					clientDone <- fmt.Errorf("got %q, want pong", string(pong[:]))
					return
				}
				clientDone <- nil
			}()

			srvRaw, err := ln.Accept()
			if err != nil {
				t.Fatalf("accept tcp: %v", err)
			}
			spy := &pass7DeadlineSpyConn{Conn: srvRaw}
			remoteA, remoteB := net.Pipe()
			defer func() { _ = remoteB.Close() }()

			go func() {
				defer func() { _ = remoteB.Close() }()
				var in [4]byte
				if _, rErr := io.ReadFull(remoteB, in[:]); rErr == nil && string(in[:]) == "ping" {
					_, _ = remoteB.Write([]byte("pong"))
				}
			}()

			var dialedTarget string
			var pipeSawZeroDeadlines bool
			var pipeSawNonZeroHandshake bool
			err = serveSocksConn(t.Context(), spy, func(_ context.Context, destAddr string) (net.Conn, error) {
				dialedTarget = destAddr
				return remoteA, nil
			}, func(_ context.Context, c1, c2 net.Conn) error {
				sawNonZero, readDL, writeDL := spy.snapshot()
				pipeSawNonZeroHandshake = sawNonZero
				pipeSawZeroDeadlines = readDL.IsZero() && writeDL.IsZero()
				pipeBidirectional(c1, c2)
				return nil
			})
			if err != nil {
				t.Fatalf("serveSocksConn: %v", err)
			}
			if err := <-clientDone; err != nil {
				t.Fatalf("client flow: %v", err)
			}
			if dialedTarget != tc.wantTarget {
				t.Fatalf("dialedTarget = %q, want %q", dialedTarget, tc.wantTarget)
			}
			if !pipeSawNonZeroHandshake || !pipeSawZeroDeadlines {
				t.Fatalf("deadline state in pipeFn: sawHandshakeDeadline=%v zeroDeadlines=%v, want (true, true)",
					pipeSawNonZeroHandshake, pipeSawZeroDeadlines)
			}
		})
	}
}

func performPass7Socks5ClientHandshake(t *testing.T, client net.Conn) {
	t.Helper()
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write socks5 greeting: %v", err)
	}
	var greetResp [2]byte
	if _, err := io.ReadFull(client, greetResp[:]); err != nil || greetResp != [2]byte{0x05, 0x00} {
		t.Fatalf("read socks5 greeting reply: resp=%v err=%v", greetResp, err)
	}
	host := "example.com"
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, []byte(host)...)
	req = append(req, 0x1F, 0x90) // 8080
	if _, err := client.Write(req); err != nil {
		t.Fatalf("write socks5 connect: %v", err)
	}
	var reply [10]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply[1] != 0x00 {
		t.Fatalf("read socks5 grant reply: reply=%v err=%v", reply, err)
	}
}

func performPass7Socks4aClientHandshake(t *testing.T, client net.Conn) {
	t.Helper()
	req := []byte{0x04, 0x01, 0x1F, 0x90, 0x00, 0x00, 0x00, 0x01, 'u', 0x00}
	req = append(req, []byte("example.com\x00")...)
	if _, err := client.Write(req); err != nil {
		t.Fatalf("write socks4a connect: %v", err)
	}
	var reply [8]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply[1] != 0x5A {
		t.Fatalf("read socks4a grant reply: reply=%v err=%v", reply, err)
	}
}

func assertPass7ReverseSocksStalledReplyTimesOut(t *testing.T) {
	reqBytes := []byte{
		0x05, 0x01, 0x00, // greeting
		0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50, // CONNECT 127.0.0.1:80
	}
	stalledConn := newPass7NoDeadlineStallReplyConn(reqBytes)
	remoteA, remoteB := net.Pipe()
	defer func() {
		_ = remoteA.Close()
		_ = remoteB.Close()
	}()

	var pipeCalled atomic.Bool
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveSocksConnWithTimeout(
			t.Context(),
			stalledConn,
			60*time.Millisecond,
			func(_ context.Context, _ string) (net.Conn, error) {
				return remoteA, nil
			},
			func(_ context.Context, _, _ net.Conn) error {
				pipeCalled.Store(true)
				return nil
			},
		)
	}()

	select {
	case <-stalledConn.stalledCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for writeSocksReply to enter stalled grant write")
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error from stalled reverse-SOCKS reply write, got nil")
		}
		if !strings.Contains(err.Error(), "socks handshake timed out") && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("unexpected stalled reply error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveSocksConnWithTimeout did not abort stalled reverse-SOCKS reply write")
	}

	if pipeCalled.Load() {
		t.Fatal("pipeFn must never be invoked when writeSocksReply times out")
	}
}

func assertPass7SocksAddressValidation(t *testing.T) {
	// Direct unit checks on readSocks5Address for domain empty, NUL domain, and port 0.
	directCases := []struct {
		name    string
		atyp    byte
		payload []byte
		wantMsg string
	}{
		{
			name:    "domain_empty_len_zero",
			atyp:    0x03,
			payload: []byte{0x00, 0x00, 0x50},
			wantMsg: "empty SOCKS5 domain",
		},
		{
			name:    "domain_contains_nul",
			atyp:    0x03,
			payload: []byte{0x08, 'b', 'a', 'd', 0x00, 'h', 'o', 's', 't', 0x00, 0x50},
			wantMsg: "NUL",
		},
		{
			name:    "domain_port_zero",
			atyp:    0x03,
			payload: []byte{0x04, 't', 'e', 's', 't', 0x00, 0x00},
			wantMsg: "port 0",
		},
		{
			name:    "ipv4_port_zero",
			atyp:    0x01,
			payload: []byte{127, 0, 0, 1, 0x00, 0x00},
			wantMsg: "port 0",
		},
		{
			name:    "ipv6_port_zero",
			atyp:    0x04,
			payload: append(make([]byte, 16), 0x00, 0x00),
			wantMsg: "port 0",
		},
	}

	for _, tc := range directCases {
		t.Run("direct_"+tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer func() {
				_ = c1.Close()
				_ = c2.Close()
			}()
			go func() {
				_, _ = c1.Write(tc.payload)
				_ = c1.Close()
			}()
			got, err := readSocks5Address(c2, tc.atyp)
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("readSocks5Address(%s) = (%q, %v), want error containing %q", tc.name, got, err, tc.wantMsg)
			}
		})
	}

	// End-to-end serveSocksConn checks verifying dialFn is never called for invalid SOCKS5/SOCKS4/SOCKS4a targets.
	wireCases := []struct {
		name  string
		bytes []byte
	}{
		{
			name:  "socks5_empty_domain",
			bytes: []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x00, 0x00, 0x50},
		},
		{
			name:  "socks5_nul_domain",
			bytes: []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 0x05, 'a', 0x00, 'b', '.', 'c', 0x00, 0x50},
		},
		{
			name:  "socks5_port_zero",
			bytes: []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00},
		},
		{
			name:  "socks4_port_zero",
			bytes: []byte{0x04, 0x01, 0x00, 0x00, 127, 0, 0, 1, 0x00},
		},
		{
			name:  "socks4a_empty_domain",
			bytes: []byte{0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, 0x00, 0x00},
		},
		{
			name:  "socks4a_port_zero",
			bytes: append([]byte{0x04, 0x01, 0x00, 0x00, 0, 0, 0, 1, 0x00}, []byte("example.com\x00")...),
		},
	}

	for _, tc := range wireCases {
		t.Run("wire_"+tc.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer func() {
				_ = c1.Close()
				_ = c2.Close()
			}()
			readDone := make(chan []byte, 1)
			go func() {
				out, _ := io.ReadAll(c1)
				readDone <- out
			}()
			go func() {
				_, _ = c1.Write(tc.bytes)
			}()
			var dialCalled atomic.Bool
			err := serveSocksConn(t.Context(), c2, func(_ context.Context, _ string) (net.Conn, error) {
				dialCalled.Store(true)
				return nil, errors.New("unexpected dial")
			}, func(_ context.Context, _, _ net.Conn) error {
				return nil
			})
			if err == nil {
				t.Fatalf("%s: expected serveSocksConn error, got nil", tc.name)
			}
			if strings.Contains(err.Error(), "i/o timeout") {
				t.Fatalf("%s: unexpected timeout instead of address validation error: %v", tc.name, err)
			}
			if dialCalled.Load() {
				t.Fatalf("%s: dialFn must not be called for invalid destination", tc.name)
			}
			<-readDone
		})
	}
}

type pass7CloseBarrierRig struct {
	*pass6LiveRemoteForwardRig
	blockCancelAt     int32
	shadowCancelEnter chan struct{}
	shadowCancelOnce  sync.Once
	releaseShadow     chan struct{}
	tcpipFwdCount     atomic.Int32
}

func startPass7CloseBarrierRig(t *testing.T, blockCancelAt int32) *pass7CloseBarrierRig {
	t.Helper()
	listener, sshServerCfg := startKeepAliveTestSSHServer(t)
	base := &pass6LiveRemoteForwardRig{
		staticEntered: make(chan struct{}),
		releaseStatic: make(chan struct{}),
		acceptStatic:  true,
	}
	rig := &pass7CloseBarrierRig{
		pass6LiveRemoteForwardRig: base,
		blockCancelAt:             blockCancelAt,
		shadowCancelEnter:         make(chan struct{}),
		releaseShadow:             make(chan struct{}),
	}

	srvReady := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		sConn, chans, reqs, err := cryptoSSH.NewServerConn(conn, sshServerCfg)
		if err != nil {
			return
		}
		base.serverConn = sConn
		close(srvReady)
		wg.Go(func() { rig.handleServerGlobalRequests(reqs) })
		for newCh := range chans {
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unexpected client channel")
		}
	})

	rawConn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial test SSH server: %v", err)
	}
	cConn, chans, reqs, err := cryptoSSH.NewClientConn(rawConn, listener.Addr().String(), &cryptoSSH.ClientConfig{
		User:            "alice",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password("test")},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		_ = rawConn.Close()
		t.Fatalf("NewClientConn: %v", err)
	}
	<-srvReady

	rawCli := cryptoSSH.NewClient(cConn, chans, reqs)
	ctx, cancel := context.WithCancel(context.Background())
	srv := &MuxServer{
		serverCtx:         ctx,
		serverCancel:      cancel,
		sshClient:         rawCli,
		rootConn:          rawConn,
		dialNetwork:       "tcp4",
		persistEnabled:    true,
		persistIndefinite: true,
		idleNotify:        make(chan struct{}),
		shutdownChan:      make(chan struct{}),
	}
	base.muxServer = srv

	t.Cleanup(func() {
		select {
		case <-rig.releaseShadow:
		default:
			close(rig.releaseShadow)
		}
		_ = srv.Shutdown()
		if base.serverConn != nil {
			_ = base.serverConn.Close()
		}
		_ = listener.Close()
		wg.Wait()
	})
	return rig
}

func (r *pass7CloseBarrierRig) handleServerGlobalRequests(reqs <-chan *cryptoSSH.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			r.tcpipFwdCount.Add(1)
			r.replyTcpipForward(req)
		case "cancel-tcpip-forward":
			n := r.cancelTcpipCalls.Add(1)
			if r.blockCancelAt > 0 && n == r.blockCancelAt {
				r.shadowCancelOnce.Do(func() { close(r.shadowCancelEnter) })
				<-r.releaseShadow
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

type pass7BlockingReplyConn struct {
	net.Conn
	enterOnce sync.Once
	enteredCh chan struct{}
	releaseCh chan struct{}
}

func (c *pass7BlockingReplyConn) Write(p []byte) (int, error) {
	c.enterOnce.Do(func() { close(c.enteredCh) })
	<-c.releaseCh
	return c.Conn.Write(p)
}

// TestPass7_H7_CloseForwardBarrierAndDrainAccounting verifies H7:
//   - handleCloseFwd keeps the endpoint closing barrier active across primary
//     closer AND retained shadowClosers so a concurrent re-open cannot race with
//     delayed cancel-tcpip-forward teardown;
//   - WaitForDrain and PrepareHandoff wait until BOTH closeMuxForwardEntryWithShadows
//     AND MUX_S_OK reply write finish.
func TestPass7_H7_CloseForwardBarrierAndDrainAccounting(t *testing.T) {
	setTestHome(t)
	t.Run("closing_barrier_blocks_reopen_until_shadow_closers_finish", assertPass7ClosingBarrierBlocksReopenUntilShadowsFinish)
	t.Run("wait_for_drain_and_prepare_handoff_wait_until_mux_s_ok_written", assertPass7CloseFwdHoldsDrainUntilReplyWritten)
}

func assertPass7ClosingBarrierBlocksReopenUntilShadowsFinish(t *testing.T) {
	const portP = uint32(45710)
	rig := startPass7CloseBarrierRig(t, 2)
	portA := startPass6TaggedLocalBackend(t, "backendA")
	portB := startPass6TaggedLocalBackend(t, "backendB")

	mustPass4OpenFwdOK(t, rig.muxServer, MuxFwdRequest{
		RequestID:   1,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  portP,
		ConnectHost: "127.0.0.1",
		ConnectPort: portA,
	})

	// Trigger a dynamic port collision on portP so a shadowCloser is retained on portP's entry.
	rig.pushDynamicPorts(portP)
	pt, _ := runPass4MuxFwdCall(t, func(c net.Conn) error {
		return rig.muxServer.handleOpenFwd(c, MuxFwdRequest{
			RequestID:   2,
			FwdType:     MUX_FWD_REMOTE,
			ListenHost:  "127.0.0.1",
			ListenPort:  0,
			ConnectHost: "127.0.0.1",
			ConnectPort: portB,
		})
	})
	if pt != MUX_S_FAILURE {
		t.Fatalf("colliding dynamic open = 0x%x, want MUX_S_FAILURE", pt)
	}

	// Start closing portP; cancel #1 succeeds, cancel #2 (shadowCloser) blocks on shadowCancelEnter.
	closeDone := make(chan uint32, 1)
	go func() {
		cPt, _ := runPass4MuxFwdCall(t, func(c net.Conn) error {
			return rig.muxServer.handleCloseFwd(c, MuxFwdRequest{
				RequestID:   3,
				FwdType:     MUX_FWD_REMOTE,
				ListenHost:  "127.0.0.1",
				ListenPort:  portP,
				ConnectHost: "127.0.0.1",
				ConnectPort: portA,
			})
		})
		closeDone <- cPt
	}()

	select {
	case <-rig.shadowCancelEnter:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for shadowCloser cancel-tcpip-forward #2")
	}

	if rig.muxServer.PrepareHandoff() {
		rig.muxServer.CancelHandoff()
		t.Fatal("PrepareHandoff succeeded while handleCloseFwd shadow teardown was still in flight")
	}

	beforeOpenFwdCount := rig.tcpipFwdCount.Load()
	reopenDone := make(chan uint32, 1)
	go func() {
		oPt, _ := runPass4MuxFwdCall(t, func(c net.Conn) error {
			return rig.muxServer.handleOpenFwd(c, MuxFwdRequest{
				RequestID:   4,
				FwdType:     MUX_FWD_REMOTE,
				ListenHost:  "127.0.0.1",
				ListenPort:  portP,
				ConnectHost: "127.0.0.1",
				ConnectPort: portB,
			})
		})
		reopenDone <- oPt
	}()

	// Give the concurrent re-open goroutine time to reach acquireForwardEndpoint and park on closing barrier.
	time.Sleep(40 * time.Millisecond)
	if got := rig.tcpipFwdCount.Load(); got != beforeOpenFwdCount {
		t.Fatalf("re-open sent tcpip-forward (%d -> %d) before shadowCloser teardown finished", beforeOpenFwdCount, got)
	}

	close(rig.releaseShadow)

	if gotClose := <-closeDone; gotClose != MUX_S_OK {
		t.Fatalf("handleCloseFwd packet = 0x%x, want MUX_S_OK", gotClose)
	}
	if gotReopen := <-reopenDone; gotReopen != MUX_S_OK {
		t.Fatalf("concurrent re-open packet = 0x%x, want MUX_S_OK", gotReopen)
	}

	if got := rig.probeForwardedTCP(t, "127.0.0.1", portP, "after-reopen"); got != "backendB:after-reopen" {
		t.Fatalf("forwarded payload after reopen = %q, want %q", got, "backendB:after-reopen")
	}
}

func assertPass7CloseFwdHoldsDrainUntilReplyWritten(t *testing.T) {
	mockConn := &pass4MuxForwardSSHConn{nextRemotePort: 45800}
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp4")
	defer cleanup()

	mustPass4OpenFwdOK(t, srv, MuxFwdRequest{
		RequestID:   10,
		FwdType:     MUX_FWD_LOCAL,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: "127.0.0.1",
		ConnectPort: 8080,
	})
	ports := collectPass4AllocatedPorts(t, srv)
	if len(ports) != 1 {
		t.Fatalf("allocated local ports = %v, want 1 port", ports)
	}

	srvSide, cliSide := net.Pipe()
	defer func() {
		_ = srvSide.Close()
		_ = cliSide.Close()
	}()
	blockingConn := &pass7BlockingReplyConn{
		Conn:      srvSide,
		enteredCh: make(chan struct{}),
		releaseCh: make(chan struct{}),
	}

	closeErrCh := make(chan error, 1)
	go func() {
		closeErrCh <- srv.handleCloseFwd(blockingConn, MuxFwdRequest{
			RequestID:   11,
			FwdType:     MUX_FWD_LOCAL,
			ListenHost:  "127.0.0.1",
			ListenPort:  ports[0],
			ConnectHost: "127.0.0.1",
			ConnectPort: 8080,
		})
	}()

	pktCh := make(chan uint32, 1)
	go func() {
		pt, _, err := ReadMuxPacket(cliSide)
		if err != nil {
			pktCh <- 0
			return
		}
		pktCh <- pt
	}()

	select {
	case <-blockingConn.enteredCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for handleCloseFwd to reach sendOk write")
	}

	if srv.PrepareHandoff() {
		srv.CancelHandoff()
		t.Fatal("PrepareHandoff succeeded before handleCloseFwd finished writing MUX_S_OK")
	}

	shortCtx, shortCancel := context.WithTimeout(t.Context(), 35*time.Millisecond)
	defer shortCancel()
	if err := srv.WaitForDrain(shortCtx, 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitForDrain while MUX_S_OK blocked = %v, want context.DeadlineExceeded", err)
	}

	drainDone := make(chan error, 1)
	go func() {
		drainCtx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		drainDone <- srv.WaitForDrain(drainCtx, 0)
	}()

	close(blockingConn.releaseCh)

	if err := <-closeErrCh; err != nil {
		t.Fatalf("handleCloseFwd: %v", err)
	}
	if pt := <-pktCh; pt != MUX_S_OK {
		t.Fatalf("reply packet = 0x%x, want MUX_S_OK", pt)
	}
	if err := <-drainDone; err != nil {
		t.Fatalf("WaitForDrain after MUX_S_OK: %v", err)
	}
	if !srv.PrepareHandoff() {
		t.Fatal("PrepareHandoff failed after handleCloseFwd fully completed")
	}
	srv.CancelHandoff()
}

// TestPass7_H8_MuxServerShutsDownWhenSSHTransportDrops verifies that when the
// underlying SSH transport exits asynchronously (e.g. remote server closes the
// TCP connection), MuxServer promptly shuts down and unlinks its Unix control
// socket so no zombie MUX_S_ALIVE control socket survives.
func TestPass7_H8_MuxServerShutsDownWhenSSHTransportDrops(t *testing.T) {
	setTestHome(t)
	listener, sshServerCfg := startKeepAliveTestSSHServer(t)

	serverConnCh := make(chan *cryptoSSH.ServerConn, 1)
	var wg sync.WaitGroup
	wg.Go(func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		sConn, chans, reqs, err := cryptoSSH.NewServerConn(conn, sshServerCfg)
		if err != nil {
			return
		}
		serverConnCh <- sConn
		go cryptoSSH.DiscardRequests(reqs)
		for newCh := range chans {
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "none")
		}
		_ = sConn.Wait()
	})
	defer func() {
		_ = listener.Close()
		wg.Wait()
	}()

	rawConn, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial test SSH server: %v", err)
	}
	cConn, chans, reqs, err := cryptoSSH.NewClientConn(rawConn, listener.Addr().String(), &cryptoSSH.ClientConfig{
		User:            "alice",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password("test")},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
	})
	if err != nil {
		_ = rawConn.Close()
		t.Fatalf("NewClientConn: %v", err)
	}
	sshCli := cryptoSSH.NewClient(cConn, chans, reqs)
	sConn := <-serverConnCh

	sockDir, err := os.MkdirTemp("/tmp", "mux7-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(sockDir) }()
	controlPath := filepath.Join(sockDir, "ctrl.sock")

	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:       controlPath,
		ExpectedUID:       uint32(os.Getuid()),
		CheckPeerUID:      true,
		PersistEnabled:    true,
		PersistIndefinite: true,
		SSHClient:         sshCli,
		RootConn:          rawConn,
	})
	if err != nil {
		_ = sshCli.Close()
		t.Fatalf("NewMuxServer: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()

	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve() }()

	muxCli, err := DialMuxClient(t.Context(), controlPath)
	if err != nil {
		t.Fatalf("DialMuxClient before drop: %v", err)
	}
	pid, err := muxCli.AliveCheck(t.Context())
	_ = muxCli.Close()
	if err != nil || pid == 0 {
		t.Fatalf("AliveCheck before drop = (%d, %v), want live master PID", pid, err)
	}

	// Simulate remote SSH disconnect.
	_ = sConn.Close()

	select {
	case <-srv.Wait():
	case <-time.After(3 * time.Second):
		t.Fatal("MuxServer did not shut down after underlying SSH transport dropped")
	}
	select {
	case <-serveDone:
	case <-time.After(3 * time.Second):
		t.Fatal("MuxServer.Serve did not exit after SSH transport drop")
	}

	if _, statErr := os.Lstat(controlPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Lstat(%q) after transport drop = %v, want os.ErrNotExist", controlPath, statErr)
	}
	if zombieCli, dialErr := DialMuxClient(t.Context(), controlPath); dialErr == nil {
		_ = zombieCli.Close()
		t.Fatal("DialMuxClient succeeded after SSH transport dropped; zombie socket survived")
	}
}

type pass7BlockingDynamicOpenSSHConn struct {
	dummyMuxGateConn
	enterOnce   sync.Once
	enteredCh   chan struct{}
	releaseCh   chan struct{}
	dynamicPort uint32
}

func (c *pass7BlockingDynamicOpenSSHConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	switch name {
	case "tcpip-forward":
		var req struct {
			BindAddr string
			BindPort uint32
		}
		_ = cryptoSSH.Unmarshal(payload, &req)
		if req.BindPort == 0 && wantReply {
			c.enterOnce.Do(func() { close(c.enteredCh) })
			<-c.releaseCh
			return true, cryptoSSH.Marshal(struct{ Port uint32 }{Port: c.dynamicPort}), nil
		}
		return true, nil, nil
	case "cancel-tcpip-forward":
		return true, nil, nil
	default:
		return false, nil, errors.New("unsupported request")
	}
}

// TestPass7_M4_OpenForwardInFlightBlocksHandoffAndDrain verifies M4:
//   - dynamic ListenPort == 0 opens in flight (before publishForward) block
//     PrepareHandoff and WaitForDrain so the in-flight forward publishes cleanly;
//   - authorize("forward") confirmation prompts in flight also block
//     PrepareHandoff and WaitForDrain.
func TestPass7_M4_OpenForwardInFlightBlocksHandoffAndDrain(t *testing.T) {
	setTestHome(t)
	t.Run("dynamic_port_zero_open_in_flight_blocks_handoff_and_drain", assertPass7DynamicPortZeroInFlightBlocksHandoff)
	t.Run("authorize_forward_in_flight_blocks_handoff_and_drain", assertPass7AuthorizeInFlightBlocksHandoff)
}

func assertPass7DynamicPortZeroInFlightBlocksHandoff(t *testing.T) {
	const allocPort = uint32(45720)
	mockConn := &pass7BlockingDynamicOpenSSHConn{
		enteredCh:   make(chan struct{}),
		releaseCh:   make(chan struct{}),
		dynamicPort: allocPort,
	}
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp4")
	defer cleanup()

	type openResult struct {
		pt      uint32
		payload []byte
	}
	openDone := make(chan openResult, 1)
	go func() {
		pt, payload := runPass4MuxFwdCall(t, func(c net.Conn) error {
			return srv.handleOpenFwd(c, MuxFwdRequest{
				RequestID:   21,
				FwdType:     MUX_FWD_REMOTE,
				ListenHost:  "127.0.0.1",
				ListenPort:  0,
				ConnectHost: "127.0.0.1",
				ConnectPort: 8080,
			})
		})
		openDone <- openResult{pt: pt, payload: payload}
	}()

	select {
	case <-mockConn.enteredCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for dynamic tcpip-forward to enter SendRequest")
	}

	if srv.PrepareHandoff() {
		srv.CancelHandoff()
		t.Fatal("PrepareHandoff succeeded while ListenPort == 0 handleOpenFwd was in flight")
	}
	shortCtx, shortCancel := context.WithTimeout(t.Context(), 35*time.Millisecond)
	defer shortCancel()
	if err := srv.WaitForDrain(shortCtx, 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitForDrain during in-flight ListenPort == 0 open = %v, want context.DeadlineExceeded", err)
	}

	close(mockConn.releaseCh)
	res := <-openDone
	if res.pt != MUX_S_REMOTE_PORT || len(res.payload) != 8 {
		t.Fatalf("dynamic open result = (0x%x, len=%d), want MUX_S_REMOTE_PORT", res.pt, len(res.payload))
	}
	if gotPort := binary.BigEndian.Uint32(res.payload[4:8]); gotPort != allocPort {
		t.Fatalf("allocated port = %d, want %d", gotPort, allocPort)
	}

	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{
		RequestID:   22,
		FwdType:     MUX_FWD_REMOTE,
		ListenHost:  "127.0.0.1",
		ListenPort:  allocPort,
		ConnectHost: "127.0.0.1",
		ConnectPort: 8080,
	})
	if !srv.PrepareHandoff() {
		t.Fatal("PrepareHandoff failed after dynamic forward closed")
	}
	srv.CancelHandoff()
}

func assertPass7AuthorizeInFlightBlocksHandoff(t *testing.T) {
	mockConn := &pass4MuxForwardSSHConn{nextRemotePort: 45730}
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp4")
	defer cleanup()

	confirmEntered := make(chan struct{})
	releaseConfirm := make(chan struct{})
	var enterOnce sync.Once
	srv.askConfirmation = true
	srv.confirmSession = func(action string) bool {
		if action == "forward" {
			enterOnce.Do(func() { close(confirmEntered) })
			<-releaseConfirm
		}
		return false
	}

	openDone := make(chan uint32, 1)
	go func() {
		pt, _ := runPass4MuxFwdCall(t, func(c net.Conn) error {
			return srv.handleOpenFwd(c, MuxFwdRequest{
				RequestID:   31,
				FwdType:     MUX_FWD_LOCAL,
				ListenHost:  "127.0.0.1",
				ListenPort:  0,
				ConnectHost: "127.0.0.1",
				ConnectPort: 8080,
			})
		})
		openDone <- pt
	}()

	select {
	case <-confirmEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for authorize(forward) callback")
	}

	if srv.PrepareHandoff() {
		srv.CancelHandoff()
		t.Fatal("PrepareHandoff succeeded while authorize(forward) was in flight")
	}
	shortCtx, shortCancel := context.WithTimeout(t.Context(), 35*time.Millisecond)
	defer shortCancel()
	if err := srv.WaitForDrain(shortCtx, 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitForDrain during authorize(forward) = %v, want context.DeadlineExceeded", err)
	}

	close(releaseConfirm)
	if pt := <-openDone; pt != MUX_S_PERMISSION_DENIED {
		t.Fatalf("denied forward packet = 0x%x, want MUX_S_PERMISSION_DENIED", pt)
	}
	if !srv.PrepareHandoff() {
		t.Fatal("PrepareHandoff failed after denied forward finished")
	}
	srv.CancelHandoff()
}

// TestPass7_M5_UnifiedForwardSpecValidationAndStreamLocalNormalization verifies M5:
//   - validateAndNormalizeMuxFwdSpec, handleOpenFwd, and handleCloseFwd reject
//     out-of-range TCP ports (> 65535, formatted unsigned without 32-bit overflow),
//     ConnectPort == 0 on non-dynamic forwards, NUL bytes in ListenHost/ConnectHost,
//     and empty StreamLocal paths;
//   - StreamLocal ConnectHost paths (ConnectPort == MUX_SPECIAL_PORT_UNIX) are
//     cleaned symmetrically across open, duplicate detection, and close.
func TestPass7_M5_UnifiedForwardSpecValidationAndStreamLocalNormalization(t *testing.T) {
	setTestHome(t)
	t.Run("rejects_invalid_ports_hosts_and_nul_bytes_on_open_and_close", assertPass7InvalidFwdSpecsRejected)
	t.Run("streamlocal_connect_host_canonicalizes_across_open_duplicate_and_close", assertPass7StreamLocalConnectHostCanonicalization)
}

func assertPass7InvalidFwdSpecsRejected(t *testing.T) {
	mockConn := &pass4MuxForwardSSHConn{nextRemotePort: 45750}
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp4")
	defer cleanup()

	badCases := []struct {
		name       string
		req        MuxFwdRequest
		wantSubstr string
	}{
		{
			name:       "listen_port_65536",
			req:        MuxFwdRequest{FwdType: MUX_FWD_LOCAL, ListenHost: "127.0.0.1", ListenPort: 65536, ConnectHost: "127.0.0.1", ConnectPort: 80},
			wantSubstr: "65536",
		},
		{
			name:       "listen_port_high_uint32_unsigned_format",
			req:        MuxFwdRequest{FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: 0x80000001, ConnectHost: "127.0.0.1", ConnectPort: 80},
			wantSubstr: "2147483649",
		},
		{
			name:       "local_connect_port_zero",
			req:        MuxFwdRequest{FwdType: MUX_FWD_LOCAL, ListenHost: "127.0.0.1", ListenPort: 8080, ConnectHost: "127.0.0.1", ConnectPort: 0},
			wantSubstr: "connect port 0",
		},
		{
			name:       "remote_connect_port_zero_with_host",
			req:        MuxFwdRequest{FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: 8080, ConnectHost: "127.0.0.1", ConnectPort: 0},
			wantSubstr: "connect port 0",
		},
		{
			name:       "connect_port_high_uint32_unsigned_format",
			req:        MuxFwdRequest{FwdType: MUX_FWD_LOCAL, ListenHost: "127.0.0.1", ListenPort: 8080, ConnectHost: "127.0.0.1", ConnectPort: 0xFFFFFFFF},
			wantSubstr: "4294967295",
		},
		{
			name:       "dynamic_nonzero_connect_port",
			req:        MuxFwdRequest{FwdType: MUX_FWD_DYNAMIC, ListenHost: "127.0.0.1", ListenPort: 1080, ConnectPort: 80},
			wantSubstr: "connect port 80",
		},
		{
			name:       "empty_tcp_connect_host",
			req:        MuxFwdRequest{FwdType: MUX_FWD_LOCAL, ListenHost: "127.0.0.1", ListenPort: 8080, ConnectHost: "   ", ConnectPort: 80},
			wantSubstr: "connect host cannot be empty",
		},
		{
			name:       "empty_streamlocal_listen_path",
			req:        MuxFwdRequest{FwdType: MUX_FWD_LOCAL, ListenHost: "   ", ListenPort: MUX_SPECIAL_PORT_UNIX, ConnectHost: "127.0.0.1", ConnectPort: 80},
			wantSubstr: "cannot be empty",
		},
		{
			name:       "empty_streamlocal_connect_path",
			req:        MuxFwdRequest{FwdType: MUX_FWD_LOCAL, ListenHost: "127.0.0.1", ListenPort: 8080, ConnectHost: "   ", ConnectPort: MUX_SPECIAL_PORT_UNIX},
			wantSubstr: "cannot be empty",
		},
		{
			name:       "nul_in_listen_host",
			req:        MuxFwdRequest{FwdType: MUX_FWD_LOCAL, ListenHost: "127.0.0.1\x00bad", ListenPort: 8080, ConnectHost: "127.0.0.1", ConnectPort: 80},
			wantSubstr: "NUL",
		},
		{
			name:       "nul_in_connect_host",
			req:        MuxFwdRequest{FwdType: MUX_FWD_REMOTE, ListenHost: "127.0.0.1", ListenPort: 8080, ConnectHost: "/tmp/a\x00b.sock", ConnectPort: MUX_SPECIAL_PORT_UNIX},
			wantSubstr: "NUL",
		},
	}

	for i, tc := range badCases {
		_, _, err := validateAndNormalizeMuxFwdSpec(
			tc.req.FwdType, tc.req.ListenHost, tc.req.ListenPort, tc.req.ConnectHost, tc.req.ConnectPort,
		)
		if err == nil || !strings.Contains(err.Error(), tc.wantSubstr) {
			t.Fatalf("%s: validateAndNormalizeMuxFwdSpec err = %v, want substring %q", tc.name, err, tc.wantSubstr)
		}

		req := tc.req
		req.RequestID = uint32(100 + i)
		openPt, openPayload := runPass4MuxFwdCall(t, func(c net.Conn) error {
			return srv.handleOpenFwd(c, req)
		})
		_, openReason, _ := DecodeMuxError(openPayload)
		if openPt != MUX_S_FAILURE || !strings.Contains(openReason, tc.wantSubstr) {
			t.Fatalf("%s: handleOpenFwd = (0x%x, %q), want MUX_S_FAILURE containing %q", tc.name, openPt, openReason, tc.wantSubstr)
		}

		closePt, closePayload := runPass4MuxFwdCall(t, func(c net.Conn) error {
			return srv.handleCloseFwd(c, req)
		})
		_, closeReason, _ := DecodeMuxError(closePayload)
		if closePt != MUX_S_FAILURE || !strings.Contains(closeReason, tc.wantSubstr) {
			t.Fatalf("%s: handleCloseFwd = (0x%x, %q), want MUX_S_FAILURE containing %q", tc.name, closePt, closeReason, tc.wantSubstr)
		}
	}

	// Verify reverse-dynamic MUX_FWD_REMOTE (ConnectHost="", ConnectPort=0) and MUX_FWD_DYNAMIC remain valid.
	if _, _, err := validateAndNormalizeMuxFwdSpec(MUX_FWD_REMOTE, "127.0.0.1", 1080, "", 0); err != nil {
		t.Fatalf("reverse-dynamic MUX_FWD_REMOTE rejected: %v", err)
	}
	if _, _, err := validateAndNormalizeMuxFwdSpec(MUX_FWD_DYNAMIC, "127.0.0.1", 1080, "", 0); err != nil {
		t.Fatalf("MUX_FWD_DYNAMIC rejected: %v", err)
	}
}

func assertPass7StreamLocalConnectHostCanonicalization(t *testing.T) {
	mockConn := &pass4MuxForwardSSHConn{nextRemotePort: 45790}
	srv, cleanup := newPass4TestMuxServer(t, mockConn, "tcp4")
	defer cleanup()

	sockDir, err := os.MkdirTemp("/tmp", "mux7u-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer func() { _ = os.RemoveAll(sockDir) }()

	listenRaw := sockDir + "//sub/../listen.sock"
	listenClean := filepath.Join(sockDir, "listen.sock")
	targetRaw := sockDir + "//nested/../target.sock"
	targetClean := filepath.Join(sockDir, "target.sock")

	// Open local -> StreamLocal forward using non-canonical ListenHost and ConnectHost.
	mustPass4OpenFwdOK(t, srv, MuxFwdRequest{
		RequestID:   201,
		FwdType:     MUX_FWD_LOCAL,
		ListenHost:  listenRaw,
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: targetRaw,
		ConnectPort: MUX_SPECIAL_PORT_UNIX,
	})

	// Re-open with canonical paths: must be recognized as idempotent duplicate (not conflict).
	mustPass4OpenFwdOK(t, srv, MuxFwdRequest{
		RequestID:   202,
		FwdType:     MUX_FWD_LOCAL,
		ListenHost:  listenClean,
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: targetClean,
		ConnectPort: MUX_SPECIAL_PORT_UNIX,
	})
	if got := srv.forwardCount(); got != 1 {
		t.Fatalf("forwardCount after canonical duplicate open = %d, want 1", got)
	}

	// Close using another non-canonical spelling of ConnectHost: must match and tear down cleanly.
	mustPass4CloseFwdOK(t, srv, MuxFwdRequest{
		RequestID:   203,
		FwdType:     MUX_FWD_LOCAL,
		ListenHost:  listenClean,
		ListenPort:  MUX_SPECIAL_PORT_UNIX,
		ConnectHost: sockDir + "///target.sock",
		ConnectPort: MUX_SPECIAL_PORT_UNIX,
	})
	assertPass4MuxForwardTablesEmpty(t, srv)
}
