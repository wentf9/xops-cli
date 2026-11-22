package ssh

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type w10bSSHServerHooks struct {
	onDirectTCPIP func(connCtx context.Context, newCh cryptoSSH.NewChannel)
	onSession     func(connCtx context.Context, sConn *cryptoSSH.ServerConn, newCh cryptoSSH.NewChannel)
}

type w10bSSHServer struct {
	addr     string
	host     string
	port     int
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	hooks    w10bSSHServerHooks
	mu       sync.Mutex
	conns    []net.Conn
	wg       sync.WaitGroup
}

func startW10bSSHServer(t *testing.T, parentCtx context.Context, hooks w10bSSHServerHooks) *w10bSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := cryptoSSH.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	srvCfg := &cryptoSSH.ServerConfig{
		PasswordCallback: func(_ cryptoSSH.ConnMetadata, pass []byte) (*cryptoSSH.Permissions, error) {
			if string(pass) == sshfixture.Password {
				return &cryptoSSH.Permissions{}, nil
			}
			return nil, errors.New("invalid password")
		},
	}
	srvCfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen w10b SSH server: %v", err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	ctx, cancel := context.WithCancel(parentCtx)
	s := &w10bSSHServer{
		addr:     ln.Addr().String(),
		host:     tcpAddr.IP.String(),
		port:     tcpAddr.Port,
		listener: ln,
		ctx:      ctx,
		cancel:   cancel,
		hooks:    hooks,
	}
	s.wg.Go(func() {
		for {
			raw, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, raw)
			s.mu.Unlock()
			s.wg.Go(func() {
				s.serveConn(raw, srvCfg)
			})
		}
	})
	t.Cleanup(func() {
		s.cancel()
		_ = s.listener.Close()
		s.mu.Lock()
		conns := append([]net.Conn(nil), s.conns...)
		s.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
		s.wg.Wait()
	})
	return s
}

func (s *w10bSSHServer) serveConn(raw net.Conn, cfg *cryptoSSH.ServerConfig) {
	defer func() { _ = raw.Close() }()
	stopClose := context.AfterFunc(s.ctx, func() { _ = raw.Close() })
	defer stopClose()

	sConn, chans, reqs, err := cryptoSSH.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer func() { _ = sConn.Close() }()

	connCtx, connCancel := context.WithCancel(s.ctx)
	defer connCancel()

	var connWG sync.WaitGroup
	connWG.Go(func() { cryptoSSH.DiscardRequests(reqs) })

	for newCh := range chans {
		switch newCh.ChannelType() {
		case "direct-tcpip":
			if s.hooks.onDirectTCPIP != nil {
				ch := newCh
				connWG.Go(func() { s.hooks.onDirectTCPIP(connCtx, ch) })
				continue
			}
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "direct-tcpip disabled")
		case "session":
			if s.hooks.onSession != nil {
				ch := newCh
				connWG.Go(func() { s.hooks.onSession(connCtx, sConn, ch) })
				continue
			}
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "session disabled")
		default:
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported")
		}
	}
	connCancel()
	connWG.Wait()
}

type w10bMuxOpts struct {
	requestTimeout    time.Duration
	allowAgentForward bool
	agentSocket       string
	dialAgent         func(context.Context, string) (net.Conn, error)
}

func startW10bDirectMux(
	t *testing.T,
	ctx context.Context,
	sshSrv *w10bSSHServer,
	sockName string,
	opts w10bMuxOpts,
) (*MuxServer, *modeSwitchConn, string) {
	t.Helper()
	rawTCP, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", sshSrv.addr)
	if err != nil {
		t.Fatalf("dial w10b SSH server: %v", err)
	}
	rootConn := newModeSwitchConn(rawTCP)
	sshCfg := &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	cConn, chans, reqs, err := cryptoSSH.NewClientConn(rootConn, sshSrv.addr, sshCfg)
	if err != nil {
		_ = rootConn.Close()
		t.Fatalf("ssh NewClientConn: %v", err)
	}
	sshCli := cryptoSSH.NewClient(cConn, chans, reqs)

	sockPath := filepath.Join(shortSocketDir(t), sockName)
	srv, err := StartMuxServer(ctx, sshCli, MuxMasterOptions{
		Path:              sockPath,
		RootConn:          rootConn,
		AllowAgentForward: opts.allowAgentForward,
		AgentSocket:       opts.agentSocket,
		DialAgent:         opts.dialAgent,
		Target: TargetContext{
			Host: sshSrv.host,
			Port: sshSrv.port,
			User: "fixture",
			Control: &ControlConfig{
				Master:  ControlMasterYes,
				Path:    sockPath,
				Persist: "yes",
			},
		},
		InitialActiveSessions: 0,
	})
	if err != nil {
		_ = rootConn.Close()
		_ = sshCli.Close()
		if errors.Is(err, ErrUnsupportedMuxPlatform) {
			t.Skipf("mux control socket unsupported on platform: %v", err)
		}
		t.Fatalf("StartMuxServer: %v", err)
	}
	if opts.requestTimeout > 0 {
		srv.requestTimeout = opts.requestTimeout
	}
	t.Cleanup(func() {
		_ = rootConn.Close()
		_ = srv.Shutdown()
		select {
		case <-srv.Wait():
		case <-time.After(2 * time.Second):
		}
	})
	return srv, rootConn, sockPath
}

func assertW10bWedgedEscalationDrains(
	t *testing.T,
	ctx context.Context,
	srv *MuxServer,
	rootConn *modeSwitchConn,
	sockPath string,
	trigger func(),
	baselineGoroutines int,
	label string,
) {
	t.Helper()
	drainDone := make(chan error, 1)
	go func() {
		drainDone <- srv.WaitForDrain(ctx, 0)
	}()

	rootConn.wedgeWrite.Store(true)
	if trigger != nil {
		trigger()
	}

	waitWithin(t, label+": bounded escalation shutdown", 600*time.Millisecond, func() {
		<-srv.Wait()
	})
	select {
	case drainErr := <-drainDone:
		if drainErr != nil {
			t.Fatalf("%s: WaitForDrain returned %v", label, drainErr)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("%s: WaitForDrain remained wedged", label)
	}
	if !rootConn.closed.Load() {
		t.Fatalf("%s: expected escalation to abort write-wedged RootConn", label)
	}
	waitForCondition(t, time.Second, func() bool {
		return srv.ActiveSessions() == 0
	}, label+": ActiveSessions did not drain to 0")
	assertW7aMuxDrainedClosed(t, srv, sockPath)
	waitForGoroutinesAtMost(t, baselineGoroutines+2, time.Second, label+" goroutine check")
}

// TestW10b_C10_M2_SlowRemoteChannelCloseEchoPreservesHealthyMuxServer verifies
// C10-M2: muxForwardChannelConn.Close passes nil (NOT reqsDone) to
// closeMuxChannelBounded. When a remote peer delays echoing
// SSH_MSG_CHANNEL_CLOSE by > 2*channelCloseTimeout on a single -L stream while
// the transport is healthy, muxForwardChannelConn.Close returns in <50ms and
// the shared MuxServer stays running and healthy (AliveCheck succeeds).
func TestW10b_C10_M2_SlowRemoteChannelCloseEchoPreservesHealthyMuxServer(t *testing.T) {
	t.Run("a_direct_muxForwardChannelConn_close_fast_and_preserves_master", testW10bC10M2DirectConnCloseFast)
	t.Run("b_local_forward_L_stream_slow_remote_close_keeps_master_serving", testW10bC10M2LocalForwardSlowClose)
}

func testW10bC10M2DirectConnCloseFast(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const closeTimeout = 80 * time.Millisecond
	releaseRemoteClose := make(chan struct{})
	defer close(releaseRemoteClose)
	remoteSawEOF := make(chan struct{}, 1)

	sshSrv := startW10bSSHServer(t, ctx, w10bSSHServerHooks{
		onDirectTCPIP: func(connCtx context.Context, newCh cryptoSSH.NewChannel) {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				return
			}
			go cryptoSSH.DiscardRequests(reqs)
			defer func() { _ = ch.Close() }()

			buf := make([]byte, 32)
			n, rErr := ch.Read(buf)
			if rErr == nil && n > 0 {
				_, _ = ch.Write(buf[:n])
			}
			_, _ = io.Copy(io.Discard, ch)
			select {
			case remoteSawEOF <- struct{}{}:
			default:
			}
			// Deliberately delay echoing SSH_MSG_CHANNEL_CLOSE past >2*closeTimeout.
			select {
			case <-releaseRemoteClose:
			case <-connCtx.Done():
			}
		},
	})

	srv, _, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w10b-m2-dir.sock", w10bMuxOpts{
		requestTimeout: closeTimeout,
	})
	muxCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	fwdConn, err := srv.dialSSHMux(ctx, "tcp", "127.0.0.1:80")
	if err != nil {
		t.Fatalf("dialSSHMux: %v", err)
	}
	const ping = "m2-ping\n"
	if _, err := io.WriteString(fwdConn, ping); err != nil {
		t.Fatalf("write fwdConn: %v", err)
	}
	got := make([]byte, len(ping))
	if _, err := io.ReadFull(fwdConn, got); err != nil || string(got) != ping {
		t.Fatalf("read fwdConn = (%q, %v), want %q", string(got), err, ping)
	}

	// Close fwdConn while the remote peer withholds SSH_MSG_CHANNEL_CLOSE
	// for >2*channelCloseTimeout. Close() must return in <50ms without
	// firing s.interruptTransportAndShutdown().
	start := time.Now()
	closeErr := fwdConn.Close()
	elapsed := time.Since(start)
	if closeErr != nil {
		t.Fatalf("muxForwardChannelConn.Close() = %v, want nil", closeErr)
	}
	if elapsed >= 50*time.Millisecond {
		t.Fatalf("muxForwardChannelConn.Close() took %v, want <50ms", elapsed)
	}

	select {
	case <-remoteSawEOF:
	case <-time.After(2 * time.Second):
		t.Fatal("remote handler did not observe EOF/close")
	}

	// Hold past >2*channelCloseTimeout while remote still withholds close echo.
	time.Sleep(2*closeTimeout + 40*time.Millisecond)
	if srv.isShuttingDown() || srv.currentPhase() != muxPhaseRunning {
		t.Fatalf("healthy MuxServer torn down by slow remote close echo: phase=%d shuttingDown=%v", srv.currentPhase(), srv.isShuttingDown())
	}
	if _, err := muxCli.AliveCheck(ctx); err != nil {
		t.Fatalf("AliveCheck failed after slow remote channel close: %v", err)
	}
}

func testW10bC10M2LocalForwardSlowClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const closeTimeout = 80 * time.Millisecond
	var streamSeq atomic.Int32
	releaseFirstClose := make(chan struct{})
	defer close(releaseFirstClose)

	sshSrv := startW10bSSHServer(t, ctx, w10bSSHServerHooks{
		onDirectTCPIP: func(connCtx context.Context, newCh cryptoSSH.NewChannel) {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				return
			}
			go cryptoSSH.DiscardRequests(reqs)
			defer func() { _ = ch.Close() }()

			seq := streamSeq.Add(1)
			buf := make([]byte, 64)
			if n, rErr := ch.Read(buf); rErr == nil && n > 0 {
				_, _ = ch.Write(buf[:n])
			}
			_ = ch.CloseWrite()
			_, _ = io.Copy(io.Discard, ch)
			if seq == 1 {
				// Delay SSH_MSG_CHANNEL_CLOSE echo on the first -L stream by >2*closeTimeout.
				select {
				case <-releaseFirstClose:
				case <-connCtx.Done():
				}
			}
		},
	})

	srv, _, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w10b-m2-L.sock", w10bMuxOpts{
		requestTimeout: closeTimeout,
	})
	muxCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	localPort := pickFreeLocalTCPPort(t)
	if _, err := muxCli.OpenForward(ctx, ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  "127.0.0.1",
		ListenPort:  localPort,
		ConnectHost: "127.0.0.1",
		ConnectPort: 80,
	}); err != nil {
		t.Fatalf("OpenForward(-L): %v", err)
	}
	localAddr := net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(localPort), 10))
	s1 := openW7aVerifiedTCPStream(t, localAddr, "m2-L1\n")
	_ = s1.Close()

	// Stream 1's activeForwardStreams must drain cleanly even though the
	// remote peer has not echoed SSH_MSG_CHANNEL_CLOSE yet.
	waitForCondition(t, 2*closeTimeout, func() bool {
		srv.idleMu.Lock()
		active := srv.activeForwardStreams
		srv.idleMu.Unlock()
		return active == 0
	}, "first -L stream did not drain while remote delayed SSH_MSG_CHANNEL_CLOSE")

	// Sleep past 2*closeTimeout and confirm MuxServer stays alive and serves a 2nd stream.
	time.Sleep(2*closeTimeout + 40*time.Millisecond)
	if _, err := muxCli.AliveCheck(ctx); err != nil {
		t.Fatalf("AliveCheck after slow -L remote close failed: %v", err)
	}
	s2 := openW7aVerifiedTCPStream(t, localAddr, "m2-L2\n")
	_ = s2.Close()
}

// TestW10b_C10_L1_DialSSHMuxDrainsStderrExtendedDataBeyondWindow verifies
// C10-L1: MuxServer.dialSSHMux drains ch.Stderr() so >2.5 MiB of
// SSH_MSG_CHANNEL_EXTENDED_DATA cannot exhaust x/crypto/ssh's shared 2 MiB
// channel receive window and stall normal channel data on -L / -D streams.
func TestW10b_C10_L1_DialSSHMuxDrainsStderrExtendedDataBeyondWindow(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const stderrTotalBytes = 2600 * 1024 // > 2.5 MiB (exceeds 2 MiB SSH channel window)
	const tailPayload = "w10b-after-stderr-ok\n"

	stderrWriteErr := make(chan error, 1)
	sshSrv := startW10bSSHServer(t, ctx, w10bSSHServerHooks{
		onDirectTCPIP: func(_ context.Context, newCh cryptoSSH.NewChannel) {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				return
			}
			go cryptoSSH.DiscardRequests(reqs)
			defer func() { _ = ch.Close() }()

			chunk := bytes.Repeat([]byte("E"), 32*1024)
			var wErr error
			for sent := 0; sent < stderrTotalBytes; {
				n := min(len(chunk), stderrTotalBytes-sent)
				written, err := ch.Stderr().Write(chunk[:n])
				sent += written
				if err != nil {
					wErr = err
					break
				}
			}
			stderrWriteErr <- wErr
			if wErr != nil {
				return
			}
			if _, err := io.WriteString(ch, tailPayload); err != nil {
				return
			}
			// Echo one round-trip after stderr flood to confirm bidirectional flow.
			buf := make([]byte, 64)
			if n, rErr := ch.Read(buf); rErr == nil && n > 0 {
				_, _ = ch.Write(buf[:n])
			}
		},
	})

	runtime.GC()
	baseline := runtime.NumGoroutine()

	srv, _, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w10b-l1-stderr.sock", w10bMuxOpts{})
	muxCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	localPort := pickFreeLocalTCPPort(t)
	if _, err := muxCli.OpenForward(ctx, ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  "127.0.0.1",
		ListenPort:  localPort,
		ConnectHost: "127.0.0.1",
		ConnectPort: 80,
	}); err != nil {
		t.Fatalf("OpenForward(-L): %v", err)
	}

	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(localPort), 10)))
	if err != nil {
		t.Fatalf("dial -L port: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	gotTail := make([]byte, len(tailPayload))
	if _, err := io.ReadFull(conn, gotTail); err != nil {
		t.Fatalf("read normal data after >2.5 MiB stderr failed (window stalled?): %v", err)
	}
	if string(gotTail) != tailPayload {
		t.Fatalf("tail payload = %q, want %q", string(gotTail), tailPayload)
	}
	select {
	case wErr := <-stderrWriteErr:
		if wErr != nil {
			t.Fatalf("remote stderr flood failed: %v", wErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("remote stderr flood did not finish")
	}

	assertW7aEchoRoundTrip(t, conn, "w10b-post-stderr-echo\n")
	_ = conn.Close()
	_ = muxCli.Close()
	_ = srv.Shutdown()
	<-srv.Wait()
	waitForGoroutinesAtMost(t, baseline+2, time.Second, "C10-L1 stderr drain goroutine check")
}

func waitForProxyChannelRequest(t *testing.T, rawConn net.Conn, wantType string) {
	t.Helper()
	_ = rawConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer func() { _ = rawConn.SetReadDeadline(time.Time{}) }()
	for {
		pkt, err := readUnpaddedPacket(rawConn)
		if err != nil {
			t.Fatalf("readUnpaddedPacket waiting for %q: %v", wantType, err)
		}
		if len(pkt) >= 5 && pkt[0] == msgChannelRequest {
			r := newMuxReader(pkt[5:])
			if rType, rErr := r.ReadString(); rErr == nil && rType == wantType {
				return
			}
		}
	}
}

// TestW10b_C10_M1_ProxyRelayBoundedCloseWriteAndRequestReplyOnWedgedTransport
// verifies C10-M1 across all 4 MUX_C_PROXY write-wedged paths:
//  1. relayChannelInput msgChannelEOF -> closeMuxChannelWriteBounded
//  2. handleRemoteRequestReply -> replyMuxChannelRequestBounded
//  3. proxySessionState.closeAll with pending remote WantReply=true request
//  4. retireChannel (msgChannelClose) with pending remote WantReply=true request
func TestW10b_C10_M1_ProxyRelayBoundedCloseWriteAndRequestReplyOnWedgedTransport(t *testing.T) {
	t.Run("a_relayChannelInput_CloseWrite_wedged", func(t *testing.T) {
		testW10bC10M1ProxyWedged(t, "eof")
	})
	t.Run("b_handleRemoteRequestReply_wedged", func(t *testing.T) {
		testW10bC10M1ProxyWedged(t, "reply")
	})
	t.Run("c_closeAll_pending_remote_request_wedged", func(t *testing.T) {
		testW10bC10M1ProxyWedged(t, "disconnect")
	})
	t.Run("d_retireChannel_handleClose_pending_remote_request_wedged", func(t *testing.T) {
		testW10bC10M1ProxyWedged(t, "close")
	})
}

func testW10bC10M1ProxyWedged(t *testing.T, mode string) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	const closeTimeout = 80 * time.Millisecond
	needRemoteProbe := mode != "eof"
	execStarted := make(chan struct{}, 1)

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
					case execStarted <- struct{}{}:
					default:
					}
					if needRemoteProbe {
						_, _ = ch.SendRequest("probe@w10b", true, []byte("ping"))
					}
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

	srv, rootConn, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w10b-m1-"+mode+".sock", w10bMuxOpts{
		requestTimeout: closeTimeout,
	})

	rawProxy, serverCh, closeProxy := openRawMuxProxyChannel(t, ctx, sockPath, "hold", 65536, 32768)
	defer closeProxy()

	select {
	case <-execStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("remote exec session did not start")
	}
	if needRemoteProbe {
		waitForProxyChannelRequest(t, rawProxy, "probe@w10b")
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
		t.Fatalf("ActiveSessions before wedged %s = %d, want 1", mode, got)
	}

	assertW10bWedgedEscalationDrains(t, ctx, srv, rootConn, sockPath, func() {
		switch mode {
		case "eof":
			w := newMuxWriter()
			w.buf = append(w.buf, msgChannelEOF)
			w.WriteUint32(serverCh)
			_ = writeUnpaddedPacket(rawProxy, w.Bytes())
		case "reply":
			w := newMuxWriter()
			w.buf = append(w.buf, msgChannelSuccess)
			w.WriteUint32(serverCh)
			_ = writeUnpaddedPacket(rawProxy, w.Bytes())
		case "disconnect":
			closeProxy()
		case "close":
			w := newMuxWriter()
			w.buf = append(w.buf, msgChannelClose)
			w.WriteUint32(serverCh)
			_ = writeUnpaddedPacket(rawProxy, w.Bytes())
		}
	}, baseline, "C10-M1 proxy "+mode)
}

type w10bHookCloseConn struct {
	net.Conn
	onClose func()
}

func (c *w10bHookCloseConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return c.Conn.Close()
}

type w10bFakeAgentHarness struct {
	dialAgent      func(context.Context, string) (net.Conn, error)
	agentOpened    chan struct{}
	closeAllLocal  func()
	setOnConnClose func(func())
}

func newW10bFakeAgentHarness(t *testing.T) *w10bFakeAgentHarness {
	t.Helper()
	var (
		mu       sync.Mutex
		conns    []net.Conn
		onClose  func()
		openOnce sync.Once
	)
	opened := make(chan struct{})
	h := &w10bFakeAgentHarness{
		agentOpened: opened,
	}
	h.setOnConnClose = func(fn func()) {
		mu.Lock()
		onClose = fn
		mu.Unlock()
	}
	h.dialAgent = func(_ context.Context, _ string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		mu.Lock()
		conns = append(conns, c1, c2)
		mu.Unlock()
		// Serve one ping byte to prove the forwarded agent channel is active,
		// then hold open until closeAllLocal or peer closes.
		go func() {
			var b [1]byte
			if _, err := io.ReadFull(c2, b[:]); err == nil {
				_, _ = c2.Write(b[:])
				openOnce.Do(func() { close(opened) })
				_, _ = io.Copy(io.Discard, c2)
			}
			_ = c2.Close()
		}()
		return &w10bHookCloseConn{
			Conn: c1,
			onClose: func() {
				mu.Lock()
				fn := onClose
				mu.Unlock()
				if fn != nil {
					fn()
				}
			},
		}, nil
	}
	h.closeAllLocal = func() {
		mu.Lock()
		snapshot := append([]net.Conn(nil), conns...)
		mu.Unlock()
		for _, c := range snapshot {
			_ = c.Close()
		}
	}
	t.Cleanup(h.closeAllLocal)
	return h
}

func startW10bAgentSSHServer(t *testing.T, ctx context.Context, holdAgentOpen <-chan struct{}, holdSessionOpen <-chan struct{}) (*w10bSSHServer, <-chan struct{}) {
	t.Helper()
	agentLive := make(chan struct{}, 1)
	sshSrv := startW10bSSHServer(t, ctx, w10bSSHServerHooks{
		onSession: func(connCtx context.Context, sConn *cryptoSSH.ServerConn, newCh cryptoSSH.NewChannel) {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				return
			}
			defer func() { _ = ch.Close() }()

			var agentWG sync.WaitGroup
			defer agentWG.Wait()

			for req := range reqs {
				switch req.Type {
				case agentForwardRequestType:
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					agentWG.Go(func() {
						aCh, aReqs, openErr := sConn.OpenChannel(agentForwardChannelType, nil)
						if openErr != nil {
							return
						}
						go cryptoSSH.DiscardRequests(aReqs)
						defer func() { _ = aCh.Close() }()
						if _, wErr := aCh.Write([]byte{'P'}); wErr != nil {
							return
						}
						var ack [1]byte
						if _, rErr := io.ReadFull(aCh, ack[:]); rErr != nil {
							return
						}
						select {
						case agentLive <- struct{}{}:
						default:
						}
						select {
						case <-holdAgentOpen:
						case <-connCtx.Done():
						}
					})
				case "exec":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					if holdSessionOpen != nil {
						select {
						case <-holdSessionOpen:
						case <-connCtx.Done():
						}
						return
					}
					_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
					return
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		},
	})
	return sshSrv, agentLive
}

func openRawMuxProxyAgentSession(t *testing.T, ctx context.Context, sockPath string) (net.Conn, uint32, func()) {
	t.Helper()
	mc, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	unbind := bindConnContext(ctx, mc.conn, 10*time.Second)
	if err := WriteMuxPacket(mc.conn, MUX_C_PROXY, encodeChannelIDs(1)); err != nil {
		unbind()
		_ = mc.Close()
		t.Fatalf("WriteMuxPacket(MUX_C_PROXY): %v", err)
	}
	pktType, payload, err := ReadMuxPacket(mc.conn)
	unbind()
	if err != nil || pktType != MUX_S_PROXY {
		_ = mc.Close()
		t.Fatalf("MUX_S_PROXY = (0x%x, %q, %v)", pktType, payload, err)
	}
	if _, err := readUnpaddedPacket(mc.conn); err != nil {
		_ = mc.Close()
		t.Fatalf("read initial proxy packet: %v", err)
	}

	openW := newMuxWriter()
	openW.buf = append(openW.buf, msgChannelOpen)
	openW.WriteString("session")
	openW.WriteUint32(1)
	openW.WriteUint32(65536)
	openW.WriteUint32(32768)
	if err := writeUnpaddedPacket(mc.conn, openW.Bytes()); err != nil {
		_ = mc.Close()
		t.Fatalf("write msgChannelOpen: %v", err)
	}

	var serverCh uint32
	for {
		pkt, rErr := readUnpaddedPacket(mc.conn)
		if rErr != nil {
			_ = mc.Close()
			t.Fatalf("read open confirmation: %v", rErr)
		}
		if len(pkt) >= 9 && pkt[0] == msgChannelOpenConfirmation {
			serverCh = binaryUint32(pkt[5:9])
			break
		}
	}

	reqW := newMuxWriter()
	reqW.buf = append(reqW.buf, msgChannelRequest)
	reqW.WriteUint32(serverCh)
	reqW.WriteString(agentForwardRequestType)
	reqW.WriteBool(true)
	if err := writeUnpaddedPacket(mc.conn, reqW.Bytes()); err != nil {
		_ = mc.Close()
		t.Fatalf("write auth-agent-req: %v", err)
	}
	for {
		pkt, rErr := readUnpaddedPacket(mc.conn)
		if rErr != nil {
			_ = mc.Close()
			t.Fatalf("read auth-agent-req reply: %v", rErr)
		}
		if len(pkt) >= 5 && pkt[0] == msgChannelSuccess {
			break
		}
		if len(pkt) >= 5 && pkt[0] == msgChannelFailure {
			_ = mc.Close()
			t.Fatal("master rejected MUX_C_PROXY auth-agent-req@openssh.com")
		}
	}
	return mc.conn, serverCh, func() { _ = mc.Close() }
}

func binaryUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// TestW10b_C10_M3_AgentForwardBoundedReleaseAndCloseWriteOnWedgedTransport
// verifies C10-M3 across:
//   - (a) MUX_C_PROXY releaseAgentProxyLease() / releaseWithDeadline() when an
//     auth-agent@openssh.com channel is active over a write-wedged transport;
//   - (b) serveLocalAgentChannel CloseWrite() when the local agent closes over
//     a write-wedged transport while the session is still open;
//   - (c) direct Client agentForwardLease.releaseWithDeadline() escalating via
//     Client.Interrupt() on a write-wedged transport;
//   - (d) healthy agentForwardLease release preserving the shared MuxServer.
func TestW10b_C10_M3_AgentForwardBoundedReleaseAndCloseWriteOnWedgedTransport(t *testing.T) {
	t.Run("a_mux_proxy_agent_lease_release_wedged", func(t *testing.T) {
		testW10bC10M3MuxProxyAgentWedged(t, false)
	})
	t.Run("b_mux_serveLocalAgentChannel_CloseWrite_wedged", func(t *testing.T) {
		testW10bC10M3MuxProxyAgentWedged(t, true)
	})
	t.Run("c_client_agent_lease_release_escalates_via_interrupt", testW10bC10M3ClientAgentReleaseWedged)
	t.Run("d_healthy_agent_lease_release_preserves_mux_server", testW10bC10M3HealthyAgentReleasePreservesMux)
}

func testW10bC10M3MuxProxyAgentWedged(t *testing.T, triggerLocalAgentClose bool) {
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

	label := "release"
	if triggerLocalAgentClose {
		label = "closewrite"
	}
	srv, rootConn, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w10b-m3-"+label+".sock", w10bMuxOpts{
		requestTimeout:    closeTimeout,
		allowAgentForward: true,
		agentSocket:       "/w10b-fake-agent.sock",
		dialAgent:         agentHarness.dialAgent,
	})

	rawProxy, serverCh, closeProxy := openRawMuxProxyAgentSession(t, ctx, sockPath)
	defer closeProxy()

	select {
	case <-agentLive:
	case <-time.After(3 * time.Second):
		t.Fatal("auth-agent@openssh.com channel did not become live")
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
		t.Fatalf("ActiveSessions before wedged agent %s = %d, want 1", label, got)
	}

	if !triggerLocalAgentClose {
		// Wedge writes precisely when releaseWithDeadline closes entry.agentConn
		// (AFTER pc.remoteCh has already closed cleanly), so ONLY
		// releaseWithDeadline's entry.sshCh.Close() / serveLocalAgentChannel hits
		// the write-wedged transport.
		var wedgeOnce sync.Once
		agentHarness.setOnConnClose(func() {
			wedgeOnce.Do(func() { rootConn.wedgeWrite.Store(true) })
		})
		drainDone := make(chan error, 1)
		go func() {
			drainDone <- srv.WaitForDrain(ctx, 0)
		}()
		w := newMuxWriter()
		w.buf = append(w.buf, msgChannelClose)
		w.WriteUint32(serverCh)
		_ = writeUnpaddedPacket(rawProxy, w.Bytes())

		waitWithin(t, "C10-M3 mux agent release: bounded escalation shutdown", 600*time.Millisecond, func() {
			<-srv.Wait()
		})
		select {
		case drainErr := <-drainDone:
			if drainErr != nil {
				t.Fatalf("C10-M3 mux agent release: WaitForDrain returned %v", drainErr)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatal("C10-M3 mux agent release: WaitForDrain remained wedged")
		}
		if !rootConn.closed.Load() {
			t.Fatal("C10-M3 mux agent release: expected escalation to abort write-wedged RootConn")
		}
		waitForCondition(t, time.Second, func() bool {
			return srv.ActiveSessions() == 0
		}, "C10-M3 mux agent release: ActiveSessions did not drain to 0")
		assertW7aMuxDrainedClosed(t, srv, sockPath)
		waitForGoroutinesAtMost(t, baseline+2, time.Second, "C10-M3 mux agent release goroutine check")
		return
	}

	assertW10bWedgedEscalationDrains(t, ctx, srv, rootConn, sockPath, func() {
		// Close the local fake agent while the proxy session is still open:
		// io.Copy(sshCh, agentConn) exits and hits lease.closeSSHChannelWriteBounded(sshCh).
		agentHarness.closeAllLocal()
	}, baseline, "C10-M3 mux agent "+label)
}

func testW10bC10M3ClientAgentReleaseWedged(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	holdAgent := make(chan struct{})
	defer close(holdAgent)
	holdSession := make(chan struct{})
	defer close(holdSession)

	agentHarness := newW10bFakeAgentHarness(t)
	sshSrv, agentLive := startW10bAgentSSHServer(t, ctx, holdAgent, holdSession)

	rawTCP, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", sshSrv.addr)
	if err != nil {
		t.Fatalf("dial w10b SSH server: %v", err)
	}
	rootConn := newModeSwitchConn(rawTCP)
	defer func() { _ = rootConn.Close() }()

	sshCfg := &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	cConn, chans, reqs, err := cryptoSSH.NewClientConn(rootConn, sshSrv.addr, sshCfg)
	if err != nil {
		t.Fatalf("ssh NewClientConn: %v", err)
	}
	sshCli := cryptoSSH.NewClient(cConn, chans, reqs)
	defer func() { _ = sshCli.Close() }()

	opts := &Options{}
	if err := opts.Set(OptionForwardAgent, "yes"); err != nil {
		t.Fatalf("Set(ForwardAgent): %v", err)
	}
	client := NewTestClient(ConnectionConfig{
		Address: sshSrv.host,
		Port:    sshSrv.port,
		User:    "fixture",
		Options: opts,
	})
	client.sshClient = sshCli
	client.rootConn = rootConn
	client.environment = Environment{
		AgentSocket: "/w10b-client-agent.sock",
		DialAgent:   agentHarness.dialAgent,
	}

	runtime.GC()
	baseline := runtime.NumGoroutine()

	lease := client.acquireSessionAgentLease(ctx)
	if lease == nil {
		t.Fatal("acquireSessionAgentLease returned nil")
	}
	sess, err := sshCli.NewSession()
	if err != nil {
		lease.Release()
		t.Fatalf("NewSession: %v", err)
	}
	defer func() { _ = sess.Close() }()

	ok, err := sess.SendRequest(agentForwardRequestType, true, nil)
	if err != nil || !ok {
		lease.Release()
		t.Fatalf("SendRequest(%s) = (%v, %v), want (true, nil)", agentForwardRequestType, ok, err)
	}
	select {
	case <-agentLive:
	case <-time.After(3 * time.Second):
		t.Fatal("client auth-agent@openssh.com channel did not become live")
	}

	// Wedge writes and verify lease.releaseWithDeadline escalates via client.Interrupt().
	rootConn.wedgeWrite.Store(true)
	waitWithin(t, "Client agentForwardLease.releaseWithDeadline escalation", 500*time.Millisecond, func() {
		lease.releaseWithDeadline(time.Now().Add(80 * time.Millisecond))
	})
	if !rootConn.closed.Load() {
		t.Fatal("expected Client agentForwardLease escalation to invoke Client.Interrupt and close rootConn")
	}
	_ = sess.Close()
	_ = sshCli.Close()
	waitForGoroutinesAtMost(t, baseline+2, time.Second, "C10-M3 Client agent release goroutine check")
}

func testW10bC10M3HealthyAgentReleasePreservesMux(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	holdAgent := make(chan struct{})
	closeHoldAgent := sync.OnceFunc(func() { close(holdAgent) })
	defer closeHoldAgent()
	holdSession := make(chan struct{})
	defer close(holdSession)

	agentHarness := newW10bFakeAgentHarness(t)
	sshSrv, agentLive := startW10bAgentSSHServer(t, ctx, holdAgent, holdSession)

	srv, _, sockPath := startW10bDirectMux(t, ctx, sshSrv, "w10b-m3-healthy.sock", w10bMuxOpts{
		requestTimeout:    80 * time.Millisecond,
		allowAgentForward: true,
		agentSocket:       "/w10b-healthy-agent.sock",
		dialAgent:         agentHarness.dialAgent,
	})

	_, _, closeProxy := openRawMuxProxyAgentSession(t, ctx, sockPath)
	select {
	case <-agentLive:
	case <-time.After(3 * time.Second):
		t.Fatal("healthy auth-agent@openssh.com channel did not become live")
	}
	// Release remote agent channel handler once local closes agentConn/sshCh.
	closeHoldAgent()
	closeProxy()

	waitForCondition(t, 2*time.Second, func() bool {
		return srv.ActiveSessions() == 0
	}, "healthy proxy session with agent lease did not drain to 0")

	muxCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient after healthy agent release: %v", err)
	}
	defer func() { _ = muxCli.Close() }()
	if _, err := muxCli.AliveCheck(ctx); err != nil {
		t.Fatalf("AliveCheck failed after healthy agent lease release: %v", err)
	}
}
