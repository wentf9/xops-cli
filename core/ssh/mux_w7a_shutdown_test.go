package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

type w7aEchoBackend struct {
	addr     string
	host     string
	port     uint32
	listener net.Listener
	mu       sync.Mutex
	conns    []net.Conn
	wg       sync.WaitGroup
}

func startW7aEchoBackend(t *testing.T) *w7aEchoBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo backend: %v", err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	b := &w7aEchoBackend{
		addr:     ln.Addr().String(),
		host:     tcpAddr.IP.String(),
		port:     uint32(tcpAddr.Port),
		listener: ln,
	}
	b.wg.Go(func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			b.mu.Lock()
			b.conns = append(b.conns, conn)
			b.mu.Unlock()
			b.wg.Go(func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 4096)
				for {
					n, rErr := conn.Read(buf)
					if n > 0 {
						if _, wErr := conn.Write(buf[:n]); wErr != nil {
							return
						}
					}
					if rErr != nil {
						return
					}
				}
			})
		}
	})
	t.Cleanup(func() {
		_ = b.listener.Close()
		b.mu.Lock()
		conns := append([]net.Conn(nil), b.conns...)
		b.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
		b.wg.Wait()
	})
	return b
}

// w7aForwardSSHServer is an in-process SSH server supporting password auth,
// direct-tcpip (-L / -D / ProxyJump), and real TCP-backed tcpip-forward +
// cancel-tcpip-forward + forwarded-tcpip (-R) with deterministic teardown.
type w7aForwardSSHServer struct {
	addr     string
	host     string
	port     int
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func startW7aForwardSSHServer(t *testing.T, parentCtx context.Context) *w7aForwardSSHServer {
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
		t.Fatalf("listen w7a SSH server: %v", err)
	}
	tcpAddr := ln.Addr().(*net.TCPAddr)
	ctx, cancel := context.WithCancel(parentCtx)
	s := &w7aForwardSSHServer{
		addr:     ln.Addr().String(),
		host:     tcpAddr.IP.String(),
		port:     tcpAddr.Port,
		listener: ln,
		ctx:      ctx,
		cancel:   cancel,
	}
	s.wg.Go(func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			s.wg.Go(func() {
				s.serveConn(conn, srvCfg)
			})
		}
	})
	t.Cleanup(func() {
		s.cancel()
		_ = s.listener.Close()
		s.wg.Wait()
	})
	return s
}

func (s *w7aForwardSSHServer) serveConn(raw net.Conn, cfg *cryptoSSH.ServerConfig) {
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

	var (
		connWG    sync.WaitGroup
		fwdMu     sync.Mutex
		remoteLns = make(map[string]net.Listener)
	)
	closeAllRemoteListeners := func() {
		fwdMu.Lock()
		lns := make([]net.Listener, 0, len(remoteLns))
		for k, l := range remoteLns {
			lns = append(lns, l)
			delete(remoteLns, k)
		}
		fwdMu.Unlock()
		for _, l := range lns {
			_ = l.Close()
		}
	}
	defer closeAllRemoteListeners()

	connWG.Go(func() {
		for req := range reqs {
			switch req.Type {
			case "tcpip-forward":
				s.handleTCPIPForward(connCtx, sConn, req, &fwdMu, remoteLns, &connWG)
			case "cancel-tcpip-forward":
				s.handleCancelTCPIPForward(req, &fwdMu, remoteLns)
			default:
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			}
		}
	})

	for newCh := range chans {
		switch newCh.ChannelType() {
		case "direct-tcpip":
			s.handleDirectTCPIP(connCtx, newCh, &connWG)
		default:
			_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported")
		}
	}
	connCancel()
	closeAllRemoteListeners()
	connWG.Wait()
}

func (s *w7aForwardSSHServer) handleTCPIPForward(
	connCtx context.Context,
	sConn *cryptoSSH.ServerConn,
	req *cryptoSSH.Request,
	fwdMu *sync.Mutex,
	remoteLns map[string]net.Listener,
	connWG *sync.WaitGroup,
) {
	var payload struct {
		BindAddr string
		BindPort uint32
	}
	if err := cryptoSSH.Unmarshal(req.Payload, &payload); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	bindHost := payload.BindAddr
	if bindHost == "" || bindHost == "localhost" {
		bindHost = "127.0.0.1"
	}
	listenAddr := net.JoinHostPort(bindHost, strconv.FormatUint(uint64(payload.BindPort), 10))
	ln, err := (&net.ListenConfig{}).Listen(connCtx, "tcp", listenAddr)
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	allocPort := uint32(ln.Addr().(*net.TCPAddr).Port)
	key := net.JoinHostPort(payload.BindAddr, strconv.FormatUint(uint64(allocPort), 10))
	fwdMu.Lock()
	remoteLns[key] = ln
	fwdMu.Unlock()

	if req.WantReply {
		var replyPayload []byte
		if payload.BindPort == 0 {
			replyPayload = cryptoSSH.Marshal(struct{ Port uint32 }{Port: allocPort})
		}
		_ = req.Reply(true, replyPayload)
	}

	connWG.Go(func() {
		defer func() { _ = ln.Close() }()
		for {
			rc, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			connWG.Go(func() {
				defer func() { _ = rc.Close() }()
				stopRC := context.AfterFunc(connCtx, func() { _ = rc.Close() })
				defer stopRC()

				originHost, originPortStr, _ := net.SplitHostPort(rc.RemoteAddr().String())
				originPort, _ := strconv.ParseUint(originPortStr, 10, 32)
				openPayload := cryptoSSH.Marshal(struct {
					Addr       string
					Port       uint32
					OriginAddr string
					OriginPort uint32
				}{
					Addr:       payload.BindAddr,
					Port:       allocPort,
					OriginAddr: originHost,
					OriginPort: uint32(originPort),
				})
				ch, chReqs, openErr := sConn.OpenChannel("forwarded-tcpip", openPayload)
				if openErr != nil {
					return
				}
				connWG.Go(func() { cryptoSSH.DiscardRequests(chReqs) })
				defer func() { _ = ch.Close() }()
				w7aPipeConnChannel(rc, ch)
			})
		}
	})
}

func (s *w7aForwardSSHServer) handleCancelTCPIPForward(
	req *cryptoSSH.Request,
	fwdMu *sync.Mutex,
	remoteLns map[string]net.Listener,
) {
	var payload struct {
		BindAddr string
		BindPort uint32
	}
	if err := cryptoSSH.Unmarshal(req.Payload, &payload); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	key := net.JoinHostPort(payload.BindAddr, strconv.FormatUint(uint64(payload.BindPort), 10))
	fwdMu.Lock()
	ln := remoteLns[key]
	delete(remoteLns, key)
	fwdMu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
}

func (s *w7aForwardSSHServer) handleDirectTCPIP(connCtx context.Context, newCh cryptoSSH.NewChannel, connWG *sync.WaitGroup) {
	var payload struct {
		Host       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}
	if err := cryptoSSH.Unmarshal(newCh.ExtraData(), &payload); err != nil {
		_ = newCh.Reject(cryptoSSH.Prohibited, "bad payload")
		return
	}
	targetAddr := net.JoinHostPort(payload.Host, strconv.Itoa(int(payload.Port)))
	upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(connCtx, "tcp", targetAddr)
	if err != nil {
		_ = newCh.Reject(cryptoSSH.ConnectionFailed, err.Error())
		return
	}
	ch, chReqs, err := newCh.Accept()
	if err != nil {
		_ = upstream.Close()
		return
	}
	connWG.Go(func() { cryptoSSH.DiscardRequests(chReqs) })
	connWG.Go(func() {
		defer func() {
			_ = upstream.Close()
			_ = ch.Close()
		}()
		stopUp := context.AfterFunc(connCtx, func() { _ = upstream.Close() })
		defer stopUp()
		w7aPipeConnChannel(upstream, ch)
	})
}

func w7aPipeConnChannel(tc net.Conn, ch cryptoSSH.Channel) {
	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(tc, ch)
		if tcp, ok := tc.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	})
	wg.Go(func() {
		_, _ = io.Copy(ch, tc)
		_ = ch.CloseWrite()
	})
	wg.Wait()
}

func dialW7aDirectMux(
	t *testing.T,
	ctx context.Context,
	sshSrv *w7aForwardSSHServer,
	sockName string,
) (*MuxServer, *modeSwitchConn, string) {
	t.Helper()
	rawTCP, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", sshSrv.addr)
	if err != nil {
		t.Fatalf("dial w7a SSH server: %v", err)
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
		Path:     sockPath,
		RootConn: rootConn,
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
		InitialActiveSessions: 1,
	})
	if err != nil {
		_ = rootConn.Close()
		_ = sshCli.Close()
		if errors.Is(err, ErrUnsupportedMuxPlatform) {
			t.Skipf("mux control socket unsupported on platform: %v", err)
		}
		t.Fatalf("StartMuxServer: %v", err)
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

func pickFreeLocalTCPPort(t *testing.T) uint32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pickFreeLocalTCPPort: %v", err)
	}
	port := uint32(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	return port
}

func assertW7aEchoRoundTrip(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write echo payload %q: %v", payload, err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo payload %q: %v", payload, err)
	}
	if string(buf) != payload {
		t.Fatalf("echo mismatch: got %q, want %q", string(buf), payload)
	}
	_ = conn.SetDeadline(time.Time{})
}

func openW7aVerifiedTCPStream(t *testing.T, addr, payload string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial forwarded TCP %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	assertW7aEchoRoundTrip(t, conn, payload)
	return conn
}

func openW7aVerifiedSocks5Stream(t *testing.T, socksAddr, destHost string, destPort uint32, payload string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5 %s: %v", socksAddr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	// SOCKS5 greeting: version 5, 1 method, no-auth (0x00)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	var greetResp [2]byte
	if _, err := io.ReadFull(conn, greetResp[:]); err != nil {
		t.Fatalf("read SOCKS5 greeting reply: %v", err)
	}
	if greetResp[0] != 0x05 || greetResp[1] != 0x00 {
		t.Fatalf("unexpected SOCKS5 greeting reply: %v", greetResp)
	}

	// SOCKS5 CONNECT to IPv4 destHost:destPort
	ip4 := net.ParseIP(destHost).To4()
	if ip4 == nil {
		t.Fatalf("destHost %q is not IPv4", destHost)
	}
	req := make([]byte, 10)
	req[0] = 0x05 // VER
	req[1] = 0x01 // CONNECT
	req[2] = 0x00 // RSV
	req[3] = 0x01 // IPv4
	copy(req[4:8], ip4)
	binary.BigEndian.PutUint16(req[8:10], uint16(destPort))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write SOCKS5 CONNECT: %v", err)
	}
	var connResp [10]byte
	if _, err := io.ReadFull(conn, connResp[:]); err != nil {
		t.Fatalf("read SOCKS5 CONNECT reply: %v", err)
	}
	if connResp[0] != 0x05 || connResp[1] != 0x00 {
		t.Fatalf("SOCKS5 CONNECT rejected: %v", connResp)
	}
	_ = conn.SetDeadline(time.Time{})

	assertW7aEchoRoundTrip(t, conn, payload)
	return conn
}

func assertW7aConnUnblocks(t *testing.T, conn net.Conn, timeout time.Duration, label string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	var b [1]byte
	_, err := conn.Read(b[:])
	if err == nil {
		t.Fatalf("%s: expected closed/EOF read after shutdown, got byte", label)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("%s: active forward stream stayed blocked past %v", label, timeout)
	}
}

func assertW7aMuxDrainedClosed(t *testing.T, srv *MuxServer, sockPath string) {
	t.Helper()
	if GetActiveMuxServer(sockPath) != nil {
		t.Fatalf("GetActiveMuxServer(%q) != nil after Shutdown", sockPath)
	}
	if _, statErr := os.Lstat(sockPath); !os.IsNotExist(statErr) {
		t.Fatalf("control socket %q still exists after Shutdown: statErr=%v", sockPath, statErr)
	}
	waitForCondition(t, time.Second, func() bool {
		srv.idleMu.Lock()
		phase := srv.phase
		fwdEntries := srv.forwardTable.entryCountLocked()
		fwdEndpoints := srv.forwardTable.endpointCountLocked()
		activeStreams := srv.activeForwardStreams
		inFlight := srv.openFwdsInFlight + srv.closeFwdsInFlight + srv.stopRepliesInFlight + srv.sessionOpensInFlight
		srv.idleMu.Unlock()

		srv.streamsMu.Lock()
		closed := srv.streamsClosed
		localCount := len(srv.liveLocalStreams)
		remoteCount := len(srv.liveRemoteStreams)
		srv.streamsMu.Unlock()

		return phase == muxPhaseClosed &&
			fwdEntries == 0 &&
			fwdEndpoints == 0 &&
			activeStreams == 0 &&
			inFlight == 0 &&
			closed &&
			localCount == 0 &&
			remoteCount == 0
	}, "MuxServer state/forward/stream counters did not drain cleanly after Shutdown")
}

// TestW7a_DirectMuxShutdown_WriteWedgedActiveForwards verifies C7-H1 on a direct
// MuxServer with active -L, -D, and -R forward streams over a write-wedged TCP
// RootConn: both srv.Shutdown() and -O exit complete in <500ms, srv.Wait()
// unblocks, all forward streams terminate promptly, and zero goroutines leak.
// It also checks healthy -O cancel and healthy Shutdown control behavior.
func TestW7a_DirectMuxShutdown_WriteWedgedActiveForwards(t *testing.T) {
	t.Run("shutdown_with_active_L_D_R", func(t *testing.T) {
		testW7aDirectWedgedForwards(t, false)
	})
	t.Run("terminate_O_exit_with_active_L_D_R", func(t *testing.T) {
		testW7aDirectWedgedForwards(t, true)
	})
	t.Run("healthy_cancel_and_shutdown_control", testW7aHealthyCancelAndShutdownControl)
}

func testW7aDirectWedgedForwards(t *testing.T, viaTerminate bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	echoBackend := startW7aEchoBackend(t)
	sshSrv := startW7aForwardSSHServer(t, ctx)

	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()

	srv, rootConn, sockPath := dialW7aDirectMux(t, ctx, sshSrv, "w7a-dir.sock")

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
		ConnectHost: echoBackend.host,
		ConnectPort: echoBackend.port,
	}); err != nil {
		t.Fatalf("OpenForward(-L): %v", err)
	}

	dynPort := pickFreeLocalTCPPort(t)
	if _, err := muxCli.OpenForward(ctx, ForwardRequest{
		Type:       ForwardDynamic,
		ListenHost: "127.0.0.1",
		ListenPort: dynPort,
	}); err != nil {
		t.Fatalf("OpenForward(-D): %v", err)
	}

	remotePort, err := muxCli.OpenForward(ctx, ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: echoBackend.host,
		ConnectPort: echoBackend.port,
	})
	if err != nil || remotePort == 0 {
		t.Fatalf("OpenForward(-R): port=%d err=%v", remotePort, err)
	}

	// Open and data-verify all three forward streams (-L, -D, -R) and keep them live.
	localStream := openW7aVerifiedTCPStream(t, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(localPort), 10)), "w7a-L\n")
	dynStream := openW7aVerifiedSocks5Stream(t, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(dynPort), 10)), echoBackend.host, echoBackend.port, "w7a-D\n")
	remoteStream := openW7aVerifiedTCPStream(t, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(remotePort), 10)), "w7a-R\n")

	waitForCondition(t, time.Second, func() bool {
		srv.streamsMu.Lock()
		nLocal := len(srv.liveLocalStreams)
		nRemote := len(srv.liveRemoteStreams)
		srv.streamsMu.Unlock()
		return nLocal >= 3 && nRemote >= 3
	}, "expected liveLocalStreams and liveRemoteStreams to track all 3 forward streams")

	// Wedge TCP writes on the master's direct SSH transport.
	rootConn.wedgeWrite.Store(true)

	waitWithin(t, "direct MuxServer teardown with active -L/-D/-R over write-wedged RootConn", 500*time.Millisecond, func() {
		if viaTerminate {
			if termErr := muxCli.Terminate(ctx); termErr != nil {
				t.Errorf("MuxClient.Terminate(-O exit): %v", termErr)
			}
		} else {
			_ = srv.Shutdown()
		}
		<-srv.Wait()
	})

	if !rootConn.closed.Load() {
		t.Fatal("write-wedged direct RootConn was not closed by Shutdown")
	}
	assertW7aConnUnblocks(t, localStream, 300*time.Millisecond, "-L active stream")
	assertW7aConnUnblocks(t, dynStream, 300*time.Millisecond, "-D active stream")
	assertW7aConnUnblocks(t, remoteStream, 300*time.Millisecond, "-R active stream")
	_ = localStream.Close()
	_ = dynStream.Close()
	_ = remoteStream.Close()
	_ = muxCli.Close()

	assertW7aMuxDrainedClosed(t, srv, sockPath)
	waitForGoroutinesAtMost(t, baselineGoroutines+2, time.Second, "W7a direct wedged shutdown goroutine check")
}

func testW7aHealthyCancelAndShutdownControl(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	echoBackend := startW7aEchoBackend(t)
	sshSrv := startW7aForwardSSHServer(t, ctx)

	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()

	srv, _, sockPath := dialW7aDirectMux(t, ctx, sshSrv, "w7a-healthy.sock")
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
		ConnectHost: echoBackend.host,
		ConnectPort: echoBackend.port,
	}); err != nil {
		t.Fatalf("OpenForward(-L): %v", err)
	}
	remotePort, err := muxCli.OpenForward(ctx, ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: echoBackend.host,
		ConnectPort: echoBackend.port,
	})
	if err != nil || remotePort == 0 {
		t.Fatalf("OpenForward(-R): port=%d err=%v", remotePort, err)
	}

	localStream := openW7aVerifiedTCPStream(t, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(localPort), 10)), "healthy-L1\n")
	remoteStream := openW7aVerifiedTCPStream(t, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(remotePort), 10)), "healthy-R1\n")

	// Healthy single-forward -O cancel on -R closes only -R's listener without shutting down the master.
	if err := muxCli.CloseForward(ctx, ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  remotePort,
		ConnectHost: echoBackend.host,
		ConnectPort: echoBackend.port,
	}); err != nil {
		t.Fatalf("CloseForward(-R) on healthy master: %v", err)
	}
	if _, err := muxCli.AliveCheck(ctx); err != nil {
		t.Fatalf("AliveCheck after healthy -O cancel(-R): %v", err)
	}
	assertW7aEchoRoundTrip(t, localStream, "healthy-L2\n")
	assertW7aEchoRoundTrip(t, remoteStream, "healthy-R2\n")

	// Healthy -O exit cleanly shuts down active streams and master.
	waitWithin(t, "healthy MuxServer -O exit with active streams", 500*time.Millisecond, func() {
		if err := muxCli.Terminate(ctx); err != nil {
			t.Errorf("healthy Terminate: %v", err)
		}
		<-srv.Wait()
	})
	assertW7aConnUnblocks(t, localStream, 300*time.Millisecond, "healthy -L stream")
	assertW7aConnUnblocks(t, remoteStream, 300*time.Millisecond, "healthy -R stream")
	_ = localStream.Close()
	_ = remoteStream.Close()
	_ = muxCli.Close()

	assertW7aMuxDrainedClosed(t, srv, sockPath)
	waitForGoroutinesAtMost(t, baselineGoroutines+2, time.Second, "W7a healthy control goroutine check")
}

// TestW7a_ProxyJumpMuxShutdown_WriteWedgedBastionActiveForward verifies C7-H1
// on a 2-hop ProxyJump MuxServer (bastion -> target via Connector) with an
// active -L forward stream when bastion's TCP PhysicalRootConn is write-wedged:
// calling targetMaster.Shutdown() directly or via -O exit (non-CloseAll path)
// completes in <500ms with zero goroutine leaks.
func TestW7a_ProxyJumpMuxShutdown_WriteWedgedBastionActiveForward(t *testing.T) {
	t.Run("direct_target_master_shutdown_active_L", func(t *testing.T) {
		testW7aProxyJumpWedgedBastion(t, false)
	})
	t.Run("terminate_O_exit_target_master_active_L", func(t *testing.T) {
		testW7aProxyJumpWedgedBastion(t, true)
	})
}

func testW7aProxyJumpWedgedBastion(t *testing.T, viaTerminate bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	echoBackend := startW7aEchoBackend(t)
	bastionSrv := startW7aForwardSSHServer(t, ctx)
	targetSrv := startW7aForwardSSHServer(t, ctx)

	targetSock := filepath.Join(shortSocketDir(t), "w7a-pj-t.sock")
	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bastionSrv.host, Port: bastionSrv.port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: targetSrv.host, Port: targetSrv.port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
		ctrls: map[string]*ControlConfig{
			"target": {Master: ControlMasterAuto, Path: targetSock, Persist: "yes"},
		},
	}

	runtime.GC()
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
	var targetMaster *MuxServer
	waitForCondition(t, 2*time.Second, func() bool {
		targetMaster = GetActiveMuxServer(targetSock)
		return targetMaster != nil
	}, "target ProxyJump control master did not start")

	muxCli, err := DialMuxClient(ctx, targetSock)
	if err != nil {
		t.Fatalf("DialMuxClient(targetSock): %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	localPort := pickFreeLocalTCPPort(t)
	if _, err := muxCli.OpenForward(ctx, ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  "127.0.0.1",
		ListenPort:  localPort,
		ConnectHost: echoBackend.host,
		ConnectPort: echoBackend.port,
	}); err != nil {
		t.Fatalf("OpenForward(-L) on ProxyJump target master: %v", err)
	}

	localStream := openW7aVerifiedTCPStream(t, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(localPort), 10)), "w7a-pj-L\n")

	waitForCondition(t, time.Second, func() bool {
		targetMaster.streamsMu.Lock()
		nRemote := len(targetMaster.liveRemoteStreams)
		targetMaster.streamsMu.Unlock()
		return nRemote >= 1
	}, "expected targetMaster.liveRemoteStreams to track active -L channel")

	bastionConn := dialer.connAt(0)
	if bastionConn == nil {
		t.Fatal("expected dialer to record bastion PhysicalRootConn")
	}
	bastionConn.wedgeWrite.Store(true)

	// Trigger targetMaster teardown DIRECTLY (non-CloseAll path).
	waitWithin(t, "ProxyJump targetMaster teardown with active -L over write-wedged bastion", 500*time.Millisecond, func() {
		if viaTerminate {
			if termErr := muxCli.Terminate(ctx); termErr != nil {
				t.Errorf("targetMaster Terminate(-O exit): %v", termErr)
			}
		} else {
			_ = targetMaster.Shutdown()
		}
		<-targetMaster.Wait()
	})

	if !bastionConn.closed.Load() {
		t.Fatal("targetMaster teardown did not abort write-wedged bastion PhysicalRootConn")
	}
	assertW7aConnUnblocks(t, localStream, 300*time.Millisecond, "ProxyJump -L active stream")
	_ = localStream.Close()
	_ = muxCli.Close()

	assertW7aMuxDrainedClosed(t, targetMaster, targetSock)
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("pool CheckInvariants after ProxyJump targetMaster shutdown: %v", err)
	}
	_ = connector.CloseAll()
	waitForGoroutinesAtMost(t, baselineGoroutines+2, time.Second, "W7a ProxyJump wedged shutdown goroutine check")
}

// TestW7a_RemoteForwardTimeoutRecovery_WriteWedgedWithActiveLocalStream verifies
// C7-H1 for -R listenRemoteMux and closeMuxForwardEntryWithShadows timeout
// escalation while a -L forward stream is active on a write-wedged MuxServer:
// timeout escalation calls Shutdown(), unblocks <-done and the control RPC
// handler in <500ms, drains all tables/barriers, and leaks zero goroutines.
func TestW7a_RemoteForwardTimeoutRecovery_WriteWedgedWithActiveLocalStream(t *testing.T) {
	t.Run("listenRemoteMux_timeout_with_active_L", testW7aListenRemoteMuxTimeoutWithActiveL)
	t.Run("closeMuxForwardEntryWithShadows_timeout_with_active_L", testW7aCloseRemoteMuxTimeoutWithActiveL)
	t.Run("proxyJump_closeMuxForwardEntryWithShadows_timeout_with_active_L", testW7aProxyJumpCloseRemoteMuxTimeoutWithActiveL)
}

func testW7aListenRemoteMuxTimeoutWithActiveL(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	echoBackend := startW7aEchoBackend(t)
	sshSrv := startW7aForwardSSHServer(t, ctx)

	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()

	srv, rootConn, sockPath := dialW7aDirectMux(t, ctx, sshSrv, "w7a-rm-open.sock")
	srv.requestTimeout = 80 * time.Millisecond

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
		ConnectHost: echoBackend.host,
		ConnectPort: echoBackend.port,
	}); err != nil {
		t.Fatalf("OpenForward(-L): %v", err)
	}
	localStream := openW7aVerifiedTCPStream(t, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(localPort), 10)), "w7a-rm-L\n")

	rootConn.wedgeWrite.Store(true)

	var openErr error
	waitWithin(t, "listenRemoteMux timeout recovery with active -L over write-wedged transport", 500*time.Millisecond, func() {
		_, openErr = muxCli.OpenForward(ctx, ForwardRequest{
			Type:        ForwardRemote,
			ListenHost:  "127.0.0.1",
			ListenPort:  0,
			ConnectHost: echoBackend.host,
			ConnectPort: echoBackend.port,
		})
		<-srv.Wait()
	})
	if openErr == nil {
		t.Fatal("expected OpenForward(-R) over write-wedged transport to fail")
	}
	if !rootConn.closed.Load() {
		t.Fatal("listenRemoteMux timeout escalation did not abort write-wedged RootConn")
	}
	assertW7aConnUnblocks(t, localStream, 300*time.Millisecond, "-L stream after listenRemoteMux timeout")
	_ = localStream.Close()
	_ = muxCli.Close()

	assertW7aMuxDrainedClosed(t, srv, sockPath)
	waitForGoroutinesAtMost(t, baselineGoroutines+2, time.Second, "W7a listenRemoteMux timeout goroutine check")
}

func testW7aCloseRemoteMuxTimeoutWithActiveL(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	echoBackend := startW7aEchoBackend(t)
	sshSrv := startW7aForwardSSHServer(t, ctx)

	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()

	srv, rootConn, sockPath := dialW7aDirectMux(t, ctx, sshSrv, "w7a-rm-close.sock")
	srv.requestTimeout = 80 * time.Millisecond

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
		ConnectHost: echoBackend.host,
		ConnectPort: echoBackend.port,
	}); err != nil {
		t.Fatalf("OpenForward(-L): %v", err)
	}
	remotePort, err := muxCli.OpenForward(ctx, ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: echoBackend.host,
		ConnectPort: echoBackend.port,
	})
	if err != nil || remotePort == 0 {
		t.Fatalf("OpenForward(-R): port=%d err=%v", remotePort, err)
	}

	localStream := openW7aVerifiedTCPStream(t, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(localPort), 10)), "w7a-rc-L\n")
	remoteStream := openW7aVerifiedTCPStream(t, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(remotePort), 10)), "w7a-rc-R\n")

	rootConn.wedgeWrite.Store(true)

	waitWithin(t, "closeMuxForwardEntryWithShadows timeout recovery with active -L/-R over write-wedged transport", 500*time.Millisecond, func() {
		_ = muxCli.CloseForward(ctx, ForwardRequest{
			Type:        ForwardRemote,
			ListenHost:  "127.0.0.1",
			ListenPort:  remotePort,
			ConnectHost: echoBackend.host,
			ConnectPort: echoBackend.port,
		})
		<-srv.Wait()
	})
	if !rootConn.closed.Load() {
		t.Fatal("closeMuxForwardEntryWithShadows timeout escalation did not abort write-wedged RootConn")
	}
	assertW7aConnUnblocks(t, localStream, 300*time.Millisecond, "-L stream after closeMuxForwardEntryWithShadows timeout")
	assertW7aConnUnblocks(t, remoteStream, 300*time.Millisecond, "-R stream after closeMuxForwardEntryWithShadows timeout")
	_ = localStream.Close()
	_ = remoteStream.Close()
	_ = muxCli.Close()

	assertW7aMuxDrainedClosed(t, srv, sockPath)
	waitForGoroutinesAtMost(t, baselineGoroutines+2, time.Second, "W7a closeMuxForwardEntryWithShadows timeout goroutine check")
}

func testW7aProxyJumpCloseRemoteMuxTimeoutWithActiveL(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	echoBackend := startW7aEchoBackend(t)
	bastionSrv := startW7aForwardSSHServer(t, ctx)
	targetSrv := startW7aForwardSSHServer(t, ctx)

	targetSock := filepath.Join(shortSocketDir(t), "w7a-pj-rc.sock")
	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID: "bastion", Address: bastionSrv.host, Port: bastionSrv.port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: targetSrv.host, Port: targetSrv.port,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
		ctrls: map[string]*ControlConfig{
			"target": {Master: ControlMasterAuto, Path: targetSock, Persist: "yes"},
		},
	}

	runtime.GC()
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
	var targetMaster *MuxServer
	waitForCondition(t, 2*time.Second, func() bool {
		targetMaster = GetActiveMuxServer(targetSock)
		return targetMaster != nil
	}, "target ProxyJump control master did not start")
	targetMaster.requestTimeout = 60 * time.Millisecond

	muxCli, err := DialMuxClient(ctx, targetSock)
	if err != nil {
		t.Fatalf("DialMuxClient: %v", err)
	}
	defer func() { _ = muxCli.Close() }()

	localPort := pickFreeLocalTCPPort(t)
	if _, err := muxCli.OpenForward(ctx, ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  "127.0.0.1",
		ListenPort:  localPort,
		ConnectHost: echoBackend.host,
		ConnectPort: echoBackend.port,
	}); err != nil {
		t.Fatalf("OpenForward(-L): %v", err)
	}
	remotePort, err := muxCli.OpenForward(ctx, ForwardRequest{
		Type:        ForwardRemote,
		ListenHost:  "127.0.0.1",
		ListenPort:  0,
		ConnectHost: echoBackend.host,
		ConnectPort: echoBackend.port,
	})
	if err != nil || remotePort == 0 {
		t.Fatalf("OpenForward(-R): port=%d err=%v", remotePort, err)
	}

	localStream := openW7aVerifiedTCPStream(t, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(localPort), 10)), "w7a-pj-rc-L\n")

	bastionConn := dialer.connAt(0)
	if bastionConn == nil {
		t.Fatal("expected dialer to record bastion PhysicalRootConn")
	}
	bastionConn.wedgeWrite.Store(true)

	waitWithin(t, "ProxyJump closeMuxForwardEntryWithShadows timeout recovery with active -L", 500*time.Millisecond, func() {
		_ = muxCli.CloseForward(ctx, ForwardRequest{
			Type:        ForwardRemote,
			ListenHost:  "127.0.0.1",
			ListenPort:  remotePort,
			ConnectHost: echoBackend.host,
			ConnectPort: echoBackend.port,
		})
		<-targetMaster.Wait()
	})

	if !bastionConn.closed.Load() {
		t.Fatal("ProxyJump -R cancel timeout escalation did not abort write-wedged bastion PhysicalRootConn")
	}
	assertW7aConnUnblocks(t, localStream, 300*time.Millisecond, "ProxyJump -L stream after -R cancel timeout")
	_ = localStream.Close()
	_ = muxCli.Close()

	assertW7aMuxDrainedClosed(t, targetMaster, targetSock)
	if err := connector.pool.CheckInvariants(false); err != nil {
		t.Fatalf("pool CheckInvariants after ProxyJump -R cancel timeout: %v", err)
	}
	_ = connector.CloseAll()
	waitForGoroutinesAtMost(t, baselineGoroutines+2, time.Second, "W7a ProxyJump -R cancel timeout goroutine check")
}
