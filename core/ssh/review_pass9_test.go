package ssh

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

func TestPass9_H3_QuotedEnvAndForwardTokenization(t *testing.T) {
	envCases := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:  "single quoted value with spaces",
			input: `"FOO=hello world"`,
			want:  []string{"FOO=hello world"},
		},
		{
			name:  "multiple double-quoted key=value tokens",
			input: `"FOO=hello" "BAR=world baz"`,
			want:  []string{"FOO=hello", "BAR=world baz"},
		},
		{
			name:    "unterminated double quote rejected",
			input:   `"FOO=unterminated`,
			wantErr: true,
		},
	}
	for _, tc := range envCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := splitQuotedEnvTokens(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("splitQuotedEnvTokens(%q) err = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
			if !tc.wantErr && !slices.Equal(got, tc.want) {
				t.Errorf("splitQuotedEnvTokens(%q) = %#v, want %#v", tc.input, got, tc.want)
			}
		})
	}

	fwdGot, err := splitForwardFields(`"/tmp/sock dir/app.sock" 127.0.0.1:8080`)
	if err != nil {
		t.Fatalf("splitForwardFields: %v", err)
	}
	wantFwd := []string{"/tmp/sock dir/app.sock", "127.0.0.1:8080"}
	if !slices.Equal(fwdGot, wantFwd) {
		t.Errorf("splitForwardFields = %#v, want %#v", fwdGot, wantFwd)
	}
	if _, err := splitForwardFields(`"/tmp/unclosed 127.0.0.1:8080`); err == nil {
		t.Fatal("expected error for unclosed quote in splitForwardFields")
	}
}

func TestPass9_H4_KnownHostsZoneCasePreservationAndBracketWildcard(t *testing.T) {
	if got := lowercaseSSHHostPreservingZone("FE80::1%ETH0"); got != "fe80::1%ETH0" {
		t.Errorf("lowercaseSSHHostPreservingZone(FE80::1%%ETH0) = %q, want fe80::1%%ETH0", got)
	}
	if got := lowercaseSSHHostPreservingZone("APP.EXAMPLE.COM"); got != "app.example.com" {
		t.Errorf("lowercaseSSHHostPreservingZone(APP.EXAMPLE.COM) = %q, want app.example.com", got)
	}

	if got := khOpenSSHHostPort(khAddr{host: "FE80::1%ETH0", port: "22"}); got != "fe80::1%ETH0" {
		t.Errorf("khOpenSSHHostPort(22) = %q, want fe80::1%%ETH0", got)
	}
	if got := khOpenSSHHostPort(khAddr{host: "FE80::1%ETH0", port: "2222"}); got != "[fe80::1%ETH0]:2222" {
		t.Errorf("khOpenSSHHostPort(2222) = %q, want [fe80::1%%ETH0]:2222", got)
	}

	khPath := filepath.Join(t.TempDir(), "known_hosts")
	_, pubKey := generateTestEncryptedKey(t, "pass9-secret")
	if err := appendKnownHost(khPath, "FE80::1%ETH0", pubKey, true); err != nil {
		t.Fatalf("appendKnownHost: %v", err)
	}
	rawLine, err := os.ReadFile(khPath)
	if err != nil {
		t.Fatalf("ReadFile(known_hosts): %v", err)
	}
	db := newKnownHostsDB()
	if err := db.parseLine(bytes.TrimSpace(rawLine), khPath, 1); err != nil {
		t.Fatalf("db.parseLine(%q): %v", string(rawLine), err)
	}
	if len(db.lines) != 1 || db.lines[0].matcher == nil {
		t.Fatalf("expected 1 hashed entry, got %+v", db.lines)
	}
	if !db.lines[0].matcher.match(khAddr{host: "fe80::1%ETH0", port: ""}) {
		t.Error("hashed entry must match fe80::1 with empty port and ETH0 zone (default 22)")
	}
	if db.lines[0].matcher.match(khAddr{host: "fe80::1%eth0", port: "22"}) {
		t.Error("hashed entry must preserve case-sensitive IPv6 zone (ETH0 != eth0)")
	}

	m, err := newKHHostnameMatcher("[sub.example.com]*")
	if err != nil {
		t.Fatalf("newKHHostnameMatcher([sub.example.com]*): %v", err)
	}
	if !m.match(khAddr{host: "sub.example.com", port: "2222"}) {
		t.Error("expected [sub.example.com]* to match port 2222")
	}
	if _, err := newKHHostnameMatcher("[sub.example.com"); err == nil {
		t.Error("expected unclosed bracket pattern [sub.example.com to fail")
	}
	if _, err := newKHHostnameMatcher("[sub.example.com]"); err == nil {
		t.Error("expected bare [sub.example.com] without :port or trailing wildcard to fail")
	}
}

func TestPass9_H5_ForegroundReleaseRace_HandoffStopInvalidation_CancelHandoffShutdown(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	// 1. Concurrent -O stop + RemoveForegroundSession keeps active passenger session alive.
	for iter := range 4 {
		srv := newPass6SocketMuxServer(t, MuxServerOptions{
			PersistEnabled:        true,
			PersistIndefinite:     true,
			InitialActiveSessions: 1,
		})
		srv.ReleaseForegroundOnStop()
		if !srv.addActiveSession() {
			t.Fatalf("iter %d: failed to add passenger session", iter)
		}

		muxCli, err := DialMuxClient(ctx, srv.ControlPath())
		if err != nil {
			t.Fatalf("iter %d: DialMuxClient: %v", iter, err)
		}

		var wg sync.WaitGroup
		wg.Go(func() {
			_ = muxCli.StopListening(ctx)
		})
		wg.Go(func() {
			srv.RemoveForegroundSession()
		})
		wg.Wait()
		_ = muxCli.Close()

		if got := srv.ActiveSessions(); got != 1 {
			t.Fatalf("iter %d: ActiveSessions after concurrent stop+release = %d, want 1", iter, got)
		}
		select {
		case <-srv.Wait():
			t.Fatalf("iter %d: master shut down prematurely while passenger session still active", iter)
		default:
		}

		srv.removeActiveSession()
		select {
		case <-srv.Wait():
		case <-time.After(3 * time.Second):
			t.Fatalf("iter %d: master did not retire after passenger exited", iter)
		}
	}

	// 2. -O stop after PrepareHandoffWithSessions invalidates CommitHandoffReady.
	handoffSrv := newPass6SocketMuxServer(t, MuxServerOptions{
		PersistEnabled:        true,
		PersistIndefinite:     true,
		InitialActiveSessions: 1,
	})
	if !handoffSrv.PrepareHandoffWithSessions(1) {
		t.Fatal("PrepareHandoffWithSessions(1) failed")
	}
	if !handoffSrv.CommitHandoffReady() {
		t.Fatal("expected CommitHandoffReady=true before -O stop")
	}
	stopCli, err := DialMuxClient(ctx, handoffSrv.ControlPath())
	if err != nil {
		t.Fatalf("DialMuxClient(handoffSrv): %v", err)
	}
	if err := stopCli.StopListening(ctx); err != nil {
		_ = stopCli.Close()
		t.Fatalf("StopListening during reserved handoff: %v", err)
	}
	_ = stopCli.Close()
	if handoffSrv.CommitHandoffReady() {
		t.Fatal("expected CommitHandoffReady=false after -O stop invalidated reservation")
	}
	handoffSrv.CancelHandoff()

	// 3. CancelHandoff shuts down non-persistent master whose sessions dropped to 0.
	nonPersist := &MuxServer{
		persistEnabled:   false,
		hadActiveSession: true,
		idleNotify:       make(chan struct{}),
		shutdownChan:     make(chan struct{}),
	}
	nonPersist.activeSessions.Store(1)
	if !nonPersist.PrepareHandoffWithSessions(1) {
		t.Fatal("PrepareHandoffWithSessions(1) on non-persistent master failed")
	}
	nonPersist.removeActiveSession()
	select {
	case <-nonPersist.Wait():
		t.Fatal("non-persistent master closed before CancelHandoff while reserved")
	default:
	}
	nonPersist.CancelHandoff()
	select {
	case <-nonPersist.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("CancelHandoff leaked idle non-persistent master")
	}
}

func TestPass9_M2_StoppedListeningRejectsAddSessionAndSkipsAskConfirmation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	var confirms atomic.Int32
	srv := newPass6SocketMuxServer(t, MuxServerOptions{
		PersistEnabled:        true,
		PersistIndefinite:     true,
		InitialActiveSessions: 1,
		AskConfirmation:       true,
		ConfirmSession: func(string) bool {
			confirms.Add(1)
			return false
		},
	})

	conn, err := net.Dial("unix", srv.ControlPath())
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("unix socket unsupported: %v", err)
		}
		t.Fatalf("dial mux socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, nil)); err != nil {
		t.Fatalf("WriteMuxPacket(HELLO): %v", err)
	}
	if pktType, _, err := ReadMuxPacket(conn); err != nil || pktType != MUX_MSG_HELLO {
		t.Fatalf("ReadMuxPacket(HELLO) = (0x%x, %v)", pktType, err)
	}

	stopCli, err := DialMuxClient(ctx, srv.ControlPath())
	if err != nil {
		t.Fatalf("DialMuxClient(stop): %v", err)
	}
	if err := stopCli.StopListening(ctx); err != nil {
		_ = stopCli.Close()
		t.Fatalf("StopListening: %v", err)
	}
	_ = stopCli.Close()

	if srv.addActiveSession() {
		t.Fatal("addActiveSession must reject new sessions once stoppedListening is true")
	}

	if err := WriteMuxPacket(conn, MUX_C_PROXY, EncodeMuxRequestID(42)); err != nil {
		t.Fatalf("WriteMuxPacket(MUX_C_PROXY): %v", err)
	}
	pktType, _, err := ReadMuxPacket(conn)
	if err != nil {
		t.Fatalf("ReadMuxPacket(MUX_C_PROXY resp): %v", err)
	}
	if pktType == MUX_S_PROXY {
		t.Fatal("expected stoppedListening master to reject MUX_C_PROXY")
	}
	if confirms.Load() != 0 {
		t.Fatalf("ConfirmSession called %d times on stopped master, want 0", confirms.Load())
	}
}

func verifyMuxBadAllocPortRejected(t *testing.T, ctx context.Context, badPort uint32) {
	t.Helper()
	sockPath := filepath.Join(shortSocketDir(t), "m3-bad.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix socket listen skipped: %v", err)
	}
	var closeFwdSeen atomic.Bool
	srvDone := make(chan struct{})
	go func(alloc uint32) {
		defer close(srvDone)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _, _ = ReadMuxPacket(conn)
		_ = WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, nil))
		pktType, payload, err := ReadMuxPacket(conn)
		if err == nil && pktType == MUX_C_OPEN_FWD {
			req, _ := DecodeMuxFwdRequest(payload)
			_ = WriteMuxPacket(conn, MUX_S_REMOTE_PORT, EncodeMuxRemotePort(req.RequestID, alloc))
		}
		pktType, payload, err = ReadMuxPacket(conn)
		if err == nil && pktType == MUX_C_CLOSE_FWD {
			closeFwdSeen.Store(true)
			req, _ := DecodeMuxFwdRequest(payload)
			_ = WriteMuxPacket(conn, MUX_S_OK, EncodeMuxClientRequestID(req.RequestID))
		}
	}(badPort)

	cli := &Client{muxSocketPath: sockPath, muxExpectedUID: localPeerUID()}
	fwd, err := cli.RemoteForward(ctx, ":0", "127.0.0.1:8080")
	_ = ln.Close()
	<-srvDone
	if err == nil || fwd != nil {
		t.Fatalf("bad allocPort=%d: RemoteForward = (%v, %v), want error and nil", badPort, fwd, err)
	}
	if badPort > 0 && !closeFwdSeen.Load() {
		t.Errorf("bad allocPort=%d: expected RemoteForward to send MUX_C_CLOSE_FWD cleanup", badPort)
	}
}

func TestPass9_M3_RemoteForwardViaMuxBoundsExtensionsAndOptions(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	// 1. Out-of-range dynamic port (0 and >65535) fails and sends MUX_C_CLOSE_FWD.
	for _, badPort := range []uint32{0, 70000} {
		verifyMuxBadAllocPortRejected(t, ctx, badPort)
	}

	// 2. Addr() uses master GatewayPorts / DialNetwork extensions rather than passenger defaults.
	sockPath := filepath.Join(shortSocketDir(t), "m3-ext.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix socket listen skipped: %v", err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 2 {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if _, _, err := ReadMuxPacket(c); err != nil {
					return
				}
				exts := []MuxExtension{
					{Name: muxExtGatewayPorts, Value: "yes"},
					{Name: muxExtDialNetwork, Value: "tcp4"},
				}
				_ = WriteMuxPacket(c, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, exts))
				for {
					pktType, payload, err := ReadMuxPacket(c)
					if err != nil {
						return
					}
					switch pktType {
					case MUX_C_OPEN_FWD:
						req, _ := DecodeMuxFwdRequest(payload)
						_ = WriteMuxPacket(c, MUX_S_REMOTE_PORT, EncodeMuxRemotePort(req.RequestID, 43210))
					case MUX_C_CLOSE_FWD:
						req, _ := DecodeMuxFwdRequest(payload)
						_ = WriteMuxPacket(c, MUX_S_OK, EncodeMuxClientRequestID(req.RequestID))
						return
					}
				}
			}(conn)
		}
	}()

	passenger := &Client{muxSocketPath: sockPath, muxExpectedUID: localPeerUID()}
	// Unsupported WithForwardConnectionLimit must fail cleanly over mux.
	if _, err := passenger.RemoteForward(ctx, ":0", "127.0.0.1:8080", WithForwardConnectionLimit(4)); err == nil {
		t.Fatal("expected WithForwardConnectionLimit over mux to fail")
	}
	fwdCtx, fwdCancel := context.WithCancel(ctx)
	fwd, err := passenger.RemoteForward(fwdCtx, ":0", "127.0.0.1:8080")
	if err != nil {
		fwdCancel()
		t.Fatalf("RemoteForward with extensions: %v", err)
	}
	if got := fwd.Addr().String(); got != "0.0.0.0:43210" {
		t.Errorf("fwd.Addr().String() = %q, want 0.0.0.0:43210 (from master GatewayPorts=yes + DialNetwork=tcp4)", got)
	}
	fwdCancel()
	select {
	case <-fwd.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for fwd.Done() after cancel")
	}
	_ = ln.Close()
	<-done
}

type pass9PipeDialer struct {
	t          *testing.T
	dialedAddr string
}

func (d *pass9PipeDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *pass9PipeDialer) DialContext(_ context.Context, _ string, addr string) (net.Conn, error) {
	d.dialedAddr = addr
	cSide, sSide := newLoopbackConnPair(d.t)
	startInMemoryPipeSSHServer(d.t, sSide, "pw")
	return cSide, nil
}

type pass9CaptureVerifier struct {
	gotPort int
}

func (v *pass9CaptureVerifier) Verify(_ context.Context, req HostKeyRequest, _ cryptoSSH.PublicKey) error {
	v.gotPort = req.Port
	return nil
}

func TestPass9_L2_InitializeConnectionPortZeroNormalizedBeforeVerifier(t *testing.T) {
	dialer := &pass9PipeDialer{t: t}
	verifier := &pass9CaptureVerifier{}
	conn := NewConnector(&mockConfigStore{}, WithDialer(dialer), WithHostKeyVerifier(verifier))
	defer func() { _ = conn.CloseAll() }()

	client, err := conn.initializeConnection(t.Context(), connectionPlanNode{
		name: "n0",
		cfg: &ClientConfig{
			NodeID:   "n0",
			Address:  "127.0.0.1",
			Port:     0,
			User:     "test",
			AuthType: "password",
			Password: "pw",
		},
	}, dialer)
	if err != nil {
		t.Fatalf("initializeConnection(Port:0): %v", err)
	}
	_ = client.Close()

	if dialer.dialedAddr != "127.0.0.1:22" {
		t.Errorf("dialedAddr = %q, want 127.0.0.1:22", dialer.dialedAddr)
	}
	if verifier.gotPort != 22 {
		t.Errorf("HostKeyVerifier saw Port = %d, want 22", verifier.gotPort)
	}
}
