//go:build linux || darwin || freebsd

package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	cryptoSSH "golang.org/x/crypto/ssh"
)

// stallOnSessionReqServer accepts SSH connections and "session" channels, then
// invokes onReq before never replying to the first channel request (e.g.
// "pty-req" or "exec"), letting tests deterministically wedge the upstream
// transport mid-MUX_C_NEW_SESSION.
type stallOnSessionReqServer struct {
	addr     string
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func newStallOnSessionReqServer(t *testing.T, parentCtx context.Context, onReq func(reqType string)) *stallOnSessionReqServer {
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
		t.Fatalf("listen stall session server: %v", err)
	}
	ctx, cancel := context.WithCancel(parentCtx)
	s := &stallOnSessionReqServer{
		addr:     ln.Addr().String(),
		listener: ln,
		ctx:      ctx,
		cancel:   cancel,
	}
	s.wg.Go(func() {
		for {
			raw, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			s.wg.Go(func() {
				defer func() { _ = raw.Close() }()
				stopClose := context.AfterFunc(ctx, func() { _ = raw.Close() })
				defer stopClose()

				sConn, chans, reqs, hsErr := cryptoSSH.NewServerConn(raw, srvCfg)
				if hsErr != nil {
					return
				}
				defer func() { _ = sConn.Close() }()

				var connWG sync.WaitGroup
				connWG.Go(func() { cryptoSSH.DiscardRequests(reqs) })
				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(cryptoSSH.UnknownChannelType, "unsupported")
						continue
					}
					ch, chReqs, accErr := newCh.Accept()
					if accErr != nil {
						continue
					}
					connWG.Go(func() {
						defer func() { _ = ch.Close() }()
						if req, ok := <-chReqs; ok {
							if onReq != nil {
								onReq(req.Type)
							}
							// Deliberately hold without replying until ctx closes.
							<-ctx.Done()
						}
					})
				}
				connWG.Wait()
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

// TestW8b_C8_M2_PassengerRequestEscalatesToPhysicalRoot verifies C8-M2:
// when StartMuxServer is constructed with a raw *ssh.chanConn (or nil RootConn)
// plus PhysicalRootConn and the upstream bastion transport write-wedges before
// a MUX_C_NEW_SESSION request ("pty-req"/"exec") receives a reply,
// sendBoundedPassengerRequest times out, delegates interruption to
// s.closeTransportBounded() -> PhysicalRootConn.Close(), completes Shutdown()
// in <500ms, and leaks 0 goroutines.
func TestW8b_C8_M2_PassengerRequestEscalatesToPhysicalRoot(t *testing.T) {
	t.Run("raw_chan_conn_pty_req_with_physical_root", func(t *testing.T) {
		testW8bC8M2PassengerEscalation(t, false, true, "pty-req")
	})
	t.Run("nil_root_conn_exec_with_physical_root", func(t *testing.T) {
		testW8bC8M2PassengerEscalation(t, true, false, "exec")
	})
}

func testW8bC8M2PassengerEscalation(t *testing.T, nilRootConn, wantTTY bool, wantReqType string) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	bastionSrv := newKeepAliveBarrierServer(t, ctx)

	var (
		bastionPhys *modeSwitchConn
		wedgedOnce  sync.Once
		wedgedCh    = make(chan struct{})
		reqTypeSeen atomic.Value
	)
	targetSrv := newStallOnSessionReqServer(t, ctx, func(reqType string) {
		wedgedOnce.Do(func() {
			reqTypeSeen.Store(reqType)
			if bastionPhys != nil {
				bastionPhys.wedgeWrite.Store(true)
			}
			close(wedgedCh)
		})
	})

	// Establish physical bastion transport wrapped in modeSwitchConn.
	rawTCP, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", bastionSrv.addr)
	if err != nil {
		t.Fatalf("dial bastion TCP: %v", err)
	}
	bastionPhys = newModeSwitchConn(rawTCP)
	t.Cleanup(func() { _ = bastionPhys.Close() })

	sshCfg := &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	bConn, bChans, bReqs, err := cryptoSSH.NewClientConn(bastionPhys, bastionSrv.addr, sshCfg)
	if err != nil {
		t.Fatalf("bastion SSH handshake: %v", err)
	}
	bastionClient := cryptoSSH.NewClient(bConn, bChans, bReqs)
	t.Cleanup(func() { _ = bastionClient.Close() })

	// Open a raw *ssh.chanConn direct-tcpip hop through bastion to targetSrv.
	rawHopConn, err := bastionClient.Dial("tcp", targetSrv.addr)
	if err != nil {
		t.Fatalf("bastion direct-tcpip dial target: %v", err)
	}
	tConn, tChans, tReqs, err := cryptoSSH.NewClientConn(rawHopConn, targetSrv.addr, sshCfg)
	if err != nil {
		_ = rawHopConn.Close()
		t.Fatalf("target SSH handshake over raw chanConn: %v", err)
	}
	targetClient := cryptoSSH.NewClient(tConn, tChans, tReqs)

	baselineGoroutines := runtime.NumGoroutine()

	sockPath := filepath.Join(shortSocketDir(t), "c8m2-passenger.sock")
	optRootConn := rawHopConn
	if nilRootConn {
		optRootConn = nil
	}
	server, err := StartMuxServer(ctx, targetClient, MuxMasterOptions{
		Path:             sockPath,
		RootConn:         optRootConn,
		PhysicalRootConn: bastionPhys,
		Target: TargetContext{
			Control: &ControlConfig{
				Master:  ControlMasterYes,
				Path:    sockPath,
				Persist: "yes",
			},
		},
	})
	if err != nil {
		_ = targetClient.Close()
		t.Fatalf("StartMuxServer: %v", err)
	}
	server.requestTimeout = 50 * time.Millisecond
	t.Cleanup(func() {
		_ = bastionPhys.Close()
		_ = server.Shutdown()
	})

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial mux socket: %v", err)
	}
	defer func() { _ = clientConn.Close() }()
	if err := performClientMuxHandshake(clientConn); err != nil {
		t.Fatalf("mux handshake: %v", err)
	}

	reqPayload := EncodeMuxNewSession(MuxNewSessionRequest{
		RequestID: 42,
		WantTTY:   wantTTY,
		TermType:  "xterm",
		Command:   "echo w8b",
	})
	if err := WriteMuxPacket(clientConn, MUX_C_NEW_SESSION, reqPayload); err != nil {
		t.Fatalf("WriteMuxPacket(MUX_C_NEW_SESSION): %v", err)
	}
	sendSessionPipeFDs(t, clientConn)

	select {
	case <-wedgedCh:
	case <-time.After(3 * time.Second):
		t.Fatal("target server never received passenger session request")
	}
	if gotReq, _ := reqTypeSeen.Load().(string); gotReq != wantReqType {
		t.Fatalf("stalled passenger request type = %q, want %q", gotReq, wantReqType)
	}

	// Verify channel close hit the write-wedged bastion transport.
	select {
	case <-bastionPhys.writeBlocked:
	case <-time.After(2 * time.Second):
		t.Fatal("expected interrupted passenger channel close to hit write-wedged bastion")
	}

	// Once sessionShutdownTimeout elapses, sendBoundedPassengerRequest must
	// escalate via s.closeTransportBounded() -> bastionPhys.Close() and drive
	// s.Shutdown() to completion promptly (not hang forever on rawHopConn.Close).
	select {
	case <-server.Wait():
	case <-time.After(sessionShutdownTimeout + 600*time.Millisecond):
		t.Fatalf("MuxServer did not shut down after wedged %v request; escalation to PhysicalRootConn failed", reqTypeSeen.Load())
	}
	if !bastionPhys.closed.Load() {
		t.Fatal("sendBoundedPassengerRequest timeout did not escalate to PhysicalRootConn.Close()")
	}

	// Explicit Shutdown() must complete well within 500ms.
	waitWithin(t, "post-escalation server.Shutdown()", 500*time.Millisecond, func() {
		_ = server.Shutdown()
	})
	_ = clientConn.Close()
	_ = bastionClient.Close()

	// Verify 0 leaked goroutines from MuxServer / sendBoundedPassengerRequest /
	// rawHopConn / SSH client teardown.
	waitForGoroutinesAtMost(t, baselineGoroutines+1, 500*time.Millisecond, "C8-M2 passenger request escalation goroutine check")
}

// TestW8b_C8_L1_DialSSHMuxChannelAbandonedUsesBoundedClose verifies C8-L1 in
// MuxServer.dialSSHMuxChannel: when a late OpenChannel completes after timeout
// abandonment over a write-wedged transport where ch.Close() stalls,
// s.closeMuxChannelBounded(ch, nil) escalates via interruptTransportAndShutdown
// and tears down cleanly with 0 goroutine leaks.
func TestW8b_C8_L1_DialSSHMuxChannelAbandonedUsesBoundedClose(t *testing.T) {
	rootClosedCh := make(chan struct{})
	var rootCloseOnce sync.Once
	rawHop := newSyntheticRawChanConn(true, false)
	physRoot := &physicalRootHookConn{
		Conn: newSyntheticRawChanConn(false, false),
		onClose: func() {
			rawHop.forceAbort()
			rootCloseOnce.Do(func() { close(rootClosedCh) })
		},
	}

	sshConn := &lateStallingOpenSSHConn{
		openStarted:  make(chan struct{}),
		releaseCh:    make(chan struct{}),
		rootClosedCh: rootClosedCh,
		closeDone:    make(chan struct{}),
	}
	chans := make(chan cryptoSSH.NewChannel)
	close(chans)
	reqs := make(chan *cryptoSSH.Request)
	close(reqs)
	sshCli := cryptoSSH.NewClient(sshConn, chans, reqs)

	sockPath := filepath.Join(shortSocketDir(t), "l1-dial.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		PeerCheck:         PeerCheckDisabledForTesting,
		SSHClient:         sshCli,
		RootConn:          rawHop,
		PhysicalRootConn:  physRoot,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	srv.requestTimeout = 30 * time.Millisecond
	t.Cleanup(func() {
		rootCloseOnce.Do(func() { close(rootClosedCh) })
		_ = srv.Shutdown()
	})

	baseline := runtime.NumGoroutine()

	_, _, dialErr := srv.dialSSHMuxChannel(t.Context(), "tcp", "127.0.0.1:22")
	if !errors.Is(dialErr, context.DeadlineExceeded) {
		t.Fatalf("dialSSHMuxChannel err = %v, want context.DeadlineExceeded", dialErr)
	}

	// Release late OpenChannel so the abandoned goroutine hits
	// s.closeMuxChannelBounded(ch, nil) on a stalled channel close.
	close(sshConn.releaseCh)

	select {
	case <-srv.Wait():
	case <-time.After(sessionShutdownTimeout + 800*time.Millisecond):
		t.Fatal("abandoned dialSSHMuxChannel stalled without escalating via closeMuxChannelBounded")
	}
	if !physRoot.closed.Load() {
		t.Fatal("expected dialSSHMuxChannel closeMuxChannelBounded escalation to close PhysicalRootConn")
	}
	select {
	case <-sshConn.closeDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("stalled channel Close did not unblock after PhysicalRootConn abort")
	}
	waitForGoroutinesAtMost(t, baseline+1, 500*time.Millisecond, "C8-L1 dialSSHMuxChannel goroutine check")
}
