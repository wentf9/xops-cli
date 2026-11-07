package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
)

// muxFixture is one in-memory SSH server plus a master transport attached to a
// proxy master listening on a temporary control socket.
type muxFixture struct {
	Server      *sshfixture.Server
	Master      *MuxServer
	SocketPath  string
	Host        string
	Port        int
	Target      TargetContext
	RawClient   *cryptoSSH.Client
	FixtureHost string
}

func startMuxFixture(t *testing.T, ctx context.Context, options sshfixture.Options) *muxFixture {
	t.Helper()

	fixture, err := sshfixture.NewWithOptions(ctx, options)
	if err != nil {
		t.Fatalf("sshfixture.NewWithOptions failed: %v", err)
	}

	host, portText, err := net.SplitHostPort(fixture.Address)
	if err != nil {
		_ = fixture.Close()
		t.Fatalf("SplitHostPort failed: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		_ = fixture.Close()
		t.Fatalf("Atoi failed: %v", err)
	}

	rawClient, err := cryptoSSH.Dial("tcp", fixture.Address, &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fixture.HostKey),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		_ = fixture.Close()
		t.Fatalf("cryptoSSH.Dial master failed: %v", err)
	}

	socketPath := filepath.Join(t.TempDir(), "master.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       socketPath,
		SSHClient:         rawClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		_ = rawClient.Close()
		_ = fixture.Close()
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	go func() { _ = server.Serve() }()

	muxFixture := &muxFixture{
		Server:      fixture,
		Master:      server,
		SocketPath:  socketPath,
		Host:        host,
		Port:        port,
		Target:      TargetContext{Host: host, Port: port, User: "fixture"},
		RawClient:   rawClient,
		FixtureHost: host,
	}
	t.Cleanup(func() {
		_ = server.Shutdown()
		_ = rawClient.Close()
		_ = fixture.Close()
	})
	return muxFixture
}

// TestMuxProxy_ForwardsStderr verifies that remote stderr reaches the proxy
// client. Dropping SSH_MSG_CHANNEL_EXTENDED_DATA silently loses all remote
// diagnostics produced through a shared connection.
func TestMuxProxy_ForwardsStderr(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fixture := startMuxFixture(t, ctx, sshfixture.Options{
		ExecHandler: func(_ string, ch cryptoSSH.Channel) {
			_, _ = io.WriteString(ch, "stdout-line\n")
			_, _ = io.WriteString(ch.Stderr(), "stderr-line\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{3}))
		},
	})

	client, proxyConn, err := DialControlProxy(ctx, fixture.SocketPath, fixture.Target)
	if err != nil {
		t.Fatalf("DialControlProxy failed: %v", err)
	}
	defer func() {
		_ = client.Close()
		_ = proxyConn.Close()
	}()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer func() { _ = session.Close() }()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run("emit-both")
	var exitErr *cryptoSSH.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 3 {
		t.Fatalf("expected exit status 3, got %v", err)
	}
	if got := stdout.String(); got != "stdout-line\n" {
		t.Fatalf("unexpected stdout %q", got)
	}
	if got := stderr.String(); got != "stderr-line\n" {
		t.Fatalf("expected stderr line through proxy, got %q", got)
	}
}

// TestMuxProxy_LargeStderrDoesNotDeadlock verifies that stderr larger than the
// SSH channel window keeps flowing. An unconsumed stderr stream blocks the
// remote process once its window is exhausted.
func TestMuxProxy_LargeStderrDoesNotDeadlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const payloadSize = 512 * 1024
	payload := strings.Repeat("e", payloadSize)
	fixture := startMuxFixture(t, ctx, sshfixture.Options{
		ExecHandler: func(_ string, ch cryptoSSH.Channel) {
			_, _ = io.WriteString(ch.Stderr(), payload)
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})

	client, proxyConn, err := DialControlProxy(ctx, fixture.SocketPath, fixture.Target)
	if err != nil {
		t.Fatalf("DialControlProxy failed: %v", err)
	}
	defer func() {
		_ = client.Close()
		_ = proxyConn.Close()
	}()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer func() { _ = session.Close() }()

	var stdout bytes.Buffer
	session.Stdout = &stdout

	var stderrMu sync.Mutex
	stderrBytes := 0
	session.Stderr = writerFunc(func(p []byte) (int, error) {
		stderrMu.Lock()
		defer stderrMu.Unlock()
		stderrBytes += len(p)
		return len(p), nil
	})

	runDone := make(chan error, 1)
	go func() { runDone <- session.Run("flood-stderr") }()

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("session.Run failed: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("proxy session deadlocked while forwarding large stderr")
	}

	stderrMu.Lock()
	got := stderrBytes
	stderrMu.Unlock()
	if got != payloadSize {
		t.Fatalf("expected %d stderr bytes through proxy, got %d", payloadSize, got)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// TestMuxProxy_ConcurrentExecKeepsRequestRepliesOrdered reproduces the class of
// failure where a channel close is written while a want-reply request (exec) is
// still in flight, making the proxy client fail with io.EOF.
func TestMuxProxy_ConcurrentExecKeepsRequestRepliesOrdered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fixture := startMuxFixture(t, ctx, sshfixture.Options{
		ExecHandler: func(_ string, ch cryptoSSH.Channel) {
			_, _ = io.WriteString(ch, "test_output\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})

	const workers, iterations = 5, 5
	var (
		waitGroup sync.WaitGroup
		failMu    sync.Mutex
		failures  []string
	)
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func(workerID int) {
			defer waitGroup.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				client, proxyConn, err := DialControlProxy(ctx, fixture.SocketPath, fixture.Target)
				if err != nil {
					failMu.Lock()
					failures = append(failures, err.Error())
					failMu.Unlock()
					return
				}
				session, err := client.NewSession()
				if err != nil {
					_ = client.Close()
					_ = proxyConn.Close()
					failMu.Lock()
					failures = append(failures, err.Error())
					failMu.Unlock()
					return
				}
				out, err := session.Output("echo ordered")
				_ = session.Close()
				_ = client.Close()
				_ = proxyConn.Close()
				if err != nil || string(out) != "test_output\n" {
					failMu.Lock()
					failures = append(failures, "worker "+strconv.Itoa(workerID)+" iteration "+strconv.Itoa(iteration))
					failMu.Unlock()
				}
			}
		}(worker)
	}
	waitGroup.Wait()

	if len(failures) > 0 {
		t.Fatalf("proxy exec failures: %d (%s)", len(failures), strings.Join(failures, "; "))
	}
}

// TestMuxProxy_ForwardsGlobalRequests verifies that proxy clients can use
// global requests. Remote forwarding (tcpip-forward) fails when the master
// rejects every global request locally.
func TestMuxProxy_ForwardsGlobalRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fixture := startMuxFixture(t, ctx, sshfixture.Options{})

	client, proxyConn, err := DialControlProxy(ctx, fixture.SocketPath, fixture.Target)
	if err != nil {
		t.Fatalf("DialControlProxy failed: %v", err)
	}
	defer func() {
		_ = client.Close()
		_ = proxyConn.Close()
	}()

	// A keepalive-style want-reply global request must be answered by the remote
	// server rather than rejected locally by the master.
	ok, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
	if err != nil {
		t.Fatalf("global request through proxy failed: %v", err)
	}
	if !ok {
		t.Fatal("expected remote server to accept the keepalive global request")
	}
}

// TestMuxServer_DynamicForwardSOCKS5 verifies that -O forward -D terminates
// SOCKS5 CONNECT requests on the master's transport instead of closing them.
func TestMuxServer_DynamicForwardSOCKS5(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo target failed: %v", err)
	}
	defer func() { _ = echoListener.Close() }()
	go func() {
		for {
			conn, acceptErr := echoListener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	fixture := startMuxFixture(t, ctx, sshfixture.Options{})

	dynamicListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen dynamic port failed: %v", err)
	}
	defer func() { _ = dynamicListener.Close() }()
	go fixture.Master.serveDynamicForward(dynamicListener)

	socksAddr := dynamicListener.Addr().String()
	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial SOCKS5 listener failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	performSocks5HandshakeAndConnect(t, conn, echoListener.Addr().String())

	payload := []byte("proxy-dynamic-forward")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write through SOCKS5 tunnel failed: %v", err)
	}
	got := make([]byte, len(payload))
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline failed: %v", err)
	}
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read through SOCKS5 tunnel failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("unexpected echo payload %q", got)
	}
}

// TestMuxServer_ShutdownKeepsReplacementSocket verifies that a draining master
// does not unlink a control socket that a newer master already owns.
func TestMuxServer_ShutdownKeepsReplacementSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hard-link socket replacement is not used on Windows")
	}

	directory := t.TempDir()
	socketPath := filepath.Join(directory, "replace.sock")

	draining, err := NewMuxServer(MuxServerOptions{
		ControlPath:       socketPath,
		SSHClient:         newDummySSHClient(),
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	go func() { _ = draining.Serve() }()

	// The admin stops listening, which unlinks the path and lets a replacement
	// master take it over.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	control, err := DialMuxClient(ctx, socketPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	if err := control.StopListening(ctx); err != nil {
		_ = control.Close()
		t.Fatalf("StopListening failed: %v", err)
	}
	_ = control.Close()

	replacement, err := StartMuxServer(ctx, newDummySSHClient(), MuxMasterOptions{
		Path:   socketPath,
		Target: TargetContext{Control: &ControlConfig{Master: ControlMasterYes, Path: socketPath}},
	})
	if err != nil {
		t.Fatalf("replacement StartMuxServer failed: %v", err)
	}
	if got := GetActiveMuxServer(socketPath); got != replacement {
		t.Fatalf("replacement master was not registered, got %v", got)
	}
	defer func() { _ = replacement.Shutdown() }()

	if got := GetActiveMuxServer(socketPath); got != replacement {
		t.Fatalf("expected the replacement master to own the registry entry, got %v", got)
	}

	// Draining the old master must not remove the replacement socket or entry.
	if err := draining.Shutdown(); err != nil {
		t.Fatalf("draining Shutdown failed: %v", err)
	}
	if !socketPathExists(socketPath) {
		t.Fatal("draining master unlinked the replacement control socket")
	}
	if got := GetActiveMuxServer(socketPath); got != replacement {
		t.Fatalf("draining master removed the replacement registry entry, got %v", got)
	}

	control, err = DialMuxClient(ctx, socketPath)
	if err != nil {
		t.Fatalf("replacement master is unreachable after draining shutdown: %v", err)
	}
	if _, err := control.AliveCheck(ctx); err != nil {
		_ = control.Close()
		t.Fatalf("replacement master alive check failed: %v", err)
	}
	_ = control.Close()
}

// TestMuxProxy_RemoteChannelRequestDoesNotBlockForever verifies that a remote
// want-reply channel request which the proxy client never answers is released
// when the channel ends. A pending remote request that is neither relayed nor
// rejected keeps the server blocked after the client is gone.
func TestMuxProxy_RemoteChannelRequestDoesNotBlockForever(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	type requestOutcome struct {
		accepted bool
		err      error
	}
	outcome := make(chan requestOutcome, 1)

	fixture := startMuxFixture(t, ctx, sshfixture.Options{
		ExecHandler: func(_ string, ch cryptoSSH.Channel) {
			// Ask the client for a reply without blocking the handler, then finish
			// the session. The client (x/crypto Session) never answers, so only the
			// master's teardown path can release this request.
			go func() {
				accepted, err := ch.SendRequest("keepalive@openssh.com", true, nil)
				outcome <- requestOutcome{accepted: accepted, err: err}
			}()
			_, _ = io.WriteString(ch, "handler-finished\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})

	client, proxyConn, err := DialControlProxy(ctx, fixture.SocketPath, fixture.Target)
	if err != nil {
		t.Fatalf("DialControlProxy failed: %v", err)
	}
	defer func() {
		_ = client.Close()
		_ = proxyConn.Close()
	}()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	out, err := session.Output("leave-request-unanswered")
	_ = session.Close()
	if err != nil {
		t.Fatalf("session.Output failed: %v", err)
	}
	if string(out) != "handler-finished\n" {
		t.Fatalf("unexpected output %q", out)
	}

	select {
	case result := <-outcome:
		if result.err == nil && result.accepted {
			t.Fatalf("expected the unanswered request to be rejected, got accepted")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("remote channel request was never released after the channel ended")
	}
}

// TestMuxServer_ShutdownClosesForwardedStreams verifies that Shutdown releases
// accepted forwarding connections instead of leaving idle readers running.
func TestMuxServer_ShutdownClosesForwardedStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo target failed: %v", err)
	}
	defer func() { _ = echoListener.Close() }()
	go func() {
		for {
			conn, acceptErr := echoListener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	fixture := startMuxFixture(t, ctx, sshfixture.Options{})

	// Start a local forwarding listener owned by the master, registered exactly as
	// handleOpenFwd does so Shutdown can close it.
	forwardListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen forward port failed: %v", err)
	}
	t.Cleanup(func() { _ = forwardListener.Close() })
	fixture.Master.forwards.Store("mux-test-local-forward", forwardListener)
	go fixture.Master.serveLocalForward(forwardListener, echoListener.Addr().String())

	clientConn, err := net.Dial("tcp", forwardListener.Addr().String())
	if err != nil {
		t.Fatalf("dial forwarding listener failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	payload := []byte("forwarded-before-shutdown")
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatalf("write through forward failed: %v", err)
	}
	echoed := make([]byte, len(payload))
	if err := clientConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set read deadline failed: %v", err)
	}
	if _, err := io.ReadFull(clientConn, echoed); err != nil {
		t.Fatalf("read through forward failed: %v", err)
	}

	// An idle forwarded stream must be released by Shutdown.
	if err := fixture.Master.Shutdown(); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set read deadline failed: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := clientConn.Read(buf); err == nil {
		t.Fatal("expected the forwarded stream to be closed by Shutdown")
	}

	if err := fixture.Master.Shutdown(); err != nil {
		t.Fatalf("second Shutdown failed: %v", err)
	}
}

type failingOpenChannelSSHConn struct {
	*dummySSHConn
	openErr error
}

func (f *failingOpenChannelSSHConn) OpenChannel(string, []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	return nil, nil, f.openErr
}

// TestMuxProxy_OpenChannelFailurePreservesReasonAndHintsMaxSessions verifies that
// openRemoteChannel unwraps *cryptoSSH.OpenChannelError instead of double-wrapping
// "ssh: rejected: connect failed (...)" and appends a MaxSessions hint on session
// "open failed".
func TestMuxProxy_OpenChannelFailurePreservesReasonAndHintsMaxSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	conn := &failingOpenChannelSSHConn{
		dummySSHConn: &dummySSHConn{chans: chans, reqs: reqs},
		openErr: &cryptoSSH.OpenChannelError{
			Reason:  cryptoSSH.ConnectionFailed,
			Message: "open failed",
		},
	}
	rawClient := cryptoSSH.NewClient(conn, chans, reqs)
	defer func() { _ = rawClient.Close() }()

	sockPath := filepath.Join(t.TempDir(), "maxsessions.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         rawClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	client, proxyConn, err := DialControlProxy(ctx, sockPath, TargetContext{Host: "127.0.0.1", Port: 22, User: "test"})
	if err != nil {
		t.Fatalf("DialControlProxy failed: %v", err)
	}
	defer func() {
		_ = client.Close()
		_ = proxyConn.Close()
	}()

	_, err = client.NewSession()
	if err == nil {
		t.Fatal("expected NewSession error, got nil")
	}
	errMsg := err.Error()
	if strings.Count(errMsg, "ssh: rejected:") > 1 {
		t.Fatalf("expected single ssh: rejected prefix, got double-wrapped error: %q", errMsg)
	}
	if !strings.Contains(errMsg, "MaxSessions limit may be reached") {
		t.Fatalf("expected MaxSessions diagnostic hint in error, got: %q", errMsg)
	}
}

// TestMuxProxy_InitialPacketAndPingPong verifies that entering MUX_C_PROXY mode
// immediately emits the server's initial global request packet (so `-O proxy < /dev/null`
// receives connection-protocol output) and answers SSH_MSG_PING (192) with SSH_MSG_PONG (193).
func TestMuxProxy_InitialPacketAndPingPong(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fixture := startMuxFixture(t, ctx, sshfixture.Options{})

	stream, err := DialMuxProxyStream(ctx, fixture.SocketPath)
	if err != nil {
		t.Fatalf("DialMuxProxyStream failed: %v", err)
	}
	defer func() { _ = stream.Close() }()

	// 1. Read the initial packet sent by the master upon entering proxy mode
	if err := stream.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	initPkt, err := readUnpaddedPacket(stream)
	if err != nil {
		t.Fatalf("read initial proxy packet failed: %v", err)
	}
	if len(initPkt) == 0 || initPkt[0] != msgGlobalRequest {
		t.Fatalf("expected initial packet to be msgGlobalRequest (%d), got %v", msgGlobalRequest, initPkt)
	}

	// 2. Send SSH_MSG_PING (192) and verify SSH_MSG_PONG (193) reply
	pingPayload := []byte{msgPing, 0, 0, 0, 4, 'p', 'i', 'n', 'g'}
	if err := writeUnpaddedPacket(stream, pingPayload); err != nil {
		t.Fatalf("write ping packet failed: %v", err)
	}
	pongPkt, err := readUnpaddedPacket(stream)
	if err != nil {
		t.Fatalf("read pong packet failed: %v", err)
	}
	expectedPong := []byte{msgPong, 0, 0, 0, 4, 'p', 'i', 'n', 'g'}
	if !bytes.Equal(pongPkt, expectedPong) {
		t.Fatalf("expected pong %v, got %v", expectedPong, pongPkt)
	}
}

// TestConnector_MultiplexTargetMismatchAndAskRejectionFailClosed verifies that:
//  1. Reusing a static ControlPath pointing to a different target host fails closed
//     with ErrControlTargetMismatch instead of connecting to the wrong host.
//  2. When an ask/autoask master rejects a session confirmation, Connector fails
//     closed with ErrControlProxyRejected instead of silently falling back to a
//     direct connection.
func TestConnector_MultiplexTargetMismatchAndAskRejectionFailClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fixture := startMuxFixture(t, ctx, sshfixture.Options{})

	// Advertise target identity and ask-mode rejection on the fixture's master
	// before any client connects to the control socket.
	fixture.Master.target = TargetContext{
		Host: "host-a.example.com",
		Port: fixture.Port,
		User: "fixture",
	}
	fixture.Master.askConfirmation = true
	fixture.Master.confirmSession = func(string) bool { return false }

	provider := &staticMuxTestProvider{
		configs: map[string]*ClientConfig{
			"node-b": {
				NodeID:   "node-b",
				Address:  "host-b.example.com",
				Port:     fixture.Port,
				User:     "fixture",
				AuthType: "password",
				Password: sshfixture.Password,
			},
			"node-a": {
				NodeID:   "node-a",
				Address:  "host-a.example.com",
				Port:     fixture.Port,
				User:     "fixture",
				AuthType: "password",
				Password: sshfixture.Password,
			},
		},
		controls: map[string]*ControlConfig{
			"node-b": {
				Master: ControlMasterAuto,
				Path:   fixture.SocketPath,
			},
			"node-a": {
				Master: ControlMasterAuto,
				Path:   fixture.SocketPath,
			},
		},
	}

	connector := NewConnector(provider, WithControlProvider(provider))
	defer func() { _ = connector.CloseAll() }()

	// 1. Connecting to node-b via a socket bound to host-a must fail closed with ErrControlTargetMismatch
	_, err := connector.Connect(ctx, "node-b")
	if !errors.Is(err, ErrControlTargetMismatch) {
		t.Fatalf("expected ErrControlTargetMismatch when reusing static socket for wrong host, got: %v", err)
	}

	// 2. Verify node-a (matching target) fails closed with ErrControlProxyRejected when ask master denies confirmation
	_, err = connector.Connect(ctx, "node-a")
	if !errors.Is(err, ErrControlProxyRejected) {
		t.Fatalf("expected ErrControlProxyRejected when ask master denies confirmation, got: %v", err)
	}
}

type staticMuxTestProvider struct {
	configs  map[string]*ClientConfig
	controls map[string]*ControlConfig
}

func (p *staticMuxTestProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	if cfg, ok := p.configs[nodeID]; ok {
		cloned := *cfg
		return &cloned, nil
	}
	return nil, errors.New("node not found")
}

func (p *staticMuxTestProvider) GetControlConfig(nodeID string) (*ControlConfig, error) {
	if ctrl, ok := p.controls[nodeID]; ok {
		return ctrl.Clone(), nil
	}
	return nil, nil
}

// TestDialControlProxyClient_ExecutesSessionAndValidatesTarget verifies that
// DialControlProxyClient wraps a MUX_C_PROXY connection in *Client, executes
// remote commands without direct TCP fallback, and rejects target mismatches.
func TestDialControlProxyClient_ExecutesSessionAndValidatesTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fixture := startMuxFixture(t, ctx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			_, _ = io.WriteString(ch, "proxy-client-out:"+cmd+"\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	fixture.Master.target = fixture.Target

	// 1. Target mismatch fails closed with ErrControlTargetMismatch
	wrongTarget := TargetContext{Host: "other.example.com", Port: fixture.Port, User: "fixture"}
	_, err := DialControlProxyClient(ctx, fixture.SocketPath, wrongTarget, Environment{}, nil, nil)
	if !errors.Is(err, ErrControlTargetMismatch) {
		t.Fatalf("expected ErrControlTargetMismatch, got: %v", err)
	}

	// 2. Empty target (e.g. -O proxy -S <sock> -- cmd) succeeds and runs command
	cliNoTarget, err := DialControlProxyClient(ctx, fixture.SocketPath, TargetContext{}, Environment{}, nil, nil)
	if err != nil {
		t.Fatalf("DialControlProxyClient with empty target failed: %v", err)
	}
	defer func() { _ = cliNoTarget.Close() }()

	out, err := cliNoTarget.Run(ctx, "echo ok", WithInterpreter(InterpreterServer), WithLaunchDialect(LaunchUnknown))
	if err != nil {
		t.Fatalf("cliNoTarget.Run failed: %v", err)
	}
	if strings.TrimSpace(out) != "proxy-client-out:echo ok" {
		t.Fatalf("unexpected output: %q", out)
	}
}
