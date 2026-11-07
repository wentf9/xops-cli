package ssh

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
)

// stubRemoteChannel is a channel with no transport behind it, for exercising the
// proxy relay state machine without a live SSH server.
type stubRemoteChannel struct {
	closed atomic.Bool
}

func (c *stubRemoteChannel) Read([]byte) (int, error)                       { return 0, io.EOF }
func (c *stubRemoteChannel) Write(data []byte) (int, error)                 { return len(data), nil }
func (c *stubRemoteChannel) CloseWrite() error                              { return nil }
func (c *stubRemoteChannel) SendRequest(string, bool, []byte) (bool, error) { return true, nil }
func (c *stubRemoteChannel) Stderr() io.ReadWriter                          { return nil }
func (c *stubRemoteChannel) Close() error {
	c.closed.Store(true)
	return nil
}

func encodeChannelIDs(values ...uint32) []byte {
	w := newMuxWriter()
	for _, value := range values {
		w.WriteUint32(value)
	}
	return w.Bytes()
}

func newStubProxySession(t *testing.T) (*proxySessionState, *proxyChan, net.Conn) {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		_ = conn.Close()
		_ = peer.Close()
	})
	ps := &proxySessionState{
		server: &MuxServer{},
		conn:   conn,
		global: newOrderedQueue[proxyGlobalRequest](),
	}
	pc := &proxyChan{
		remoteCh:          &stubRemoteChannel{},
		clientCh:          7,
		serverCh:          3,
		clientWindow:      newClientFlowWindow(4096),
		clientMaxPacket:   1024,
		requests:          newOrderedQueue[proxyChannelRequest](),
		input:             newOrderedQueue[proxyChannelInput](),
		pendingRemoteReqs: newRemoteRequestQueue(),
	}
	ps.channels.Store(pc.serverCh, pc)
	return ps, pc, peer
}

// TestProxyEchoesClientInitiatedChannelClose verifies that a channel the client
// closed receives exactly one SSH_MSG_CHANNEL_CLOSE back. RFC 4254 requires that
// answer, and x/crypto only releases the client-side channel (unblocking readers)
// after receiving it.
func TestProxyEchoesClientInitiatedChannelClose(t *testing.T) {
	ps, pc, peer := newStubProxySession(t)

	// net.Pipe is synchronous, so the peer must read while the close is written.
	type readResult struct {
		packet []byte
		err    error
	}
	readCh := make(chan readResult, 1)
	if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	go func() {
		packet, err := readUnpaddedPacket(peer)
		readCh <- readResult{packet: packet, err: err}
	}()
	ps.handleClose(encodeChannelIDs(pc.serverCh))

	result := <-readCh
	if result.err != nil {
		t.Fatalf("reading the close echo failed: %v", result.err)
	}
	packet := result.packet
	if len(packet) < 5 || packet[0] != msgChannelClose {
		t.Fatalf("expected SSH_MSG_CHANNEL_CLOSE, got %v", packet)
	}
	if channel := binary.BigEndian.Uint32(packet[1:5]); channel != pc.clientCh {
		t.Fatalf("close echo addressed channel %d, want %d", channel, pc.clientCh)
	}
	if !pc.remoteCh.(*stubRemoteChannel).closed.Load() {
		t.Fatal("handleClose did not close the remote channel")
	}

	// A second close (for example the client's answer to a master-initiated
	// close) must not produce another packet, and nothing may follow the close.
	if err := peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}
	if _, err := readUnpaddedPacket(peer); err == nil {
		t.Fatal("duplicate SSH_MSG_CHANNEL_CLOSE was written")
	}
	if err := ps.writeChannelPacket(pc, []byte{msgChannelData, 0, 0, 0, 0}); !errors.Is(err, io.EOF) {
		t.Fatalf("expected a closed channel to reject further packets, got %v", err)
	}
	if err := ps.writeChannelPacket(pc, nil); !errors.Is(err, io.EOF) {
		t.Fatalf("expected a closed channel to reject the close echo write, got %v", err)
	}
}

// TestProxySessionStopsWritingAfterClose verifies that a torn-down proxy session
// writes nothing further. Waking relay workers after the connection is gone must
// not push a close (or any other packet) into a dead transport.
func TestProxySessionStopsWritingAfterClose(t *testing.T) {
	ps, pc, _ := newStubProxySession(t)

	// net.Pipe writes block without a reader; a stray write must fail fast instead
	// of hanging the test, and closeSent records whether a write was attempted.
	if err := ps.conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline failed: %v", err)
	}
	ps.closeAll()

	if err := ps.writeChannelPacket(pc, []byte{msgChannelData, 0, 0, 0, 0}); !errors.Is(err, io.EOF) {
		t.Fatalf("expected a closed session to reject channel packets, got %v", err)
	}
	if err := ps.writePacket([]byte{msgRequestSuccess}); err == nil {
		t.Fatal("expected a closed session to reject session-level packets")
	}
	ps.closeChannel(pc)
	if pc.closeSent {
		t.Fatal("closeChannel wrote a close packet after the session ended")
	}
}

// TestProxyReleasesClientChannelAfterClientClose verifies the observable effect
// of the close echo: after the client closes a session, reading its output must
// return EOF instead of blocking until the connection dies.
func TestProxyReleasesClientChannelAfterClientClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	release := make(chan struct{})
	fixture := startMuxFixture(t, ctx, sshfixture.Options{
		ExecHandler: func(command string, channel cryptoSSH.Channel) {
			if command == "hold" {
				<-release
				return
			}
			_, _ = io.WriteString(channel, "ok\n")
			_, _ = channel.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	defer close(release)

	client, proxyConn, err := DialControlProxy(ctx, fixture.SocketPath, fixture.Target)
	if err != nil {
		t.Fatalf("DialControlProxy failed: %v", err)
	}
	defer func() {
		_ = client.Close()
		_ = proxyConn.Close()
	}()

	// The remote command never finishes, so the channel stays open until the
	// client closes it explicitly.
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe failed: %v", err)
	}
	if err := session.Start("hold"); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("closing the session failed: %v", err)
	}

	readDone := make(chan error, 1)
	go func() {
		var buffer [1]byte
		_, err := stdout.Read(buffer[:])
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("expected EOF on the closed channel, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client channel was not released after it sent SSH_MSG_CHANNEL_CLOSE")
	}

	// The connection must survive the close: a second session still works.
	second, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession after a client-initiated close failed: %v", err)
	}
	defer func() { _ = second.Close() }()
	output, err := second.Output("echo ok")
	if err != nil {
		t.Fatalf("command after a client-initiated close failed: %v", err)
	}
	if string(output) != "ok\n" {
		t.Fatalf("output after a client-initiated close = %q, want %q", output, "ok\n")
	}
}

// probeFixtureConn answers keepalives on demand and records every Close, so a
// test can tell whether a shared cached connection was interrupted.
type probeFixtureConn struct {
	cryptoSSH.Conn
	requestSeen  chan struct{}
	release      chan struct{}
	requestCount atomic.Int32
	closeCount   atomic.Int32
}

func (c *probeFixtureConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	if c.requestCount.Add(1) == 1 {
		close(c.requestSeen)
	}
	<-c.release
	return true, nil, nil
}

func (c *probeFixtureConn) OpenChannel(string, []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	return nil, nil, errors.New("fixture target unreachable")
}

func (c *probeFixtureConn) Close() error {
	c.closeCount.Add(1)
	return nil
}

// TestJumpHopProbeSurvivesCallerCancellation verifies that canceling one caller
// while a cached jump hop is being validated does not interrupt that shared
// transport. The probe belongs to the connector's shared task, not to the
// caller that happens to trigger it.
func TestJumpHopProbeSurvivesCallerCancellation(t *testing.T) {
	hopConn := &probeFixtureConn{
		requestSeen: make(chan struct{}),
		release:     make(chan struct{}),
	}
	// Unblock the shared probe on every path, including failures, so a regression
	// cannot stall connector shutdown on a keepalive that never answers. The defer
	// is registered after the connector's so it runs before CloseAll joins it.
	releaseHopProbe := sync.OnceFunc(func() { close(hopConn.release) })
	provider := &jumpChainProvider{
		cfgs: map[string]*ClientConfig{
			"jump": {
				NodeID: "jump", Address: "192.0.2.30", Port: 22, User: "ops", AuthType: "password", Password: "secret",
			},
			"target": {
				NodeID: "target", Address: "192.0.2.31", Port: 22, User: "ops", AuthType: "password", Password: "secret",
				ProxyJump: "jump",
			},
		},
	}
	connector := newTestConnector(provider, WithInteractionHandler(&mockUI{}))
	defer func() {
		if err := connector.CloseAll(); err != nil {
			t.Logf("CloseAll failed: %v", err)
		}
	}()
	defer releaseHopProbe()
	connector.clients.Set("jump", &PooledClient{SSHClient: &cryptoSSH.Client{Conn: hopConn}})

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := connector.Connect(firstCtx, "target")
		firstDone <- err
	}()
	select {
	case <-hopConn.requestSeen:
	case <-time.After(5 * time.Second):
		t.Fatal("cached jump hop was never probed")
	}

	cancelFirst()
	select {
	case err := <-firstDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected caller cancellation, got %v", err)
		}
		// The cancellation must be reported for the hop that was being validated,
		// not masked into a "rebuild the chain" fallback.
		if !strings.Contains(err.Error(), "'jump'") {
			t.Fatalf("cancellation lost the hop that was being probed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled caller did not return")
	}

	// Let the shared probe finish, then drive a second connection through the
	// same hop. It fails at the unreachable target, but the hop must stay usable.
	releaseHopProbe()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := connector.Connect(ctx, "target"); err == nil {
		t.Fatal("expected the unreachable target to fail the connection")
	}
	if got := hopConn.closeCount.Load(); got != 0 {
		t.Fatalf("canceling a caller closed the shared jump transport %d times", got)
	}
}
