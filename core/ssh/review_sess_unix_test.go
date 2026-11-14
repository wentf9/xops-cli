//go:build linux || darwin || freebsd

package ssh

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// TestReviewSess_L3_L8_PassengerBoundedRequestsAndCloexec verifies:
//   - L3: MUX_C_NEW_SESSION SendRequest calls (pty-req, exec, etc.) time out via
//     sendBoundedChannelRequest when the remote server stalls, returning MUX_S_FAILURE
//     and closing the passenger's descriptors promptly;
//   - L8: recvFDs marks every received descriptor FD_CLOEXEC and handles peer EOF without spinning;
//   - M3 (mux live): MuxServer with DialNetwork="tcp6" binds default local forward on [::1].
func TestReviewSess_L3_L8_PassengerBoundedRequestsAndCloexec(t *testing.T) {
	// L8a: Peer closes socket before sending FDs -> returns EOF cleanly instead of spinning.
	connEOF, peerEOF := newPassengerFDChannel(t)
	_ = unix.Close(peerEOF)
	if fds, err := recvFDs(connEOF, 1); err == nil {
		closeFDRange(fds)
		t.Fatal("expected recvFDs on closed peer socket to fail with EOF")
	}

	// L8b: Received FDs have FD_CLOEXEC set immediately.
	connFD, peerFD := newPassengerFDChannel(t)
	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wPipe.Close() }()
	sendDescriptor(t, peerFD, int(rPipe.Fd()))
	_ = rPipe.Close()

	fds, err := recvFDs(connFD, 1)
	if err != nil || len(fds) != 1 {
		t.Fatalf("recvFDs = (%v, %v), want 1 fd", fds, err)
	}
	flags, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0)
	_ = unix.Close(fds[0])
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("received fd flags = 0x%x (err=%v), want FD_CLOEXEC set", flags, err)
	}

	// L3: Stalled remote SendRequest during MUX_C_NEW_SESSION must time out promptly.
	stalledConn := &stalledPassengerSSHConn{unblock: make(chan struct{})}
	chans := make(chan cryptoSSH.NewChannel)
	close(chans)
	reqs := make(chan *cryptoSSH.Request)
	close(reqs)
	sshClient := cryptoSSH.NewClient(stalledConn, chans, reqs)
	defer func() {
		close(stalledConn.unblock)
		_ = sshClient.Close()
	}()

	sockPath := filepath.Join(shortSocketDir(t), "stalled-req.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         sshClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	server.requestTimeout = 80 * time.Millisecond
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial mux socket: %v", err)
	}
	defer func() { _ = clientConn.Close() }()
	if err := performClientMuxHandshake(clientConn); err != nil {
		t.Fatalf("mux handshake: %v", err)
	}

	const reqID uint32 = 99
	reqPayload := EncodeMuxNewSession(MuxNewSessionRequest{
		RequestID: reqID,
		WantTTY:   true,
		TermType:  "xterm",
		Command:   "id",
	})
	if err := WriteMuxPacket(clientConn, MUX_C_NEW_SESSION, reqPayload); err != nil {
		t.Fatalf("WriteMuxPacket: %v", err)
	}
	sendSessionPipeFDs(t, clientConn)

	_ = clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	pktType, respPayload, err := ReadMuxPacket(clientConn)
	if err != nil {
		t.Fatalf("ReadMuxPacket after stalled pty-req: %v", err)
	}
	if pktType != MUX_S_FAILURE {
		t.Fatalf("packet type = 0x%08x, want MUX_S_FAILURE (0x%08x); payload=%q", pktType, MUX_S_FAILURE, string(respPayload))
	}

	// M3 (live mux -L under DialNetwork="tcp6"):
	if hasIPv6Loopback() {
		sockPath6 := filepath.Join(shortSocketDir(t), "mux6.sock")
		chans6 := make(chan cryptoSSH.NewChannel)
		reqs6 := make(chan *cryptoSSH.Request)
		sshCli6 := cryptoSSH.NewClient(&dummySSHConn{chans: chans6, reqs: reqs6}, chans6, reqs6)
		defer func() { _ = sshCli6.Close() }()

		srv6, err := NewMuxServer(MuxServerOptions{
			ControlPath:       sockPath6,
			SSHClient:         sshCli6,
			DialNetwork:       "tcp6",
			PersistEnabled:    true,
			PersistIndefinite: true,
		})
		if err != nil {
			t.Fatalf("NewMuxServer(tcp6): %v", err)
		}
		defer func() { _ = srv6.Shutdown() }()
		go func() { _ = srv6.Serve() }()

		mc, err := DialMuxClient(t.Context(), sockPath6)
		if err != nil {
			t.Fatalf("DialMuxClient(tcp6): %v", err)
		}
		defer func() { _ = mc.Close() }()

		// Open local forward with empty ListenHost ("") on ephemeral port under tcp6.
		freeLn, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Fatalf("allocate free tcp6 port: %v", err)
		}
		freePort := uint32(freeLn.Addr().(*net.TCPAddr).Port)
		_ = freeLn.Close()

		if _, err := mc.OpenForward(t.Context(), ForwardRequest{
			Type:        ForwardType(MUX_FWD_LOCAL),
			ListenHost:  "",
			ListenPort:  freePort,
			ConnectHost: "::1",
			ConnectPort: 22,
		}); err != nil {
			t.Fatalf("MuxClient.OpenForward under tcp6 failed: %v", err)
		}
		info, err := mc.RequestInfo(t.Context(), "channels")
		if err != nil || !strings.Contains(info, "::1") {
			t.Fatalf("expected mux tcp6 default forward on ::1, got info=%q err=%v", info, err)
		}
	}
}

type stalledPassengerSSHConn struct {
	dummyMuxGateConn
	unblock chan struct{}
}

func (s *stalledPassengerSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if name != "session" {
		return nil, nil, errors.New("unsupported channel")
	}
	reqs := make(chan *cryptoSSH.Request)
	ch := &stalledPassengerChannel{
		closed:  make(chan struct{}),
		unblock: s.unblock,
	}
	return ch, reqs, nil
}

type stalledPassengerChannel struct {
	closeOnce sync.Once
	closed    chan struct{}
	unblock   <-chan struct{}
}

func (c *stalledPassengerChannel) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *stalledPassengerChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *stalledPassengerChannel) CloseWrite() error           { return nil }
func (c *stalledPassengerChannel) Stderr() io.ReadWriter       { return &nopRW{} }
func (c *stalledPassengerChannel) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *stalledPassengerChannel) SendRequest(string, bool, []byte) (bool, error) {
	select {
	case <-c.closed:
		return false, io.EOF
	case <-c.unblock:
		return false, io.EOF
	}
}
