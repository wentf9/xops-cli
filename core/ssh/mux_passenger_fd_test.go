//go:build linux || darwin || freebsd

package ssh

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// newPassengerFDChannel returns the receiving end as a *net.UnixConn plus the
// raw peer descriptor a test can use to send SCM_RIGHTS messages.
func newPassengerFDChannel(t *testing.T) (*net.UnixConn, int) {
	t.Helper()
	sv, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair failed: %v", err)
	}
	file := os.NewFile(uintptr(sv[0]), "passenger-fd-test")
	if file == nil {
		_ = unix.Close(sv[0])
		_ = unix.Close(sv[1])
		t.Fatalf("wrap socketpair end in a file failed")
	}
	// FileConn duplicates the descriptor, so the *os.File must be closed here.
	conn, err := net.FileConn(file)
	_ = file.Close()
	if err != nil {
		_ = unix.Close(sv[1])
		t.Fatalf("wrap socketpair end in a connection failed: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = unix.Close(sv[1])
	})
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("socketpair end is %T, want *net.UnixConn", conn)
	}
	return unixConn, sv[1]
}

// sendDescriptor transmits one descriptor in its own control message, which is
// what OpenSSH's mm_send_fd does for every session descriptor.
func sendDescriptor(t *testing.T, peer int, fd int) {
	t.Helper()
	if err := unix.Sendmsg(peer, []byte{0}, unix.UnixRights(fd), nil, 0); err != nil {
		t.Fatalf("send descriptor %d failed: %v", fd, err)
	}
}

// TestRecvFDsAccumulatesSplitControlMessages verifies that descriptors arriving
// one control message at a time (the OpenSSH passenger layout) are accumulated.
// A single recvmsg would either fail or lose descriptors, which broke every
// passenger session that did not happen to batch its three descriptors.
func TestRecvFDsAccumulatesSplitControlMessages(t *testing.T) {
	conn, peer := newPassengerFDChannel(t)

	first, firstWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	defer func() { _ = firstWriter.Close() }()
	second, secondWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	defer func() { _ = secondWriter.Close() }()

	sendDescriptor(t, peer, int(first.Fd()))
	sendDescriptor(t, peer, int(second.Fd()))
	// The sender keeps its own references; the receiver owns the duplicates.
	_ = first.Close()
	_ = second.Close()

	fds, err := recvFDs(conn, 2)
	if err != nil {
		t.Fatalf("recvFDs failed: %v", err)
	}
	defer closeFDRange(fds)
	if len(fds) != 2 {
		t.Fatalf("received %d descriptors, want 2", len(fds))
	}

	if _, err := firstWriter.Write([]byte("first")); err != nil {
		t.Fatalf("write first pipe failed: %v", err)
	}
	if _, err := secondWriter.Write([]byte("second")); err != nil {
		t.Fatalf("write second pipe failed: %v", err)
	}
	assertReceived := func(fd int, want string) {
		t.Helper()
		buffer := make([]byte, len(want))
		if _, err := unix.Read(fd, buffer); err != nil {
			t.Fatalf("read from received descriptor %d failed: %v", fd, err)
		}
		if string(buffer) != want {
			t.Fatalf("received descriptor %d yielded %q, want %q", fd, buffer, want)
		}
	}
	assertReceived(fds[0], "first")
	assertReceived(fds[1], "second")

	for _, fd := range fds {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil {
			t.Fatalf("read descriptor flags for %d failed: %v", fd, err)
		}
		if flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("received descriptor %d is not close-on-exec", fd)
		}
	}
}

// TestRecvFDsClosesSurplusDescriptors verifies that a peer cannot retain extra
// descriptors by sending more than the request needs: the surplus is closed
// rather than handed to the caller.
func TestRecvFDsClosesSurplusDescriptors(t *testing.T) {
	conn, peer := newPassengerFDChannel(t)

	needed, neededWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	defer func() { _ = neededWriter.Close() }()
	surplus, surplusWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	defer func() { _ = surplusWriter.Close() }()

	if err := unix.Sendmsg(peer, []byte{0}, unix.UnixRights(int(needed.Fd()), int(surplus.Fd())), nil, 0); err != nil {
		t.Fatalf("send descriptors failed: %v", err)
	}
	_ = needed.Close()
	_ = surplus.Close()

	fds, err := recvFDs(conn, 1)
	if err != nil {
		t.Fatalf("recvFDs failed: %v", err)
	}
	defer closeFDRange(fds)
	if len(fds) != 1 {
		t.Fatalf("received %d descriptors, want 1", len(fds))
	}
	if _, err := neededWriter.Write([]byte("kept")); err != nil {
		t.Fatalf("write to the retained descriptor failed: %v", err)
	}
	if _, err := surplusWriter.Write([]byte("x")); !errors.Is(err, syscall.EPIPE) {
		t.Fatalf("expected surplus pipe write to fail with EPIPE after surplus fd was closed, got %v", err)
	}
}

// TestRecvFilesOwnsDescriptors verifies the single-owner contract: closing the
// returned file closes the descriptor once, and a repeated Close is a no-op that
// cannot free a descriptor another goroutine has since reused.
func TestRecvFilesOwnsDescriptors(t *testing.T) {
	conn, peer := newPassengerFDChannel(t)

	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	defer func() { _ = pipeWrite.Close() }()
	sendDescriptor(t, peer, int(pipeRead.Fd()))
	_ = pipeRead.Close()

	files, err := recvFiles(conn, "passenger", "stdin")
	if err != nil {
		t.Fatalf("recvFiles failed: %v", err)
	}
	if len(files) != 1 || files[0] == nil {
		t.Fatalf("recvFiles returned %d files, want 1", len(files))
	}

	received := int(files[0].Fd())
	if err := files[0].Close(); err != nil {
		t.Fatalf("closing the owning file failed: %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(received), unix.F_GETFD, 0); err == nil {
		t.Fatalf("descriptor %d is still open after its owning file was closed", received)
	}

	// Reuse the descriptor number so a second close would be observable.
	canaryRead, canaryWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("canary pipe failed: %v", err)
	}
	defer func() { _ = canaryRead.Close() }()
	defer func() { _ = canaryWrite.Close() }()

	if err := files[0].Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("expected a repeated close to report os.ErrClosed, got %v", err)
	}
	if _, err := unix.FcntlInt(uintptr(received), unix.F_GETFD, 0); err != nil {
		t.Fatalf("repeated close touched the descriptor number %d now owned by another file: %v", received, err)
	}
}

type ptyRejectingSSHConn struct {
	*dummySSHConn
}

type ptyRejectingChannel struct {
	reqs chan *cryptoSSH.Request
}

func (c *ptyRejectingChannel) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *ptyRejectingChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *ptyRejectingChannel) Close() error                { return nil }
func (c *ptyRejectingChannel) CloseWrite() error           { return nil }
func (c *ptyRejectingChannel) Stderr() io.ReadWriter       { return c }
func (c *ptyRejectingChannel) SendRequest(name string, _ bool, _ []byte) (bool, error) {
	switch name {
	case "pty-req":
		return false, nil
	case "exec", "shell":
		c.reqs <- &cryptoSSH.Request{
			Type:      "exit-status",
			WantReply: false,
			Payload:   cryptoSSH.Marshal(struct{ Status uint32 }{0}),
		}
		close(c.reqs)
		return true, nil
	default:
		return true, nil
	}
}

func (c *ptyRejectingSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if name != "session" {
		return nil, nil, errors.New("unsupported channel")
	}
	reqs := make(chan *cryptoSSH.Request, 1)
	return &ptyRejectingChannel{reqs: reqs}, reqs, nil
}

func sendSessionPipeFDs(t *testing.T, clientConn net.Conn) {
	t.Helper()
	unixClient, ok := clientConn.(*net.UnixConn)
	if !ok {
		t.Fatalf("expected *net.UnixConn, got %T", clientConn)
	}
	rawConn, err := unixClient.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn failed: %v", err)
	}
	for range 3 {
		r, w, pipeErr := os.Pipe()
		if pipeErr != nil {
			t.Fatalf("os.Pipe failed: %v", pipeErr)
		}
		var sendErr error
		_ = rawConn.Control(func(fd uintptr) {
			sendErr = unix.Sendmsg(int(fd), []byte{0}, unix.UnixRights(int(r.Fd())), nil, 0)
		})
		_ = r.Close()
		_ = w.Close()
		if sendErr != nil {
			t.Fatalf("send fd failed: %v", sendErr)
		}
	}
}

// TestPassengerSession_TTYAllocFailSentAfterSessionOpenedWithSessionID verifies
// that when PTY allocation fails in passenger mode, the master sends
// MUX_S_SESSION_OPENED(reqID, sessionID) first, followed by
// MUX_S_TTY_ALLOC_FAIL(sessionID) and MUX_S_EXIT_MESSAGE(sessionID, exitCode).
func TestPassengerSession_TTYAllocFailSentAfterSessionOpenedWithSessionID(t *testing.T) {
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	conn := &ptyRejectingSSHConn{dummySSHConn: &dummySSHConn{chans: chans, reqs: reqs}}
	sshClient := cryptoSSH.NewClient(conn, chans, reqs)
	defer func() { _ = sshClient.Close() }()

	sockPath := filepath.Join(shortSocketDir(t), "pty-fail.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         sshClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix socket failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	if err := performClientMuxHandshake(clientConn); err != nil {
		t.Fatalf("mux handshake failed: %v", err)
	}

	const reqID uint32 = 42
	reqPayload := EncodeMuxNewSession(MuxNewSessionRequest{
		RequestID: reqID,
		WantTTY:   true,
		TermType:  "xterm-256color",
		Command:   "echo ok",
	})
	if err := WriteMuxPacket(clientConn, MUX_C_NEW_SESSION, reqPayload); err != nil {
		t.Fatalf("send MUX_C_NEW_SESSION failed: %v", err)
	}
	sendSessionPipeFDs(t, clientConn)

	// 1. First packet MUST be MUX_S_SESSION_OPENED(reqID=42, sessionID=1)
	pktType, payload, err := ReadMuxPacket(clientConn)
	if err != nil {
		t.Fatalf("read first response packet failed: %v", err)
	}
	if pktType != MUX_S_SESSION_OPENED {
		t.Fatalf("expected first packet MUX_S_SESSION_OPENED (0x%08x), got 0x%08x", MUX_S_SESSION_OPENED, pktType)
	}
	gotReqID, sessionID, err := DecodeMuxSessionOpened(payload)
	if err != nil {
		t.Fatalf("DecodeMuxSessionOpened failed: %v", err)
	}
	if gotReqID != reqID {
		t.Fatalf("session opened request ID = %d, want %d", gotReqID, reqID)
	}

	// 2. Second packet MUST be MUX_S_TTY_ALLOC_FAIL(sessionID)
	pktType, payload, err = ReadMuxPacket(clientConn)
	if err != nil {
		t.Fatalf("read second response packet failed: %v", err)
	}
	if pktType != MUX_S_TTY_ALLOC_FAIL {
		t.Fatalf("expected second packet MUX_S_TTY_ALLOC_FAIL (0x%08x), got 0x%08x", MUX_S_TTY_ALLOC_FAIL, pktType)
	}
	ttyFailSessionID, err := DecodeMuxTTYAllocFail(payload)
	if err != nil {
		t.Fatalf("DecodeMuxTTYAllocFail failed: %v", err)
	}
	if ttyFailSessionID != sessionID {
		t.Fatalf("MUX_S_TTY_ALLOC_FAIL carried ID %d, want sessionID %d (not reqID %d)", ttyFailSessionID, sessionID, reqID)
	}

	// 3. Third packet MUST be MUX_S_EXIT_MESSAGE(sessionID, 0)
	pktType, payload, err = ReadMuxPacket(clientConn)
	if err != nil {
		t.Fatalf("read third response packet failed: %v", err)
	}
	if pktType != MUX_S_EXIT_MESSAGE {
		t.Fatalf("expected third packet MUX_S_EXIT_MESSAGE (0x%08x), got 0x%08x", MUX_S_EXIT_MESSAGE, pktType)
	}
	exitSessionID, exitCode, err := DecodeMuxExitMessage(payload)
	if err != nil {
		t.Fatalf("DecodeMuxExitMessage failed: %v", err)
	}
	if exitSessionID != sessionID || exitCode != 0 {
		t.Fatalf("exit message = (session=%d, code=%d), want (session=%d, code=0)", exitSessionID, exitCode, sessionID)
	}
}

type subsystemEchoSSHConn struct {
	*dummySSHConn
}

type subsystemEchoChannel struct {
	reqs   chan *cryptoSSH.Request
	inR    *io.PipeReader
	inW    *io.PipeWriter
	outR   *io.PipeReader
	outW   *io.PipeWriter
	stderr bytes.Buffer
}

func newSubsystemEchoChannel() (*subsystemEchoChannel, <-chan *cryptoSSH.Request) {
	reqs := make(chan *cryptoSSH.Request, 1)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	return &subsystemEchoChannel{
		reqs: reqs,
		inR:  inR,
		inW:  inW,
		outR: outR,
		outW: outW,
	}, reqs
}

func (c *subsystemEchoChannel) Read(b []byte) (int, error)  { return c.outR.Read(b) }
func (c *subsystemEchoChannel) Write(b []byte) (int, error) { return c.inW.Write(b) }
func (c *subsystemEchoChannel) CloseWrite() error           { return c.inW.Close() }
func (c *subsystemEchoChannel) Close() error {
	_ = c.inW.Close()
	_ = c.outW.Close()
	return nil
}
func (c *subsystemEchoChannel) Stderr() io.ReadWriter { return &c.stderr }
func (c *subsystemEchoChannel) SendRequest(name string, _ bool, payload []byte) (bool, error) {
	if name != "subsystem" {
		return false, nil
	}
	var sub struct{ Subsystem string }
	if err := cryptoSSH.Unmarshal(payload, &sub); err != nil || sub.Subsystem != "sftp" {
		return false, nil
	}
	go func() {
		// Wait until client stdin echoes and closes (CloseWrite -> EOF), then
		// reply on stdout and emit exit-status 0.
		data, _ := io.ReadAll(c.inR)
		_, _ = c.outW.Write(append([]byte("sftp-echo:"), data...))
		_ = c.outW.Close()
		c.reqs <- &cryptoSSH.Request{
			Type:      "exit-status",
			WantReply: false,
			Payload:   cryptoSSH.Marshal(struct{ Status uint32 }{0}),
		}
		close(c.reqs)
	}()
	return true, nil
}

func (c *subsystemEchoSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if name != "session" {
		return nil, nil, errors.New("unsupported channel")
	}
	ch, reqs := newSubsystemEchoChannel()
	return ch, reqs, nil
}

// TestPassengerSession_SubsystemAndStdinEOF verifies that a passenger subsystem
// request (e.g. native sftp) starts I/O properly, propagates stdin EOF via
// CloseWrite so the remote subsystem terminates cleanly, and returns exit
// status 0 instead of failing immediately with exit status 255.
func TestPassengerSession_SubsystemAndStdinEOF(t *testing.T) {
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	conn := &subsystemEchoSSHConn{dummySSHConn: &dummySSHConn{chans: chans, reqs: reqs}}
	sshClient := cryptoSSH.NewClient(conn, chans, reqs)
	defer func() { _ = sshClient.Close() }()

	sockPath := filepath.Join(shortSocketDir(t), "sftp-subsys.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         sshClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix socket failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	if err := performClientMuxHandshake(clientConn); err != nil {
		t.Fatalf("mux handshake failed: %v", err)
	}

	const reqID uint32 = 9
	reqPayload := EncodeMuxNewSession(MuxNewSessionRequest{
		RequestID: reqID,
		Subsystem: true,
		Command:   "sftp",
	})
	if err := WriteMuxPacket(clientConn, MUX_C_NEW_SESSION, reqPayload); err != nil {
		t.Fatalf("send MUX_C_NEW_SESSION failed: %v", err)
	}

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdin pipe failed: %v", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdout pipe failed: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stderr pipe failed: %v", err)
	}
	defer func() {
		_ = stdinW.Close()
		_ = stdoutR.Close()
		_ = stderrR.Close()
	}()

	unixClient := clientConn.(*net.UnixConn)
	rawConn, err := unixClient.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn failed: %v", err)
	}
	for _, f := range []*os.File{stdinR, stdoutW, stderrW} {
		var sendErr error
		_ = rawConn.Control(func(fd uintptr) {
			sendErr = unix.Sendmsg(int(fd), []byte{0}, unix.UnixRights(int(f.Fd())), nil, 0)
		})
		_ = f.Close()
		if sendErr != nil {
			t.Fatalf("send fd failed: %v", sendErr)
		}
	}

	if _, err := stdinW.Write([]byte("ls /tmp\nquit\n")); err != nil {
		t.Fatalf("write stdin failed: %v", err)
	}
	_ = stdinW.Close() // Trigger EOF propagation to remote subsystem

	pktType, _, err := ReadMuxPacket(clientConn)
	if err != nil {
		t.Fatalf("read MUX_S_SESSION_OPENED failed: %v", err)
	}
	if pktType != MUX_S_SESSION_OPENED {
		t.Fatalf("expected MUX_S_SESSION_OPENED, got 0x%08x", pktType)
	}

	outBytes, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatalf("read stdout pipe failed: %v", err)
	}
	if string(outBytes) != "sftp-echo:ls /tmp\nquit\n" {
		t.Fatalf("unexpected subsystem stdout: %q", string(outBytes))
	}

	pktType, payload, err := ReadMuxPacket(clientConn)
	if err != nil {
		t.Fatalf("read MUX_S_EXIT_MESSAGE failed: %v", err)
	}
	if pktType != MUX_S_EXIT_MESSAGE {
		t.Fatalf("expected MUX_S_EXIT_MESSAGE, got 0x%08x", pktType)
	}
	_, exitCode, err := DecodeMuxExitMessage(payload)
	if err != nil {
		t.Fatalf("DecodeMuxExitMessage failed: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("expected subsystem exit code 0, got %d", exitCode)
	}
}

type immediateExitSSHConn struct {
	*dummySSHConn
}

type immediateExitChannel struct {
	reqs chan *cryptoSSH.Request
}

func (c *immediateExitChannel) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *immediateExitChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *immediateExitChannel) Close() error                { return nil }
func (c *immediateExitChannel) CloseWrite() error           { return nil }
func (c *immediateExitChannel) Stderr() io.ReadWriter       { return c }
func (c *immediateExitChannel) SendRequest(name string, _ bool, _ []byte) (bool, error) {
	if name == "exec" || name == "shell" {
		c.reqs <- &cryptoSSH.Request{
			Type:      "exit-status",
			WantReply: false,
			Payload:   cryptoSSH.Marshal(struct{ Status uint32 }{0}),
		}
		close(c.reqs)
	}
	return true, nil
}

func (c *immediateExitSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if name != "session" {
		return nil, nil, errors.New("unsupported channel")
	}
	reqs := make(chan *cryptoSSH.Request, 1)
	return &immediateExitChannel{reqs: reqs}, reqs, nil
}

func mustCloexecPipe(t *testing.T, p *[2]int) {
	t.Helper()
	if err := unix.Pipe(p[:]); err != nil {
		t.Fatalf("unix.Pipe failed: %v", err)
	}
	unix.CloseOnExec(p[0])
	unix.CloseOnExec(p[1])
}

// TestPassengerSession_BlockingPipeDoesNotDeadlockOnExit verifies that when a
// passenger client passes a blocking pipe fd (created via unix.Pipe without
// O_NONBLOCK, mimicking a blocking TTY or pipe from native /usr/bin/ssh) whose
// write end remains open in the client, remote command exit wakes the stdin
// pump immediately via unix.Poll without mutating O_NONBLOCK on the shared open
// file description.
func TestPassengerSession_BlockingPipeDoesNotDeadlockOnExit(t *testing.T) {
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	conn := &immediateExitSSHConn{dummySSHConn: &dummySSHConn{chans: chans, reqs: reqs}}
	sshClient := cryptoSSH.NewClient(conn, chans, reqs)
	defer func() { _ = sshClient.Close() }()

	sockPath := filepath.Join(shortSocketDir(t), "blocking-pipe.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         sshClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix socket failed: %v", err)
	}
	defer func() { _ = clientConn.Close() }()

	if err := performClientMuxHandshake(clientConn); err != nil {
		t.Fatalf("mux handshake failed: %v", err)
	}

	const reqID uint32 = 77
	reqPayload := EncodeMuxNewSession(MuxNewSessionRequest{
		RequestID: reqID,
		Command:   "true",
	})
	if err := WriteMuxPacket(clientConn, MUX_C_NEW_SESSION, reqPayload); err != nil {
		t.Fatalf("send MUX_C_NEW_SESSION failed: %v", err)
	}

	// Create raw blocking pipes (no O_NONBLOCK) so os.NewFile does not register
	// them with the nonblocking poller. Keep stdinPipe[1] open in the test!
	var stdinPipe, stdoutPipe, stderrPipe [2]int
	mustCloexecPipe(t, &stdinPipe)
	defer func() { _ = unix.Close(stdinPipe[1]) }()
	mustCloexecPipe(t, &stdoutPipe)
	defer func() { _ = unix.Close(stdoutPipe[0]) }()
	mustCloexecPipe(t, &stderrPipe)
	defer func() { _ = unix.Close(stderrPipe[0]) }()

	unixClient := clientConn.(*net.UnixConn)
	rawConn, err := unixClient.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn failed: %v", err)
	}
	for _, fdToSend := range []int{stdinPipe[0], stdoutPipe[1], stderrPipe[1]} {
		var sendErr error
		_ = rawConn.Control(func(sockFD uintptr) {
			sendErr = unix.Sendmsg(int(sockFD), []byte{0}, unix.UnixRights(fdToSend), nil, 0)
		})
		_ = unix.Close(fdToSend)
		if sendErr != nil {
			t.Fatalf("send fd failed: %v", sendErr)
		}
	}

	if err := clientConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}

	pktType, _, err := ReadMuxPacket(clientConn)
	if err != nil || pktType != MUX_S_SESSION_OPENED {
		t.Fatalf("expected MUX_S_SESSION_OPENED, got pkt=0x%08x err=%v", pktType, err)
	}

	pktType, payload, err := ReadMuxPacket(clientConn)
	if err != nil || pktType != MUX_S_EXIT_MESSAGE {
		t.Fatalf("expected MUX_S_EXIT_MESSAGE without deadlock, got pkt=0x%08x err=%v", pktType, err)
	}
	_, exitCode, err := DecodeMuxExitMessage(payload)
	if err != nil || exitCode != 0 {
		t.Fatalf("unexpected exit message: code=%d err=%v", exitCode, err)
	}

	// Verify the shared open file description did NOT have O_NONBLOCK mutated.
	flags, err := unix.FcntlInt(uintptr(stdinPipe[1]), unix.F_GETFL, 0)
	if err != nil {
		t.Fatalf("FcntlInt(F_GETFL) failed: %v", err)
	}
	if flags&unix.O_NONBLOCK != 0 {
		t.Fatalf("passenger session mutated O_NONBLOCK on shared open file description (flags=0x%x)", flags)
	}
}
