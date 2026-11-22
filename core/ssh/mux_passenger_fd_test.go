//go:build linux || darwin || freebsd

package ssh

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
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
	defer func() {
		_ = server.Shutdown()
		<-server.Wait()
	}()
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
	defer func() {
		_ = server.Shutdown()
		<-server.Wait()
	}()
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
	defer func() {
		_ = server.Shutdown()
		<-server.Wait()
	}()
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

func sendCustomPipeFDs(t *testing.T, clientConn net.Conn, fds [3]int) {
	t.Helper()
	unixClient, ok := clientConn.(*net.UnixConn)
	if !ok {
		t.Fatalf("expected *net.UnixConn, got %T", clientConn)
	}
	rawConn, err := unixClient.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn failed: %v", err)
	}
	for _, fd := range fds {
		var sendErr error
		_ = rawConn.Control(func(sockFD uintptr) {
			sendErr = unix.Sendmsg(int(sockFD), []byte{0}, unix.UnixRights(fd), nil, 0)
		})
		if sendErr != nil {
			t.Fatalf("send fd %d failed: %v", fd, sendErr)
		}
	}
}

type floodModeChannel struct {
	reqs         chan *cryptoSSH.Request
	reqsOnce     sync.Once
	closed       chan struct{}
	closeOnce    sync.Once
	floodPayload []byte
	off          int
	eofStdout    bool
	readHit      chan struct{}
	readOnce     sync.Once
	zeroWrite    bool
	writeHit     chan struct{}
	releaseExit  chan struct{}
}

type eofReadWriter struct{}

func (eofReadWriter) Read([]byte) (int, error)    { return 0, io.EOF }
func (eofReadWriter) Write(b []byte) (int, error) { return len(b), nil }

func (c *floodModeChannel) closeReqs() {
	c.reqsOnce.Do(func() {
		if c.reqs != nil {
			close(c.reqs)
		}
	})
}

func (c *floodModeChannel) Read(b []byte) (int, error) {
	if c.eofStdout {
		if c.releaseExit != nil {
			select {
			case <-c.releaseExit:
			case <-c.closed:
			}
		}
		return 0, io.EOF
	}
	if c.off < len(c.floodPayload) {
		n := copy(b, c.floodPayload[c.off:])
		c.off += n
		if c.readHit != nil {
			c.readOnce.Do(func() { close(c.readHit) })
		}
		return n, nil
	}
	<-c.closed
	return 0, io.EOF
}

func (c *floodModeChannel) Write(b []byte) (int, error) {
	if c.zeroWrite {
		if c.writeHit != nil {
			select {
			case <-c.writeHit:
			default:
				close(c.writeHit)
			}
		}
		<-c.closed
		return 0, net.ErrClosed
	}
	return len(b), nil
}

func (c *floodModeChannel) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	c.closeReqs()
	return nil
}

func (c *floodModeChannel) CloseWrite() error     { return nil }
func (c *floodModeChannel) Stderr() io.ReadWriter { return eofReadWriter{} }
func (c *floodModeChannel) SendRequest(name string, _ bool, reqPayload []byte) (bool, error) {
	if name == "exec" {
		cmd := string(reqPayload)
		switch {
		case strings.Contains(cmd, "ping"):
			c.eofStdout = true
			c.reqs <- &cryptoSSH.Request{
				Type:      "exit-status",
				WantReply: false,
				Payload:   cryptoSSH.Marshal(struct{ Status uint32 }{0}),
			}
			c.closeReqs()
		case strings.Contains(cmd, "zero"):
			c.zeroWrite = true
			c.eofStdout = true
			go func() {
				if c.releaseExit != nil {
					select {
					case <-c.releaseExit:
					case <-c.closed:
						return
					}
				}
				select {
				case c.reqs <- &cryptoSSH.Request{
					Type:      "exit-status",
					WantReply: false,
					Payload:   cryptoSSH.Marshal(struct{ Status uint32 }{0}),
				}:
				case <-c.closed:
					return
				}
				c.closeReqs()
			}()
		default:
			c.floodPayload = bytes.Repeat([]byte{'A'}, 256*1024)
		}
	}
	return true, nil
}

type routedSessionSSHConn struct {
	*dummySSHConn
	readHit     chan struct{}
	writeHit    chan struct{}
	releaseExit chan struct{}
}

func (conn *routedSessionSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if name != "session" {
		return nil, nil, errors.New("unsupported")
	}
	reqs := make(chan *cryptoSSH.Request, 1)
	return &floodModeChannel{
		reqs:        reqs,
		closed:      make(chan struct{}),
		readHit:     conn.readHit,
		writeHit:    conn.writeHit,
		releaseExit: conn.releaseExit,
	}, reqs, nil
}

func waitPipeWriteBackpressured(t *testing.T, writeFD int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	pfd := []unix.PollFd{{Fd: int32(writeFD), Events: unix.POLLOUT}}
	for time.Now().Before(deadline) {
		if err := t.Context().Err(); err != nil {
			t.Fatalf("context canceled waiting for write backpressure: %v", err)
		}
		pfd[0].Revents = 0
		n, err := unix.Poll(pfd, 0)
		if err == nil && (n == 0 || pfd[0].Revents&unix.POLLOUT == 0) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("stdout pipe never became write-backpressured")
}

func waitServerActiveSessionsZero(t *testing.T, server *MuxServer) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if server.ActiveSessions() == 0 {
			return
		}
		if err := t.Context().Err(); err != nil {
			t.Fatalf("context canceled waiting for ActiveSessions()==0 (current=%d): %v", server.ActiveSessions(), err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("MuxServer ActiveSessions() = %d, want 0", server.ActiveSessions())
}

func TestPassengerSession_FullBlockingStdoutPipeDoesNotKillMuxServerOnClientDisconnect(t *testing.T) {
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	readHit := make(chan struct{})
	conn := &routedSessionSSHConn{
		dummySSHConn: &dummySSHConn{chans: chans, reqs: reqs},
		readHit:      readHit,
	}
	sshClient := cryptoSSH.NewClient(conn, chans, reqs)
	defer func() { _ = sshClient.Close() }()

	sockPath := filepath.Join(shortSocketDir(t), "full-pipe-isolation.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         sshClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() {
		_ = server.Shutdown()
		<-server.Wait()
	}()
	go func() { _ = server.Serve() }()

	// Session 1: unread blocking stdout pipe fills past kernel pipe buffer and blocks copyToPollableFD.
	var inPipe, outPipe, errPipe [2]int
	mustCloexecPipe(t, &inPipe)
	mustCloexecPipe(t, &outPipe)
	mustCloexecPipe(t, &errPipe)
	defer func() {
		for _, fd := range []int{inPipe[0], inPipe[1], outPipe[0], outPipe[1], errPipe[0], errPipe[1]} {
			_ = unix.Close(fd)
		}
	}()

	c1, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	if err := performClientMuxHandshake(c1); err != nil {
		_ = c1.Close()
		t.Fatalf("handshake 1: %v", err)
	}
	if err := WriteMuxPacket(c1, MUX_C_NEW_SESSION, EncodeMuxNewSession(MuxNewSessionRequest{
		RequestID: 1,
		Command:   "flood",
	})); err != nil {
		_ = c1.Close()
		t.Fatalf("send session 1: %v", err)
	}
	sendCustomPipeFDs(t, c1, [3]int{inPipe[0], outPipe[1], errPipe[1]})
	_, _, err = ReadMuxPacket(c1) // MUX_S_SESSION_OPENED
	if err != nil {
		_ = c1.Close()
		t.Fatalf("read session 1 opened: %v", err)
	}

	select {
	case <-readHit:
	case <-time.After(3 * time.Second):
		_ = c1.Close()
		t.Fatal("flood session never began reading payload")
	}
	waitPipeWriteBackpressured(t, outPipe[1])
	_ = c1.Close()
	waitServerActiveSessionsZero(t, server)

	// Shared master must NOT be torn down when passenger 1 disconnects with a full stdout pipe.
	select {
	case <-server.Wait():
		t.Fatal("MuxServer shut down after passenger with full stdout pipe disconnected")
	default:
	}

	// Session 2 on the same master must succeed.
	c2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial session 2: %v", err)
	}
	defer func() { _ = c2.Close() }()
	if err := performClientMuxHandshake(c2); err != nil {
		t.Fatalf("handshake 2: %v", err)
	}
	if err := WriteMuxPacket(c2, MUX_C_NEW_SESSION, EncodeMuxNewSession(MuxNewSessionRequest{
		RequestID: 2,
		Command:   "ping",
	})); err != nil {
		t.Fatalf("send session 2: %v", err)
	}
	sendSessionPipeFDs(t, c2)
	pt, _, err := ReadMuxPacket(c2)
	if err != nil || pt != MUX_S_SESSION_OPENED {
		t.Fatalf("session 2 opened = (0x%x, %v), want MUX_S_SESSION_OPENED", pt, err)
	}
	pt, payload, err := ReadMuxPacket(c2)
	if err != nil || pt != MUX_S_EXIT_MESSAGE {
		t.Fatalf("session 2 exit = (0x%x, %v), want MUX_S_EXIT_MESSAGE", pt, err)
	}
	_, code, _ := DecodeMuxExitMessage(payload)
	if code != 0 {
		t.Fatalf("session 2 exit code = %d, want 0", code)
	}
}

func TestPassengerSession_RemoteZeroWindowWriteExitsCleanlyWithoutKillingServer(t *testing.T) {
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	writeHit := make(chan struct{})
	releaseExit := make(chan struct{})
	conn := &routedSessionSSHConn{
		dummySSHConn: &dummySSHConn{chans: chans, reqs: reqs},
		writeHit:     writeHit,
		releaseExit:  releaseExit,
	}
	sshClient := cryptoSSH.NewClient(conn, chans, reqs)
	defer func() { _ = sshClient.Close() }()

	sockPath := filepath.Join(shortSocketDir(t), "zero-win-exit.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         sshClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() {
		_ = server.Shutdown()
		<-server.Wait()
	}()
	go func() { _ = server.Serve() }()

	var inPipe, outPipe, errPipe [2]int
	mustCloexecPipe(t, &inPipe)
	mustCloexecPipe(t, &outPipe)
	mustCloexecPipe(t, &errPipe)
	defer func() {
		for _, fd := range []int{inPipe[0], inPipe[1], outPipe[0], outPipe[1], errPipe[0], errPipe[1]} {
			_ = unix.Close(fd)
		}
	}()
	// Seed stdin so copyFromPollableFD immediately calls ch.Write and blocks in zero-window state.
	if _, wErr := unix.Write(inPipe[1], []byte("stdin-data")); wErr != nil {
		t.Fatalf("seed stdin pipe: %v", wErr)
	}

	c1, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	defer func() { _ = c1.Close() }()
	if err := performClientMuxHandshake(c1); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := WriteMuxPacket(c1, MUX_C_NEW_SESSION, EncodeMuxNewSession(MuxNewSessionRequest{
		RequestID: 1,
		Command:   "zero",
	})); err != nil {
		t.Fatalf("send session: %v", err)
	}
	sendCustomPipeFDs(t, c1, [3]int{inPipe[0], outPipe[1], errPipe[1]})

	// Ensure copyFromPollableFD is genuinely blocked in ch.Write before releasing remote exit.
	select {
	case <-writeHit:
	case <-time.After(3 * time.Second):
		close(releaseExit)
		t.Fatal("copyFromPollableFD never reached blocked zero-window ch.Write")
	}
	close(releaseExit)

	// Wait for exit message despite blocked remote Write & open stdinPipe[1].
	done := make(chan error, 1)
	go func() {
		pt, _, rErr := ReadMuxPacket(c1) // OPENED
		if rErr != nil {
			done <- rErr
			return
		}
		if pt != MUX_S_SESSION_OPENED {
			done <- errors.New("expected session opened")
			return
		}
		pt, _, rErr = ReadMuxPacket(c1) // EXIT_MESSAGE
		if rErr != nil {
			done <- rErr
			return
		}
		if pt != MUX_S_EXIT_MESSAGE {
			done <- errors.New("expected exit message")
			return
		}
		done <- nil
	}()
	select {
	case rErr := <-done:
		if rErr != nil {
			t.Fatalf("zero-window exit session failed: %v", rErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("zero-window session deadlocked on remote exit")
	}
	waitServerActiveSessionsZero(t, server)

	select {
	case <-server.Wait():
		t.Fatal("MuxServer shut down unexpectedly after zero-window session exit")
	case <-time.After(80 * time.Millisecond):
	}
}

func TestCopyToPollableFD_LazyWakePipeLeavesZeroOpenWakePipesWhileIdle(t *testing.T) {
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe stdout: %v", err)
	}
	defer func() {
		_ = rOut.Close()
		_ = wOut.Close()
	}()
	rSrc, wSrc, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe src: %v", err)
	}
	defer func() {
		_ = rSrc.Close()
		_ = wSrc.Close()
	}()

	stop := make(chan struct{})
	var baseFDs int
	if runtime.GOOS == "linux" {
		entries, _ := os.ReadDir("/proc/self/fd")
		baseFDs = len(entries)
	}
	done := make(chan error, 1)
	go func() {
		done <- copyToPollableFD(wOut, rSrc, stop)
	}()

	if _, wErr := wSrc.Write([]byte("hello")); wErr != nil {
		t.Fatalf("write src: %v", wErr)
	}
	buf := make([]byte, 5)
	if _, rErr := io.ReadFull(rOut, buf); rErr != nil || string(buf) != "hello" {
		t.Fatalf("read out = (%q, %v), want %q", string(buf), rErr, "hello")
	}
	if runtime.GOOS == "linux" {
		entries, _ := os.ReadDir("/proc/self/fd")
		// One goroutine stack / no wake pipe should add zero open FDs while idle.
		if len(entries) > baseFDs {
			t.Fatalf("open FDs grew from %d to %d while copyToPollableFD is idle", baseFDs, len(entries))
		}
	}

	_ = wSrc.Close()
	select {
	case copyErr := <-done:
		if copyErr != nil {
			t.Fatalf("copyToPollableFD: %v", copyErr)
		}
	case <-time.After(2 * time.Second):
		close(stop)
		t.Fatal("copyToPollableFD did not exit on source EOF")
	}
	close(stop)
}

type newlineFloodReader struct {
	chunk []byte
	done  chan struct{}
	reads atomic.Int64
}

func (r *newlineFloodReader) Read(p []byte) (int, error) {
	select {
	case <-r.done:
		return 0, io.EOF
	default:
		r.reads.Add(1)
		n := copy(p, r.chunk)
		return n, nil
	}
}

func TestCopyToPollableFD_ReopenedBlockingPTYDoesNotBlockOnCancel(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("pty.Open unavailable in environment: %v", err)
	}
	defer func() {
		_ = master.Close()
		_ = slave.Close()
	}()

	// Put slave descriptor in blocking mode (as inherited by an interactive passenger)
	// and write '\n'-heavy lines that default OPOST|ONLCR doubles inside the kernel.
	slaveConn, err := slave.SyscallConn()
	if err != nil {
		t.Fatalf("slave SyscallConn: %v", err)
	}
	_ = slaveConn.Control(func(fd uintptr) {
		_ = unix.SetNonblock(int(fd), false)
	})

	// Pre-saturate master's n_tty receive buffer on Linux so flush_to_ldisc cannot
	// asynchronously drain 4095 bytes out of tty_buffer after copyToPollableFD parks
	// in poll(POLLOUT) (which would flip POLLOUT back to 1 without waking write_wait).
	saturatePTYMasterInput(t, master, slave)

	stop := make(chan struct{})
	srcDone := make(chan struct{})
	src := &newlineFloodReader{
		chunk: bytes.Repeat([]byte{'\n'}, 512),
		done:  srcDone,
	}
	done := make(chan error, 1)
	go func() {
		done <- copyToPollableFD(slave, src, stop)
	}()

	// Wait deterministically until the un-drained PTY slave reports POLLOUT==0
	// (failing fast if copyToPollableFD exits prematurely).
	if ctrlErr := slaveConn.Control(func(fd uintptr) {
		deadline := time.Now().Add(5 * time.Second)
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		for time.Now().Before(deadline) {
			select {
			case copyErr := <-done:
				t.Fatalf("copyToPollableFD(PTY) exited before backpressure: %v", copyErr)
			case <-t.Context().Done():
				t.Fatalf("context canceled waiting for PTY write backpressure: %v", t.Context().Err())
			default:
			}
			pfd[0].Revents = 0
			n, pollErr := unix.Poll(pfd, 0)
			if pollErr == nil && (n == 0 || pfd[0].Revents&unix.POLLOUT == 0) {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("stdout pipe never became write-backpressured")
	}); ctrlErr != nil {
		t.Fatalf("slave Control: %v", ctrlErr)
	}
	if src.reads.Load() == 0 {
		t.Fatal("copyToPollableFD(PTY) never read newline flood before backpressure")
	}
	close(stop)
	close(srcDone)

	select {
	case copyErr := <-done:
		if copyErr != nil {
			t.Fatalf("copyToPollableFD(PTY) returned error after stop: %v", copyErr)
		}
	case <-time.After(2 * time.Second):
		_ = master.Close()
		t.Fatal("copyToPollableFD(PTY) blocked inside kernel write past stop cancellation")
	}

	var slaveFlags int
	_ = slaveConn.Control(func(fd uintptr) {
		slaveFlags, _ = unix.FcntlInt(fd, unix.F_GETFL, 0)
	})
	if slaveFlags&unix.O_NONBLOCK != 0 {
		t.Fatalf("copyToPollableFD mutated caller's PTY O_NONBLOCK flag: flags=%#x", slaveFlags)
	}
}
