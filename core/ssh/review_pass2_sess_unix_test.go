//go:build linux || darwin || freebsd

package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// TestReviewPass2_M7_MultiCmsgCloexecTruncatedAndZeroFDsFailClosed verifies:
//   - extractReceivedFDsMarkCloexec marks FDs in earlier cmsgs CloseOnExec even
//     when a trailing cmsg in the same oob buffer is truncated/malformed;
//   - recvFDs closes earlier FDs on multi-cmsg parse error;
//   - recvFDs fails closed immediately when a peer sends plain bytes with 0 FDs.
func TestReviewPass2_M7_MultiCmsgCloexecTruncatedAndZeroFDsFailClosed(t *testing.T) {
	t.Run("multi-cmsg with trailing truncated header marks first FD cloexec and returns error", func(t *testing.T) {
		rPipe, wPipe, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = wPipe.Close() }()

		dupFD, err := unix.Dup(int(rPipe.Fd()))
		_ = rPipe.Close()
		if err != nil {
			t.Fatalf("unix.Dup: %v", err)
		}
		defer func() { _ = unix.Close(dupFD) }()

		// Clear FD_CLOEXEC on dupFD first so we prove extractReceivedFDsMarkCloexec sets it!
		if _, err := unix.FcntlInt(uintptr(dupFD), unix.F_SETFD, 0); err != nil {
			t.Fatalf("clear FD_CLOEXEC: %v", err)
		}

		validCmsg := unix.UnixRights(dupFD)
		// Append a short trailing byte sequence (< CmsgLen(0)) to simulate a truncated second cmsg.
		truncatedTail := make([]byte, 0, len(validCmsg)+4)
		truncatedTail = append(truncatedTail, validCmsg...)
		truncatedTail = append(truncatedTail, 1, 2, 3, 4)

		fds, parseErr := extractReceivedFDsMarkCloexec(truncatedTail)
		if parseErr == nil {
			t.Fatal("expected error on trailing truncated cmsg fragment, got nil")
		}
		if len(fds) != 1 || fds[0] != dupFD {
			t.Fatalf("fds = %v, want [%d]", fds, dupFD)
		}
		flags, err := unix.FcntlInt(uintptr(dupFD), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("dupFD flags = 0x%x (err=%v), want FD_CLOEXEC set despite trailing error", flags, err)
		}
	})

	t.Run("recvFDs fails closed immediately on plain byte without SCM_RIGHTS", func(t *testing.T) {
		conn, peerFD := newPassengerFDChannel(t)
		defer func() { _ = unix.Close(peerFD) }()

		if _, err := unix.Write(peerFD, []byte{'X'}); err != nil {
			t.Fatalf("unix.Write plain byte: %v", err)
		}

		start := time.Now()
		fds, err := recvFDs(conn, 1)
		closeFDRange(fds)
		if err == nil || !strings.Contains(err.Error(), "expected ancillary file descriptor") {
			t.Fatalf("recvFDs on plain data = (%v, %v), want ancillary-fd error", fds, err)
		}
		if elapsed := time.Since(start); elapsed >= 2*time.Second {
			t.Fatalf("recvFDs spun for %s instead of failing immediately", elapsed)
		}
	})
}

// TestReviewPass2_M9_PassengerZombieShutdownReqsDrainEnvPolicyAndStdioFwd covers:
//   - M9a: wedged channel Close + SendRequest triggers MuxServer.Shutdown so no zombie master remains;
//   - M9b: handlePassengerSession drains reqs on early setup failure;
//   - M9c: applyPassengerEnvAndPTY enforces name syntax, NUL check, denylist, 32KiB, and 128-var limits;
//   - M9d: handlePassengerStdioFwd uses bounded dialSSHMux and aborts on early control-socket disconnect.
func TestReviewPass2_M9_PassengerZombieShutdownReqsDrainEnvPolicyAndStdioFwd(t *testing.T) {
	t.Run("wedged transport interrupt shuts down MuxServer instead of leaving zombie alive socket", assertPass2WedgedPassengerShutsDownMaster)
	t.Run("early passenger setup error drains session reqs channel", assertPass2EarlyPassengerErrorDrainsReqs)
	t.Run("applyPassengerEnvAndPTY enforces env validation denylist and caps", assertPass2PassengerEnvValidationAndDenylist)
	t.Run("handlePassengerStdioFwd bounds dial and watches control disconnect", assertPass2PassengerStdioFwdBoundsAndDisconnect)
}

func assertPass2WedgedPassengerShutsDownMaster(t *testing.T) {
	rootA, rootB := net.Pipe()
	defer func() {
		_ = rootA.Close()
		_ = rootB.Close()
	}()

	wedgedConn := &pass2WedgedTransportSSHConn{unblockOnTransportClose: make(chan struct{})}
	chans := make(chan cryptoSSH.NewChannel)
	close(chans)
	reqs := make(chan *cryptoSSH.Request)
	close(reqs)
	rawCli := cryptoSSH.NewClient(wedgedConn, chans, reqs)

	sockPath := filepath.Join(shortSocketDir(t), "wedged-master.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         rawCli,
		RootConn:          &pass2ClosingHookConn{Conn: rootA, ch: wedgedConn.unblockOnTransportClose},
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	srv.requestTimeout = 40 * time.Millisecond
	defer func() { _ = srv.Shutdown() }()
	go func() { _ = srv.Serve() }()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer func() { _ = clientConn.Close() }()
	if err := performClientMuxHandshake(clientConn); err != nil {
		t.Fatalf("performClientMuxHandshake: %v", err)
	}

	reqPayload := EncodeMuxNewSession(MuxNewSessionRequest{
		RequestID: 11,
		WantTTY:   true,
		TermType:  "xterm",
		Command:   "true",
	})
	if err := WriteMuxPacket(clientConn, MUX_C_NEW_SESSION, reqPayload); err != nil {
		t.Fatalf("WriteMuxPacket: %v", err)
	}
	sendSessionPipeFDs(t, clientConn)

	select {
	case <-srv.Wait():
	case <-time.After(sessionShutdownTimeout + 3*time.Second):
		t.Fatal("MuxServer remained alive as a zombie after wedged passenger transport interrupt")
	}

	if _, statErr := os.Lstat(sockPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected wedged master control socket %q to be unlinked, statErr=%v", sockPath, statErr)
	}
}

type pass2ClosingHookConn struct {
	net.Conn
	once sync.Once
	ch   chan struct{}
}

func (c *pass2ClosingHookConn) Close() error {
	c.once.Do(func() { close(c.ch) })
	return c.Conn.Close()
}

type pass2WedgedTransportSSHConn struct {
	dummyMuxGateConn
	unblockOnTransportClose chan struct{}
}

func (w *pass2WedgedTransportSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if name != "session" {
		return nil, nil, errors.New("unsupported channel")
	}
	reqs := make(chan *cryptoSSH.Request)
	ch := &pass2WedgedChannel{
		unblock: w.unblockOnTransportClose,
		reqs:    reqs,
	}
	return ch, reqs, nil
}

type pass2WedgedChannel struct {
	unblock   <-chan struct{}
	reqs      chan *cryptoSSH.Request
	closeOnce sync.Once
}

func (c *pass2WedgedChannel) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *pass2WedgedChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *pass2WedgedChannel) CloseWrite() error           { return nil }
func (c *pass2WedgedChannel) Stderr() io.ReadWriter       { return &nopRW{} }
func (c *pass2WedgedChannel) Close() error {
	// Block until underlying transport is interrupted, simulating a completely wedged peer/mux.
	<-c.unblock
	c.closeOnce.Do(func() { close(c.reqs) })
	return io.EOF
}
func (c *pass2WedgedChannel) SendRequest(string, bool, []byte) (bool, error) {
	<-c.unblock
	return false, io.EOF
}

func assertPass2EarlyPassengerErrorDrainsReqs(t *testing.T) {
	reqReplied := make(chan bool, 1)
	connMock := &pass2ReqsOnOpenSSHConn{reqReplied: reqReplied}
	chans := make(chan cryptoSSH.NewChannel)
	close(chans)
	reqs := make(chan *cryptoSSH.Request)
	close(reqs)
	rawCli := cryptoSSH.NewClient(connMock, chans, reqs)
	defer func() { _ = rawCli.Close() }()

	sockPath := filepath.Join(shortSocketDir(t), "drain-reqs.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         rawCli,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	defer func() { _ = srv.Shutdown() }()
	go func() { _ = srv.Serve() }()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer func() { _ = clientConn.Close() }()
	if err := performClientMuxHandshake(clientConn); err != nil {
		t.Fatalf("performClientMuxHandshake: %v", err)
	}

	// Trigger early failure in applyPassengerEnvAndPTY via invalid env variable name.
	reqPayload := EncodeMuxNewSession(MuxNewSessionRequest{
		RequestID: 21,
		Env:       []string{"INVALID-NAME=1"},
		Command:   "id",
	})
	if err := WriteMuxPacket(clientConn, MUX_C_NEW_SESSION, reqPayload); err != nil {
		t.Fatalf("WriteMuxPacket: %v", err)
	}
	sendSessionPipeFDs(t, clientConn)

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	pktType, _, err := ReadMuxPacket(clientConn)
	if err != nil || pktType != MUX_S_FAILURE {
		t.Fatalf("ReadMuxPacket = (0x%x, %v), want MUX_S_FAILURE", pktType, err)
	}

	select {
	case <-reqReplied:
	case <-time.After(2 * time.Second):
		t.Fatal("undrained session reqs channel leaked want-reply request on early passenger error")
	}
}

type pass2ReqsOnOpenSSHConn struct {
	dummyMuxGateConn
	reqReplied chan<- bool
}

func (c *pass2ReqsOnOpenSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if name != "session" {
		return nil, nil, errors.New("unsupported")
	}
	reqs := make(chan *cryptoSSH.Request)
	ch := &pass2RecordingEnvChannel{}
	go func() {
		defer close(reqs)
		// Push a server-initiated channel request into unbuffered reqs; only
		// DiscardRequests(reqs) in handlePassengerSession unblocks this send!
		reqs <- &cryptoSSH.Request{Type: "keepalive@openssh.com", WantReply: false}
		c.reqReplied <- true
	}()
	return ch, reqs, nil
}

type pass2RecordingEnvChannel struct {
	mu        sync.Mutex
	envs      []string
	reqs      chan *cryptoSSH.Request
	closeOnce sync.Once
}

func (c *pass2RecordingEnvChannel) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *pass2RecordingEnvChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *pass2RecordingEnvChannel) CloseWrite() error           { return nil }
func (c *pass2RecordingEnvChannel) Stderr() io.ReadWriter       { return &nopRW{} }
func (c *pass2RecordingEnvChannel) Close() error {
	c.closeOnce.Do(func() {
		if c.reqs != nil {
			close(c.reqs)
		}
	})
	return nil
}
func (c *pass2RecordingEnvChannel) SendRequest(reqType string, _ bool, payload []byte) (bool, error) {
	if reqType == "env" {
		var kv struct {
			Name  string
			Value string
		}
		if cryptoSSH.Unmarshal(payload, &kv) == nil {
			c.mu.Lock()
			c.envs = append(c.envs, kv.Name+"="+kv.Value)
			c.mu.Unlock()
		}
	}
	return true, nil
}

func assertPass2PassengerEnvValidationAndDenylist(t *testing.T) {
	log := &captureDebugLogger{}
	srv := &MuxServer{logger: log, requestTimeout: time.Second}

	// 1. Denylisted names are skipped while valid allowed names are deduplicated & sent.
	ch := &pass2RecordingEnvChannel{}
	var ttyFailed bool
	err := applyPassengerEnvAndPTY(srv, ch, MuxNewSessionRequest{
		Env: []string{
			"LD_PRELOAD=/tmp/evil.so",
			"XOPS_INTERNAL=secret",
			"GITHUB_TOKEN=ghp_123",
			"APP_MODE=staging",
			"APP_MODE=production",
			"LC_ALL=C",
		},
	}, &ttyFailed)
	if err != nil {
		t.Fatalf("applyPassengerEnvAndPTY valid+denylist: %v", err)
	}
	if len(ch.envs) != 2 || ch.envs[0] != "APP_MODE=production" || ch.envs[1] != "LC_ALL=C" {
		t.Fatalf("forwarded passenger envs = %v, want [APP_MODE=production LC_ALL=C]", ch.envs)
	}
	if !log.contains("LD_PRELOAD") {
		t.Fatal("expected debug log for blocked LD_PRELOAD")
	}

	// 2. Reject invalid variable names, NUL values, >32KiB entry, and >128 variables.
	manyVars := make([]string, MaxSessionEnvVars+1)
	for i := range manyVars {
		manyVars[i] = "VAR_" + strconv.Itoa(i) + "=1"
	}
	invalidCases := [][]string{
		{"NO_EQUALS"},
		{"1BAD=val"},
		{"BAD-NAME=val"},
		{"NUL_VAL=abc\x00def"},
		{"BIG=" + strings.Repeat("x", MaxSessionEnvEntryBytes)},
		manyVars,
	}
	for i, envList := range invalidCases {
		badCh := &pass2RecordingEnvChannel{}
		if err := applyPassengerEnvAndPTY(srv, badCh, MuxNewSessionRequest{Env: envList}, &ttyFailed); !errors.Is(err, ErrSSHOptionsValidation) {
			t.Fatalf("case %d: expected ErrSSHOptionsValidation, got %v (sent=%v)", i, err, badCh.envs)
		}
		if len(badCh.envs) != 0 {
			t.Fatalf("case %d: expected 0 env requests sent before validation failure, got %v", i, badCh.envs)
		}
	}
}

func assertPass2PassengerStdioFwdBoundsAndDisconnect(t *testing.T) {
	// Part A: Stalled direct-tcpip open times out via dialSSHMux (requestTimeout).
	stalledDialConn := &pass2StdioFwdSSHConn{stallOpen: true, unblock: make(chan struct{})}
	chans := make(chan cryptoSSH.NewChannel)
	close(chans)
	reqs := make(chan *cryptoSSH.Request)
	close(reqs)
	rawStalled := cryptoSSH.NewClient(stalledDialConn, chans, reqs)
	defer func() {
		close(stalledDialConn.unblock)
		_ = rawStalled.Close()
	}()

	sockStalled := filepath.Join(shortSocketDir(t), "stdio-stall.sock")
	srvStalled, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockStalled,
		SSHClient:         rawStalled,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	srvStalled.requestTimeout = 80 * time.Millisecond
	defer func() { _ = srvStalled.Shutdown() }()
	go func() { _ = srvStalled.Serve() }()

	cStalled, err := net.Dial("unix", sockStalled)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer func() { _ = cStalled.Close() }()
	if err := performClientMuxHandshake(cStalled); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := WriteMuxPacket(cStalled, MUX_C_NEW_STDIO_FWD, EncodeMuxNewStdioFwd(MuxNewStdioFwdRequest{
		RequestID:   31,
		ConnectHost: "127.0.0.1",
		ConnectPort: 8080,
	})); err != nil {
		t.Fatalf("WriteMuxPacket: %v", err)
	}
	sendStdioPipeFDs(t, cStalled)

	_ = cStalled.SetReadDeadline(time.Now().Add(2 * time.Second))
	pktType, _, err := ReadMuxPacket(cStalled)
	if err != nil || pktType != MUX_S_FAILURE {
		t.Fatalf("stalled stdio fwd ReadMuxPacket = (0x%x, %v), want MUX_S_FAILURE", pktType, err)
	}

	// Part B: Early control-socket disconnect closes remote stream and drops ActiveSessions to 0.
	remoteClosed := make(chan struct{})
	liveDialConn := &pass2StdioFwdSSHConn{remoteClosed: remoteClosed, unblock: make(chan struct{})}
	chans2 := make(chan cryptoSSH.NewChannel)
	close(chans2)
	reqs2 := make(chan *cryptoSSH.Request)
	close(reqs2)
	rawLive := cryptoSSH.NewClient(liveDialConn, chans2, reqs2)
	defer func() {
		close(liveDialConn.unblock)
		_ = rawLive.Close()
	}()

	sockLive := filepath.Join(shortSocketDir(t), "stdio-disc.sock")
	srvLive, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockLive,
		SSHClient:         rawLive,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer(live): %v", err)
	}
	defer func() { _ = srvLive.Shutdown() }()
	go func() { _ = srvLive.Serve() }()

	cLive, err := net.Dial("unix", sockLive)
	if err != nil {
		t.Fatalf("net.Dial(live): %v", err)
	}
	if err := performClientMuxHandshake(cLive); err != nil {
		t.Fatalf("handshake(live): %v", err)
	}
	if err := WriteMuxPacket(cLive, MUX_C_NEW_STDIO_FWD, EncodeMuxNewStdioFwd(MuxNewStdioFwdRequest{
		RequestID:   32,
		ConnectHost: "127.0.0.1",
		ConnectPort: 9090,
	})); err != nil {
		t.Fatalf("WriteMuxPacket(live): %v", err)
	}
	inR, inW, outR, outW := sendKeepOpenStdioPipes(t, cLive)
	defer func() {
		_ = inR.Close()
		_ = inW.Close()
		_ = outR.Close()
		_ = outW.Close()
	}()

	_ = cLive.SetReadDeadline(time.Now().Add(2 * time.Second))
	pktType, _, err = ReadMuxPacket(cLive)
	if err != nil || pktType != MUX_S_SESSION_OPENED {
		t.Fatalf("live stdio fwd ReadMuxPacket = (0x%x, %v), want MUX_S_SESSION_OPENED", pktType, err)
	}

	// Disconnect the control socket while both stdio pipes remain open!
	_ = cLive.Close()

	select {
	case <-remoteClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("remote direct-tcpip stream was not closed after passenger control-socket disconnect")
	}

	deadline := time.Now().Add(2 * time.Second)
	for srvLive.ActiveSessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := srvLive.ActiveSessions(); got != 0 {
		t.Fatalf("srvLive.ActiveSessions() = %d after control disconnect, want 0", got)
	}
}

func sendStdioPipeFDs(t *testing.T, conn net.Conn) {
	t.Helper()
	uc := conn.(*net.UnixConn)
	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		r, w, pErr := os.Pipe()
		if pErr != nil {
			t.Fatal(pErr)
		}
		var sendErr error
		_ = raw.Write(func(fd uintptr) bool {
			sendErr = unix.Sendmsg(int(fd), []byte{0}, unix.UnixRights(int(r.Fd())), nil, 0)
			return true
		})
		_ = r.Close()
		_ = w.Close()
		if sendErr != nil {
			t.Fatalf("Sendmsg stdio fd: %v", sendErr)
		}
	}
}

func sendKeepOpenStdioPipes(t *testing.T, conn net.Conn) (*os.File, *os.File, *os.File, *os.File) {
	t.Helper()
	uc := conn.(*net.UnixConn)
	raw, err := uc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_ = inR.Close()
		_ = inW.Close()
		t.Fatal(err)
	}
	for _, fdToSend := range []int{int(inR.Fd()), int(outW.Fd())} {
		var sendErr error
		_ = raw.Write(func(fd uintptr) bool {
			sendErr = unix.Sendmsg(int(fd), []byte{0}, unix.UnixRights(fdToSend), nil, 0)
			return true
		})
		if sendErr != nil {
			t.Fatalf("Sendmsg keep-open stdio fd: %v", sendErr)
		}
	}
	return inR, inW, outR, outW
}

type pass2StdioFwdSSHConn struct {
	dummyMuxGateConn
	stallOpen    bool
	unblock      chan struct{}
	remoteClosed chan struct{}
}

func (c *pass2StdioFwdSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if name != "direct-tcpip" {
		return nil, nil, errors.New("unsupported channel")
	}
	if c.stallOpen {
		<-c.unblock
		return nil, nil, errors.New("stalled open canceled")
	}
	reqs := make(chan *cryptoSSH.Request)
	ch := &pass2BlockingStreamChannel{
		closed:   make(chan struct{}),
		onClosed: c.remoteClosed,
		reqs:     reqs,
	}
	return ch, reqs, nil
}

type pass2BlockingStreamChannel struct {
	closeOnce sync.Once
	closed    chan struct{}
	onClosed  chan struct{}
	reqs      chan *cryptoSSH.Request
}

func (c *pass2BlockingStreamChannel) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}
func (c *pass2BlockingStreamChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *pass2BlockingStreamChannel) CloseWrite() error           { return nil }
func (c *pass2BlockingStreamChannel) Stderr() io.ReadWriter       { return &nopRW{} }
func (c *pass2BlockingStreamChannel) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		close(c.reqs)
		if c.onClosed != nil {
			close(c.onClosed)
		}
	})
	return nil
}
func (c *pass2BlockingStreamChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}

// TestReviewPass2_H6_And_L2_PTYEscapeDisconnectAndResumeTermios verifies on real PTYs:
//   - H6: RunInteractivePlanWithIO and RunInteractiveWithSudoExecutionIO return
//     ErrEscapeDisconnect (exit status 255) on <Enter>~. instead of context.Canceled;
//   - L2: enterTerminalRawMode updates saved termios state on ~^Z resume and
//     non-fatal SuspendProcess failure prints [suspend failed: ...] without closing stdin.
func TestReviewPass2_H6_And_L2_PTYEscapeDisconnectAndResumeTermios(t *testing.T) {
	master1, slave1 := openPass2LinuxPTY(t)
	assertPass2PlanEscapeDisconnect(t, master1, slave1)

	master2, slave2 := openPass2LinuxPTY(t)
	assertPass2SudoExecEscapeDisconnect(t, master2, slave2)

	master3, slave3 := openPass2LinuxPTY(t)
	assertPass2PTYResumeUpdatesTermiosAndSurvivesSuspendFailure(t, master3, slave3)
}

func openPass2LinuxPTY(t *testing.T) (master *os.File, slave *os.File) {
	t.Helper()
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" && runtime.GOARCH != "386" && runtime.GOARCH != "riscv64") {
		t.Skipf("Linux /dev/ptmx PTY test skipped on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	const (
		linuxTIOCSPTLCK = 0x40045431
		linuxTIOCGPTN   = 0x80045430
	)
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0600)
	if err != nil {
		t.Fatalf("open /dev/ptmx: %v", err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(int(master.Fd()), linuxTIOCSPTLCK, 0); err != nil {
		t.Fatalf("TIOCSPTLCK: %v", err)
	}
	ptsNum, err := unix.IoctlGetInt(int(master.Fd()), linuxTIOCGPTN)
	if err != nil {
		t.Fatalf("TIOCGPTN: %v", err)
	}
	slave, err = os.OpenFile("/dev/pts/"+strconv.Itoa(ptsNum), os.O_RDWR|unix.O_NOCTTY, 0600)
	if err != nil {
		t.Fatalf("open /dev/pts/%d: %v", ptsNum, err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

func assertPass2PlanEscapeDisconnect(t *testing.T, master, slave *os.File) {
	t.Helper()
	execReady := make(chan struct{}, 1)
	rawCli, cleanup := startPass2InteractivePTYServer(t, execReady, nil)
	defer cleanup()

	cli := NewTestClientWithRaw(rawCli, ConnectionConfig{Address: "plan-pty.example"})
	cli.handshakeTimeout = time.Second

	plan, err := PlanCommand("top", CommandOptions{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("PlanCommand: %v", err)
	}

	var stderrBuf bytes.Buffer
	ctx := t.Context()
	done := make(chan error, 1)
	go func() {
		done <- cli.RunInteractivePlanWithIO(ctx, plan, InteractiveIO{
			Stdin:  slave,
			Stdout: slave,
			Stderr: &pass2ContextBuffer{buf: &stderrBuf},
		})
	}()

	<-execReady
	waitPass2RawMode(slave)

	if _, err := master.Write([]byte{'\r', '~', '.'}); err != nil {
		t.Fatalf("master.Write(~.): %v", err)
	}

	select {
	case runErr := <-done:
		if !errors.Is(runErr, ErrEscapeDisconnect) {
			t.Fatalf("RunInteractivePlanWithIO on ~. returned %v, want ErrEscapeDisconnect (not context.Canceled!)", runErr)
		}
		if errors.Is(runErr, context.Canceled) {
			t.Fatalf("RunInteractivePlanWithIO must not wrap context.Canceled on ~.: %v", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunInteractivePlanWithIO hung after ~.")
	}
}

func assertPass2SudoExecEscapeDisconnect(t *testing.T, master, slave *os.File) {
	t.Helper()
	execReady := make(chan struct{}, 1)
	rawCli, cleanup := startPass2InteractivePTYServer(t, execReady, nil)
	defer cleanup()

	cli := NewTestClientWithRaw(rawCli, ConnectionConfig{
		Address:  "sudo-pty.example",
		SudoMode: SudoModeRoot,
	})
	cli.handshakeTimeout = time.Second

	var stderrBuf bytes.Buffer
	ctx := t.Context()
	done := make(chan error, 1)
	go func() {
		done <- cli.RunInteractiveWithSudoExecutionIO(
			ctx,
			"top",
			&ExecutionConfig{Interpreter: InterpreterSh, LaunchDialect: LaunchPOSIX},
			InteractiveIO{
				Stdin:  slave,
				Stdout: slave,
				Stderr: &pass2ContextBuffer{buf: &stderrBuf},
			},
		)
	}()

	<-execReady
	waitPass2RawMode(slave)

	if _, err := master.Write([]byte{'\r', '~', '.'}); err != nil {
		t.Fatalf("master.Write(~.): %v", err)
	}

	select {
	case runErr := <-done:
		if !errors.Is(runErr, ErrEscapeDisconnect) {
			t.Fatalf("RunInteractiveWithSudoExecutionIO on ~. returned %v, want ErrEscapeDisconnect", runErr)
		}
		if errors.Is(runErr, context.Canceled) {
			t.Fatalf("RunInteractiveWithSudoExecutionIO must not return context.Canceled on ~.: %v", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunInteractiveWithSudoExecutionIO hung after ~.")
	}
}

func assertPass2PTYResumeUpdatesTermiosAndSurvivesSuspendFailure(t *testing.T, master, slave *os.File) {
	t.Helper()
	const (
		linuxTCGETS = 0x5401
		linuxTCSETS = 0x5402
	)
	origTios, err := unix.IoctlGetTermios(int(slave.Fd()), linuxTCGETS)
	if err != nil {
		t.Fatalf("TCGETS initial: %v", err)
	}
	wantPostExitEchoOff := origTios.Lflag &^ unix.ECHO

	shellReady := make(chan struct{}, 1)
	remoteStdinCh := make(chan string, 1)
	rawCli, cleanup := startPass2InteractivePTYServer(t, shellReady, remoteStdinCh)
	defer cleanup()

	var suspendCall atomic.Int32
	cli := NewTestClientWithRaw(rawCli, ConnectionConfig{Address: "resume-pty.example"})
	cli.handshakeTimeout = time.Second
	cli.environment = sanitizeEnvironment(Environment{
		SuspendProcess: func() error {
			call := suspendCall.Add(1)
			if call == 1 {
				// Simulate parent shell toggling stty -echo while xops was suspended!
				cur, gErr := unix.IoctlGetTermios(int(slave.Fd()), linuxTCGETS)
				if gErr == nil {
					cur.Lflag &^= unix.ECHO
					_ = unix.IoctlSetTermios(int(slave.Fd()), linuxTCSETS, cur)
				}
				return nil
			}
			// Second ~^Z: simulate sandboxed SIGTSTP failure (EPERM) while raw mode succeeds!
			return errors.New("kill SIGTSTP: operation not permitted")
		},
	})

	var stderrBuf bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- cli.ShellWithIO(t.Context(), InteractiveIO{
			Stdin:  slave,
			Stdout: slave,
			Stderr: &pass2ContextBuffer{buf: &stderrBuf},
		})
	}()

	<-shellReady
	waitPass2RawMode(slave)

	// 1st ~^Z (mutates cooked termios ECHO bit), 2nd ~^Z (fails with EPERM), then "ping\n" (proves stdin stayed alive!), then ~. to exit.
	if _, err := master.Write([]byte{'~', 0x1a, '~', 0x1a, 'p', 'i', 'n', 'g', '\n'}); err != nil {
		t.Fatalf("master.Write suspend+ping: %v", err)
	}

	select {
	case gotRemote := <-remoteStdinCh:
		if gotRemote != "ping\n" {
			t.Fatalf("remote shell received %q after failed ~^Z, want %q", gotRemote, "ping\n")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("remote stdin closed or stalled after non-fatal ~^Z suspend error")
	}

	if _, err := master.Write([]byte{'~', '.'}); err != nil {
		t.Fatalf("master.Write(~.): %v", err)
	}
	select {
	case shellErr := <-done:
		if !errors.Is(shellErr, ErrEscapeDisconnect) {
			t.Fatalf("ShellWithIO returned %v, want ErrEscapeDisconnect", shellErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ShellWithIO hung on ~.")
	}

	afterTios, err := unix.IoctlGetTermios(int(slave.Fd()), linuxTCGETS)
	if err != nil {
		t.Fatalf("TCGETS after exit: %v", err)
	}
	if afterTios.Lflag != wantPostExitEchoOff {
		t.Fatalf("final restored Lflag = 0x%x, want updated resume Lflag 0x%x (stale initial Lflag was 0x%x)",
			afterTios.Lflag, wantPostExitEchoOff, origTios.Lflag)
	}
	if !strings.Contains(stderrBuf.String(), "[suspend failed: kill SIGTSTP: operation not permitted]") {
		t.Fatalf("expected [suspend failed: ...] warning in stderr, got %q", stderrBuf.String())
	}
}

func waitPass2RawMode(slave *os.File) {
	const linuxTCGETS = 0x5401
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cur, err := unix.IoctlGetTermios(int(slave.Fd()), linuxTCGETS); err == nil && cur.Lflag&unix.ICANON == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type pass2ContextBuffer struct {
	mu  sync.Mutex
	buf *bytes.Buffer
}

func (w *pass2ContextBuffer) WriteContext(ctx context.Context, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *pass2ContextBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func startPass2InteractivePTYServer(
	t *testing.T,
	ready chan<- struct{},
	firstLineOut chan<- string,
) (*cryptoSSH.Client, func()) {
	t.Helper()
	return startPass2InMemorySSHServer(t, func(req *cryptoSSH.Request, ch cryptoSSH.Channel) {
		switch req.Type {
		case "pty-req", "window-change", "env":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec", "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			select {
			case ready <- struct{}{}:
			default:
			}
			if firstLineOut != nil {
				go func() {
					var line bytes.Buffer
					var b [1]byte
					for {
						n, err := ch.Read(b[:])
						if n > 0 {
							line.WriteByte(b[0])
							if b[0] == '\n' {
								select {
								case firstLineOut <- line.String():
								default:
								}
								return
							}
						}
						if err != nil {
							return
						}
					}
				}()
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	})
}
