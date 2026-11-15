//go:build linux || darwin || freebsd

package ssh

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	logger "github.com/wentf9/xops-cli/core/log"
	cryptoSSH "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

var muxTempSeq atomic.Uint64

func nextMuxTempToken() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.BigEndian.Uint32(b[:]) & 0xffff
	}
	seq := muxTempSeq.Add(1)
	return (uint32(os.Getpid())&0xff)<<8 | uint32(seq&0xff)
}

func disableUnixListenerUnlinkOnClose(listener net.Listener) {
	if unixLn, ok := listener.(*net.UnixListener); ok {
		unixLn.SetUnlinkOnClose(false)
	}
}

func isAddressAlreadyInUse(err error) bool {
	if err == nil {
		return false
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) && (sysErr == syscall.EADDRINUSE || sysErr == syscall.EEXIST) {
		return true
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "address already in use") || strings.Contains(errStr, "file exists")
}

func bindAndLinkSocket(targetPath string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
		return nil, fmt.Errorf("create socket directory failed: %w", err)
	}

	maxPathLen := MaxControlPathLength() - 1 // 107 on Linux, 103 on Darwin/BSD
	targetLen := len(targetPath)
	suffixBudget := maxPathLen - targetLen
	dir := filepath.Dir(targetPath)
	dirBudget := maxPathLen - (len(dir) + 1)

	useSuffixTemp := suffixBudget >= 8
	useDirTemp := !useSuffixTemp && dirBudget >= 8

	if !useSuffixTemp && !useDirTemp {
		// Fallback: Direct bind on targetPath when path length budget is exhausted.
		listener, err := net.Listen("unix", targetPath)
		if err != nil {
			if isAddressAlreadyInUse(err) {
				return nil, fmt.Errorf("%w: %s", ErrMasterAlreadyExists, targetPath)
			}
			return nil, fmt.Errorf("listen on control socket failed: %w", err)
		}
		disableUnixListenerUnlinkOnClose(listener)
		if err := os.Chmod(targetPath, 0600); err != nil {
			_ = listener.Close()
			_ = os.Remove(targetPath)
			return nil, fmt.Errorf("chmod control socket failed: %w", err)
		}
		return listener, nil
	}

	// Linking Strategy: Bind tempPath -> Chmod 0600 -> Atomic Link to targetPath -> Unlink tempPath.
	var (
		listener net.Listener
		tempPath string
		err      error
	)
	for attempt := 0; attempt < 4; attempt++ {
		val := nextMuxTempToken()
		if useSuffixTemp {
			tempPath = fmt.Sprintf("%s.m%04x.t", targetPath, val)
		} else {
			tempPath = filepath.Join(dir, fmt.Sprintf(".m%04x.t", val))
		}
		listener, err = net.Listen("unix", tempPath)
		if err == nil {
			break
		}
		if !isAddressAlreadyInUse(err) {
			return nil, fmt.Errorf("listen on temp control socket failed: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("listen on temp control socket failed: %w", err)
	}
	disableUnixListenerUnlinkOnClose(listener)
	defer func() {
		_ = os.Remove(tempPath)
	}()

	// Enforce 0600 permissions without mutating process-global umask.
	if err := os.Chmod(tempPath, 0600); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("chmod temp control socket failed: %w", err)
	}

	err = os.Link(tempPath, targetPath)
	if err != nil {
		if errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EEXIST) {
			if retryReplaceStaleSocketLink(tempPath, targetPath) {
				return listener, nil
			}
			_ = listener.Close()
			return nil, fmt.Errorf("%w: %s", ErrMasterAlreadyExists, targetPath)
		}
		_ = listener.Close()
		return nil, fmt.Errorf("link control socket failed: %w", err)
	}

	return listener, nil
}

func retryReplaceStaleSocketLink(tempPath, targetPath string) bool {
	origFi, statErr := os.Lstat(targetPath)
	if statErr != nil || !isControlSocketFileInfo(origFi) {
		return false
	}
	probeConn, probeErr := net.DialTimeout("unix", targetPath, 200*time.Millisecond)
	if probeErr == nil {
		_ = probeConn.Close()
		return false
	}
	if !isConnectionRefused(probeErr) {
		return false
	}
	// Re-verify SameFile before unlinking so a concurrent new master is never clobbered.
	currFi, currErr := os.Lstat(targetPath)
	if currErr != nil || !isControlSocketFileInfo(currFi) || !os.SameFile(origFi, currFi) {
		return false
	}
	_ = os.Remove(targetPath)
	return os.Link(tempPath, targetPath) == nil
}

func checkPeerUID(conn net.Conn, expectedUID uint32) error {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return fmt.Errorf("connection does not support raw socket control")
	}
	rawConn, err := sc.SyscallConn()
	if err != nil {
		return err
	}

	var peerUID uint32
	var credErr error
	err = rawConn.Control(func(fd uintptr) {
		peerUID, credErr = getPeerUID(int(fd))
	})
	if err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}

	if peerUID != expectedUID && peerUID != 0 {
		return fmt.Errorf("%w: peer UID %d does not match expected UID %d", ErrUnauthorizedPeer, peerUID, expectedUID)
	}
	return nil
}

// localPeerUID reports the effective local user used to validate a control
// socket endpoint.
func localPeerUID() uint32 {
	euid := os.Geteuid()
	if euid < 0 {
		return 0
	}
	return uint32(euid)
}

func handlePassengerSession(s *MuxServer, conn net.Conn, reqID uint32, payload []byte) error {
	if !s.canAdmitNewSession() {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	if err := s.authorize("passenger session"); err != nil {
		return sendPermissionDenied(conn, reqID, err.Error())
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return sendFailure(conn, reqID, "passenger mode requires unix domain socket")
	}

	files, err := recvFiles(unixConn, "passenger-session", "stdin", "stdout", "stderr")
	if err != nil {
		return sendFailure(conn, reqID, fmt.Sprintf("receive session file descriptors failed: %v", err))
	}
	// Exactly one owner: the received descriptors belong to these files, so they
	// must never be closed again as raw descriptors. A second unix.Close on the
	// same number can hit an unrelated descriptor a concurrent goroutine reused.
	defer closeFiles(files)

	req, err := DecodeMuxNewSession(payload)
	if err != nil {
		return sendFailure(conn, reqID, fmt.Sprintf("malformed new session request: %v", err))
	}

	if !s.addActiveSession() {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	defer s.removeActiveSession()

	s.trackStream(conn)
	defer s.untrackStream(conn)

	ch, reqs, err := s.sshClient.OpenChannel("session", nil)
	if err != nil {
		return sendFailure(conn, reqID, fmt.Sprintf("open ssh session failed: %v", err))
	}
	handoffReqs := false
	defer func() {
		if !handoffReqs {
			go discardAbortedChannelRequests(s.baseContext(), reqs)
		}
	}()
	releasePassengerAgent, err := enablePassengerAgentForward(s, ch, req.WantAgent)
	defer releasePassengerAgent()
	defer func() { _ = ch.Close() }()
	if err != nil {
		return sendFailure(conn, reqID, fmt.Sprintf("agent forward request failed: %v", err))
	}

	var ttyAllocFailed bool
	if err := applyPassengerEnvAndPTY(s, ch, req, &ttyAllocFailed); err != nil {
		return sendFailure(conn, reqID, err.Error())
	}

	if err := startPassengerChannel(s, ch, req); err != nil {
		return sendFailure(conn, reqID, err.Error())
	}

	const sessionID uint32 = 1
	if err := sendSessionOpened(conn, reqID, sessionID); err != nil {
		return err
	}
	if ttyAllocFailed {
		if err := sendTTYAllocFail(conn, sessionID); err != nil {
			return err
		}
	}

	handoffReqs = true
	exitCode := runPassengerChannelIO(conn, ch, reqs, files)
	return sendExitMessage(conn, sessionID, exitCode)
}

func applyPassengerEnvAndPTY(s *MuxServer, ch cryptoSSH.Channel, req MuxNewSessionRequest, ttyAllocFailed *bool) error {
	if len(req.Env) > MaxSessionEnvVars {
		return fmt.Errorf("%w: passenger session environment exceeds maximum of %d variables", ErrSSHOptionsValidation, MaxSessionEnvVars)
	}
	envAcc := newSessionEnvAccumulator()
	for _, env := range req.Env {
		k, v, ok := strings.Cut(env, "=")
		if !ok || !isValidEnvVarName(k) {
			return fmt.Errorf("%w: invalid passenger environment variable %q", ErrSSHOptionsValidation, env)
		}
		if strings.ContainsRune(v, 0) {
			return fmt.Errorf("%w: passenger environment variable %q contains NUL byte", ErrSSHOptionsValidation, k)
		}
		if len(k)+1+len(v) > MaxSessionEnvEntryBytes {
			return fmt.Errorf("%w: passenger environment variable %q exceeds %d bytes", ErrSSHOptionsValidation, k, MaxSessionEnvEntryBytes)
		}
		if isDeniedSendEnvName(k) {
			s.getLogger().Debugf("mux: passenger env variable %q blocked by denylist", k)
			continue
		}
		if err := envAcc.upsert(EnvVar{Name: k, Value: v}); err != nil {
			return err
		}
	}
	for _, ev := range envAcc.resolved {
		envPayload := cryptoSSH.Marshal(struct {
			Name  string
			Value string
		}{Name: ev.Name, Value: ev.Value})
		accepted, envErr := s.sendBoundedPassengerRequest(ch, "env", envPayload)
		if envErr != nil {
			return fmt.Errorf("set env %q failed: %w", ev.Name, envErr)
		}
		if !accepted {
			s.getLogger().Debugf("mux: server rejected env variable %q for passenger session", ev.Name)
		}
	}
	if !req.WantTTY {
		return nil
	}
	termType := req.TermType
	if termType == "" {
		termType = "xterm"
	}
	ptyReq := struct {
		Term     string
		Columns  uint32
		Rows     uint32
		Width    uint32
		Height   uint32
		Modelist string
	}{
		Term:     termType,
		Columns:  80,
		Rows:     24,
		Width:    640,
		Height:   480,
		Modelist: "\x00",
	}
	accepted, ptyErr := s.sendBoundedPassengerRequest(ch, "pty-req", cryptoSSH.Marshal(ptyReq))
	if ptyErr != nil {
		return fmt.Errorf("pty-req failed: %w", ptyErr)
	}
	if !accepted {
		*ttyAllocFailed = true
	}
	return nil
}

type muxTransportInterruptConn struct {
	net.Conn
	onClose func()
}

func (c *muxTransportInterruptConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

func (s *MuxServer) sendBoundedPassengerRequest(ch cryptoSSH.Channel, reqType string, payload []byte) (bool, error) {
	ctx := context.Background()
	if s != nil && s.serverCtx != nil {
		ctx = s.serverCtx
	}
	var (
		sshCli      *cryptoSSH.Client
		root        net.Conn
		timeout     time.Duration
		log         logger.DebugLogger
		interrupted atomic.Bool
	)
	if s != nil {
		sshCli = s.sshClient
		root = s.rootConn
		timeout = s.requestTimeout
		log = s.logger
	}
	helper := &Client{
		sshClient: sshCli,
		rootConn: &muxTransportInterruptConn{
			Conn:    root,
			onClose: func() { interrupted.Store(true) },
		},
		handshakeTimeout: timeout,
		logger:           log,
	}
	accepted, err := helper.sendBoundedChannelRequest(ctx, ch, reqType, payload, false)
	if s != nil && interrupted.Load() {
		_ = s.Shutdown()
	}
	return accepted, err
}

func enablePassengerAgentForward(s *MuxServer, ch cryptoSSH.Channel, wantAgent bool) (func(), error) {
	if !wantAgent {
		return func() {}, nil
	}
	if !s.allowAgentForward || s.agentSocket == "" || s.dialAgent == nil {
		s.getLogger().Debugf("mux: ignoring passenger WantAgent request because master AllowAgentForward is disabled")
		return func() {}, nil
	}
	router, err := getOrCreateAgentRouter(s.sshClient)
	if err != nil {
		s.getLogger().Debugf("mux: failed to initialize agent router for passenger session: %v", err)
		return func() {}, nil
	}
	lease, err := router.acquireLocalLease(s.serverCtx, s.agentSocket, s.dialAgent, s.getLogger())
	if err != nil {
		return func() {}, nil
	}
	accepted, reqErr := s.sendBoundedPassengerRequest(ch, agentForwardRequestType, nil)
	if reqErr != nil {
		lease.Release()
		return func() {}, reqErr
	}
	if !accepted {
		lease.Release()
		s.getLogger().Debugf("mux: server rejected %s for passenger session", agentForwardRequestType)
		return func() {}, nil
	}
	return lease.Release, nil
}

func startPassengerChannel(s *MuxServer, ch cryptoSSH.Channel, req MuxNewSessionRequest) error {
	switch {
	case req.Subsystem:
		payload := cryptoSSH.Marshal(struct{ Subsystem string }{Subsystem: req.Command})
		accepted, err := s.sendBoundedPassengerRequest(ch, "subsystem", payload)
		if err != nil {
			return fmt.Errorf("subsystem failed: %w", err)
		}
		if !accepted {
			return fmt.Errorf("subsystem %q request rejected", req.Command)
		}
	case req.Command == "":
		accepted, err := s.sendBoundedPassengerRequest(ch, "shell", nil)
		if err != nil {
			return fmt.Errorf("shell failed: %w", err)
		}
		if !accepted {
			return errors.New("shell request rejected")
		}
	default:
		payload := cryptoSSH.Marshal(struct{ Command string }{Command: req.Command})
		accepted, err := s.sendBoundedPassengerRequest(ch, "exec", payload)
		if err != nil {
			return fmt.Errorf("start command failed: %w", err)
		}
		if !accepted {
			return errors.New("exec request rejected")
		}
	}
	return nil
}

// copyFromPollableFD copies bytes from a received passenger descriptor (which
// may be a blocking TTY or pipe without O_NONBLOCK) into dst until EOF or until
// stop is closed. Using unix.Poll with a private wakeup pipe avoids both:
//  1. mutating O_NONBLOCK on a shared open file description (which would corrupt
//     the caller's parent shell TTY), and
//  2. blocking inside a raw read() syscall that os.File.Close() cannot interrupt.
func copyFromPollableFD(dst io.Writer, src *os.File, stop <-chan struct{}) error {
	rawConn, err := src.SyscallConn()
	if err != nil {
		_, copyErr := io.Copy(dst, src)
		return copyErr
	}

	var wakePipe [2]int
	if err := unix.Pipe(wakePipe[:]); err != nil {
		_, copyErr := io.Copy(dst, src)
		return copyErr
	}
	unix.CloseOnExec(wakePipe[0])
	unix.CloseOnExec(wakePipe[1])
	_ = unix.SetNonblock(wakePipe[0], true)
	_ = unix.SetNonblock(wakePipe[1], true)

	var closeWakeWrite sync.Once
	triggerWake := func() {
		closeWakeWrite.Do(func() {
			_ = unix.Close(wakePipe[1])
		})
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-stop:
			triggerWake()
		case <-done:
		}
	}()
	defer func() {
		close(done)
		triggerWake()
		_ = unix.Close(wakePipe[0])
	}()

	buf := make([]byte, 32*1024)
	var copyErr error
	ctrlErr := rawConn.Control(func(fd uintptr) {
		srcFD := int(fd)
		for {
			pfds := []unix.PollFd{
				{Fd: int32(srcFD), Events: unix.POLLIN},
				{Fd: int32(wakePipe[0]), Events: unix.POLLIN},
			}
			_, pollErr := unix.Poll(pfds, -1)
			if pollErr != nil {
				if errors.Is(pollErr, syscall.EINTR) {
					continue
				}
				copyErr = pollErr
				return
			}
			if pfds[1].Revents != 0 {
				return
			}
			if pfds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) == 0 {
				continue
			}
			n, readErr := unix.Read(srcFD, buf)
			if n > 0 {
				if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
					copyErr = writeErr
					return
				}
			}
			if readErr != nil {
				if errors.Is(readErr, syscall.EINTR) || errors.Is(readErr, syscall.EAGAIN) {
					continue
				}
				copyErr = readErr
				return
			}
			if n == 0 {
				return
			}
		}
	})
	if copyErr != nil {
		return copyErr
	}
	return ctrlErr
}

func runPassengerChannelIO(conn net.Conn, ch cryptoSSH.Channel, reqs <-chan *cryptoSSH.Request, files []*os.File) uint32 {
	stdinFile, stdoutFile, stderrFile := files[0], files[1], files[2]

	var (
		exitCode atomic.Uint32
		hasExit  atomic.Bool
	)
	exitCode.Store(255)

	reqsDone := make(chan struct{})
	go func() {
		defer close(reqsDone)
		for r := range reqs {
			recognized := false
			switch r.Type {
			case "exit-status":
				var status struct{ Status uint32 }
				if err := cryptoSSH.Unmarshal(r.Payload, &status); err == nil {
					exitCode.Store(status.Status)
					hasExit.Store(true)
					recognized = true
				}
			case "exit-signal":
				var sig struct {
					Signal     string
					CoreDumped bool
					Error      string
					Lang       string
				}
				if err := cryptoSSH.Unmarshal(r.Payload, &sig); err == nil {
					if !hasExit.Load() {
						exitCode.Store(255)
						hasExit.Store(true)
					}
					recognized = true
				}
			}
			if r.WantReply {
				_ = r.Reply(recognized, nil)
			}
		}
	}()

	var outWG sync.WaitGroup
	outWG.Add(2)
	go func() {
		defer outWG.Done()
		_, _ = io.Copy(stdoutFile, ch)
	}()
	go func() {
		defer outWG.Done()
		_, _ = io.Copy(stderrFile, ch.Stderr())
	}()

	stopStdin := make(chan struct{})
	var stopStdinOnce sync.Once
	cancelStdin := func() { stopStdinOnce.Do(func() { close(stopStdin) }) }

	stdinDone := make(chan struct{})
	go func() {
		defer close(stdinDone)
		_ = copyFromPollableFD(ch, stdinFile, stopStdin)
		_ = ch.CloseWrite()
	}()

	outDone := make(chan struct{})
	go func() {
		outWG.Wait()
		<-reqsDone
		close(outDone)
	}()

	// Watch the control socket while the remote channel runs: if the passenger
	// client terminates early (closing conn), abort the remote channel so neither
	// the remote process nor the copy workers leak.
	connClosed := make(chan struct{})
	var stopConnWatch func() bool
	if d, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		go func() {
			defer close(connClosed)
			var buf [1]byte
			_, _ = conn.Read(buf[:])
		}()
		stopConnWatch = func() bool {
			_ = d.SetReadDeadline(time.Now())
			<-connClosed
			_ = d.SetReadDeadline(time.Time{})
			return true
		}
	} else {
		stopConnWatch = func() bool { return false }
	}

	select {
	case <-outDone:
		stopConnWatch()
	case <-connClosed:
		cancelStdin()
		_ = ch.Close()
		<-stdinDone
		closeFiles(files)
		<-outDone
		return exitCode.Load()
	}

	// Wake the stdin poller and close inherited descriptors before sending
	// MUX_S_EXIT_MESSAGE so the passenger client sees EOF on its stdout/stderr
	// pipes and our local stdin reader unblocks immediately even when the caller
	// passed a blocking TTY or pipe descriptor.
	cancelStdin()
	<-stdinDone
	_ = stdoutFile.Close()
	_ = stderrFile.Close()
	_ = stdinFile.Close()
	_ = ch.Close()

	if !hasExit.Load() {
		return 0
	}
	return exitCode.Load()
}

func resolvePassengerStdioFwdTarget(s *MuxServer, payload []byte) (dialNetwork, targetAddr, errMsg string) {
	fwdReq, err := DecodeMuxNewStdioFwd(payload)
	if err != nil {
		return "", "", fmt.Sprintf("malformed stdio fwd request: %v", err)
	}
	connectHost := normalizeMuxForwardHost(fwdReq.ConnectHost, fwdReq.ConnectPort)
	if fwdReq.ConnectPort == MUX_SPECIAL_PORT_UNIX {
		if strings.TrimSpace(connectHost) == "" {
			return "", "", "invalid stdio forward streamlocal socket path: path cannot be empty"
		}
		return "unix", connectHost, ""
	}
	if connectHost == "" {
		return "", "", "invalid stdio forward target host: host cannot be empty"
	}
	if fwdReq.ConnectPort < 1 || fwdReq.ConnectPort > 65535 {
		return "", "", fmt.Sprintf("invalid stdio forward port %d: must be in 1..65535", fwdReq.ConnectPort)
	}
	return s.effectiveDialNetwork(), net.JoinHostPort(connectHost, strconv.FormatUint(uint64(fwdReq.ConnectPort), 10)), ""
}

func handlePassengerStdioFwd(s *MuxServer, conn net.Conn, reqID uint32, payload []byte) error {
	if !s.canAdmitNewSession() {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	if err := s.authorize("passenger stdio forward"); err != nil {
		return sendPermissionDenied(conn, reqID, err.Error())
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return sendFailure(conn, reqID, "passenger stdio forward requires unix domain socket")
	}

	files, err := recvFiles(unixConn, "passenger-stdio", "in", "out")
	if err != nil {
		return sendFailure(conn, reqID, fmt.Sprintf("receive stdio file descriptors failed: %v", err))
	}
	// The received descriptors belong to these files; see handlePassengerSession.
	defer closeFiles(files)

	dialNetwork, targetAddr, errMsg := resolvePassengerStdioFwdTarget(s, payload)
	if errMsg != "" {
		return sendFailure(conn, reqID, errMsg)
	}

	if !s.addActiveSession() {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	defer s.removeActiveSession()

	s.trackStream(conn)
	defer s.untrackStream(conn)

	stream, err := s.dialSSHMux(s.baseContext(), dialNetwork, targetAddr)
	if err != nil {
		return sendFailure(conn, reqID, fmt.Sprintf("remote dial failed: %v", err))
	}
	defer func() { _ = stream.Close() }()

	if err := sendSessionOpened(conn, reqID, 1); err != nil {
		return err
	}

	stdinFile, stdoutFile := files[0], files[1]

	stopStdin := make(chan struct{})
	cancelStdin := sync.OnceFunc(func() { close(stopStdin) })
	stdinDone := make(chan error, 1)
	stdoutDone := make(chan error, 1)
	go func() {
		copyErr := copyFromPollableFD(stream, stdinFile, stopStdin)
		if cw, ok := stream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		stdinDone <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(stdoutFile, stream)
		stdoutDone <- copyErr
	}()

	// Watch the control socket while stdio forwarding runs: if the passenger
	// client terminates early (closing conn), abort the remote stream and close
	// inherited descriptors immediately so neither remote forward nor copy workers leak.
	connClosed := make(chan struct{})
	var stopConnWatch func() bool
	if d, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		go func() {
			defer close(connClosed)
			var buf [1]byte
			_, _ = conn.Read(buf[:])
		}()
		stopConnWatch = func() bool {
			_ = d.SetReadDeadline(time.Now())
			<-connClosed
			_ = d.SetReadDeadline(time.Time{})
			return true
		}
	} else {
		stopConnWatch = func() bool { return false }
	}

	// Wait for remote -> stdout to finish (or control-socket disconnect), while
	// allowing stdin EOF to half-close the remote stream so request/response
	// protocols (like HTTP or banner probes with short stdin) still receive the
	// remote server's response before tearing down both descriptors.
	var (
		outErr       error
		disconnected bool
	)
	select {
	case outErr = <-stdoutDone:
		stopConnWatch()
	case <-connClosed:
		disconnected = true
		cancelStdin()
		_ = stream.Close()
		closeFiles(files)
		outErr = <-stdoutDone
	}

	cancelStdin()
	inErr := <-stdinDone
	_ = stream.Close()
	_ = stdinFile.Close()
	_ = stdoutFile.Close()
	if disconnected {
		return nil
	}

	firstErr := outErr
	if firstErr == nil && !errors.Is(inErr, os.ErrClosed) {
		firstErr = inErr
	}

	exitStatus := uint32(0)
	if firstErr != nil && !errors.Is(firstErr, io.EOF) && !errors.Is(firstErr, os.ErrClosed) {
		exitStatus = 1
	}
	return sendExitMessage(conn, 1, exitStatus)
}

// passengerFDReceiveTimeout bounds how long a master waits for a passenger
// client to hand over its session descriptors. The peer is local, so this only
// stops a stuck or malicious peer from pinning a handler goroutine forever.
const passengerFDReceiveTimeout = 5 * time.Second

// recvFiles receives exactly count inherited descriptors and hands each one to
// an *os.File. The files own the descriptors from that point on: the caller must
// close them and must never close the raw descriptor numbers again. A second
// unix.Close on a reused number would close an unrelated descriptor owned by
// another goroutine.
func recvFiles(conn *net.UnixConn, prefix string, names ...string) ([]*os.File, error) {
	fds, err := recvFDs(conn, len(names))
	if err != nil {
		return nil, err
	}
	files := make([]*os.File, 0, len(fds))
	for index, fd := range fds {
		file := os.NewFile(uintptr(fd), prefix+"-"+names[index])
		if file == nil {
			_ = unix.Close(fd)
			closeFDRange(fds[index+1:])
			closeFiles(files)
			return nil, fmt.Errorf("wrap received descriptor %d in a file failed", fd)
		}
		files = append(files, file)
	}
	return files, nil
}

// recvFDs receives exactly count descriptors from conn and marks each of them
// close-on-exec. OpenSSH's mm_send_fd sends one descriptor per control message,
// so a single recvmsg is not guaranteed to carry all of them; descriptors beyond
// the requested count are closed instead of being returned to the caller.
func recvFDs(conn *net.UnixConn, count int) ([]int, error) {
	if count <= 0 {
		return nil, nil
	}
	if err := conn.SetReadDeadline(time.Now().Add(passengerFDReceiveTimeout)); err != nil {
		return nil, fmt.Errorf("set descriptor receive deadline failed: %w", err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("access unix socket raw connection failed: %w", err)
	}

	fds := make([]int, 0, count)
	fail := func(format string, args ...any) ([]int, error) {
		closeFDRange(fds)
		return nil, fmt.Errorf(format, args...)
	}

	const surplusFDSlack = 4
	var data [1]byte
	for len(fds) < count {
		// Reserve room for the descriptors still missing plus surplus slack: on
		// 32-bit aligned cmsg platforms (e.g. Darwin), CmsgSpace(4) has room for
		// only a single descriptor, so extra slack lets recvFDs receive and close
		// surplus descriptors instead of hitting MSG_CTRUNC.
		oob := make([]byte, unix.CmsgSpace((count-len(fds)+surplusFDSlack)*4))
		received, flags, parseCtrlErr, err := recvOneControlMsgCloexec(rawConn, data[:], oob)
		if err != nil {
			return fail("receive descriptors: %w", err)
		}
		for _, fd := range received {
			if flags&unix.MSG_CTRUNC != 0 || parseCtrlErr != nil || len(fds) >= count {
				_ = unix.Close(fd)
				continue
			}
			fds = append(fds, fd)
		}
		if flags&unix.MSG_CTRUNC != 0 {
			return fail("control message truncated")
		}
		if parseCtrlErr != nil {
			return fail("parse control message: %w", parseCtrlErr)
		}
		if len(received) == 0 {
			return fail("expected ancillary file descriptor, got none")
		}
	}
	return fds, nil
}

func extractReceivedFDsMarkCloexec(oob []byte) ([]int, error) {
	var allFDs []int
	for len(oob) > 0 {
		if len(oob) < unix.CmsgLen(0) {
			return allFDs, unix.EINVAL
		}
		hdr, data, rest, parseErr := unix.ParseOneSocketControlMessage(oob)
		if parseErr != nil {
			return allFDs, parseErr
		}
		oob = rest
		received, rightsErr := unix.ParseUnixRights(&unix.SocketControlMessage{Header: hdr, Data: data})
		if rightsErr != nil {
			continue
		}
		for _, fd := range received {
			unix.CloseOnExec(fd)
			allFDs = append(allFDs, fd)
		}
	}
	return allFDs, nil
}

func closeFDRange(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}

// closeFiles releases every owned file. It is safe to call after the handler
// already closed an individual file: os.File tracks its own closed state.
func closeFiles(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}
