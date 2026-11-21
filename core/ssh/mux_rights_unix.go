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

func bindAndLinkSocket(targetPath string) (net.Listener, os.FileInfo, error) {
	maxPathLen := MaxControlPathLength() - 1 // 107 on Linux, 103 on Darwin/BSD
	targetLen := len(targetPath)
	if targetLen > maxPathLen {
		return nil, nil, fmt.Errorf("control path %q exceeds maximum Unix socket path length (%d bytes)", targetPath, maxPathLen)
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0700); err != nil {
		return nil, nil, fmt.Errorf("create socket directory failed: %w", err)
	}
	suffixBudget := maxPathLen - targetLen
	dir := filepath.Dir(targetPath)
	dirBudget := maxPathLen - (len(dir) + 1)

	useSuffixTemp := suffixBudget >= 8
	useDirTemp := !useSuffixTemp && dirBudget >= 8

	if !useSuffixTemp && !useDirTemp {
		// Fallback: Direct bind on targetPath when path length budget is exhausted.
		return bindDirectControlSocket(targetPath)
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
			return nil, nil, fmt.Errorf("listen on temp control socket failed: %w", err)
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("listen on temp control socket failed: %w", err)
	}
	disableUnixListenerUnlinkOnClose(listener)
	defer func() {
		_ = os.Remove(tempPath)
	}()

	// Enforce 0600 permissions without mutating process-global umask.
	if err := os.Chmod(tempPath, 0600); err != nil {
		_ = listener.Close()
		return nil, nil, fmt.Errorf("chmod temp control socket failed: %w", err)
	}
	origFi, lstatErr := os.Lstat(tempPath)
	if lstatErr != nil {
		_ = listener.Close()
		return nil, nil, fmt.Errorf("stat temp control socket failed: %w", lstatErr)
	}

	err = os.Link(tempPath, targetPath)
	if err != nil {
		if errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EEXIST) {
			if retryReplaceStaleSocketLink(tempPath, targetPath) {
				return listener, origFi, nil
			}
			_ = listener.Close()
			return nil, nil, fmt.Errorf("%w: %s", ErrMasterAlreadyExists, targetPath)
		}
		_ = listener.Close()
		return nil, nil, fmt.Errorf("link control socket failed: %w", err)
	}

	return listener, origFi, nil
}

func bindDirectControlSocket(targetPath string) (net.Listener, os.FileInfo, error) {
	listener, err := net.Listen("unix", targetPath)
	if err != nil {
		if isAddressAlreadyInUse(err) {
			return nil, nil, fmt.Errorf("%w: %s", ErrMasterAlreadyExists, targetPath)
		}
		return nil, nil, fmt.Errorf("listen on control socket failed: %w", err)
	}
	disableUnixListenerUnlinkOnClose(listener)
	if err := os.Chmod(targetPath, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(targetPath)
		return nil, nil, fmt.Errorf("chmod control socket failed: %w", err)
	}
	origFi, lstatErr := os.Lstat(targetPath)
	if lstatErr != nil {
		_ = listener.Close()
		_ = os.Remove(targetPath)
		return nil, nil, fmt.Errorf("stat control socket failed: %w", lstatErr)
	}
	return listener, origFi, nil
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
	if !s.beginSessionAdmission() {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	admitted := false
	defer func() {
		if !admitted {
			s.endSessionAdmission()
		}
	}()
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

	if !s.promoteSessionAdmission() {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	admitted = true
	defer s.removeActiveSession()

	s.trackStream(conn)
	defer s.untrackStream(conn)

	ch, reqs, err := s.openBoundedMuxChannel(s.baseContext(), "session", nil)
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
	defer func() { _ = s.closeMuxChannelBounded(ch, nil) }()
	if err != nil {
		return sendFailure(conn, reqID, fmt.Sprintf("agent forward request failed: %v", err))
	}

	var ttyAllocFailed bool
	if err := applyPassengerEnvAndPTYWithFiles(s, ch, req, files, &ttyAllocFailed); err != nil {
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
	exitCode := runPassengerChannelIO(s, conn, ch, reqs, files)
	return sendExitMessage(conn, sessionID, exitCode)
}

func applyPassengerEnvAndPTY(s *MuxServer, ch cryptoSSH.Channel, req MuxNewSessionRequest, ttyAllocFailed *bool) error {
	return applyPassengerEnvAndPTYWithFiles(s, ch, req, nil, ttyAllocFailed)
}

func probePassengerWinsize(files []*os.File) (cols, rows, width, height uint32) {
	const (
		defaultCols   = 80
		defaultRows   = 24
		defaultWidth  = 640
		defaultHeight = 480
	)
	for _, f := range files {
		if f == nil {
			continue
		}
		rawConn, err := f.SyscallConn()
		if err != nil {
			continue
		}
		var (
			ws    *unix.Winsize
			wsErr error
		)
		if ctrlErr := rawConn.Control(func(fd uintptr) {
			ws, wsErr = unix.IoctlGetWinsize(int(fd), unix.TIOCGWINSZ)
		}); ctrlErr == nil && wsErr == nil && ws != nil && ws.Col > 0 && ws.Row > 0 {
			return uint32(ws.Col), uint32(ws.Row), uint32(ws.Xpixel), uint32(ws.Ypixel)
		}
	}
	return defaultCols, defaultRows, defaultWidth, defaultHeight
}

func applyPassengerEnvAndPTYWithFiles(s *MuxServer, ch cryptoSSH.Channel, req MuxNewSessionRequest, files []*os.File, ttyAllocFailed *bool) error {
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
	cols, rows, width, height := probePassengerWinsize(files)
	ptyReq := struct {
		Term     string
		Columns  uint32
		Rows     uint32
		Width    uint32
		Height   uint32
		Modelist string
	}{
		Term:     termType,
		Columns:  cols,
		Rows:     rows,
		Width:    width,
		Height:   height,
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
	if ch == nil || (sshCli != nil && sshCli.Conn == nil) {
		return false, net.ErrClosed
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
	if s == nil || !s.allowAgentForward || s.agentSocket == "" || s.dialAgent == nil || s.sshClient == nil || s.sshClient.Conn == nil {
		s.getLogger().Debugf("mux: ignoring passenger WantAgent request because master AllowAgentForward is disabled or transport closed")
		return func() {}, nil
	}
	router, err := getOrCreateAgentRouter(s.sshClient)
	if err != nil {
		s.getLogger().Debugf("mux: failed to initialize agent router for passenger session: %v", err)
		return func() {}, nil
	}
	lease, err := router.acquireLocalLease(s.baseContext(), s.agentSocket, s.dialAgent, s.getLogger())
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
const (
	passengerPipeWriteCap       = 512
	passengerCharDeviceWriteCap = 32
)

func isClosedChan(ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// openWakePipeMonitor creates an internal O_CLOEXEC wakeup pipe via os.Pipe()
// and writes a wake byte before closing the write end when stop closes so
// poll(2) wakes via POLLIN even if another fd reference lingers briefly.
func openWakePipeMonitor(stop <-chan struct{}) (*os.File, func(), error) {
	wakeR, wakeW, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}

	triggerWake := sync.OnceFunc(func() {
		_, _ = wakeW.Write([]byte{1})
		_ = wakeW.Close()
	})
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-stop:
			triggerWake()
		case <-done:
		}
	}()
	cleanup := func() {
		close(done)
		wg.Wait()
		triggerWake()
		_ = wakeR.Close()
	}
	return wakeR, cleanup, nil
}

func pollReadChunkFD(rawConn, wakeConn syscall.RawConn, buf []byte) (int, error) {
	var (
		n       int
		readErr error
	)
	ctrlErr := rawConn.Control(func(fd uintptr) {
		srcFD := int(fd)
		wErr := wakeConn.Control(func(wfd uintptr) {
			wakeFD := int(wfd)
			pfds := []unix.PollFd{
				{Fd: int32(srcFD), Events: unix.POLLIN},
				{Fd: int32(wakeFD), Events: unix.POLLIN},
			}
			for {
				pfds[0].Revents = 0
				pfds[1].Revents = 0
				_, pollErr := unix.Poll(pfds, -1)
				if pollErr != nil {
					if errors.Is(pollErr, syscall.EINTR) {
						continue
					}
					readErr = pollErr
					return
				}
				if pfds[1].Revents != 0 {
					return
				}
				if pfds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) == 0 {
					continue
				}
				n, readErr = unix.Read(srcFD, buf)
				if errors.Is(readErr, syscall.EINTR) || errors.Is(readErr, syscall.EAGAIN) {
					readErr = nil
					continue
				}
				return
			}
		})
		if wErr != nil && readErr == nil {
			readErr = wErr
		}
	})
	if readErr != nil {
		return n, readErr
	}
	return n, ctrlErr
}

func copyFromPollableFD(dst io.Writer, src *os.File, stop <-chan struct{}) error {
	rawConn, err := src.SyscallConn()
	if err != nil {
		_, copyErr := io.Copy(dst, src)
		return copyErr
	}
	wakeFile, cleanup, err := openWakePipeMonitor(stop)
	if err != nil {
		_, copyErr := io.Copy(dst, src)
		return copyErr
	}
	defer cleanup()

	wakeConn, err := wakeFile.SyscallConn()
	if err != nil {
		_, copyErr := io.Copy(dst, src)
		return copyErr
	}

	buf := make([]byte, 32*1024)
	for {
		if isClosedChan(stop) {
			return nil
		}
		n, readErr := pollReadChunkFD(rawConn, wakeConn, buf)
		if n > 0 {
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
		}
		if readErr != nil || n == 0 {
			return readErr
		}
	}
}

func inspectRawConnChunkCap(rawConn syscall.RawConn) (isRegular, isNonblock, isSocket bool, maxChunk int) {
	maxChunk = passengerPipeWriteCap
	_ = rawConn.Control(func(fd uintptr) {
		flags, fErr := unix.FcntlInt(fd, unix.F_GETFL, 0)
		var st unix.Stat_t
		sErr := unix.Fstat(int(fd), &st)
		fmtMode := st.Mode & unix.S_IFMT
		isRegular = sErr == nil && fmtMode == unix.S_IFREG
		isSocket = sErr == nil && fmtMode == unix.S_IFSOCK
		isChar := sErr == nil && fmtMode == unix.S_IFCHR
		isNonblock = fErr == nil && (flags&unix.O_NONBLOCK) != 0
		switch {
		case isRegular || isNonblock || isSocket:
			maxChunk = 32 * 1024
		case isChar:
			maxChunk = passengerCharDeviceWriteCap
		}
	})
	return isRegular, isNonblock, isSocket, maxChunk
}

func preparePollableWriteTarget(dst *os.File, allowReopen bool) (rawConn syscall.RawConn, owned *os.File, useMsgDontWait, needSharedLock bool, maxChunk int, err error) {
	rawConn, err = dst.SyscallConn()
	if err != nil {
		return nil, nil, false, false, 0, err
	}
	isRegular, isNonblock, isSocket, capBytes := inspectRawConnChunkCap(rawConn)
	if isRegular || isNonblock || isSocket {
		return rawConn, nil, isSocket && !isNonblock, false, capBytes, nil
	}
	if !allowReopen {
		return rawConn, nil, false, true, capBytes, nil
	}
	reopened, reopenErr := reopenNonBlockingWriteFile(dst)
	if reopenErr != nil || reopened == nil {
		return rawConn, nil, false, true, capBytes, nil
	}
	ownedRaw, rawErr := reopened.SyscallConn()
	if rawErr != nil {
		_ = reopened.Close()
		return rawConn, nil, false, true, capBytes, nil
	}
	_, ownedNonblock, _, ownedCap := inspectRawConnChunkCap(ownedRaw)
	if !ownedNonblock {
		_ = reopened.Close()
		return rawConn, nil, false, true, capBytes, nil
	}
	return ownedRaw, reopened, false, false, ownedCap, nil
}

func writePollableChunk(dstFD int, remaining []byte, maxChunk int, retryEAGAIN, useMsgDontWait bool) (int, bool, error) {
	chunk := remaining
	if len(chunk) > maxChunk {
		chunk = chunk[:maxChunk]
	}
	var (
		nw   int
		wErr error
	)
	if useMsgDontWait {
		nw, wErr = unix.SendmsgN(dstFD, chunk, nil, nil, unix.MSG_DONTWAIT)
	} else {
		nw, wErr = unix.Write(dstFD, chunk)
	}
	if nw > 0 {
		return nw, false, nil
	}
	if wErr != nil {
		if errors.Is(wErr, syscall.EINTR) {
			return 0, false, nil
		}
		if errors.Is(wErr, syscall.EAGAIN) || errors.Is(wErr, syscall.EWOULDBLOCK) {
			return 0, retryEAGAIN, nil
		}
		return 0, false, wErr
	}
	return 0, false, io.ErrShortWrite
}

func pollWriteNonBlockingStep(dstFD int, remaining []byte, maxChunk int, useMsgDontWait bool) (nw int, needWait bool, err error) {
	pfd := []unix.PollFd{{Fd: int32(dstFD), Events: unix.POLLOUT}}
	for {
		pfd[0].Revents = 0
		nEvents, pollErr := unix.Poll(pfd, 0)
		if pollErr != nil {
			if errors.Is(pollErr, syscall.EINTR) {
				continue
			}
			return 0, false, pollErr
		}
		if nEvents == 0 || pfd[0].Revents == 0 {
			return 0, true, nil
		}
		if pfd[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return 0, false, syscall.EPIPE
		}
		if pfd[0].Revents&unix.POLLOUT == 0 {
			return 0, true, nil
		}
		return writePollableChunk(dstFD, remaining, maxChunk, true, useMsgDontWait)
	}
}

func pollWriteAllFDFast(rawConn syscall.RawConn, data []byte, maxChunk int, useMsgDontWait bool, writeMu *sync.Mutex, stop <-chan struct{}) (remaining []byte, stopped bool, err error) {
	remaining = data
	ctrlErr := rawConn.Control(func(fd uintptr) {
		dstFD := int(fd)
		for len(remaining) > 0 {
			if isClosedChan(stop) {
				stopped = true
				return
			}
			nw, needWait, stepErr := runSerializedPollWriteStep(dstFD, remaining, maxChunk, useMsgDontWait, writeMu)
			if nw > 0 {
				remaining = remaining[nw:]
				continue
			}
			if stepErr != nil {
				err = stepErr
				return
			}
			if needWait {
				return
			}
		}
	})
	if err != nil {
		return remaining, false, err
	}
	return remaining, stopped, ctrlErr
}

func runSerializedPollWriteStep(dstFD int, remaining []byte, maxChunk int, useMsgDontWait bool, writeMu *sync.Mutex) (int, bool, error) {
	if writeMu != nil {
		writeMu.Lock()
		defer writeMu.Unlock()
	}
	return pollWriteNonBlockingStep(dstFD, remaining, maxChunk, useMsgDontWait)
}

func pollWriteAllFDWithWake(rawConn, wakeConn syscall.RawConn, data []byte, maxChunk int, useMsgDontWait bool, writeMu *sync.Mutex) (bool, error) {
	remaining := data
	var (
		stopped  bool
		writeErr error
	)
	ctrlErr := rawConn.Control(func(fd uintptr) {
		dstFD := int(fd)
		wErr := wakeConn.Control(func(wfd uintptr) {
			wakeFD := int(wfd)
			pfds := []unix.PollFd{
				{Fd: int32(dstFD), Events: unix.POLLOUT},
				{Fd: int32(wakeFD), Events: unix.POLLIN},
			}
			for len(remaining) > 0 {
				pfds[0].Revents = 0
				pfds[1].Revents = 0
				_, pollErr := unix.Poll(pfds, -1)
				if pollErr != nil {
					if errors.Is(pollErr, syscall.EINTR) {
						continue
					}
					writeErr = pollErr
					return
				}
				if pfds[1].Revents != 0 {
					stopped = true
					return
				}
				if pfds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
					writeErr = syscall.EPIPE
					return
				}
				if pfds[0].Revents&unix.POLLOUT == 0 {
					continue
				}
				nw, stepErr := writeAfterPollOut(dstFD, remaining, maxChunk, useMsgDontWait, writeMu)
				if nw > 0 {
					remaining = remaining[nw:]
				}
				if stepErr != nil {
					writeErr = stepErr
					return
				}
			}
		})
		if wErr != nil && writeErr == nil {
			writeErr = wErr
		}
	})
	if stopped {
		return true, nil
	}
	if writeErr != nil {
		return false, writeErr
	}
	return false, ctrlErr
}

func writeAfterPollOut(dstFD int, remaining []byte, maxChunk int, useMsgDontWait bool, writeMu *sync.Mutex) (int, error) {
	if writeMu != nil {
		// Re-check POLLOUT under writeMu so a concurrent writer sharing this
		// blocking pipe cannot exhaust PIPE_BUF before we write.
		nw, _, err := runSerializedPollWriteStep(dstFD, remaining, maxChunk, useMsgDontWait, writeMu)
		return nw, err
	}
	nw, _, err := writePollableChunk(dstFD, remaining, maxChunk, false, useMsgDontWait)
	return nw, err
}

func copyToPollableFD(dst *os.File, src io.Reader, stop <-chan struct{}) error {
	return copyToPollableFDSerialized(dst, src, stop, nil)
}

func copyToPollableFDSerialized(dst *os.File, src io.Reader, stop <-chan struct{}, sharedMu *sync.Mutex) error {
	return copyToPollableFDWithReopen(dst, src, stop, sharedMu, true)
}

func copyToPollableFDWithReopen(dst *os.File, src io.Reader, stop <-chan struct{}, sharedMu *sync.Mutex, allowReopen bool) error {
	rawConn, owned, useMsgDontWait, needSharedLock, maxChunk, err := preparePollableWriteTarget(dst, allowReopen)
	if err != nil {
		_, copyErr := io.Copy(dst, src)
		return copyErr
	}
	if owned != nil {
		defer func() { _ = owned.Close() }()
	}
	var writeMu *sync.Mutex
	if needSharedLock {
		writeMu = sharedMu
	}

	var (
		wakeFile    *os.File
		wakeConn    syscall.RawConn
		wakeCleanup func()
	)
	defer func() {
		if wakeCleanup != nil {
			wakeCleanup()
		}
	}()
	ensureWakeConn := func() (syscall.RawConn, error) {
		if wakeConn != nil {
			return wakeConn, nil
		}
		wf, cleanup, wErr := openWakePipeMonitor(stop)
		if wErr != nil {
			return nil, wErr
		}
		wc, cErr := wf.SyscallConn()
		if cErr != nil {
			cleanup()
			return nil, cErr
		}
		wakeFile = wf
		_ = wakeFile
		wakeCleanup = cleanup
		wakeConn = wc
		return wakeConn, nil
	}

	buf := make([]byte, 32*1024)
	for {
		if isClosedChan(stop) {
			return nil
		}
		n, readErr := src.Read(buf)
		if n > 0 {
			remaining, stopped, fastErr := pollWriteAllFDFast(rawConn, buf[:n], maxChunk, useMsgDontWait, writeMu, stop)
			if stopped {
				return nil
			}
			if fastErr != nil {
				return fastErr
			}
			if len(remaining) > 0 {
				wc, wErr := ensureWakeConn()
				if wErr != nil {
					return wErr
				}
				wStopped, wWriteErr := pollWriteAllFDWithWake(rawConn, wc, remaining, maxChunk, useMsgDontWait, writeMu)
				if wWriteErr != nil {
					return wWriteErr
				}
				if wStopped {
					return nil
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func waitPassengerDrainBounded(done <-chan struct{}) {
	timer := time.NewTimer(sessionShutdownTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}

// passengerCopyResult pairs a close-once completion channel with the copy
// worker's terminal error so any number of callers can safely await completion
// without double-receiving from an unclosed value channel.
type passengerCopyResult struct {
	done chan struct{}
	err  error
}

func newPassengerCopyResult() *passengerCopyResult {
	return &passengerCopyResult{done: make(chan struct{})}
}

func (r *passengerCopyResult) finish(err error) {
	r.err = err
	close(r.done)
}

func (r *passengerCopyResult) Done() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.done
}

func (r *passengerCopyResult) Err() error {
	if r == nil {
		return nil
	}
	<-r.done
	return r.err
}

func runPassengerChannelIO(s *MuxServer, conn net.Conn, ch cryptoSSH.Channel, reqs <-chan *cryptoSSH.Request, files []*os.File) uint32 {
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

	stopOutput := make(chan struct{})
	cancelOutput := sync.OnceFunc(func() { close(stopOutput) })

	var sharedOutMu *sync.Mutex
	if stOut, err1 := stdoutFile.Stat(); err1 == nil {
		if stErr, err2 := stderrFile.Stat(); err2 == nil && os.SameFile(stOut, stErr) {
			sharedOutMu = &sync.Mutex{}
		}
	}

	var outWG sync.WaitGroup
	outWG.Add(2)
	go func() {
		defer outWG.Done()
		_ = copyToPollableFDSerialized(stdoutFile, ch, stopOutput, sharedOutMu)
	}()
	go func() {
		defer outWG.Done()
		_ = copyToPollableFDSerialized(stderrFile, ch.Stderr(), stopOutput, sharedOutMu)
	}()

	stopStdin := make(chan struct{})
	cancelStdin := sync.OnceFunc(func() { close(stopStdin) })

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
	connClosed, stopConnWatch := startPassengerStdioConnWatch(conn)

	var serverDone <-chan struct{}
	if s != nil {
		serverDone = s.baseContext().Done()
	}

	abortChannel := func(needStopWatch bool) uint32 {
		if needStopWatch {
			stopConnWatch()
		}
		cancelStdin()
		cancelOutput()
		_ = s.closeMuxChannelBounded(ch, nil)
		_ = stdoutFile.Close()
		_ = stderrFile.Close()
		drainDone := make(chan struct{})
		go func() {
			<-stdinDone
			<-outDone
			close(drainDone)
		}()
		waitPassengerDrainBounded(drainDone)
		_ = stdinFile.Close()
		return exitCode.Load()
	}

	select {
	case <-outDone:
		stopConnWatch()
	case <-connClosed:
		return abortChannel(false)
	case <-serverDone:
		return abortChannel(true)
	}

	// Close the SSH channel before joining stdinDone so a copyFromPollableFD
	// blocked on ch.Write or ch.CloseWrite due to exhausted remote window unblocks cleanly.
	cancelStdin()
	cancelOutput()
	_ = s.closeMuxChannelBounded(ch, nil)
	waitPassengerDrainBounded(stdinDone)
	_ = stdoutFile.Close()
	_ = stderrFile.Close()
	_ = stdinFile.Close()

	// exitCode starts at 255 and is overwritten only by an explicit exit-status
	// (or preserved as 255 on exit-signal / abrupt transport disconnect).
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

func startPassengerStdioConnWatch(conn net.Conn) (<-chan struct{}, func() bool) {
	connClosed := make(chan struct{})
	d, ok := conn.(interface{ SetReadDeadline(time.Time) error })
	if !ok {
		return connClosed, func() bool { return false }
	}
	go func() {
		defer close(connClosed)
		var buf [1]byte
		_, _ = conn.Read(buf[:])
	}()
	return connClosed, func() bool {
		_ = d.SetReadDeadline(time.Now())
		<-connClosed
		_ = d.SetReadDeadline(time.Time{})
		return true
	}
}

func handlePassengerStdioFwd(s *MuxServer, conn net.Conn, reqID uint32, payload []byte) error {
	if !s.beginSessionAdmission() {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	admitted := false
	defer func() {
		if !admitted {
			s.endSessionAdmission()
		}
	}()
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

	if !s.promoteSessionAdmission() {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	admitted = true
	defer s.removeActiveSession()

	s.trackStream(conn)
	defer s.untrackStream(conn)

	ch, reqs, err := s.dialSSHMuxChannel(s.baseContext(), dialNetwork, targetAddr)
	if err != nil {
		return sendFailure(conn, reqID, fmt.Sprintf("remote dial failed: %v", err))
	}
	defer func() { _ = s.closeMuxChannelBounded(ch, nil) }()

	if err := sendSessionOpened(conn, reqID, 1); err != nil {
		go discardAbortedChannelRequests(s.baseContext(), reqs)
		return err
	}

	remoteClosed := make(chan struct{})
	go func() {
		defer close(remoteClosed)
		if reqs != nil {
			cryptoSSH.DiscardRequests(reqs)
		}
	}()
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		if se := ch.Stderr(); se != nil {
			_, _ = io.Copy(io.Discard, se)
		}
	}()

	stdinFile, stdoutFile := files[0], files[1]

	stopStdin := make(chan struct{})
	cancelStdin := sync.OnceFunc(func() { close(stopStdin) })
	stopOutput := make(chan struct{})
	cancelOutput := sync.OnceFunc(func() { close(stopOutput) })
	stdinRes := newPassengerCopyResult()
	stdoutRes := newPassengerCopyResult()
	go func() {
		copyErr := copyFromPollableFD(ch, stdinFile, stopStdin)
		_ = ch.CloseWrite()
		stdinRes.finish(copyErr)
	}()
	go func() {
		stdoutRes.finish(copyToPollableFD(stdoutFile, ch, stopOutput))
	}()

	return awaitPassengerStdioFwdCompletion(s, conn, ch, stdinFile, stdoutFile, cancelStdin, cancelOutput, stdinRes, stdoutRes, remoteClosed, stderrDone)
}

func awaitPassengerStdioFwdCompletion(
	s *MuxServer,
	conn net.Conn,
	ch cryptoSSH.Channel,
	stdinFile, stdoutFile *os.File,
	cancelStdin, cancelOutput func(),
	stdinRes, stdoutRes *passengerCopyResult,
	remoteClosed, stderrDone <-chan struct{},
) error {
	connClosed, stopConnWatch := startPassengerStdioConnWatch(conn)

	// Wait for remote -> stdout to finish (or control-socket disconnect). If
	// remote sent SSH_MSG_CHANNEL_EOF while keeping the channel open, propagate
	// EOF on stdoutFile and let remaining stdin finish uploading until local
	// EOF or remote channel close.
	var (
		outErr, inErr error
		aborted       bool
		serverDone    <-chan struct{}
	)
	if s != nil {
		serverDone = s.baseContext().Done()
	}
	select {
	case <-stdoutRes.Done():
		outErr = stdoutRes.Err()
		if outErr == nil && !isClosedChan(remoteClosed) {
			_ = stdoutFile.Close()
			select {
			case <-stdinRes.Done():
				inErr = stdinRes.Err()
				stopConnWatch()
			case <-remoteClosed:
				stopConnWatch()
			case <-connClosed:
				aborted = true
			case <-serverDone:
				stopConnWatch()
				aborted = true
			}
		} else {
			stopConnWatch()
		}
	case <-connClosed:
		aborted = true
	case <-serverDone:
		stopConnWatch()
		aborted = true
	}
	if aborted {
		return abortPassengerStdioFwd(s, ch, stdinFile, stdoutFile, cancelStdin, cancelOutput, stdoutRes, stdinRes, stderrDone)
	}

	cancelStdin()
	cancelOutput()
	_ = s.closeMuxChannelBounded(ch, nil)
	waitPassengerDrainBounded(stdinRes.Done())
	if isClosedChan(stdinRes.Done()) {
		inErr = stdinRes.Err()
	}
	waitPassengerDrainBounded(stderrDone)
	_ = stdinFile.Close()
	_ = stdoutFile.Close()

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

func abortPassengerStdioFwd(
	s *MuxServer,
	stream io.Closer,
	stdinFile, stdoutFile *os.File,
	cancelStdin, cancelOutput func(),
	stdoutRes, stdinRes *passengerCopyResult,
	stderrDone <-chan struct{},
) error {
	cancelStdin()
	cancelOutput()
	_ = s.closeMuxChannelBounded(stream, nil)
	_ = stdoutFile.Close()
	waitDone := make(chan struct{})
	go func() {
		if stdoutRes != nil {
			<-stdoutRes.Done()
		}
		if stdinRes != nil {
			<-stdinRes.Done()
		}
		if stderrDone != nil {
			<-stderrDone
		}
		close(waitDone)
	}()
	waitPassengerDrainBounded(waitDone)
	_ = stdinFile.Close()
	return nil
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
