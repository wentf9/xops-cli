//go:build linux || darwin || freebsd

package ssh

import (
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
	defer func() { _ = ch.Close() }()

	for _, env := range req.Env {
		if k, v, ok := strings.Cut(env, "="); ok && k != "" {
			_, _ = ch.SendRequest("env", false, cryptoSSH.Marshal(struct {
				Name  string
				Value string
			}{Name: k, Value: v}))
		}
	}

	ttyAllocFailed := false
	if req.WantTTY {
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
		if accepted, err := ch.SendRequest("pty-req", true, cryptoSSH.Marshal(ptyReq)); err != nil || !accepted {
			ttyAllocFailed = true
		}
	}

	if err := startPassengerChannel(ch, req); err != nil {
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

	exitCode := runPassengerChannelIO(conn, ch, reqs, files)
	return sendExitMessage(conn, sessionID, exitCode)
}

func startPassengerChannel(ch cryptoSSH.Channel, req MuxNewSessionRequest) error {
	switch {
	case req.Subsystem:
		payload := cryptoSSH.Marshal(struct{ Subsystem string }{Subsystem: req.Command})
		accepted, err := ch.SendRequest("subsystem", true, payload)
		if err != nil {
			return fmt.Errorf("subsystem failed: %w", err)
		}
		if !accepted {
			return fmt.Errorf("subsystem %q request rejected", req.Command)
		}
	case req.Command == "":
		accepted, err := ch.SendRequest("shell", true, nil)
		if err != nil {
			return fmt.Errorf("shell failed: %w", err)
		}
		if !accepted {
			return errors.New("shell request rejected")
		}
	default:
		payload := cryptoSSH.Marshal(struct{ Command string }{Command: req.Command})
		accepted, err := ch.SendRequest("exec", true, payload)
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

func handlePassengerStdioFwd(s *MuxServer, conn net.Conn, reqID uint32, payload []byte) error {
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

	fwdReq, err := DecodeMuxNewStdioFwd(payload)
	if err != nil {
		return sendFailure(conn, reqID, fmt.Sprintf("malformed stdio fwd request: %v", err))
	}

	if !s.addActiveSession() {
		return sendFailure(conn, reqID, "mux master is shutting down")
	}
	defer s.removeActiveSession()

	s.trackStream(conn)
	defer s.untrackStream(conn)

	targetAddr := net.JoinHostPort(fwdReq.ConnectHost, strconv.FormatUint(uint64(fwdReq.ConnectPort), 10))
	stream, err := s.sshClient.Dial("tcp", targetAddr)
	if err != nil {
		return sendFailure(conn, reqID, fmt.Sprintf("remote dial failed: %v", err))
	}
	defer func() { _ = stream.Close() }()

	if err := sendSessionOpened(conn, reqID, 1); err != nil {
		return err
	}

	stdinFile, stdoutFile := files[0], files[1]

	stopStdin := make(chan struct{})
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

	// Wait for remote -> stdout to finish (or stdin error if it fails), while
	// allowing stdin EOF to half-close the remote stream so request/response
	// protocols (like HTTP or banner probes with short stdin) still receive the
	// remote server's response before tearing down both descriptors.
	outErr := <-stdoutDone
	close(stopStdin)
	inErr := <-stdinDone
	_ = stream.Close()
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

	fds := make([]int, 0, count)
	fail := func(format string, args ...any) ([]int, error) {
		closeFDRange(fds)
		return nil, fmt.Errorf(format, args...)
	}

	var data [1]byte
	for len(fds) < count {
		// Reserve room for the descriptors still missing: an undersized buffer
		// truncates the control message and silently drops descriptors.
		oob := make([]byte, unix.CmsgSpace((count-len(fds))*4))
		_, oobn, flags, _, err := conn.ReadMsgUnix(data[:], oob)
		if err != nil {
			return fail("receive descriptors: %w", err)
		}
		messages, parseCtrlErr := unix.ParseSocketControlMessage(oob[:oobn])
		for messageIndex := range messages {
			received, parseErr := unix.ParseUnixRights(&messages[messageIndex])
			if parseErr != nil {
				continue
			}
			for _, fd := range received {
				unix.CloseOnExec(fd)
				if flags&unix.MSG_CTRUNC != 0 || parseCtrlErr != nil || len(fds) >= count {
					_ = unix.Close(fd)
					continue
				}
				fds = append(fds, fd)
			}
		}
		if flags&unix.MSG_CTRUNC != 0 {
			return fail("control message truncated")
		}
		if parseCtrlErr != nil {
			return fail("parse control message: %w", parseCtrlErr)
		}
	}
	return fds, nil
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
