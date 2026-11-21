package ssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"
)

// encodeSCMRightFD builds a single-FD SOL_SOCKET/SCM_RIGHTS control message
// using only Go standard library packages so this test file compiles cleanly
// across Linux, macOS, and Windows.
func encodeSCMRightFD(fd int) ([]byte, bool) {
	const is64Bit = ^uint(0)>>63 == 1
	switch runtime.GOOS {
	case "linux":
		if !is64Bit {
			return nil, false
		}
		// Linux 64-bit little-endian cmsghdr: uint64 len (20), int32 level (1), int32 type (1), int32 fd, 4-byte pad.
		var buf [24]byte
		binary.LittleEndian.PutUint64(buf[0:8], 20)
		binary.LittleEndian.PutUint32(buf[8:12], 1)  // SOL_SOCKET
		binary.LittleEndian.PutUint32(buf[12:16], 1) // SCM_RIGHTS
		binary.LittleEndian.PutUint32(buf[16:20], uint32(fd))
		return buf[:], true
	case "darwin":
		// Darwin cmsghdr: uint32 len (16), int32 level (0xffff), int32 type (1), int32 fd.
		var buf [16]byte
		binary.LittleEndian.PutUint32(buf[0:4], 16)
		binary.LittleEndian.PutUint32(buf[4:8], 0xffff) // SOL_SOCKET
		binary.LittleEndian.PutUint32(buf[8:12], 1)     // SCM_RIGHTS
		binary.LittleEndian.PutUint32(buf[12:16], uint32(fd))
		return buf[:], true
	default:
		return nil, false
	}
}

func sendPortableUnixFDs(t *testing.T, conn net.Conn, files ...*os.File) {
	t.Helper()
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("portable SCM_RIGHTS helper only targets little-endian 64-bit architectures, got %s", runtime.GOARCH)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("expected *net.UnixConn, got %T", conn)
	}
	for _, f := range files {
		raw, err := f.SyscallConn()
		if err != nil {
			t.Fatalf("SyscallConn failed: %v", err)
		}
		var (
			sendErr error
			okEnc   bool
		)
		ctrlErr := raw.Control(func(fd uintptr) {
			oob, encOK := encodeSCMRightFD(int(fd))
			okEnc = encOK
			if !encOK {
				return
			}
			_, _, sendErr = unixConn.WriteMsgUnix([]byte{0}, oob, nil)
		})
		if ctrlErr != nil {
			t.Fatalf("raw.Control failed: %v", ctrlErr)
		}
		if !okEnc {
			t.Skipf("portable SCM_RIGHTS helper unsupported on %s/%s", runtime.GOOS, runtime.GOARCH)
		}
		if sendErr != nil {
			t.Fatalf("WriteMsgUnix(SCM_RIGHTS) failed: %v", sendErr)
		}
	}
}

func p0ShortUnixSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "xp0-")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// -----------------------------------------------------------------------------
// Fix 2: Passenger stdio forward stdoutDone double-receive hang & goroutine leak
// -----------------------------------------------------------------------------

type p0HalfCloseStdioSSHConn struct {
	dummyMuxGateConn
	readEOFHit chan struct{}
	chClosed   chan struct{}
}

func (c *p0HalfCloseStdioSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if name != "direct-tcpip" {
		return nil, nil, fmt.Errorf("unexpected channel %q", name)
	}
	reqs := make(chan *cryptoSSH.Request)
	ch := &p0HalfCloseStdioChannel{
		banner:     bytes.NewReader([]byte("READY\n")),
		reqs:       reqs,
		readEOFHit: c.readEOFHit,
		chClosed:   c.chClosed,
	}
	return ch, reqs, nil
}

type p0HalfCloseStdioChannel struct {
	banner     *bytes.Reader
	reqs       chan *cryptoSSH.Request
	readEOFHit chan struct{}
	chClosed   chan struct{}
	eofOnce    sync.Once
	closeOnce  sync.Once
}

func (c *p0HalfCloseStdioChannel) Read(b []byte) (int, error) {
	n, err := c.banner.Read(b)
	if errors.Is(err, io.EOF) {
		c.eofOnce.Do(func() {
			if c.readEOFHit != nil {
				close(c.readEOFHit)
			}
		})
	}
	return n, err
}

func (c *p0HalfCloseStdioChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *p0HalfCloseStdioChannel) CloseWrite() error           { return nil }
func (c *p0HalfCloseStdioChannel) Stderr() io.ReadWriter       { return &nopRW{} }
func (c *p0HalfCloseStdioChannel) Close() error {
	c.closeOnce.Do(func() {
		close(c.reqs)
		if c.chClosed != nil {
			close(c.chClosed)
		}
	})
	return nil
}
func (c *p0HalfCloseStdioChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, nil
}

func TestP0_PassengerStdioFwd_HalfOpenRemoteEOFThenAbortNoHangNoLeak(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix SCM_RIGHTS passenger stdio forward test requires linux or darwin")
	}

	for _, trigger := range []string{"connClosed", "serverShutdown"} {
		t.Run(trigger, func(t *testing.T) {
			assertP0PassengerStdioFwdHalfOpenAbort(t, trigger)
		})
	}
}

func assertP0PassengerStdioFwdHalfOpenAbort(t *testing.T, trigger string) {
	t.Helper()
	readEOFHit := make(chan struct{})
	chClosed := make(chan struct{})
	mockConn := &p0HalfCloseStdioSSHConn{readEOFHit: readEOFHit, chClosed: chClosed}
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	close(chans)
	close(reqs)
	rawCli := cryptoSSH.NewClient(mockConn, chans, reqs)
	defer func() { _ = rawCli.Close() }()

	sock := filepath.Join(p0ShortUnixSocketDir(t), "sf.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sock,
		SSHClient:         rawCli,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	defer func() {
		_ = srv.Shutdown()
		<-srv.Wait()
	}()
	go func() { _ = srv.Serve() }()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := performClientMuxHandshake(c); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := WriteMuxPacket(c, MUX_C_NEW_STDIO_FWD, EncodeMuxNewStdioFwd(MuxNewStdioFwdRequest{
		RequestID:   101,
		ConnectHost: "127.0.0.1",
		ConnectPort: 9000,
	})); err != nil {
		t.Fatalf("WriteMuxPacket: %v", err)
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
	defer func() {
		_ = inW.Close()
		_ = outR.Close()
	}()
	sendPortableUnixFDs(t, c, inR, outW)
	_ = inR.Close()
	_ = outW.Close()

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if pktType, _, err := ReadMuxPacket(c); err != nil || pktType != MUX_S_SESSION_OPENED {
		t.Fatalf("ReadMuxPacket = (0x%x, %v), want MUX_S_SESSION_OPENED", pktType, err)
	}

	// Drain remote half-close banner + EOF on stdoutR, proving stdoutRes is already completed
	// and awaitPassengerStdioFwdCompletion is now waiting in the half-open stdin upload select.
	if banner, err := io.ReadAll(outR); err != nil || string(banner) != "READY\n" {
		t.Fatalf("stdout banner = (%q, %v), want READY\\n", string(banner), err)
	}
	select {
	case <-readEOFHit:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for remote stdout EOF")
	}

	// Abort while stdinW is still open! Previously abortPassengerStdioFwd blocked
	// forever on a second <-stdoutDone receive, stalling for sessionShutdownTimeout (5s).
	start := time.Now()
	if trigger == "connClosed" {
		_ = c.Close()
	} else {
		_ = srv.Shutdown()
	}

	select {
	case <-chClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("remote channel was not closed promptly on abort")
	}
	waitP0ActiveSessionsZero(t, srv, start)
}

func waitP0ActiveSessionsZero(t *testing.T, srv *MuxServer, start time.Time) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for srv.ActiveSessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	elapsed := time.Since(start)
	if srv.ActiveSessions() != 0 {
		t.Fatalf("ActiveSessions() = %d after abort, want 0", srv.ActiveSessions())
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("abort after remote half-close stalled for %v (suspected stdoutDone double-receive hang)", elapsed)
	}
}

// -----------------------------------------------------------------------------
// Fix 3: Passenger session missing exit-status returns 255 (never false-success 0)
// -----------------------------------------------------------------------------

type p0PassengerExitSSHConn struct {
	dummyMuxGateConn
	mode string // "missing-exit", "exit-0", "exit-42", "exit-signal"
}

func (c *p0PassengerExitSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	if name != "session" {
		return nil, nil, fmt.Errorf("unexpected channel %q", name)
	}
	reqs := make(chan *cryptoSSH.Request, 2)
	return &p0PassengerExitChannel{
		mode: c.mode,
		reqs: reqs,
		out:  bytes.NewReader([]byte("partial-output")),
	}, reqs, nil
}

type p0PassengerExitChannel struct {
	mode      string
	reqs      chan *cryptoSSH.Request
	out       *bytes.Reader
	closeOnce sync.Once
}

func (c *p0PassengerExitChannel) Read(b []byte) (int, error)  { return c.out.Read(b) }
func (c *p0PassengerExitChannel) Write(b []byte) (int, error) { return len(b), nil }
func (c *p0PassengerExitChannel) CloseWrite() error           { return nil }
func (c *p0PassengerExitChannel) Stderr() io.ReadWriter       { return &nopRW{} }
func (c *p0PassengerExitChannel) Close() error {
	c.closeOnce.Do(func() { close(c.reqs) })
	return nil
}

func (c *p0PassengerExitChannel) SendRequest(name string, _ bool, _ []byte) (bool, error) {
	if name != "exec" && name != "shell" {
		return true, nil
	}
	switch c.mode {
	case "missing-exit":
		// Abruptly close reqs without sending exit-status or exit-signal.
		c.closeOnce.Do(func() { close(c.reqs) })
	case "exit-0":
		c.reqs <- &cryptoSSH.Request{
			Type:    "exit-status",
			Payload: cryptoSSH.Marshal(struct{ Status uint32 }{0}),
		}
		c.closeOnce.Do(func() { close(c.reqs) })
	case "exit-42":
		c.reqs <- &cryptoSSH.Request{
			Type:    "exit-status",
			Payload: cryptoSSH.Marshal(struct{ Status uint32 }{42}),
		}
		c.closeOnce.Do(func() { close(c.reqs) })
	case "exit-signal":
		c.reqs <- &cryptoSSH.Request{
			Type: "exit-signal",
			Payload: cryptoSSH.Marshal(struct {
				Signal     string
				CoreDumped bool
				Error      string
				Lang       string
			}{Signal: "TERM"}),
		}
		c.closeOnce.Do(func() { close(c.reqs) })
	}
	return true, nil
}

func TestP0_PassengerSession_MissingExitStatusReturns255(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix SCM_RIGHTS passenger session test requires linux or darwin")
	}

	cases := []struct {
		mode     string
		wantExit uint32
	}{
		{mode: "missing-exit", wantExit: 255},
		{mode: "exit-0", wantExit: 0},
		{mode: "exit-42", wantExit: 42},
		{mode: "exit-signal", wantExit: 255},
	}

	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			chans := make(chan cryptoSSH.NewChannel)
			reqs := make(chan *cryptoSSH.Request)
			close(chans)
			close(reqs)
			rawCli := cryptoSSH.NewClient(&p0PassengerExitSSHConn{mode: tc.mode}, chans, reqs)
			defer func() { _ = rawCli.Close() }()

			sock := filepath.Join(p0ShortUnixSocketDir(t), "exit.sock")
			srv, err := NewMuxServer(MuxServerOptions{
				ControlPath:       sock,
				SSHClient:         rawCli,
				PersistEnabled:    true,
				PersistIndefinite: true,
			})
			if err != nil {
				t.Fatalf("NewMuxServer: %v", err)
			}
			defer func() {
				_ = srv.Shutdown()
				<-srv.Wait()
			}()
			go func() { _ = srv.Serve() }()

			c, err := net.Dial("unix", sock)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer func() { _ = c.Close() }()
			if err := performClientMuxHandshake(c); err != nil {
				t.Fatalf("handshake: %v", err)
			}

			if err := WriteMuxPacket(c, MUX_C_NEW_SESSION, EncodeMuxNewSession(MuxNewSessionRequest{
				RequestID: 7,
				Command:   "run-cmd",
			})); err != nil {
				t.Fatalf("WriteMuxPacket: %v", err)
			}

			inR, inW, _ := os.Pipe()
			outR, outW, _ := os.Pipe()
			errR, errW, _ := os.Pipe()
			defer func() {
				_ = inW.Close()
				_ = outR.Close()
				_ = errR.Close()
			}()
			sendPortableUnixFDs(t, c, inR, outW, errW)
			_ = inR.Close()
			_ = outW.Close()
			_ = errW.Close()

			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			pktType, _, err := ReadMuxPacket(c)
			if err != nil || pktType != MUX_S_SESSION_OPENED {
				t.Fatalf("first packet = (0x%x, %v), want MUX_S_SESSION_OPENED", pktType, err)
			}
			_, _ = io.ReadAll(outR)

			pktType, payload, err := ReadMuxPacket(c)
			if err != nil || pktType != MUX_S_EXIT_MESSAGE {
				t.Fatalf("second packet = (0x%x, %v), want MUX_S_EXIT_MESSAGE", pktType, err)
			}
			_, gotExit, err := DecodeMuxExitMessage(payload)
			if err != nil {
				t.Fatalf("DecodeMuxExitMessage: %v", err)
			}
			if gotExit != tc.wantExit {
				t.Fatalf("mode %s exit code = %d, want %d", tc.mode, gotExit, tc.wantExit)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Fix 4: StreamLocalBindUnlink socket-only check, origFi TOCTOU, Windows AST
// -----------------------------------------------------------------------------

func TestP0_StreamLocal_BindUnlinkNonSocketAndTOCTOU(t *testing.T) {
	t.Run("rejects_regular_file_symlink_and_directory", assertP0StreamLocalRejectsNonSockets)
	t.Run("replaces_stale_socket_and_preserves_swapped_file_on_close", assertP0StreamLocalReplacesStaleAndPreservesSwap)
	t.Run("direct_near_max_len_path_rejects_regular_file_and_unlinks_stale_socket", assertP0StreamLocalDirectNearMaxLen)
}

func assertP0StreamLocalRejectsNonSockets(t *testing.T) {
	ctx := t.Context()
	dir := p0ShortUnixSocketDir(t)

	// 1. Regular file must NOT be unlinked.
	regPath := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(regPath, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ln, err := listenLocalStreamLocal(ctx, regPath, DefaultStreamLocalBindMask, true); err == nil {
		_ = ln.Close()
		t.Fatal("listenLocalStreamLocal(bindUnlink=true) succeeded on regular file")
	} else if !strings.Contains(err.Error(), "cannot unlink non-socket path") {
		t.Fatalf("unexpected error for regular file: %v", err)
	}
	if got, err := os.ReadFile(regPath); err != nil || string(got) != "precious" {
		t.Fatalf("regular file corrupted/removed: got=%q err=%v", string(got), err)
	}

	// 2. Directory must NOT be unlinked.
	dirTarget := filepath.Join(dir, "subdir")
	if err := os.Mkdir(dirTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	if ln, err := listenLocalStreamLocal(ctx, dirTarget, DefaultStreamLocalBindMask, true); err == nil {
		_ = ln.Close()
		t.Fatal("listenLocalStreamLocal(bindUnlink=true) succeeded on directory")
	} else if !strings.Contains(err.Error(), "cannot unlink non-socket path") {
		t.Fatalf("unexpected error for directory: %v", err)
	}
	if fi, statErr := os.Lstat(dirTarget); statErr != nil || !fi.IsDir() {
		t.Fatalf("directory was removed or altered: %v", statErr)
	}

	// 3. Symlink (even pointing to a real socket!) must NOT be unlinked.
	realSock := filepath.Join(dir, "real.sock")
	realLn, err := net.Listen("unix", realSock)
	if err != nil {
		t.Fatalf("net.Listen(real.sock): %v", err)
	}
	defer func() {
		_ = realLn.Close()
		_ = os.Remove(realSock)
	}()
	linkToSock := filepath.Join(dir, "link-to-sock")
	if err := os.Symlink(realSock, linkToSock); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable on Windows without privileges: %v", err)
		}
		t.Fatal(err)
	}
	if ln, err := listenLocalStreamLocal(ctx, linkToSock, DefaultStreamLocalBindMask, true); err == nil {
		_ = ln.Close()
		t.Fatal("listenLocalStreamLocal(bindUnlink=true) succeeded on symlink to socket")
	} else if !strings.Contains(err.Error(), "cannot unlink non-socket path") {
		t.Fatalf("unexpected error for symlink: %v", err)
	}
	if fi, statErr := os.Lstat(linkToSock); statErr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink was removed or altered: %v", statErr)
	}
	if fi, statErr := os.Lstat(realSock); statErr != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("symlink target socket was removed or altered: %v", statErr)
	}
}

func assertP0StreamLocalReplacesStaleAndPreservesSwap(t *testing.T) {
	ctx := t.Context()
	dir := p0ShortUnixSocketDir(t)
	sockPath := filepath.Join(dir, "stale.sock")

	createStaleUnixSocketForTest(t, sockPath)

	// bindUnlink=true MUST succeed on a real stale socket.
	ln, err := listenLocalStreamLocal(ctx, sockPath, DefaultStreamLocalBindMask, true)
	if err != nil {
		t.Fatalf("listenLocalStreamLocal(bindUnlink=true) on stale socket failed: %v", err)
	}
	fiBefore, err := os.Lstat(sockPath)
	if err != nil || fiBefore.Mode()&os.ModeSocket == 0 {
		_ = ln.Close()
		t.Fatalf("bound path is not a socket: fi=%v err=%v", fiBefore, err)
	}

	// Simulate an external replacement of sockPath with a different file before Close();
	// because origFi was captured from our socket inode, Close() MUST NOT delete the replacement!
	if err := os.Remove(sockPath); err != nil {
		_ = ln.Close()
		t.Fatalf("remove original socket: %v", err)
	}
	if err := os.WriteFile(sockPath, []byte("replacement"), 0o600); err != nil {
		_ = ln.Close()
		t.Fatalf("write replacement: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("ln.Close() failed: %v", err)
	}
	if got, err := os.ReadFile(sockPath); err != nil || string(got) != "replacement" {
		t.Fatalf("Close() deleted externally replaced file: got=%q err=%v", string(got), err)
	}
}

func assertP0StreamLocalDirectNearMaxLen(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix temp-link vs direct sun_path budget test is Unix-specific")
	}
	ctx := t.Context()
	base := p0ShortUnixSocketDir(t)
	maxLen := MaxControlPathLength() - 1
	targetDirLen := maxLen - 5
	if len(base) >= targetDirLen-2 {
		t.Skip("temp dir already too long for direct budget test")
	}
	pad := strings.Repeat("d", targetDirLen-len(base)-1)
	nested := filepath.Join(base, pad)
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	regPath := filepath.Join(nested, "f.s")
	if len(regPath) > maxLen || maxLen-len(regPath) >= 8 || maxLen-(len(nested)+1) >= 8 {
		t.Fatalf("expected direct path budget exhaustion: len(path)=%d len(dir)=%d max=%d", len(regPath), len(nested), maxLen)
	}
	if err := os.WriteFile(regPath, []byte("direct-keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ln, err := listenLocalStreamLocal(ctx, regPath, DefaultStreamLocalBindMask, true); err == nil {
		_ = ln.Close()
		t.Fatal("direct listenLocalStreamLocal(bindUnlink=true) succeeded on regular file")
	} else if !strings.Contains(err.Error(), "cannot unlink non-socket path") {
		t.Fatalf("unexpected direct regular-file error: %v", err)
	}
	if got, err := os.ReadFile(regPath); err != nil || string(got) != "direct-keep" {
		t.Fatalf("direct branch modified/removed regular file: got=%q err=%v", string(got), err)
	}

	stalePath := filepath.Join(nested, "u.s")
	createStaleUnixSocketForTest(t, stalePath)
	ln, err := listenLocalStreamLocal(ctx, stalePath, DefaultStreamLocalBindMask, true)
	if err != nil {
		t.Fatalf("direct listenLocalStreamLocal(bindUnlink=true) on stale socket failed: %v", err)
	}
	_ = ln.Close()
}

func TestP0_StreamLocal_WindowsStructuralInvariants(t *testing.T) {
	t.Parallel()

	inspectFile := func(filename string) map[string]*ast.FuncDecl {
		t.Helper()
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filename, nil, 0)
		if err != nil {
			t.Fatalf("parse %s failed: %v", filename, err)
		}
		funcs := make(map[string]*ast.FuncDecl)
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
				funcs[fn.Name.Name] = fn
			}
		}
		return funcs
	}

	assertCalls := func(filename string, funcs map[string]*ast.FuncDecl, fnName string, required ...string) {
		t.Helper()
		fn := funcs[fnName]
		if fn == nil || fn.Body == nil {
			t.Fatalf("missing function %s in %s", fnName, filename)
		}
		seen := make(map[string]bool)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				seen[fun.Name] = true
			case *ast.SelectorExpr:
				if pkg, ok := fun.X.(*ast.Ident); ok {
					seen[pkg.Name+"."+fun.Sel.Name] = true
				}
			}
			return true
		})
		for _, req := range required {
			if !seen[req] {
				t.Errorf("%s:%s must call %s (seen: %v)", filename, fnName, req, seen)
			}
		}
	}

	slFuncs := inspectFile("streamlocal_windows.go")
	assertCalls("streamlocal_windows.go", slFuncs, "listenLocalStreamLocal",
		"validateWindowsSocketPath",
		"MaxControlPathLength",
		"fsx.ReplaceStaleSocketSlot",
		"fsx.BindSocketSlot",
	)

	// Confirm mux_rights_windows.go also enforces validateWindowsSocketPath and delegates to fsx.SocketSlot.
	mrFuncs := inspectFile("mux_rights_windows.go")
	assertCalls("mux_rights_windows.go", mrFuncs, "bindAndLinkSocket",
		"validateWindowsSocketPath",
		"fsx.BindSocketSlot",
	)
}

// -----------------------------------------------------------------------------
// Fix 5: Path traversal guard in ExpandControlPath & ExpandStreamLocalPath
//        + leading whitespace tilde trim + Windows NTFS ADS bind guard
// -----------------------------------------------------------------------------

func TestP0_ExpandControlAndStreamLocalPath_TraversalAndWhitespace(t *testing.T) {
	t.Parallel()

	baseEnv := Environment{
		HomeDir:   "/home/alice",
		LocalUser: "alice",
		LocalHost: "workstation.example.com",
		LocalUID:  "1000",
	}
	baseTarget := TargetContext{
		Host:         "app.internal",
		Port:         2222,
		User:         "deploy",
		OriginalHost: "app-alias",
		JumpHost:     "bastion.internal",
	}

	assertP0ControlPathWhitespaceTilde(t, baseEnv, baseTarget)
	assertP0IdentityTokenTraversalRejected(t, baseEnv, baseTarget)
	assertP0HashAndIPv6TokenParity(t, baseEnv, baseTarget)
}

func assertP0ControlPathWhitespaceTilde(t *testing.T, baseEnv Environment, baseTarget TargetContext) {
	t.Helper()
	gotTilde, err := ExpandControlPath("  ~/.ssh/cm-%C  ", baseEnv, baseTarget)
	if err != nil {
		t.Fatalf("ExpandControlPath(leading space tilde) failed: %v", err)
	}
	wantTilde, err := ExpandControlPath("~/.ssh/cm-%C", baseEnv, baseTarget)
	if err != nil {
		t.Fatalf("ExpandControlPath(clean tilde) failed: %v", err)
	}
	if gotTilde != wantTilde || !strings.HasPrefix(gotTilde, filepath.Join("/home/alice", ".ssh")) {
		t.Fatalf("ExpandControlPath(leading space tilde) = %q, want %q", gotTilde, wantTilde)
	}
	if gotBareTilde, err := ExpandControlPath("  ~  ", baseEnv, baseTarget); err != nil || gotBareTilde != "/home/alice" {
		t.Fatalf("ExpandControlPath('  ~  ') = (%q, %v), want ('/home/alice', nil)", gotBareTilde, err)
	}
}

func isExpectedShortLocalHostRejection(localHost string) bool {
	short := localHost
	if idx := strings.Index(short, "."); idx != -1 {
		short = short[:idx]
	}
	return short != "" && (strings.ContainsAny(short, `/\`) || short == "." || short == ".." || strings.Contains(short, "..") || strings.ContainsRune(short, 0))
}

func assertP0IdentityTokenTraversalRejected(t *testing.T, baseEnv Environment, baseTarget TargetContext) {
	t.Helper()
	badPayloads := []string{
		"..",
		".",
		"../etc/passwd",
		"foo/../bar",
		"foo/bar",
		`/etc/shadow`,
		`..\evil`,
		`a\b`,
		`\share\evil`,
		"foo..bar",
		"a\x00b",
	}
	tokenSpecs := []struct {
		token string
		apply func(env *Environment, target *TargetContext, payload string)
	}{
		{"%h", func(_ *Environment, target *TargetContext, p string) { target.Host = p }},
		{"%r", func(_ *Environment, target *TargetContext, p string) { target.User = p }},
		{"%n", func(_ *Environment, target *TargetContext, p string) { target.OriginalHost = p }},
		{"%j", func(_ *Environment, target *TargetContext, p string) { target.JumpHost = p }},
		{"%u", func(env *Environment, _ *TargetContext, p string) { env.LocalUser = p }},
		{"%l", func(env *Environment, _ *TargetContext, p string) { env.LocalHost = p }},
		{"%L", func(env *Environment, _ *TargetContext, p string) { env.LocalHost = p + ".corp.local" }},
		{"%i", func(env *Environment, _ *TargetContext, p string) { env.LocalUID = p }},
	}

	for _, ts := range tokenSpecs {
		for _, payload := range badPayloads {
			env := baseEnv
			target := baseTarget
			ts.apply(&env, &target, payload)
			if ts.token == "%L" && !isExpectedShortLocalHostRejection(env.LocalHost) {
				continue
			}

			pattern := "/tmp/dir/" + ts.token + ".sock"
			if got, err := ExpandControlPath(pattern, env, target); err == nil {
				t.Errorf("ExpandControlPath(%q) with %s=%q unexpectedly succeeded -> %q", pattern, ts.token, payload, got)
			}
			if got, err := ExpandStreamLocalPath(pattern, env, target, false); err == nil {
				t.Errorf("ExpandStreamLocalPath(%q) with %s=%q unexpectedly succeeded -> %q", pattern, ts.token, payload, got)
			}
		}
	}
}

func assertP0HashAndIPv6TokenParity(t *testing.T, baseEnv Environment, baseTarget TargetContext) {
	t.Helper()
	hostileTarget := baseTarget
	hostileTarget.Host = "../evil"
	hostileTarget.User = `bad\user`
	if got, err := ExpandControlPath("/tmp/cm-%C.sock", baseEnv, hostileTarget); err != nil {
		t.Fatalf("ExpandControlPath(%%C) with hostile unused fields failed: %v", err)
	} else if !strings.HasPrefix(got, "/tmp/cm-") || strings.Contains(got, "..") || strings.Contains(got, `\`) {
		t.Fatalf("unexpected %%C output: %q", got)
	}

	ipv6Target := TargetContext{
		Host:         "2001:db8::1",
		Port:         2222,
		User:         "ops",
		OriginalHost: "2001:db8::1",
		JumpHost:     "admin@bastion.example:2200",
	}
	if got, err := ExpandControlPath("/tmp/cm-%r@%h-%j.sock", baseEnv, ipv6Target); err != nil {
		t.Fatalf("ExpandControlPath(IPv6+jump port) failed: %v", err)
	} else if got != "/tmp/cm-ops@2001:db8::1-admin@bastion.example:2200.sock" {
		t.Fatalf("unexpected IPv6 control path: %q", got)
	}
	if got, err := ExpandStreamLocalPath("/tmp/sl-%h-%j.sock", baseEnv, ipv6Target, false); err != nil {
		t.Fatalf("ExpandStreamLocalPath(IPv6+jump port) failed: %v", err)
	} else if got != "/tmp/sl-2001:db8::1-admin@bastion.example:2200.sock" {
		t.Fatalf("unexpected IPv6 streamlocal path: %q", got)
	}
}

func TestP0_ValidateWindowsSocketPath(t *testing.T) {
	t.Parallel()

	validPaths := []string{
		`C:\Users\alice\.ssh\cm-0b0117f298c0491db0094f1e54b915bc9cd61bea.sock`,
		`D:/temp/xops/streamlocal.sock`,
		`c:\tmp\mux.sock`,
		`\\server\share\dir\mux.sock`,
		`relative\dir\mux.sock`,
		`cm-simple.sock`,
	}
	for _, p := range validPaths {
		if err := validateWindowsSocketPath(p); err != nil {
			t.Errorf("validateWindowsSocketPath(%q) = %v, want nil", p, err)
		}
	}

	invalidPaths := []string{
		"",
		`C:\Users\alice\.ssh\cm-root@example.com:22`,
		`C:\Users\alice\.ssh\cm-2001:db8::1.sock`,
		`C:\Users\alice\.ssh\sub:ads\cm.sock`,
		`.\cm.sock:evilstream`,
		`C::ads`,
		`1:ads`,
		`:ads`,
		`C:\tmp\a*b.sock`,
		`C:\tmp\a?b.sock`,
		`C:\tmp\a"b.sock`,
		`C:\tmp\a<b.sock`,
		`C:\tmp\a>b.sock`,
		`C:\tmp\a|b.sock`,
		`\\?\C:\tmp\cm.sock`,
		"C:\\tmp\\cm\x00.sock",
		"C:\\tmp\\cm\n.sock",
	}
	for _, p := range invalidPaths {
		if err := validateWindowsSocketPath(p); err == nil {
			t.Errorf("validateWindowsSocketPath(%q) = nil, want error", p)
		}
	}
}

// -----------------------------------------------------------------------------
// Fix 6: MuxServer lifecycle & race fixes
// -----------------------------------------------------------------------------

func TestP0_MuxServer_StopListeningRejectsInFlightOpenFwd(t *testing.T) {
	t.Run("mid_authorize_dynamic_port_0_rejected_after_stop", func(t *testing.T) {
		assertP0StopRejectsMidAuthorizeOpenFwd(t, 0)
	})
	t.Run("mid_authorize_static_port_rejected_after_stop", func(t *testing.T) {
		probeLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint32(probeLn.Addr().(*net.TCPAddr).Port)
		_ = probeLn.Close()
		assertP0StopRejectsMidAuthorizeOpenFwd(t, port)
	})
	t.Run("commitReservedForwardSlot_and_lockForPublishForward_reject_in_stopping_listen", assertP0CommitAndLockRejectStoppingListen)
}

func assertP0StopRejectsMidAuthorizeOpenFwd(t *testing.T, portToBind uint32) {
	t.Helper()
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	close(chans)
	close(reqs)
	rawCli := cryptoSSH.NewClient(&dummyMuxGateConn{}, chans, reqs)
	defer func() { _ = rawCli.Close() }()

	authEntered := make(chan struct{})
	authRelease := make(chan struct{})
	var authOnce sync.Once

	sock := filepath.Join(p0ShortUnixSocketDir(t), "stop-fwd.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:           sock,
		SSHClient:             rawCli,
		PersistEnabled:        true,
		PersistIndefinite:     true,
		InitialActiveSessions: 1, // Keep server alive in muxPhaseStoppingListen until we release it
		AskConfirmation:       true,
		ConfirmSession: func(action string) bool {
			authOnce.Do(func() { close(authEntered) })
			<-authRelease
			return true
		},
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	defer func() {
		_ = srv.Shutdown()
		<-srv.Wait()
	}()
	go func() { _ = srv.Serve() }()

	fwdCli, err := DialMuxClient(t.Context(), sock)
	if err != nil {
		t.Fatalf("DialMuxClient(fwd): %v", err)
	}
	defer func() { _ = fwdCli.Close() }()

	stopCli, err := DialMuxClient(t.Context(), sock)
	if err != nil {
		t.Fatalf("DialMuxClient(stop): %v", err)
	}
	defer func() { _ = stopCli.Close() }()

	openDone := make(chan error, 1)
	go func() {
		_, oErr := fwdCli.OpenForward(t.Context(), ForwardRequest{
			Type:        ForwardLocal,
			ListenHost:  "127.0.0.1",
			ListenPort:  portToBind,
			ConnectHost: "127.0.0.1",
			ConnectPort: 22,
		})
		openDone <- oErr
	}()

	select {
	case <-authEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("handleOpenFwd never reached authorize()")
	}

	if err := stopCli.StopListening(t.Context()); err != nil {
		t.Fatalf("StopListening: %v", err)
	}
	close(authRelease)

	select {
	case openErr := <-openDone:
		if openErr == nil || !strings.Contains(openErr.Error(), "shutting down") {
			t.Fatalf("OpenForward after -O stop = %v, want shutting down error", openErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OpenForward reply after -O stop")
	}

	if got := srv.forwardCount(); got != 0 {
		t.Fatalf("forwardCount() = %d after -O stop rejection, want 0", got)
	}

	srv.RemoveForegroundSession()
	select {
	case <-srv.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("MuxServer did not shut down after releasing foreground session post -O stop")
	}
}

func assertP0CommitAndLockRejectStoppingListen(t *testing.T) {
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	close(chans)
	close(reqs)
	rawCli := cryptoSSH.NewClient(&dummyMuxGateConn{}, chans, reqs)
	defer func() { _ = rawCli.Close() }()

	sock := filepath.Join(p0ShortUnixSocketDir(t), "commit-stop.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:           sock,
		SSHClient:             rawCli,
		PersistEnabled:        true,
		PersistIndefinite:     true,
		InitialActiveSessions: 1,
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	defer func() {
		_ = srv.Shutdown()
		<-srv.Wait()
	}()

	lk := forwardListenKey{fwdScope: muxForwardScopeLocal, network: "tcp", keyHost: "127.0.0.1", listenPort: 18080}
	slot, outcome := srv.acquireForwardEndpoint(lk, MUX_FWD_LOCAL, "example.com", 80)
	if outcome != muxEndpointReserved || slot == nil {
		t.Fatalf("acquireForwardEndpoint = (%v, %v), want reserved", slot, outcome)
	}

	srv.idleMu.Lock()
	srv.markStoppedListeningLocked()
	srv.idleMu.Unlock()

	var closed atomic.Bool
	cand := &muxForwardEntry{
		closer:  p0CloserFunc(func() error { closed.Store(true); return nil }),
		fwdType: MUX_FWD_LOCAL,
	}
	entry, dup, conflict, shuttingDown := srv.commitReservedForwardSlot(lk, slot, "1:127.0.0.1:18080:example.com:80", cand)
	if !shuttingDown || entry != nil || dup || conflict {
		t.Fatalf("commitReservedForwardSlot in StoppingListen = (%v, dup=%v, conflict=%v, shuttingDown=%v), want shuttingDown=true",
			entry, dup, conflict, shuttingDown)
	}
	if !closed.Load() {
		t.Fatal("unpublished candidate closer was not closed on StoppingListen rejection")
	}
	if srv.forwardCount() != 0 {
		t.Fatalf("forwardCount() = %d, want 0", srv.forwardCount())
	}
	if srv.lockForPublishForward(false, forwardListenKey{}) {
		srv.idleMu.Unlock()
		t.Fatal("lockForPublishForward succeeded in StoppingListen, want false")
	}
}

type p0CloserFunc func() error

func (f p0CloserFunc) Close() error { return f() }

func TestP0_MuxServer_ConcurrentStopAndTerminateUnlinkBeforeOK(t *testing.T) {
	for iter := range 5 {
		t.Run(fmt.Sprintf("iter_%d", iter), func(t *testing.T) {
			chans := make(chan cryptoSSH.NewChannel)
			reqs := make(chan *cryptoSSH.Request)
			close(chans)
			close(reqs)
			rawCli := cryptoSSH.NewClient(&dummyMuxGateConn{}, chans, reqs)
			defer func() { _ = rawCli.Close() }()

			sock := filepath.Join(p0ShortUnixSocketDir(t), "race-unlink.sock")
			srv, err := NewMuxServer(MuxServerOptions{
				ControlPath:           sock,
				SSHClient:             rawCli,
				PersistEnabled:        true,
				PersistIndefinite:     true,
				InitialActiveSessions: 1,
			})
			if err != nil {
				t.Fatalf("NewMuxServer: %v", err)
			}
			defer func() {
				_ = srv.Shutdown()
				<-srv.Wait()
			}()
			go func() { _ = srv.Serve() }()

			const clientsN = 6
			clients := make([]*MuxClient, clientsN)
			for i := range clientsN {
				mc, dErr := DialMuxClient(t.Context(), sock)
				if dErr != nil {
					t.Fatalf("DialMuxClient[%d]: %v", i, dErr)
				}
				clients[i] = mc
				defer func(c *MuxClient) { _ = c.Close() }(mc)
			}

			start := make(chan struct{})
			var wg sync.WaitGroup
			errCh := make(chan error, clientsN)
			for i, mc := range clients {
				wg.Add(1)
				go func(idx int, c *MuxClient) {
					defer wg.Done()
					<-start
					var opErr error
					if idx%2 == 0 {
						opErr = c.StopListening(t.Context())
					} else {
						opErr = c.Terminate(t.Context())
					}
					if opErr == nil {
						// Every caller that observes MUX_S_OK MUST observe the socket already unlinked!
						if _, statErr := os.Lstat(sock); !errors.Is(statErr, os.ErrNotExist) {
							errCh <- fmt.Errorf("client %d received MUX_S_OK before control socket %q was unlinked: %w", idx, sock, statErr)
						}
					}
				}(i, mc)
			}
			close(start)
			wg.Wait()
			close(errCh)

			for e := range errCh {
				t.Fatal(e)
			}

			select {
			case <-srv.Wait():
			case <-time.After(2 * time.Second):
				t.Fatal("MuxServer did not shut down after concurrent stop/exit")
			}
		})
	}
}

func TestP0_MuxServer_ControlPersistIdleDisarmedDuringAdmission(t *testing.T) {
	t.Run("proxy_authorize_disarms_idle_timeout", assertP0IdleDisarmedDuringProxyApprove)
	t.Run("denied_proxy_rearms_idle_timeout", assertP0IdleRearmedAfterProxyDeny)
	t.Run("passenger_session_disarms_idle_during_authorize_and_recvFiles", assertP0IdleDisarmedDuringPassengerSession)
}

func assertP0IdleDisarmedDuringProxyApprove(t *testing.T) {
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	close(chans)
	close(reqs)
	rawCli := cryptoSSH.NewClient(&dummyMuxGateConn{}, chans, reqs)
	defer func() { _ = rawCli.Close() }()

	sock := filepath.Join(p0ShortUnixSocketDir(t), "idle-proxy.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:     sock,
		SSHClient:       rawCli,
		PersistEnabled:  true,
		PersistDuration: 45 * time.Millisecond,
		AskConfirmation: true,
		ConfirmSession: func(action string) bool {
			time.Sleep(150 * time.Millisecond)
			return true
		},
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	defer func() {
		_ = srv.Shutdown()
		<-srv.Wait()
	}()
	go func() { _ = srv.Serve() }()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := performClientMuxHandshake(c); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := WriteMuxPacket(c, MUX_C_PROXY, EncodeMuxClientRequestID(1)); err != nil {
		t.Fatalf("WriteMuxPacket(MUX_C_PROXY): %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if pktType, _, err := ReadMuxPacket(c); err != nil || pktType != MUX_S_PROXY {
		t.Fatalf("MUX_C_PROXY reply = (0x%x, %v), want MUX_S_PROXY (idle timeout raced?)", pktType, err)
	}
	if srv.isShuttingDown() {
		t.Fatal("MuxServer entered shutdown while proxy session was admitted")
	}
	_ = c.Close()

	select {
	case <-srv.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("MuxServer did not retire after admitted proxy session closed")
	}
}

func assertP0IdleRearmedAfterProxyDeny(t *testing.T) {
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	close(chans)
	close(reqs)
	rawCli := cryptoSSH.NewClient(&dummyMuxGateConn{}, chans, reqs)
	defer func() { _ = rawCli.Close() }()

	sock := filepath.Join(p0ShortUnixSocketDir(t), "idle-deny.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:     sock,
		SSHClient:       rawCli,
		PersistEnabled:  true,
		PersistDuration: 45 * time.Millisecond,
		AskConfirmation: true,
		ConfirmSession: func(action string) bool {
			time.Sleep(120 * time.Millisecond)
			return false
		},
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	defer func() {
		_ = srv.Shutdown()
		<-srv.Wait()
	}()
	go func() { _ = srv.Serve() }()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := performClientMuxHandshake(c); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := WriteMuxPacket(c, MUX_C_PROXY, EncodeMuxClientRequestID(2)); err != nil {
		t.Fatalf("WriteMuxPacket(MUX_C_PROXY): %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if pktType, _, err := ReadMuxPacket(c); err != nil || pktType != MUX_S_PERMISSION_DENIED {
		t.Fatalf("MUX_C_PROXY(denied) reply = (0x%x, %v), want MUX_S_PERMISSION_DENIED (not shutdown)", pktType, err)
	}

	select {
	case <-srv.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("MuxServer did not retire on idle timeout after denied proxy admission")
	}
}

func assertP0IdleDisarmedDuringPassengerSession(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix passenger admission test requires linux or darwin")
	}
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	close(chans)
	close(reqs)
	rawCli := cryptoSSH.NewClient(&p0PassengerExitSSHConn{mode: "exit-0"}, chans, reqs)
	defer func() { _ = rawCli.Close() }()

	sock := filepath.Join(p0ShortUnixSocketDir(t), "idle-pass.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:     sock,
		SSHClient:       rawCli,
		PersistEnabled:  true,
		PersistDuration: 45 * time.Millisecond,
		AskConfirmation: true,
		ConfirmSession: func(action string) bool {
			time.Sleep(120 * time.Millisecond)
			return true
		},
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	defer func() {
		_ = srv.Shutdown()
		<-srv.Wait()
	}()
	go func() { _ = srv.Serve() }()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := performClientMuxHandshake(c); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := WriteMuxPacket(c, MUX_C_NEW_SESSION, EncodeMuxNewSession(MuxNewSessionRequest{
		RequestID: 15,
		Command:   "ok",
	})); err != nil {
		t.Fatalf("WriteMuxPacket: %v", err)
	}

	// Delay sending FDs well past PersistDuration to also cover recvFiles window!
	time.Sleep(160 * time.Millisecond)

	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	defer func() {
		_ = inW.Close()
		_ = outR.Close()
		_ = errR.Close()
	}()
	sendPortableUnixFDs(t, c, inR, outW, errW)
	_ = inR.Close()
	_ = outW.Close()
	_ = errW.Close()

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if pktType, _, err := ReadMuxPacket(c); err != nil || pktType != MUX_S_SESSION_OPENED {
		t.Fatalf("first packet = (0x%x, %v), want MUX_S_SESSION_OPENED", pktType, err)
	}
	_, _ = io.ReadAll(outR)
	pktType, payload, err := ReadMuxPacket(c)
	if err != nil || pktType != MUX_S_EXIT_MESSAGE {
		t.Fatalf("second packet = (0x%x, %v), want MUX_S_EXIT_MESSAGE", pktType, err)
	}
	_, code, _ := DecodeMuxExitMessage(payload)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	select {
	case <-srv.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("MuxServer did not retire after passenger session finished")
	}
}

func TestP0_MuxServer_ControlPersistIdleDisarmedDuringStdioFwdAdmission(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Unix passenger stdio fwd admission test requires linux or darwin")
	}

	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	close(chans)
	close(reqs)
	rawCli := cryptoSSH.NewClient(&p0HalfCloseStdioSSHConn{}, chans, reqs)
	defer func() { _ = rawCli.Close() }()

	sock := filepath.Join(p0ShortUnixSocketDir(t), "idle-sf.sock")
	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:     sock,
		SSHClient:       rawCli,
		PersistEnabled:  true,
		PersistDuration: 45 * time.Millisecond,
		AskConfirmation: true,
		ConfirmSession: func(action string) bool {
			time.Sleep(120 * time.Millisecond)
			return true
		},
	})
	if err != nil {
		t.Fatalf("NewMuxServer: %v", err)
	}
	defer func() {
		_ = srv.Shutdown()
		<-srv.Wait()
	}()
	go func() { _ = srv.Serve() }()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := performClientMuxHandshake(c); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if err := WriteMuxPacket(c, MUX_C_NEW_STDIO_FWD, EncodeMuxNewStdioFwd(MuxNewStdioFwdRequest{
		RequestID:   25,
		ConnectHost: "127.0.0.1",
		ConnectPort: 9001,
	})); err != nil {
		t.Fatalf("WriteMuxPacket: %v", err)
	}

	// Delay sending FDs past PersistDuration to prove recvFiles is also shielded from onIdleTimeout.
	time.Sleep(160 * time.Millisecond)

	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	defer func() {
		_ = outR.Close()
	}()
	sendPortableUnixFDs(t, c, inR, outW)
	_ = inR.Close()
	_ = outW.Close()

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	pktType, _, err := ReadMuxPacket(c)
	if err != nil || pktType != MUX_S_SESSION_OPENED {
		t.Fatalf("first packet = (0x%x, %v), want MUX_S_SESSION_OPENED", pktType, err)
	}
	got, err := io.ReadAll(outR)
	if err != nil || string(got) != "READY\n" {
		t.Fatalf("stdio fwd stdout = (%q, %v), want READY\\n", string(got), err)
	}
	_ = inW.Close()

	pktType, payload, err := ReadMuxPacket(c)
	if err != nil || pktType != MUX_S_EXIT_MESSAGE {
		t.Fatalf("second packet = (0x%x, %v), want MUX_S_EXIT_MESSAGE", pktType, err)
	}
	_, code, _ := DecodeMuxExitMessage(payload)
	if code != 0 {
		t.Fatalf("stdio fwd exit code = %d, want 0", code)
	}

	select {
	case <-srv.Wait():
	case <-time.After(2 * time.Second):
		t.Fatal("MuxServer did not retire after stdio fwd finished")
	}
}
