//go:build linux || darwin || freebsd

package ssh

import (
	"bytes"
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

type round4HalfCloseSSHConn struct {
	dummyMuxGateConn
	uploadBuf bytes.Buffer
	mu        sync.Mutex
	eofSent   chan struct{}
	eofOnce   sync.Once
}

func (c *round4HalfCloseSSHConn) OpenChannel(name string, _ []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	reqs := make(chan *cryptoSSH.Request)
	closeWhenClosed := make(chan struct{})
	ch := &round4HalfCloseChannel{
		banner:      "READY\n",
		parent:      c,
		reqs:        reqs,
		closeSignal: closeWhenClosed,
	}
	return ch, reqs, nil
}

type round4HalfCloseChannel struct {
	parent      *round4HalfCloseSSHConn
	banner      string
	bannerSent  bool
	reqs        chan *cryptoSSH.Request
	closeSignal chan struct{}
	closeOnce   sync.Once
}

func (c *round4HalfCloseChannel) Read(p []byte) (int, error) {
	if !c.bannerSent {
		c.bannerSent = true
		n := copy(p, c.banner)
		return n, nil
	}
	return 0, io.EOF // Immediate remote half-close while channel remains open for stdin writes!
}

func (c *round4HalfCloseChannel) Write(p []byte) (int, error) {
	c.parent.mu.Lock()
	n, err := c.parent.uploadBuf.Write(p)
	c.parent.mu.Unlock()
	return n, err
}

func (c *round4HalfCloseChannel) CloseWrite() error {
	c.parent.eofOnce.Do(func() { close(c.parent.eofSent) })
	c.closeOnce.Do(func() {
		close(c.closeSignal)
		close(c.reqs)
	})
	return nil
}

func (c *round4HalfCloseChannel) Close() error {
	_ = c.CloseWrite()
	return nil
}
func (c *round4HalfCloseChannel) Stderr() io.ReadWriter                          { return &nopRW{} }
func (c *round4HalfCloseChannel) SendRequest(string, bool, []byte) (bool, error) { return false, nil }

func TestRound4_P2_6_PassengerStdioFwdPreservesRemoteHalfCloseUpload(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "xops-r4-hf-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()
	sock := filepath.Join(tmpDir, "hf.sock")

	mockConn := &round4HalfCloseSSHConn{eofSent: make(chan struct{})}
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	close(chans)
	close(reqs)
	raw := cryptoSSH.NewClient(mockConn, chans, reqs)
	defer func() { _ = raw.Close() }()

	srv, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sock,
		SSHClient:         raw,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown() }()
	go func() { _ = srv.Serve() }()

	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err := performClientMuxHandshake(c); err != nil {
		t.Fatal(err)
	}
	if err := WriteMuxPacket(c, MUX_C_NEW_STDIO_FWD, EncodeMuxNewStdioFwd(MuxNewStdioFwdRequest{
		RequestID:   9,
		ConnectHost: "127.0.0.1",
		ConnectPort: 9000,
	})); err != nil {
		t.Fatal(err)
	}
	inR, inW, outR, outW := sendKeepOpenStdioPipes(t, c)
	_ = inR.Close()
	_ = outW.Close()
	defer func() {
		_ = inW.Close()
		_ = outR.Close()
	}()

	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	pktType, _, err := ReadMuxPacket(c)
	if err != nil || pktType != MUX_S_SESSION_OPENED {
		t.Fatalf("ReadMuxPacket = (0x%x, %v), want MUX_S_SESSION_OPENED", pktType, err)
	}

	// Read READY banner and wait for stdout EOF triggered by remote half-close.
	banner, err := io.ReadAll(outR)
	if err != nil || string(banner) != "READY\n" {
		t.Fatalf("stdout banner = (%q, %v), want %q", string(banner), err, "READY\n")
	}

	// Even AFTER remote half-close + stdout EOF, client stdin upload MUST still succeed!
	wantPayload := strings.Repeat("upload-data-", 64)
	if _, err := io.WriteString(inW, wantPayload); err != nil {
		t.Fatalf("write stdin after remote half-close failed: %v", err)
	}
	_ = inW.Close()

	select {
	case <-mockConn.eofSent:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for client stdin CloseWrite after remote half-close")
	}
	mockConn.mu.Lock()
	gotUpload := mockConn.uploadBuf.String()
	mockConn.mu.Unlock()
	if gotUpload != wantPayload {
		t.Fatalf("uploaded len=%d, want %d", len(gotUpload), len(wantPayload))
	}
}

func TestRound4_P2_7_CopyStdinToPreservesNonBlockAndRetriesEAGAIN(t *testing.T) {
	sv, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.SetNonblock(sv[0], true)
	rFile := os.NewFile(uintptr(sv[0]), "nonblock-stdin")
	wFile := os.NewFile(uintptr(sv[1]), "nonblock-peer")
	defer func() {
		_ = rFile.Close()
		_ = wFile.Close()
	}()

	var out bytes.Buffer
	var outMu sync.Mutex
	notify := make(chan struct{}, 16)
	w := &lockedBufWriter{buf: &out, mu: &outMu, notify: notify}

	cancel, done, err := copyStdinTo(rFile, w)
	if err != nil {
		t.Fatalf("copyStdinTo: %v", err)
	}
	waitOut := func(want string) {
		t.Helper()
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		for {
			outMu.Lock()
			got := out.String()
			outMu.Unlock()
			if got == want {
				return
			}
			select {
			case <-notify:
			case <-deadline.C:
				outMu.Lock()
				cur := out.String()
				outMu.Unlock()
				t.Fatalf("timed out waiting for %q, got %q", want, cur)
			}
		}
	}
	if _, err := wFile.Write([]byte("chunk-1")); err != nil {
		t.Fatal(err)
	}
	waitOut("chunk-1")
	if _, err := wFile.Write([]byte("chunk-2")); err != nil {
		t.Fatal(err)
	}
	waitOut("chunk-1chunk-2")
	_ = cancel()
	if cErr := <-done; cErr != nil {
		t.Fatalf("copyStdinTo returned error: %v", cErr)
	}

	raw, _ := rFile.SyscallConn()
	var flags int
	_ = raw.Control(func(fd uintptr) {
		flags, _ = unix.FcntlInt(fd, unix.F_GETFL, 0)
	})
	if flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("copyStdinTo cleared O_NONBLOCK on caller-owned nonblocking descriptor: flags=%#x", flags)
	}
	outMu.Lock()
	got := out.String()
	outMu.Unlock()
	if got != "chunk-1chunk-2" {
		t.Fatalf("copied stdin = %q, want %q", got, "chunk-1chunk-2")
	}
}

type lockedBufWriter struct {
	mu     *sync.Mutex
	buf    *bytes.Buffer
	notify chan struct{}
}

func (w *lockedBufWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.buf.Write(p)
	w.mu.Unlock()
	if w.notify != nil && n > 0 {
		select {
		case w.notify <- struct{}{}:
		default:
		}
	}
	return n, err
}

func TestRound4_P2_3_BlockingSocketOutputDoesNotBlockOnDisconnect(t *testing.T) {
	sv, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Put sv[0] in blocking mode as an inherited passenger stdout socket.
	_ = unix.SetNonblock(sv[0], false)
	sockW := os.NewFile(uintptr(sv[0]), "blocking-sock-out")
	sockR := os.NewFile(uintptr(sv[1]), "blocking-sock-peer")
	defer func() {
		_ = sockW.Close()
		_ = sockR.Close()
	}()

	stop := make(chan struct{})
	srcDone := make(chan struct{})
	src := &blockingFloodReader{done: srcDone}
	done := make(chan error, 1)
	go func() {
		done <- copyToPollableFD(sockW, src, stop)
	}()

	cSock, _ := sockW.SyscallConn()
	_ = cSock.Control(func(fd uintptr) { waitPipeWriteBackpressured(t, int(fd)) })
	close(stop)
	close(srcDone)
	select {
	case copyErr := <-done:
		if copyErr != nil {
			t.Fatalf("copyToPollableFD(blocking socket) err = %v", copyErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("copyToPollableFD(blocking socket) blocked in kernel send past stop cancellation")
	}
}

func TestRound4_P2_3_SharedBlockingPipeSerializedFallbackDoesNotBlock(t *testing.T) {
	rPipe, wPipe1, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	dupFD, err := unix.Dup(int(wPipe1.Fd()))
	if err != nil {
		_ = rPipe.Close()
		_ = wPipe1.Close()
		t.Fatal(err)
	}
	unix.CloseOnExec(dupFD)
	wPipe2 := os.NewFile(uintptr(dupFD), "shared-blocking-stderr")
	defer func() {
		_ = rPipe.Close()
		_ = wPipe1.Close()
		_ = wPipe2.Close()
	}()

	// Put shared pipe write end in blocking mode to force shared blocking fallback.
	c1, _ := wPipe1.SyscallConn()
	_ = c1.Control(func(fd uintptr) { _ = unix.SetNonblock(int(fd), false) })
	_, owned, _, needSharedLock, _, targetErr := preparePollableWriteTarget(wPipe1, false)
	if owned != nil {
		_ = owned.Close()
	}
	if targetErr != nil || !needSharedLock {
		t.Fatalf("preparePollableWriteTarget(allowReopen=false) = (needSharedLock=%v, err=%v), want (true, nil)", needSharedLock, targetErr)
	}

	stop := make(chan struct{})
	srcDone := make(chan struct{})
	var sharedMu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = copyToPollableFDWithReopen(wPipe1, &blockingFloodReader{done: srcDone}, stop, &sharedMu, false)
	}()
	go func() {
		defer wg.Done()
		_ = copyToPollableFDWithReopen(wPipe2, &blockingFloodReader{done: srcDone}, stop, &sharedMu, false)
	}()

	_ = c1.Control(func(fd uintptr) { waitPipeWriteBackpressured(t, int(fd)) })
	close(stop)
	close(srcDone)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shared blocking pipe serialized writers blocked past stop cancellation")
	}
}

type blockingFloodReader struct {
	done chan struct{}
}

func (r *blockingFloodReader) Read(p []byte) (int, error) {
	select {
	case <-r.done:
		return 0, io.EOF
	default:
		for i := range p {
			p[i] = 'a'
		}
		return len(p), nil
	}
}
