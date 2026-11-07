package ssh

import (
	"context"
	"errors"
	"fmt"
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

type dummySSHConn struct {
	chans  chan cryptoSSH.NewChannel
	reqs   chan *cryptoSSH.Request
	closed bool
	mu     sync.Mutex
}

func (d *dummySSHConn) User() string                                           { return "test" }
func (d *dummySSHConn) SessionID() []byte                                      { return []byte("test") }
func (d *dummySSHConn) ClientVersion() []byte                                  { return []byte("test") }
func (d *dummySSHConn) ServerVersion() []byte                                  { return []byte("test") }
func (d *dummySSHConn) RemoteAddr() net.Addr                                   { return &net.IPAddr{} }
func (d *dummySSHConn) LocalAddr() net.Addr                                    { return &net.IPAddr{} }
func (d *dummySSHConn) SendRequest(string, bool, []byte) (bool, []byte, error) { return true, nil, nil }
func (d *dummySSHConn) OpenChannel(string, []byte) (cryptoSSH.Channel, <-chan *cryptoSSH.Request, error) {
	return nil, nil, errors.New("open channel not implemented in dummy")
}
func (d *dummySSHConn) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.closed {
		d.closed = true
		close(d.chans)
		close(d.reqs)
	}
	return nil
}
func (d *dummySSHConn) Wait() error { return nil }

func newDummySSHClient() *cryptoSSH.Client {
	chans := make(chan cryptoSSH.NewChannel)
	reqs := make(chan *cryptoSSH.Request)
	conn := &dummySSHConn{chans: chans, reqs: reqs}
	return cryptoSSH.NewClient(conn, chans, reqs)
}

func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "xops-mux-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestMuxServer_SocketCreation_PermissionsAndLink(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mux-server-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "master.sock")
	opts := MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   newDummySSHClient(),
	}

	server, err := NewMuxServer(opts)
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()

	// Check file exists
	fi, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("socket file does not exist: %v", err)
	}

	if runtime.GOOS != "windows" {
		// Verify permissions 0600
		perm := fi.Mode().Perm()
		if perm != 0600 {
			t.Fatalf("expected permissions 0600, got %o", perm)
		}
	}

	// Creating a second server on the same path must return ErrMasterAlreadyExists
	_, err = NewMuxServer(opts)
	if err == nil || !errors.Is(err, ErrMasterAlreadyExists) {
		t.Fatalf("expected ErrMasterAlreadyExists, got: %v", err)
	}
}

func TestMuxServer_AliveCheck(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mux-server-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "alive.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   newDummySSHClient(),
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()

	go func() { _ = server.Serve() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	pid, err := client.AliveCheck(ctx)
	if err != nil {
		t.Fatalf("AliveCheck failed: %v", err)
	}
	if int(pid) != os.Getpid() {
		t.Fatalf("expected pid %d, got %d", os.Getpid(), pid)
	}
}

func TestMuxServer_PeerUID_Verification(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Peer UID verification not applicable on Windows")
	}

	tmpDir, err := os.MkdirTemp("", "mux-server-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "peeruid.sock")

	// 1. Matching UID
	currentUID := uint32(os.Getuid())
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:  sockPath,
		ExpectedUID:  currentUID,
		CheckPeerUID: true,
		SSHClient:    newDummySSHClient(),
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	go func() { _ = server.Serve() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed with matching UID: %v", err)
	}
	if _, err := client.AliveCheck(ctx); err != nil {
		t.Fatalf("AliveCheck failed with matching UID: %v", err)
	}
	_ = client.Close()
	_ = server.Shutdown()

	// 2. Mismatched UID (currentUID + 1)
	mismatchPath := filepath.Join(tmpDir, "mismatch.sock")
	serverMismatch, err := NewMuxServer(MuxServerOptions{
		ControlPath:  mismatchPath,
		ExpectedUID:  currentUID + 9999,
		CheckPeerUID: true,
		SSHClient:    newDummySSHClient(),
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = serverMismatch.Shutdown() }()
	go func() { _ = serverMismatch.Serve() }()

	_, err = DialMuxClient(ctx, mismatchPath)
	if err == nil {
		t.Fatal("expected connection to fail with mismatched UID, got nil error")
	}
}

func TestMuxServer_Terminate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mux-server-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "term.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   newDummySSHClient(),
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}

	go func() { _ = server.Serve() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	if err := client.Terminate(ctx); err != nil {
		t.Fatalf("Terminate failed: %v", err)
	}

	// Server shutdown channel should close
	select {
	case <-server.Wait():
		// OK
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for server shutdown")
	}

	// Socket file should be removed
	if socketPathExists(sockPath) {
		t.Fatalf("expected socket %q to be unlinked after termination", sockPath)
	}
}

func TestMuxServer_StopListening(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mux-server-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "stop.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   newDummySSHClient(),
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()

	go func() { _ = server.Serve() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	if err := client.StopListening(ctx); err != nil {
		t.Fatalf("StopListening failed: %v", err)
	}

	// Socket file should be unlinked
	time.Sleep(50 * time.Millisecond)
	if socketPathExists(sockPath) {
		t.Fatalf("expected socket %q to be unlinked after stop listening", sockPath)
	}
}

func TestMuxServer_ControlPersist_IdleCountdown(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mux-server-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "persist.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:     sockPath,
		PersistEnabled:  true,
		PersistDuration: 100 * time.Millisecond,
		SSHClient:       newDummySSHClient(),
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}

	go func() { _ = server.Serve() }()

	// Server should shut down after 100ms idle
	select {
	case <-server.Wait():
		// OK
	case <-time.After(1 * time.Second):
		t.Fatal("server did not shut down on idle timeout")
	}

	if socketPathExists(sockPath) {
		t.Fatalf("expected socket %q to be unlinked after idle shutdown", sockPath)
	}
}

func TestMuxServer_LongSocketPaths(t *testing.T) {
	maxLen := MaxControlPathLength()
	tmpDir, err := os.MkdirTemp("", "m1-longpath-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	mockClient := newDummySSHClient()

	// Test boundary lengths up to maxLen - 1
	lengthsToTest := []int{50, 70, 75, 80, 85, 90, 95, 100, maxLen - 1}

	for _, targetLen := range lengthsToTest {
		if targetLen >= maxLen {
			continue
		}
		prefix := filepath.Join(tmpDir, "s_")
		if len(prefix) >= targetLen {
			continue
		}
		sockName := prefix + strings.Repeat("x", targetLen-len(prefix))
		if len(sockName) != targetLen {
			continue
		}

		if err := ValidateControlPath(sockName); err != nil {
			t.Fatalf("ValidateControlPath rejected valid length %d: %v", targetLen, err)
		}

		server, err := NewMuxServer(MuxServerOptions{
			ControlPath: sockName,
			SSHClient:   mockClient,
		})
		if err != nil {
			t.Fatalf("NewMuxServer failed for valid length %d: %v", targetLen, err)
		}

		fi, err := os.Stat(sockName)
		if err != nil {
			_ = server.Shutdown()
			t.Fatalf("socket does not exist for length %d: %v", targetLen, err)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0600 {
			_ = server.Shutdown()
			t.Fatalf("expected perm 0600 for length %d, got %o", targetLen, fi.Mode().Perm())
		}

		_ = server.Shutdown()
	}
}

func TestMuxServer_UmaskIsolationConcurrent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "m1-umask-iso-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	mockClient := newDummySSHClient()
	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	// Goroutine 1: Continuously create temporary directories and verify +x execute permission
	var dirPermErr atomic.Pointer[error]
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopChan:
				return
			default:
				d, err := os.MkdirTemp(tmpDir, "check-perm-*")
				if err != nil {
					e := fmt.Errorf("MkdirTemp failed: %w", err)
					dirPermErr.Store(&e)
					return
				}
				fi, err := os.Stat(d)
				if err != nil {
					e := fmt.Errorf("stat failed: %w", err)
					dirPermErr.Store(&e)
					return
				}
				// Verify execute permission (0100) is never stripped
				if fi.Mode().Perm()&0100 == 0 {
					e := fmt.Errorf("CRITICAL: directory %s lost execute permission: %o", d, fi.Mode().Perm())
					dirPermErr.Store(&e)
					return
				}
				_ = os.Remove(d)
			}
		}
	}()

	// Goroutine 2: Repeatedly start and stop MuxServers
	for i := 0; i < 50; i++ {
		sockPath := filepath.Join(tmpDir, fmt.Sprintf("server_%d.sock", i))
		server, err := NewMuxServer(MuxServerOptions{
			ControlPath: sockPath,
			SSHClient:   mockClient,
		})
		if err != nil {
			t.Fatalf("NewMuxServer iteration %d failed: %v", i, err)
		}
		_ = server.Shutdown()
	}

	close(stopChan)
	wg.Wait()

	if errPtr := dirPermErr.Load(); errPtr != nil {
		t.Fatalf("Umask isolation failure: %v", *errPtr)
	}
}

func TestMuxServer_ExtInfo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mux-extinfo-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "info.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   newDummySSHClient(),
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()

	go func() { _ = server.Serve() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	connInfo, err := client.RequestInfo(ctx, "connection")
	if err != nil {
		t.Fatalf("RequestInfo(connection) failed: %v", err)
	}
	if !strings.Contains(connInfo, "OpenSSH multiplexing control connection") {
		t.Fatalf("unexpected connection info: %s", connInfo)
	}

	chanInfo, err := client.RequestInfo(ctx, "channels")
	if err != nil {
		t.Fatalf("RequestInfo(channels) failed: %v", err)
	}
	if !strings.Contains(chanInfo, "Active Forwardings:") {
		t.Fatalf("unexpected channels info: %s", chanInfo)
	}
}

func TestMuxServer_ForegroundSession(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mux-foreground-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "fg.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:           sockPath,
		SSHClient:             newDummySSHClient(),
		PersistEnabled:        true,
		PersistDuration:       100 * time.Millisecond,
		InitialActiveSessions: 1,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()

	if server.ActiveSessions() != 1 {
		t.Fatalf("expected 1 active session, got %d", server.ActiveSessions())
	}

	// Should not shut down because active session is 1
	time.Sleep(150 * time.Millisecond)
	select {
	case <-server.Wait():
		t.Fatal("server shut down prematurely while foreground session active")
	default:
	}

	// Remove foreground session
	server.RemoveForegroundSession()
	if server.ActiveSessions() != 0 {
		t.Fatalf("expected 0 active sessions, got %d", server.ActiveSessions())
	}

	// Now it should shut down after persistDuration
	select {
	case <-server.Wait():
		// OK
	case <-time.After(500 * time.Millisecond):
		t.Fatal("server failed to shut down after foreground session removed")
	}
}

func TestMuxServer_MalformedRequestPreservesRequestID(t *testing.T) {
	sockPath := filepath.Join(shortSocketDir(t), "malformed.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   newDummySSHClient(),
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, nil)); err != nil {
		t.Fatalf("send hello failed: %v", err)
	}
	if _, _, err := ReadMuxPacket(conn); err != nil {
		t.Fatalf("read hello failed: %v", err)
	}

	// Send a truncated MUX_C_NEW_SESSION containing only request_id = 42.
	const wantReqID uint32 = 42
	if err := WriteMuxPacket(conn, MUX_C_NEW_SESSION, EncodeMuxRequestID(wantReqID)); err != nil {
		t.Fatalf("send truncated new session failed: %v", err)
	}
	msgType, payload, err := ReadMuxPacket(conn)
	if err != nil {
		t.Fatalf("read failure response failed: %v", err)
	}
	if msgType != MUX_S_FAILURE {
		t.Fatalf("expected MUX_S_FAILURE (0x%08x), got 0x%08x", MUX_S_FAILURE, msgType)
	}
	gotReqID, reason, err := DecodeMuxError(payload)
	if err != nil {
		t.Fatalf("DecodeMuxError failed: %v", err)
	}
	if gotReqID != wantReqID {
		t.Fatalf("expected failure request_id=%d, got %d (reason=%q)", wantReqID, gotReqID, reason)
	}
}

func TestMuxServer_ForwardKeyNormalizesEmptyListenHost(t *testing.T) {
	sockPath := filepath.Join(shortSocketDir(t), "fwd-norm.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   newDummySSHClient(),
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Pick an ephemeral local port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	freePort := uint32(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()

	// Open with empty ListenHost (simulating native `ssh -O forward -L port:host:port`)
	fwdReq := ForwardRequest{
		Type:        ForwardLocal,
		ListenHost:  "",
		ListenPort:  freePort,
		ConnectHost: "127.0.0.1",
		ConnectPort: 80,
	}
	if _, err := client.OpenForward(ctx, fwdReq); err != nil {
		t.Fatalf("OpenForward failed: %v", err)
	}

	channelsInfo, err := client.RequestInfo(ctx, "channels")
	if err != nil {
		t.Fatalf("RequestInfo(channels) failed: %v", err)
	}
	expectedEntry := fmt.Sprintf("1:127.0.0.1:%d:127.0.0.1:80", freePort)
	if !strings.Contains(channelsInfo, expectedEntry) {
		t.Fatalf("expected normalized forward entry %q in channels info, got:\n%s", expectedEntry, channelsInfo)
	}

	// Cancel with explicit 127.0.0.1 ListenHost must match the normalized key
	cancelReq := fwdReq
	cancelReq.ListenHost = "127.0.0.1"
	if err := client.CloseForward(ctx, cancelReq); err != nil {
		t.Fatalf("CloseForward with normalized host failed: %v", err)
	}
}
