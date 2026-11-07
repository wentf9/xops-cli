package ssh

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
)

// TestAdversarial_ControlPersist_ForegroundSessionProtection verifies that
// an interactive foreground master does NOT terminate prematurely after
// PersistDuration expires while the session is active, nor does a finishing
// proxy client inadvertently start the idle countdown while the foreground session is ongoing.
func TestAdversarial_ControlPersist_ForegroundSessionProtection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "adv-fg-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "fg_protect.sock")
	persistDuration := 150 * time.Millisecond

	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:           sockPath,
		SSHClient:             newDummySSHClient(),
		PersistEnabled:        true,
		PersistDuration:       persistDuration,
		InitialActiveSessions: 1, // Foreground session active
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()

	go func() { _ = server.Serve() }()

	if server.ActiveSessions() != 1 {
		t.Fatalf("expected activeSessions == 1, got %d", server.ActiveSessions())
	}

	// 1. Wait longer than 2x persistDuration while foreground session is active
	time.Sleep(350 * time.Millisecond)

	select {
	case <-server.Wait():
		t.Fatal("CRITICAL: foreground master terminated prematurely while session was active!")
	default:
		// Passed: server is still running
	}

	// 2. Perform AliveCheck via client to verify server responds properly
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed during active foreground session: %v", err)
	}
	defer func() { _ = client.Close() }()

	pid, err := client.AliveCheck(ctx)
	if err != nil || pid == 0 {
		t.Fatalf("AliveCheck failed during foreground session: %v, pid=%d", err, pid)
	}

	// 3. Connect a proxy client, verify active sessions increments
	proxyRawConn, err := connectTestProxyClient(sockPath)
	if err != nil {
		t.Fatalf("connectTestProxyClient failed: %v", err)
	}

	if server.ActiveSessions() != 2 {
		_ = proxyRawConn.Close()
		t.Fatalf("expected activeSessions == 2 with proxy connected, got %d", server.ActiveSessions())
	}

	// Disconnect the proxy client
	_ = proxyRawConn.Close()

	// Wait for server to process proxy disconnect
	deadline := time.Now().Add(200 * time.Millisecond)
	for server.ActiveSessions() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if server.ActiveSessions() != 1 {
		t.Fatalf("expected activeSessions to return to 1 after proxy disconnect, got %d", server.ActiveSessions())
	}

	// Wait another 300ms (> persistDuration) to verify proxy exit did NOT trigger idle shutdown
	time.Sleep(300 * time.Millisecond)
	select {
	case <-server.Wait():
		t.Fatal("CRITICAL: proxy exit triggered idle shutdown while foreground session was still active!")
	default:
		// Passed
	}

	// 4. End the foreground session
	server.RemoveForegroundSession()
	if server.ActiveSessions() != 0 {
		t.Fatalf("expected activeSessions == 0 after RemoveForegroundSession, got %d", server.ActiveSessions())
	}

	// Now idle timer should expire and server should terminate within [persistDuration, persistDuration + 500ms]
	select {
	case <-server.Wait():
		// Succeeded: server exited cleanly on idle timeout
	case <-time.After(1 * time.Second):
		t.Fatal("server failed to terminate after foreground session removed and idle timeout elapsed")
	}

	// Verify socket file was unlinked
	if socketPathExists(sockPath) {
		t.Fatalf("expected socket %q to be unlinked after shutdown", sockPath)
	}
}

func connectTestProxyClient(sockPath string) (net.Conn, error) {
	proxyRawConn, err := net.Dial("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	if err := performClientMuxHandshake(proxyRawConn); err != nil {
		_ = proxyRawConn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	if err := WriteMuxPacket(proxyRawConn, MUX_C_PROXY, EncodeMuxRequestID(10)); err != nil {
		_ = proxyRawConn.Close()
		return nil, fmt.Errorf("send proxy packet: %w", err)
	}
	respType, _, err := ReadMuxPacket(proxyRawConn)
	if err != nil || respType != MUX_S_PROXY {
		_ = proxyRawConn.Close()
		return nil, fmt.Errorf("expected MUX_S_PROXY, got 0x%x (err: %w)", respType, err)
	}
	return proxyRawConn, nil
}

// TestAdversarial_ControlPersist_ResetTimerOnNewClient verifies that incoming
// client connections properly cancel and reset the idle timeout countdown.
func TestAdversarial_ControlPersist_ResetTimerOnNewClient(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "adv-reset-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "reset.sock")
	persistDuration := 250 * time.Millisecond

	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:           sockPath,
		SSHClient:             newDummySSHClient(),
		PersistEnabled:        true,
		PersistDuration:       persistDuration,
		InitialActiveSessions: 0, // Starts idle
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()

	go func() { _ = server.Serve() }()

	// Wait 120ms (nearly halfway through persistDuration)
	time.Sleep(120 * time.Millisecond)

	// Connect a proxy client
	proxyConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial proxyConn failed: %v", err)
	}
	defer func() { _ = proxyConn.Close() }()

	if err := performClientMuxHandshake(proxyConn); err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if err := WriteMuxPacket(proxyConn, MUX_C_PROXY, EncodeMuxRequestID(1)); err != nil {
		t.Fatalf("send MUX_C_PROXY failed: %v", err)
	}
	respType, _, err := ReadMuxPacket(proxyConn)
	if err != nil || respType != MUX_S_PROXY {
		t.Fatalf("expected MUX_S_PROXY, got 0x%x (err: %v)", respType, err)
	}

	// Hold connection for 300ms (> original persistDuration)
	time.Sleep(300 * time.Millisecond)

	select {
	case <-server.Wait():
		t.Fatal("CRITICAL: server shut down while proxy client was actively connected!")
	default:
		// OK: alive
	}

	// Close proxy connection
	_ = proxyConn.Close()

	// Wait for activeSessions to hit 0
	deadline := time.Now().Add(200 * time.Millisecond)
	for server.ActiveSessions() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// At this point, a fresh persistDuration timer (250ms) must have started.
	// After 100ms, server should still be alive
	time.Sleep(100 * time.Millisecond)
	select {
	case <-server.Wait():
		t.Fatal("server shut down too early before new persistDuration elapsed")
	default:
		// OK
	}

	// After another 250ms (total 350ms post-disconnect > 250ms), server must be shut down
	select {
	case <-server.Wait():
		// OK: Clean shutdown
	case <-time.After(500 * time.Millisecond):
		t.Fatal("server failed to shut down after new persistDuration elapsed")
	}
}

// TestAdversarial_BackgroundDaemon_CleanExitOnSignalOrCommand verifies that
// background daemons terminate cleanly when MUX_C_TERMINATE (-O exit) is received.
func TestAdversarial_BackgroundDaemon_CleanExitOnSignalOrCommand(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "adv-exit-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "exit_cmd.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         newDummySSHClient(),
		PersistEnabled:    true,
		PersistIndefinite: true, // indefinite persist, only exits on -O exit
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()

	go func() { _ = server.Serve() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient failed: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Send -O exit
	if err := client.Terminate(ctx); err != nil {
		t.Fatalf("Terminate (-O exit) failed: %v", err)
	}

	// Server should shut down cleanly within 500ms
	select {
	case <-server.Wait():
		// Passed: Clean shutdown
	case <-time.After(1 * time.Second):
		t.Fatal("server did not terminate after receiving MUX_C_TERMINATE")
	}

	// Socket must be removed
	if socketPathExists(sockPath) {
		t.Fatalf("expected socket %q to be unlinked after -O exit", sockPath)
	}
}

// TestAdversarial_BackgroundDaemon_StopListeningDrain verifies that
// MUX_C_STOP_LISTENING unlinks the socket immediately so no new clients can join,
// while allowing active proxy clients to complete their work before final shutdown.
func TestAdversarial_BackgroundDaemon_StopListeningDrain(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "adv-stop-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "stop_drain.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         newDummySSHClient(),
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()

	go func() { _ = server.Serve() }()

	// 1. Establish an active proxy connection (Client 1)
	proxyConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial proxy failed: %v", err)
	}
	defer func() { _ = proxyConn.Close() }()

	if err := performClientMuxHandshake(proxyConn); err != nil {
		t.Fatalf("proxy handshake failed: %v", err)
	}
	if err := WriteMuxPacket(proxyConn, MUX_C_PROXY, EncodeMuxRequestID(1)); err != nil {
		t.Fatalf("send proxy failed: %v", err)
	}
	respType, _, err := ReadMuxPacket(proxyConn)
	if err != nil || respType != MUX_S_PROXY {
		t.Fatalf("expected MUX_S_PROXY, got 0x%x (err: %v)", respType, err)
	}

	if server.ActiveSessions() != 1 {
		t.Fatalf("expected activeSessions == 1, got %d", server.ActiveSessions())
	}

	// 2. Client 2 sends StopListening
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ctlCli, err := DialMuxClient(ctx, sockPath)
	if err != nil {
		t.Fatalf("DialMuxClient for StopListening failed: %v", err)
	}
	if err := ctlCli.StopListening(ctx); err != nil {
		_ = ctlCli.Close()
		t.Fatalf("StopListening failed: %v", err)
	}
	_ = ctlCli.Close()

	// Socket file should be unlinked on disk
	time.Sleep(30 * time.Millisecond)
	if socketPathExists(sockPath) {
		t.Fatalf("expected socket %q to be unlinked after StopListening", sockPath)
	}

	// New connection attempts should fail immediately with ENOENT or Connection Refused
	_, dialErr := net.Dial("unix", sockPath)
	if dialErr == nil {
		t.Fatal("expected dial to fail on unlinked socket after StopListening")
	}

	// BUT the server must NOT have shut down yet, because Client 1 is still active
	select {
	case <-server.Wait():
		t.Fatal("CRITICAL: server shut down before active proxy client finished!")
	default:
		// Passed
	}

	// 3. Now Client 1 finishes and closes
	_ = proxyConn.Close()

	// Once the last session finishes, server committed to shutdown committed by stoppedListening
	select {
	case <-server.Wait():
		// Passed: Gracefully shut down after session drain
	case <-time.After(1 * time.Second):
		t.Fatal("server failed to shut down after drained sessions reached 0")
	}
}

// TestAdversarial_StaleSocket_CrashedMasterDeadlockPrevention verifies that
// when a master process crashes or closes abruptly while proxy clients are connected,
// the clients unblock with EOF/error without hanging or deadlocking.
func TestAdversarial_StaleSocket_CrashedMasterDeadlockPrevention(t *testing.T) {
	fixtureCtx, fixtureCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer fixtureCancel()

	fixture, err := sshfixture.NewWithOptions(fixtureCtx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			_, _ = io.WriteString(ch, "alive_output\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fixture.Close() }()

	host, portStr, err := net.SplitHostPort(fixture.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "adv-crash-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "crashed_master.sock")

	// Connect master client to test SSH fixture
	sshConfig := &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fixture.HostKey),
		Timeout:         3 * time.Second,
	}
	rawClient, err := cryptoSSH.Dial("tcp", fixture.Address, sshConfig)
	if err != nil {
		t.Fatalf("cryptoSSH.Dial failed: %v", err)
	}

	server, err := NewMuxServer(MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   rawClient,
	})
	if err != nil {
		_ = rawClient.Close()
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	go func() { _ = server.Serve() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Client dials via DialControlProxy
	target := TargetContext{
		Host: host,
		Port: port,
		User: "fixture",
	}
	proxyClient, proxyConn, err := DialControlProxy(ctx, sockPath, target)
	if err != nil {
		_ = server.Shutdown()
		_ = rawClient.Close()
		t.Fatalf("DialControlProxy failed: %v", err)
	}
	defer func() {
		_ = proxyClient.Close()
		_ = proxyConn.Close()
	}()

	// Open a session and verify it works
	session, err := proxyClient.NewSession()
	if err != nil {
		_ = server.Shutdown()
		_ = rawClient.Close()
		t.Fatalf("NewSession failed: %v", err)
	}
	out, err := session.Output("echo master_alive")
	if err != nil || string(out) != "alive_output\n" {
		_ = session.Close()
		_ = server.Shutdown()
		_ = rawClient.Close()
		t.Fatalf("session output failed: %v (output: %q)", err, string(out))
	}
	_ = session.Close()

	// Open another session
	hangSession, err := proxyClient.NewSession()
	if err != nil {
		_ = server.Shutdown()
		_ = rawClient.Close()
		t.Fatalf("hangSession NewSession failed: %v", err)
	}
	defer func() { _ = hangSession.Close() }()

	// SIMULATE CRASH: Abruptly kill the master server and underlying transport
	_ = server.Shutdown()
	_ = rawClient.Close()

	// The client channel or reading must unblock with an error within a bounded deadline
	doneChan := make(chan error, 1)
	go func() {
		err := hangSession.Run("sleep 10")
		doneChan <- err
	}()

	select {
	case runErr := <-doneChan:
		// Succeeded: client unblocked promptly
		if runErr == nil {
			t.Fatal("expected error from crashed master, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CRITICAL DEADLOCK: client hung indefinitely after master crashed!")
	}
}

// TestAdversarial_ConcurrencyStress_UnderRace executes simultaneous client connects,
// proxies, alive checks, ext info queries, and abrupt disconnects concurrently
// to verify zero data races, deadlocks, or state corruption.
func TestAdversarial_ConcurrencyStress_UnderRace(t *testing.T) {
	fixtureCtx, fixtureCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer fixtureCancel()

	fixture, err := sshfixture.NewWithOptions(fixtureCtx, sshfixture.Options{
		ExecHandler: func(cmd string, ch cryptoSSH.Channel) {
			_, _ = io.WriteString(ch, "test_output\n")
			_, _ = ch.SendRequest("exit-status", false, cryptoSSH.Marshal(struct{ Status uint32 }{0}))
		},
	})
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fixture.Close() }()

	host, portStr, err := net.SplitHostPort(fixture.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir, err := os.MkdirTemp("", "adv-race-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "stress.sock")

	sshConfig := &cryptoSSH.ClientConfig{
		User:            "fixture",
		Auth:            []cryptoSSH.AuthMethod{cryptoSSH.Password(sshfixture.Password)},
		HostKeyCallback: cryptoSSH.FixedHostKey(fixture.HostKey),
		Timeout:         5 * time.Second,
	}
	rawClient, err := cryptoSSH.Dial("tcp", fixture.Address, sshConfig)
	if err != nil {
		t.Fatalf("cryptoSSH.Dial failed: %v", err)
	}
	defer func() { _ = rawClient.Close() }()

	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       sockPath,
		SSHClient:         rawClient,
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()

	go func() { _ = server.Serve() }()

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	target := TargetContext{
		Host: host,
		Port: port,
		User: "fixture",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	runProxyExecWorkers(ctx, &wg, errCh, sockPath, target, 5)
	runAliveCheckWorkers(ctx, &wg, errCh, sockPath, 5)
	runExtInfoWorkers(ctx, &wg, errCh, sockPath, 5)
	runChurnWorkers(&wg, sockPath, 5)

	wg.Wait()
	close(errCh)

	var errs []error
	for e := range errCh {
		errs = append(errs, e)
	}
	if len(errs) > 0 {
		t.Fatalf("concurrency stress failed with %d errors: %v", len(errs), errs[0])
	}
}

func runProxyExecWorkers(ctx context.Context, wg *sync.WaitGroup, errCh chan<- error, sockPath string, target TargetContext, count int) {
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for iter := 0; iter < 5; iter++ {
				cli, pConn, err := DialControlProxy(ctx, sockPath, target)
				if err != nil {
					errCh <- fmt.Errorf("worker %d proxy dial: %w", workerID, err)
					return
				}
				sess, err := cli.NewSession()
				if err != nil {
					_ = cli.Close()
					_ = pConn.Close()
					errCh <- fmt.Errorf("worker %d session: %w", workerID, err)
					return
				}
				out, err := sess.Output("echo test_output")
				_ = sess.Close()
				_ = cli.Close()
				_ = pConn.Close()
				if err != nil || string(out) != "test_output\n" {
					errCh <- fmt.Errorf("worker %d exec failed: %w, out: %s", workerID, err, string(out))
					return
				}
			}
		}(i)
	}
}

func runAliveCheckWorkers(ctx context.Context, wg *sync.WaitGroup, errCh chan<- error, sockPath string, count int) {
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for iter := 0; iter < 10; iter++ {
				cli, err := DialMuxClient(ctx, sockPath)
				if err != nil {
					errCh <- fmt.Errorf("worker %d alive dial: %w", workerID, err)
					return
				}
				pid, err := clientAliveCheckWithTimeout(cli, ctx)
				_ = cli.Close()
				if err != nil || pid == 0 {
					errCh <- fmt.Errorf("worker %d alive check failed: %w", workerID, err)
					return
				}
			}
		}(i)
	}
}

func runExtInfoWorkers(ctx context.Context, wg *sync.WaitGroup, errCh chan<- error, sockPath string, count int) {
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for iter := 0; iter < 10; iter++ {
				cli, err := DialMuxClient(ctx, sockPath)
				if err != nil {
					errCh <- fmt.Errorf("worker %d info dial: %w", workerID, err)
					return
				}
				info, err := cli.RequestInfo(ctx, "connection")
				if err != nil || !strings.Contains(info, "OpenSSH multiplexing") {
					_ = cli.Close()
					errCh <- fmt.Errorf("worker %d info req: %w", workerID, err)
					return
				}
				_ = cli.Close()
			}
		}(i)
	}
}

func runChurnWorkers(wg *sync.WaitGroup, sockPath string, count int) {
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iter := 0; iter < 20; iter++ {
				c, err := net.Dial("unix", sockPath)
				if err == nil {
					_ = c.Close()
				}
			}
		}()
	}
}

func performClientMuxHandshake(conn net.Conn) error {
	exts := []MuxExtension{{Name: "info", Value: "1"}}
	if err := WriteMuxPacket(conn, MUX_MSG_HELLO, EncodeMuxHello(MuxProtoVersion, exts)); err != nil {
		return err
	}
	msgType, payload, err := ReadMuxPacket(conn)
	if err != nil {
		return err
	}
	if msgType != MUX_MSG_HELLO {
		return fmt.Errorf("expected MUX_MSG_HELLO, got 0x%08x", msgType)
	}
	serverVer, _, err := DecodeMuxHello(payload)
	if err != nil || serverVer != MuxProtoVersion {
		return fmt.Errorf("unsupported server proto ver %d", serverVer)
	}
	return nil
}

func clientAliveCheckWithTimeout(cli *MuxClient, ctx context.Context) (uint32, error) {
	cCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	return cli.AliveCheck(cCtx)
}
