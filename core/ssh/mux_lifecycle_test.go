package ssh

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
)

// TestControlClientRejectsForeignMaster verifies that a client refuses a control
// socket whose peer is not the expected local user. Without this check any local
// user could plant a socket in a shared directory and receive the session.
func TestControlClientRejectsForeignMaster(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("peer credentials are unavailable on Windows")
	}

	socketPath := filepath.Join(t.TempDir(), "foreign.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       socketPath,
		SSHClient:         newDummySSHClient(),
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Baseline: the real local UID is accepted.
	client, err := DialMuxClient(ctx, socketPath)
	if err != nil {
		t.Fatalf("DialMuxClient with the local UID failed: %v", err)
	}
	if _, err := client.AliveCheck(ctx); err != nil {
		_ = client.Close()
		t.Fatalf("AliveCheck failed: %v", err)
	}
	_ = client.Close()

	// A different expected UID must be rejected before any request is sent.
	foreignUID := localPeerUID() + 1
	if _, err := DialMuxClient(ctx, socketPath, WithExpectedPeerUID(foreignUID)); !errors.Is(err, ErrUnauthorizedPeer) {
		t.Fatalf("expected ErrUnauthorizedPeer from DialMuxClient, got %v", err)
	}

	rawConn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer func() { _ = rawConn.Close() }()
	if err := checkPeerUID(rawConn, foreignUID); !errors.Is(err, ErrUnauthorizedPeer) {
		t.Fatalf("expected ErrUnauthorizedPeer from checkPeerUID, got %v", err)
	}
	if err := checkPeerUID(rawConn, localPeerUID()); err != nil {
		t.Fatalf("expected local UID to pass, got %v", err)
	}
}

// TestMuxServer_AskModeRequiresConfirmation verifies that ask/autoask masters do
// not admit sessions silently and fail closed when no confirmer is configured.
func TestMuxServer_AskModeRequiresConfirmation(t *testing.T) {
	start := func(t *testing.T, confirm func(string) bool) *MuxServer {
		t.Helper()
		socketPath := filepath.Join(t.TempDir(), "ask.sock")
		server, err := NewMuxServer(MuxServerOptions{
			ControlPath:       socketPath,
			SSHClient:         newDummySSHClient(),
			PersistEnabled:    true,
			PersistIndefinite: true,
			AskConfirmation:   true,
			ConfirmSession:    confirm,
		})
		if err != nil {
			t.Fatalf("NewMuxServer failed: %v", err)
		}
		go func() { _ = server.Serve() }()
		t.Cleanup(func() { _ = server.Shutdown() })
		return server
	}

	t.Run("no confirmer rejects", func(t *testing.T) {
		server := start(t, nil)

		proxyConn, err := connectTestProxyClient(server.ControlPath())
		if err != nil {
			if proxyConn != nil {
				_ = proxyConn.Close()
			}
			// MUX_S_PERMISSION_DENIED surfaces as a handshake failure.
			return
		}
		_ = proxyConn.Close()
		t.Fatal("expected proxy admission to be rejected without a confirmer")
	})

	t.Run("denied confirmer rejects", func(t *testing.T) {
		server := start(t, func(string) bool { return false })
		if _, err := connectTestProxyClient(server.ControlPath()); err == nil {
			t.Fatal("expected proxy admission to be rejected when the confirmer denies")
		}
	})

	t.Run("approved confirmer admits", func(t *testing.T) {
		var mu sync.Mutex
		var actions []string
		server := start(t, func(action string) bool {
			mu.Lock()
			defer mu.Unlock()
			actions = append(actions, action)
			return true
		})

		proxyConn, err := connectTestProxyClient(server.ControlPath())
		if err != nil {
			t.Fatalf("expected approved proxy session to be admitted: %v", err)
		}
		_ = proxyConn.Close()

		mu.Lock()
		defer mu.Unlock()
		if len(actions) != 1 || actions[0] != "proxy session" {
			t.Fatalf("expected one proxy session confirmation, got %v", actions)
		}
	})

	t.Run("not-ask master skips confirmation", func(t *testing.T) {
		socketPath := filepath.Join(t.TempDir(), "plain.sock")
		server, err := NewMuxServer(MuxServerOptions{
			ControlPath:       socketPath,
			SSHClient:         newDummySSHClient(),
			PersistEnabled:    true,
			PersistIndefinite: true,
		})
		if err != nil {
			t.Fatalf("NewMuxServer failed: %v", err)
		}
		defer func() { _ = server.Shutdown() }()
		go func() { _ = server.Serve() }()

		proxyConn, err := connectTestProxyClient(socketPath)
		if err != nil {
			t.Fatalf("non-ask master must admit sessions: %v", err)
		}
		_ = proxyConn.Close()
	})
}

// TestConnectorCloseAllReleasesOwnedMaster verifies that a connector releases the
// control socket it owns. Leaving the socket behind makes the next command treat
// a dead master as alive.
func TestConnectorCloseAllReleasesOwnedMaster(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fixture := startMuxFixture(t, ctx, sshfixture.Options{})

	socketPath := filepath.Join(t.TempDir(), "owned.sock")
	provider := &testMuxProvider{
		cfg: &ClientConfig{
			NodeID:   "owned-node",
			Address:  fixture.Host,
			Port:     fixture.Port,
			User:     "fixture",
			AuthType: "password",
			Password: sshfixture.Password,
		},
		ctrl: &ControlConfig{Master: ControlMasterAuto, Path: socketPath},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	if _, err := connector.Connect(ctx, "owned-node"); err != nil {
		_ = connector.CloseAll()
		t.Fatalf("connect failed: %v", err)
	}

	waitForCondition(t, 5*time.Second, func() bool {
		return GetActiveMuxServer(socketPath) != nil
	}, "connector did not start a master")

	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll failed: %v", err)
	}

	if GetActiveMuxServer(socketPath) != nil {
		t.Fatal("CloseAll left the master registered")
	}
	if socketPathExists(socketPath) {
		t.Fatalf("CloseAll left a stale control socket at %q", socketPath)
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(message)
}

// TestStartMuxServerDefaultsPeerUIDCheck verifies that a host which omits
// Environment.LocalUID cannot silently disable the master-side peer credential
// check, and that an explicit or malformed value never weakens it either.
func TestStartMuxServerDefaultsPeerUIDCheck(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	start := func(t *testing.T, localUID string) *MuxServer {
		t.Helper()
		server, err := StartMuxServer(ctx, newDummySSHClient(), MuxMasterOptions{
			Path:        filepath.Join(t.TempDir(), "peer-uid.sock"),
			Environment: Environment{LocalUID: localUID},
		})
		if err != nil {
			t.Fatalf("StartMuxServer failed: %v", err)
		}
		t.Cleanup(func() { _ = server.Shutdown() })
		return server
	}

	t.Run("missing LocalUID falls back to the effective user", func(t *testing.T) {
		server := start(t, "")
		if !server.checkPeerUID {
			t.Fatal("peer UID check was silently disabled without Environment.LocalUID")
		}
		if server.expectedUID != localPeerUID() {
			t.Fatalf("expected UID %d, got %d", localPeerUID(), server.expectedUID)
		}
	})

	t.Run("explicit LocalUID wins", func(t *testing.T) {
		server := start(t, "1234")
		if !server.checkPeerUID || server.expectedUID != 1234 {
			t.Fatalf("expected the explicit UID 1234 to be enforced, got check=%v uid=%d", server.checkPeerUID, server.expectedUID)
		}
	})

	t.Run("malformed LocalUID keeps the check enabled", func(t *testing.T) {
		server := start(t, "not-a-uid")
		if !server.checkPeerUID {
			t.Fatal("malformed Environment.LocalUID disabled the peer UID check")
		}
		if server.expectedUID != localPeerUID() {
			t.Fatalf("expected the effective UID %d as fallback, got %d", localPeerUID(), server.expectedUID)
		}
	})
}

// TestControlClientRequiresExactPeerUID verifies that the client-side peer check
// is never skipped for uid 0. A client running as root previously treated the
// expected UID 0 as "no check" and accepted a socket planted by any other local
// user, which is exactly the hijack the check exists to stop.
func TestControlClientRequiresExactPeerUID(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("peer credentials are unavailable on Windows")
	}
	if localPeerUID() == 0 {
		t.Skip("this process already runs as root, so uid 0 is the correct peer")
	}

	socketPath := filepath.Join(t.TempDir(), "root-expectation.sock")
	server, err := NewMuxServer(MuxServerOptions{
		ControlPath:       socketPath,
		SSHClient:         newDummySSHClient(),
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Expecting root must reject this non-root master instead of accepting it.
	if _, err := DialMuxClient(ctx, socketPath, WithExpectedPeerUID(0)); !errors.Is(err, ErrUnauthorizedPeer) {
		t.Fatalf("expected ErrUnauthorizedPeer from DialMuxClient, got %v", err)
	}
	if _, _, err := DialControlProxy(ctx, socketPath, TargetContext{}, WithExpectedPeerUID(0)); !errors.Is(err, ErrUnauthorizedPeer) {
		t.Fatalf("expected ErrUnauthorizedPeer from DialControlProxy, got %v", err)
	}
	if _, err := DialMuxProxyStream(ctx, socketPath, WithExpectedPeerUID(0)); !errors.Is(err, ErrUnauthorizedPeer) {
		t.Fatalf("expected ErrUnauthorizedPeer from DialMuxProxyStream, got %v", err)
	}
}

// TestConnectorOwnedMasterSurvivesIdleTimeout verifies that the connector's own
// transport counts as an active session on the master it started. Without that
// reference a bounded ControlPersist timer fires while this process still uses
// the transport, and the master shuts the connection down mid-session.
func TestConnectorOwnedMasterSurvivesIdleTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	fixture, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("fixture failed: %v", err)
	}
	defer func() { _ = fixture.Close() }()
	host, port := fixtureEndpoint(t, fixture.Address)

	socketPath := filepath.Join(t.TempDir(), "owned-idle.sock")
	provider := &testMuxProvider{
		cfg: &ClientConfig{
			NodeID:   "idle-node",
			Address:  host,
			Port:     port,
			User:     "fixture",
			AuthType: "password",
			Password: sshfixture.Password,
		},
		ctrl: &ControlConfig{Master: ControlMasterAuto, Path: socketPath, Persist: "100ms"},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() {
		if closeErr := connector.CloseAll(); closeErr != nil {
			t.Logf("CloseAll failed: %v", closeErr)
		}
	}()

	client, err := connector.Connect(ctx, "idle-node")
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	waitForCondition(t, 10*time.Second, func() bool {
		return GetActiveMuxServer(socketPath) != nil
	}, "connector did not start a control master")

	// Longer than several persist durations: an unowned master would have shut
	// down and closed this transport by now.
	time.Sleep(600 * time.Millisecond)
	if GetActiveMuxServer(socketPath) == nil {
		t.Fatal("bounded ControlPersist idle timeout shut down a master whose transport is still in use")
	}

	session, err := client.sshClient.NewSession()
	if err != nil {
		t.Fatalf("the transport was closed under the connector: %v", err)
	}
	output, err := session.Output("after-idle")
	_ = session.Close()
	if err != nil {
		t.Fatalf("command over the owned master failed after the idle window: %v", err)
	}
	if string(output) != "fixture-output" {
		t.Fatalf("command output = %q, want %q", output, "fixture-output")
	}
	if got := fixture.Authenticated.Load(); got != 1 {
		t.Fatalf("expected the seeded connection to be reused, got %d authentications", got)
	}
}

// TestMuxServerStopListeningRetiresIdleMaster verifies that -O stop actually
// ends a master that has no session to drain, including a -N master that opted
// into ReleaseForegroundOnStop.
func TestMuxServerStopListeningRetiresIdleMaster(t *testing.T) {
	for _, tc := range []struct {
		name            string
		initialSessions int32
		releaseOnStop   bool
	}{
		{name: "idle daemon", initialSessions: 0, releaseOnStop: false},
		{name: "no-cmd master", initialSessions: 1, releaseOnStop: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socketPath := filepath.Join(t.TempDir(), "stop-idle.sock")
			server, err := NewMuxServer(MuxServerOptions{
				ControlPath:           socketPath,
				SSHClient:             newDummySSHClient(),
				PersistEnabled:        !tc.releaseOnStop,
				PersistIndefinite:     !tc.releaseOnStop,
				InitialActiveSessions: tc.initialSessions,
			})
			if err != nil {
				t.Fatalf("NewMuxServer failed: %v", err)
			}
			if tc.releaseOnStop {
				server.ReleaseForegroundOnStop()
			}
			go func() { _ = server.Serve() }()
			defer func() { _ = server.Shutdown() }()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, err := DialMuxClient(ctx, socketPath)
			if err != nil {
				t.Fatalf("DialMuxClient failed: %v", err)
			}
			if err := client.StopListening(ctx); err != nil {
				_ = client.Close()
				t.Fatalf("StopListening failed: %v", err)
			}
			_ = client.Close()

			select {
			case <-server.Wait():
			case <-time.After(5 * time.Second):
				t.Fatal("an idle master kept running after -O stop")
			}
			if socketPathExists(socketPath) {
				t.Fatalf("control socket %q survived -O stop", socketPath)
			}
		})
	}
}

// TestConnectorReleaseMasterDropsOnlySessionReference verifies the handoff
// contract: releasing drops the connector's active-session reference so a
// ControlPersist handoff can take the master over, without stopping the master
// this process still owns (CloseAll must remain able to stop it).
func TestConnectorReleaseMasterDropsOnlySessionReference(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	fixture, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("fixture failed: %v", err)
	}
	defer func() { _ = fixture.Close() }()
	host, port := fixtureEndpoint(t, fixture.Address)

	socketPath := filepath.Join(t.TempDir(), "release.sock")
	provider := &testMuxProvider{
		cfg: &ClientConfig{
			NodeID:   "release-node",
			Address:  host,
			Port:     port,
			User:     "fixture",
			AuthType: "password",
			Password: sshfixture.Password,
		},
		ctrl: &ControlConfig{Master: ControlMasterAuto, Path: socketPath, Persist: "0"},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() {
		if closeErr := connector.CloseAll(); closeErr != nil {
			t.Logf("CloseAll failed: %v", closeErr)
		}
	}()
	if _, err := connector.Connect(ctx, "release-node"); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	var master *MuxServer
	waitForCondition(t, 10*time.Second, func() bool {
		master = GetActiveMuxServer(socketPath)
		return master != nil
	}, "connector did not start a control master")

	if got := master.ActiveSessions(); got != 1 {
		t.Fatalf("the owning connector must count as one session, got %d", got)
	}
	if !connector.ReleaseMaster(master) {
		t.Fatal("ReleaseMaster did not report the connector as the owner")
	}
	if got := master.ActiveSessions(); got != 0 {
		t.Fatalf("expected the session reference to be dropped, got %d", got)
	}
	// A repeated release (base process and daemon child both call it) must not
	// drive the counter negative.
	connector.ReleaseMaster(master)
	if got := master.ActiveSessions(); got != 0 {
		t.Fatalf("repeated ReleaseMaster changed the session count to %d", got)
	}
	if GetActiveMuxServer(socketPath) != master {
		t.Fatal("ReleaseMaster stopped a master the connector still owns")
	}

	if err := connector.CloseAll(); err != nil {
		t.Fatalf("CloseAll failed: %v", err)
	}
	if GetActiveMuxServer(socketPath) != nil {
		t.Fatal("CloseAll left a released master running")
	}
	if socketPathExists(socketPath) {
		t.Fatalf("CloseAll left the control socket at %q", socketPath)
	}
}
