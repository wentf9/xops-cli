package ssh

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	logger "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
)

type testMuxProvider struct {
	cfg  *ClientConfig
	ctrl *ControlConfig
}

func (p *testMuxProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	return p.cfg, nil
}

func (p *testMuxProvider) GetControlConfig(nodeID string) (*ControlConfig, error) {
	return p.ctrl, nil
}

func TestConnector_ActiveMasterReuse(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mux-connector-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "master.sock")
	dummyClient := newDummySSHClient()

	server, err := NewMuxServer(MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   dummyClient,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	defer func() { _ = server.Shutdown() }()
	go func() { _ = server.Serve() }()

	provider := &testMuxProvider{
		cfg: &ClientConfig{
			NodeID:   "test-node",
			Address:  "192.0.2.1",
			Port:     22,
			User:     "testuser",
			AuthType: "password",
		},
		ctrl: &ControlConfig{
			Master: ControlMasterAuto,
			Path:   sockPath,
		},
	}

	recorder := &diagnosticRecorder{}
	connector := newTestConnector(provider, WithDiagnostics(recorder))
	defer func() { _ = connector.CloseAll() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := connector.Connect(ctx, "test-node")
	if err != nil {
		t.Fatalf("connector.Connect failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}

	// Verify connection reuse diagnostic was emitted
	reused := false
	for _, diag := range recorder.snapshot() {
		if diag.Kind == logger.ConnectionReused && diag.NodeID == "test-node" {
			reused = true
			break
		}
	}
	if !reused {
		t.Fatal("expected logger.ConnectionReused diagnostic to be emitted")
	}
}

func TestConnector_StaleSocketAutoUnlink(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mux-stale-unlink-*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sockPath := filepath.Join(tmpDir, "stale.sock")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("syscall.Socket failed: %v", err)
	}
	sa := &syscall.SockaddrUnix{Name: sockPath}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("syscall.Bind failed: %v", err)
	}
	_ = syscall.Close(fd)

	if !socketPathExists(sockPath) {
		t.Fatalf("expected stale socket to exist before connect")
	}

	// Start real in-memory test SSH server for fallback direct dial
	address, stopServer := startTestMultiAuthSSHServer(t, nil, "fixture")
	defer stopServer()

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	provider := &testMuxProvider{
		cfg: &ClientConfig{
			NodeID:   "stale-node",
			Address:  host,
			Port:     port,
			User:     "fixture",
			AuthType: "password",
			Password: "fixture",
		},
		ctrl: &ControlConfig{
			Master: ControlMasterAuto,
			Path:   sockPath,
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() { _ = connector.CloseAll() }()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := connector.Connect(ctx, "stale-node")
	if err != nil {
		t.Fatalf("connector.Connect failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}

	// Verify the stale socket was unlinked and recreated by the background master!
	var recreated bool
	for range 50 {
		if socketPathExists(sockPath) {
			recreated = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !recreated {
		t.Fatalf("expected master socket to be recreated by new master on %q", sockPath)
	}
}

func TestConnector_ControlMasterDisabled(t *testing.T) {
	address, stopServer := startTestMultiAuthSSHServer(t, nil, "fixture")
	defer stopServer()

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	provider := &testMuxProvider{
		cfg: &ClientConfig{
			NodeID:   "direct-node",
			Address:  host,
			Port:     port,
			User:     "fixture",
			AuthType: "password",
			Password: "fixture",
		},
		ctrl: &ControlConfig{
			Master: ControlMasterNo,
			Path:   "none", // explicitly disabled
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() { _ = connector.CloseAll() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	client, err := connector.Connect(ctx, "direct-node")
	if err != nil {
		t.Fatalf("connector.Connect failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

// TestConnector_StaleSocketRecoveryDoesNotDemoteExplicitMaster verifies that
// when a stale control socket is replaced by a live master before removal, a
// caller requesting ControlMaster=yes/ask (-M) is not demoted to a proxy client.
func TestConnector_StaleSocketRecoveryDoesNotDemoteExplicitMaster(t *testing.T) {
	tmpDir := shortSocketDir(t)
	staleFile := filepath.Join(tmpDir, "stale-orig")
	if err := os.WriteFile(staleFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	origFi, err := os.Stat(staleFile)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	sockPath := filepath.Join(tmpDir, "master.sock")
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

	connector := newTestConnector(&testMuxProvider{})
	defer func() { _ = connector.CloseAll() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for _, mode := range []ControlMasterMode{ControlMasterYes, ControlMasterAsk} {
		target := TargetContext{
			Host:    "192.0.2.1",
			Port:    22,
			User:    "fixture",
			Control: &ControlConfig{Master: mode, Path: sockPath},
		}
		planNode := connectionPlanNode{
			name:    "explicit-master",
			cfg:     &ClientConfig{NodeID: "explicit-master", Address: "192.0.2.1", Port: 22, User: "fixture"},
			control: target.Control,
		}
		// 1. Replaced socket (origFi != currFi)
		client, err := connector.handleStaleControlSocket(ctx, planNode, sockPath, target, origFi)
		if err != nil {
			t.Fatalf("handleStaleControlSocket (%s, replaced) failed: %v", mode, err)
		}
		if client != nil {
			t.Fatalf("handleStaleControlSocket (%s, replaced) attached as proxy client instead of refusing demotion", mode)
		}

		// 2. Same file identity that became alive before unlink (origFi == currFi)
		sameFi, statErr := os.Lstat(sockPath)
		if statErr != nil {
			t.Fatalf("Lstat(sockPath) failed: %v", statErr)
		}
		client, err = connector.handleStaleControlSocket(ctx, planNode, sockPath, target, sameFi)
		if err != nil {
			t.Fatalf("handleStaleControlSocket (%s, sameFi) failed: %v", mode, err)
		}
		if client != nil {
			t.Fatalf("handleStaleControlSocket (%s, sameFi) attached as proxy client instead of refusing demotion", mode)
		}
		if !socketPathExists(sockPath) {
			t.Fatalf("handleStaleControlSocket (%s) unlinked a live master socket", mode)
		}
	}
}

type multiNodeMuxProvider struct {
	cfgs  map[string]*ClientConfig
	ctrls map[string]*ControlConfig
}

func (p *multiNodeMuxProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	if cfg, ok := p.cfgs[nodeID]; ok {
		return cfg, nil
	}
	return nil, errors.New("node not found: " + nodeID)
}

func (p *multiNodeMuxProvider) GetControlConfig(nodeID string) (*ControlConfig, error) {
	if ctrl, ok := p.ctrls[nodeID]; ok {
		return ctrl, nil
	}
	return nil, nil
}

// TestTryConnectMultiplex_NeverDeletesRegularFile verifies that if ControlPath
// points to an existing regular file (or non-socket), tryConnectMultiplex and
// handleStaleControlSocket never unlink it.
func TestTryConnectMultiplex_NeverDeletesRegularFile(t *testing.T) {
	tmpDir := shortSocketDir(t)
	regularFile := filepath.Join(tmpDir, "important-data.txt")
	const wantContent = "do-not-delete-me"
	if err := os.WriteFile(regularFile, []byte(wantContent), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	provider := &testMuxProvider{
		cfg: &ClientConfig{
			NodeID:   "reg-file-node",
			Address:  "192.0.2.1",
			Port:     22,
			User:     "fixture",
			AuthType: "password",
		},
		ctrl: &ControlConfig{
			Master: ControlMasterAuto,
			Path:   regularFile,
		},
	}
	connector := newTestConnector(provider)
	defer func() { _ = connector.CloseAll() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	planNode := connectionPlanNode{
		name:    "reg-file-node",
		cfg:     provider.cfg,
		control: provider.ctrl,
	}
	client, err := connector.tryConnectMultiplex(ctx, planNode)
	if err != nil {
		t.Fatalf("tryConnectMultiplex returned unexpected error: %v", err)
	}
	if client != nil {
		t.Fatalf("expected nil client for regular file, got %v", client)
	}

	got, readErr := os.ReadFile(regularFile)
	if readErr != nil {
		t.Fatalf("regular file was deleted or became unreadable: %v", readErr)
	}
	if string(got) != wantContent {
		t.Fatalf("regular file content changed: got %q, want %q", string(got), wantContent)
	}
}

// TestTryConnectMultiplex_TimeoutDoesNotUnlinkLiveMaster verifies that a slow or
// unresponsive Unix socket that times out duringMUX_MSG_HELLO is not treated as
// a dead stale socket and is NOT unlinked on disk.
func TestTryConnectMultiplex_TimeoutDoesNotUnlinkLiveMaster(t *testing.T) {
	tmpDir := shortSocketDir(t)
	sockPath := filepath.Join(tmpDir, "slow-master.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen unix failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	// Accept connections and hold them open without sending MUX_MSG_HELLO so the
	// probe times out instead of returning ECONNREFUSED.
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				<-done
				_ = c.Close()
			}(conn)
		}
	}()

	provider := &testMuxProvider{
		cfg: &ClientConfig{
			NodeID:   "slow-node",
			Address:  "192.0.2.1",
			Port:     22,
			User:     "fixture",
			AuthType: "password",
		},
		ctrl: &ControlConfig{
			Master: ControlMasterAuto,
			Path:   sockPath,
		},
	}
	connector := newTestConnector(provider)
	defer func() { _ = connector.CloseAll() }()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	planNode := connectionPlanNode{
		name:    "slow-node",
		cfg:     provider.cfg,
		control: provider.ctrl,
	}
	client, _ := connector.tryConnectMultiplex(ctx, planNode)
	if client != nil {
		t.Fatalf("expected nil client on probe timeout, got %v", client)
	}

	fi, statErr := os.Lstat(sockPath)
	if statErr != nil {
		t.Fatalf("live master socket was unlinked after probe timeout: %v", statErr)
	}
	if !isControlSocketFileInfo(fi) {
		t.Fatalf("expected socket mode to remain intact, got %v", fi.Mode())
	}
}

// TestProxyJump_TargetMasterShutdownPreservesBastion verifies that shutting down
// the target hop's MuxServer only closes the target hop's SSH transport and does
// NOT close the bastion hop's physical transport.
func TestProxyJump_TargetMasterShutdownPreservesBastion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	bastionFix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New(bastion) failed: %v", err)
	}
	defer func() { _ = bastionFix.Close() }()

	targetFix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New(target) failed: %v", err)
	}
	defer func() { _ = targetFix.Close() }()

	bHost, bPortStr, err := net.SplitHostPort(bastionFix.Address)
	if err != nil {
		t.Fatal(err)
	}
	bPort, _ := strconv.Atoi(bPortStr)

	tHost, tPortStr, err := net.SplitHostPort(targetFix.Address)
	if err != nil {
		t.Fatal(err)
	}
	tPort, _ := strconv.Atoi(tPortStr)

	tmpDir := shortSocketDir(t)
	bastionSock := filepath.Join(tmpDir, "bastion.sock")
	targetSock := filepath.Join(tmpDir, "target.sock")

	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"bastion": {
				NodeID:   "bastion",
				Address:  bHost,
				Port:     bPort,
				User:     "fixture",
				AuthType: "password",
				Password: sshfixture.Password,
			},
			"target": {
				NodeID:    "target",
				Address:   tHost,
				Port:      tPort,
				User:      "fixture",
				AuthType:  "password",
				Password:  sshfixture.Password,
				ProxyJump: "bastion",
			},
		},
		ctrls: map[string]*ControlConfig{
			"bastion": {
				Master:  ControlMasterAuto,
				Path:    bastionSock,
				Persist: "yes",
			},
			"target": {
				Master:  ControlMasterAuto,
				Path:    targetSock,
				Persist: "yes",
			},
		},
	}

	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() { _ = connector.CloseAll() }()

	targetClient, err := connector.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("Connect(target) failed: %v", err)
	}
	if targetClient == nil {
		t.Fatal("expected non-nil target client")
	}

	targetMaster := GetActiveMuxServer(targetSock)
	bastionMaster := GetActiveMuxServer(bastionSock)
	if targetMaster == nil || bastionMaster == nil {
		t.Fatalf("expected both targetMaster (%v) and bastionMaster (%v) to be started", targetMaster, bastionMaster)
	}

	// Shut down the target master (simulating `xops ssh -O exit target`).
	if err := targetMaster.Shutdown(); err != nil {
		t.Fatalf("targetMaster.Shutdown() failed: %v", err)
	}

	// Bastion's underlying SSH transport and mux socket must remain alive!
	bastionMuxClient, err := DialMuxClient(ctx, bastionSock)
	if err != nil {
		t.Fatalf("DialMuxClient(bastionSock) failed after target master shutdown: %v", err)
	}
	defer func() { _ = bastionMuxClient.Close() }()
	if _, err := bastionMuxClient.AliveCheck(ctx); err != nil {
		t.Fatalf("bastion master AliveCheck failed after target master shutdown: %v", err)
	}

	bastionPooled, ok := connector.clients.Get("bastion")
	if !ok || bastionPooled == nil || bastionPooled.SSHClient == nil {
		t.Fatal("expected cached bastion client to remain in connector")
	}
	if _, _, err := bastionPooled.SSHClient.SendRequest("keepalive@openssh.com", true, nil); err != nil {
		t.Fatalf("bastion SSH transport was killed when target master shut down: %v", err)
	}
}

// TestDialAndPublishProxy_HonorsCancelWithoutDeadline verifies that
// DialControlProxy unblocks immediately when its context is cancelled even if
// the context carries no deadline.
func TestDialAndPublishProxy_HonorsCancelWithoutDeadline(t *testing.T) {
	tmpDir := shortSocketDir(t)
	sockPath := filepath.Join(tmpDir, "hang-proxy.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen unix failed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan struct{}, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		select {
		case accepted <- struct{}{}:
		default:
		}
		<-done
		_ = conn.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, _, dialErr := DialControlProxy(ctx, sockPath, TargetContext{Host: "192.0.2.1", Port: 22, User: "fixture"})
		errCh <- dialErr
	}()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("DialControlProxy did not connect to unix socket")
	}

	cancel()

	select {
	case dialErr := <-errCh:
		if dialErr == nil {
			t.Fatal("expected DialControlProxy to fail after context cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DialControlProxy remained blocked after context without deadline was cancelled")
	}
}

// TestConnectorMastersOrderAndMultiHopProxyJumpChain verifies R6-1 and R6-2:
//  1. Connector.Masters() returns masters in deterministic creation order
//     (outermost jump to innermost target), never randomized map order.
//  2. Intermediate hops in a comma-separated ProxyJump chain (jump1,jump2,jump3)
//     retain their full upstream prefix chain (e.g. jump3 has ProxyJump="jump1,jump2").
func TestConnectorMastersOrderAndMultiHopProxyJumpChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	provider := &multiNodeMuxProvider{
		cfgs: map[string]*ClientConfig{
			"jump1":  {NodeID: "jump1", Address: "10.0.0.1", Port: 22, User: "u1"},
			"jump2":  {NodeID: "jump2", Address: "10.0.0.2", Port: 22, User: "u2"},
			"jump3":  {NodeID: "jump3", Address: "10.0.0.3", Port: 22, User: "u3"},
			"target": {NodeID: "target", Address: "10.0.0.4", Port: 22, User: "u4", ProxyJump: "jump1,jump2,jump3"},
		},
		ctrls: map[string]*ControlConfig{},
	}
	connector := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() { _ = connector.CloseAll() }()

	// Verify R6-2: resolveConnectionPlan preserves full prefix jump chain on jump3.
	plan, err := connector.resolveConnectionPlan(ctx, "target")
	if err != nil {
		t.Fatalf("resolveConnectionPlan(target) failed: %v", err)
	}
	if len(plan) != 4 {
		t.Fatalf("expected 4 plan nodes, got %d", len(plan))
	}
	// plan is [target, jump3, jump2, jump1]
	if plan[1].name != "jump3" || plan[1].cfg.ProxyJump != "jump1,jump2" {
		t.Fatalf("expected jump3 ProxyJump=%q, got name=%q ProxyJump=%q", "jump1,jump2", plan[1].name, plan[1].cfg.ProxyJump)
	}
	if plan[2].name != "jump2" || plan[2].cfg.ProxyJump != "jump1" {
		t.Fatalf("expected jump2 ProxyJump=%q, got name=%q ProxyJump=%q", "jump1", plan[2].name, plan[2].cfg.ProxyJump)
	}
	if plan[3].name != "jump1" || plan[3].cfg.ProxyJump != "" {
		t.Fatalf("expected jump1 ProxyJump empty, got name=%q ProxyJump=%q", plan[3].name, plan[3].cfg.ProxyJump)
	}

	// Verify R6-1: trackMaster / Masters() preserves deterministic registration order.
	m1 := &MuxServer{target: TargetContext{OriginalHost: "jump1"}, shutdownChan: make(chan struct{})}
	m2 := &MuxServer{target: TargetContext{OriginalHost: "jump2"}, shutdownChan: make(chan struct{})}
	m3 := &MuxServer{target: TargetContext{OriginalHost: "jump3"}, shutdownChan: make(chan struct{})}
	m4 := &MuxServer{target: TargetContext{OriginalHost: "target"}, shutdownChan: make(chan struct{})}
	connector.trackMaster(m1)
	connector.trackMaster(m2)
	connector.trackMaster(m3)
	connector.trackMaster(m4)

	want := []*MuxServer{m1, m2, m3, m4}
	for iter := 0; iter < 20; iter++ {
		got := connector.Masters()
		if len(got) != len(want) {
			t.Fatalf("iter %d: expected %d masters, got %d", iter, len(want), len(got))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("iter %d: masters[%d] = %v, want %v", iter, i, got[i].Target().OriginalHost, want[i].Target().OriginalHost)
			}
		}
	}
}

type funcSessionConfirmer func(ctx context.Context, action string) (bool, error)

func (f funcSessionConfirmer) ConfirmSession(ctx context.Context, action string) (bool, error) {
	return f(ctx, action)
}

func TestConnectorMultiplex_ControlMasterAskAllowReuse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fix, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fix.Close() }()

	host, portStr, err := net.SplitHostPort(fix.Address)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	sockPath := filepath.Join(shortSocketDir(t), "ask-reuse.sock")

	var confirmCalls atomic.Int32
	confirmer := funcSessionConfirmer(func(ctx context.Context, action string) (bool, error) {
		confirmCalls.Add(1)
		return true, nil
	})

	masterProvider := &testMuxProvider{
		cfg: &ClientConfig{
			NodeID:   "ask-node",
			Address:  host,
			Port:     port,
			User:     "fixture",
			Password: sshfixture.Password,
			AuthType: "password",
		},
		ctrl: &ControlConfig{
			Master:  ControlMasterAsk,
			Path:    sockPath,
			Persist: "5m",
		},
	}
	masterConn := newTestConnector(masterProvider, WithHostKeyVerifier(&fixtureTrust{}), WithSessionConfirmer(confirmer))
	defer func() { _ = masterConn.CloseAll() }()

	masterClient, err := masterConn.Connect(ctx, "ask-node")
	if err != nil {
		t.Fatalf("master Connect failed: %v", err)
	}
	defer func() { _ = masterClient.Close() }()

	if GetActiveMuxServer(sockPath) == nil {
		t.Fatalf("expected active mux server on %q", sockPath)
	}

	// 1. Without AllowReuse (e.g. config has ControlMaster=ask and CLI did not pass -S),
	// a second connector treats itself as an explicit master and does NOT attach to the existing master.
	noReuseProvider := &testMuxProvider{
		cfg: masterProvider.cfg,
		ctrl: &ControlConfig{
			Master:     ControlMasterAsk,
			Path:       sockPath,
			AllowReuse: false,
		},
	}
	noReuseConn := newTestConnector(noReuseProvider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() { _ = noReuseConn.CloseAll() }()

	noReuseClient, err := noReuseConn.Connect(ctx, "ask-node")
	if err != nil {
		t.Fatalf("noReuse Connect failed: %v", err)
	}
	_ = noReuseClient.Close()
	if confirmCalls.Load() != 0 {
		t.Fatalf("expected 0 ConfirmSession calls when AllowReuse=false, got %d", confirmCalls.Load())
	}

	// 2. With AllowReuse=true (CLI explicitly passed -S <path> without -M),
	// the second connector attaches to the existing ask master and triggers ConfirmSession.
	reuseProvider := &testMuxProvider{
		cfg: masterProvider.cfg,
		ctrl: &ControlConfig{
			Master:     ControlMasterAsk,
			Path:       sockPath,
			AllowReuse: true,
		},
	}
	reuseConn := newTestConnector(reuseProvider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() { _ = reuseConn.CloseAll() }()

	reuseClient, err := reuseConn.Connect(ctx, "ask-node")
	if err != nil {
		t.Fatalf("reuse Connect failed: %v", err)
	}
	defer func() { _ = reuseClient.Close() }()

	if confirmCalls.Load() != 1 {
		t.Fatalf("expected ConfirmSession to be called once on reuse with AllowReuse=true, got %d", confirmCalls.Load())
	}
	out, err := reuseClient.Run(ctx, "echo ask-reused")
	if err != nil || !strings.Contains(out, "fixture-output") {
		t.Fatalf("expected command over reused ask master to succeed, got out=%q err=%v", out, err)
	}
}
