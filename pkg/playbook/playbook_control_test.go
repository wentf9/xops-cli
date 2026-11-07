package playbook_test

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	cryptoSSH "golang.org/x/crypto/ssh"

	"github.com/wentf9/xops-cli/core/concurrent"
	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/playbook"
)

type diagnosticRecorder struct {
	mu     sync.Mutex
	events []corelog.Diagnostic
}

func (r *diagnosticRecorder) ObserveDiagnostic(d corelog.Diagnostic) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, d)
}

func (r *diagnosticRecorder) hasEvent(kind corelog.DiagnosticKind, nodeID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if e.Kind == kind && (nodeID == "" || e.NodeID == nodeID) {
			return true
		}
	}
	return false
}

// setupPlaybookFixture creates an sshfixture and a master connection with MuxServer listening on a socket.
func setupPlaybookFixture(t *testing.T, ctx context.Context) (*sshfixture.Server, string, *ssh.MuxServer, string, uint16) {
	t.Helper()

	fixture, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}

	host, portStr, err := net.SplitHostPort(fixture.Address)
	if err != nil {
		t.Fatalf("SplitHostPort failed: %v", err)
	}
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi failed: %v", err)
	}
	port := uint16(portInt)

	// Establish direct SSH master client connection to fixture
	clientCfg := &cryptoSSH.ClientConfig{
		User: "fixture",
		Auth: []cryptoSSH.AuthMethod{
			cryptoSSH.Password(sshfixture.Password),
		},
		HostKeyCallback: cryptoSSH.FixedHostKey(fixture.HostKey),
		Timeout:         5 * time.Second,
	}
	sshClient, err := cryptoSSH.Dial("tcp", fixture.Address, clientCfg)
	if err != nil {
		t.Fatalf("cryptoSSH.Dial master failed: %v", err)
	}

	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "playbook_master.sock")

	muxServer, err := ssh.NewMuxServer(ssh.MuxServerOptions{
		ControlPath: sockPath,
		SSHClient:   sshClient,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	go func() { _ = muxServer.Serve() }()

	t.Cleanup(func() {
		_ = muxServer.Shutdown()
		_ = sshClient.Close()
		_ = fixture.Close()
	})

	return fixture, sockPath, muxServer, host, port
}

func TestPlaybook_ActiveControlSocketReuse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fixture, sockPath, _, host, port := setupPlaybookFixture(t, ctx)

	// Configure playbook inventory with ControlPath pointing to active socket
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("host-1", models.Host{Address: host, Port: port})
	cfg.Identities.Set("id-1", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("web-01", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
		Tags:        []string{"web"},
		Control: &ssh.ControlConfig{
			Master: ssh.ControlMasterAuto,
			Path:   sockPath,
		},
	})

	provider := config.NewProviderWithoutOpenSSH(cfg)
	recorder := &diagnosticRecorder{}

	connector := adapter.NewConnector(provider, ssh.WithDiagnostics(recorder), ssh.WithHostKeyVerifier(fixtureTrust{key: fixture.HostKey}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	pb := &playbook.Playbook{
		Name: "test-playbook-mux",
		Targets: playbook.Targets{
			Nodes: []string{"web-01"},
		},
		Steps: []playbook.Step{
			{Name: "step-1", Shell: "echo step1"},
			{Name: "step-2", Shell: "echo step2"},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}

	if len(report.Hosts) != 1 {
		t.Fatalf("expected 1 host report, got %d", len(report.Hosts))
	}
	hr := report.Hosts[0]
	if hr.Status != playbook.HostStatusSuccess {
		t.Fatalf("expected host status success, got %v", hr.Status)
	}
	if len(hr.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(hr.Steps))
	}
	for i, step := range hr.Steps {
		if step.Status != playbook.StatusChanged {
			t.Errorf("step %d (%s) status = %v, expected StatusChanged (err: %v)", i, step.StepName, step.Status, step.Err)
		}
	}

	// Verify ConnectionReused diagnostic was recorded for web-01
	if !recorder.hasEvent(corelog.ConnectionReused, "web-01") {
		t.Errorf("expected ConnectionReused diagnostic event for web-01")
	}

	// Verify no new SSH handshakes / authentications were made to the fixture
	// The master dial was authentication #1; playbook reused the socket via MUX_C_PROXY without new authentication
	if authed := fixture.Authenticated.Load(); authed != 1 {
		t.Errorf("expected exactly 1 SSH authentication on fixture, got %d", authed)
	}
}

func TestPlaybook_CrossNodeSocketSharing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fixture, sockPath, _, host, port := setupPlaybookFixture(t, ctx)

	// Configure two nodes sharing the same physical host and same master socket
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("host-1", models.Host{Address: host, Port: port})
	cfg.Identities.Set("id-1", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})

	cfg.Nodes.Set("web-01", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
		Tags:        []string{"web"},
		Control: &ssh.ControlConfig{
			Master: ssh.ControlMasterAuto,
			Path:   sockPath,
		},
	})
	cfg.Nodes.Set("web-02", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
		Tags:        []string{"web"},
		Control: &ssh.ControlConfig{
			Master: ssh.ControlMasterAuto,
			Path:   sockPath,
		},
	})

	provider := config.NewProviderWithoutOpenSSH(cfg)
	recorder := &diagnosticRecorder{}

	connector := adapter.NewConnector(provider, ssh.WithDiagnostics(recorder), ssh.WithHostKeyVerifier(fixtureTrust{key: fixture.HostKey}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	pb := &playbook.Playbook{
		Name: "test-playbook-cross-node",
		Targets: playbook.Targets{
			Nodes: []string{"web-01", "web-02"},
		},
		Steps: []playbook.Step{
			{Name: "step-shared", Shell: "echo shared"},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}

	if len(report.Hosts) != 2 {
		t.Fatalf("expected 2 host reports, got %d", len(report.Hosts))
	}
	for _, hr := range report.Hosts {
		if hr.Status != playbook.HostStatusSuccess {
			t.Errorf("host %s status = %v, expected HostStatusSuccess", hr.NodeID, hr.Status)
		}
	}

	// Both web-01 and web-02 should have reused the active socket
	if !recorder.hasEvent(corelog.ConnectionReused, "web-01") {
		t.Errorf("expected ConnectionReused diagnostic for web-01")
	}
	if !recorder.hasEvent(corelog.ConnectionReused, "web-02") {
		t.Errorf("expected ConnectionReused diagnostic for web-02")
	}

	// Verify only 1 initial SSH authentication was performed on fixture
	if authed := fixture.Authenticated.Load(); authed != 1 {
		t.Errorf("expected exactly 1 SSH authentication on fixture, got %d", authed)
	}
}

func TestPlaybook_ControlPathNone_BypassesReuse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fixture, sockPath, _, host, port := setupPlaybookFixture(t, ctx)

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("host-1", models.Host{Address: host, Port: port})
	cfg.Identities.Set("id-1", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})

	// Node configured with Path: "none" (explicit disablement) even though sockPath exists
	cfg.Nodes.Set("web-direct", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
		Control: &ssh.ControlConfig{
			Master: ssh.ControlMasterNo,
			Path:   "none",
		},
	})

	_ = sockPath // active socket exists, but node explicitly set "none"

	provider := config.NewProviderWithoutOpenSSH(cfg)
	recorder := &diagnosticRecorder{}

	connector := adapter.NewConnector(provider, ssh.WithDiagnostics(recorder), ssh.WithHostKeyVerifier(fixtureTrust{key: fixture.HostKey}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	pb := &playbook.Playbook{
		Name: "test-playbook-no-mux",
		Targets: playbook.Targets{
			Nodes: []string{"web-direct"},
		},
		Steps: []playbook.Step{
			{Name: "direct-step", Shell: "echo direct"},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}

	if len(report.Hosts) != 1 || report.Hosts[0].Status != playbook.HostStatusSuccess {
		t.Fatalf("expected 1 successful host report, got %+v", report.Hosts)
	}

	// ConnectionReused should NOT have been emitted because Path is "none"
	if recorder.hasEvent(corelog.ConnectionReused, "web-direct") {
		t.Errorf("ConnectionReused should NOT be emitted when ControlPath is 'none'")
	}

	// Directly dialed fixture: total authentications should now be 2 (master + web-direct)
	if authed := fixture.Authenticated.Load(); authed != 2 {
		t.Errorf("expected 2 SSH authentications on fixture, got %d", authed)
	}
}

func TestPlaybook_StaleSocketAutoUnlinkAndFallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fixture, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fixture.Close() }()

	host, portStr, _ := net.SplitHostPort(fixture.Address)
	portInt, _ := strconv.Atoi(portStr)
	port := uint16(portInt)

	// Create a stale socket on disk without active listener
	tmpDir := t.TempDir()
	staleSockPath := filepath.Join(tmpDir, "stale.sock")
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("create socket failed: %v", err)
	}
	defer func() { _ = syscall.Close(fd) }()
	sa := &syscall.SockaddrUnix{Name: staleSockPath}
	if err := syscall.Bind(fd, sa); err != nil {
		t.Fatalf("bind failed: %v", err)
	}
	_ = syscall.Close(fd) // Close without listening, leaving stale socket file

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("host-1", models.Host{Address: host, Port: port})
	cfg.Identities.Set("id-1", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("web-stale", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
		Control: &ssh.ControlConfig{
			Master: ssh.ControlMasterAuto,
			Path:   staleSockPath,
		},
	})

	provider := config.NewProviderWithoutOpenSSH(cfg)
	recorder := &diagnosticRecorder{}

	connector := adapter.NewConnector(provider, ssh.WithDiagnostics(recorder), ssh.WithHostKeyVerifier(fixtureTrust{key: fixture.HostKey}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	pb := &playbook.Playbook{
		Name: "test-stale-socket-fallback",
		Targets: playbook.Targets{
			Nodes: []string{"web-stale"},
		},
		Steps: []playbook.Step{
			{Name: "fallback-step", Shell: "echo fallback"},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}

	if len(report.Hosts) != 1 || report.Hosts[0].Status != playbook.HostStatusSuccess {
		t.Fatalf("expected 1 successful host report after stale fallback, got %+v", report.Hosts)
	}

	// Verify the step succeeded
	if report.Hosts[0].Steps[0].Status != playbook.StatusChanged {
		t.Errorf("expected step status changed, got %v", report.Hosts[0].Steps[0].Status)
	}

	// Verify stale socket was unlinked and a new master started on staleSockPath
	aliveProbeCtx, probeCancel := context.WithTimeout(ctx, 2*time.Second)
	defer probeCancel()
	client, probeErr := ssh.DialMuxClient(aliveProbeCtx, staleSockPath)
	if probeErr != nil {
		t.Fatalf("expected new master to be listening on staleSockPath: %v", probeErr)
	}
	defer func() { _ = client.Close() }()
	pid, aliveErr := client.AliveCheck(aliveProbeCtx)
	if aliveErr != nil || pid == 0 {
		t.Errorf("alive check on recreated master failed: %v, pid=%d", aliveErr, pid)
	}

	// Direct dial was used for the initial connection so ConnectionReused was not emitted
	if recorder.hasEvent(corelog.ConnectionReused, "web-stale") {
		t.Errorf("ConnectionReused should not be emitted on initial stale socket fallback")
	}
}
