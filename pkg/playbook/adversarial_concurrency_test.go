package playbook_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/concurrent"
	corelog "github.com/wentf9/xops-cli/core/log"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/playbook"
)

// TestAdversarial_Playbook_HighConcurrencySocketSharing stress tests multiple nodes
// executing concurrently in parallel over a single active master control socket.
// It verifies that all steps succeed concurrently and that 0 additional SSH authentications occur.
func TestAdversarial_Playbook_HighConcurrencySocketSharing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fixture, sockPath, _, host, port := setupPlaybookFixture(t, ctx)

	const numNodes = 8
	const stepsPerNode = 3

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("shared-host", models.Host{Address: host, Port: port})
	cfg.Identities.Set("shared-id", models.Identity{User: "fixture", AuthType: "password", Password: "synthetic-ssh-fixture-password"})

	var targetNodes []string
	for i := 1; i <= numNodes; i++ {
		nodeID := fmt.Sprintf("web-%02d", i)
		targetNodes = append(targetNodes, nodeID)
		cfg.Nodes.Set(nodeID, models.Node{
			HostRef:     "shared-host",
			IdentityRef: "shared-id",
			Tags:        []string{"web"},
			SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
				Master: ssh.ControlMasterAuto,
				Path:   sockPath,
			}),
		})
	}

	provider := config.NewProviderWithoutOpenSSH(cfg)
	recorder := &diagnosticRecorder{}

	connector := adapter.NewConnector(provider, ssh.WithDiagnostics(recorder), ssh.WithHostKeyVerifier(fixtureTrust{key: fixture.HostKey}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	var steps []playbook.Step
	for s := 1; s <= stepsPerNode; s++ {
		steps = append(steps, playbook.Step{
			Name:  fmt.Sprintf("step-%d", s),
			Shell: fmt.Sprintf("echo step-%d", s),
		})
	}

	pb := &playbook.Playbook{
		Name: "adversarial-concurrency-mux",
		Settings: playbook.Settings{
			Concurrency: numNodes, // Maximum parallel concurrency across all nodes
		},
		Targets: playbook.Targets{
			Nodes: targetNodes,
		},
		Steps: steps,
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine.Run failed under concurrency: %v", err)
	}

	if len(report.Hosts) != numNodes {
		t.Fatalf("expected %d host reports, got %d", numNodes, len(report.Hosts))
	}

	for _, hr := range report.Hosts {
		if hr.Status != playbook.HostStatusSuccess {
			t.Errorf("host %s failed with status %v", hr.NodeID, hr.Status)
		}
		if len(hr.Steps) != stepsPerNode {
			t.Errorf("host %s expected %d steps, got %d", hr.NodeID, stepsPerNode, len(hr.Steps))
		}
		for sIdx, sReport := range hr.Steps {
			if sReport.Status != playbook.StatusChanged {
				t.Errorf("host %s step %d status = %v, expected StatusChanged", hr.NodeID, sIdx, sReport.Status)
			}
		}

		// Verify ConnectionReused diagnostic was recorded for each node
		if !recorder.hasEvent(corelog.ConnectionReused, hr.NodeID) {
			t.Errorf("expected ConnectionReused diagnostic for %s", hr.NodeID)
		}
	}

	// VERIFY ZERO NEW SSH AUTHENTICATIONS:
	// Only 1 initial authentication from setupPlaybookFixture's master dial.
	// All 8 nodes and 24 steps ran concurrently without performing any additional SSH authentications!
	authed := fixture.Authenticated.Load()
	if authed != 1 {
		t.Fatalf("CRITICAL: expected exactly 1 SSH authentication on remote peer, got %d (connection was not reused!)", authed)
	}
}

// TestAdversarial_Playbook_RapidSequentialMultiStep verifies that a single node
// executing a long sequence of steps over the multiplexed connection operates cleanly
// with 0 extra authentications.
func TestAdversarial_Playbook_RapidSequentialMultiStep(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fixture, sockPath, _, host, port := setupPlaybookFixture(t, ctx)

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("host-seq", models.Host{Address: host, Port: port})
	cfg.Identities.Set("id-seq", models.Identity{User: "fixture", AuthType: "password", Password: "synthetic-ssh-fixture-password"})
	cfg.Nodes.Set("node-seq", models.Node{
		HostRef:     "host-seq",
		IdentityRef: "id-seq",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master: ssh.ControlMasterAuto,
			Path:   sockPath,
		}),
	})

	provider := config.NewProviderWithoutOpenSSH(cfg)
	recorder := &diagnosticRecorder{}

	connector := adapter.NewConnector(provider, ssh.WithDiagnostics(recorder), ssh.WithHostKeyVerifier(fixtureTrust{key: fixture.HostKey}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	const numSteps = 10
	var steps []playbook.Step
	for i := 1; i <= numSteps; i++ {
		steps = append(steps, playbook.Step{
			Name:  fmt.Sprintf("rapid-step-%02d", i),
			Shell: fmt.Sprintf("echo rapid-%02d", i),
		})
	}

	pb := &playbook.Playbook{
		Name: "rapid-sequential-playbook",
		Targets: playbook.Targets{
			Nodes: []string{"node-seq"},
		},
		Steps: steps,
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}

	if len(report.Hosts) != 1 || report.Hosts[0].Status != playbook.HostStatusSuccess {
		t.Fatalf("expected host success, got %+v", report.Hosts)
	}
	if len(report.Hosts[0].Steps) != numSteps {
		t.Fatalf("expected %d steps, got %d", numSteps, len(report.Hosts[0].Steps))
	}

	// Authentications must remain exactly 1
	if authed := fixture.Authenticated.Load(); authed != 1 {
		t.Fatalf("expected 1 authentication, got %d", authed)
	}
}

// TestAdversarial_Playbook_ConcurrentSharedAndDirectNodes tests a mixed execution where
// some nodes reuse a master socket while others bypass it via ControlPath: "none".
func TestAdversarial_Playbook_ConcurrentSharedAndDirectNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fixture, sockPath, _, host, port := setupPlaybookFixture(t, ctx)

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("mixed-host", models.Host{Address: host, Port: port})
	cfg.Identities.Set("mixed-id", models.Identity{User: "fixture", AuthType: "password", Password: "synthetic-ssh-fixture-password"})

	// 4 shared nodes
	for i := 1; i <= 4; i++ {
		cfg.Nodes.Set(fmt.Sprintf("shared-%02d", i), models.Node{
			HostRef:     "mixed-host",
			IdentityRef: "mixed-id",
			SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
				Master: ssh.ControlMasterAuto,
				Path:   sockPath,
			}),
		})
	}

	// 2 direct nodes (bypass mux)
	for i := 1; i <= 2; i++ {
		cfg.Nodes.Set(fmt.Sprintf("direct-%02d", i), models.Node{
			HostRef:     "mixed-host",
			IdentityRef: "mixed-id",
			SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
				Master: ssh.ControlMasterNo,
				Path:   "none",
			}),
		})
	}

	provider := config.NewProviderWithoutOpenSSH(cfg)
	recorder := &diagnosticRecorder{}

	connector := adapter.NewConnector(provider, ssh.WithDiagnostics(recorder), ssh.WithHostKeyVerifier(fixtureTrust{key: fixture.HostKey}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	pb := &playbook.Playbook{
		Name: "mixed-shared-direct-playbook",
		Settings: playbook.Settings{
			Concurrency: 6,
		},
		Targets: playbook.Targets{
			Nodes: []string{"shared-01", "shared-02", "shared-03", "shared-04", "direct-01", "direct-02"},
		},
		Steps: []playbook.Step{
			{Name: "step-mixed", Shell: "echo mixed"},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine.Run failed: %v", err)
	}

	if len(report.Hosts) != 6 {
		t.Fatalf("expected 6 host reports, got %d", len(report.Hosts))
	}
	for _, hr := range report.Hosts {
		if hr.Status != playbook.HostStatusSuccess {
			t.Errorf("host %s failed: status %v", hr.NodeID, hr.Status)
		}
	}

	// Verify shared nodes reused connection
	for i := 1; i <= 4; i++ {
		sharedID := fmt.Sprintf("shared-%02d", i)
		if !recorder.hasEvent(corelog.ConnectionReused, sharedID) {
			t.Errorf("expected ConnectionReused for %s", sharedID)
		}
	}

	// Verify direct nodes did NOT reuse connection
	for i := 1; i <= 2; i++ {
		directID := fmt.Sprintf("direct-%02d", i)
		if recorder.hasEvent(corelog.ConnectionReused, directID) {
			t.Errorf("direct node %s should NOT have emitted ConnectionReused", directID)
		}
	}

	// Authentications: 1 (master dial) + 2 (direct-01 & direct-02) = 3 total.
	// The 4 shared nodes contributed ZERO additional authentications!
	if authed := fixture.Authenticated.Load(); authed != 3 {
		t.Fatalf("expected 3 total authentications (1 master + 2 direct), got %d", authed)
	}
}

// TestAdversarial_Playbook_StaleSocketSimulatedCrashRecovery tests that if a previous
// master crashes and leaves a dead socket on disk, a playbook execution unblocks,
// unlinks the stale socket, starts a fresh master, and executes the steps successfully.
func TestAdversarial_Playbook_StaleSocketSimulatedCrashRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fixture, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatalf("sshfixture.New failed: %v", err)
	}
	defer func() { _ = fixture.Close() }()

	tmpDir := shortPlaybookSocketDir(t)
	staleSockPath := filepath.Join(tmpDir, "crashed_playbook.sock")

	// Create a dead socket on disk
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("create socket failed: %v", err)
	}
	sa := &syscall.SockaddrUnix{Name: staleSockPath}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		t.Fatalf("bind failed: %v", err)
	}
	_ = syscall.Close(fd) // Dead socket on disk

	host, portStr, err := net.SplitHostPort(fixture.Address)
	if err != nil {
		t.Fatal(err)
	}
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(portInt)

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("host-crash", models.Host{Address: host, Port: port})
	cfg.Identities.Set("id-crash", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	cfg.Nodes.Set("node-crash", models.Node{
		HostRef:     "host-crash",
		IdentityRef: "id-crash",
		SSHOptions: ssh.OptionsFromControl(&ssh.ControlConfig{
			Master: ssh.ControlMasterAuto,
			Path:   staleSockPath,
		}),
	})

	provider := config.NewProviderWithoutOpenSSH(cfg)
	recorder := &diagnosticRecorder{}

	connector := adapter.NewConnector(provider, ssh.WithDiagnostics(recorder), ssh.WithHostKeyVerifier(fixtureTrust{key: fixture.HostKey}))
	connector.AcceptNewHostKey.Store(true)
	defer func() { _ = connector.CloseAll() }()

	pb := &playbook.Playbook{
		Name: "crash-recovery-playbook",
		Targets: playbook.Targets{
			Nodes: []string{"node-crash"},
		},
		Steps: []playbook.Step{
			{Name: "step-after-crash-1", Shell: "echo recovered-1"},
			{Name: "step-after-crash-2", Shell: "echo recovered-2"},
		},
	}

	engine := playbook.NewEngine(pb, provider, connector)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("engine.Run failed after master crash: %v", err)
	}

	if len(report.Hosts) != 1 || report.Hosts[0].Status != playbook.HostStatusSuccess {
		t.Fatalf("expected host success after crash recovery, got %+v", report.Hosts)
	}
	if len(report.Hosts[0].Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(report.Hosts[0].Steps))
	}

	// Verify master socket on staleSockPath was recreated and is alive!
	probeCtx, pCancel := context.WithTimeout(ctx, 2*time.Second)
	defer pCancel()
	mCli, probeErr := ssh.DialMuxClient(probeCtx, staleSockPath)
	if probeErr != nil {
		t.Fatalf("expected newly created master on %s: %v", staleSockPath, probeErr)
	}
	defer func() { _ = mCli.Close() }()
	pid, checkErr := mCli.AliveCheck(probeCtx)
	if checkErr != nil || pid == 0 {
		t.Fatalf("AliveCheck failed on recovered master: %v", checkErr)
	}
}
