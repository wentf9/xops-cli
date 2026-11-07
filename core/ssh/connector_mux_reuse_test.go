package ssh

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
)

// jumpChainProvider serves one configuration per node, unlike testMuxProvider
// which answers every lookup with the same node.
type jumpChainProvider struct {
	cfgs map[string]*ClientConfig
	ctrl map[string]*ControlConfig
}

func (p *jumpChainProvider) GetConfig(nodeID string) (*ClientConfig, error) {
	cfg, ok := p.cfgs[nodeID]
	if !ok {
		return nil, fmt.Errorf("unknown node %q", nodeID)
	}
	cloned := *cfg
	return &cloned, nil
}

func (p *jumpChainProvider) GetControlConfig(nodeID string) (*ControlConfig, error) {
	return p.ctrl[nodeID], nil
}

// staticControlProvider points every node at one control path, which is what a
// live adapter does while the active configuration is being resolved.
type staticControlProvider struct{ ctrl *ControlConfig }

func (p staticControlProvider) GetControlConfig(string) (*ControlConfig, error) {
	return p.ctrl, nil
}

// planFixtureSecrets returns the fixture password for the captured plan version.
type planFixtureSecrets struct{}

func (planFixtureSecrets) ResolveSecret(ctx context.Context, req SecretRequest) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if req.VersionToken != "v1" {
		return nil, ErrSnapshotMismatch
	}
	return []byte(sshfixture.Password), nil
}

func fixtureEndpoint(t *testing.T, address string) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("SplitHostPort(%q) failed: %v", address, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("Atoi(%q) failed: %v", portText, err)
	}
	return host, port
}

// TestConnectReusesJumpChainedTargetWithoutBastionAuth verifies that an active
// control master on a jump-chained target is reused without dialing and
// re-authenticating to the bastion. Otherwise every reused command replays the
// jump host's authentication, including its one-time factors, and defeats the
// purpose of connection sharing.
func TestConnectReusesJumpChainedTargetWithoutBastionAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	bastion, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("bastion fixture failed: %v", err)
	}
	defer func() { _ = bastion.Close() }()
	target, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("target fixture failed: %v", err)
	}
	defer func() { _ = target.Close() }()

	bastionHost, bastionPort := fixtureEndpoint(t, bastion.Address)
	targetHost, targetPort := fixtureEndpoint(t, target.Address)
	socketPath := filepath.Join(shortSocketDir(t), "chain.sock")

	provider := &jumpChainProvider{
		cfgs: map[string]*ClientConfig{
			"jump": {
				NodeID: "jump", Address: bastionHost, Port: bastionPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
			},
			"target": {
				NodeID: "target", Address: targetHost, Port: targetPort,
				User: "fixture", AuthType: "password", Password: sshfixture.Password,
				ProxyJump: "jump",
			},
		},
		ctrl: map[string]*ControlConfig{
			"target": {Master: ControlMasterAuto, Path: socketPath},
		},
	}

	first := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() {
		if err := first.CloseAll(); err != nil {
			t.Logf("CloseAll failed: %v", err)
		}
	}()
	if _, err := first.Connect(ctx, "target"); err != nil {
		t.Fatalf("initial jump-chained connect failed: %v", err)
	}
	waitForCondition(t, 10*time.Second, func() bool {
		return GetActiveMuxServer(socketPath) != nil
	}, "connector did not start a control master on the target")
	if got := bastion.Authenticated.Load(); got != 1 {
		t.Fatalf("initial connect authenticated %d times on the bastion, want 1", got)
	}

	second := newTestConnector(provider, WithHostKeyVerifier(&fixtureTrust{}))
	defer func() {
		if err := second.CloseAll(); err != nil {
			t.Logf("CloseAll failed: %v", err)
		}
	}()
	client, err := second.Connect(ctx, "target")
	if err != nil {
		t.Fatalf("reuse connect failed: %v", err)
	}
	if got := bastion.Authenticated.Load(); got != 1 {
		t.Fatalf("reuse re-authenticated to the bastion: %d authentications, want 1", got)
	}
	if got := target.Authenticated.Load(); got != 1 {
		t.Fatalf("reuse re-authenticated to the target: %d authentications, want 1", got)
	}

	session, err := client.sshClient.NewSession()
	if err != nil {
		t.Fatalf("NewSession through the reused master failed: %v", err)
	}
	defer func() { _ = session.Close() }()
	output, err := session.Output("reuse-check")
	if err != nil {
		t.Fatalf("command through the reused master failed: %v", err)
	}
	if string(output) != "fixture-output" {
		t.Fatalf("reused command output = %q, want %q", output, "fixture-output")
	}
}

// TestPlanConnectionDoesNotAttachToControlMaster verifies that a captured
// connection plan never attaches to an existing control master. The plan is a
// frozen generation keyed by scope, hops and trust versions, while a control
// socket is addressed only by %l%h%p%r%j, so joining one would reuse a transport
// admitted under another scope or credential version and bypass RetirePlan.
func TestPlanConnectionDoesNotAttachToControlMaster(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	fixture, err := sshfixture.NewWithOptions(ctx, sshfixture.Options{})
	if err != nil {
		t.Fatalf("fixture failed: %v", err)
	}
	defer func() { _ = fixture.Close() }()
	host, port := fixtureEndpoint(t, fixture.Address)

	socketPath := filepath.Join(shortSocketDir(t), "existing.sock")
	master, err := NewMuxServer(MuxServerOptions{
		ControlPath:       socketPath,
		SSHClient:         newDummySSHClient(),
		PersistEnabled:    true,
		PersistIndefinite: true,
	})
	if err != nil {
		t.Fatalf("NewMuxServer failed: %v", err)
	}
	go func() { _ = master.Serve() }()
	defer func() { _ = master.Shutdown() }()

	connector := NewConnector(&forbiddenPlanProvider{},
		WithSecretResolver(planFixtureSecrets{}),
		WithHostKeyVerifier(&fixtureTrust{}),
		WithControlProvider(staticControlProvider{ctrl: &ControlConfig{Master: ControlMasterAuto, Path: socketPath}}),
	)
	defer func() {
		if err := connector.CloseAll(); err != nil {
			t.Logf("CloseAll failed: %v", err)
		}
	}()

	plan := ConnectionPlan{Scope: "runtime", Hops: []ConnectionConfig{{
		NodeID: "node", Address: host, Port: port, User: "fixture", AuthType: "password", AuthUpdateToken: "v1",
	}}}
	lease, err := connector.ConnectPlan(ctx, plan)
	if err != nil {
		t.Fatalf("ConnectPlan failed: %v", err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()

	session, err := lease.Client.sshClient.NewSession()
	if err != nil {
		t.Fatalf("plan attached to the control master instead of dialing its own transport: %v", err)
	}
	defer func() { _ = session.Close() }()
	output, err := session.Output("plan-check")
	if err != nil {
		t.Fatalf("command on the plan transport failed: %v", err)
	}
	if string(output) != "fixture-output" {
		t.Fatalf("plan command output = %q, want %q", output, "fixture-output")
	}
}
