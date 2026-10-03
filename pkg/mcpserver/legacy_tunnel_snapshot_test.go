package mcpserver

import (
	"context"
	"errors"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	coreruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/testutil/sshfixture"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"golang.org/x/crypto/ssh/knownhosts"
)

type tunnelSnapshotStore struct {
	mu  sync.Mutex
	cfg *config.Configuration
}

func (s *tunnelSnapshotStore) Load() (*config.Configuration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return config.NewProviderWithoutOpenSSH(s.cfg).Snapshot(), nil
}
func (s *tunnelSnapshotStore) Save(cfg *config.Configuration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = config.NewProviderWithoutOpenSSH(cfg).Snapshot()
	return nil
}

func setupLegacyTunnelRepository(t *testing.T) (context.Context, *config.Repository, *sshfixture.Server, *sshfixture.Server) {
	t.Helper()
	home := isolateMCPTestEnvironment(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	first, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil {
			t.Error(err)
		}
	})
	second, err := sshfixture.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil {
			t.Error(err)
		}
	})
	known := knownhosts.Line([]string{knownhosts.Normalize(first.Address)}, first.HostKey) + "\n" + knownhosts.Line([]string{knownhosts.Normalize(second.Address)}, second.HostKey) + "\n"
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(known), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := runtimeTestProvider("node").Snapshot()
	cfg.Hosts.Set("host", tunnelSnapshotHost(t, first.Address))
	cfg.Identities.Set("identity", models.Identity{User: "fixture", AuthType: "password", Password: sshfixture.Password})
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, &tunnelSnapshotStore{cfg: cfg})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, repo, first, second
}

func TestLegacyTunnelDialsTheNewlyAdmittedRepositoryTarget(t *testing.T) {
	ctx, repo, first, second := setupLegacyTunnelRepository(t)
	runtime, err := NewRuntime(ctx, WithConfigProvider(repo))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			t.Error(err)
		}
	}()
	client := connectRuntimeTestClient(t, runtime)
	ref := repo.View().NodeRefs["node"]
	node, _, identity, err := repo.Resolve("node")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.ReplaceNodeAtRefContext(ctx, ref, "node", node, tunnelSnapshotHost(t, second.Address), identity); err != nil {
		t.Fatal(err)
	}
	input := tunnelTestInput(t, startTunnelEcho(t), "remote", "after-edit")
	created := callTunnelTool(t, client, "xops_tunnel_create", input)
	if created.State != "running" {
		t.Fatalf("creation failed: %+v", created)
	}
	assertTunnelEcho(t, created.ListenAddress)
	if first.Forwards.Load() != 0 || second.Forwards.Load() != 1 {
		t.Fatalf("tunnel used startup rather than admitted endpoint: old=%d new=%d", first.Forwards.Load(), second.Forwards.Load())
	}
	callTunnelTool(t, client, "xops_tunnel_stop", TunnelInput{TunnelID: created.TunnelID})
}

func tunnelSnapshotHost(t *testing.T, address string) models.Host {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return models.Host{Address: host, Port: uint16(port)}
}

type holdLegacyTunnelAdmission struct {
	ports.ExecutionGate
	entered, release chan struct{}
}

func (g *holdLegacyTunnelAdmission) Enter(ctx context.Context, request ports.Admission) (ports.Permit, error) {
	permit, err := g.ExecutionGate.Enter(ctx, request)
	if err == nil && request.Binding.Tool == "xops_tunnel_create" && request.Phase == ports.Execute {
		close(g.entered)
		select {
		case <-g.release:
		case <-ctx.Done():
			return nil, errors.Join(ctx.Err(), permit.Close())
		}
	}
	return permit, err
}

func TestLegacyTunnelRetainsAdmittedTargetAcrossLaterRepositoryEdit(t *testing.T) {
	ctx, repo, first, second := setupLegacyTunnelRepository(t)
	host := newLegacyHost(legacyConfig{provider: repo})
	dependencies := host.dependencies()
	gate := &holdLegacyTunnelAdmission{ExecutionGate: dependencies.Gate, entered: make(chan struct{}), release: make(chan struct{})}
	dependencies.Gate = gate
	runtime, err := coreruntime.NewRuntime(ctx, coreruntime.WithDependencies(dependencies))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			t.Error(err)
		}
	}()
	client := connectRuntimeTestClient(t, runtime)
	input := tunnelTestInput(t, startTunnelEcho(t), "remote", "admitted-before-edit")
	type result struct {
		output TunnelOutput
		err    error
	}
	done := make(chan result, 1)
	go func() {
		var output TunnelOutput
		_, err := legacyCall(ctx, client, "xops_tunnel_create", input, &output)
		done <- result{output, err}
	}()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal("tunnel did not reach admission barrier")
	}
	ref := repo.View().NodeRefs["node"]
	node, _, identity, err := repo.Resolve("node")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.ReplaceNodeAtRefContext(ctx, ref, "node", node, tunnelSnapshotHost(t, second.Address), identity); err != nil {
		t.Fatal(err)
	}
	close(gate.release)
	select {
	case created := <-done:
		if created.err != nil {
			t.Fatal(created.err)
		}
		if created.output.Tunnel.State != "running" {
			t.Fatalf("admitted tunnel failed: %+v", created.output)
		}
		assertTunnelEcho(t, created.output.Tunnel.ListenAddress)
		if first.Forwards.Load() != 1 || second.Forwards.Load() != 0 {
			t.Fatal("post-admission edit redirected the tunnel")
		}
		callTunnelTool(t, client, "xops_tunnel_stop", TunnelInput{TunnelID: created.output.Tunnel.TunnelID})
	case <-ctx.Done():
		t.Fatal("tunnel creation did not finish")
	}
}
