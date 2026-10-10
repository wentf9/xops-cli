package mcphost

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	corepolicy "github.com/wentf9/xops-cli/core/mcp/policy"
	"github.com/wentf9/xops-cli/core/mcp/ports"
	mcpruntime "github.com/wentf9/xops-cli/core/mcp/runtime"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestCLIBindingSurvivesRuntimeRecreationAndRejectsChangedTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Guardrail = &corepolicy.Config{Enabled: false}
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "fixture", AuthType: "password", Password: "synthetic"})
	cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "identity"})
	first := newHost(Config{Provider: config.NewProviderWithoutOpenSSH(cfg)})
	view, err := first.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node"}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := ports.Bind(view, "scope", "test", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(transfer.Authorization{Snapshot: view, Binding: binding})
	if err != nil {
		t.Fatal(err)
	}
	var restored transfer.Authorization
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	admission := ports.Admission{OperationID: "recovery", Phase: ports.Recovery, Snapshot: restored.Snapshot, Binding: restored.Binding}
	second := newHost(Config{Provider: config.NewProviderWithoutOpenSSH(cfg)})
	permit, err := second.Enter(ctx, admission)
	if err != nil {
		t.Fatalf("recreated host rejected identical persisted binding: %v", err)
	}
	if err := permit.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.2", Port: 22})
	third := newHost(Config{Provider: config.NewProviderWithoutOpenSSH(cfg)})
	if permit, err := third.Enter(ctx, admission); !errors.Is(err, ports.ErrStaleBinding) {
		if permit != nil {
			if err := permit.Close(); err != nil {
				t.Error(err)
			}
		}
		t.Fatalf("recreated host redirected old recovery: %v", err)
	}
}

func TestCLIRecoveryReconstructsHTTPPolicyDefaults(t *testing.T) {
	for _, policy := range []*corepolicy.Config{nil, {Enabled: true, ApprovalThreshold: "dangerous"}, {Enabled: true, NoElicitFallback: "allow"}} {
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Guardrail = policy
		provider := config.NewProviderWithoutOpenSSH(cfg)
		httpHost := newHost(Config{Provider: provider, HTTP: &mcpruntime.HTTPOptions{}})
		recovery := newHost(Config{Provider: provider, Recovery: true})
		a, err := httpHost.Resolve(t.Context(), ports.ResolveRequest{})
		if err != nil {
			t.Fatal(err)
		}
		b, err := recovery.Resolve(t.Context(), ports.ResolveRequest{})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := ports.Bind(a, "scope", "test", struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		if err := binding.Validate(b); err != nil {
			t.Fatalf("offline recovery changed the HTTP policy: %v", err)
		}
	}
}

func TestCLIBindingInvalidatesOnExecutionChangeAndPreservesOnUnrelatedChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Guardrail = &corepolicy.Config{Enabled: false}
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "fixture", AuthType: "password", Password: "synthetic"})
	cfg.Execution = &ssh.ExecutionConfig{Interpreter: ssh.InterpreterBash, LaunchDialect: ssh.LaunchPOSIX}

	// node1 inherits global execution
	cfg.Nodes.Set("node1", models.Node{HostRef: "host", IdentityRef: "identity"})
	// node2 explicitly overrides execution
	cfg.Nodes.Set("node2", models.Node{
		HostRef: "host", IdentityRef: "identity",
		Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX},
	})

	prov := config.NewProviderWithoutOpenSSH(cfg)
	h := newHost(Config{Provider: prov})

	snap1, err := h.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node1"}})
	if err != nil {
		t.Fatal(err)
	}
	binding1, err := ports.Bind(snap1, "scope", "test", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if err := binding1.Validate(snap1); err != nil {
		t.Fatalf("initial node1 validate failed: %v", err)
	}

	snap2, err := h.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node2"}})
	if err != nil {
		t.Fatal(err)
	}
	binding2, err := ports.Bind(snap2, "scope", "test", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if err := binding2.Validate(snap2); err != nil {
		t.Fatalf("initial node2 validate failed: %v", err)
	}

	// 1. Change global execution interpreter from bash to server
	cfg.Execution = &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchPOSIX}
	provUpdated := config.NewProviderWithoutOpenSSH(cfg)
	hUpdated := newHost(Config{Provider: provUpdated})

	snap1New, err := hUpdated.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node1"}})
	if err != nil {
		t.Fatal(err)
	}
	// node1 inherited global execution, so its effective execution changed and old binding MUST be invalidated
	if err := binding1.Validate(snap1New); !errors.Is(err, ports.ErrStaleBinding) {
		t.Fatalf("node1 binding should be stale after global execution change, got: %v", err)
	}

	snap2New, err := hUpdated.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node2"}})
	if err != nil {
		t.Fatal(err)
	}
	// node2 explicitly set server+posix, so its effective execution did NOT change; old binding MUST remain valid!
	if err := binding2.Validate(snap2New); err != nil {
		t.Fatalf("node2 binding should remain valid despite unrelated global execution change, got: %v", err)
	}

	// 2. Change node2's explicit execution
	cfg.Nodes.Set("node2", models.Node{
		HostRef: "host", IdentityRef: "identity",
		Execution: &ssh.ExecutionConfig{Interpreter: ssh.InterpreterServer, LaunchDialect: ssh.LaunchCmd},
	})
	provNode2Changed := config.NewProviderWithoutOpenSSH(cfg)
	hNode2Changed := newHost(Config{Provider: provNode2Changed})

	snap2Changed, err := hNode2Changed.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node2"}})
	if err != nil {
		t.Fatal(err)
	}
	// Now node2 binding MUST be invalidated
	if err := binding2.Validate(snap2Changed); !errors.Is(err, ports.ErrStaleBinding) {
		t.Fatalf("node2 binding should be stale after node execution change, got: %v", err)
	}

	// 3. Unrelated change (e.g. changing PasswordPromptPattern or adding an unrelated node3)
	// Must NOT invalidate existing valid bindings
	binding2Fresh, err := ports.Bind(snap2Changed, "scope", "test", struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.PasswordPromptPattern = "^password: "
	cfg.Nodes.Set("node3", models.Node{HostRef: "host", IdentityRef: "identity"})
	provUnrelated := config.NewProviderWithoutOpenSSH(cfg)
	hUnrelated := newHost(Config{Provider: provUnrelated})

	snap2Unrelated, err := hUnrelated.Resolve(ctx, ports.ResolveRequest{Selectors: []string{"node2"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := binding2Fresh.Validate(snap2Unrelated); err != nil {
		t.Fatalf("unrelated change should not invalidate node2 binding: %v", err)
	}
}
