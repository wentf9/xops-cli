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
