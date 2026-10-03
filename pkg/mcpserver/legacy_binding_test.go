package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/ports"
	"github.com/wentf9/xops-cli/core/mcp/transfer"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestLegacyBindingSurvivesRuntimeRecreationAndRejectsChangedTarget(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Guardrail = &config.GuardrailConfig{Enabled: false}
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "fixture", AuthType: "password", Password: "synthetic"})
	cfg.Nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "identity"})
	first := newLegacyHost(legacyConfig{provider: config.NewProviderWithoutOpenSSH(cfg)})
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
	second := newLegacyHost(legacyConfig{provider: config.NewProviderWithoutOpenSSH(cfg)})
	permit, err := second.Enter(ctx, admission)
	if err != nil {
		t.Fatalf("recreated host rejected identical persisted binding: %v", err)
	}
	if err := permit.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.2", Port: 22})
	third := newLegacyHost(legacyConfig{provider: config.NewProviderWithoutOpenSSH(cfg)})
	if permit, err := third.Enter(ctx, admission); !errors.Is(err, ports.ErrStaleBinding) {
		if permit != nil {
			if err := permit.Close(); err != nil {
				t.Error(err)
			}
		}
		t.Fatalf("recreated host redirected old recovery: %v", err)
	}
}

func TestLegacyRecoveryReconstructsHTTPPolicyDefaults(t *testing.T) {
	for _, policy := range []*config.GuardrailConfig{nil, {Enabled: true, ApprovalThreshold: "dangerous"}, {Enabled: true, NoElicitFallback: "allow"}} {
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Guardrail = policy
		provider := config.NewProviderWithoutOpenSSH(cfg)
		httpHost := newLegacyHost(legacyConfig{provider: provider, http: &HTTPOptions{}})
		recovery := newLegacyHost(legacyConfig{provider: provider, recovery: true})
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
