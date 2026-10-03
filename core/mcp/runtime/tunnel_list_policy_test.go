package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/guardrail"
	"github.com/wentf9/xops-cli/core/mcp/tunnel"
	config "github.com/wentf9/xops-cli/core/testutil/mcphost"
	"github.com/wentf9/xops-cli/core/testutil/mcphost/models"
)

func tunnelListPolicyRuntime(t *testing.T) *Runtime {
	t.Helper()
	return tunnelListRuntimeWithPolicy(t, &config.GuardrailConfig{
		Enabled: true, ApprovalThreshold: "dangerous", NoElicitFallback: guardrail.FallbackDeny,
		NodeOverrides: map[string]config.NodeGuardrailCfg{"restricted-*": {ApprovalThreshold: "safe"}},
	})
}

func tunnelListRuntimeWithPolicy(t *testing.T, policy *config.GuardrailConfig) *Runtime {
	t.Helper()
	f := startTunnelSSHFixture(t, 0)
	cfg := f.provider.Snapshot()
	for _, id := range []string{"restricted-a", "restricted-b", "restricted-c"} {
		cfg.Nodes.Set(id, models.Node{HostRef: "host", IdentityRef: "identity"})
	}
	cfg.Guardrail = policy
	f.provider = config.NewProviderWithoutOpenSSH(cfg)
	return newTunnelRuntime(t, f)
}

// Seed already-authorized tasks directly so query approval is the only
// permission exercised by the client under test. The runner still uses SSH.
func seedTunnelListTask(t *testing.T, r *Runtime, nodeID, requestID string) tunnel.Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	s, err := r.tunnels.Create(ctx, tunnel.Spec{RequestID: requestID, NodeID: nodeID, Mode: "local", TargetHost: "127.0.0.1", TargetPort: 1}, "fixture-seed")
	if err != nil || s.State != "running" {
		t.Fatalf("seed: %+v, %v", s, err)
	}
	return s
}

func tunnelListPolicyClient(t *testing.T, r *Runtime, protocol string, opts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	if _, err := r.server.Connect(r.ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "tunnel-list-policy-test", Version: "1"}, opts)
	session, err := client.Connect(t.Context(), ct, &mcp.ClientSessionOptions{ProtocolVersion: protocol})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTransferTestResource(t, session) })
	return session
}

func callTunnelList(t *testing.T, client *mcp.ClientSession, input ListTunnelsInput) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "xops_tunnel_list", Arguments: input})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func decodeTunnelList(t *testing.T, result *mcp.CallToolResult) []tunnel.Status {
	t.Helper()
	if result.IsError {
		t.Fatalf("list failed: %+v", result.Content)
	}
	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var out ListTunnelsOutput
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out.Tunnels
}

func assertTunnelListDenied(t *testing.T, result *mcp.CallToolResult, records []tunnel.Status) {
	t.Helper()
	if !result.IsError {
		t.Fatal("unfiltered list bypassed node approval")
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if strings.Contains(string(data), record.TunnelID) {
			t.Fatal("denied list disclosed a tunnel record")
		}
	}
}

func TestMCPTunnelUnfilteredListPolicies(t *testing.T) {
	for _, protocol := range []string{"2025-11-25", "2026-07-28"} {
		for _, action := range []string{"accept", "decline", "cancel", "unsupported"} {
			t.Run(protocol+"/"+action, func(t *testing.T) {
				r := tunnelListPolicyRuntime(t)
				records := []tunnel.Status{
					seedTunnelListTask(t, r, "node", "public"),
					seedTunnelListTask(t, r, "restricted-a", "first"),
					seedTunnelListTask(t, r, "restricted-a", "duplicate-node"),
					seedTunnelListTask(t, r, "restricted-b", "second-node"),
				}
				var approvals atomic.Int32
				opts := tunnelApprovalOptions(t, action, &approvals)
				if handler := opts.ElicitationHandler; handler != nil {
					opts.ElicitationHandler = func(ctx context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
						if !strings.Contains(req.Params.Message, "Nodes: node, restricted-a, restricted-b") {
							t.Error("approval did not name the distinct, sorted node set")
						}
						return handler(ctx, req)
					}
				}
				client := tunnelListPolicyClient(t, r, protocol, opts)
				result := callTunnelList(t, client, ListTunnelsInput{})
				if action != "accept" {
					assertTunnelListDenied(t, result, records)
					return
				}
				if got := decodeTunnelList(t, result); len(got) != len(records) {
					t.Fatalf("returned %d records, want %d", len(got), len(records))
				}
				if approvals.Load() != 1 {
					t.Fatalf("approvals = %d, want one batch approval", approvals.Load())
				}
			})
		}
	}
}

func TestMCPTunnelListPolicyMatchesFilters(t *testing.T) {
	for _, protocol := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(protocol, func(t *testing.T) {
			r := tunnelListPolicyRuntime(t)
			public := seedTunnelListTask(t, r, "node", "public")
			private := seedTunnelListTask(t, r, "restricted-a", "private")
			if _, err := r.tunnels.Stop(t.Context(), public.TunnelID); err != nil {
				t.Fatal(err)
			}
			client := tunnelListPolicyClient(t, r, protocol, nil)
			for _, tc := range []struct {
				input  ListTunnelsInput
				denied bool
				count  int
			}{
				{ListTunnelsInput{}, true, 0},
				{ListTunnelsInput{State: "running"}, true, 0},
				{ListTunnelsInput{State: "stopped"}, false, 1},
				{ListTunnelsInput{State: "failed"}, false, 0},
				{ListTunnelsInput{NodeID: "alias"}, false, 1},
				{ListTunnelsInput{NodeID: "restricted-a"}, true, 0},
				{ListTunnelsInput{NodeID: "restricted-a", State: "stopped"}, true, 0},
			} {
				result := callTunnelList(t, client, tc.input)
				if tc.denied {
					assertTunnelListDenied(t, result, []tunnel.Status{public, private})
					continue
				}
				if got := decodeTunnelList(t, result); len(got) != tc.count {
					t.Fatalf("filter %+v returned %d records, want %d", tc.input, len(got), tc.count)
				}
			}
		})
	}
}

func TestMCPTunnelListGlobalThresholdWithWildcard(t *testing.T) {
	for _, protocol := range []string{"2025-11-25", "2026-07-28"} {
		for _, action := range []string{"accept", "decline", "cancel", "unsupported"} {
			t.Run(protocol+"/"+action, func(t *testing.T) {
				r := tunnelListRuntimeWithPolicy(t, &config.GuardrailConfig{
					Enabled: true, ApprovalThreshold: "safe", NoElicitFallback: guardrail.FallbackDeny,
					NodeOverrides: map[string]config.NodeGuardrailCfg{"*": {ApprovalThreshold: "dangerous"}},
				})
				record := seedTunnelListTask(t, r, "node", "wildcard")
				var approvals atomic.Int32
				client := tunnelListPolicyClient(t, r, protocol, tunnelApprovalOptions(t, action, &approvals))
				filtered := decodeTunnelList(t, callTunnelList(t, client, ListTunnelsInput{NodeID: "alias"}))
				if len(filtered) != 1 || filtered[0].TunnelID != record.TunnelID || approvals.Load() != 0 {
					t.Fatal("explicit node filter did not retain its override")
				}
				for _, input := range []ListTunnelsInput{{}, {State: "failed"}} {
					result := callTunnelList(t, client, input)
					if action != "accept" {
						assertTunnelListDenied(t, result, []tunnel.Status{record})
						continue
					}
					want := 1
					if input.State != "" {
						want = 0
					}
					if got := decodeTunnelList(t, result); len(got) != want {
						t.Fatalf("list length = %d, want %d", len(got), want)
					}
				}
				if action == "accept" && approvals.Load() != 2 {
					t.Fatalf("approvals = %d, want 2", approvals.Load())
				}
			})
		}
	}
}

func TestMCPTunnelListApprovalNodeSetChange(t *testing.T) {
	for _, protocol := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(protocol, func(t *testing.T) {
			r := tunnelListPolicyRuntime(t)
			initial := seedTunnelListTask(t, r, "restricted-a", "initial")
			var added atomic.Pointer[tunnel.Status]
			opts := &mcp.ClientOptions{ElicitationHandler: func(ctx context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				if added.Load() == nil {
					s, err := r.tunnels.Create(ctx, tunnel.Spec{RequestID: "during-approval", NodeID: "restricted-c", Mode: "local", TargetHost: "127.0.0.1", TargetPort: 1}, "fixture-seed")
					if err != nil {
						return nil, fmt.Errorf("create concurrent fixture tunnel: %w", err)
					}
					if s.State != "running" {
						return nil, fmt.Errorf("concurrent fixture tunnel state=%s: %s", s.State, s.Error)
					}
					added.Store(&s)
				}
				return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approved": true}}, nil
			}}
			client := tunnelListPolicyClient(t, r, protocol, opts)
			result := callTunnelList(t, client, ListTunnelsInput{})
			created := added.Load()
			if created == nil {
				t.Fatal("approval was not requested")
			}
			if protocol == "2025-11-25" {
				got := decodeTunnelList(t, result)
				if len(got) != 1 || got[0].TunnelID != initial.TunnelID {
					t.Fatal("list refreshed to include a node outside the approved snapshot")
				}
			} else {
				// A modern continuation must not reuse approval for a changed
				// node set, even when both sets require the same risk level.
				assertTunnelListDenied(t, result, []tunnel.Status{initial, *created})
			}
			fresh := decodeTunnelList(t, callTunnelList(t, client, ListTunnelsInput{}))
			if len(fresh) != 2 || !slices.ContainsFunc(fresh, func(s tunnel.Status) bool { return s.TunnelID == created.TunnelID }) {
				t.Fatalf("fresh approval did not include new node: %+v", fresh)
			}
		})
	}
}
