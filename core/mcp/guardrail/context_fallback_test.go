package guardrail

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/policy"
)

func TestUpdatedPolicyFallbackDoesNotInheritStartupOptIn(t *testing.T) {
	for _, protocol := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			ct, st := mcp.NewInMemoryTransports()
			server := mcp.NewServer(&mcp.Implementation{Name: "fallback-test", Version: "1"}, nil)
			ss, err := server.Connect(ctx, st, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := ss.Close(); err != nil {
					t.Error(err)
				}
			}()
			client := mcp.NewClient(&mcp.Implementation{Name: "without-elicitation", Version: "1"}, nil)
			cs, err := client.Connect(ctx, ct, &mcp.ClientSessionOptions{ProtocolVersion: protocol})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := cs.Close(); err != nil {
					t.Error(err)
				}
			}()
			for _, startup := range []string{FallbackAllow, FallbackDeny} {
				g := NewWithAuditSink(&policy.Config{Enabled: true, ApprovalThreshold: "safe", NoElicitFallback: startup}, &contextualAudit{})
				for _, current := range []string{"", FallbackAllow, FallbackDeny, FallbackDowngrade} {
					for _, dangerous := range []bool{false, true} {
						tool := "xops_write_file"
						if dangerous {
							tool = "xops_ssh_run"
						}
						ri := RiskInput{ToolName: tool, Command: "rm -rf /var/tmp/fixture", Paths: []string{"/var/tmp/fixture"}}
						executed := false
						wrapped := WithGuardrail(g, tool, func(struct{}) RiskInput { return ri }, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
							executed = true
							return nil, struct{}{}, nil
						})
						work := WithPolicy(ctx, policy.Config{Enabled: true, ApprovalThreshold: "safe", NoElicitFallback: current}, "current-policy")
						_, _, err := wrapped(work, &mcp.CallToolRequest{Session: ss, Params: &mcp.CallToolParamsRaw{}}, struct{}{})
						allowed := current == FallbackAllow || !dangerous && (current == "" || current == FallbackDowngrade)
						if executed != allowed || (err == nil) != allowed {
							t.Errorf("startup=%q current=%q dangerous=%v: executed=%v error=%v", startup, current, dangerous, executed, err)
						}
					}
				}
			}
		})
	}
}
