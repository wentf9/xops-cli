package guardrail

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/policy"
)

type contextualAudit struct {
	mu      sync.Mutex
	entries []AuditEntry
}

func (a *contextualAudit) Append(ctx context.Context, entry AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, entry)
	return nil
}

func TestInvocationPoliciesAreIndependentDefensiveViews(t *testing.T) {
	g := New(nil)
	allowed := policy.Config{Enabled: false, BlockedPatterns: []string{"forbidden"}}
	first := WithPolicy(t.Context(), allowed, "first")
	allowed.Enabled = true
	allowed.BlockedPatterns[0] = "*"
	second := WithPolicy(t.Context(), allowed, "second")
	risk := RiskInput{ToolName: "xops_ssh_run", Command: "hostname"}
	if g.EvaluateContext(first, risk) != Allow || g.EvaluateContext(second, risk) != Deny {
		t.Fatal("policy snapshots contaminated one another")
	}
}

func TestOutcomeAuditSurvivesRequestCancellation(t *testing.T) {
	audit := &contextualAudit{}
	g := NewWithAuditSink(&policy.Config{Enabled: false}, audit)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	ctx = WithPolicy(ctx, policy.Config{Enabled: false}, "bound-target")
	handler := WithGuardrail(g, "xops_list_nodes", func(struct{}) RiskInput { return RiskInput{} },
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
			cancel()
			return nil, struct{}{}, nil
		})
	if _, _, err := handler(ctx, nil, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if len(audit.entries) != 2 || audit.entries[1].Outcome != "executed" || audit.entries[1].Binding != "bound-target" {
		t.Fatal("cancelled caller lost execution audit or binding")
	}
}

type failingContextAudit struct{ err error }

func (a failingContextAudit) Append(context.Context, AuditEntry) error { return a.err }

func TestIntentAuditFailurePreventsExecution(t *testing.T) {
	marker := errors.New("audit unavailable")
	g := NewWithAuditSink(&policy.Config{Enabled: false}, failingContextAudit{marker})
	executed := false
	handler := WithGuardrail(g, "xops_list_nodes", func(struct{}) RiskInput { return RiskInput{} },
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, struct{}, error) {
			executed = true
			return nil, struct{}{}, nil
		})
	_, _, err := handler(t.Context(), nil, struct{}{})
	if !errors.Is(err, marker) || executed {
		t.Fatal("execution bypassed a failed intent audit")
	}
}
