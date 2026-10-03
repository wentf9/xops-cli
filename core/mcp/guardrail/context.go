package guardrail

import (
	"context"
	"fmt"
	"time"

	"github.com/wentf9/xops-cli/core/mcp/policy"
)

// AuditSink is a host-owned, context-aware audit destination. Append must finish
// within its context and must never retry the remote operation being recorded.
type AuditSink interface {
	Append(context.Context, AuditEntry) error
}

type invocationPolicy struct {
	config  policy.Config
	binding string
}
type invocationPolicyKey struct{}

// WithPolicy binds a defensive policy and operation identity to one invocation.
// Approval state stays owned by the original Guardrail across round trips.
func WithPolicy(ctx context.Context, cfg policy.Config, binding string) context.Context {
	return context.WithValue(ctx, invocationPolicyKey{}, invocationPolicy{policy.Clone(cfg), binding})
}

// NewWithAuditSink borrows a host-owned audit sink; it does not close it or
// discover a file path. The runtime validates the sink before construction.
func NewWithAuditSink(cfg *policy.Config, sink AuditSink) *Guardrail {
	g := New(cfg)
	g.sink = sink
	return g
}

func (g *Guardrail) invocation(ctx context.Context) (*Policy, string, string) {
	if scoped, ok := ctx.Value(invocationPolicyKey{}).(invocationPolicy); ok {
		fallback := scoped.config.NoElicitFallback
		if fallback == "" {
			fallback = FallbackDowngrade
		}
		return NewPolicy(&scoped.config), fallback, scoped.binding
	}
	return g.policy, g.noElicitFallback, ""
}

func (g *Guardrail) EvaluateContext(ctx context.Context, input RiskInput) Decision {
	policy, _, _ := g.invocation(ctx)
	return policy.Evaluate(Classify(input), input)
}

func (g *Guardrail) log(ctx context.Context, entry AuditEntry) error {
	g.auditMu.RLock()
	sink, writer := g.sink, g.audit
	g.auditMu.RUnlock()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("append audit entry: %w", err)
	}
	_, _, entry.Binding = g.invocation(ctx)
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	if sink != nil {
		return sink.Append(ctx, entry)
	}
	if writer == nil {
		return fmt.Errorf("audit destination is not configured")
	}
	return writer.Log(entry)
}

func (g *Guardrail) logOutcome(ctx context.Context, entry AuditEntry) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return g.log(cleanup, entry)
}
