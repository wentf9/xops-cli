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

type requestEnvelopeBox struct {
	envelope any
}
type requestEnvelopeKey struct{}

// WithPolicy binds a defensive policy and operation identity to one invocation.
// Approval state stays owned by the original Guardrail across round trips.
func WithPolicy(ctx context.Context, cfg policy.Config, binding string) context.Context {
	return context.WithValue(ctx, invocationPolicyKey{}, invocationPolicy{policy.Clone(cfg), binding})
}

// WithRequestEnvelope attaches a pre-inspection canonical request identity to
// ctx so two-phase tools bind pending approval challenges to the exact request
// envelope invariant across Round 1 and Round 2 (tool, action, node, raw input,
// and snapshot/policy identity).
func WithRequestEnvelope(ctx context.Context, envelope any) context.Context {
	return context.WithValue(ctx, requestEnvelopeKey{}, requestEnvelopeBox{envelope: envelope})
}

func requestEnvelopeFromContext(ctx context.Context) (any, bool) {
	if ctx == nil {
		return nil, false
	}
	box, ok := ctx.Value(requestEnvelopeKey{}).(requestEnvelopeBox)
	return box.envelope, ok
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

// HasProtectedPath reports whether input.Paths or input.RecursivePaths matches
// any built-in sensitive path or configured ProtectedPaths under the policy
// active in ctx. When policy is disabled it returns false; when policy is nil
// it fails closed and returns true.
func (g *Guardrail) HasProtectedPath(ctx context.Context, input RiskInput) bool {
	if g == nil {
		return true
	}
	pol, _, _ := g.invocation(ctx)
	if pol == nil || pol.cfg == nil {
		return true
	}
	if pol.cfg.Disabled {
		return false
	}
	return pol.isPathProtected(input.Paths, input.RecursivePaths) ||
		AnalyzePaths(input.Paths) >= Moderate ||
		AnalyzeRecursivePaths(input.RecursivePaths) >= Moderate
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
