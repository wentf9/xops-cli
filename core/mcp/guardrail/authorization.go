package guardrail

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Evaluate checks policy without executing an operation or requesting approval.
// It allows callers to reject a forbidden path before resolving remote metadata.
func (g *Guardrail) Evaluate(input RiskInput) Decision {
	return g.policy.Evaluate(Classify(input), input)
}

// Authorize prepares a deferred operation. It intentionally does not report
// executed: the caller must audit actual streaming and commit with the returned
// operation ID. Complete typed input is bound by the existing approval flow.
func (g *Guardrail) Authorize(ctx context.Context, req *mcp.CallToolRequest, input RiskInput, completeInput any) (string, *mcp.CallToolResult, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, fmt.Errorf("authorize operation: %w", err)
	}
	opID, err := generateOperationID()
	if err != nil {
		return "", nil, err
	}
	risk := Classify(input)
	decision := g.EvaluateContext(ctx, input)
	entry := AuditEntry{OperationID: opID, Tool: input.ToolName, NodeID: input.NodeID, NodeIDs: input.NodeIDs, Paths: input.Paths,
		Command: input.Command, Details: input.Details, RiskLevel: risk.String(), Decision: decision.String()}
	if decision == Deny {
		entry.Outcome = "denied"
		return "", nil, errors.Join(errors.New("guardrail: deferred operation denied by policy"), g.log(ctx, entry))
	}
	if decision == NeedApproval {
		pending, approveErr := g.requestToolApproval(ctx, req, risk, input, completeInput)
		if approveErr != nil {
			entry.Outcome, entry.Error = "denied", approveErr.Error()
			return "", nil, errors.Join(approveErr, g.log(ctx, entry))
		}
		if pending != nil {
			entry.Outcome = "approval_requested"
			if err := g.log(ctx, entry); err != nil {
				return "", nil, fmt.Errorf("audit deferred approval: %w", err)
			}
			return "", pending, nil
		}
		entry.Decision = "approved"
	}
	entry.Outcome = "authorized"
	if err := g.log(ctx, entry); err != nil {
		return "", nil, fmt.Errorf("audit deferred authorization: %w", err)
	}
	return opID, nil, nil
}

// RecordAuthorized records a phase of an already-authorized immutable task.
// It grants no permissions and is not a replacement for Authorize.
func (g *Guardrail) RecordAuthorized(operationID string, input RiskInput, outcome string, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return g.RecordAuthorizedContext(ctx, operationID, input, outcome, cause)
}

// RecordAuthorizedContext records a bounded phase without granting permission.
func (g *Guardrail) RecordAuthorizedContext(ctx context.Context, operationID string, input RiskInput, outcome string, cause error) error {
	entry := AuditEntry{OperationID: operationID, Tool: input.ToolName, NodeID: input.NodeID, NodeIDs: input.NodeIDs, Paths: input.Paths,
		RiskLevel: Classify(input).String(), Details: input.Details, Decision: "authorized", Outcome: outcome}
	if cause != nil {
		entry.Error = cause.Error()
	}
	if err := g.log(ctx, entry); err != nil {
		return fmt.Errorf("audit deferred operation phase %s: %w", outcome, err)
	}
	return nil
}
