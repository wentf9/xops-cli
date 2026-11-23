package guardrail

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type pendingApproval struct {
	session *mcp.ServerSession
	digest  [32]byte
	expires time.Time
}

func hasApprovalRoundTripParams(req *mcp.CallToolRequest) bool {
	return req != nil && req.Params != nil && (req.Params.RequestState != "" || len(req.Params.InputResponses) > 0)
}

func approvalBindingDigest(risk RiskLevel, ri RiskInput, input any, binding string) ([32]byte, error) {
	data, err := json.Marshal(struct {
		Risk    RiskLevel
		Context RiskInput
		Input   any
		Binding string
	}{risk, ri, input, binding})
	if err != nil {
		return [32]byte{}, fmt.Errorf("bind approval input: %w", err)
	}
	return sha256.Sum256(data), nil
}

// consumeApprovalResponse validates and consumes two-step approval round-trip
// state carried on a request even when policy currently evaluates to Allow.
func (g *Guardrail) consumeApprovalResponse(ctx context.Context, req *mcp.CallToolRequest, risk RiskLevel, ri RiskInput, input any) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("approval cancelled: %w", err)
	}
	if req == nil || req.Session == nil {
		return fmt.Errorf("approval session unavailable")
	}
	if req.Params == nil {
		return fmt.Errorf("approval tool parameters unavailable")
	}
	_, _, binding := g.invocation(ctx)
	digest, err := approvalBindingDigest(risk, ri, input, binding)
	if err != nil {
		return err
	}
	_, err = g.advanceApproval(ctx, req, risk, ri, digest)
	return err
}

// requestToolApproval binds a single-use challenge to the full typed input,
// tool, risk and session. No remote effect happens before it is consumed.
func (g *Guardrail) requestToolApproval(ctx context.Context, req *mcp.CallToolRequest, risk RiskLevel, ri RiskInput, input any) (*mcp.CallToolResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("approval cancelled: %w", err)
	}
	if req == nil || req.Session == nil {
		return nil, fmt.Errorf("approval session unavailable")
	}
	_, fallback, binding := g.invocation(ctx)
	init := req.Session.InitializeParams()
	if init == nil || init.ProtocolVersion < "2026-07-28" {
		return nil, RequestApproval(ctx, req.Session, risk, ri, fallback)
	}
	if init.Capabilities == nil || init.Capabilities.Elicitation == nil || (init.Capabilities.Elicitation.Form == nil && init.Capabilities.Elicitation.URL != nil) {
		return nil, applyFallback(fmt.Errorf("client does not support form approval"), risk, fallback)
	}
	if req.Params == nil {
		return nil, fmt.Errorf("approval tool parameters unavailable")
	}
	digest, err := approvalBindingDigest(risk, ri, input, binding)
	if err != nil {
		return nil, err
	}
	return g.advanceApproval(ctx, req, risk, ri, digest)
}

// advanceApproval owns the bounded challenge state; policy and capability
// checks have already completed before acquiring its lock.
func (g *Guardrail) advanceApproval(ctx context.Context, req *mcp.CallToolRequest, risk RiskLevel, ri RiskInput, digest [32]byte) (*mcp.CallToolResult, error) {
	now := time.Now()
	g.approvalMu.Lock()
	defer g.approvalMu.Unlock()
	if pending, ok := g.pendingApprovals[req.Params.RequestState]; ok && !now.Before(pending.expires) {
		delete(g.pendingApprovals, req.Params.RequestState)
		return nil, fmt.Errorf("approval challenge expired; operation denied")
	}
	for key, pending := range g.pendingApprovals {
		if !now.Before(pending.expires) {
			delete(g.pendingApprovals, key)
		}
	}
	if req.Params.RequestState != "" || len(req.Params.InputResponses) > 0 {
		token := req.Params.RequestState
		pending, ok := g.pendingApprovals[token]
		if !ok || pending.session != req.Session || pending.digest != digest {
			return nil, fmt.Errorf("approval challenge invalid, expired, or does not match operation")
		}
		delete(g.pendingApprovals, token)
		response, ok := req.Params.InputResponses["approval"].(*mcp.ElicitResult)
		if !ok || len(req.Params.InputResponses) != 1 {
			return nil, fmt.Errorf("invalid approval response")
		}
		return nil, interpretApproval(response)
	}
	if len(g.pendingApprovals) >= 256 {
		return nil, fmt.Errorf("too many pending approvals")
	}
	token, err := generateOperationID()
	if err != nil {
		return nil, err
	}
	if g.pendingApprovals == nil {
		g.pendingApprovals = make(map[string]pendingApproval)
	}
	expires := now.Add(2 * time.Minute)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	g.pendingApprovals[token] = pendingApproval{session: req.Session, digest: digest, expires: expires}
	return &mcp.CallToolResult{InputRequests: mcp.InputRequestMap{"approval": approvalParams(risk, ri)}, RequestState: token}, nil
}
