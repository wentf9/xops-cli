package guardrail

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/core/mcp/policy"
)

type pendingApproval struct {
	session        *mcp.ServerSession
	digest         [32]byte
	envelopeDigest [32]byte
	ri             RiskInput
	expires        time.Time
}

func cloneRiskInput(ri RiskInput) RiskInput {
	ri.NodeIDs = slices.Clone(ri.NodeIDs)
	ri.Paths = slices.Clone(ri.Paths)
	ri.RecursivePaths = slices.Clone(ri.RecursivePaths)
	if ri.Execution != nil {
		ri.Execution = ri.Execution.Clone()
	}
	return ri
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

func (g *Guardrail) approvalEnvelopeDigest(ctx context.Context, ri RiskInput, input any) ([32]byte, error) {
	if env, ok := requestEnvelopeFromContext(ctx); ok {
		var cfg policy.Config
		if pol, _, _ := g.invocation(ctx); pol != nil && pol.cfg != nil {
			cfg = policy.Clone(*pol.cfg)
			cfg.AuditLog = ""
		}
		data, err := json.Marshal(struct {
			HasEnvelope bool
			ToolName    string
			Action      string
			NodeID      string
			Envelope    any
			Policy      policy.Config
		}{true, ri.ToolName, ri.Action, ri.NodeID, env, cfg})
		if err != nil {
			return [32]byte{}, fmt.Errorf("bind approval envelope: %w", err)
		}
		return sha256.Sum256(data), nil
	}
	_, _, binding := g.invocation(ctx)
	data, err := json.Marshal(struct {
		HasEnvelope bool
		ToolName    string
		Action      string
		NodeID      string
		Input       any
		Binding     string
	}{false, ri.ToolName, ri.Action, ri.NodeID, input, binding})
	if err != nil {
		return [32]byte{}, fmt.Errorf("bind approval envelope: %w", err)
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
	envDigest, err := g.approvalEnvelopeDigest(ctx, ri, input)
	if err != nil {
		return err
	}
	_, err = g.advanceApproval(ctx, req, risk, ri, digest, envDigest)
	return err
}

func supportsFormElicitation(init *mcp.InitializeParams) bool {
	return init != nil &&
		init.Capabilities != nil &&
		init.Capabilities.Elicitation != nil &&
		(init.Capabilities.Elicitation.Form != nil || init.Capabilities.Elicitation.URL == nil)
}

// IsApprovedRoundTripResponse reports whether req carries a syntactically valid
// single-entry form-elicitation response explicitly approving the operation.
// It does not inspect or mutate pending challenge state.
func (g *Guardrail) IsApprovedRoundTripResponse(req *mcp.CallToolRequest) bool {
	if req == nil || req.Params == nil || req.Params.RequestState == "" || len(req.Params.InputResponses) != 1 {
		return false
	}
	response, ok := req.Params.InputResponses["approval"].(*mcp.ElicitResult)
	if !ok {
		return false
	}
	return interpretApproval(response) == nil
}

// HasActivePendingApprovalForEnvelope reports whether req carries a non-expired
// pending two-step approval challenge belonging to req.Session AND bound to the
// exact pre-inspection request envelope derived from (ctx, ri, input). It does
// not mutate pending state.
func (g *Guardrail) HasActivePendingApprovalForEnvelope(ctx context.Context, req *mcp.CallToolRequest, ri RiskInput, input any) (bool, error) {
	if g == nil || req == nil || req.Session == nil || req.Params == nil || req.Params.RequestState == "" {
		return false, nil
	}
	envDigest, err := g.approvalEnvelopeDigest(ctx, ri, input)
	if err != nil {
		return false, err
	}
	now := time.Now()
	g.approvalMu.Lock()
	defer g.approvalMu.Unlock()
	pending, ok := g.pendingApprovals[req.Params.RequestState]
	return ok && now.Before(pending.expires) && pending.session == req.Session && pending.envelopeDigest == envDigest, nil
}

// HasMatchingPendingApproval reports whether req carries a non-expired
// two-step approval challenge bound to the exact session, risk, context,
// complete input, envelope, and policy binding. It does not mutate pending state.
func (g *Guardrail) HasMatchingPendingApproval(ctx context.Context, req *mcp.CallToolRequest, ri RiskInput, input any) (bool, error) {
	if g == nil || req == nil || req.Session == nil || req.Params == nil || req.Params.RequestState == "" {
		return false, nil
	}
	_, _, binding := g.invocation(ctx)
	digest, err := approvalBindingDigest(Classify(ri), ri, input, binding)
	if err != nil {
		return false, err
	}
	envDigest, err := g.approvalEnvelopeDigest(ctx, ri, input)
	if err != nil {
		return false, err
	}
	now := time.Now()
	g.approvalMu.Lock()
	defer g.approvalMu.Unlock()
	pending, ok := g.pendingApprovals[req.Params.RequestState]
	return ok && now.Before(pending.expires) && pending.session == req.Session && pending.digest == digest && pending.envelopeDigest == envDigest, nil
}

// ConsumeDeclinedPendingApproval consumes a pending two-step approval challenge
// matching req.Session and the request envelope when the client returned a
// declined, cancelled, or malformed InputResponses payload, and audits "denied"
// using the challenge's bound RiskInput without performing any remote inspection.
func (g *Guardrail) ConsumeDeclinedPendingApproval(ctx context.Context, req *mcp.CallToolRequest, ri RiskInput, input any) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("approval cancelled: %w", err)
	}
	if g == nil {
		return errors.New("guardrail: operation denied — guardrail is not configured")
	}
	if req == nil || req.Session == nil || req.Params == nil {
		return errors.New("approval challenge invalid, expired, or does not match operation")
	}
	envDigest, err := g.approvalEnvelopeDigest(ctx, ri, input)
	if err != nil {
		return err
	}
	token := req.Params.RequestState
	now := time.Now()
	var cause error
	auditRI := ri

	g.approvalMu.Lock()
	pending, ok := g.pendingApprovals[token]
	switch {
	case !ok:
		cause = errors.New("approval challenge invalid, expired, or does not match operation")
	case !now.Before(pending.expires):
		delete(g.pendingApprovals, token)
		cause = errors.New("approval challenge expired; operation denied")
	case pending.session != req.Session || pending.envelopeDigest != envDigest:
		cause = errors.New("approval challenge invalid, expired, or does not match operation")
	default:
		if pending.ri.ToolName != "" {
			auditRI = cloneRiskInput(pending.ri)
		}
		delete(g.pendingApprovals, token)
	}
	g.approvalMu.Unlock()

	if cause == nil {
		response, respOK := req.Params.InputResponses["approval"].(*mcp.ElicitResult)
		if !respOK || len(req.Params.InputResponses) != 1 {
			cause = errors.New("invalid approval response")
		} else {
			cause = interpretApproval(response)
			if cause == nil {
				cause = errors.New("guardrail: approval was not explicitly granted")
			}
		}
	}

	opID, idErr := generateOperationID()
	if idErr != nil {
		return errors.Join(cause, idErr)
	}
	entry := AuditEntry{
		OperationID: opID,
		Tool:        auditRI.ToolName,
		NodeID:      auditRI.NodeID,
		NodeIDs:     auditRI.NodeIDs,
		Paths:       auditRI.Paths,
		Command:     auditRI.Command,
		Details:     auditRI.Details,
		RiskLevel:   Classify(auditRI).String(),
		Decision:    g.evaluateDecision(ctx, auditRI).String(),
		Outcome:     "denied",
		Error:       cause.Error(),
	}
	return errors.Join(cause, g.log(ctx, entry))
}

// RetirePendingApproval atomically consumes req's pending lexical approval
// challenge bound to (ri, input) under ctx WITHOUT recording an "authorized"
// audit entry. It is used when canonical path inspection escalates risk or
// denies the request so the superseded Round-1 token cannot be replayed and no
// orphaned "authorized" audit record is created.
func (g *Guardrail) RetirePendingApproval(ctx context.Context, req *mcp.CallToolRequest, ri RiskInput, input any) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("approval cancelled: %w", err)
	}
	if g == nil {
		return errors.New("guardrail: operation denied — guardrail is not configured")
	}
	if req == nil || req.Session == nil || req.Params == nil || req.Params.RequestState == "" {
		return errors.New("approval challenge invalid, expired, or does not match operation")
	}
	_, _, binding := g.invocation(ctx)
	digest, err := approvalBindingDigest(Classify(ri), ri, input, binding)
	if err != nil {
		return err
	}
	envDigest, err := g.approvalEnvelopeDigest(ctx, ri, input)
	if err != nil {
		return err
	}
	token := req.Params.RequestState
	now := time.Now()
	g.approvalMu.Lock()
	pending, ok := g.pendingApprovals[token]
	if ok && !now.Before(pending.expires) {
		delete(g.pendingApprovals, token)
		g.approvalMu.Unlock()
		return errors.New("approval challenge expired; operation denied")
	}
	if !ok || pending.session != req.Session || pending.digest != digest || pending.envelopeDigest != envDigest {
		g.approvalMu.Unlock()
		return errors.New("approval challenge invalid, expired, or does not match operation")
	}
	delete(g.pendingApprovals, token)
	g.approvalMu.Unlock()
	return nil
}

// InvalidatePendingApproval deletes req's pending approval challenge if owned
// by req.Session and records a terminal audit entry ("error" or "denied") so a
// failed pre-authorization inspection cannot leave a Round-2 token replayable
// as an SFTP error oracle.
func (g *Guardrail) InvalidatePendingApproval(ctx context.Context, req *mcp.CallToolRequest, ri RiskInput, outcome string, cause error) error {
	if g == nil {
		return cause
	}
	auditRI := ri
	if req != nil && req.Session != nil && req.Params != nil && req.Params.RequestState != "" {
		token := req.Params.RequestState
		g.approvalMu.Lock()
		if pending, ok := g.pendingApprovals[token]; ok && pending.session == req.Session {
			if pending.ri.ToolName != "" {
				auditRI = cloneRiskInput(pending.ri)
			}
			delete(g.pendingApprovals, token)
		}
		g.approvalMu.Unlock()
	}
	if outcome == "" {
		outcome = "error"
	}
	opID, idErr := generateOperationID()
	if idErr != nil {
		return errors.Join(cause, idErr)
	}
	entry := AuditEntry{
		OperationID: opID,
		Tool:        auditRI.ToolName,
		NodeID:      auditRI.NodeID,
		NodeIDs:     auditRI.NodeIDs,
		Paths:       auditRI.Paths,
		Command:     auditRI.Command,
		Details:     auditRI.Details,
		RiskLevel:   Classify(auditRI).String(),
		Decision:    g.evaluateDecision(ctx, auditRI).String(),
		Outcome:     outcome,
	}
	if cause != nil {
		entry.Error = cause.Error()
	}
	if auditErr := g.logOutcome(ctx, entry); auditErr != nil {
		return errors.Join(cause, fmt.Errorf("audit invalidated approval failed: %w", auditErr))
	}
	return cause
}

// ConsumePendingApprovalForScope validates and consumes req's pending two-step
// approval challenge bound to (pendingRI, pendingInput) under pendingCtx, then
// records a single "authorized" audit entry using auditCtx and auditRI (the
// canonical resolved scope). Used by two-phase handlers when a Round-1 lexical
// approval safely covers the canonical scope without risk escalation.
func (g *Guardrail) ConsumePendingApprovalForScope(
	pendingCtx context.Context,
	req *mcp.CallToolRequest,
	pendingRI RiskInput,
	pendingInput any,
	auditCtx context.Context,
	auditRI RiskInput,
) (string, error) {
	if err := auditCtx.Err(); err != nil {
		return "", fmt.Errorf("authorize operation: %w", err)
	}
	if g == nil {
		return "", errors.New("guardrail: deferred operation denied — guardrail is not configured")
	}
	opID, err := generateOperationID()
	if err != nil {
		return "", err
	}
	risk := Classify(auditRI)
	decision := g.evaluateDecision(auditCtx, auditRI)
	entry := AuditEntry{
		OperationID: opID,
		Tool:        auditRI.ToolName,
		NodeID:      auditRI.NodeID,
		NodeIDs:     auditRI.NodeIDs,
		Paths:       auditRI.Paths,
		Command:     auditRI.Command,
		Details:     auditRI.Details,
		RiskLevel:   risk.String(),
		Decision:    decision.String(),
	}
	if decision == Deny {
		_ = g.RetirePendingApproval(pendingCtx, req, pendingRI, pendingInput)
		entry.Outcome = "denied"
		return "", errors.Join(errors.New("guardrail: deferred operation denied by policy"), g.log(auditCtx, entry))
	}
	if approveErr := g.consumeApprovalResponse(pendingCtx, req, Classify(pendingRI), pendingRI, pendingInput); approveErr != nil {
		entry.Outcome, entry.Error = "denied", approveErr.Error()
		return "", errors.Join(approveErr, g.log(auditCtx, entry))
	}
	entry.Decision = "approved"
	entry.Outcome = "authorized"
	if err := g.log(auditCtx, entry); err != nil {
		return "", fmt.Errorf("audit deferred authorization: %w", err)
	}
	return opID, nil
}

// requestToolApproval binds a single-use challenge to the full typed input,
// tool, risk, request envelope, and session. No remote effect happens before it is consumed.
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
		if hasApprovalRoundTripParams(req) {
			return nil, g.consumeApprovalResponse(ctx, req, risk, ri, input)
		}
		return nil, RequestApproval(ctx, req.Session, risk, ri, fallback)
	}
	if !supportsFormElicitation(init) {
		if hasApprovalRoundTripParams(req) {
			return nil, g.consumeApprovalResponse(ctx, req, risk, ri, input)
		}
		return nil, applyFallback(fmt.Errorf("client does not support form approval"), risk, fallback)
	}
	if req.Params == nil {
		return nil, fmt.Errorf("approval tool parameters unavailable")
	}
	digest, err := approvalBindingDigest(risk, ri, input, binding)
	if err != nil {
		return nil, err
	}
	envDigest, err := g.approvalEnvelopeDigest(ctx, ri, input)
	if err != nil {
		return nil, err
	}
	return g.advanceApproval(ctx, req, risk, ri, digest, envDigest)
}

// advanceApproval owns the bounded challenge state; policy and capability
// checks have already completed before acquiring its lock.
func (g *Guardrail) advanceApproval(ctx context.Context, req *mcp.CallToolRequest, risk RiskLevel, ri RiskInput, digest, envDigest [32]byte) (*mcp.CallToolResult, error) {
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
		if !ok || pending.session != req.Session || pending.digest != digest || pending.envelopeDigest != envDigest {
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
	g.pendingApprovals[token] = pendingApproval{
		session:        req.Session,
		digest:         digest,
		envelopeDigest: envDigest,
		ri:             cloneRiskInput(ri),
		expires:        expires,
	}
	return &mcp.CallToolResult{InputRequests: mcp.InputRequestMap{"approval": approvalParams(risk, ri)}, RequestState: token}, nil
}
