package guardrail

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Fallback policies when client does not support Elicitation.
const (
	FallbackDeny      = "deny"      // reject everything that needs approval
	FallbackAllow     = "allow"     // allow all, rely on client-side tool approval
	FallbackDowngrade = "downgrade" // allow moderate ops, still deny dangerous
)

// RequestApproval sends an Elicitation request to the MCP client, asking the
// user to approve a dangerous operation.
//
// If the client does not support Elicitation, it falls back to the configured
// policy (deny / allow / downgrade).
func RequestApproval(ctx context.Context, session *mcp.ServerSession, risk RiskLevel, input RiskInput, fallback string) error {
	if session == nil {
		return fmt.Errorf("guardrail: no session available, cannot request approval")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("guardrail: approval cancelled: %w", err)
	}
	initialized := session.InitializeParams()
	if initialized == nil {
		return fmt.Errorf("guardrail: approval session is not initialized")
	}
	if initialized.Capabilities == nil || initialized.Capabilities.Elicitation == nil ||
		(initialized.Capabilities.Elicitation.Form == nil && initialized.Capabilities.Elicitation.URL != nil) {
		return applyFallback(fmt.Errorf("client does not support form approval"), risk, fallback)
	}
	approvalCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	result, err := session.Elicit(approvalCtx, approvalParams(risk, input))
	if err != nil {
		var rpcErr *jsonrpc.Error
		if approvalCtx.Err() == nil && errors.As(err, &rpcErr) && rpcErr.Code == jsonrpc.CodeMethodNotFound {
			return applyFallback(err, risk, fallback)
		}
		return fmt.Errorf("guardrail: approval request failed (operation denied): %w", err)
	}
	return interpretApproval(result)
}

func approvalParams(risk RiskLevel, input RiskInput) *mcp.ElicitParams {
	return &mcp.ElicitParams{Mode: "form", Message: buildApprovalMessage(risk, input), RequestedSchema: map[string]any{
		"type": "object", "properties": map[string]any{"approved": map[string]any{"type": "boolean", "title": "Approve this operation", "default": false}}, "required": []string{"approved"},
	}}
}

func interpretApproval(result *mcp.ElicitResult) error {
	if result == nil {
		return fmt.Errorf("guardrail: empty approval response, denying")
	}
	switch result.Action {
	case "accept":
		if approved, ok := result.Content["approved"].(bool); ok && approved {
			return nil
		}
		return fmt.Errorf("guardrail: approval was not explicitly granted")
	case "decline":
		return fmt.Errorf("guardrail: operation explicitly declined by user")
	case "cancel":
		return fmt.Errorf("guardrail: operation cancelled by user")
	default:
		return fmt.Errorf("guardrail: unexpected approval response %q, denying", result.Action)
	}
}

// applyFallback decides what to do when Elicitation is not available.
func applyFallback(elicitErr error, risk RiskLevel, fallback string) error {
	switch fallback {
	case FallbackAllow:
		return nil
	case FallbackDowngrade:
		if risk < Dangerous {
			return nil
		}
		return fmt.Errorf("guardrail: dangerous operation denied — client does not support approval and fallback is %q: %w", fallback, elicitErr)
	default: // "deny" or unrecognized
		return fmt.Errorf("guardrail: approval request failed (operation denied): %w", elicitErr)
	}
}

func buildApprovalMessage(risk RiskLevel, input RiskInput) string {
	var b strings.Builder
	fmt.Fprintf(&b, "⚠️ [Risk: %s] Operation requires your approval\n\n", strings.ToUpper(risk.String()))
	fmt.Fprintf(&b, "Tool:  %s\n", input.ToolName)
	if input.NodeID != "" {
		fmt.Fprintf(&b, "Node:  %s\n", input.NodeID)
	}
	if input.Command != "" {
		fmt.Fprintf(&b, "Command: %s\n", input.Command)
	}
	if input.Sudo {
		b.WriteString("Sudo: yes\n")
	}
	if len(input.Paths) > 0 {
		fmt.Fprintf(&b, "Paths: %s\n", strings.Join(input.Paths, ", "))
	}
	b.WriteString("\nDo you approve this operation?")
	return b.String()
}
