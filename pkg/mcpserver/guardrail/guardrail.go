package guardrail

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/wentf9/xops-cli/pkg/config"
)

const auditMetadataKey = "io.xops.audit"

// Guardrail coordinates risk classification, policy evaluation, approval,
// and audit logging for MCP tool invocations.
type Guardrail struct {
	policy           *Policy
	audit            AuditWriter
	noElicitFallback string
}

// New creates a Guardrail from configuration. If cfg is nil, defaults are used.
func New(cfg *config.GuardrailConfig) *Guardrail {
	if cfg == nil {
		cfg = DefaultGuardrailConfig()
	}
	fallback := cfg.NoElicitFallback
	if fallback == "" {
		fallback = FallbackDowngrade
	}
	return &Guardrail{
		policy:           NewPolicy(cfg),
		audit:            NewAuditLogger(cfg.AuditLog),
		noElicitFallback: fallback,
	}
}

// SetAuditWriter replaces the underlying AuditWriter (useful for testing or custom sinks).
func (g *Guardrail) SetAuditWriter(w AuditWriter) {
	if g != nil {
		g.audit = w
	}
}

func generateOperationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate operation id failed: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// WithGuardrail wraps any typed tool handler with the full guardrail pipeline:
// classify -> policy -> approval -> pre-audit intent -> execute -> post-audit result.
//
// riskInputFn extracts a RiskInput from the tool-specific input type.
func WithGuardrail[In, Out any](
	g *Guardrail,
	toolName string,
	riskInputFn func(In) RiskInput,
	handler mcp.ToolHandlerFor[In, Out],
) mcp.ToolHandlerFor[In, Out] {
	if g == nil {
		return handler
	}

	return func(ctx context.Context, req *mcp.CallToolRequest, input In) (*mcp.CallToolResult, Out, error) {
		var zero Out
		opID, idErr := generateOperationID()
		if idErr != nil {
			return nil, zero, fmt.Errorf("guardrail: %w", idErr)
		}

		ri := riskInputFn(input)
		ri.ToolName = toolName

		risk := Classify(ri)
		decision := g.policy.Evaluate(risk, ri)

		entry := AuditEntry{
			OperationID: opID,
			Tool:        toolName,
			NodeID:      ri.NodeID,
			Command:     ri.Command,
			Paths:       ri.Paths,
			RiskLevel:   risk.String(),
			Decision:    decision.String(),
		}

		switch decision {
		case Deny:
			entry.Outcome = "denied"
			denyErr := fmt.Errorf("guardrail: operation %s denied — blocked by security policy", opID)
			if auditErr := g.audit.Log(entry); auditErr != nil {
				return nil, zero, errors.Join(denyErr, fmt.Errorf("audit log failed: %w", auditErr))
			}
			return nil, zero, denyErr

		case NeedApproval:
			if err := RequestApproval(ctx, req.Session, risk, ri, g.noElicitFallback); err != nil {
				entry.Outcome = "denied"
				entry.Error = err.Error()
				if auditErr := g.audit.Log(entry); auditErr != nil {
					return nil, zero, errors.Join(err, fmt.Errorf("audit log failed: %w", auditErr))
				}
				return nil, zero, err
			}
			entry.Decision = "approved"
		}

		// 前置阶段：记录操作意图（Intent）。若审计强制且前置写入失败，直接拒绝执行，避免无审计操作。
		entry.Outcome = "intent"
		if auditErr := g.audit.Log(entry); auditErr != nil {
			return nil, zero, fmt.Errorf("guardrail: write intent audit log failed: %w", auditErr)
		}

		result, output, err := handler(ctx, req, input)

		// 后置阶段：更新最终执行结果
		entry.Outcome = "executed"
		if err != nil {
			entry.Outcome = "error"
			entry.Error = err.Error()
		}
		if postAuditErr := g.audit.Log(entry); postAuditErr != nil {
			if err != nil {
				return result, zero, errors.Join(err, fmt.Errorf("post-execution audit log failed: %w", postAuditErr))
			}
			// 操作已在目标节点成功执行。为了防止 MCP SDK 将其误判为失败并诱导客户端自动重试，
			// 我们返回成功结果并在 result 中附加不可重试的审计告警信息。
			if result == nil {
				result = &mcp.CallToolResult{}
			}
			if result.Meta == nil {
				result.Meta = make(mcp.Meta)
			}
			result.Meta[auditMetadataKey] = map[string]any{
				"operation_id": opID,
				"executed":     true,
				"audit_failed": true,
				"retryable":    false,
			}
			auditWarning := fmt.Sprintf("[WARNING: AUDIT_FAILED] Operation %s executed successfully, but post-execution audit log failed: %v. (DO NOT RETRY)", opID, postAuditErr)
			result.Content = append(result.Content, &mcp.TextContent{
				Text: auditWarning,
			})
			return result, output, nil
		}

		return result, output, err
	}
}
