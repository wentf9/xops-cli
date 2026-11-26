package protocol

import (
	"encoding/json/jsontext"
	"errors"
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	ucauto "github.com/wentf9/xops-cli/core/internal/usecase/automation"
	uccred "github.com/wentf9/xops-cli/core/internal/usecase/credential"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	ucobs "github.com/wentf9/xops-cli/core/internal/usecase/observability"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	maxErrorMessageBytes = 1024
	approvalNextStepHint = "向人工操作员展示 envelope 与 envelope_digest，确认后携带相同参数与 approval={verdict, envelope_digest, envelope} 重新调用。"
)

// DecodeApprovalSubmission 将可选的 MCP ApprovalSubmissionDTO 校验并转换为不可变 gate.ApprovalSubmission。
func DecodeApprovalSubmission(opt algebraic.Option[ApprovalSubmissionDTO]) (algebraic.Option[gate.ApprovalSubmission], error) {
	dto, ok := opt.Get()
	if !ok {
		return algebraic.None[gate.ApprovalSubmission](), nil
	}
	resp, err := ports.NewApprovalDecisionResponse(dto.Verdict, dto.EnvelopeDigest, dto.Comment)
	if err != nil {
		return algebraic.None[gate.ApprovalSubmission](), fmt.Errorf("%w: %w", ErrInvalidApproval, err)
	}
	if env, hasEnv := dto.Envelope.Get(); hasEnv {
		envDig, dErr := env.Digest()
		if dErr != nil {
			return algebraic.None[gate.ApprovalSubmission](), fmt.Errorf("%w: %w", ErrInvalidApproval, dErr)
		}
		if envDig != dto.EnvelopeDigest {
			return algebraic.None[gate.ApprovalSubmission](), fmt.Errorf("%w: envelope_digest 与信封内容摘要不匹配", ErrInvalidApproval)
		}
	}
	sub, err := gate.NewApprovalSubmission(gate.ApprovalSubmissionSpec{
		Envelope: dto.Envelope,
		Response: resp,
	})
	if err != nil {
		return algebraic.None[gate.ApprovalSubmission](), fmt.Errorf("%w: %w", ErrInvalidApproval, err)
	}
	return algebraic.Some(sub), nil
}

// ClassifyError 将底层门控、用例、状态机或端口错误确定性分类为 JSON-RPC 错误码与脱敏 ToolErrorPayload；
// 严格保护 ApprovalChallengeError 完整信封、Halted 熔断标志与 OutcomeUnknown/UncertainCommit 禁止重试语义。
func ClassifyError(err error) (int, ToolErrorPayload) {
	if err == nil {
		return CodeInternalError, ToolErrorPayload{Code: "internal_error", Message: "unknown empty error"}
	}
	msg := sanitizeErrorText(err.Error())
	if code, payload, matched := classifyGateAndApprovalError(err, msg); matched {
		return code, payload
	}
	if code, payload, matched := classifyUncertainError(err, msg); matched {
		return code, payload
	}
	return classifyDomainAndPortError(err, msg)
}

func classifyGateAndApprovalError(err error, msg string) (int, ToolErrorPayload, bool) {
	if errors.Is(err, gate.ErrGateHalted) {
		return CodeGateHalted, ToolErrorPayload{
			Code: "gate_halted", Message: msg, Halted: true,
		}, true
	}
	if errors.Is(err, ports.ErrAuditPostWrite) {
		return CodeGateHalted, ToolErrorPayload{
			Code: "audit_post_write_error", Message: msg, Halted: true,
		}, true
	}
	if chErr, ok := errors.AsType[*gate.ApprovalChallengeError](err); ok && chErr != nil && chErr.IsValid() {
		return CodeApprovalRequired, ToolErrorPayload{
			Code:    "approval_required",
			Message: sanitizeErrorText(chErr.Reason()),
			ApprovalChallenge: &ApprovalChallengeDTO{
				Envelope:       chErr.Envelope(),
				EnvelopeDigest: chErr.EnvelopeDigest(),
				Escalated:      chErr.Escalated(),
				Reason:         sanitizeErrorText(chErr.Reason()),
				Instructions:   approvalNextStepHint,
			},
		}, true
	}
	if isAuthorizationFailure(err) {
		return CodeAuthorizationDenied, ToolErrorPayload{
			Code: "authorization_denied", Message: msg,
		}, true
	}
	return 0, ToolErrorPayload{}, false
}

func isAuthorizationFailure(err error) bool {
	return errors.Is(err, gate.ErrAuthorizationDenied) ||
		errors.Is(err, gate.ErrApprovalRequired) ||
		errors.Is(err, gate.ErrApprovalRejected) ||
		errors.Is(err, gate.ErrApprovalExpired) ||
		errors.Is(err, gate.ErrApprovalReplayed) ||
		errors.Is(err, gate.ErrApprovalMismatch) ||
		errors.Is(err, gate.ErrApprovalInvalidated) ||
		errors.Is(err, gate.ErrScopeEscalated) ||
		errors.Is(err, gate.ErrPendingLimitExceeded)
}

func classifyUncertainError(err error, msg string) (int, ToolErrorPayload, bool) {
	switch {
	case errors.Is(err, uctrans.ErrUncertainCommit):
		return CodeUncertainOutcome, ToolErrorPayload{
			Code: "transfer_uncertain_commit", Message: msg, Uncertain: true,
		}, true
	case errors.Is(err, ucauto.ErrUncertainOutcome) ||
		errors.Is(err, ucauto.ErrUncertainDurability) ||
		errors.Is(err, ucobs.ErrUncertainOutcome) ||
		errors.Is(err, ucinv.ErrUncertainDurability) ||
		errors.Is(err, ucinv.ErrCommitOutcomeUnknown) ||
		errors.Is(err, uccred.ErrUncertainDurability) ||
		errors.Is(err, uccred.ErrSagaUncertain) ||
		errors.Is(err, ucinv.ErrEnrollmentUncertain):
		return CodeUncertainOutcome, ToolErrorPayload{
			Code: "uncertain_outcome", Message: msg, Uncertain: true,
		}, true
	default:
		return 0, ToolErrorPayload{}, false
	}
}

func classifyDomainAndPortError(err error, msg string) (int, ToolErrorPayload) {
	switch {
	case errors.Is(err, ErrInvalidParams) ||
		errors.Is(err, ErrInvalidApproval) ||
		errors.Is(err, ErrInvalidJSONRPC) ||
		errors.Is(err, ErrInvalidMCPMessage) ||
		errors.Is(err, ports.ErrInvalidArgument) ||
		errors.Is(err, ucinv.ErrInvalidRequest) ||
		errors.Is(err, ucinv.ErrInvalidTarget) ||
		errors.Is(err, ucsess.ErrInvalidRequest) ||
		errors.Is(err, uctrans.ErrInvalidRequest) ||
		errors.Is(err, ucauto.ErrInvalidRequest) ||
		errors.Is(err, ucobs.ErrInvalidRequest) ||
		errors.Is(err, ucobs.ErrInvalidGUIInput):
		return CodeInvalidParams, ToolErrorPayload{Code: "invalid_params", Message: msg}
	case errors.Is(err, ErrToolNotFound):
		return CodeMethodNotFound, ToolErrorPayload{Code: "tool_not_found", Message: msg}
	case errors.Is(err, ports.ErrNotFound) ||
		errors.Is(err, ucinv.ErrAssetNotFound) ||
		errors.Is(err, uctrans.ErrTransferNotFound) ||
		errors.Is(err, ucsess.ErrPTYClosed) ||
		errors.Is(err, fsm.ErrIllegalTransition) ||
		errors.Is(err, uctrans.ErrCorruptJournal):
		return CodeInvalidState, ToolErrorPayload{Code: "invalid_state", Message: msg}
	case errors.Is(err, uctrans.ErrOperatorReadUnavailable) ||
		errors.Is(err, ucauto.ErrOperatorReadUnavailable):
		return CodeAuthorizationDenied, ToolErrorPayload{Code: "sandbox_policy_denied", Message: msg}
	default:
		return CodeInternalError, ToolErrorPayload{Code: "execution_error", Message: msg}
	}
}

// NewToolSuccessResult 将工具成功输出编码为确定性 JSON/v2 的 CallToolResult（文本块 + structuredContent + 附加内容块）。
func NewToolSuccessResult(payload any, extraBlocks ...ContentBlock) (CallToolResult, error) {
	raw, err := MarshalCanonical(payload)
	if err != nil {
		return CallToolResult{}, fmt.Errorf("编码工具响应载荷失败: %w", err)
	}
	blocks := make([]ContentBlock, 0, 1+len(extraBlocks))
	blocks = append(blocks, NewTextContent(string(raw)))
	blocks = append(blocks, extraBlocks...)
	return CallToolResult{
		Content:           blocks,
		StructuredContent: jsontext.Value(raw),
		IsError:           false,
	}, nil
}

// NewToolErrorResult 将错误分类并编码为结构化 IsError=true 的 CallToolResult，同时返回对应 JSON-RPC 错误码。
func NewToolErrorResult(err error) (CallToolResult, int, error) {
	code, payload := ClassifyError(err)
	raw, mErr := MarshalCanonical(payload)
	if mErr != nil {
		return CallToolResult{}, CodeInternalError, fmt.Errorf("编码工具错误载荷失败: %w", mErr)
	}
	return CallToolResult{
		Content:           []ContentBlock{NewTextContent(string(raw))},
		StructuredContent: jsontext.Value(raw),
		IsError:           true,
	}, code, nil
}

func sanitizeErrorText(raw string) string {
	clean := security.SanitizePromptText(raw)
	if len(clean) <= maxErrorMessageBytes {
		return clean
	}
	return clean[:maxErrorMessageBytes] + "...(truncated)"
}
