package protocol

import (
	"encoding/json/jsontext"
	"errors"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
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
	approvalNextStepHint = "Present envelope and envelope_digest to a human operator; once approved, re-invoke with identical parameters and approval={verdict, envelope_digest, envelope}."
)

// DecodeApprovalSubmission 将可选的 MCP ApprovalSubmissionDTO 校验并转换为不可变 gate.ApprovalSubmission。
func DecodeApprovalSubmission(opt algebraic.Option[ApprovalSubmissionDTO]) (algebraic.Option[gate.ApprovalSubmission], error) {
	dto, ok := opt.Get()
	if !ok {
		return algebraic.None[gate.ApprovalSubmission](), nil
	}
	resp, err := ports.NewApprovalDecisionResponse(dto.Verdict, dto.EnvelopeDigest, dto.Comment)
	if err != nil {
		return algebraic.None[gate.ApprovalSubmission](), domi18n.WrapSentinel(ErrInvalidApproval, err)
	}
	if env, hasEnv := dto.Envelope.Get(); hasEnv {
		envDig, dErr := env.Digest()
		if dErr != nil {
			return algebraic.None[gate.ApprovalSubmission](), domi18n.WrapSentinel(ErrInvalidApproval, dErr)
		}
		if envDig != dto.EnvelopeDigest {
			return algebraic.None[gate.ApprovalSubmission](), domi18n.EF(ErrInvalidApproval, domi18n.KeyCommonMismatch, domi18n.Str("field", "envelope_digest"), domi18n.BoundStr("expected", envDig.String()), domi18n.BoundStr("actual", dto.EnvelopeDigest.String()))
		}
	}
	sub, err := gate.NewApprovalSubmission(gate.ApprovalSubmissionSpec{
		Envelope: dto.Envelope,
		Response: resp,
	})
	if err != nil {
		return algebraic.None[gate.ApprovalSubmission](), domi18n.WrapSentinel(ErrInvalidApproval, err)
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
	case errors.Is(err, ErrOutcomeUnknown) ||
		errors.Is(err, ucauto.ErrUncertainOutcome) ||
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
	case errors.Is(err, ErrParseJSON):
		return CodeParseError, ToolErrorPayload{Code: "parse_error", Message: msg}
	case errors.Is(err, fsm.ErrInvalidChunkOffset):
		return CodeInvalidParams, ToolErrorPayload{Code: "invalid_chunk_offset", Message: msg}
	case errors.Is(err, fsm.ErrTransferSizeExceeded):
		return CodeInvalidParams, ToolErrorPayload{Code: "transfer_size_exceeded", Message: msg}
	case isInvalidParamsError(err):
		return CodeInvalidParams, ToolErrorPayload{Code: "invalid_params", Message: msg}
	case errors.Is(err, ErrToolNotFound):
		return CodeMethodNotFound, ToolErrorPayload{Code: "tool_not_found", Message: msg}
	case errors.Is(err, uctrans.ErrPatchConflict):
		return CodeInvalidState, ToolErrorPayload{Code: "patch_conflict", Message: msg}
	case errors.Is(err, uctrans.ErrDigestMismatch):
		return CodeInvalidState, ToolErrorPayload{Code: "digest_mismatch", Message: msg}
	case isInvalidStateError(err):
		return CodeInvalidState, ToolErrorPayload{Code: "invalid_state", Message: msg}
	case errors.Is(err, uctrans.ErrSymlinkPolicyDenied):
		return CodeAuthorizationDenied, ToolErrorPayload{Code: "symlink_policy_denied", Message: msg}
	case errors.Is(err, uctrans.ErrOperatorReadUnavailable) ||
		errors.Is(err, ucauto.ErrOperatorReadUnavailable):
		return CodeAuthorizationDenied, ToolErrorPayload{Code: "sandbox_policy_denied", Message: msg}
	default:
		return CodeInternalError, ToolErrorPayload{Code: "execution_error", Message: msg}
	}
}

func isInvalidParamsError(err error) bool {
	return errors.Is(err, ErrInvalidParams) ||
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
		errors.Is(err, ucobs.ErrInvalidGUIInput)
}

func isInvalidStateError(err error) bool {
	return errors.Is(err, ports.ErrNotFound) ||
		errors.Is(err, ucinv.ErrAssetNotFound) ||
		errors.Is(err, uctrans.ErrTransferNotFound) ||
		errors.Is(err, ucsess.ErrPTYClosed) ||
		errors.Is(err, fsm.ErrIllegalTransition) ||
		errors.Is(err, uctrans.ErrCorruptJournal)
}

// SanitizeErrorMessage 对外暴露统一的提示注入净化与长度截断函数，供 MCP 传输层脱敏错误输出。
func SanitizeErrorMessage(raw string) string { return sanitizeErrorText(raw) }

// NewToolSuccessResult 将工具成功输出编码为确定性 JSON/v2 的 CallToolResult（文本块 + structuredContent + 附加内容块）。
func NewToolSuccessResult(payload any, extraBlocks ...ContentBlock) (CallToolResult, error) {
	raw, err := MarshalCanonical(payload)
	if err != nil {
		return CallToolResult{}, domi18n.Wrap(err, domi18n.KeyCommonOpFailed, domi18n.Str("op", "marshal tool result"))
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
		return CallToolResult{}, CodeInternalError, domi18n.Wrap(mErr, domi18n.KeyCommonOpFailed, domi18n.Str("op", "marshal tool error payload"))
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
