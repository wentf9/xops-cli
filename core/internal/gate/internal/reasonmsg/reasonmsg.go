// Package reasonmsg 提供 Security / FSM / Gate 规范英文原因到结构化 domi18n.Message 的纯函数双轨投影。
//
// 设计原则：
//   - Security/FSM/Gate 内部状态与 ApprovalEnvelope.Digest() 恒保持规范英文（逐字节稳定），
//     展示边界与门控错误经本包将封闭规范原因投影为结构化 KeyGateReason* 消息；
//   - 每条 KeyGateReason* 的规范英文兜底（CanonicalFallback）与原始规范英文原因 100% 逐字相等；
//   - 未命中封闭集的外部自定义原因严格失败关闭，回退为 BoundStr / WrapSentinelDetail，不丢失原始信息。
package reasonmsg

import (
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// ProjectMessage 将 Security / FSM / Gate 产出的封闭规范英文原因映射为结构化 domi18n.Message。
// 命中封闭集返回 (Message, true)；空串或未登记自由文本返回 (零值, false)。
func ProjectMessage(raw string) (domi18n.Message, bool) {
	id, ok := lookupReasonID(strings.TrimSpace(raw))
	if !ok {
		var zero domi18n.Message
		return zero, false
	}
	return domi18n.NewMessage(id), true
}

// Param 构造消息模板中的原因参数（如 {reason}）：
//   - raw 为空或纯空白时使用 fallbackID 对应的结构化嵌套消息；
//   - raw 命中封闭规范原因集时使用对应的结构化嵌套消息；
//   - 未命中封闭集的自由文本安全回退为 BoundStr，保证失败关闭且不丢失上下文。
func Param(key, raw string, fallbackID domi18n.MessageID) domi18n.Param {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return domi18n.Msg(key, domi18n.NewMessage(validFallbackID(fallbackID)))
	}
	if msg, ok := ProjectMessage(trimmed); ok {
		return domi18n.Msg(key, msg)
	}
	return domi18n.BoundStr(key, trimmed)
}

// ErrorForSentinel 为门控哨兵错误附加结构化原因：
//   - raw 为空或纯空白时使用 fallbackID 构造 WrapSentinel(sentinel, E(fallbackID))；
//   - raw 命中封闭规范原因集时使用对应 KeyGateReason* 构造 WrapSentinel(sentinel, E(id))；
//   - 未命中封闭集的自由文本通过 WrapSentinelDetail 保留哨兵头段与受限净化明细。
func ErrorForSentinel(sentinel error, raw string, fallbackID domi18n.MessageID) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return domi18n.WrapSentinel(sentinel, domi18n.E(validFallbackID(fallbackID)))
	}
	if id, ok := lookupReasonID(trimmed); ok {
		return domi18n.WrapSentinel(sentinel, domi18n.E(id))
	}
	return domi18n.WrapSentinelDetail(sentinel, nil, trimmed)
}

func validFallbackID(fallbackID domi18n.MessageID) domi18n.MessageID {
	if fallbackID.IsValid() {
		return fallbackID
	}
	return domi18n.KeyGateReasonApprovalRequired
}

// lookupReasonID 将 Security / FSM / Gate / Events 封闭集内的规范英文原因精确映射至 KeyGateReason*。
func lookupReasonID(raw string) (domi18n.MessageID, bool) {
	switch raw {
	case "nil or uninitialized guardrail decision":
		return domi18n.KeyGateReasonNilDecision, true
	case "no guardrail decision evaluated":
		return domi18n.KeyGateReasonEmptyDecisions, true
	case "operation risk level is unknown or invalid":
		return domi18n.KeyGateReasonUnknownRisk, true
	case "approval threshold is unknown or invalid":
		return domi18n.KeyGateReasonInvalidThreshold, true
	case "operation risk meets or exceeds approval threshold":
		return domi18n.KeyGateReasonRiskMeetsThreshold, true
	case "operation risk is below approval threshold":
		return domi18n.KeyGateReasonRiskBelowThreshold, true
	case "node overrides set is uninitialized or invalid":
		return domi18n.KeyGateReasonInvalidOverrides, true
	case "node override permits threshold evaluation":
		return domi18n.KeyGateReasonNodeOverrideAllow, true
	case "node override approval floor with unknown risk":
		return domi18n.KeyGateReasonNodeOverrideUnkRisk, true
	case "node override requires explicit approval":
		return domi18n.KeyGateReasonNodeOverrideAppr, true
	case "node override denies operation":
		return domi18n.KeyGateReasonNodeOverrideDeny, true
	case "lexical verdict denied":
		return domi18n.KeyGateReasonLexVerdictDenied, true
	case "lexical guardrail denied":
		return domi18n.KeyGateReasonLexGuardrailDenied, true
	case "invalid lexical guardrail decision":
		return domi18n.KeyGateReasonInvalidLexDecision, true
	case "round2 canonicalization probe failed":
		return domi18n.KeyGateReasonRound2CanonFailed, true
	case "canonical identity or non-path binding drifted":
		return domi18n.KeyGateReasonCanonBindingDrifted, true
	case "round2 probe failed during escalation check":
		return domi18n.KeyGateReasonRound2EscFailed, true
	case "effective verdict denied":
		return domi18n.KeyGateReasonEffVerdictDenied, true
	case "canonical guardrail denied":
		return domi18n.KeyGateReasonCanonGuardrailDeny, true
	case "canonical_scope_escalated":
		return domi18n.KeyGateReasonCanonScopeEscalated, true
	case "invalid canonical guardrail decision":
		return domi18n.KeyGateReasonInvalidCanonDecision, true
	case "user rejected approval challenge":
		return domi18n.KeyGateReasonUserRejected, true
	case "approval token expired or binding mismatch":
		return domi18n.KeyGateReasonTokenExpOrMismatch, true
	case "approval token digest mismatch":
		return domi18n.KeyGateReasonTokenDigestMismatch, true
	case "round2 probe failed":
		return domi18n.KeyGateReasonRound2ProbeFailed, true
	case "post-challenge canonical scope escalated or binding drifted":
		return domi18n.KeyGateReasonPostChallengeDrift, true
	case "invalid policy profile":
		return domi18n.KeyGateReasonInvalidProfile, true
	case "security verdict denied":
		return domi18n.KeyGateReasonVerdictDenied, true
	case "direct operator profile allow":
		return domi18n.KeyGateReasonDirectOperatorAllow, true
	case "unexpected guardrail decision":
		return domi18n.KeyGateReasonUnexpectedDecision, true
	case "operation touches protected path":
		return domi18n.KeyGateReasonProtectedPath, true
	case "guardrail denied":
		return domi18n.KeyGateReasonGuardrailDenied, true
	case "canonical denied":
		return domi18n.KeyGateReasonCanonicalDenied, true
	case "approval required":
		return domi18n.KeyGateReasonApprovalRequired, true
	case "scope escalated":
		return domi18n.KeyGateReasonScopeEscalated, true
	case "token invalidated":
		return domi18n.KeyGateReasonTokenInvalidated, true
	case "authorization denied":
		return domi18n.KeyGateReasonAuthDenied, true
	case "gate halted":
		return domi18n.KeyGateReasonGateHalted, true
	case "privilege escalation requires approval":
		return domi18n.KeyGateReasonPrivEscApproval, true
	case "pre-escalation baseline":
		return domi18n.KeyGateReasonPreEscBaseline, true
	case "audit event is invalid":
		return domi18n.KeyGateReasonInvalidAuditEvent, true
	default:
		return domi18n.MessageIDInvalid, false
	}
}
