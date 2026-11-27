package gate

import (
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// PolicyProfileKind 标识能力门控运行时的安全策略配置档（RFC §3.1 / §4.2 / ADR-008）；
// 零值恒为 PolicyProfileInvalid 并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type PolicyProfileKind uint8

const (
	// PolicyProfileInvalid 为零值无效配置档（失败关闭默认态）。
	PolicyProfileInvalid PolicyProfileKind = iota
	// PolicyProfileDirectOperator 表示 CLI / Playbook 直接人工操作员模式：
	// 仍执行完整审计闭环与显式 Deny 拦截，不因风险阈值对人工直接操作重复弹窗。
	PolicyProfileDirectOperator
	// PolicyProfileStrictOperator 表示 CLI 严格护栏模式（--policy=strict）：
	// 执行完整风险阈值、NodeOverrides、受保护路径与审批挑战，终态审计失败向调用方报错但不永久锁死短命 CLI。
	PolicyProfileStrictOperator
	// PolicyProfileStrictAgent 表示 MCP / AI Agent 严格熔断模式（ADR-008）：
	// 执行全量护栏与审批校验，任何 AuditPostWriteError 或终态审计写失败均立即不可逆进入 Halted 熔断态。
	PolicyProfileStrictAgent
)

// ParsePolicyProfileKind 严格解析规范小写策略配置档文本（"direct_operator"、"strict"、"strict_operator"、"strict_agent"）。
func ParsePolicyProfileKind(raw string) (PolicyProfileKind, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "direct_operator":
		return PolicyProfileDirectOperator, nil
	case "strict", "strict_operator":
		return PolicyProfileStrictOperator, nil
	case "strict_agent":
		return PolicyProfileStrictAgent, nil
	default:
		return PolicyProfileInvalid, domi18n.EF(ErrInvalidProfile, domi18n.KeyCommonValueInvalid, domi18n.BoundStr("value", raw))
	}
}

// PolicyProfileKind 判定、文本编解码与严格失败关闭访问器。
func (p PolicyProfileKind) IsValid() bool {
	return p >= PolicyProfileDirectOperator && p <= PolicyProfileStrictAgent
}
func (p PolicyProfileKind) IsZero() bool { return p == PolicyProfileInvalid }

// EnforcesGuardrailThresholds 报告该配置档是否启用完整审批门控（无效零值失败关闭返回 true）。
func (p PolicyProfileKind) EnforcesGuardrailThresholds() bool {
	return p != PolicyProfileDirectOperator
}

// HaltsOnAuditPostWriteError 报告该配置档是否在终态审计写失败时立即不可逆熔断（ADR-008）。
func (p PolicyProfileKind) HaltsOnAuditPostWriteError() bool {
	return p == PolicyProfileStrictAgent || !p.IsValid()
}
func (p PolicyProfileKind) String() string {
	switch p {
	case PolicyProfileDirectOperator:
		return "direct_operator"
	case PolicyProfileStrictOperator:
		return "strict_operator"
	case PolicyProfileStrictAgent:
		return "strict_agent"
	default:
		return "invalid"
	}
}
func (p PolicyProfileKind) AppendText(b []byte) ([]byte, error) {
	return appendValidEnumText(b, p.IsValid(), p.String(), ErrInvalidProfile, uint8(p))
}
func (p PolicyProfileKind) MarshalText() ([]byte, error) { return p.AppendText(nil) }
func (p *PolicyProfileKind) UnmarshalText(text []byte) error {
	return unmarshalEnumText(p, PolicyProfileInvalid, text, ErrInvalidProfile, ParsePolicyProfileKind)
}

// NoElicitFallback 定义当护栏要求审批挑战但当前环境不可交互时的回退行为；
// 零值恒为 NoElicitFallbackDeny（严格失败关闭，严禁静默放行）。
//
//xops:opaque
//xops:failclosed
type NoElicitFallback uint8

const (
	// NoElicitFallbackDeny 为零值失败关闭策略：无法交互确认时直接拒绝并记录审计。
	NoElicitFallbackDeny NoElicitFallback = iota
	// NoElicitFallbackChallenge 表示两步挑战模式：签发绑定 ApprovalEnvelope 供外部客户端展示并二次提交核验。
	NoElicitFallbackChallenge
)

// ParseNoElicitFallback 严格解析不可交互回退策略（"deny"、"challenge"），拒绝任何放行别名。
func ParseNoElicitFallback(raw string) (NoElicitFallback, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "deny":
		return NoElicitFallbackDeny, nil
	case "challenge":
		return NoElicitFallbackChallenge, nil
	default:
		return NoElicitFallbackDeny, domi18n.EF(ErrInvalidFallback, domi18n.KeyCommonValueInvalid, domi18n.BoundStr("value", raw))
	}
}

// NoElicitFallback 判定与文本编解码访问器（越界非法值与解码失败均重置为 NoElicitFallbackDeny）。
func (f NoElicitFallback) IsValid() bool {
	return f == NoElicitFallbackDeny || f == NoElicitFallbackChallenge
}
func (f NoElicitFallback) IsZero() bool { return f == NoElicitFallbackDeny }
func (f NoElicitFallback) String() string {
	switch f {
	case NoElicitFallbackDeny:
		return "deny"
	case NoElicitFallbackChallenge:
		return "challenge"
	default:
		return "deny(invalid)"
	}
}
func (f NoElicitFallback) AppendText(b []byte) ([]byte, error) {
	return appendValidEnumText(b, f.IsValid(), f.String(), ErrInvalidFallback, uint8(f))
}
func (f NoElicitFallback) MarshalText() ([]byte, error) { return f.AppendText(nil) }
func (f *NoElicitFallback) UnmarshalText(text []byte) error {
	return unmarshalEnumText(f, NoElicitFallbackDeny, text, ErrInvalidFallback, ParseNoElicitFallback)
}

func appendValidEnumText(b []byte, valid bool, name string, baseErr error, raw uint8) ([]byte, error) {
	if !valid {
		return nil, domi18n.EF(baseErr, domi18n.KeyCommonValueInvalid, domi18n.Uint64("value", uint64(raw)))
	}
	return append(b, name...), nil
}

func unmarshalEnumText[T any](dst *T, zero T, text []byte, nilErr error, parse func(string) (T, error)) error {
	if dst == nil {
		return nilErr
	}
	parsed, err := parse(string(text))
	if err != nil {
		*dst = zero
		return err
	}
	*dst = parsed
	return nil
}
