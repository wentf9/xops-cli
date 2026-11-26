package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
)

// PolicyProfile 标识 Engine 能力门控的安全策略配置档（RFC §3.1 / §4.2 / ADR-008）；零值恒失败关闭。
//
//xops:opaque
//xops:failclosed
type PolicyProfile uint8

const (
	PolicyProfileInvalid        PolicyProfile = iota // 零值无效配置档（失败关闭默认态）
	PolicyProfileDirectOperator                      // CLI 直接人工操作员模式（保留审计闭环与显式 Deny 拦截）
	PolicyProfileStrictOperator                      // CLI 严格护栏模式（--policy=strict）
	PolicyProfileStrictAgent                         // MCP / AI Agent 严格熔断模式（终态审计失败立即 Halted）
)

// NoElicitFallback 定义护栏要求人工审批但运行环境不可交互时的回退行为；零值恒为 Deny（失败关闭）。
//
//xops:opaque
//xops:failclosed
type NoElicitFallback uint8

const (
	NoElicitFallbackDeny      NoElicitFallback = iota // 零值失败关闭：不可交互时直接拒绝并写入审计
	NoElicitFallbackChallenge                         // 两步挑战模式：签发绑定审批信封供调用方二次提交核验
)

// RequestTTYMode 标识 SSH 会话的伪终端分配策略（auto/yes/no/force，对应 -t/-tt/-T）；零值按操作类型取确定性默认。
//
//xops:opaque
//xops:failclosed
type RequestTTYMode uint8

const (
	RequestTTYUnset RequestTTYMode = iota // 未显式设置（零值）
	RequestTTYAuto                        // 自动模式：仅交互 Shell 且本机为交互终端时分配 PTY
	RequestTTYYes                         // 本机为交互终端时分配 PTY（-t）
	RequestTTYNo                          // 禁止分配 PTY（-T）
	RequestTTYForce                       // 强制分配远端 PTY（-tt）
)

type enumPair[T any] struct {
	k string
	v T
}

func parseEnumPairs[T any](raw string, zero T, baseErr error, pairs ...enumPair[T]) (T, error) {
	norm := strings.ToLower(strings.TrimSpace(raw))
	for _, p := range pairs {
		if p.k == norm {
			return p.v, nil
		}
	}
	return zero, fmt.Errorf("%w: %q", baseErr, raw)
}

// ParsePolicyProfile / ParseNoElicitFallback / ParseRequestTTYMode 严格解析公开枚举文本（零堆分配）。
func ParsePolicyProfile(raw string) (PolicyProfile, error) {
	return parseEnumPairs(raw, PolicyProfileInvalid, ErrInvalidProfile,
		enumPair[PolicyProfile]{"direct_operator", PolicyProfileDirectOperator},
		enumPair[PolicyProfile]{"strict", PolicyProfileStrictOperator},
		enumPair[PolicyProfile]{"strict_operator", PolicyProfileStrictOperator},
		enumPair[PolicyProfile]{"strict_agent", PolicyProfileStrictAgent})
}
func ParseNoElicitFallback(raw string) (NoElicitFallback, error) {
	return parseEnumPairs(raw, NoElicitFallbackDeny, ErrInvalidFallback,
		enumPair[NoElicitFallback]{"deny", NoElicitFallbackDeny},
		enumPair[NoElicitFallback]{"challenge", NoElicitFallbackChallenge})
}
func ParseRequestTTYMode(raw string) (RequestTTYMode, error) {
	return parseEnumPairs(raw, RequestTTYUnset, ErrInvalidRequestTTY,
		enumPair[RequestTTYMode]{"auto", RequestTTYAuto}, enumPair[RequestTTYMode]{"yes", RequestTTYYes},
		enumPair[RequestTTYMode]{"true", RequestTTYYes}, enumPair[RequestTTYMode]{"no", RequestTTYNo},
		enumPair[RequestTTYMode]{"false", RequestTTYNo}, enumPair[RequestTTYMode]{"force", RequestTTYForce})
}

// PolicyProfile / NoElicitFallback / RequestTTYMode 只读校验、文本序列化与内部映射方法。
func (p PolicyProfile) IsValid() bool {
	return p >= PolicyProfileDirectOperator && p <= PolicyProfileStrictAgent
}
func (p PolicyProfile) IsZero() bool { return p == PolicyProfileInvalid }
func (p PolicyProfile) String() string {
	return lookupEnumName(uint8(p), "invalid", "invalid", "direct_operator", "strict_operator", "strict_agent")
}
func (p PolicyProfile) AppendText(b []byte) ([]byte, error) {
	return appendValidEnumText(b, p.IsValid(), p.String(), ErrInvalidProfile, uint8(p))
}
func (p PolicyProfile) MarshalText() ([]byte, error) { return p.AppendText(nil) }
func (p *PolicyProfile) UnmarshalText(t []byte) error {
	return unmarshalEnumText(p, PolicyProfileInvalid, t, ErrInvalidProfile, ParsePolicyProfile)
}
func (p PolicyProfile) toGateProfile() (gate.PolicyProfileKind, error) {
	return mapEnum(p, p.IsValid(), ErrInvalidProfile, gate.PolicyProfileInvalid, gate.PolicyProfileDirectOperator, gate.PolicyProfileStrictOperator, gate.PolicyProfileStrictAgent)
}
func (f NoElicitFallback) IsValid() bool { return f <= NoElicitFallbackChallenge }
func (f NoElicitFallback) IsZero() bool  { return f == NoElicitFallbackDeny }
func (f NoElicitFallback) String() string {
	return lookupEnumName(uint8(f), "deny(invalid)", "deny", "challenge")
}
func (f NoElicitFallback) AppendText(b []byte) ([]byte, error) {
	return appendValidEnumText(b, f.IsValid(), f.String(), ErrInvalidFallback, uint8(f))
}
func (f NoElicitFallback) MarshalText() ([]byte, error) { return f.AppendText(nil) }
func (f *NoElicitFallback) UnmarshalText(t []byte) error {
	return unmarshalEnumText(f, NoElicitFallbackDeny, t, ErrInvalidFallback, ParseNoElicitFallback)
}
func (f NoElicitFallback) toGateFallback() (gate.NoElicitFallback, error) {
	return mapEnum(f, f.IsValid(), ErrInvalidFallback, gate.NoElicitFallbackDeny, gate.NoElicitFallbackChallenge)
}
func (m RequestTTYMode) IsValid() bool { return m >= RequestTTYAuto && m <= RequestTTYForce }
func (m RequestTTYMode) IsZero() bool  { return m == RequestTTYUnset }
func (m RequestTTYMode) String() string {
	return lookupEnumName(uint8(m), "unset", "unset", "auto", "yes", "no", "force")
}
func (m RequestTTYMode) AppendText(b []byte) ([]byte, error) {
	return appendValidEnumText(b, m.IsValid(), m.String(), ErrInvalidRequestTTY, uint8(m))
}
func (m RequestTTYMode) MarshalText() ([]byte, error) { return m.AppendText(nil) }
func (m *RequestTTYMode) UnmarshalText(t []byte) error {
	return unmarshalEnumText(m, RequestTTYUnset, t, ErrInvalidRequestTTY, ParseRequestTTYMode)
}
func (m RequestTTYMode) toSessionTTYMode() (ucsess.RequestTTYMode, error) {
	return mapEnum(m, m <= RequestTTYForce, ErrInvalidRequestTTY, ucsess.RequestTTYUnset, ucsess.RequestTTYAuto, ucsess.RequestTTYYes, ucsess.RequestTTYNo, ucsess.RequestTTYForce)
}

// HaltInfo 描述 Engine 底层安全门控首次进入不可逆 Halted 熔断态时的只读诊断快照（ADR-008）；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type HaltInfo struct {
	inner gate.HaltInfo
	valid bool
}

// OnHaltFunc 是 Engine 进入不可逆 Halted 熔断态且已通知连接池吊销全部句柄后触发至多一次的可选外部回调。
type OnHaltFunc func(info HaltInfo)

func haltInfoFromGate(info gate.HaltInfo) HaltInfo {
	if !info.IsValid() {
		return HaltInfo{}
	}
	return HaltInfo{inner: info, valid: true}
}

// HaltInfo 零值安全只读访问器。
func (h HaltInfo) IsValid() bool       { return h.valid && h.inner.IsValid() }
func (h HaltInfo) IsZero() bool        { return !h.IsValid() }
func (h HaltInfo) ProcessID() string   { return validOrZero(h.IsValid(), h.inner.ProcessID().String()) }
func (h HaltInfo) Reason() string      { return validOrZero(h.IsValid(), h.inner.Reason()) }
func (h HaltInfo) Cause() error        { return validOrZero(h.IsValid(), h.inner.Cause()) }
func (h HaltInfo) HaltedAt() time.Time { return validOrZero(h.IsValid(), h.inner.HaltedAt()) }
func (h HaltInfo) OperationID() algebraic.Option[security.OperationID] {
	return validOrZero(h.IsValid(), h.inner.OperationID())
}

func validOrZero[T any](valid bool, v T) T {
	if !valid {
		return zeroVal[T]()
	}
	return v
}
func mapEnum[F ~uint8, T any](v F, ok bool, baseErr error, table ...T) (T, error) {
	if ok && int(v) < len(table) {
		return table[v], nil
	}
	return zeroVal[T](), fmt.Errorf("%w: %d", baseErr, uint8(v))
}
func lookupEnumName(idx uint8, fallback string, names ...string) string {
	if int(idx) < len(names) {
		return names[idx]
	}
	return fallback
}
func appendValidEnumText(b []byte, valid bool, name string, baseErr error, raw uint8) ([]byte, error) {
	if !valid {
		return nil, fmt.Errorf("%w: %d", baseErr, raw)
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
