package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	"github.com/wentf9/xops-cli/core/ports"
)

// PolicyProfile 标识 Engine 能力门控的安全策略配置档（对应 RFC §3.1 / §4.2 / ADR-008）；
// 零值恒为 PolicyProfileInvalid 并严格失败关闭。
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

// ParsePolicyProfile / ParseNoElicitFallback / ParseRequestTTYMode 严格解析公开枚举文本。
func ParsePolicyProfile(raw string) (PolicyProfile, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "direct_operator":
		return PolicyProfileDirectOperator, nil
	case "strict", "strict_operator":
		return PolicyProfileStrictOperator, nil
	case "strict_agent":
		return PolicyProfileStrictAgent, nil
	default:
		return PolicyProfileInvalid, fmt.Errorf("%w: %q", ErrInvalidProfile, raw)
	}
}
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
func (p *PolicyProfile) UnmarshalText(text []byte) error {
	return unmarshalEnumText(p, PolicyProfileInvalid, text, ErrInvalidProfile, ParsePolicyProfile)
}
func (p PolicyProfile) toGateProfile() (gate.PolicyProfileKind, error) {
	if p.IsValid() {
		return [...]gate.PolicyProfileKind{gate.PolicyProfileInvalid, gate.PolicyProfileDirectOperator, gate.PolicyProfileStrictOperator, gate.PolicyProfileStrictAgent}[p], nil
	}
	return gate.PolicyProfileInvalid, fmt.Errorf("%w: %d", ErrInvalidProfile, uint8(p))
}

// NoElicitFallback 定义护栏要求人工审批但运行环境不可交互时的回退行为；零值恒为 NoElicitFallbackDeny（严格失败关闭）。
//
//xops:opaque
//xops:failclosed
type NoElicitFallback uint8

const (
	NoElicitFallbackDeny      NoElicitFallback = iota // 零值失败关闭：不可交互时直接拒绝并写入审计
	NoElicitFallbackChallenge                         // 两步挑战模式：签发绑定审批信封供调用方二次提交核验
)

// ParseNoElicitFallback 严格解析不可交互回退策略文本（"deny"、"challenge"）。
func ParseNoElicitFallback(raw string) (NoElicitFallback, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "deny":
		return NoElicitFallbackDeny, nil
	case "challenge":
		return NoElicitFallbackChallenge, nil
	default:
		return NoElicitFallbackDeny, fmt.Errorf("%w: %q", ErrInvalidFallback, raw)
	}
}
func (f NoElicitFallback) IsValid() bool {
	return f == NoElicitFallbackDeny || f == NoElicitFallbackChallenge
}
func (f NoElicitFallback) IsZero() bool { return f == NoElicitFallbackDeny }
func (f NoElicitFallback) String() string {
	return lookupEnumName(uint8(f), "deny(invalid)", "deny", "challenge")
}
func (f NoElicitFallback) AppendText(b []byte) ([]byte, error) {
	return appendValidEnumText(b, f.IsValid(), f.String(), ErrInvalidFallback, uint8(f))
}
func (f NoElicitFallback) MarshalText() ([]byte, error) { return f.AppendText(nil) }
func (f *NoElicitFallback) UnmarshalText(text []byte) error {
	return unmarshalEnumText(f, NoElicitFallbackDeny, text, ErrInvalidFallback, ParseNoElicitFallback)
}
func (f NoElicitFallback) toGateFallback() (gate.NoElicitFallback, error) {
	if f.IsValid() {
		return [...]gate.NoElicitFallback{gate.NoElicitFallbackDeny, gate.NoElicitFallbackChallenge}[f], nil
	}
	return gate.NoElicitFallbackDeny, fmt.Errorf("%w: %d", ErrInvalidFallback, uint8(f))
}

// RequestTTYMode 标识 SSH 会话的伪终端分配策略（对应 OpenSSH RequestTTY auto/yes/no/force 与 -t/-tt/-T）；
// 零值 RequestTTYUnset 在运行期按操作类型取确定性默认（交互 Shell=auto，单命令=no）。
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

// ParseRequestTTYMode 严格解析 RequestTTY 文本（"auto"、"yes"、"no"、"force"）。
func ParseRequestTTYMode(raw string) (RequestTTYMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "auto":
		return RequestTTYAuto, nil
	case "yes", "true":
		return RequestTTYYes, nil
	case "no", "false":
		return RequestTTYNo, nil
	case "force":
		return RequestTTYForce, nil
	default:
		return RequestTTYUnset, fmt.Errorf("%w: %q", ErrInvalidRequestTTY, raw)
	}
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
func (m *RequestTTYMode) UnmarshalText(text []byte) error {
	return unmarshalEnumText(m, RequestTTYUnset, text, ErrInvalidRequestTTY, ParseRequestTTYMode)
}
func (m RequestTTYMode) toSessionTTYMode() (ucsess.RequestTTYMode, error) {
	if int(m) <= int(RequestTTYForce) {
		return [...]ucsess.RequestTTYMode{ucsess.RequestTTYUnset, ucsess.RequestTTYAuto, ucsess.RequestTTYYes, ucsess.RequestTTYNo, ucsess.RequestTTYForce}[m], nil
	}
	return ucsess.RequestTTYUnset, fmt.Errorf("%w: %d", ErrInvalidRequestTTY, uint8(m))
}

func lookupEnumName(idx uint8, fallback string, names ...string) string {
	if int(idx) < len(names) {
		return names[idx]
	}
	return fallback
}

// HaltInfo 描述 Engine 底层安全门控首次进入不可逆 Halted 熔断态时的只读诊断快照（ADR-008）；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type HaltInfo struct {
	processID   string
	operationID algebraic.Option[security.OperationID]
	reason      string
	cause       error
	haltedAt    time.Time
	valid       bool
}

// OnHaltFunc 是 Engine 进入不可逆 Halted 熔断态且已通知连接池吊销全部句柄后触发至多一次的可选外部回调。
type OnHaltFunc func(info HaltInfo)

func haltInfoFromGate(info gate.HaltInfo) HaltInfo {
	if !info.IsValid() {
		return HaltInfo{}
	}
	return HaltInfo{
		processID: info.ProcessID().String(), operationID: info.OperationID(),
		reason: info.Reason(), cause: info.Cause(), haltedAt: info.HaltedAt(), valid: true,
	}
}

// IsValid / IsZero / ProcessID / OperationID / Reason / Cause / HaltedAt 提供熔断快照只读访问器。
func (h HaltInfo) IsValid() bool {
	return h.valid && h.processID != "" && h.reason != "" && !h.haltedAt.IsZero()
}
func (h HaltInfo) IsZero() bool        { return !h.IsValid() }
func (h HaltInfo) ProcessID() string   { return validOrZero(h.IsValid(), h.processID) }
func (h HaltInfo) Reason() string      { return validOrZero(h.IsValid(), h.reason) }
func (h HaltInfo) Cause() error        { return validOrZero(h.IsValid(), h.cause) }
func (h HaltInfo) HaltedAt() time.Time { return validOrZero(h.IsValid(), h.haltedAt) }
func (h HaltInfo) OperationID() algebraic.Option[security.OperationID] {
	return validOrZero(h.IsValid(), h.operationID)
}

// ReconcileReport 封装启动期 O(1) 跨进程崩溃审计对账的不可变汇总报告（ADR-008 / RFC §3.4）；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type ReconcileReport struct {
	raw   ports.CrashReconcileReport
	valid bool
}

// IsValid / IsZero / ScannedLocks / LiveLocksSkipped / DeadLocksClaimed / AbortedOperations / Equal 提供只读访问器。
func (r ReconcileReport) IsValid() bool     { return r.valid && r.raw.IsValid() }
func (r ReconcileReport) IsZero() bool      { return !r.IsValid() }
func (r ReconcileReport) ScannedLocks() int { return validOrZero(r.IsValid(), r.raw.ScannedLocks()) }
func (r ReconcileReport) LiveLocksSkipped() int {
	return validOrZero(r.IsValid(), r.raw.LiveLocksSkipped())
}
func (r ReconcileReport) DeadLocksClaimed() int {
	return validOrZero(r.IsValid(), r.raw.DeadLocksClaimed())
}
func (r ReconcileReport) AbortedOperations() []security.OperationID {
	return validOrZero(r.IsValid(), r.raw.AbortedOperations())
}
func (r ReconcileReport) Equal(other ReconcileReport) bool {
	return r.IsValid() && other.IsValid() && r.raw.Equal(other.raw)
}

// ResolvedTarget 封装目标解析产出的不可变来源证明、生效策略与 Merkle 链式连接计划；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type ResolvedTarget struct {
	inner ucinv.ResolvedTarget
	valid bool
}

// IsValid / IsZero / NodeID / Origin / OriginKind / Policy / Plan 提供目标解析快照只读访问器。
func (r ResolvedTarget) IsValid() bool  { return r.valid && r.inner.IsValid() }
func (r ResolvedTarget) IsZero() bool   { return !r.IsValid() }
func (r ResolvedTarget) NodeID() string { return validOrZero(r.IsValid(), r.inner.NodeID()) }
func (r ResolvedTarget) Origin() inventory.NodeOrigin {
	return validOrZero(r.IsValid(), r.inner.Origin())
}
func (r ResolvedTarget) OriginKind() option.OriginKind {
	return validOrZero(r.IsValid(), r.inner.OriginKind())
}
func (r ResolvedTarget) Policy() option.EffectivePolicy {
	return validOrZero(r.IsValid(), r.inner.Policy())
}
func (r ResolvedTarget) Plan() plan.SealedConnectionPlan {
	return validOrZero(r.IsValid(), r.inner.Plan())
}

func validOrZero[T any](valid bool, v T) T {
	if !valid {
		return zeroVal[T]()
	}
	return v
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
