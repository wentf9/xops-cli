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
	// PolicyProfileInvalid 为零值无效配置档（失败关闭默认态）。
	PolicyProfileInvalid PolicyProfile = iota
	// PolicyProfileDirectOperator 表示 CLI 直接人工操作员模式（保留完整审计闭环与显式 Deny 拦截）。
	PolicyProfileDirectOperator
	// PolicyProfileStrictOperator 表示 CLI 严格护栏模式（--policy=strict，启用完整风险阈值与审批挑战）。
	PolicyProfileStrictOperator
	// PolicyProfileStrictAgent 表示 MCP / AI Agent 严格熔断模式（终态审计失败立即不可逆进入 Halted 态）。
	PolicyProfileStrictAgent
)

// ParsePolicyProfile 严格解析规范小写策略配置档文本（"direct_operator"、"strict"、"strict_operator"、"strict_agent"）。
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

// IsValid 报告 p 是否为合法的安全策略配置档。
func (p PolicyProfile) IsValid() bool {
	return p >= PolicyProfileDirectOperator && p <= PolicyProfileStrictAgent
}

// IsZero 报告 p 是否处于无效零值态。
func (p PolicyProfile) IsZero() bool { return p == PolicyProfileInvalid }

// String 返回配置档的规范小写文本；非法值返回 "invalid"。
func (p PolicyProfile) String() string {
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

// AppendText 实现 encoding.TextAppender（值接收者）；对非法值失败关闭。
func (p PolicyProfile) AppendText(b []byte) ([]byte, error) {
	return appendValidEnumText(b, p.IsValid(), p.String(), ErrInvalidProfile, uint8(p))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (p PolicyProfile) MarshalText() ([]byte, error) { return p.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 PolicyProfileInvalid。
func (p *PolicyProfile) UnmarshalText(text []byte) error {
	return unmarshalEnumText(p, PolicyProfileInvalid, text, ErrInvalidProfile, ParsePolicyProfile)
}

func (p PolicyProfile) toGateProfile() (gate.PolicyProfileKind, error) {
	switch p {
	case PolicyProfileDirectOperator:
		return gate.PolicyProfileDirectOperator, nil
	case PolicyProfileStrictOperator:
		return gate.PolicyProfileStrictOperator, nil
	case PolicyProfileStrictAgent:
		return gate.PolicyProfileStrictAgent, nil
	default:
		return gate.PolicyProfileInvalid, fmt.Errorf("%w: %d", ErrInvalidProfile, uint8(p))
	}
}

// NoElicitFallback 定义护栏要求人工审批但运行环境不可交互时的回退行为；
// 零值恒为 NoElicitFallbackDeny（严格失败关闭，严禁静默放行）。
//
//xops:opaque
//xops:failclosed
type NoElicitFallback uint8

const (
	// NoElicitFallbackDeny 为零值失败关闭策略：不可交互时直接拒绝并写入审计。
	NoElicitFallbackDeny NoElicitFallback = iota
	// NoElicitFallbackChallenge 表示两步挑战模式：签发绑定审批信封供调用方二次提交核验。
	NoElicitFallbackChallenge
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

// IsValid 报告 f 是否为合法的不可交互回退策略。
func (f NoElicitFallback) IsValid() bool {
	return f == NoElicitFallbackDeny || f == NoElicitFallbackChallenge
}

// IsZero 报告 f 是否处于零值默认拒绝态。
func (f NoElicitFallback) IsZero() bool { return f == NoElicitFallbackDeny }

// String 返回回退策略的规范小写文本。
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

// AppendText 实现 encoding.TextAppender（值接收者）；对非法越界值失败关闭。
func (f NoElicitFallback) AppendText(b []byte) ([]byte, error) {
	return appendValidEnumText(b, f.IsValid(), f.String(), ErrInvalidFallback, uint8(f))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (f NoElicitFallback) MarshalText() ([]byte, error) { return f.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 NoElicitFallbackDeny。
func (f *NoElicitFallback) UnmarshalText(text []byte) error {
	return unmarshalEnumText(f, NoElicitFallbackDeny, text, ErrInvalidFallback, ParseNoElicitFallback)
}

func (f NoElicitFallback) toGateFallback() (gate.NoElicitFallback, error) {
	switch f {
	case NoElicitFallbackDeny:
		return gate.NoElicitFallbackDeny, nil
	case NoElicitFallbackChallenge:
		return gate.NoElicitFallbackChallenge, nil
	default:
		return gate.NoElicitFallbackDeny, fmt.Errorf("%w: %d", ErrInvalidFallback, uint8(f))
	}
}

// RequestTTYMode 标识 SSH 会话的伪终端分配策略（对应 OpenSSH RequestTTY auto/yes/no/force 与 -t/-tt/-T）；
// 零值 RequestTTYUnset 在运行期按操作类型取确定性默认（交互 Shell=auto，单命令=no）。
//
//xops:opaque
//xops:failclosed
type RequestTTYMode uint8

const (
	// RequestTTYUnset 表示未显式设置（零值）。
	RequestTTYUnset RequestTTYMode = iota
	// RequestTTYAuto 表示自动模式：仅交互 Shell 且本机为交互终端时分配 PTY。
	RequestTTYAuto
	// RequestTTYYes 表示本机为交互终端时分配 PTY（对应 -t）。
	RequestTTYYes
	// RequestTTYNo 表示禁止分配 PTY（对应 -T）。
	RequestTTYNo
	// RequestTTYForce 表示强制分配远端 PTY，即使本机非交互终端（对应 -tt）。
	RequestTTYForce
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

// IsValid 报告 m 是否为已显式设置的合法 RequestTTYMode。
func (m RequestTTYMode) IsValid() bool { return m >= RequestTTYAuto && m <= RequestTTYForce }

// IsZero 报告 m 是否处于未设置零值态。
func (m RequestTTYMode) IsZero() bool { return m == RequestTTYUnset }

// String 返回规范小写名称；未设置或非法返回 "unset"。
func (m RequestTTYMode) String() string {
	switch m {
	case RequestTTYAuto:
		return "auto"
	case RequestTTYYes:
		return "yes"
	case RequestTTYNo:
		return "no"
	case RequestTTYForce:
		return "force"
	default:
		return "unset"
	}
}

// AppendText 实现 encoding.TextAppender（值接收者）；对未设置/非法值失败关闭。
func (m RequestTTYMode) AppendText(b []byte) ([]byte, error) {
	return appendValidEnumText(b, m.IsValid(), m.String(), ErrInvalidRequestTTY, uint8(m))
}

// MarshalText 实现 encoding.TextMarshaler（值接收者）。
func (m RequestTTYMode) MarshalText() ([]byte, error) { return m.AppendText(nil) }

// UnmarshalText 实现 encoding.TextUnmarshaler；失败时重置为 RequestTTYUnset。
func (m *RequestTTYMode) UnmarshalText(text []byte) error {
	return unmarshalEnumText(m, RequestTTYUnset, text, ErrInvalidRequestTTY, ParseRequestTTYMode)
}

func (m RequestTTYMode) toSessionTTYMode() (ucsess.RequestTTYMode, error) {
	switch m {
	case RequestTTYUnset:
		return ucsess.RequestTTYUnset, nil
	case RequestTTYAuto:
		return ucsess.RequestTTYAuto, nil
	case RequestTTYYes:
		return ucsess.RequestTTYYes, nil
	case RequestTTYNo:
		return ucsess.RequestTTYNo, nil
	case RequestTTYForce:
		return ucsess.RequestTTYForce, nil
	default:
		return ucsess.RequestTTYUnset, fmt.Errorf("%w: %d", ErrInvalidRequestTTY, uint8(m))
	}
}

// HaltInfo 描述 Engine 底层安全门控首次进入不可逆 Halted 熔断态时的只读诊断快照（ADR-008）；
// 零值恒无效并失败关闭。
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

// OnHaltFunc 是 Engine 进入不可逆 Halted 熔断态且已通知连接池吊销全部句柄后，
// 在锁外线性化触发至多一次的可选外部通知回调。
type OnHaltFunc func(info HaltInfo)

func haltInfoFromGate(info gate.HaltInfo) HaltInfo {
	if !info.IsValid() {
		return HaltInfo{}
	}
	return HaltInfo{
		processID:   info.ProcessID().String(),
		operationID: info.OperationID(),
		reason:      info.Reason(),
		cause:       info.Cause(),
		haltedAt:    info.HaltedAt(),
		valid:       true,
	}
}

// IsValid 报告熔断诊断快照是否有效。
func (h HaltInfo) IsValid() bool {
	return h.valid && h.processID != "" && h.reason != "" && !h.haltedAt.IsZero()
}

// IsZero 报告熔断诊断快照是否为无效零值。
func (h HaltInfo) IsZero() bool { return !h.IsValid() }

// ProcessID 返回触发熔断时的运行期进程实例标识文本。
func (h HaltInfo) ProcessID() string {
	if !h.IsValid() {
		return ""
	}
	return h.processID
}

// OperationID 返回导致熔断的操作标识（若由特定操作终态审计写失败触发）。
func (h HaltInfo) OperationID() algebraic.Option[security.OperationID] {
	if !h.IsValid() {
		return algebraic.None[security.OperationID]()
	}
	return h.operationID
}

// Reason 返回脱敏后的熔断原因摘要。
func (h HaltInfo) Reason() string {
	if !h.IsValid() {
		return ""
	}
	return h.reason
}

// Cause 返回触发熔断的底层错误根因。
func (h HaltInfo) Cause() error {
	if !h.IsValid() {
		return nil
	}
	return h.cause
}

// HaltedAt 返回进入熔断态的 UTC 时间戳。
func (h HaltInfo) HaltedAt() time.Time {
	if !h.IsValid() {
		return time.Time{}
	}
	return h.haltedAt
}

// ReconcileReport 封装启动期 O(1) 跨进程崩溃审计对账的不可变汇总报告（ADR-008 / RFC §3.4）；
// 零值恒无效并失败关闭，使 cmd/xops 与 entry 层无需接触 core/internal/gate。
//
//xops:opaque
//xops:failclosed
type ReconcileReport struct {
	raw   ports.CrashReconcileReport
	valid bool
}

// IsValid 报告崩溃对账汇总报告是否有效。
func (r ReconcileReport) IsValid() bool { return r.valid && r.raw.IsValid() }

// IsZero 报告崩溃对账汇总报告是否为无效零值。
func (r ReconcileReport) IsZero() bool { return !r.IsValid() }

// ScannedLocks 返回扫描到的进程锁文件总数。
func (r ReconcileReport) ScannedLocks() int {
	if !r.IsValid() {
		return 0
	}
	return r.raw.ScannedLocks()
}

// LiveLocksSkipped 返回因原进程仍存活而跳过的锁文件数量。
func (r ReconcileReport) LiveLocksSkipped() int {
	if !r.IsValid() {
		return 0
	}
	return r.raw.LiveLocksSkipped()
}

// DeadLocksClaimed 返回成功非阻塞抢占并完成清理的残留死亡进程锁数量。
func (r ReconcileReport) DeadLocksClaimed() int {
	if !r.IsValid() {
		return 0
	}
	return r.raw.DeadLocksClaimed()
}

// AbortedOperations 返回慢路径补写 AbortedByCrash 的未闭合操作标识拷贝。
func (r ReconcileReport) AbortedOperations() []security.OperationID {
	if !r.IsValid() {
		return nil
	}
	return r.raw.AbortedOperations()
}

// Equal 比较两份对账报告是否均有效且内容一致。
func (r ReconcileReport) Equal(other ReconcileReport) bool {
	return r.IsValid() && other.IsValid() && r.raw.Equal(other.raw)
}

// ResolvedTarget 封装目标解析产出的不可变来源证明、生效策略与 Merkle 链式连接计划；
// 零值恒无效并失败关闭，供 entry/cli 进行展示或直接二次传入 Exec/InteractiveSSH/RunSSH。
//
//xops:opaque
//xops:failclosed
type ResolvedTarget struct {
	inner ucinv.ResolvedTarget
	valid bool
}

// IsValid 报告 ResolvedTarget 是否经 Engine.ResolveTarget 合法编译产出。
func (r ResolvedTarget) IsValid() bool { return r.valid && r.inner.IsValid() }

// IsZero 报告 ResolvedTarget 是否处于无效零值态。
func (r ResolvedTarget) IsZero() bool { return !r.IsValid() }

// NodeID 返回目标主机的原始标识名（别名或规范主机名）。
func (r ResolvedTarget) NodeID() string {
	if !r.IsValid() {
		return ""
	}
	return r.inner.NodeID()
}

// Origin 返回封闭来源和类型（*inventory.OriginAdHoc 或 *inventory.OriginOpenSSHVirtual）。
func (r ResolvedTarget) Origin() inventory.NodeOrigin {
	if !r.IsValid() {
		return nil
	}
	return r.inner.Origin()
}

// OriginKind 返回来源枚举标签；无效零值返回 option.OriginInvalid。
func (r ResolvedTarget) OriginKind() option.OriginKind {
	if !r.IsValid() {
		return option.OriginInvalid
	}
	return r.inner.OriginKind()
}

// Policy 返回末跳四层合并后的不可变生效策略。
func (r ResolvedTarget) Policy() option.EffectivePolicy {
	if !r.IsValid() {
		return zeroVal[option.EffectivePolicy]()
	}
	return r.inner.Policy()
}

// Plan 返回已封缄的不可变单跳或多跳 Merkle 连接计划。
func (r ResolvedTarget) Plan() plan.SealedConnectionPlan {
	if !r.IsValid() {
		return zeroVal[plan.SealedConnectionPlan]()
	}
	return r.inner.Plan()
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
