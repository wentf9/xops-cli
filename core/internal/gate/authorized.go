package gate

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync/atomic"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
)

// Authorized 是由 core/internal/gate 物理独占定义与签发的编译期强类型能力证明（ADR-008 / RFC §3.1）。
//
// 不变式与防绕过机制：
//   - 全字段未导出且标注 //xops:opaque 与 //xops:failclosed，全仓任何外部包均无法构造有效实例；
//   - 同时内置正向有效门控 valid bool 与吊销原子标志 revoked *atomic.Bool：零值恒无效且已吊销；
//   - 退出 WithAuthorized 回调或 Gate 进入 Halted 熔断态的瞬间立即置 revoked=true，
//     阻断借用句柄在作用域外或熔断后的任何残留消费；
//   - 仅当类型参数 C 为具体幻影能力（CapInspect..CapMutate）且与 binding.Capability() 一致时有效，
//     擦除接口类型 Authorized[security.Capability] 恒失败关闭。
//
//xops:opaque
//xops:failclosed
type Authorized[C security.Capability] struct {
	traceID  security.TraceID
	opID     security.OperationID
	binding  security.OperationBinding
	profile  PolicyProfileKind
	risk     security.RiskLevel
	recorder *outcomeRecorder
	valid    bool         // 正向有效门控（零值恒无效，兼容 failclosed 对 atomic.Bool 检查）
	revoked  *atomic.Bool // 退出回调或 Gate 进入 Halted 熔断态立即置 true
}

// IsValid 报告能力证明是否经合法签发、未吊销、能力类型具体匹配且全部核心标识有效。
func (a Authorized[C]) IsValid() bool {
	capKind := security.CapabilityKindOf[C]()
	return a.valid && a.revoked != nil && !a.revoked.Load() &&
		capKind.IsValid() && a.traceID.IsValid() && a.opID.IsValid() &&
		a.binding.IsValid() && a.binding.Capability() == capKind &&
		a.profile.IsValid() && a.risk.IsValid()
}

// IsZero 报告能力证明是否为未初始化零值。
func (a Authorized[C]) IsZero() bool { return !a.valid || a.revoked == nil }

// IsRevoked 报告能力证明是否已吊销或未初始化（零值失败关闭返回 true）。
func (a Authorized[C]) IsRevoked() bool { return !a.valid || a.revoked == nil || a.revoked.Load() }

// Validate 以地道 Go error 形式核验当前能力证明是否仍处于活跃有效态，供用例服务与连接池边界调用。
func (a Authorized[C]) Validate() error {
	if !a.valid || a.revoked == nil {
		return ErrInvalidPermit
	}
	if a.revoked.Load() {
		return ErrPermitRevoked
	}
	if !a.IsValid() {
		return ErrInvalidPermit
	}
	return nil
}

// Capability 返回与当前能力证明强绑定的运行期能力类别；无效或已吊销时返回 CapabilityInvalid。
func (a Authorized[C]) Capability() security.CapabilityKind {
	if !a.IsValid() {
		return security.CapabilityInvalid
	}
	return a.binding.Capability()
}

// TraceID 返回当前授权操作绑定的链路追踪标识；无效或已吊销时返回零值。
func (a Authorized[C]) TraceID() security.TraceID {
	if !a.IsValid() {
		return zeroVal[security.TraceID]()
	}
	return a.traceID
}

// OperationID 返回当前授权操作绑定的唯一操作标识；无效或已吊销时返回零值。
func (a Authorized[C]) OperationID() security.OperationID {
	if !a.IsValid() {
		return zeroVal[security.OperationID]()
	}
	return a.opID
}

// Binding 返回当前授权操作绑定的不可变规范操作快照；无效或已吊销时返回零值。
func (a Authorized[C]) Binding() security.OperationBinding {
	if !a.IsValid() {
		return zeroVal[security.OperationBinding]()
	}
	return a.binding
}

// Profile 返回签发本证明时的安全策略配置档；无效或已吊销时返回 PolicyProfileInvalid。
func (a Authorized[C]) Profile() PolicyProfileKind {
	if !a.IsValid() {
		return PolicyProfileInvalid
	}
	return a.profile
}

// Risk 返回本次授权最终生效的风险等级；无效或已吊销时返回 RiskUnknown。
func (a Authorized[C]) Risk() security.RiskLevel {
	if !a.IsValid() {
		return security.RiskUnknown
	}
	return a.risk
}

// ReportOutcome 允许受权回调向 WithAuthorized 上报强类型 execution.ExecutionOutcome，
// 确保 *execution.OutcomeUnknown 在终态审计中严格映射为 ports.AuditOutcomeUnknown（严禁降级）。
func (a Authorized[C]) ReportOutcome(outcome execution.ExecutionOutcome) error {
	if err := a.Validate(); err != nil {
		return err
	}
	return a.recorder.record(outcome)
}

// Authorizer 定义物理封闭于 core/internal/gate 的能力门控授权器抽象（RFC §3.1），
// 供用例服务与 MCP 运行时以接口依赖注入，同时由 Go 包可见性彻底封死外部伪造实现。
type Authorizer interface {
	// IsHalted 报告底层门控是否已进入不可逆 Halted 熔断态。
	IsHalted() bool
	// Profile 返回底层门控绑定的策略配置档。
	Profile() PolicyProfileKind

	evaluateAndAudit(ctx context.Context, req rawGateRequest) (issuedPermit, error)
	finalizeAudit(ctx context.Context, permit issuedPermit, runErr error) error
	isHalted() bool
}

// WithAuthorized 是全仓唯一签发强类型能力证明 Authorized[C] 的包级泛型作用域门控函数（ADR-008 / RFC §3.1）。
//
// 执行契约（Plan §4.4 / ADR-011）：
//  1. 严格失败关闭校验：拒绝 nil ctx、nil/typed-nil Authorizer、nil run、无效请求、
//     擦除接口类型参数 C=security.Capability 与能力不匹配；
//  2. 严格按 Stage(+opID) -> Audit(Authorized) -> run(opCtx, auth) -> Audit(Finalized) -> Unstage(-opID) 推进；
//  3. 无论正常返回、错误、上下文取消、panic 还是 runtime.Goexit，退出前均立即吊销 auth 并闭合终态审计，
//     实现进程内零孤儿审计记录；panic 在完成吊销与终态审计后原样继续向上传播；
//  4. 标注 //xops:syncclosure 与 //xops:borrowed，由 xopsvet/linearlease 在编译期静态阻断 auth 逃逸闭包；
//  5. 严禁注入 trace.LeaseScope（该作用域仅归属 core/internal/pool，遵循 ADR-009 嵌套序）。
//
//xops:syncclosure
//xops:borrowed
func WithAuthorized[C security.Capability](
	ctx context.Context,
	g Authorizer,
	req GateRequest[C],
	run func(ctx context.Context, auth Authorized[C]) error,
) error {
	if err := validateWithAuthorizedInputs(ctx, g, req, run); err != nil {
		return err
	}
	permit, err := g.evaluateAndAudit(ctx, req.raw)
	if err != nil {
		return err
	}
	opCtx, traceErr := trace.WithTrace(ctx, permit.traceID, permit.opID)
	if traceErr != nil {
		permit.revoke()
		return g.finalizeAudit(ctx, permit, traceErr)
	}
	auth := Authorized[C]{
		traceID:  permit.traceID,
		opID:     permit.opID,
		binding:  permit.binding,
		profile:  permit.profile,
		risk:     permit.risk,
		recorder: permit.recorder,
		valid:    true,
		revoked:  permit.revoked,
	}
	return executeAuthorizedScope(ctx, opCtx, g, permit, auth, run)
}

func validateWithAuthorizedInputs[C security.Capability](
	ctx context.Context,
	g Authorizer,
	req GateRequest[C],
	run func(ctx context.Context, auth Authorized[C]) error,
) error {
	if ctx == nil {
		return ErrNilContext
	}
	if g == nil {
		return ErrNilAuthorizer
	}
	if run == nil {
		return ErrNilCallback
	}
	capKind := security.CapabilityKindOf[C]()
	if !capKind.IsValid() {
		return fmt.Errorf("%w: 禁止以未具象化 Capability 接口调用 WithAuthorized", ErrCapabilityMismatch)
	}
	if !req.IsValid() {
		return ErrInvalidRequest
	}
	if req.raw.capKind != capKind || req.raw.binding.Capability() != capKind {
		return fmt.Errorf("%w: 能力类型 %s 与请求绑定 %s 不一致", ErrCapabilityMismatch, capKind, req.raw.binding.Capability())
	}
	return nil
}

func executeAuthorizedScope[C security.Capability](
	parentCtx context.Context,
	opCtx context.Context,
	g Authorizer,
	permit issuedPermit,
	auth Authorized[C],
	run func(ctx context.Context, auth Authorized[C]) error,
) error {
	completed := false
	defer func() {
		if completed {
			return
		}
		r := recover()
		permit.revoke()
		var abortErr error
		if r != nil {
			abortErr = newOperationPanicError(r, debug.Stack())
		} else {
			abortErr = ErrOperationAborted
		}
		// 异常退场路径同样强制闭合终态审计并触发熔断检查，杜绝孤儿审计记录。
		_ = g.finalizeAudit(parentCtx, permit, abortErr)
		if r != nil {
			panic(r)
		}
	}()
	runErr := run(opCtx, auth)
	completed = true
	permit.revoke()
	return g.finalizeAudit(parentCtx, permit, runErr)
}

// OutcomeCarrier 允许领域或用例层错误携带强类型 execution.ExecutionOutcome，
// 供 WithAuthorized 通过 errors.AsType[OutcomeCarrier] 无损保留 OutcomeUnknown 语义。
type OutcomeCarrier interface {
	error
	ExecutionOutcome() execution.ExecutionOutcome
}

// OutcomeError 将强类型 execution.ExecutionOutcome 与根因错误封装为标准错误链（INV-C6 / ADR-016）；
// 零值与 typed-nil 均安全失败关闭。
//
//xops:opaque
//xops:failclosed
type OutcomeError struct {
	outcome execution.ExecutionOutcome
	cause   error
	valid   bool
}

// WrapOutcomeError 校验 outcome 有效后构造不可变 *OutcomeError；若 cause 为 nil 则以 outcome 类别兜底。
func WrapOutcomeError(outcome execution.ExecutionOutcome, cause error) (*OutcomeError, error) {
	if outcome == nil || !outcome.IsValid() {
		return nil, ErrInvalidOutcome
	}
	return &OutcomeError{outcome: outcome, cause: cause, valid: true}, nil
}

// OutcomeError 只读访问器与标准错误接口实现（nil 与无效零值安全失败关闭）。
func (e *OutcomeError) IsValid() bool {
	return e != nil && e.valid && e.outcome != nil && e.outcome.IsValid()
}
func (e *OutcomeError) ExecutionOutcome() execution.ExecutionOutcome {
	if !e.IsValid() {
		return nil
	}
	return e.outcome
}
func (e *OutcomeError) Unwrap() error {
	if !e.IsValid() {
		return nil
	}
	return e.cause
}
func (e *OutcomeError) Error() string {
	if !e.IsValid() {
		return ErrInvalidOutcome.Error()
	}
	if e.cause == nil {
		return fmt.Sprintf("gate: execution outcome=%s", e.outcome.Kind())
	}
	return fmt.Sprintf("gate: execution outcome=%s: %v", e.outcome.Kind(), e.cause)
}

// OperationPanicError 记录受权回调发生 panic 时的原始值与堆栈，用于终态审计归因。
//
//xops:opaque
//xops:failclosed
type OperationPanicError struct {
	value any
	stack []byte
	valid bool
}

func newOperationPanicError(val any, stack []byte) *OperationPanicError {
	cp := make([]byte, len(stack))
	copy(cp, stack)
	return &OperationPanicError{value: val, stack: cp, valid: true}
}

func (e *OperationPanicError) IsValid() bool { return e != nil && e.valid }
func (e *OperationPanicError) Unwrap() error {
	if !e.IsValid() {
		return nil
	}
	return ErrOperationPanicked
}
func (e *OperationPanicError) Error() string {
	if !e.IsValid() {
		return ErrOperationPanicked.Error()
	}
	return fmt.Sprintf("%s: %v", ErrOperationPanicked.Error(), e.value)
}

// ApprovalChallengeError 承载两步审批回退模式（NoElicitFallbackChallenge）签发的不可变 ApprovalEnvelope，
// 实现 Unwrap() -> ErrApprovalRequired，使外部宿主（如 MCP）可直接展示并回传审批回执。
//
//xops:opaque
//xops:failclosed
type ApprovalChallengeError struct {
	envelope  security.ApprovalEnvelope
	digest    security.Digest
	escalated bool
	reason    string
	valid     bool
}

func newApprovalChallengeError(env security.ApprovalEnvelope, dig security.Digest, escalated bool, reason string) *ApprovalChallengeError {
	return &ApprovalChallengeError{
		envelope: env, digest: dig, escalated: escalated,
		reason: sanitizeReason(reason, "approval required"), valid: env.IsValid() && dig.IsValid(),
	}
}

// ApprovalChallengeError 只读访问器与标准错误接口（Unwrap 返回 ErrApprovalRequired，nil 安全）。
func (e *ApprovalChallengeError) IsValid() bool {
	return e != nil && e.valid && e.envelope.IsValid() && e.digest.IsValid()
}
func (e *ApprovalChallengeError) Envelope() security.ApprovalEnvelope {
	if !e.IsValid() {
		return zeroVal[security.ApprovalEnvelope]()
	}
	return e.envelope
}
func (e *ApprovalChallengeError) EnvelopeDigest() security.Digest {
	if !e.IsValid() {
		return zeroVal[security.Digest]()
	}
	return e.digest
}
func (e *ApprovalChallengeError) Escalated() bool { return e.IsValid() && e.escalated }
func (e *ApprovalChallengeError) Reason() string {
	if !e.IsValid() {
		return ""
	}
	return e.reason
}
func (e *ApprovalChallengeError) Unwrap() error {
	if !e.IsValid() {
		return nil
	}
	return ErrApprovalRequired
}
func (e *ApprovalChallengeError) Error() string {
	if !e.IsValid() {
		return ErrApprovalRequired.Error()
	}
	return fmt.Sprintf("%s (op=%s, escalated=%v): %s", ErrApprovalRequired.Error(), e.envelope.OperationID(), e.escalated, e.reason)
}
