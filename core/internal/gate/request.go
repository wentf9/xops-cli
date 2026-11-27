package gate

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
)

// CanonicalizeResult 携带 Round-2 远端规范化探测（如 SFTP 软链展开）产出的规范绑定与路径集合。
type CanonicalizeResult struct {
	Binding        security.OperationBinding                    // 必填：规范化后的操作绑定（非路径身份字段严禁漂移）
	Paths          []string                                     // 可选：附加规范化直接目标路径（与 Binding.CanonicalPaths 单调去重并集求值）
	RecursivePaths []string                                     // 可选：附加规范化递归目录路径（与 Binding.RecursivePaths 单调去重并集求值）
	Risk           algebraic.Option[security.RiskLevel]         // 可选：规范化阶段识别的风险等级（与词法风险取 Join）
	Verdict        algebraic.Option[security.Verdict]           // 可选：规范化阶段安全判定（与词法判定取 Meet）
	DecisionFloor  algebraic.Option[security.GuardrailDecision] // 可选：规范化阶段附加最严决策下限
}

// CanonicalizeFunc 执行 Round-2 远端路径规范化探测并返回规范绑定与作用域输入。
type CanonicalizeFunc func(ctx context.Context) (CanonicalizeResult, error)

// ApprovalSubmissionSpec 是构造不可变两步审批提交载荷 ApprovalSubmission 的入参规格。
type ApprovalSubmissionSpec struct {
	Envelope algebraic.Option[security.ApprovalEnvelope] // 可选：客户端回传的完整审批信封（若提供则校验与挂起挑战一致）
	Response ports.ApprovalDecisionResponse              // 必填：锚定信封 SHA-256 摘要的用户审批回执
}

// ApprovalSubmission 表示两步审批流程中客户端回传的不可变审批提交对象（INV-E5）；
// 零值恒无效并严格失败关闭。
//
//xops:opaque
//xops:failclosed
type ApprovalSubmission struct {
	envelope algebraic.Option[security.ApprovalEnvelope]
	response ports.ApprovalDecisionResponse
	valid    bool
}

// NewApprovalSubmission 校验审批回执及可选完整信封后构造不可变 ApprovalSubmission。
func NewApprovalSubmission(spec ApprovalSubmissionSpec) (ApprovalSubmission, error) {
	if !spec.Response.IsValid() {
		return ApprovalSubmission{}, domi18n.EF(ErrApprovalMismatch, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ApprovalDecisionResponse"))
	}
	if env, ok := spec.Envelope.Get(); ok {
		if !env.IsValid() {
			return ApprovalSubmission{}, domi18n.EF(ErrApprovalMismatch, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ApprovalEnvelope"))
		}
	}
	return ApprovalSubmission{
		envelope: spec.Envelope,
		response: spec.Response,
		valid:    true,
	}, nil
}

// IsValid 报告审批提交对象是否有效。
func (s ApprovalSubmission) IsValid() bool {
	if !s.valid || !s.response.IsValid() {
		return false
	}
	if env, ok := s.envelope.Get(); ok && !env.IsValid() {
		return false
	}
	return true
}

// IsZero 报告审批提交对象是否为无效零值。
func (s ApprovalSubmission) IsZero() bool { return !s.IsValid() }

// Envelope 返回可选审批信封快照。
func (s ApprovalSubmission) Envelope() algebraic.Option[security.ApprovalEnvelope] {
	if !s.IsValid() {
		return algebraic.None[security.ApprovalEnvelope]()
	}
	return s.envelope
}

// Response 返回绑定的审批决策回执。
func (s ApprovalSubmission) Response() ports.ApprovalDecisionResponse {
	if !s.IsValid() {
		return zeroVal[ports.ApprovalDecisionResponse]()
	}
	return s.response
}

// GateRequestSpec 是构造强类型不可变授权请求 GateRequest[C] 的显式入参规格。
type GateRequestSpec[C security.Capability] struct {
	TraceID         algebraic.Option[security.TraceID]           // 可选：显式链路标识（None 时优先继承 ctx，否则由 Entropy 生成）
	OperationID     algebraic.Option[security.OperationID]       // 可选：显式操作标识（None 时由 Entropy 生成；两步审批时须匹配信封）
	Binding         security.OperationBinding                    // 必填：不可变规范绑定，其 Capability 必须严格等于 C
	Risk            security.RiskLevel                           // 必填：操作基准风险等级（严禁 RiskUnknown）
	Verdict         algebraic.Option[security.Verdict]           // 可选：调用方前置二值判定（None 默认 VerdictAllow）
	DecisionFloor   algebraic.Option[security.GuardrailDecision] // 可选：调用方附加最严护栏决策下限
	ScopeSummary    string                                       // 可选：审批提示与审计摘要（为空时按 Binding 自动生成）
	Paths           []string                                     // 可选：词法阶段附加直接目标路径（与 Binding.CanonicalPaths 单调去重并集求值）
	RecursivePaths  []string                                     // 可选：词法阶段附加递归目录路径（与 Binding.RecursivePaths 单调去重并集求值）
	Canonicalize    CanonicalizeFunc                             // 可选：Round-2 规范化回调（启用两阶段升级检测）
	Approval        algebraic.Option[ApprovalSubmission]         // 可选：两步审批流程回传的审批回执
	OperationStream *events.OperationStream                      // 可选：单操作隔离事件流（用于发射审批挑战与 FSM 转移事件，并自动对齐/继承 TraceID 与 OperationID）
}

// GateRequest 携带与编译期幻影能力 C 强绑定的不可变授权请求；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type GateRequest[C security.Capability] struct {
	raw   rawGateRequest
	valid bool
}

// rawGateRequest 为包内统一的擦除泛型后请求载体，供封闭接口 Authorizer.evaluateAndAudit 消费。
type rawGateRequest struct {
	capKind        security.CapabilityKind
	traceID        algebraic.Option[security.TraceID]
	operationID    algebraic.Option[security.OperationID]
	binding        security.OperationBinding
	risk           security.RiskLevel
	verdict        security.Verdict
	decisionFloor  algebraic.Option[security.GuardrailDecision]
	scopeSummary   string
	paths          []string
	recursivePaths []string
	canonicalize   CanonicalizeFunc
	approval       algebraic.Option[ApprovalSubmission]
	opStream       *events.OperationStream
	valid          bool
}

// NewGateRequest 校验幻影能力 C 与 Binding.Capability 一致性及全部可选字段不变量，构造不可变 GateRequest[C]。
func NewGateRequest[C security.Capability](spec GateRequestSpec[C]) (GateRequest[C], error) {
	capKind := security.CapabilityKindOf[C]()
	if !capKind.IsValid() {
		return GateRequest[C]{}, domi18n.EF(ErrCapabilityMismatch, domi18n.KeyGateAbstractCapability)
	}
	if !spec.Binding.IsValid() {
		return GateRequest[C]{}, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "OperationBinding"))
	}
	if spec.Binding.Capability() != capKind {
		return GateRequest[C]{}, domi18n.EF(ErrCapabilityMismatch, domi18n.KeyCommonMismatch, domi18n.Str("field", "capability"), domi18n.Str("expected", capKind.String()), domi18n.Str("actual", spec.Binding.Capability().String()))
	}
	if !spec.Risk.IsValid() {
		return GateRequest[C]{}, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "RiskLevel"))
	}
	traceID, opID, err := resolveGateRequestOptionals(
		spec.TraceID, spec.OperationID, spec.Verdict, spec.DecisionFloor, spec.Approval, spec.OperationStream,
	)
	if err != nil {
		return GateRequest[C]{}, err
	}
	verdict := spec.Verdict.OrElse(security.VerdictAllow)
	paths := unionPaths(spec.Binding.CanonicalPaths(), spec.Paths)
	recPaths := unionPaths(spec.Binding.RecursivePaths(), spec.RecursivePaths)
	summary := buildScopeSummary(spec.ScopeSummary, spec.Binding)

	return GateRequest[C]{
		raw: rawGateRequest{
			capKind:        capKind,
			traceID:        traceID,
			operationID:    opID,
			binding:        spec.Binding,
			risk:           spec.Risk,
			verdict:        verdict,
			decisionFloor:  spec.DecisionFloor,
			scopeSummary:   summary,
			paths:          paths,
			recursivePaths: recPaths,
			canonicalize:   spec.Canonicalize,
			approval:       spec.Approval,
			opStream:       spec.OperationStream,
			valid:          true,
		},
		valid: true,
	}, nil
}

// resolveGateRequestOptionals 校验全部可选字段有效性，并在提供 OperationStream 时严格校验显式 ID
// （含审批信封 OperationID）一致性且自动继承未设置的 TraceID/OperationID，防止事件因 ID 失配静默丢弃。
func resolveGateRequestOptionals(
	tid algebraic.Option[security.TraceID],
	opID algebraic.Option[security.OperationID],
	verdict algebraic.Option[security.Verdict],
	floor algebraic.Option[security.GuardrailDecision],
	approval algebraic.Option[ApprovalSubmission],
	opStream *events.OperationStream,
) (algebraic.Option[security.TraceID], algebraic.Option[security.OperationID], error) {
	noneT, noneO := algebraic.None[security.TraceID](), algebraic.None[security.OperationID]()
	if optInvalid(tid) || optInvalid(opID) || optInvalid(verdict) || optInvalid(approval) {
		return noneT, noneO, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "optional request field"))
	}
	if fl, ok := floor.Get(); ok && (fl == nil || !fl.IsValid()) {
		return noneT, noneO, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "decision_floor"))
	}
	if opStream == nil {
		return tid, opID, nil
	}
	return alignIDsWithOperationStream(tid, opID, approval, opStream)
}

func alignIDsWithOperationStream(
	tid algebraic.Option[security.TraceID],
	opID algebraic.Option[security.OperationID],
	approval algebraic.Option[ApprovalSubmission],
	opStream *events.OperationStream,
) (algebraic.Option[security.TraceID], algebraic.Option[security.OperationID], error) {
	noneT, noneO := algebraic.None[security.TraceID](), algebraic.None[security.OperationID]()
	if opStream.IsClosed() {
		return noneT, noneO, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonComponentClosed, domi18n.Str("component", "operation_stream"))
	}
	streamTID, streamOpID := opStream.TraceID(), opStream.OperationID()
	if !streamTID.IsValid() || !streamOpID.IsValid() {
		return noneT, noneO, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "operation_stream binding"))
	}
	if explicitT, ok := tid.Get(); ok && !explicitT.Equal(streamTID) {
		return noneT, noneO, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonMismatch, domi18n.Str("field", "trace_id"), domi18n.Str("expected", streamTID.String()), domi18n.Str("actual", explicitT.String()))
	}
	if explicitO, ok := opID.Get(); ok && !explicitO.Equal(streamOpID) {
		return noneT, noneO, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonMismatch, domi18n.Str("field", "operation_id"), domi18n.Str("expected", streamOpID.String()), domi18n.Str("actual", explicitO.String()))
	}
	if sub, ok := approval.Get(); ok {
		if env, hasEnv := sub.Envelope().Get(); hasEnv && !env.OperationID().Equal(streamOpID) {
			return noneT, noneO, domi18n.WrapS(ErrInvalidRequest, ErrApprovalMismatch, domi18n.KeyCommonMismatch, domi18n.Str("field", "envelope OperationID"), domi18n.Str("expected", streamOpID.String()), domi18n.Str("actual", env.OperationID().String()))
		}
	}
	return algebraic.Some(streamTID), algebraic.Some(streamOpID), nil
}

// unionPaths 执行单调去重路径并集（INV-E3 / ADR-014）：始终将 Binding 绑定路径与调用方附加路径一并纳入护栏求值，
// 杜绝通过传入良性显式 Paths 掩盖 Binding 内受保护路径的裂脑绕过。
func unionPaths(bound, explicit []string) []string {
	total := len(bound) + len(explicit)
	if total == 0 {
		return nil
	}
	seen := make(map[string]struct{}, total)
	out := make([]string, 0, total)
	for _, group := range [2][]string{bound, explicit} {
		for _, p := range group {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func buildScopeSummary(raw string, b security.OperationBinding) string {
	clean := sanitizeReason(raw, "")
	if clean != "" {
		return truncateUTF8(clean, maxSummaryBytes)
	}
	node := b.NodeID()
	if node == "" {
		node = "global"
	}
	return truncateUTF8(b.Tool()+"."+b.Action()+" capability="+b.Capability().String()+" node="+node, maxSummaryBytes)
}

// IsValid 报告 GateRequest[C] 是否经合法构造且能力绑定一致。
func (r GateRequest[C]) IsValid() bool {
	capKind := security.CapabilityKindOf[C]()
	return r.valid && r.raw.valid && capKind.IsValid() && r.raw.capKind == capKind &&
		r.raw.binding.IsValid() && r.raw.binding.Capability() == capKind && r.raw.risk.IsValid()
}

// IsZero 报告 GateRequest[C] 是否为无效零值。
func (r GateRequest[C]) IsZero() bool { return !r.IsValid() }

// Binding 返回请求绑定的不可变 OperationBinding。
func (r GateRequest[C]) Binding() security.OperationBinding {
	if !r.IsValid() {
		return zeroVal[security.OperationBinding]()
	}
	return r.raw.binding
}

// Risk 返回请求声明的基准风险等级；无效零值返回 RiskUnknown。
func (r GateRequest[C]) Risk() security.RiskLevel {
	if !r.IsValid() {
		return security.RiskUnknown
	}
	return r.raw.risk
}

// ScopeSummary 返回脱敏后的审批与审计作用域摘要。
func (r GateRequest[C]) ScopeSummary() string {
	if !r.IsValid() {
		return ""
	}
	return r.raw.scopeSummary
}

// outcomeRecorder 维护单次授权调用期内由回调显式上报的执行结果（支持并发只增不降：OutcomeUnknown 不可逆）。
type outcomeRecorder struct {
	mu      sync.Mutex
	outcome execution.ExecutionOutcome
}

func (r *outcomeRecorder) record(out execution.ExecutionOutcome) error {
	if r == nil || out == nil || !out.IsValid() {
		return ErrInvalidOutcome
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// 一旦记录了 OutcomeUnknown，严禁被后续任何结果降级覆盖（INV-C6 / ADR-016）。
	if r.outcome != nil && r.outcome.Kind() == execution.OutcomeKindUnknown {
		return nil
	}
	r.outcome = out
	return nil
}

func (r *outcomeRecorder) load() execution.ExecutionOutcome {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	out := r.outcome
	r.mu.Unlock()
	return out
}

// issuedPermit 保存 evaluateAndAudit 签发给 WithAuthorized 与 finalizeAudit 的内部授权凭证上下文。
type issuedPermit struct {
	traceID   security.TraceID
	opID      security.OperationID
	binding   security.OperationBinding
	profile   PolicyProfileKind
	risk      security.RiskLevel
	decision  security.DecisionKind
	startedAt time.Time
	handleSeq uint64
	revoked   *atomic.Bool
	recorder  *outcomeRecorder
	opStream  *events.OperationStream
	valid     bool
}

func (p issuedPermit) revoke() {
	if p.revoked != nil {
		p.revoked.Store(true)
	}
}
