package events

import (
	"bytes"
	"maps"
	"math"
	"slices"
	"strconv"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// Event 是 XOps v2 全域作用域事件流的封闭代数和类型（ADR-010 / RFC §3.6）。
// 仅限本包内 12 个不可变指针变体实现，由 xopsvet/sumexhaust 静态强制全仓 type switch 穷尽覆盖与 fail-closed default。
//
//xops:failclosed
type Event interface {
	sealedEvent()
	rawBase() (EventKind, EventClass, EventMeta)
	Kind() EventKind
	Class() EventClass
	Backpressure() BackpressurePolicy
	CoalesceKey() string
	Meta() EventMeta
	IsValid() bool
}

// sealedEventMixin 为全部具体事件变体提供未导出封闭标记、共享元数据与正向门控 valid bool。
// 命名以 sealed 前缀开头，xopsvet/sumexhaust 自动识别为混入标记而非业务变体；指针接收者确保仅 *Variant 满足 Event。
type sealedEventMixin struct {
	kind  EventKind
	class EventClass
	meta  EventMeta
	valid bool
}

func (*sealedEventMixin) sealedEvent() {}
func (m *sealedEventMixin) rawBase() (EventKind, EventClass, EventMeta) {
	return m.kind, m.class, m.meta
}
func newBase(k EventKind, c EventClass, m EventMeta) sealedEventMixin {
	return sealedEventMixin{k, c, m, true}
}
func (m *sealedEventMixin) baseValid(requireOpID bool) bool {
	return m != nil && m.valid && m.kind.IsValid() && m.class.IsValid() && m.meta.IsValid() &&
		(!requireOpID || m.meta.OperationID().IsSome())
}

// 12 个封闭事件变体的构造输入规格与不可变不透明结构体（全私有字段 + 正向门控 valid bool，零值恒失败关闭）。
type (
	OperationStartedSpec struct {
		Meta         EventMeta
		Capability   security.CapabilityKind
		Tool, Action string
		PlanDigest   algebraic.Option[plan.PlanDigest]
		Summary      string
	}
	//xops:opaque
	//xops:failclosed
	OperationStartedEvent struct {
		sealedEventMixin
		capability        security.CapabilityKind
		tool, action, sum string
		planDigest        algebraic.Option[plan.PlanDigest]
	}

	OperationCompletedSpec struct {
		Meta          EventMeta
		Capability    security.CapabilityKind
		Duration      algebraic.Duration
		Outcome       algebraic.Option[execution.ExecutionOutcome]
		Succeeded     bool
		Code, Message string
	}
	//xops:opaque
	//xops:failclosed
	OperationCompletedEvent struct {
		sealedEventMixin
		capability    security.CapabilityKind
		duration      algebraic.Duration
		outcome       algebraic.Option[execution.ExecutionOutcome]
		succeeded     bool
		code, message string
	}

	OutputChunkSpec struct {
		Meta       EventMeta
		Stream     OutputStreamKind
		ChunkIndex uint64
		Data       []byte
		Truncated  bool
	}
	//xops:opaque
	//xops:failclosed
	OutputChunkEvent struct {
		sealedEventMixin
		stream     OutputStreamKind
		chunkIndex uint64
		data       []byte
		truncated  bool
	}

	StepEventSpec struct {
		Meta       EventMeta
		PlaybookID algebraic.Option[playbook.PlaybookID]
		StepID     playbook.StepID
		Status     playbook.StepStatus
		Duration   algebraic.Duration
		Outcome    algebraic.Option[execution.ExecutionOutcome]
		Message    string
	}
	//xops:opaque
	//xops:failclosed
	StepEvent struct {
		sealedEventMixin
		playbookID algebraic.Option[playbook.PlaybookID]
		stepID     playbook.StepID
		status     playbook.StepStatus
		duration   algebraic.Duration
		outcome    algebraic.Option[execution.ExecutionOutcome]
		message    string
	}

	FSMTransitionSpec struct {
		Meta                          EventMeta
		Machine                       FSMMachineKind
		FromState, ToState, EventName string
		Detail                        string
		Terminal                      bool
	}
	//xops:opaque
	//xops:failclosed
	FSMTransitionEvent struct {
		sealedEventMixin
		machine                               FSMMachineKind
		fromState, toState, eventName, detail string
		terminal                              bool
	}

	ApprovalChallengeSpec struct {
		Meta      EventMeta
		Envelope  security.ApprovalEnvelope
		Phase     fsm.ApprovalPhase
		Escalated bool
		Reason    string
	}
	//xops:opaque
	//xops:failclosed
	ApprovalChallengeEvent struct {
		sealedEventMixin
		envelope  security.ApprovalEnvelope
		phase     fsm.ApprovalPhase
		escalated bool
		reason    string
	}

	TransferProgressSpec struct {
		Meta                                          EventMeta
		TransferID                                    security.OperationID
		Direction                                     fsm.TransferDirection
		BytesTransferred, TotalBytes, ChunksCompleted uint64
		Elapsed                                       algebraic.Duration
		RateBytesPerSec                               uint64
		Stage                                         string
	}
	//xops:opaque
	//xops:failclosed
	TransferProgressEvent struct {
		sealedEventMixin
		transferID                                                     security.OperationID
		direction                                                      fsm.TransferDirection
		bytesTransferred, totalBytes, chunksCompleted, rateBytesPerSec uint64
		elapsed                                                        algebraic.Duration
		stage                                                          string
	}

	MetricSampleSpec struct {
		Meta             EventMeta
		MetricName, Unit string
		Value            float64
		Interval         algebraic.Duration
		Labels           map[string]string
	}
	//xops:opaque
	//xops:failclosed
	MetricSampleEvent struct {
		sealedEventMixin
		metricName, unit string
		value            float64
		interval         algebraic.Duration
		labels           map[string]string
	}

	AuditRecordSpec struct {
		Meta              EventMeta
		Stage             AuditStage
		ProcessInstanceID string
		Capability        security.CapabilityKind
		Decision          security.GuardrailDecision
		Risk              security.RiskLevel
		Binding           algebraic.Option[security.OperationBinding]
		Outcome           algebraic.Option[execution.ExecutionOutcome]
		Duration          algebraic.Duration
		Reason            string
	}
	//xops:opaque
	//xops:failclosed
	AuditRecordEvent struct {
		sealedEventMixin
		stage                     AuditStage
		processInstanceID, reason string
		capability                security.CapabilityKind
		decision                  security.GuardrailDecision
		risk                      security.RiskLevel
		binding                   algebraic.Option[security.OperationBinding]
		outcome                   algebraic.Option[execution.ExecutionOutcome]
		duration                  algebraic.Duration
	}

	PoolStateSpec struct {
		Meta         EventMeta
		Action       PoolEventAction
		PlanDigest   algebraic.Option[plan.PlanDigest]
		HopDigest    algebraic.Option[plan.HopDigest]
		Endpoint     algebraic.Option[netaddr.Endpoint]
		HandleKind   algebraic.Option[plan.HandleKindCode]
		HandleID     algebraic.Option[plan.HandleID]
		Generation   uint64
		ActiveLeases uint32
		Latency      algebraic.Duration
		Detail       string
	}
	//xops:opaque
	//xops:failclosed
	PoolStateEvent struct {
		sealedEventMixin
		action       PoolEventAction
		planDigest   algebraic.Option[plan.PlanDigest]
		hopDigest    algebraic.Option[plan.HopDigest]
		endpoint     algebraic.Option[netaddr.Endpoint]
		handleKind   algebraic.Option[plan.HandleKindCode]
		handleID     algebraic.Option[plan.HandleID]
		generation   uint64
		activeLeases uint32
		latency      algebraic.Duration
		detail       string
	}

	DiagnosticSpec struct {
		Meta          EventMeta
		Scope         DiagnosticScope
		Severity      Severity
		Code, Message string
		Attrs         map[string]string
	}
	//xops:opaque
	//xops:failclosed
	DiagnosticEvent struct {
		sealedEventMixin
		scope         DiagnosticScope
		severity      Severity
		code, message string
		attrs         map[string]string
	}

	BusDroppedSpec struct {
		Meta                       EventMeta
		Scope                      DiagnosticScope
		DroppedTotal, DroppedDelta uint64
		Reason                     string
	}
	//xops:opaque
	//xops:failclosed
	BusDroppedEvent struct {
		sealedEventMixin
		scope                      DiagnosticScope
		droppedTotal, droppedDelta uint64
		reason                     string
	}
)

// NewOperationStartedEvent 校验操作元数据、能力类别与工具动作标识并构造 *OperationStartedEvent。
func NewOperationStartedEvent(s OperationStartedSpec) (*OperationStartedEvent, error) {
	if err := requireOpMeta(s.Meta); err != nil {
		return nil, err
	}
	if !s.Capability.IsValid() || !isValidASCIIToken(s.Tool, maxCodeBytes) || !isValidASCIIToken(s.Action, maxCodeBytes) || optInvalid(s.PlanDigest) {
		return nil, fieldErr(ErrInvalidEvent, "operation_started")
	}
	return &OperationStartedEvent{newBase(EventKindOperationStarted, EventClassOperation, s.Meta), s.Capability, s.Tool, s.Action, sanitizeText(s.Summary, maxTextBytes), s.PlanDigest}, nil
}

// NewOperationCompletedEvent 校验非负耗时与结果一致性（严禁降级 OutcomeUnknown）并构造 *OperationCompletedEvent。
func NewOperationCompletedEvent(s OperationCompletedSpec) (*OperationCompletedEvent, error) {
	if err := requireOpMeta(s.Meta); err != nil {
		return nil, err
	}
	if !s.Capability.IsValid() || s.Duration.IsNegative() || (s.Code != "" && !isValidASCIIToken(s.Code, maxCodeBytes)) {
		return nil, fieldErr(ErrInvalidEvent, "operation_completed")
	}
	if err := validateCompletedOutcomeConsistency(s.Succeeded, s.Outcome); err != nil {
		return nil, err
	}
	return &OperationCompletedEvent{newBase(EventKindOperationCompleted, EventClassOperation, s.Meta), s.Capability, s.Duration, s.Outcome, s.Succeeded, s.Code, sanitizeText(s.Message, maxTextBytes)}, nil
}

// NewOutputChunkEvent 校验输出通道与分块上限（<= 1 MiB）并深拷贝载荷构造 *OutputChunkEvent。
func NewOutputChunkEvent(s OutputChunkSpec) (*OutputChunkEvent, error) {
	if err := requireOpMeta(s.Meta); err != nil {
		return nil, err
	}
	if !s.Stream.IsValid() || len(s.Data) > maxOutputChunkBytes || (len(s.Data) == 0 && !s.Truncated) {
		return nil, fieldErr(ErrInvalidEvent, "output_chunk")
	}
	return &OutputChunkEvent{newBase(EventKindOutputChunk, EventClassOperation, s.Meta), s.Stream, s.ChunkIndex, bytes.Clone(s.Data), s.Truncated}, nil
}

// NewStepEvent 校验步骤标识、状态、非负耗时与 Outcome 一致性并构造 *StepEvent。
func NewStepEvent(s StepEventSpec) (*StepEvent, error) {
	if err := requireOpMeta(s.Meta); err != nil {
		return nil, err
	}
	if optInvalid(s.PlaybookID) || !s.StepID.IsValid() || !s.Status.IsValid() || s.Duration.IsNegative() {
		return nil, fieldErr(ErrInvalidEvent, "step")
	}
	if err := validateStepOutcomeConsistency(s.Status, s.Outcome); err != nil {
		return nil, err
	}
	return &StepEvent{newBase(EventKindStep, EventClassOperation, s.Meta), s.PlaybookID, s.StepID, s.Status, s.Duration, s.Outcome, sanitizeText(s.Message, maxTextBytes)}, nil
}

// NewFSMTransitionEvent 校验状态机类型及状态/事件标识并构造 *FSMTransitionEvent。
func NewFSMTransitionEvent(s FSMTransitionSpec) (*FSMTransitionEvent, error) {
	if err := requireOpMeta(s.Meta); err != nil {
		return nil, err
	}
	if !s.Machine.IsValid() || !isValidASCIIToken(s.FromState, maxCodeBytes) || !isValidASCIIToken(s.ToState, maxCodeBytes) || !isValidASCIIToken(s.EventName, maxCodeBytes) {
		return nil, fieldErr(ErrInvalidEvent, "fsm_transition")
	}
	return &FSMTransitionEvent{newBase(EventKindFSMTransition, EventClassOperation, s.Meta), s.Machine, s.FromState, s.ToState, s.EventName, sanitizeText(s.Detail, maxTextBytes), s.Terminal}, nil
}

// 以下五个便捷构造器直接从 core/domain/fsm 强类型事件映射为 *FSMTransitionEvent。
type fsmStateToken interface {
	IsValid() bool
	String() string
}

func newTypedFSMTransition[S, K fsmStateToken](meta EventMeta, m FSMMachineKind, from, to S, evOk bool, evKind K, detail string, terminal bool) (*FSMTransitionEvent, error) {
	if !from.IsValid() || !to.IsValid() || !evOk {
		return nil, fieldErr(ErrInvalidEvent, m.String())
	}
	return NewFSMTransitionEvent(FSMTransitionSpec{meta, m, from.String(), to.String(), evKind.String(), detail, terminal})
}
func NewVaultSagaTransitionEvent(m EventMeta, from, to fsm.VaultSagaStateKind, ev fsm.VaultSagaEvent, term bool) (*FSMTransitionEvent, error) {
	return newTypedFSMTransition(m, FSMMachineVaultSaga, from, to, ev.IsValid(), ev.Kind(), ev.Detail(), term)
}
func NewApprovalTransitionEvent(m EventMeta, from, to fsm.ApprovalPhase, ev fsm.ApprovalEvent, term bool) (*FSMTransitionEvent, error) {
	return newTypedFSMTransition(m, FSMMachineApproval, from, to, ev.IsValid(), ev.Kind(), ev.Detail(), term)
}
func NewTransferTransitionEvent(m EventMeta, from, to fsm.TransferStateKind, ev fsm.TransferEvent, term bool) (*FSMTransitionEvent, error) {
	return newTypedFSMTransition(m, FSMMachineTransfer, from, to, ev.IsValid(), ev.Kind(), ev.Detail(), term)
}
func NewEnsureTransitionEvent(m EventMeta, from, to fsm.EnsurePhase, ev fsm.EnsureEvent, term bool) (*FSMTransitionEvent, error) {
	return newTypedFSMTransition(m, FSMMachineEnsure, from, to, ev.IsValid(), ev.Kind(), ev.Detail(), term)
}
func NewPendingEnrollTransitionEvent(m EventMeta, from, to fsm.PendingEnrollPhase, ev fsm.PendingEnrollEvent, term bool) (*FSMTransitionEvent, error) {
	return newTypedFSMTransition(m, FSMMachinePendingEnroll, from, to, ev.IsValid(), ev.Kind(), ev.Detail(), term)
}

// NewApprovalChallengeEvent 校验审批信封、审批阶段及 OperationID 严格绑定一致性并构造 *ApprovalChallengeEvent。
func NewApprovalChallengeEvent(s ApprovalChallengeSpec) (*ApprovalChallengeEvent, error) {
	if err := requireOpMeta(s.Meta); err != nil {
		return nil, err
	}
	if !s.Envelope.IsValid() || !s.Phase.IsValid() {
		return nil, fieldErr(ErrInvalidEvent, "approval_challenge")
	}
	if !approvalOpMatches(s.Meta, s.Envelope) {
		return nil, fieldErr(ErrOperationMismatch, "operation_id")
	}
	return &ApprovalChallengeEvent{newBase(EventKindApprovalChallenge, EventClassOperation, s.Meta), s.Envelope, s.Phase, s.Escalated, sanitizeText(s.Reason, maxTextBytes)}, nil
}

// NewTransferProgressEvent 校验传输标识、方向、字节边界与非负耗时并构造 *TransferProgressEvent。
func NewTransferProgressEvent(s TransferProgressSpec) (*TransferProgressEvent, error) {
	if err := requireOpMeta(s.Meta); err != nil {
		return nil, err
	}
	if !s.TransferID.IsValid() || !s.Direction.IsValid() || s.Elapsed.IsNegative() || (s.TotalBytes > 0 && s.BytesTransferred > s.TotalBytes) || (s.Stage != "" && !isValidASCIIToken(s.Stage, maxCodeBytes)) {
		return nil, fieldErr(ErrInvalidEvent, "transfer_progress")
	}
	return &TransferProgressEvent{newBase(EventKindTransferProgress, EventClassProgress, s.Meta), s.TransferID, s.Direction, s.BytesTransferred, s.TotalBytes, s.ChunksCompleted, s.RateBytesPerSec, s.Elapsed, s.Stage}, nil
}

// NewMetricSampleEvent 校验指标名、有限数值（拒绝 NaN/Inf 并归一化 -0）、非负采样周期与标签表并构造 *MetricSampleEvent。
func NewMetricSampleEvent(s MetricSampleSpec) (*MetricSampleEvent, error) {
	if err := requireOpMeta(s.Meta); err != nil {
		return nil, err
	}
	if !isValidASCIIToken(s.MetricName, maxCodeBytes) || math.IsNaN(s.Value) || math.IsInf(s.Value, 0) || s.Interval.IsNegative() || (s.Unit != "" && !isValidASCIIToken(s.Unit, maxLabelKeyBytes)) {
		return nil, fieldErr(ErrInvalidEvent, "metric_sample")
	}
	labels, err := canonicalizeKVMap(s.Labels, ErrInvalidEvent)
	if err != nil {
		return nil, err
	}
	return &MetricSampleEvent{newBase(EventKindMetricSample, EventClassProgress, s.Meta), s.MetricName, s.Unit, pickIf(s.Value == 0, 0.0, s.Value), s.Interval, labels}, nil
}

// NewAuditRecordEvent 校验审计阶段、进程实例 ID、安全决策/阶段一致性、绑定能力一致性与非负耗时并构造 *AuditRecordEvent。
func NewAuditRecordEvent(s AuditRecordSpec) (*AuditRecordEvent, error) {
	if err := requireOpMeta(s.Meta); err != nil {
		return nil, err
	}
	if !s.Stage.IsValid() || !isValidASCIIToken(s.ProcessInstanceID, maxCodeBytes) || !s.Capability.IsValid() || s.Decision == nil || !s.Decision.IsValid() || !s.Risk.IsValid() || s.Duration.IsNegative() {
		return nil, fieldErr(ErrInvalidEvent, "audit_record")
	}
	if err := validateAuditOptionals(s.Stage, s.Capability, s.Decision, s.Binding, s.Outcome); err != nil {
		return nil, err
	}
	return &AuditRecordEvent{newBase(EventKindAuditRecord, EventClassAudit, s.Meta), s.Stage, s.ProcessInstanceID, sanitizeText(s.Reason, maxTextBytes), s.Capability, security.NormalizeDecision(s.Decision), s.Risk, s.Binding, s.Outcome, s.Duration}, nil
}

// NewPoolStateEvent 校验连接池动作、可选摘要/端点与非负延迟并构造 *PoolStateEvent。
func NewPoolStateEvent(s PoolStateSpec) (*PoolStateEvent, error) {
	if !s.Meta.IsValid() || !s.Action.IsValid() || s.Latency.IsNegative() ||
		optInvalid(s.PlanDigest) || optInvalid(s.HopDigest) || optInvalid(s.Endpoint) || optInvalid(s.HandleKind) || optInvalid(s.HandleID) {
		return nil, fieldErr(ErrInvalidEvent, "pool_state")
	}
	return &PoolStateEvent{newBase(EventKindPoolState, EventClassSystem, s.Meta), s.Action, s.PlanDigest, s.HopDigest, s.Endpoint, s.HandleKind, s.HandleID, s.Generation, s.ActiveLeases, s.Latency, sanitizeText(s.Detail, maxTextBytes)}, nil
}

// NewDiagnosticEvent 校验诊断作用域、严重级别、非空消息与属性表并构造 *DiagnosticEvent。
func NewDiagnosticEvent(s DiagnosticSpec) (*DiagnosticEvent, error) {
	msg := sanitizeText(s.Message, maxTextBytes)
	if !s.Meta.IsValid() || !s.Scope.IsValid() || !s.Severity.IsValid() || msg == "" || (s.Code != "" && !isValidASCIIToken(s.Code, maxCodeBytes)) {
		return nil, fieldErr(ErrInvalidEvent, "diagnostic")
	}
	attrs, err := canonicalizeKVMap(s.Attrs, ErrInvalidEvent)
	if err != nil {
		return nil, err
	}
	return &DiagnosticEvent{newBase(EventKindDiagnostic, EventClassSystem, s.Meta), s.Scope, s.Severity, s.Code, msg, attrs}, nil
}

// NewBusDroppedEvent 校验作用域与单调丢弃计数（delta>0 且 total>=delta）并构造 *BusDroppedEvent。
func NewBusDroppedEvent(s BusDroppedSpec) (*BusDroppedEvent, error) {
	if !s.Meta.IsValid() || !s.Scope.IsValid() || s.DroppedDelta == 0 || s.DroppedTotal < s.DroppedDelta {
		return nil, fieldErr(ErrInvalidEvent, "bus_dropped")
	}
	return &BusDroppedEvent{newBase(EventKindBusDropped, EventClassSystem, s.Meta), s.Scope, s.DroppedTotal, s.DroppedDelta, sanitizeText(s.Reason, maxTextBytes)}, nil
}

// 12 个事件变体的 IsValid / Event 接口方法（与构造器跨字段不变式严格等价，对 typed-nil 与未初始化零值失败关闭）。
func (e *OperationStartedEvent) IsValid() bool {
	return e != nil && e.baseValid(true) && e.capability.IsValid() && e.tool != "" && e.action != "" && !optInvalid(e.planDigest)
}
func (e *OperationCompletedEvent) IsValid() bool {
	return e != nil && e.baseValid(true) && e.capability.IsValid() && !e.duration.IsNegative() && completedOutcomeConsistent(e.succeeded, e.outcome)
}
func (e *OutputChunkEvent) IsValid() bool {
	return e != nil && e.baseValid(true) && e.stream.IsValid() && len(e.data) <= maxOutputChunkBytes && (len(e.data) > 0 || e.truncated)
}
func (e *StepEvent) IsValid() bool {
	return e != nil && e.baseValid(true) && e.stepID.IsValid() && e.status.IsValid() && !e.duration.IsNegative() && !optInvalid(e.playbookID) && stepOutcomeConsistent(e.status, e.outcome)
}
func (e *FSMTransitionEvent) IsValid() bool {
	return e != nil && e.baseValid(true) && e.machine.IsValid() && e.fromState != "" && e.toState != "" && e.eventName != ""
}
func (e *ApprovalChallengeEvent) IsValid() bool {
	return e != nil && e.baseValid(true) && e.envelope.IsValid() && e.phase.IsValid() && approvalOpMatches(e.meta, e.envelope)
}
func (e *TransferProgressEvent) IsValid() bool {
	return e != nil && e.baseValid(true) && e.transferID.IsValid() && e.direction.IsValid() && !e.elapsed.IsNegative() && (e.totalBytes == 0 || e.bytesTransferred <= e.totalBytes)
}
func (e *MetricSampleEvent) IsValid() bool {
	return e != nil && e.baseValid(true) && e.metricName != "" && !math.IsNaN(e.value) && !math.IsInf(e.value, 0) && !e.interval.IsNegative()
}
func (e *AuditRecordEvent) IsValid() bool {
	return e != nil && e.baseValid(true) && e.stage.IsValid() && e.processInstanceID != "" && e.capability.IsValid() && e.risk.IsValid() && !e.duration.IsNegative() && auditCrossFieldsValid(e.stage, e.capability, e.decision, e.binding, e.outcome)
}
func (e *PoolStateEvent) IsValid() bool {
	return e != nil && e.baseValid(false) && e.action.IsValid() && !e.latency.IsNegative() &&
		!optInvalid(e.planDigest) && !optInvalid(e.hopDigest) && !optInvalid(e.endpoint) && !optInvalid(e.handleKind) && !optInvalid(e.handleID)
}
func (e *DiagnosticEvent) IsValid() bool {
	return e != nil && e.baseValid(false) && e.scope.IsValid() && e.severity.IsValid() && e.message != ""
}
func (e *BusDroppedEvent) IsValid() bool {
	return e != nil && e.baseValid(false) && e.scope.IsValid() && e.droppedDelta > 0 && e.droppedTotal >= e.droppedDelta
}

func evBP(ev Event) BackpressurePolicy { return evClass(ev).DefaultBackpressure() }

func (e *OperationStartedEvent) Kind() EventKind                    { return evKind(e) }
func (e *OperationStartedEvent) Class() EventClass                  { return evClass(e) }
func (e *OperationStartedEvent) Backpressure() BackpressurePolicy   { return evBP(e) }
func (*OperationStartedEvent) CoalesceKey() string                  { return "" }
func (e *OperationStartedEvent) Meta() EventMeta                    { return evMeta(e) }
func (e *OperationCompletedEvent) Kind() EventKind                  { return evKind(e) }
func (e *OperationCompletedEvent) Class() EventClass                { return evClass(e) }
func (e *OperationCompletedEvent) Backpressure() BackpressurePolicy { return evBP(e) }
func (*OperationCompletedEvent) CoalesceKey() string                { return "" }
func (e *OperationCompletedEvent) Meta() EventMeta                  { return evMeta(e) }
func (e *OutputChunkEvent) Kind() EventKind                         { return evKind(e) }
func (e *OutputChunkEvent) Class() EventClass                       { return evClass(e) }
func (e *OutputChunkEvent) Backpressure() BackpressurePolicy        { return evBP(e) }
func (*OutputChunkEvent) CoalesceKey() string                       { return "" }
func (e *OutputChunkEvent) Meta() EventMeta                         { return evMeta(e) }
func (e *StepEvent) Kind() EventKind                                { return evKind(e) }
func (e *StepEvent) Class() EventClass                              { return evClass(e) }
func (e *StepEvent) Backpressure() BackpressurePolicy               { return evBP(e) }
func (*StepEvent) CoalesceKey() string                              { return "" }
func (e *StepEvent) Meta() EventMeta                                { return evMeta(e) }
func (e *FSMTransitionEvent) Kind() EventKind                       { return evKind(e) }
func (e *FSMTransitionEvent) Class() EventClass                     { return evClass(e) }
func (e *FSMTransitionEvent) Backpressure() BackpressurePolicy      { return evBP(e) }
func (*FSMTransitionEvent) CoalesceKey() string                     { return "" }
func (e *FSMTransitionEvent) Meta() EventMeta                       { return evMeta(e) }
func (e *ApprovalChallengeEvent) Kind() EventKind                   { return evKind(e) }
func (e *ApprovalChallengeEvent) Class() EventClass                 { return evClass(e) }
func (e *ApprovalChallengeEvent) Backpressure() BackpressurePolicy  { return evBP(e) }
func (*ApprovalChallengeEvent) CoalesceKey() string                 { return "" }
func (e *ApprovalChallengeEvent) Meta() EventMeta                   { return evMeta(e) }
func (e *TransferProgressEvent) Kind() EventKind                    { return evKind(e) }
func (e *TransferProgressEvent) Class() EventClass                  { return evClass(e) }
func (e *TransferProgressEvent) Backpressure() BackpressurePolicy   { return evBP(e) }
func (e *TransferProgressEvent) CoalesceKey() string {
	if !e.IsValid() {
		return ""
	}
	return "transfer:" + e.transferID.String()
}
func (e *TransferProgressEvent) Meta() EventMeta              { return evMeta(e) }
func (e *MetricSampleEvent) Kind() EventKind                  { return evKind(e) }
func (e *MetricSampleEvent) Class() EventClass                { return evClass(e) }
func (e *MetricSampleEvent) Backpressure() BackpressurePolicy { return evBP(e) }
func appendFramedStr(dst []byte, s string) []byte {
	dst = strconv.AppendInt(dst, int64(len(s)), 10)
	dst = append(dst, ':')
	return append(dst, s...)
}

// CoalesceKey 采用显式字节长度前缀帧编码 (Option[NodeID], metricName, sorted labels)，
// 在数学上严格单射，杜绝含 ':', '|', '=' 等字符的跨序列合并碰撞。
func (e *MetricSampleEvent) CoalesceKey() string {
	if !e.IsValid() {
		return ""
	}
	b := make([]byte, 0, 64)
	b = append(b, "metric:"...)
	if nodeID, ok := e.meta.NodeID().Get(); ok {
		b = append(b, "1:"...)
		b = appendFramedStr(b, nodeID.String())
	} else {
		b = append(b, "0:"...)
	}
	b = append(b, ';')
	b = appendFramedStr(b, e.metricName)
	b = append(b, ';')
	b = strconv.AppendInt(b, int64(len(e.labels)), 10)
	for _, k := range slices.Sorted(maps.Keys(e.labels)) {
		b = append(b, ';')
		b = appendFramedStr(b, k)
		b = append(b, '=')
		b = appendFramedStr(b, e.labels[k])
	}
	return string(b)
}
func (e *MetricSampleEvent) Meta() EventMeta                 { return evMeta(e) }
func (e *AuditRecordEvent) Kind() EventKind                  { return evKind(e) }
func (e *AuditRecordEvent) Class() EventClass                { return evClass(e) }
func (e *AuditRecordEvent) Backpressure() BackpressurePolicy { return evBP(e) }
func (*AuditRecordEvent) CoalesceKey() string                { return "" }
func (e *AuditRecordEvent) Meta() EventMeta                  { return evMeta(e) }
func (e *PoolStateEvent) Kind() EventKind                    { return evKind(e) }
func (e *PoolStateEvent) Class() EventClass                  { return evClass(e) }
func (e *PoolStateEvent) Backpressure() BackpressurePolicy   { return evBP(e) }
func (*PoolStateEvent) CoalesceKey() string                  { return "" }
func (e *PoolStateEvent) Meta() EventMeta                    { return evMeta(e) }
func (e *DiagnosticEvent) Kind() EventKind                   { return evKind(e) }
func (e *DiagnosticEvent) Class() EventClass                 { return evClass(e) }
func (e *DiagnosticEvent) Backpressure() BackpressurePolicy  { return evBP(e) }
func (*DiagnosticEvent) CoalesceKey() string                 { return "" }
func (e *DiagnosticEvent) Meta() EventMeta                   { return evMeta(e) }
func (e *BusDroppedEvent) Kind() EventKind                   { return evKind(e) }
func (e *BusDroppedEvent) Class() EventClass                 { return evClass(e) }
func (e *BusDroppedEvent) Backpressure() BackpressurePolicy  { return evBP(e) }
func (*BusDroppedEvent) CoalesceKey() string                 { return "" }
func (e *BusDroppedEvent) Meta() EventMeta                   { return evMeta(e) }
