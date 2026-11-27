package events

import (
	"bytes"
	"maps"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/security"
)

func evBase(ev Event) (EventKind, EventClass, EventMeta) {
	if ev != nil && ev.IsValid() {
		return ev.rawBase()
	}
	return EventKindInvalid, EventClassInvalid, EventMeta{}
}
func evKind(ev Event) EventKind   { k, _, _ := evBase(ev); return k }
func evClass(ev Event) EventClass { _, c, _ := evBase(ev); return c }
func evMeta(ev Event) EventMeta   { _, _, m := evBase(ev); return m }

// snap 对指针变体执行 nil 与有效性门控，无效时返回零值副本以保障全部只读访问器 100% 无空指针解引用。
func snap[T any, P interface {
	*T
	IsValid() bool
}](p P) T {
	if p == nil || !p.IsValid() {
		return zeroVal[T]()
	}
	return *p
}

// 12 个事件变体的不可变只读访问器（全部对 typed-nil 与无效零值失败关闭，切片/映射返回防御性副本）。
func (e *OperationStartedEvent) Capability() security.CapabilityKind { return snap(e).capability }
func (e *OperationStartedEvent) Tool() string                        { return snap(e).tool }
func (e *OperationStartedEvent) Action() string                      { return snap(e).action }
func (e *OperationStartedEvent) PlanDigest() algebraic.Option[plan.PlanDigest] {
	return snap(e).planDigest
}
func (e *OperationStartedEvent) Summary() string                       { return snap(e).sum }
func (e *OperationCompletedEvent) Capability() security.CapabilityKind { return snap(e).capability }
func (e *OperationCompletedEvent) Duration() algebraic.Duration        { return snap(e).duration }
func (e *OperationCompletedEvent) Outcome() algebraic.Option[execution.ExecutionOutcome] {
	return snap(e).outcome
}
func (e *OperationCompletedEvent) Succeeded() bool                         { return e.IsValid() && e.succeeded }
func (e *OperationCompletedEvent) Code() string                            { return snap(e).code }
func (e *OperationCompletedEvent) Message() string                         { return snap(e).message }
func (e *OutputChunkEvent) Stream() OutputStreamKind                       { return snap(e).stream }
func (e *OutputChunkEvent) ChunkIndex() uint64                             { return snap(e).chunkIndex }
func (e *OutputChunkEvent) Data() []byte                                   { return bytes.Clone(snap(e).data) }
func (e *OutputChunkEvent) Truncated() bool                                { return e.IsValid() && e.truncated }
func (e *StepEvent) PlaybookID() algebraic.Option[playbook.PlaybookID]     { return snap(e).playbookID }
func (e *StepEvent) StepID() playbook.StepID                               { return snap(e).stepID }
func (e *StepEvent) Status() playbook.StepStatus                           { return snap(e).status }
func (e *StepEvent) Duration() algebraic.Duration                          { return snap(e).duration }
func (e *StepEvent) Outcome() algebraic.Option[execution.ExecutionOutcome] { return snap(e).outcome }
func (e *StepEvent) Message() string                                       { return snap(e).message }
func (e *FSMTransitionEvent) Machine() FSMMachineKind                      { return snap(e).machine }
func (e *FSMTransitionEvent) FromState() string                            { return snap(e).fromState }
func (e *FSMTransitionEvent) ToState() string                              { return snap(e).toState }
func (e *FSMTransitionEvent) EventName() string                            { return snap(e).eventName }
func (e *FSMTransitionEvent) Detail() string                               { return snap(e).detail }
func (e *FSMTransitionEvent) Terminal() bool                               { return e.IsValid() && e.terminal }
func (e *ApprovalChallengeEvent) Envelope() security.ApprovalEnvelope      { return snap(e).envelope }
func (e *ApprovalChallengeEvent) Phase() fsm.ApprovalPhase                 { return snap(e).phase }
func (e *ApprovalChallengeEvent) Escalated() bool                          { return e.IsValid() && e.escalated }
func (e *ApprovalChallengeEvent) Reason() string                           { return snap(e).reason }
func (e *TransferProgressEvent) TransferID() security.OperationID          { return snap(e).transferID }
func (e *TransferProgressEvent) Direction() fsm.TransferDirection          { return snap(e).direction }
func (e *TransferProgressEvent) BytesTransferred() uint64                  { return snap(e).bytesTransferred }
func (e *TransferProgressEvent) TotalBytes() uint64                        { return snap(e).totalBytes }
func (e *TransferProgressEvent) ChunksCompleted() uint64                   { return snap(e).chunksCompleted }
func (e *TransferProgressEvent) Elapsed() algebraic.Duration               { return snap(e).elapsed }
func (e *TransferProgressEvent) RateBytesPerSec() uint64                   { return snap(e).rateBytesPerSec }
func (e *TransferProgressEvent) Stage() string                             { return snap(e).stage }
func (e *MetricSampleEvent) MetricName() string                            { return snap(e).metricName }
func (e *MetricSampleEvent) Unit() string                                  { return snap(e).unit }
func (e *MetricSampleEvent) Value() float64                                { return snap(e).value }
func (e *MetricSampleEvent) Interval() algebraic.Duration                  { return snap(e).interval }
func (e *MetricSampleEvent) Labels() map[string]string                     { return cloneStringMap(snap(e).labels) }
func (e *AuditRecordEvent) Stage() AuditStage                              { return snap(e).stage }
func (e *AuditRecordEvent) ProcessInstanceID() string                      { return snap(e).processInstanceID }
func (e *AuditRecordEvent) Capability() security.CapabilityKind            { return snap(e).capability }
func (e *AuditRecordEvent) Decision() security.GuardrailDecision {
	if !e.IsValid() {
		return security.NewDecisionDenyWithCode("invalid_audit_event", "audit event is invalid")
	}
	return security.NormalizeDecision(e.decision)
}
func (e *AuditRecordEvent) Risk() security.RiskLevel { return snap(e).risk }
func (e *AuditRecordEvent) Binding() algebraic.Option[security.OperationBinding] {
	return snap(e).binding
}
func (e *AuditRecordEvent) Outcome() algebraic.Option[execution.ExecutionOutcome] {
	return snap(e).outcome
}
func (e *AuditRecordEvent) Duration() algebraic.Duration                { return snap(e).duration }
func (e *AuditRecordEvent) Reason() string                              { return snap(e).reason }
func (e *PoolStateEvent) Action() PoolEventAction                       { return snap(e).action }
func (e *PoolStateEvent) PlanDigest() algebraic.Option[plan.PlanDigest] { return snap(e).planDigest }
func (e *PoolStateEvent) HopDigest() algebraic.Option[plan.HopDigest]   { return snap(e).hopDigest }
func (e *PoolStateEvent) Endpoint() algebraic.Option[netaddr.Endpoint]  { return snap(e).endpoint }
func (e *PoolStateEvent) HandleKind() algebraic.Option[plan.HandleKindCode] {
	return snap(e).handleKind
}
func (e *PoolStateEvent) HandleID() algebraic.Option[plan.HandleID] { return snap(e).handleID }
func (e *PoolStateEvent) Generation() uint64                        { return snap(e).generation }
func (e *PoolStateEvent) ActiveLeases() uint32                      { return snap(e).activeLeases }
func (e *PoolStateEvent) Latency() algebraic.Duration               { return snap(e).latency }
func (e *PoolStateEvent) Detail() string                            { return snap(e).detail }
func (e *DiagnosticEvent) Scope() DiagnosticScope                   { return snap(e).scope }
func (e *DiagnosticEvent) Severity() Severity                       { return snap(e).severity }
func (e *DiagnosticEvent) Code() string                             { return snap(e).code }
func (e *DiagnosticEvent) Message() string                          { return snap(e).message }
func (e *DiagnosticEvent) Attrs() map[string]string                 { return cloneStringMap(snap(e).attrs) }
func (e *BusDroppedEvent) Scope() DiagnosticScope                   { return snap(e).scope }
func (e *BusDroppedEvent) DroppedTotal() uint64                     { return snap(e).droppedTotal }
func (e *BusDroppedEvent) DroppedDelta() uint64                     { return snap(e).droppedDelta }
func (e *BusDroppedEvent) Reason() string                           { return snap(e).reason }

// EqualEvent 按值严格比较两个 Event 是否均有效、变体一致且全部字段完全相等（nil 或无效零值恒返回 false）。
func EqualEvent(a, b Event) bool {
	if a == nil || b == nil || !a.IsValid() || !b.IsValid() || !a.Meta().Equal(b.Meta()) {
		return false
	}
	switch va := a.(type) {
	case *OperationStartedEvent:
		vb, ok := b.(*OperationStartedEvent)
		return ok && va.capability == vb.capability && va.tool == vb.tool && va.action == vb.action && equalOptComparable(va.planDigest, vb.planDigest) && va.sum == vb.sum
	case *OperationCompletedEvent:
		vb, ok := b.(*OperationCompletedEvent)
		return ok && va.capability == vb.capability && va.duration.Equal(vb.duration) && equalOptOutcome(va.outcome, vb.outcome) && va.succeeded == vb.succeeded && va.code == vb.code && va.message == vb.message
	case *OutputChunkEvent:
		vb, ok := b.(*OutputChunkEvent)
		return ok && va.stream == vb.stream && va.chunkIndex == vb.chunkIndex && va.truncated == vb.truncated && bytes.Equal(va.data, vb.data)
	case *StepEvent:
		vb, ok := b.(*StepEvent)
		return ok && equalOptComparable(va.playbookID, vb.playbookID) && va.stepID.Equal(vb.stepID) && va.status == vb.status && va.duration.Equal(vb.duration) && equalOptOutcome(va.outcome, vb.outcome) && va.message == vb.message
	case *FSMTransitionEvent:
		vb, ok := b.(*FSMTransitionEvent)
		return ok && va.machine == vb.machine && va.fromState == vb.fromState && va.toState == vb.toState && va.eventName == vb.eventName && va.detail == vb.detail && va.terminal == vb.terminal
	case *ApprovalChallengeEvent:
		vb, ok := b.(*ApprovalChallengeEvent)
		return ok && va.envelope.Equal(vb.envelope) && va.phase == vb.phase && va.escalated == vb.escalated && va.reason == vb.reason
	case *TransferProgressEvent:
		vb, ok := b.(*TransferProgressEvent)
		return ok && va.transferID.Equal(vb.transferID) && va.direction == vb.direction && va.bytesTransferred == vb.bytesTransferred && va.totalBytes == vb.totalBytes && va.chunksCompleted == vb.chunksCompleted && va.elapsed.Equal(vb.elapsed) && va.rateBytesPerSec == vb.rateBytesPerSec && va.stage == vb.stage
	case *MetricSampleEvent:
		vb, ok := b.(*MetricSampleEvent)
		return ok && va.metricName == vb.metricName && va.unit == vb.unit && va.value == vb.value && va.interval.Equal(vb.interval) && maps.Equal(va.labels, vb.labels)
	case *AuditRecordEvent:
		vb, ok := b.(*AuditRecordEvent)
		return ok && va.stage == vb.stage && va.processInstanceID == vb.processInstanceID && va.capability == vb.capability && security.EqualDecision(va.decision, vb.decision) && va.risk == vb.risk && equalOptComparable(va.binding, vb.binding) && equalOptOutcome(va.outcome, vb.outcome) && va.duration.Equal(vb.duration) && va.reason == vb.reason
	case *PoolStateEvent:
		vb, ok := b.(*PoolStateEvent)
		return ok && equalPoolStateEvent(va, vb)
	case *DiagnosticEvent:
		vb, ok := b.(*DiagnosticEvent)
		return ok && va.scope == vb.scope && va.severity == vb.severity && va.code == vb.code && va.message == vb.message && maps.Equal(va.attrs, vb.attrs)
	case *BusDroppedEvent:
		vb, ok := b.(*BusDroppedEvent)
		return ok && va.scope == vb.scope && va.droppedTotal == vb.droppedTotal && va.droppedDelta == vb.droppedDelta && va.reason == vb.reason
	default:
		return false
	}
}

func requireOpMeta(meta EventMeta) error {
	if !meta.IsValid() || meta.OperationID().IsNone() {
		return domi18n.EF(ErrInvalidEventMeta, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "operation_id"))
	}
	return nil
}

func approvalOpMatches(meta EventMeta, env security.ApprovalEnvelope) bool {
	opID, ok := meta.OperationID().Get()
	return ok && opID.Equal(env.OperationID())
}

func completedOutcomeConsistent(succeeded bool, opt algebraic.Option[execution.ExecutionOutcome]) bool {
	out, ok := opt.Get()
	if !ok {
		return true
	}
	if out == nil || !out.IsValid() {
		return false
	}
	switch v := out.(type) {
	case *execution.OutcomeUnknown, *execution.OutcomeNotStarted:
		return !succeeded
	case *execution.OutcomeCompleted:
		return succeeded == v.Succeeded()
	default:
		return false
	}
}

func validateCompletedOutcomeConsistency(succeeded bool, opt algebraic.Option[execution.ExecutionOutcome]) error {
	if !completedOutcomeConsistent(succeeded, opt) {
		return domi18n.EF(ErrInvalidEvent, domi18n.KeyEventsOutcomeConflict)
	}
	return nil
}

func stepOutcomeConsistent(status playbook.StepStatus, opt algebraic.Option[execution.ExecutionOutcome]) bool {
	out, ok := opt.Get()
	if !ok {
		return true
	}
	if out == nil || !out.IsValid() {
		return false
	}
	switch v := out.(type) {
	case *execution.OutcomeUnknown:
		return status == playbook.StepStatusOutcomeUnknown
	case *execution.OutcomeNotStarted:
		return status == playbook.StepStatusFailed || status == playbook.StepStatusAborted
	case *execution.OutcomeCompleted:
		if v.Succeeded() {
			return status == playbook.StepStatusSucceeded || status == playbook.StepStatusChanged
		}
		return status == playbook.StepStatusFailed || status == playbook.StepStatusAborted
	default:
		return false
	}
}

func validateStepOutcomeConsistency(status playbook.StepStatus, opt algebraic.Option[execution.ExecutionOutcome]) error {
	if !stepOutcomeConsistent(status, opt) {
		return domi18n.EF(ErrInvalidEvent, domi18n.KeyEventsOutcomeConflict)
	}
	return nil
}

func auditStageDecisionOK(stage AuditStage, dec security.GuardrailDecision) bool {
	if dec == nil || !dec.IsValid() {
		return false
	}
	switch stage {
	case AuditStageAuthorized, AuditStageFinalized, AuditStageAbortedByCrash:
		return dec.Kind() != security.DecisionKindDeny
	case AuditStageDenied:
		return dec.Kind() != security.DecisionKindAllow
	case AuditStageHalted:
		return dec.Kind() == security.DecisionKindDeny
	case AuditStageNeedApproval:
		return dec.Kind() == security.DecisionKindNeedApproval
	default:
		return false
	}
}

func auditCrossFieldsValid(stage AuditStage, capKind security.CapabilityKind, dec security.GuardrailDecision, binding algebraic.Option[security.OperationBinding], outcome algebraic.Option[execution.ExecutionOutcome]) bool {
	if !auditStageDecisionOK(stage, dec) || optOutcomeInvalid(outcome) {
		return false
	}
	b, hasB := binding.Get()
	if hasB && (!b.IsValid() || b.Capability() != capKind) {
		return false
	}
	if !hasB && (stage == AuditStageAuthorized || stage == AuditStageFinalized || stage == AuditStageAbortedByCrash) {
		return false
	}
	return true
}

func decisionKindText(dec security.GuardrailDecision) string {
	if dec == nil {
		return "invalid"
	}
	return dec.Kind().String()
}

func validateAuditOptionals(stage AuditStage, capKind security.CapabilityKind, dec security.GuardrailDecision, binding algebraic.Option[security.OperationBinding], outcome algebraic.Option[execution.ExecutionOutcome]) error {
	if !auditStageDecisionOK(stage, dec) {
		return domi18n.EF(ErrInvalidEvent, domi18n.KeyEventsAuditConflict, domi18n.Str("stage", stage.String()), domi18n.Str("decision", decisionKindText(dec)))
	}
	b, hasB := binding.Get()
	if hasB && (!b.IsValid() || b.Capability() != capKind) {
		return fieldErr(ErrInvalidEvent, "binding")
	}
	if !hasB && (stage == AuditStageAuthorized || stage == AuditStageFinalized || stage == AuditStageAbortedByCrash) {
		return domi18n.EF(ErrInvalidEvent, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "binding"))
	}
	if optOutcomeInvalid(outcome) {
		return fieldErr(ErrInvalidEvent, "outcome")
	}
	return nil
}

func optInvalid[T interface{ IsValid() bool }](opt algebraic.Option[T]) bool {
	v, ok := opt.Get()
	return ok && !v.IsValid()
}

func optOutcomeInvalid(opt algebraic.Option[execution.ExecutionOutcome]) bool {
	v, ok := opt.Get()
	return ok && (v == nil || !v.IsValid())
}

func equalPoolStateEvent(a, b *PoolStateEvent) bool {
	return a.action == b.action && equalOptComparable(a.planDigest, b.planDigest) && equalOptComparable(a.hopDigest, b.hopDigest) &&
		equalOptComparable(a.endpoint, b.endpoint) && equalOptVal(a.handleKind, b.handleKind) &&
		equalOptComparable(a.handleID, b.handleID) && a.generation == b.generation &&
		a.activeLeases == b.activeLeases && a.latency.Equal(b.latency) && a.detail == b.detail
}

func equalOptOutcome(a, b algebraic.Option[execution.ExecutionOutcome]) bool {
	va, oka := a.Get()
	vb, okb := b.Get()
	return oka == okb && (!oka || execution.EqualOutcome(va, vb))
}
