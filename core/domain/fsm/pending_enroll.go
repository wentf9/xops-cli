package fsm

import (
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// PendingEnrollPhase、PendingEnrollEffectKind 与 PendingEnrollEventKind 为失败关闭枚举。
type (
	//xops:opaque
	//xops:failclosed
	PendingEnrollPhase uint8
	//xops:opaque
	//xops:failclosed
	PendingEnrollEffectKind uint8
	//xops:opaque
	//xops:failclosed
	PendingEnrollEventKind uint8
)

const (
	PendingEnrollPhaseInvalid PendingEnrollPhase = iota
	PendingEnrollPhaseIdle
	PendingEnrollPhaseStaged
	PendingEnrollPhaseProbing
	PendingEnrollPhaseVerified
	PendingEnrollPhaseCommitting
	PendingEnrollPhaseCleaningUp
	PendingEnrollPhaseEnrolled
	PendingEnrollPhaseAborted
	PendingEnrollPhaseUncertain
)
const (
	enrollInInvalid uint8 = iota
	enrollInStage
	enrollInStartProbe
	enrollInProbeResult
	enrollInCommit
	enrollInCommitResult
	enrollInCleanupResult
	enrollInCancel
	enrollInExpire
)
const (
	EnrollEffectInvalid PendingEnrollEffectKind = iota
	EnrollEffectPinSecrets
	EnrollEffectProbeConnection
	EnrollEffectCommitInventoryCAS
	EnrollEffectCleanupPendingSecrets
	EnrollEffectReleasePins
)
const (
	EnrollEventInvalid PendingEnrollEventKind = iota
	EnrollEventStaged
	EnrollEventProbeStarted
	EnrollEventVerified
	EnrollEventProbeFailed
	EnrollEventCommitStarted
	EnrollEventEnrolled
	EnrollEventCommitRejected
	EnrollEventExpired
	EnrollEventCancelled
	EnrollEventCleaningUp
	EnrollEventAborted
	EnrollEventUncertain
)

// PendingEnrollContextSpec 与 PendingEnrollContext/State/Input/Effect 为失败关闭不可变值对象。
type (
	PendingEnrollContextSpec struct {
		LeaseID    security.OperationID
		TargetNode inventory.NodeID
		PinnedRefs []secret.Ref
		StagedAt   time.Time
		TTL        algebraic.Duration
	}
	//xops:opaque
	//xops:failclosed
	PendingEnrollContext struct {
		leaseID    security.OperationID
		targetNode inventory.NodeID
		pinnedRefs []secret.Ref
		stagedAt   time.Time
		ttl        algebraic.Duration
		valid      bool
	}
	//xops:opaque
	//xops:failclosed
	PendingEnrollState struct {
		phase              PendingEnrollPhase
		ctx                PendingEnrollContext
		hostKeyFingerprint algebraic.Option[inventory.KeyFingerprint]
		reason             string
		valid              bool
	}
	//xops:opaque
	//xops:failclosed
	PendingEnrollInput struct {
		kind               uint8
		ctx                PendingEnrollContext
		now                time.Time
		ok                 bool
		hostKeyFingerprint inventory.KeyFingerprint
		durability         DurabilityStatus
		outcome            SideEffectOutcome
		reason             string
		valid              bool
	}
	//xops:opaque
	//xops:failclosed
	PendingEnrollEffect struct {
		kind       PendingEnrollEffectKind
		targetNode inventory.NodeID
		refs       []secret.Ref
		valid      bool
	}
)

// PendingEnrollEvent 为 PendingEnrollFSM 发出的不可变脱敏事件。
type PendingEnrollEvent = Event[PendingEnrollEventKind]

// NewPendingEnrollContext 校验租约 ID、目标节点、时间窗口与钉住凭据集合并规范排序去重。
func NewPendingEnrollContext(spec PendingEnrollContextSpec) (PendingEnrollContext, error) {
	stagedUTC := spec.StagedAt.UTC().Round(0)
	if !spec.LeaseID.IsValid() || !spec.TargetNode.IsValid() || !isValidTimeWindow(stagedUTC, spec.TTL) ||
		len(spec.PinnedRefs) > MaxPendingSecretRefs || slices.ContainsFunc(spec.PinnedRefs, secret.Ref.IsZero) {
		return PendingEnrollContext{}, domi18n.EF(ErrInvalidEnrollLease, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "enroll_lease"))
	}
	refs := slices.Clone(spec.PinnedRefs)
	slices.SortFunc(refs, secret.Ref.Compare)
	return PendingEnrollContext{spec.LeaseID, spec.TargetNode, slices.CompactFunc(refs, secret.Ref.Equal), stagedUTC, spec.TTL, true}, nil
}

// NewPendingEnrollState 构造初始空闲状态（PendingEnrollPhaseIdle）。
func NewPendingEnrollState() PendingEnrollState {
	return PendingEnrollState{phase: PendingEnrollPhaseIdle, valid: true}
}
func (c PendingEnrollContext) IsValid() bool {
	return c.valid && c.leaseID.IsValid() && c.targetNode.IsValid() && isValidTimeWindow(c.stagedAt, c.ttl)
}
func (c PendingEnrollContext) LeaseID() security.OperationID { return c.leaseID }
func (c PendingEnrollContext) TargetNode() inventory.NodeID  { return c.targetNode }
func (c PendingEnrollContext) StagedAt() time.Time           { return c.stagedAt }
func (c PendingEnrollContext) TTL() algebraic.Duration       { return c.ttl }
func (c PendingEnrollContext) PinnedRefs() []secret.Ref      { return slices.Clone(c.pinnedRefs) }

// IsExpiredAt 报告租约在显式时刻 now 是否已过期（含零值/无效租约失败关闭）；now 早于 stagedAt 不视为过期。
func (c PendingEnrollContext) IsExpiredAt(now time.Time) bool {
	return !c.IsValid() || now.IsZero() || !now.UTC().Before(c.stagedAt.Add(c.ttl.Std()))
}

// IsActiveAt 报告租约在显式时刻 now 是否处于有效活动窗口 [stagedAt, stagedAt+ttl) 内。
func (c PendingEnrollContext) IsActiveAt(now time.Time) bool {
	return c.IsValid() && !now.IsZero() && !now.UTC().Before(c.stagedAt) && now.UTC().Before(c.stagedAt.Add(c.ttl.Std()))
}
func (c PendingEnrollContext) PendingSecretRefs() []inventory.PendingSecretRef {
	if !c.IsValid() || len(c.pinnedRefs) == 0 {
		return nil
	}
	owner, out := "pending_enroll:"+c.leaseID.String(), make([]inventory.PendingSecretRef, len(c.pinnedRefs))
	for i, ref := range c.pinnedRefs {
		out[i] = inventory.PendingSecretRef{OwnerID: owner, Ref: ref}
	}
	return out
}
func (s PendingEnrollState) IsValid() bool {
	return s.valid && s.phase.IsValid() && (s.phase == PendingEnrollPhaseIdle || s.ctx.IsValid())
}
func (s PendingEnrollState) IsTerminal() bool {
	return s.IsValid() && s.phase >= PendingEnrollPhaseEnrolled && s.phase <= PendingEnrollPhaseUncertain
}
func (s PendingEnrollState) Phase() PendingEnrollPhase     { return s.phase }
func (s PendingEnrollState) Context() PendingEnrollContext { return s.ctx }
func (s PendingEnrollState) HostKeyFingerprint() algebraic.Option[inventory.KeyFingerprint] {
	return s.hostKeyFingerprint
}
func (s PendingEnrollState) Reason() string { return s.reason }
func (s PendingEnrollState) PinnedSecretRefs() []inventory.PendingSecretRef {
	if !s.IsValid() || s.phase == PendingEnrollPhaseIdle || s.phase == PendingEnrollPhaseEnrolled || s.phase == PendingEnrollPhaseAborted {
		return nil
	}
	return s.ctx.PendingSecretRefs()
}
func (i PendingEnrollInput) IsValid() bool {
	return i.valid && i.kind >= enrollInStage && i.kind <= enrollInExpire
}
func (e PendingEnrollEffect) IsValid() bool                 { return e.valid && e.kind.IsValid() }
func (e PendingEnrollEffect) Kind() PendingEnrollEffectKind { return e.kind }
func (e PendingEnrollEffect) TargetNode() inventory.NodeID  { return e.targetNode }
func (e PendingEnrollEffect) Refs() []secret.Ref            { return slices.Clone(e.refs) }

// PendingEnrollInput 显式校验构造器集（零值输入恒无效）。
func EnrollInputStage(ctx PendingEnrollContext) (PendingEnrollInput, error) {
	if !ctx.IsValid() {
		return PendingEnrollInput{}, ErrInvalidEnrollLease
	}
	return PendingEnrollInput{kind: enrollInStage, ctx: ctx, valid: true}, nil
}
func EnrollInputStartProbe(t time.Time) (PendingEnrollInput, error) { return eT(enrollInStartProbe, t) }
func EnrollInputProbeResult(ok bool, fp inventory.KeyFingerprint, now time.Time, reason string) (PendingEnrollInput, error) {
	if !isValidRFC3339Time(now) || (ok && !fp.IsValid()) {
		return PendingEnrollInput{}, ErrInvalidInput
	}
	return PendingEnrollInput{kind: enrollInProbeResult, ok: ok, hostKeyFingerprint: fp, now: now.UTC().Round(0), reason: sanitizeReason(reason), valid: true}, nil
}
func EnrollInputCommit(t time.Time) (PendingEnrollInput, error) { return eT(enrollInCommit, t) }
func EnrollInputCommitResult(durability DurabilityStatus, reason string) (PendingEnrollInput, error) {
	if !durability.IsValid() {
		return PendingEnrollInput{}, domi18n.WrapSentinel(ErrInvalidInput, ErrInvalidDurability)
	}
	return PendingEnrollInput{kind: enrollInCommitResult, durability: durability, reason: sanitizeReason(reason), valid: true}, nil
}
func EnrollInputCleanupResult(outcome SideEffectOutcome, reason string) (PendingEnrollInput, error) {
	if !outcome.IsValid() {
		return PendingEnrollInput{}, domi18n.WrapSentinel(ErrInvalidInput, ErrInvalidOutcome)
	}
	return PendingEnrollInput{kind: enrollInCleanupResult, outcome: outcome, reason: sanitizeReason(reason), valid: true}, nil
}
func EnrollInputCancel(reason string) PendingEnrollInput {
	return PendingEnrollInput{kind: enrollInCancel, reason: sanitizeReason(reason), valid: true}
}
func EnrollInputExpire(t time.Time) (PendingEnrollInput, error) { return eT(enrollInExpire, t) }
func eT(kind uint8, now time.Time) (PendingEnrollInput, error) {
	if !isValidRFC3339Time(now) {
		return PendingEnrollInput{}, ErrInvalidInput
	}
	return PendingEnrollInput{kind: kind, now: now.UTC().Round(0), valid: true}, nil
}

// TransitionPendingEnroll 执行首连「先验证后入库」作用域租约状态机纯 Mealy 转换：
// 未通过 Probing -> Verified 前绝不发出 CommitInventoryCAS；暂存凭据全程钉住防 GC，
// 提交遇 Applied && !Durable 或未知结果立即停机于 PendingEnrollPhaseUncertain 且保留钉住。
func TransitionPendingEnroll(state PendingEnrollState, input PendingEnrollInput) (PendingEnrollState, []PendingEnrollEffect, []PendingEnrollEvent, error) {
	if !state.IsValid() {
		return state, nil, nil, ErrInvalidState
	}
	if !input.IsValid() {
		return state, nil, nil, ErrInvalidInput
	}
	switch state.phase {
	case PendingEnrollPhaseIdle:
		return stepEnrollIdle(state, input)
	case PendingEnrollPhaseStaged:
		return stepEnrollStaged(state, input)
	case PendingEnrollPhaseProbing:
		return stepEnrollProbing(state, input)
	case PendingEnrollPhaseVerified:
		return stepEnrollVerified(state, input)
	case PendingEnrollPhaseCommitting:
		return stepEnrollCommitting(state, input)
	case PendingEnrollPhaseCleaningUp:
		return stepEnrollCleaningUp(state, input)
	case PendingEnrollPhaseEnrolled, PendingEnrollPhaseAborted, PendingEnrollPhaseUncertain:
		return state, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMTerminalState, domi18n.Str("state", state.phase.String()))
	default:
		return state, nil, nil, ErrInvalidState
	}
}
func stepEnrollIdle(s PendingEnrollState, in PendingEnrollInput) (PendingEnrollState, []PendingEnrollEffect, []PendingEnrollEvent, error) {
	if in.kind != enrollInStage {
		return s, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMExpectedInput, domi18n.Str("state", s.phase.String()), domi18n.Str("expected", "Stage"))
	}
	effs := pickIf(len(in.ctx.pinnedRefs) > 0, []PendingEnrollEffect{enrollEffect(EnrollEffectPinSecrets, in.ctx.targetNode, in.ctx.pinnedRefs)}, nil)
	return PendingEnrollState{phase: PendingEnrollPhaseStaged, ctx: in.ctx, valid: true}, effs, []PendingEnrollEvent{newEvent(EnrollEventStaged, in.ctx.targetNode.String())}, nil
}
func stepEnrollStaged(s PendingEnrollState, in PendingEnrollInput) (PendingEnrollState, []PendingEnrollEffect, []PendingEnrollEvent, error) {
	if next, eff, ev, done, err := guardEnrollActive(s, in, enrollInStartProbe, "StartProbe/Cancel/Expire", "lease expired before probe"); done {
		return next, eff, ev, err
	}
	return PendingEnrollState{phase: PendingEnrollPhaseProbing, ctx: s.ctx, valid: true}, []PendingEnrollEffect{enrollEffect(EnrollEffectProbeConnection, s.ctx.targetNode, nil)}, []PendingEnrollEvent{newEvent(EnrollEventProbeStarted, s.ctx.targetNode.String())}, nil
}
func stepEnrollProbing(s PendingEnrollState, in PendingEnrollInput) (PendingEnrollState, []PendingEnrollEffect, []PendingEnrollEvent, error) {
	if next, eff, ev, done, err := guardEnrollActive(s, in, enrollInProbeResult, "ProbeResult/Cancel/Expire", "lease expired during probe"); done {
		return next, eff, ev, err
	}
	if !in.ok {
		return beginEnrollCleanup(s.ctx, EnrollEventProbeFailed, pickIf(in.reason != "", in.reason, "probe failed"))
	}
	return PendingEnrollState{phase: PendingEnrollPhaseVerified, ctx: s.ctx, hostKeyFingerprint: algebraic.Some(in.hostKeyFingerprint), valid: true}, nil, []PendingEnrollEvent{newEvent(EnrollEventVerified, in.hostKeyFingerprint.String())}, nil
}
func stepEnrollVerified(s PendingEnrollState, in PendingEnrollInput) (PendingEnrollState, []PendingEnrollEffect, []PendingEnrollEvent, error) {
	if next, eff, ev, done, err := guardEnrollActive(s, in, enrollInCommit, "Commit/Cancel/Expire", "lease expired before commit"); done {
		return next, eff, ev, err
	}
	return PendingEnrollState{phase: PendingEnrollPhaseCommitting, ctx: s.ctx, hostKeyFingerprint: s.hostKeyFingerprint, valid: true}, []PendingEnrollEffect{enrollEffect(EnrollEffectCommitInventoryCAS, s.ctx.targetNode, s.ctx.pinnedRefs)}, []PendingEnrollEvent{newEvent(EnrollEventCommitStarted, s.ctx.targetNode.String())}, nil
}
func stepEnrollCommitting(s PendingEnrollState, in PendingEnrollInput) (PendingEnrollState, []PendingEnrollEffect, []PendingEnrollEvent, error) {
	if in.kind != enrollInCommitResult {
		return s, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMExpectedInput, domi18n.Str("state", s.phase.String()), domi18n.Str("expected", "CommitResult"))
	}
	switch in.durability {
	case DurabilityCommitted:
		effs := pickIf(len(s.ctx.pinnedRefs) > 0, []PendingEnrollEffect{enrollEffect(EnrollEffectReleasePins, s.ctx.targetNode, s.ctx.pinnedRefs)}, nil)
		return PendingEnrollState{phase: PendingEnrollPhaseEnrolled, ctx: s.ctx, hostKeyFingerprint: s.hostKeyFingerprint, valid: true}, effs, []PendingEnrollEvent{newEvent(EnrollEventEnrolled, s.ctx.targetNode.String())}, nil
	case DurabilityNotApplied:
		return beginEnrollCleanup(s.ctx, EnrollEventCommitRejected, pickIf(in.reason != "", in.reason, "cas commit not applied"))
	case DurabilityAppliedNotDurable, DurabilityOutcomeUnknown:
		return enrollUncertain(s.ctx, pickIf(in.reason != "", in.reason, in.durability.String()))
	default:
		return s, nil, nil, ErrInvalidDurability
	}
}
func stepEnrollCleaningUp(s PendingEnrollState, in PendingEnrollInput) (PendingEnrollState, []PendingEnrollEffect, []PendingEnrollEvent, error) {
	if in.kind != enrollInCleanupResult {
		return s, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMExpectedInput, domi18n.Str("state", s.phase.String()), domi18n.Str("expected", "CleanupResult"))
	}
	if in.outcome == SideEffectSucceeded {
		return PendingEnrollState{phase: PendingEnrollPhaseAborted, ctx: s.ctx, reason: s.reason, valid: true}, []PendingEnrollEffect{enrollEffect(EnrollEffectReleasePins, s.ctx.targetNode, s.ctx.pinnedRefs)}, []PendingEnrollEvent{newEvent(EnrollEventAborted, s.reason)}, nil
	}
	return enrollUncertain(s.ctx, pickIf(in.reason != "", in.reason, "cleanup failed or uncertain"))
}
func guardEnrollActive(s PendingEnrollState, in PendingEnrollInput, expect uint8, expected, expMsg string) (PendingEnrollState, []PendingEnrollEffect, []PendingEnrollEvent, bool, error) {
	if in.kind == enrollInCancel {
		next, eff, ev, err := beginEnrollCleanup(s.ctx, EnrollEventCancelled, pickIf(in.reason != "", in.reason, "cancelled"))
		return next, eff, ev, true, err
	}
	if in.kind != enrollInExpire && in.kind != expect {
		return s, nil, nil, true, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMExpectedInput, domi18n.Str("state", s.phase.String()), domi18n.Str("expected", expected))
	}
	if in.now.UTC().Before(s.ctx.stagedAt) {
		return s, nil, nil, true, domi18n.EF(ErrInvalidInput, domi18n.KeyFSMTimeBeforeStaged)
	}
	if s.ctx.IsExpiredAt(in.now) {
		next, eff, ev, err := beginEnrollCleanup(s.ctx, EnrollEventExpired, pickIf(in.kind == enrollInExpire, "lease expired", expMsg))
		return next, eff, ev, true, err
	}
	if in.kind == enrollInExpire {
		return s, nil, nil, true, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMLeaseNotExpired)
	}
	return PendingEnrollState{}, nil, nil, false, nil
}
func enrollUncertain(ctx PendingEnrollContext, reason string) (PendingEnrollState, []PendingEnrollEffect, []PendingEnrollEvent, error) {
	clean := sanitizeReason(reason)
	return PendingEnrollState{phase: PendingEnrollPhaseUncertain, ctx: ctx, reason: clean, valid: true}, nil, []PendingEnrollEvent{newEvent(EnrollEventUncertain, clean)}, nil
}
func beginEnrollCleanup(ctx PendingEnrollContext, triggerKind PendingEnrollEventKind, reason string) (PendingEnrollState, []PendingEnrollEffect, []PendingEnrollEvent, error) {
	clean := sanitizeReason(reason)
	if len(ctx.pinnedRefs) == 0 {
		return PendingEnrollState{phase: PendingEnrollPhaseAborted, ctx: ctx, reason: clean, valid: true}, nil, []PendingEnrollEvent{newEvent(triggerKind, clean), newEvent(EnrollEventAborted, clean)}, nil
	}
	return PendingEnrollState{phase: PendingEnrollPhaseCleaningUp, ctx: ctx, reason: clean, valid: true}, []PendingEnrollEffect{enrollEffect(EnrollEffectCleanupPendingSecrets, ctx.targetNode, ctx.pinnedRefs)}, []PendingEnrollEvent{newEvent(triggerKind, clean), newEvent(EnrollEventCleaningUp, clean)}, nil
}
func enrollEffect(kind PendingEnrollEffectKind, target inventory.NodeID, refs []secret.Ref) PendingEnrollEffect {
	return PendingEnrollEffect{kind: kind, targetNode: target, refs: slices.Clone(refs), valid: true}
}
