package fsm

import (
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/secret"
)

// NewVaultSagaState 校验上下文并构造 VaultSagaFSM 初始状态 *VaultSagaInit。
func NewVaultSagaState(ctx VaultSagaContext) (*VaultSagaInit, error) {
	if !ctx.IsValid() {
		return nil, ErrInvalidContext
	}
	return &VaultSagaInit{vMix(ctx, VaultSagaKindInit, "")}, nil
}

// VaultSagaInput 的显式校验构造器集（零值输入恒无效并失败关闭）。
func VaultInputStart() VaultSagaInput { return VaultSagaInput{kind: vaultInStart, valid: true} }
func VaultInputWriteNewResult(o SideEffectOutcome, r string) (VaultSagaInput, error) {
	return vOutIn(vaultInWriteNew, o, r)
}
func VaultInputDeleteOldResult(o SideEffectOutcome, r string) (VaultSagaInput, error) {
	return vOutIn(vaultInDeleteOld, o, r)
}
func VaultInputCompensateResult(o SideEffectOutcome, r string) (VaultSagaInput, error) {
	return vOutIn(vaultInCompensate, o, r)
}

// VaultInputReadbackResult 构造回读核验结果输入（严格对齐 ports.SecretVault.PutAndVerify + SecretBox.Equal）：
// 仅当 outcome == SideEffectSucceeded 时允许 matched=true；遇 SideEffectOutcomeUnknown 进入 FailedUncertain 且 0 副作用。
func VaultInputReadbackResult(outcome SideEffectOutcome, matched bool, reason string) (VaultSagaInput, error) {
	if !outcome.IsValid() {
		return VaultSagaInput{}, fmt.Errorf("%w: %w", ErrInvalidInput, ErrInvalidOutcome)
	}
	if outcome != SideEffectSucceeded && matched {
		return VaultSagaInput{}, fmt.Errorf("%w: 非成功回读结果不得声称 matched=true", ErrInvalidInput)
	}
	return VaultSagaInput{kind: vaultInReadback, outcome: outcome, ok: matched, reason: sanitizeReason(reason), valid: true}, nil
}
func VaultInputCommitCASResult(durability DurabilityStatus, reason string) (VaultSagaInput, error) {
	if !durability.IsValid() {
		return VaultSagaInput{}, fmt.Errorf("%w: %w", ErrInvalidInput, ErrInvalidDurability)
	}
	return VaultSagaInput{kind: vaultInCommitCAS, durability: durability, reason: sanitizeReason(reason), valid: true}, nil
}
func VaultInputOldRefsResult(ok bool, refCount int, reason string) (VaultSagaInput, error) {
	if ok && refCount < 0 {
		return VaultSagaInput{}, fmt.Errorf("%w: 引用计数不能为负数", ErrInvalidInput)
	}
	return VaultSagaInput{kind: vaultInOldRefs, ok: ok, refCount: refCount, reason: sanitizeReason(reason), valid: true}, nil
}
func vOutIn(kind uint8, outcome SideEffectOutcome, reason string) (VaultSagaInput, error) {
	if !outcome.IsValid() {
		return VaultSagaInput{}, fmt.Errorf("%w: %w", ErrInvalidInput, ErrInvalidOutcome)
	}
	return VaultSagaInput{kind: kind, outcome: outcome, reason: sanitizeReason(reason), valid: true}, nil
}

// TransitionVaultSaga 执行 VaultSagaFSM 纯 Mealy 状态转移：
//   - CAS 前失败自动补偿删除未引用新凭据（Compensating -> RolledBack）；
//   - 任意副作用遇 OutcomeUnknown 进入 FailedUncertain（零重试）；
//   - CommitConfigCAS 遇 Applied && !Durable 进入 UncertainDurability（零重试且零删凭据）。
func TransitionVaultSaga(state VaultSagaState, input VaultSagaInput) (VaultSagaState, []VaultSagaEffect, []VaultSagaEvent, error) {
	if state == nil || !state.IsValid() {
		return state, nil, nil, ErrInvalidState
	}
	if !input.IsValid() {
		return state, nil, nil, ErrInvalidInput
	}
	switch s := state.(type) {
	case *VaultSagaInit:
		return stepVaultInit(s, input)
	case *VaultSagaWritingNew:
		return stepVaultWritingNew(s, input)
	case *VaultSagaVerifyingReadback:
		return stepVaultVerifyingReadback(s, input)
	case *VaultSagaCommittingConfig:
		return stepVaultCommittingConfig(s, input)
	case *VaultSagaCheckingOldRefs:
		return stepVaultCheckingOldRefs(s, input)
	case *VaultSagaDeletingOld:
		return stepVaultDeletingOld(s, input)
	case *VaultSagaCompensating:
		return stepVaultCompensating(s, input)
	case *VaultSagaCompleted, *VaultSagaRolledBack, *VaultSagaUncertainDurability, *VaultSagaFailedUncertain:
		return state, nil, nil, fmt.Errorf("%w: 终态 %s 不接受输入", ErrIllegalTransition, s.Kind())
	default:
		return state, nil, nil, ErrInvalidState
	}
}

func stepVaultInit(s *VaultSagaInit, in VaultSagaInput) (VaultSagaState, []VaultSagaEffect, []VaultSagaEvent, error) {
	if in.kind != vaultInStart {
		return s, nil, nil, fmt.Errorf("%w: init 仅接受 Start", ErrIllegalTransition)
	}
	return vaultNext(&VaultSagaWritingNew{vMix(s.ctx, VaultSagaKindWritingNew, "")}, VaultEffectWriteNew, s.ctx.newRef, 0, VaultEventStarted, s.ctx.newRef.String())
}
func stepVaultWritingNew(s *VaultSagaWritingNew, in VaultSagaInput) (VaultSagaState, []VaultSagaEffect, []VaultSagaEvent, error) {
	if in.kind != vaultInWriteNew {
		return s, nil, nil, fmt.Errorf("%w: writing_new 仅接受 WriteNewResult", ErrIllegalTransition)
	}
	switch in.outcome {
	case SideEffectSucceeded:
		return vaultNext(&VaultSagaVerifyingReadback{vMix(s.ctx, VaultSagaKindVerifyingReadback, "")}, VaultEffectVerifyReadback, s.ctx.newRef, 0, VaultEventNewSecretWritten, s.ctx.newRef.String())
	case SideEffectFailedNotApplied:
		return &VaultSagaRolledBack{vMix(s.ctx, VaultSagaKindRolledBack, in.reason), false}, nil, []VaultSagaEvent{newEvent(VaultEventRolledBack, in.reason)}, nil
	case SideEffectOutcomeUnknown:
		return vaultUncertain(s.ctx, VaultSagaKindWritingNew, in.reason)
	default:
		return s, nil, nil, ErrInvalidOutcome
	}
}
func stepVaultVerifyingReadback(s *VaultSagaVerifyingReadback, in VaultSagaInput) (VaultSagaState, []VaultSagaEffect, []VaultSagaEvent, error) {
	if in.kind != vaultInReadback {
		return s, nil, nil, fmt.Errorf("%w: verifying_readback 仅接受 ReadbackResult", ErrIllegalTransition)
	}
	switch in.outcome {
	case SideEffectSucceeded:
		if in.ok {
			return vaultNext(&VaultSagaCommittingConfig{vMix(s.ctx, VaultSagaKindCommittingConfig, "")}, VaultEffectCommitConfigCAS, s.ctx.newRef, s.ctx.expectedCASVersion, VaultEventReadbackVerified, s.ctx.newRef.String())
		}
		fallthrough
	case SideEffectFailedNotApplied:
		reason := pickIf(in.reason != "", in.reason, pickIf(in.outcome == SideEffectSucceeded, "readback secret mismatch", "readback failed"))
		return vaultNext(&VaultSagaCompensating{vMix(s.ctx, VaultSagaKindCompensating, reason)}, VaultEffectCompensateDeleteNew, s.ctx.newRef, 0, VaultEventReadbackFailed, reason)
	case SideEffectOutcomeUnknown:
		return vaultUncertain(s.ctx, VaultSagaKindVerifyingReadback, pickIf(in.reason != "", in.reason, "readback outcome unknown"))
	default:
		return s, nil, nil, ErrInvalidOutcome
	}
}
func stepVaultCommittingConfig(s *VaultSagaCommittingConfig, in VaultSagaInput) (VaultSagaState, []VaultSagaEffect, []VaultSagaEvent, error) {
	if in.kind != vaultInCommitCAS {
		return s, nil, nil, fmt.Errorf("%w: committing_config 仅接受 CommitCASResult", ErrIllegalTransition)
	}
	switch in.durability {
	case DurabilityCommitted:
		if oldRef, hasOld := s.ctx.oldRef.Get(); hasOld {
			return vaultNext(&VaultSagaCheckingOldRefs{vMix(s.ctx, VaultSagaKindCheckingOldRefs, "")}, VaultEffectCheckOldRefs, oldRef, 0, VaultEventConfigCommitted, s.ctx.newRef.String())
		}
		return &VaultSagaCompleted{vMix(s.ctx, VaultSagaKindCompleted, "no_old_ref"), false}, nil, []VaultSagaEvent{newEvent(VaultEventConfigCommitted, s.ctx.newRef.String()), newEvent(VaultEventCompleted, "no_old_ref")}, nil
	case DurabilityNotApplied:
		return vaultNext(&VaultSagaCompensating{vMix(s.ctx, VaultSagaKindCompensating, in.reason)}, VaultEffectCompensateDeleteNew, s.ctx.newRef, 0, VaultEventConfigRejected, in.reason)
	case DurabilityAppliedNotDurable:
		// 核心安全不变量：Applied && !Durable 停机于 UncertainDurability，严格 0 重试且 0 删除凭据。
		return &VaultSagaUncertainDurability{vMix(s.ctx, VaultSagaKindUncertainDurability, in.reason)}, nil, []VaultSagaEvent{newEvent(VaultEventUncertainDurability, in.reason)}, nil
	case DurabilityOutcomeUnknown:
		return vaultUncertain(s.ctx, VaultSagaKindCommittingConfig, in.reason)
	default:
		return s, nil, nil, ErrInvalidDurability
	}
}
func stepVaultCheckingOldRefs(s *VaultSagaCheckingOldRefs, in VaultSagaInput) (VaultSagaState, []VaultSagaEffect, []VaultSagaEvent, error) {
	if in.kind != vaultInOldRefs {
		return s, nil, nil, fmt.Errorf("%w: checking_old_refs 仅接受 OldRefsResult", ErrIllegalTransition)
	}
	if !in.ok {
		return vaultUncertain(s.ctx, VaultSagaKindCheckingOldRefs, in.reason)
	}
	oldRef, hasOld := s.ctx.oldRef.Get()
	if !hasOld || in.refCount > 0 {
		note := fmt.Sprintf("old_ref_retained:refs=%d", in.refCount)
		return &VaultSagaCompleted{vMix(s.ctx, VaultSagaKindCompleted, note), false}, nil, []VaultSagaEvent{newEvent(VaultEventOldSecretGCDeferred, note), newEvent(VaultEventCompleted, note)}, nil
	}
	return vaultNext(&VaultSagaDeletingOld{vMix(s.ctx, VaultSagaKindDeletingOld, "")}, VaultEffectDeleteOld, oldRef, 0, VaultEventOldRefsZero, oldRef.String())
}
func stepVaultDeletingOld(s *VaultSagaDeletingOld, in VaultSagaInput) (VaultSagaState, []VaultSagaEffect, []VaultSagaEvent, error) {
	if in.kind != vaultInDeleteOld {
		return s, nil, nil, fmt.Errorf("%w: deleting_old 仅接受 DeleteOldResult", ErrIllegalTransition)
	}
	if in.outcome == SideEffectSucceeded {
		oldRef, _ := s.ctx.oldRef.Get()
		return &VaultSagaCompleted{vMix(s.ctx, VaultSagaKindCompleted, "old_deleted"), true}, nil, []VaultSagaEvent{newEvent(VaultEventOldSecretDeleted, oldRef.String()), newEvent(VaultEventCompleted, "old_deleted")}, nil
	}
	return vaultUncertain(s.ctx, VaultSagaKindDeletingOld, in.reason)
}
func stepVaultCompensating(s *VaultSagaCompensating, in VaultSagaInput) (VaultSagaState, []VaultSagaEffect, []VaultSagaEvent, error) {
	if in.kind != vaultInCompensate {
		return s, nil, nil, fmt.Errorf("%w: compensating 仅接受 CompensateResult", ErrIllegalTransition)
	}
	if in.outcome == SideEffectSucceeded {
		return &VaultSagaRolledBack{vMix(s.ctx, VaultSagaKindRolledBack, s.reason), true}, nil, []VaultSagaEvent{newEvent(VaultEventCompensated, s.ctx.newRef.String()), newEvent(VaultEventRolledBack, s.reason)}, nil
	}
	return vaultUncertain(s.ctx, VaultSagaKindCompensating, in.reason)
}

func vaultNext(st VaultSagaState, eff VaultSagaEffectKind, ref secret.Ref, cas uint64, ev VaultSagaEventKind, detail string) (VaultSagaState, []VaultSagaEffect, []VaultSagaEvent, error) {
	return st, []VaultSagaEffect{{eff, ref, cas, true}}, []VaultSagaEvent{newEvent(ev, detail)}, nil
}
func vaultUncertain(ctx VaultSagaContext, step VaultSagaStateKind, reason string) (VaultSagaState, []VaultSagaEffect, []VaultSagaEvent, error) {
	return &VaultSagaFailedUncertain{vMix(ctx, VaultSagaKindFailedUncertain, reason), step}, nil, []VaultSagaEvent{newEvent(VaultEventHaltedUncertain, reason)}, nil
}
