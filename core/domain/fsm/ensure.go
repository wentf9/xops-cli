package fsm

import (
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// EnsurePhase、EnsureEffectKind 与 EnsureEventKind 为 EnsureFSM 失败关闭枚举。
type (
	//xops:opaque
	//xops:failclosed
	EnsurePhase uint8
	//xops:opaque
	//xops:failclosed
	EnsureEffectKind uint8
	//xops:opaque
	//xops:failclosed
	EnsureEventKind uint8
)

const (
	EnsurePhaseUnknown EnsurePhase = iota
	EnsurePhasePending
	EnsurePhaseChecking
	EnsurePhaseApplying
	EnsurePhasePostChecking
	EnsurePhaseConvergedUnchanged
	EnsurePhaseConvergedChanged
	EnsurePhaseFailed
	EnsurePhaseUncertainOutcome
)

const (
	ensureInInvalid uint8 = iota
	ensureInStart
	ensureInOutcome
)

const (
	EnsureEffectInvalid EnsureEffectKind = iota
	EnsureEffectRunCheck
	EnsureEffectRunApply
	EnsureEffectRunPostCheck
)

const (
	EnsureEventInvalid EnsureEventKind = iota
	EnsureEventCheckStarted
	EnsureEventRetryingNotStarted
	EnsureEventApplyStarted
	EnsureEventPostCheckStarted
	EnsureEventConvergedUnchanged
	EnsureEventConvergedChanged
	EnsureEventFailed
	EnsureEventUncertainOutcome
)

func (p EnsurePhase) IsValid() bool {
	return p >= EnsurePhasePending && p <= EnsurePhaseUncertainOutcome
}
func (k EnsureEffectKind) IsValid() bool {
	return k >= EnsureEffectRunCheck && k <= EnsureEffectRunPostCheck
}
func (k EnsureEventKind) IsValid() bool {
	return k >= EnsureEventCheckStarted && k <= EnsureEventUncertainOutcome
}
func (p EnsurePhase) String() string {
	return enumName(uint8(p), "unknown", "unknown", "pending", "checking", "applying", "post_checking", "converged_unchanged", "converged_changed", "failed", "uncertain_outcome")
}
func (k EnsureEffectKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "run_check", "run_apply", "run_post_check")
}
func (k EnsureEventKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "check_started", "retrying_not_started", "apply_started", "post_check_started", "converged_unchanged", "converged_changed", "failed", "uncertain_outcome")
}

// EnsureContext、EnsureState、EnsureInput、EnsureEffect 与 EnsureEvent 为 EnsureFSM 不可变失败关闭值对象。
type (
	//xops:opaque
	//xops:failclosed
	EnsureContext struct {
		operationID security.OperationID
		stepLabel   string
		maxRetries  uint8
		valid       bool
	}
	//xops:opaque
	//xops:failclosed
	EnsureState struct {
		phase          EnsurePhase
		ctx            EnsureContext
		retries        uint8
		at             EnsurePhase
		unknownOutcome algebraic.Option[*execution.OutcomeUnknown]
		reason         string
		valid          bool
	}
	//xops:opaque
	//xops:failclosed
	EnsureInput struct {
		kind    uint8
		outcome execution.ExecutionOutcome
		valid   bool
	}
	//xops:opaque
	//xops:failclosed
	EnsureEffect struct {
		kind    EnsureEffectKind
		attempt uint8
		valid   bool
	}
	//xops:opaque
	//xops:failclosed
	EnsureEvent struct {
		kind   EnsureEventKind
		phase  EnsurePhase
		detail string
		valid  bool
	}
)

// NewEnsureContext 校验操作标识、步骤标签与重试预算上限（<= MaxEnsureRetries），构造 EnsureContext。
func NewEnsureContext(opID security.OperationID, stepLabel string, maxRetries uint8) (EnsureContext, error) {
	if !opID.IsValid() || stepLabel == "" || len(stepLabel) > maxLabelLen || hasForbiddenStrictText(stepLabel) || maxRetries > MaxEnsureRetries {
		return EnsureContext{}, fmt.Errorf("%w: operation_id/step_label/max_retries 参数非法", ErrInvalidEnsureStep)
	}
	return EnsureContext{opID, stepLabel, maxRetries, true}, nil
}

// NewEnsureState 校验上下文并构造 EnsureFSM 初始状态（EnsurePhasePending）。
func NewEnsureState(ctx EnsureContext) (EnsureState, error) {
	if !ctx.IsValid() {
		return EnsureState{}, ErrInvalidEnsureStep
	}
	return EnsureState{phase: EnsurePhasePending, ctx: ctx, valid: true}, nil
}

func (c EnsureContext) IsValid() bool {
	return c.valid && c.operationID.IsValid() && c.stepLabel != "" && c.maxRetries <= MaxEnsureRetries
}
func (c EnsureContext) OperationID() security.OperationID { return c.operationID }
func (c EnsureContext) StepLabel() string                 { return c.stepLabel }
func (c EnsureContext) MaxRetries() uint8                 { return c.maxRetries }
func (s EnsureState) IsValid() bool {
	return s.valid && s.phase.IsValid() && s.ctx.IsValid() && s.retries <= s.ctx.maxRetries
}
func (s EnsureState) IsTerminal() bool {
	return s.IsValid() && s.phase >= EnsurePhaseConvergedUnchanged && s.phase <= EnsurePhaseUncertainOutcome
}
func (s EnsureState) Phase() EnsurePhase     { return s.phase }
func (s EnsureState) Context() EnsureContext { return s.ctx }
func (s EnsureState) Retries() uint8         { return s.retries }
func (s EnsureState) AtPhase() EnsurePhase   { return s.at }
func (s EnsureState) UnknownOutcome() algebraic.Option[*execution.OutcomeUnknown] {
	return s.unknownOutcome
}
func (s EnsureState) Reason() string { return s.reason }
func (i EnsureInput) IsValid() bool {
	return i.valid && (i.kind == ensureInStart || (i.kind == ensureInOutcome && i.outcome != nil && i.outcome.IsValid()))
}
func (e EnsureEffect) IsValid() bool          { return e.valid && e.kind.IsValid() }
func (e EnsureEffect) Kind() EnsureEffectKind { return e.kind }
func (e EnsureEffect) Attempt() uint8         { return e.attempt }
func (e EnsureEvent) IsValid() bool           { return e.valid && e.kind.IsValid() }
func (e EnsureEvent) Kind() EnsureEventKind   { return e.kind }
func (e EnsureEvent) Phase() EnsurePhase      { return e.phase }
func (e EnsureEvent) Detail() string          { return e.detail }

// EnsureInputStart 与 EnsureInputOutcome 构造 EnsureFSM 校验输入。
func EnsureInputStart() EnsureInput { return EnsureInput{kind: ensureInStart, valid: true} }
func EnsureInputOutcome(outcome execution.ExecutionOutcome) (EnsureInput, error) {
	if outcome == nil || !outcome.IsValid() {
		return EnsureInput{}, fmt.Errorf("%w: ExecutionOutcome 无效", ErrInvalidInput)
	}
	return EnsureInput{kind: ensureInOutcome, outcome: outcome, valid: true}, nil
}

// TransitionEnsure 执行 EnsureFSM 纯 Mealy 状态转移：
//   - 核心安全不变量：Checking/Applying/PostChecking 任意阶段遭遇 *execution.OutcomeUnknown 均立即停机至
//     EnsurePhaseUncertainOutcome，严格产出 0 条重试副作用；
//   - 仅有效 *execution.OutcomeNotStarted（CanRetry()==true）在未超出 maxRetries 预算时允许安排重试。
func TransitionEnsure(state EnsureState, input EnsureInput) (EnsureState, []EnsureEffect, []EnsureEvent, error) {
	if !state.IsValid() {
		return state, nil, nil, ErrInvalidState
	}
	if !input.IsValid() {
		return state, nil, nil, ErrInvalidInput
	}
	switch state.phase {
	case EnsurePhasePending:
		if input.kind != ensureInStart {
			return state, nil, nil, fmt.Errorf("%w: pending 仅接受 Start", ErrIllegalTransition)
		}
		return ensureRun(EnsurePhaseChecking, state.ctx, 0, EnsureEffectRunCheck, EnsureEventCheckStarted, state.ctx.stepLabel)
	case EnsurePhaseChecking, EnsurePhaseApplying, EnsurePhasePostChecking:
		return stepEnsurePhaseOutcome(state, input)
	case EnsurePhaseConvergedUnchanged, EnsurePhaseConvergedChanged, EnsurePhaseFailed, EnsurePhaseUncertainOutcome:
		return state, nil, nil, fmt.Errorf("%w: 终态 %s 不接受输入", ErrIllegalTransition, state.phase)
	default:
		return state, nil, nil, ErrInvalidState
	}
}

func stepEnsurePhaseOutcome(s EnsureState, in EnsureInput) (EnsureState, []EnsureEffect, []EnsureEvent, error) {
	if in.kind != ensureInOutcome {
		return s, nil, nil, fmt.Errorf("%w: %s 仅接受 Outcome", ErrIllegalTransition, s.phase)
	}
	switch v := in.outcome.(type) {
	case *execution.OutcomeUnknown:
		return EnsureState{phase: EnsurePhaseUncertainOutcome, ctx: s.ctx, at: s.phase, unknownOutcome: algebraic.Some(v), reason: v.Reason(), valid: true}, nil, []EnsureEvent{ensureEvent(EnsureEventUncertainOutcome, s.phase, v.Reason())}, nil
	case *execution.OutcomeNotStarted:
		if !v.CanRetry() || s.retries >= s.ctx.maxRetries {
			return ensureFailed(s.ctx, s.phase, pickIf(v.Reason() != "", v.Reason(), "not_started retry budget exhausted"), "retry_exhausted")
		}
		effKind := pickIf(s.phase == EnsurePhaseChecking, EnsureEffectRunCheck, pickIf(s.phase == EnsurePhaseApplying, EnsureEffectRunApply, EnsureEffectRunPostCheck))
		return ensureRun(s.phase, s.ctx, s.retries+1, effKind, EnsureEventRetryingNotStarted, v.Reason())
	case *execution.OutcomeCompleted:
		return handleEnsureCompleted(s, v)
	default:
		return s, nil, nil, ErrInvalidInput
	}
}
func handleEnsureCompleted(s EnsureState, v *execution.OutcomeCompleted) (EnsureState, []EnsureEffect, []EnsureEvent, error) {
	switch s.phase {
	case EnsurePhaseChecking:
		return handleEnsureCheckCompleted(s.ctx, v)
	case EnsurePhaseApplying:
		if v.Succeeded() {
			return ensureRun(EnsurePhasePostChecking, s.ctx, 0, EnsureEffectRunPostCheck, EnsureEventPostCheckStarted, s.ctx.stepLabel)
		}
		return ensureFailed(s.ctx, EnsurePhaseApplying, "apply exited non-zero or abnormally", "apply_failed")
	case EnsurePhasePostChecking:
		if v.Succeeded() {
			return EnsureState{phase: EnsurePhaseConvergedChanged, ctx: s.ctx, valid: true}, nil, []EnsureEvent{ensureEvent(EnsureEventConvergedChanged, EnsurePhaseConvergedChanged, s.ctx.stepLabel)}, nil
		}
		return ensureFailed(s.ctx, EnsurePhasePostChecking, "post_check unsatisfied after apply", "post_check_failed")
	default:
		return s, nil, nil, ErrInvalidState
	}
}
func handleEnsureCheckCompleted(ctx EnsureContext, v *execution.OutcomeCompleted) (EnsureState, []EnsureEffect, []EnsureEvent, error) {
	switch st := v.Status().(type) {
	case *execution.ExitCode:
		if st.IsSuccess() {
			return EnsureState{phase: EnsurePhaseConvergedUnchanged, ctx: ctx, valid: true}, nil, []EnsureEvent{ensureEvent(EnsureEventConvergedUnchanged, EnsurePhaseConvergedUnchanged, ctx.stepLabel)}, nil
		}
		return ensureRun(EnsurePhaseApplying, ctx, 0, EnsureEffectRunApply, EnsureEventApplyStarted, ctx.stepLabel)
	case *execution.ExitSignal:
		return ensureFailed(ctx, EnsurePhaseChecking, "check probe terminated by signal "+st.Signal(), "check_signal")
	case *execution.ExitUnknown:
		return ensureFailed(ctx, EnsurePhaseChecking, "check probe missing exit status", "check_exit_unknown")
	default:
		return ensureFailed(ctx, EnsurePhaseChecking, "invalid check exit status", "check_invalid_status")
	}
}
func ensureRun(phase EnsurePhase, ctx EnsureContext, retries uint8, eff EnsureEffectKind, ev EnsureEventKind, detail string) (EnsureState, []EnsureEffect, []EnsureEvent, error) {
	return EnsureState{phase: phase, ctx: ctx, retries: retries, valid: true}, []EnsureEffect{{kind: eff, attempt: retries + 1, valid: true}}, []EnsureEvent{ensureEvent(ev, phase, detail)}, nil
}
func ensureFailed(ctx EnsureContext, at EnsurePhase, reason, detail string) (EnsureState, []EnsureEffect, []EnsureEvent, error) {
	return EnsureState{phase: EnsurePhaseFailed, ctx: ctx, at: at, reason: sanitizeReason(reason), valid: true}, nil, []EnsureEvent{ensureEvent(EnsureEventFailed, at, detail)}, nil
}
func ensureEvent(kind EnsureEventKind, phase EnsurePhase, detail string) EnsureEvent {
	return EnsureEvent{kind: kind, phase: phase, detail: sanitizeReason(detail), valid: true}
}
