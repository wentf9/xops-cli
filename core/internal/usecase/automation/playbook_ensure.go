package automation

import (
	"context"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/internal/gate"
)

// runEnsureAction 严格驱动 core/domain/fsm.EnsureFSM 纯 Mealy 状态机：
// 仅对允许重试且未超 maxRetries 预算的 *OutcomeNotStarted 重试；
// 任意阶段遭遇 *OutcomeUnknown（含 Applied&&!Durable）立即停机转入 EnsurePhaseUncertainOutcome（0 重试、严禁降级）。
func (rc *playbookRunContext) runEnsureAction(
	ctx context.Context,
	target TargetNode,
	stepID playbook.StepID,
	act *playbook.StepEnsure,
	nodeEmitter *streamEmitter,
) (playbook.StepStatus, execution.ExecutionOutcome, string) {
	ensCtx, err := fsm.NewEnsureContext(rc.opID, stepID.String(), act.MaxRetries())
	if err != nil {
		return playbook.StepStatusFailed, makeNotStartedOutcome(execution.StartPhaseValidate, "invalid_ensure_ctx", err), err.Error()
	}
	state, err := fsm.NewEnsureState(ensCtx)
	if err != nil {
		return playbook.StepStatusFailed, makeNotStartedOutcome(execution.StartPhaseValidate, "invalid_ensure_state", err), err.Error()
	}
	prevPhase := state.Phase()
	state, effects, evs, err := fsm.TransitionEnsure(state, fsm.EnsureInputStart())
	if err != nil {
		return playbook.StepStatusFailed, makeNotStartedOutcome(execution.StartPhaseValidate, "ensure_start_failed", err), err.Error()
	}
	rc.emitEnsureEvents(ctx, nodeEmitter, target.nodeID, prevPhase, state, evs)

	var lastOutcome execution.ExecutionOutcome
	for !state.IsTerminal() {
		nextState, nextEffects, nextLast, failStatus, stepErr := rc.stepEnsureEffects(ctx, target, act, state, effects, nodeEmitter)
		lastOutcome = nextLast
		if stepErr != nil {
			return failStatus, lastOutcome, stepErr.Error()
		}
		state, effects = nextState, nextEffects
	}
	return mapEnsureTerminalState(state, lastOutcome)
}

func (rc *playbookRunContext) stepEnsureEffects(
	ctx context.Context,
	target TargetNode,
	act *playbook.StepEnsure,
	state fsm.EnsureState,
	effects []fsm.EnsureEffect,
	nodeEmitter *streamEmitter,
) (fsm.EnsureState, []fsm.EnsureEffect, execution.ExecutionOutcome, playbook.StepStatus, error) {
	var nextEffects []fsm.EnsureEffect
	var lastOutcome execution.ExecutionOutcome
	for _, eff := range effects {
		if rc.svc.gate.IsHalted() {
			out := makeNotStartedOutcome(execution.StartPhaseAuthorize, "gate_halted", gate.ErrGateHalted)
			return state, nil, out, playbook.StepStatusFailed, gate.ErrGateHalted
		}
		effOutcome := rc.executeEnsureEffect(ctx, target, act, eff, nodeEmitter)
		lastOutcome = effOutcome
		in, iErr := fsm.EnsureInputOutcome(effOutcome)
		if iErr != nil {
			out := makeNotStartedOutcome(execution.StartPhaseValidate, "ensure_input_invalid", iErr)
			return state, nil, out, playbook.StepStatusFailed, iErr
		}
		prev := state.Phase()
		nextState, effs, transEvs, tErr := fsm.TransitionEnsure(state, in)
		if tErr != nil {
			return state, nil, lastOutcome, playbook.StepStatusFailed, tErr
		}
		state, nextEffects = nextState, effs
		rc.emitEnsureEvents(ctx, nodeEmitter, target.nodeID, prev, state, transEvs)
	}
	return state, nextEffects, lastOutcome, playbook.StepStatusInvalid, nil
}

func (rc *playbookRunContext) emitEnsureEvents(
	ctx context.Context,
	nodeEmitter *streamEmitter,
	nodeID inventory.NodeID,
	from fsm.EnsurePhase,
	to fsm.EnsureState,
	evs []fsm.EnsureEvent,
) {
	nodeEmitter.emitEnsureTransition(ctx, nodeID, from, to.Phase(), evs, to.IsTerminal())
	rc.batchEmitter.emitEnsureTransition(ctx, nodeID, from, to.Phase(), evs, to.IsTerminal())
}

func (rc *playbookRunContext) executeEnsureEffect(
	ctx context.Context,
	target TargetNode,
	act *playbook.StepEnsure,
	eff fsm.EnsureEffect,
	nodeEmitter *streamEmitter,
) execution.ExecutionOutcome {
	switch eff.Kind() {
	case fsm.EnsureEffectRunCheck, fsm.EnsureEffectRunPostCheck:
		return rc.runEnsureSubAction(ctx, target, act.Check(), nodeEmitter)
	case fsm.EnsureEffectRunApply:
		return rc.runEnsureSubAction(ctx, target, act.Action(), nodeEmitter)
	default:
		return makeNotStartedOutcome(execution.StartPhaseValidate, "invalid_ensure_effect", ErrUnsupportedAction)
	}
}

func (rc *playbookRunContext) runEnsureSubAction(
	ctx context.Context,
	target TargetNode,
	sub playbook.StepAction,
	nodeEmitter *streamEmitter,
) execution.ExecutionOutcome {
	switch v := sub.(type) {
	case *playbook.StepShell:
		_, out, _ := rc.runShellAction(ctx, target, v, nodeEmitter)
		return out
	case *playbook.StepScript:
		_, out, _ := rc.runScriptAction(ctx, target, v, nodeEmitter)
		return out
	case *playbook.StepCopy:
		_, out, _ := rc.runCopyAction(ctx, target, v)
		return out
	case *playbook.StepTemplate:
		_, out, _ := rc.runTemplateAction(ctx, target, v)
		return out
	case *playbook.StepEnsure:
		return makeNotStartedOutcome(execution.StartPhaseValidate, "nested_ensure_forbidden", playbook.ErrNestedEnsureForbidden)
	default:
		return makeNotStartedOutcome(execution.StartPhaseValidate, "unsupported_ensure_subaction", ErrUnsupportedAction)
	}
}

func mapEnsureTerminalState(state fsm.EnsureState, lastOutcome execution.ExecutionOutcome) (playbook.StepStatus, execution.ExecutionOutcome, string) {
	switch state.Phase() {
	case fsm.EnsurePhaseConvergedUnchanged:
		okOut, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
		return playbook.StepStatusSucceeded, okOut, "ensure converged (unchanged)"
	case fsm.EnsurePhaseConvergedChanged:
		okOut, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
		return playbook.StepStatusChanged, okOut, "ensure converged (changed)"
	case fsm.EnsurePhaseUncertainOutcome:
		if unk, ok := state.UnknownOutcome().Get(); ok && unk.IsValid() {
			return playbook.StepStatusOutcomeUnknown, unk, pickIf(state.Reason() != "", state.Reason(), unk.Reason())
		}
		fallback, _ := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, "ensure_unknown", state.Reason())
		return playbook.StepStatusOutcomeUnknown, fallback, state.Reason()
	case fsm.EnsurePhaseFailed:
		return playbook.StepStatusFailed, lastOutcome, pickIf(state.Reason() != "", state.Reason(), "ensure failed")
	default:
		return playbook.StepStatusFailed, lastOutcome, "unexpected ensure terminal phase"
	}
}

func mapOutcomeToStepStatus(outcome execution.ExecutionOutcome, execErr error, successStatus playbook.StepStatus) (playbook.StepStatus, execution.ExecutionOutcome, string) {
	if outcome == nil || !outcome.IsValid() {
		out := makeNotStartedOutcome(execution.StartPhaseValidate, "missing_outcome", execErr)
		return playbook.StepStatusFailed, out, errString(execErr, "missing execution outcome")
	}
	switch v := outcome.(type) {
	case *execution.OutcomeUnknown:
		return playbook.StepStatusOutcomeUnknown, v, pickIf(v.Reason() != "", v.Reason(), errString(execErr, "outcome unknown"))
	case *execution.OutcomeNotStarted:
		return playbook.StepStatusFailed, v, pickIf(v.Reason() != "", v.Reason(), errString(execErr, "not started"))
	case *execution.OutcomeCompleted:
		if v.Succeeded() && execErr == nil {
			return successStatus, v, "ok"
		}
		return playbook.StepStatusFailed, v, errString(execErr, "non-zero exit status")
	default:
		return playbook.StepStatusFailed, outcome, "invalid execution outcome"
	}
}

func errString(err error, fallback string) string {
	if err != nil {
		return err.Error()
	}
	return fallback
}

func buildSimpleStepRecord(
	nodeID inventory.NodeID,
	stepID playbook.StepID,
	status playbook.StepStatus,
	outcome algebraic.Option[execution.ExecutionOutcome],
	dur algebraic.Duration,
	msg string,
) playbook.StepExecutionRecord {
	rec, err := playbook.NewStepExecutionRecord(playbook.StepExecutionRecordSpec{
		NodeID: nodeID, StepID: stepID, Status: status, Outcome: outcome, Duration: dur, Message: strings.TrimSpace(msg),
	})
	if err == nil {
		return rec
	}
	fallback, _ := playbook.NewStepExecutionRecord(playbook.StepExecutionRecordSpec{
		NodeID: nodeID, StepID: stepID, Status: status, Duration: algebraic.ZeroDuration(), Message: msg,
	})
	return fallback
}
