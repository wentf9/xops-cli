package fsm

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/execution"
)

func mustEnsureCtx(t *testing.T, maxRetries uint8) EnsureContext {
	t.Helper()
	ctx, err := NewEnsureContext(testOpID(30), "ensure-nginx", maxRetries)
	if err != nil {
		t.Fatalf("NewEnsureContext 失败: %v", err)
	}
	return ctx
}

func assertEnsureStep(t *testing.T, st EnsureState, effs []EnsureEffect, err error, wantPhase EnsurePhase, wantEff EnsureEffectKind) {
	t.Helper()
	if err != nil || st.Phase() != wantPhase {
		t.Fatalf("期望阶段 %s，实际 phase=%v err=%v", wantPhase, st.Phase(), err)
	}
	if wantEff == EnsureEffectInvalid && len(effs) != 0 {
		t.Fatalf("阶段 %s 不应产生副作用，实际 %v", wantPhase, effs)
	}
	if wantEff != EnsureEffectInvalid && (len(effs) != 1 || effs[0].Kind() != wantEff) {
		t.Fatalf("阶段 %s 期望副作用 %s，实际 %v", wantPhase, wantEff, effs)
	}
}

func TestEnsureConvergenceFlows(t *testing.T) {
	outOK, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	outDiff, _ := execution.NewOutcomeCompleted(execution.NewExitCode(1), false)
	inOK, _ := EnsureInputOutcome(outOK)
	inDiff, _ := EnsureInputOutcome(outDiff)

	// 1. Check 一次满足 -> ConvergedUnchanged（无 Apply）
	st, _ := NewEnsureState(mustEnsureCtx(t, 2))
	st, effs, _, err := TransitionEnsure(st, EnsureInputStart())
	assertEnsureStep(t, st, effs, err, EnsurePhaseChecking, EnsureEffectRunCheck)
	st, effs, _, err = TransitionEnsure(st, inOK)
	assertEnsureStep(t, st, effs, err, EnsurePhaseConvergedUnchanged, EnsureEffectInvalid)

	// 2. Check 不满足 -> Applying -> PostChecking -> ConvergedChanged
	st, _ = NewEnsureState(mustEnsureCtx(t, 2))
	st, _, _, _ = TransitionEnsure(st, EnsureInputStart())
	st, effs, _, err = TransitionEnsure(st, inDiff)
	assertEnsureStep(t, st, effs, err, EnsurePhaseApplying, EnsureEffectRunApply)
	st, effs, _, err = TransitionEnsure(st, inOK)
	assertEnsureStep(t, st, effs, err, EnsurePhasePostChecking, EnsureEffectRunPostCheck)
	st, effs, _, err = TransitionEnsure(st, inOK)
	assertEnsureStep(t, st, effs, err, EnsurePhaseConvergedChanged, EnsureEffectInvalid)
}

func TestEnsureAbnormalExitAndBoundedNotStartedRetry(t *testing.T) {
	sigSt, _ := execution.NewExitSignal("SIGKILL", false, "killed")
	outSig, _ := execution.NewOutcomeCompleted(sigSt, false)
	outExitUnk, _ := execution.NewOutcomeCompleted(execution.NewExitUnknown("no status"), false)
	outNotStarted, _ := execution.NewOutcomeNotStarted(execution.StartPhaseDial, "E_DIAL", "conn refused")

	// Check 遇 ExitSignal / ExitUnknown 必须失败，严禁盲目进入 Apply
	for _, abnormal := range []execution.ExecutionOutcome{outSig, outExitUnk} {
		chk, _ := NewEnsureState(mustEnsureCtx(t, 2))
		chk, _, _, _ = TransitionEnsure(chk, EnsureInputStart())
		inAbn, _ := EnsureInputOutcome(abnormal)
		res, effs, _, err := TransitionEnsure(chk, inAbn)
		assertEnsureStep(t, res, effs, err, EnsurePhaseFailed, EnsureEffectInvalid)
	}

	// 仅有效 OutcomeNotStarted 允许在 maxRetries 预算内重试，预算耗尽后转 Failed
	ctxR := mustEnsureCtx(t, 2)
	inNS, _ := EnsureInputOutcome(outNotStarted)
	for _, tc := range []struct {
		p   EnsurePhase
		eff EnsureEffectKind
	}{
		{EnsurePhaseChecking, EnsureEffectRunCheck},
		{EnsurePhaseApplying, EnsureEffectRunApply},
		{EnsurePhasePostChecking, EnsureEffectRunPostCheck},
	} {
		cur := EnsureState{phase: tc.p, ctx: ctxR, valid: true}
		cur, effs, _, err := TransitionEnsure(cur, inNS)
		assertEnsureStep(t, cur, effs, err, tc.p, tc.eff)
		if cur.Retries() != 1 || effs[0].Attempt() != 2 {
			t.Fatalf("phase=%s 第1次重试计数异常: retries=%d attempt=%d", tc.p, cur.Retries(), effs[0].Attempt())
		}
		cur, effs, _, err = TransitionEnsure(cur, inNS)
		assertEnsureStep(t, cur, effs, err, tc.p, tc.eff)
		cur, effs, _, err = TransitionEnsure(cur, inNS)
		assertEnsureStep(t, cur, effs, err, EnsurePhaseFailed, EnsureEffectInvalid)
	}
}

func TestEnsureOutcomeUnknownForbidsRetry(t *testing.T) {
	// 核心安全不变量：Checking / Applying / PostChecking 任意阶段遇 OutcomeUnknown
	// 即使 maxRetries == MaxEnsureRetries，也必须立即停机于 UncertainOutcome 且严格 0 重试副作用！
	outUnknown, _ := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, "E_LOST", "disconnect")
	ctxMax := mustEnsureCtx(t, MaxEnsureRetries)
	inUnk, _ := EnsureInputOutcome(outUnknown)
	for _, p := range []EnsurePhase{EnsurePhaseChecking, EnsurePhaseApplying, EnsurePhasePostChecking} {
		cur := EnsureState{phase: p, ctx: ctxMax, valid: true}
		next, effs, evs, err := TransitionEnsure(cur, inUnk)
		assertEnsureStep(t, next, effs, err, EnsurePhaseUncertainOutcome, EnsureEffectInvalid)
		if !next.IsTerminal() || next.AtPhase() != p {
			t.Fatalf("phase=%s UncertainOutcome 元数据异常: at=%v", p, next.AtPhase())
		}
		if _, hasUnk := next.UnknownOutcome().Get(); !hasUnk || len(evs) != 1 || evs[0].Kind() != EnsureEventUncertainOutcome {
			t.Fatalf("phase=%s 应保留 UnknownOutcome 并发出 UncertainOutcome 事件", p)
		}
	}
}

func TestEnsureExhaustivePhaseInputMatrix(t *testing.T) {
	ctx := mustEnsureCtx(t, 1)
	if _, err := NewEnsureContext(testOpID(31), "ok", MaxEnsureRetries+1); !errors.Is(err, ErrInvalidEnsureStep) {
		t.Fatalf("超出 MaxEnsureRetries 必须拒绝: %v", err)
	}
	outOK, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	inOut, _ := EnsureInputOutcome(outOK)
	inputs := []EnsureInput{EnsureInputStart(), inOut}
	states := []EnsureState{
		{phase: EnsurePhasePending, ctx: ctx, valid: true},
		{phase: EnsurePhaseChecking, ctx: ctx, valid: true},
		{phase: EnsurePhaseApplying, ctx: ctx, valid: true},
		{phase: EnsurePhasePostChecking, ctx: ctx, valid: true},
		{phase: EnsurePhaseConvergedUnchanged, ctx: ctx, valid: true},
		{phase: EnsurePhaseConvergedChanged, ctx: ctx, valid: true},
		{phase: EnsurePhaseFailed, ctx: ctx, at: EnsurePhaseChecking, valid: true},
		{phase: EnsurePhaseUncertainOutcome, ctx: ctx, at: EnsurePhaseApplying, valid: true},
	}
	if _, _, _, err := TransitionEnsure(EnsureState{}, inputs[0]); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("零值状态应返回 ErrInvalidState: %v", err)
	}
	if _, _, _, err := TransitionEnsure(states[0], EnsureInput{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("零值输入应返回 ErrInvalidInput: %v", err)
	}
	allowed := map[[2]int]bool{{0, 0}: true, {1, 1}: true, {2, 1}: true, {3, 1}: true}
	for i, st := range states {
		for j, in := range inputs {
			next, effs, evs, err := TransitionEnsure(st, in)
			if allowed[[2]int{i, j}] && err != nil {
				t.Fatalf("Ensure 矩阵(%s, %d) 期望合法，实际 %v", st.Phase(), j, err)
			}
			if !allowed[[2]int{i, j}] && (!errors.Is(err, ErrIllegalTransition) || next.Phase() != st.Phase() || len(effs) != 0 || len(evs) != 0) {
				t.Fatalf("Ensure 矩阵(%s, %d) 应失败关闭: next=%v err=%v", st.Phase(), j, next.Phase(), err)
			}
		}
	}
}
