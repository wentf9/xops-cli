package fsm

import (
	"errors"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

func mustEnrollCtx(t *testing.T, refs []secret.Ref, stagedAt time.Time) PendingEnrollContext {
	t.Helper()
	node, err := inventory.ParseNodeID("new-edge-01")
	if err != nil {
		t.Fatalf("ParseNodeID 失败: %v", err)
	}
	ttl := algebraic.FromStdDuration(5 * time.Minute)
	ctx, err := NewPendingEnrollContext(PendingEnrollContextSpec{
		LeaseID:    testOpID(40),
		TargetNode: node,
		PinnedRefs: refs,
		StagedAt:   stagedAt,
		TTL:        ttl,
	})
	if err != nil {
		t.Fatalf("NewPendingEnrollContext 失败: %v", err)
	}
	return ctx
}

func mustFingerprint(t *testing.T) inventory.KeyFingerprint {
	t.Helper()
	fp, err := inventory.ParseKeyFingerprint("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU")
	if err != nil {
		t.Fatalf("ParseKeyFingerprint 失败: %v", err)
	}
	return fp
}

func assertEnrollStep(t *testing.T, st PendingEnrollState, effs []PendingEnrollEffect, err error, wantPhase PendingEnrollPhase, wantEff PendingEnrollEffectKind) {
	t.Helper()
	if err != nil || st.Phase() != wantPhase {
		t.Fatalf("期望阶段 %s，实际 phase=%v err=%v", wantPhase, st.Phase(), err)
	}
	if wantEff == EnrollEffectInvalid && len(effs) != 0 {
		t.Fatalf("阶段 %s 不应产生副作用，实际 %v", wantPhase, effs)
	}
	if wantEff != EnrollEffectInvalid && (len(effs) != 1 || effs[0].Kind() != wantEff) {
		t.Fatalf("阶段 %s 期望副作用 %s，实际 %v", wantPhase, wantEff, effs)
	}
}

func assertEnrollGCPin(t *testing.T, graph inventory.Graph, ref secret.Ref, st PendingEnrollState, wantCanGC bool) {
	t.Helper()
	if canGC, _ := graph.CanGCSecret(ref, st.PinnedSecretRefs()...); canGC != wantCanGC {
		t.Fatalf("阶段 %s CanGCSecret=%v，期望 %v", st.Phase(), canGC, wantCanGC)
	}
}

func TestPendingEnrollVerifyBeforeEnrollAndVaultGCPinning(t *testing.T) {
	t0 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	ref := mustSecretRef(t, "vault", "staged-pass")
	ctx := mustEnrollCtx(t, []secret.Ref{ref}, t0)
	graph := inventory.EmptyGraph()
	okIn := mustEnrollIn(t)

	// 1. Idle -> Staged 钉住凭据；直接与 inventory.Graph.CanGCSecret 联调验证 GC 保护
	st := NewPendingEnrollState()
	st, effs, _, err := TransitionPendingEnroll(st, okIn(EnrollInputStage(ctx)))
	assertEnrollStep(t, st, effs, err, PendingEnrollPhaseStaged, EnrollEffectPinSecrets)
	assertEnrollGCPin(t, graph, ref, st, false)

	// 2. Verify-Before-Enroll 铁律：Staged/Probing 阶段严禁跳过探测直接 Commit！
	inCommit := okIn(EnrollInputCommit(t0.Add(time.Minute)))
	if _, effs, _, err := TransitionPendingEnroll(st, inCommit); !errors.Is(err, ErrIllegalTransition) || len(effs) != 0 {
		t.Fatalf("未探测节点严禁提交入库: effs=%v err=%v", effs, err)
	}
	st, effs, _, err = TransitionPendingEnroll(st, okIn(EnrollInputStartProbe(t0.Add(30*time.Second))))
	assertEnrollStep(t, st, effs, err, PendingEnrollPhaseProbing, EnrollEffectProbeConnection)
	assertEnrollGCPin(t, graph, ref, st, false)
	if _, _, _, err := TransitionPendingEnroll(st, inCommit); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("Probing 态严禁跳过验证直接 Commit: %v", err)
	}

	// 3. Probing -> Verified -> Committing -> Enrolled
	st, effs, _, err = TransitionPendingEnroll(st, okIn(EnrollInputProbeResult(true, mustFingerprint(t), t0.Add(45*time.Second), "")))
	assertEnrollStep(t, st, effs, err, PendingEnrollPhaseVerified, EnrollEffectInvalid)
	st, effs, _, err = TransitionPendingEnroll(st, inCommit)
	assertEnrollStep(t, st, effs, err, PendingEnrollPhaseCommitting, EnrollEffectCommitInventoryCAS)
	assertEnrollGCPin(t, graph, ref, st, false)
	st, effs, _, err = TransitionPendingEnroll(st, okIn(EnrollInputCommitResult(DurabilityCommitted, "")))
	assertEnrollStep(t, st, effs, err, PendingEnrollPhaseEnrolled, EnrollEffectReleasePins)
	if !st.IsTerminal() || len(st.PinnedSecretRefs()) != 0 {
		t.Fatalf("Enrolled 后应为终态并清空临时租约钉住")
	}
}

func TestPendingEnrollCleanupExpiryAndUncertainDurability(t *testing.T) {
	t0 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	ref := mustSecretRef(t, "vault", "temp-key")
	ctx := mustEnrollCtx(t, []secret.Ref{ref}, t0)
	graph := inventory.EmptyGraph()

	okIn := mustEnrollIn(t)
	stageAndProbe := func() PendingEnrollState {
		st, _, _, _ := TransitionPendingEnroll(NewPendingEnrollState(), okIn(EnrollInputStage(ctx)))
		st, _, _, _ = TransitionPendingEnroll(st, okIn(EnrollInputStartProbe(t0.Add(time.Second))))
		return st
	}

	// 1. 探测失败 -> CleaningUp（保持钉住） -> CleanupResult(Succeeded) -> Aborted（释放钉住允许 GC）
	st := stageAndProbe()
	st, effs, _, err := TransitionPendingEnroll(st, okIn(EnrollInputProbeResult(false, zeroVal[inventory.KeyFingerprint](), t0.Add(2*time.Second), "auth failed")))
	if err != nil || st.Phase() != PendingEnrollPhaseCleaningUp || len(effs) != 1 || effs[0].Kind() != EnrollEffectCleanupPendingSecrets {
		t.Fatalf("探测失败应进入 CleaningUp: phase=%v effs=%v err=%v", st.Phase(), effs, err)
	}
	if canGC, _ := graph.CanGCSecret(ref, st.PinnedSecretRefs()...); canGC {
		t.Fatalf("CleaningUp 未完成前严禁解除钉住")
	}
	st, effs, _, err = TransitionPendingEnroll(st, okIn(EnrollInputCleanupResult(SideEffectSucceeded, "")))
	if err != nil || st.Phase() != PendingEnrollPhaseAborted || !st.IsTerminal() || len(effs) != 1 || effs[0].Kind() != EnrollEffectReleasePins {
		t.Fatalf("清理完成应进入 Aborted 并释放钉住: phase=%v effs=%v err=%v", st.Phase(), effs, err)
	}
	if canGC, _ := graph.CanGCSecret(ref, st.PinnedSecretRefs()...); !canGC {
		t.Fatalf("Aborted 释放钉住后空图中 CanGCSecret 应返回 true")
	}

	// 2. 租约未到期时 Expire 拒绝；到期后自动进入 CleaningUp
	st = stageAndProbe()
	if _, _, _, err := TransitionPendingEnroll(st, okIn(EnrollInputExpire(t0.Add(time.Minute)))); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("未到期租约不应允许 Expire: %v", err)
	}
	st, effs, _, err = TransitionPendingEnroll(st, okIn(EnrollInputExpire(t0.Add(6*time.Minute))))
	if err != nil || st.Phase() != PendingEnrollPhaseCleaningUp || len(effs) != 1 || effs[0].Kind() != EnrollEffectCleanupPendingSecrets {
		t.Fatalf("到期租约应进入 CleaningUp: phase=%v effs=%v err=%v", st.Phase(), effs, err)
	}

	// 3. 无暂存凭据时取消直接进入 Aborted（无需 CleaningUp）
	ctxNoRef := mustEnrollCtx(t, nil, t0)
	stNoRef, _, _, _ := TransitionPendingEnroll(NewPendingEnrollState(), okIn(EnrollInputStage(ctxNoRef)))
	stNoRef, effs, _, err = TransitionPendingEnroll(stNoRef, EnrollInputCancel("user_cancel"))
	if err != nil || stNoRef.Phase() != PendingEnrollPhaseAborted || len(effs) != 0 {
		t.Fatalf("无暂存凭据取消应直接 Aborted: phase=%v effs=%v err=%v", stNoRef.Phase(), effs, err)
	}

	// 4. 提交遇 Applied && !Durable -> Uncertain，严格 0 副作用且持续保留钉住防误删！
	st = stageAndProbe()
	st, _, _, _ = TransitionPendingEnroll(st, okIn(EnrollInputProbeResult(true, mustFingerprint(t), t0.Add(5*time.Second), "")))
	st, _, _, _ = TransitionPendingEnroll(st, okIn(EnrollInputCommit(t0.Add(6*time.Second))))
	st, effs, _, err = TransitionPendingEnroll(st, okIn(EnrollInputCommitResult(DurabilityAppliedNotDurable, "fsync err")))
	if err != nil || st.Phase() != PendingEnrollPhaseUncertain || !st.IsTerminal() || len(effs) != 0 {
		t.Fatalf("Applied && !Durable 应停机于 Uncertain 且 0 副作用: phase=%v effs=%v err=%v", st.Phase(), effs, err)
	}
	if canGC, _ := graph.CanGCSecret(ref, st.PinnedSecretRefs()...); canGC {
		t.Fatalf("Uncertain 停机态必须保留凭据钉住防止 GC 误删")
	}
}

func TestPendingEnrollTimeWindowAndBackdatedInput(t *testing.T) {
	t0 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	ref := mustSecretRef(t, "vault", "time-key")
	ctx := mustEnrollCtx(t, []secret.Ref{ref}, t0)
	okIn := mustEnrollIn(t)

	// IsExpiredAt vs IsActiveAt：早于 stagedAt 不视为过期，也不处于活动窗口
	before := t0.Add(-time.Second)
	if ctx.IsExpiredAt(before) || ctx.IsActiveAt(before) {
		t.Fatalf("now < stagedAt 时 IsExpiredAt 与 IsActiveAt 均必须为 false")
	}
	if !ctx.IsActiveAt(t0) || ctx.IsExpiredAt(t0) || ctx.IsActiveAt(t0.Add(5*time.Minute)) || !ctx.IsExpiredAt(t0.Add(5*time.Minute)) {
		t.Fatalf("租约活动窗口 [stagedAt, stagedAt+ttl) 边界语义错误")
	}
	// 倒流时间戳传入活动租约必须返回 ErrInvalidInput 且不破坏原 Staged 态
	st, _, _, _ := TransitionPendingEnroll(NewPendingEnrollState(), okIn(EnrollInputStage(ctx)))
	for _, in := range []PendingEnrollInput{okIn(EnrollInputStartProbe(before)), okIn(EnrollInputExpire(before))} {
		next, effs, evs, err := TransitionPendingEnroll(st, in)
		if !errors.Is(err, ErrInvalidInput) || next.Phase() != PendingEnrollPhaseStaged || len(effs) != 0 || len(evs) != 0 {
			t.Fatalf("倒流时间戳应返回 ErrInvalidInput 且保留活动租约: next=%v effs=%v err=%v", next.Phase(), effs, err)
		}
	}
}

func TestPendingEnrollExhaustivePhaseInputMatrix(t *testing.T) {
	t0 := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	ref := mustSecretRef(t, "vault", "m-key")
	ctx := mustEnrollCtx(t, []secret.Ref{ref}, t0)
	fp := mustFingerprint(t)
	okIn := mustEnrollIn(t)

	states := []PendingEnrollState{
		NewPendingEnrollState(),
		{phase: PendingEnrollPhaseStaged, ctx: ctx, valid: true},
		{phase: PendingEnrollPhaseProbing, ctx: ctx, valid: true},
		{phase: PendingEnrollPhaseVerified, ctx: ctx, hostKeyFingerprint: algebraic.Some(fp), valid: true},
		{phase: PendingEnrollPhaseCommitting, ctx: ctx, hostKeyFingerprint: algebraic.Some(fp), valid: true},
		{phase: PendingEnrollPhaseCleaningUp, ctx: ctx, reason: "clean", valid: true},
		{phase: PendingEnrollPhaseEnrolled, ctx: ctx, hostKeyFingerprint: algebraic.Some(fp), valid: true},
		{phase: PendingEnrollPhaseAborted, ctx: ctx, reason: "ab", valid: true},
		{phase: PendingEnrollPhaseUncertain, ctx: ctx, reason: "unc", valid: true},
	}
	inputs := []PendingEnrollInput{
		okIn(EnrollInputStage(ctx)),
		okIn(EnrollInputStartProbe(t0.Add(time.Second))),
		okIn(EnrollInputProbeResult(true, fp, t0.Add(2*time.Second), "")),
		okIn(EnrollInputCommit(t0.Add(3 * time.Second))),
		okIn(EnrollInputCommitResult(DurabilityCommitted, "")),
		okIn(EnrollInputCleanupResult(SideEffectSucceeded, "")),
		EnrollInputCancel("cancel"),
		okIn(EnrollInputExpire(t0.Add(10 * time.Minute))),
	}
	if _, _, _, err := TransitionPendingEnroll(PendingEnrollState{}, inputs[0]); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("零值状态应返回 ErrInvalidState: %v", err)
	}
	if _, _, _, err := TransitionPendingEnroll(states[0], PendingEnrollInput{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("零值输入应返回 ErrInvalidInput: %v", err)
	}
	allowed := map[[2]int]bool{
		{0, 0}: true,
		{1, 1}: true, {1, 6}: true, {1, 7}: true,
		{2, 2}: true, {2, 6}: true, {2, 7}: true,
		{3, 3}: true, {3, 6}: true, {3, 7}: true,
		{4, 4}: true,
		{5, 5}: true,
	}
	for i, st := range states {
		for j, in := range inputs {
			next, effs, evs, err := TransitionPendingEnroll(st, in)
			if allowed[[2]int{i, j}] && err != nil {
				t.Fatalf("PendingEnroll 矩阵(%s, %d) 期望合法，实际 %v", st.Phase(), j, err)
			}
			if !allowed[[2]int{i, j}] && (!errors.Is(err, ErrIllegalTransition) || next.Phase() != st.Phase() || len(effs) != 0 || len(evs) != 0) {
				t.Fatalf("PendingEnroll 矩阵(%s, %d) 应失败关闭: next=%v err=%v", st.Phase(), j, next.Phase(), err)
			}
		}
	}
}

func mustEnrollIn(t *testing.T) func(PendingEnrollInput, error) PendingEnrollInput {
	return func(in PendingEnrollInput, err error) PendingEnrollInput {
		t.Helper()
		if err != nil {
			t.Fatalf("构造 PendingEnrollInput 失败: %v", err)
		}
		return in
	}
}
