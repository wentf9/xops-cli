package fsm

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
)

func mustApprovalBinding(t *testing.T, path string) security.OperationBinding {
	t.Helper()
	b, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability:     security.CapabilityKindOf[security.CapFileMut](),
		Tool:           "sftp",
		Action:         "write",
		NodeID:         "prod-1",
		CanonicalPaths: []string{path},
	})
	if err != nil {
		t.Fatalf("NewOperationBinding(%q) 失败: %v", path, err)
	}
	return b
}

func mustScopeSnap(t *testing.T, path string, zones []string, risk security.RiskLevel, dec security.GuardrailDecision) security.ScopeSnapshot {
	t.Helper()
	sp, err := security.NewScopedPath(path, false, zones...)
	if err != nil {
		t.Fatalf("NewScopedPath(%q) 失败: %v", path, err)
	}
	snap, err := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityKindOf[security.CapFileMut](),
		TargetNode: "prod-1",
		Verdict:    security.VerdictAllow,
		Risk:       risk,
		Decision:   dec,
		Paths:      []security.ScopedPath{sp},
	})
	if err != nil {
		t.Fatalf("NewScopeSnapshot 失败: %v", err)
	}
	return snap
}

func mustApprovalEnvelope(t *testing.T, opID security.OperationID, bind security.OperationBinding, risk security.RiskLevel, issuedAt time.Time) (security.ApprovalEnvelope, security.Digest) {
	t.Helper()
	dec, err := security.NewDecisionNeedApproval(risk, "need operator approval")
	if err != nil {
		t.Fatalf("NewDecisionNeedApproval 失败: %v", err)
	}
	ttl := algebraic.FromStdDuration(5 * time.Minute)
	var nonce [16]byte
	nonce[0] = 0x7F
	env, err := security.NewApprovalEnvelope(security.ApprovalEnvelopeSpec{
		OperationID:  opID,
		Binding:      bind,
		Risk:         risk,
		Decision:     dec,
		ScopeSummary: "write " + bind.Action(),
		IssuedAt:     issuedAt,
		TTL:          ttl,
		Nonce:        nonce,
	})
	if err != nil {
		t.Fatalf("NewApprovalEnvelope 失败: %v", err)
	}
	dig, err := env.Digest()
	if err != nil {
		t.Fatalf("env.Digest 失败: %v", err)
	}
	return env, dig
}

func assertApprovalPhase(t *testing.T, st ApprovalState, err error, want ApprovalPhase) {
	t.Helper()
	if err != nil || st.Phase() != want {
		t.Fatalf("期望阶段 %s，实际 phase=%v err=%v", want, st.Phase(), err)
	}
}

func assertApprovalSingleEffect(t *testing.T, effs []ApprovalEffect, want ApprovalEffectKind) {
	t.Helper()
	if len(effs) != 1 || effs[0].Kind() != want {
		t.Fatalf("期望唯一副作用 %s，实际 %v", want, effs)
	}
}

func TestApprovalProtectedAToProtectedBRedirectForcesChallenge(t *testing.T) {
	opID := testOpID(10)
	lexBind := mustApprovalBinding(t, "/etc/app/a.conf")
	canBind := mustApprovalBinding(t, "/etc/shadow")
	// 词法预检命中 Protected-A 且 Decision=Allow，远端规范化经软链重定向到 Protected-B 且 Decision 仍为 Allow
	lexSnap := mustScopeSnap(t, "/etc/app/a.conf", []string{"protected-a"}, security.RiskModerate, security.NewDecisionAllow("lex allow"))
	canSnap := mustScopeSnap(t, "/etc/shadow", []string{"protected-b"}, security.RiskModerate, security.NewDecisionAllow("can allow"))

	ctx, err := NewApprovalContext(ApprovalContextSpec{OperationID: opID, LexicalBinding: lexBind, LexicalSnapshot: lexSnap})
	if err != nil {
		t.Fatalf("NewApprovalContext 失败: %v", err)
	}
	st, err := NewApprovalState(ctx)
	assertApprovalPhase(t, st, err, ApprovalPhaseLexicalPrecheck)

	st, effs, _, err := TransitionApproval(st, ApprovalInputEvaluateLexical(true))
	assertApprovalPhase(t, st, err, ApprovalPhaseCanonicalizing)
	assertApprovalSingleEffect(t, effs, ApprovalEffectCanonicalize)

	inCan, err := ApprovalInputCanonicalized(canSnap, canBind)
	if err != nil {
		t.Fatalf("ApprovalInputCanonicalized 失败: %v", err)
	}
	st, _, _, err = TransitionApproval(st, inCan)
	assertApprovalPhase(t, st, err, ApprovalPhaseEvaluatingEscalation)

	// Protected-A -> Protected-B 软链重定向必须触发作用域升级并强制挑战审批
	st, effs, evs, err := TransitionApproval(st, ApprovalInputEvaluateEscalation())
	assertApprovalPhase(t, st, err, ApprovalPhaseChallengePending)
	assertApprovalSingleEffect(t, effs, ApprovalEffectRequestChallenge)
	if !st.Escalated() || !slices.Contains(st.EscalationReasons(), security.EscalationProtectedRedirect) {
		t.Fatalf("升级原因必须包含 EscalationProtectedRedirect: escalated=%v reasons=%v", st.Escalated(), st.EscalationReasons())
	}
	if len(evs) != 2 || evs[0].Kind() != ApprovalEventEscalationDetected {
		t.Fatalf("期望 EscalationDetected 事件，实际 %v", evs)
	}

	// 签发挑战信封并验证有效令牌通过审批
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	env, dig := mustApprovalEnvelope(t, opID, canBind, security.RiskModerate, now)
	inIssue, _ := ApprovalInputIssueChallenge(env)
	st, effs, _, err = TransitionApproval(st, inIssue)
	assertApprovalPhase(t, st, err, ApprovalPhaseChallengeIssued)
	assertApprovalSingleEffect(t, effs, ApprovalEffectPresentChallenge)

	inVerify, _ := ApprovalInputVerifyToken(dig, canBind, now.Add(time.Minute), true)
	st, _, _, err = TransitionApproval(st, inVerify)
	assertApprovalPhase(t, st, err, ApprovalPhaseApproved)
	if !st.IsApproved() || !st.Escalated() || !slices.Contains(st.EscalationReasons(), security.EscalationProtectedRedirect) {
		t.Fatalf("Approved 后必须保留 escalated 与 escalationReasons")
	}
}

func TestApprovalVerdictDenyAndMonotoneLatticeJoin(t *testing.T) {
	opID := testOpID(14)
	bind := mustApprovalBinding(t, "/etc/app/a.conf")
	// 1. 词法 VerdictDeny 即使搭配 DecisionAllow 也必须立即 Denied（INV-E1）
	sp, _ := security.NewScopedPath("/etc/app/a.conf", false)
	denyLex, _ := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityKindOf[security.CapFileMut](), TargetNode: "prod-1",
		Verdict: security.VerdictDeny, Risk: security.RiskSafe, Decision: security.NewDecisionAllow("allow"), Paths: []security.ScopedPath{sp},
	})
	ctxDeny, _ := NewApprovalContext(ApprovalContextSpec{OperationID: opID, LexicalBinding: bind, LexicalSnapshot: denyLex})
	st0, _ := NewApprovalState(ctxDeny)
	st0, _, _, err := TransitionApproval(st0, ApprovalInputEvaluateLexical(false))
	assertApprovalPhase(t, st0, err, ApprovalPhaseDenied)

	// 1b. 规范化阶段返回 VerdictDeny 即使搭配 DecisionAllow 也必须直接 Denied，严禁进入 ChallengePending
	allowLex := mustScopeSnap(t, "/etc/app/a.conf", nil, security.RiskSafe, security.NewDecisionAllow("allow"))
	ctxCanDeny, _ := NewApprovalContext(ApprovalContextSpec{OperationID: opID, LexicalBinding: bind, LexicalSnapshot: allowLex})
	stCan, _ := NewApprovalState(ctxCanDeny)
	stCan, _, _, _ = TransitionApproval(stCan, ApprovalInputEvaluateLexical(true))
	inCanDeny, _ := ApprovalInputCanonicalized(denyLex, bind)
	stCan, _, _, _ = TransitionApproval(stCan, inCanDeny)
	stCan, _, _, err = TransitionApproval(stCan, ApprovalInputEvaluateEscalation())
	assertApprovalPhase(t, stCan, err, ApprovalPhaseDenied)

	// 2. 词法 NeedApproval(RiskDangerous) -> 规范 Allow(RiskSafe)（软链指向非受保护区）不可降级，必须沿格并入 ChallengePending(RiskDangerous)
	needDec, _ := security.NewDecisionNeedApproval(security.RiskDangerous, "protected symlink")
	lexSnap := mustScopeSnap(t, "/etc/app/link", []string{"protected-a"}, security.RiskDangerous, needDec)
	canSnap := mustScopeSnap(t, "/tmp/target", nil, security.RiskSafe, security.NewDecisionAllow("outside"))
	ctxJoin, _ := NewApprovalContext(ApprovalContextSpec{OperationID: opID, LexicalBinding: mustApprovalBinding(t, "/etc/app/link"), LexicalSnapshot: lexSnap})
	st, _ := NewApprovalState(ctxJoin)
	st, _, _, err = TransitionApproval(st, ApprovalInputEvaluateLexical(true))
	assertApprovalPhase(t, st, err, ApprovalPhaseCanonicalizing)
	canBind := mustApprovalBinding(t, "/tmp/target")
	inCan, _ := ApprovalInputCanonicalized(canSnap, canBind)
	st, _, _, err = TransitionApproval(st, inCan)
	assertApprovalPhase(t, st, err, ApprovalPhaseEvaluatingEscalation)
	st, _, _, err = TransitionApproval(st, ApprovalInputEvaluateEscalation())
	assertApprovalPhase(t, st, err, ApprovalPhaseChallengePending)
	if st.EffectiveRisk() != security.RiskDangerous {
		t.Fatalf("有效合并风险必须保留 RiskDangerous，实际 %s", st.EffectiveRisk())
	}
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	lowEnv, _ := mustApprovalEnvelope(t, opID, canBind, security.RiskSafe, now)
	inLow, _ := ApprovalInputIssueChallenge(lowEnv)
	if _, _, _, err := TransitionApproval(st, inLow); !errors.Is(err, ErrInvalidApprovalEnvelope) {
		t.Fatalf("降级风险信封必须拒绝，实际 %v", err)
	}
}

func TestApprovalIdentityDriftAndBenignRound2Pinning(t *testing.T) {
	opID := testOpID(15)
	lexBind := mustApprovalBinding(t, "/app/current/cfg")
	lexSnap := mustScopeSnap(t, "/app/current/cfg", nil, security.RiskSafe, security.NewDecisionAllow("ok"))
	// 1. binding.NodeID != snapshot.TargetNode 在构造期直接拒绝
	otherNodeBind, _ := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityKindOf[security.CapFileMut](), Tool: "sftp", Action: "write", NodeID: "prod-2", CanonicalPaths: []string{"/app/current/cfg"},
	})
	if _, err := NewApprovalContext(ApprovalContextSpec{OperationID: opID, LexicalBinding: otherNodeBind, LexicalSnapshot: lexSnap}); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("NodeID 与 TargetNode 不一致必须拒绝: %v", err)
	}
	// 2. Canonicalizing 阶段非路径绑定漂移（Action 被篡改）必须直接 Denied，严禁进入 ChallengePending
	ctx, _ := NewApprovalContext(ApprovalContextSpec{OperationID: opID, LexicalBinding: lexBind, LexicalSnapshot: lexSnap})
	st, _ := NewApprovalState(ctx)
	st, _, _, _ = TransitionApproval(st, ApprovalInputEvaluateLexical(true))
	driftBind, _ := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityKindOf[security.CapFileMut](), Tool: "sftp", Action: "delete", NodeID: "prod-1", CanonicalPaths: []string{"/app/current/cfg"},
	})
	inDrift, _ := ApprovalInputCanonicalized(lexSnap, driftBind)
	stDrift, _, _, err := TransitionApproval(st, inDrift)
	assertApprovalPhase(t, stDrift, err, ApprovalPhaseDenied)

	// 3. 良性 Round-2 软链规范化：Approved 后接收同非路径绑定、无升级的规范路径并钉住 ActiveBinding（INV-E5）
	stApp, _ := NewApprovalState(ctx)
	stApp, _, _, err = TransitionApproval(stApp, ApprovalInputEvaluateLexical(false))
	assertApprovalPhase(t, stApp, err, ApprovalPhaseApproved)
	realBind := mustApprovalBinding(t, "/app/releases/v2/cfg")
	realSnap := mustScopeSnap(t, "/app/releases/v2/cfg", nil, security.RiskSafe, security.NewDecisionAllow("ok"))
	inBenign, _ := ApprovalInputCanonicalized(realSnap, realBind)
	stPinned, _, _, err := TransitionApproval(stApp, inBenign)
	assertApprovalPhase(t, stPinned, err, ApprovalPhaseApproved)
	if !stPinned.ActiveBinding().Equal(realBind) {
		t.Fatalf("良性 Round-2 规范化必须将 ActiveBinding 钉住为规范目标路径")
	}
	// 4. 复检出现 VerdictDeny 必须立即作废令牌
	spDeny, _ := security.NewScopedPath("/app/releases/v2/cfg", false)
	denySnap, _ := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityKindOf[security.CapFileMut](), TargetNode: "prod-1",
		Verdict: security.VerdictDeny, Risk: security.RiskSafe, Decision: security.NewDecisionAllow("allow"), Paths: []security.ScopedPath{spDeny},
	})
	inDeny, _ := ApprovalInputCanonicalized(denySnap, realBind)
	stInv, _, _, err := TransitionApproval(stPinned, inDeny)
	assertApprovalPhase(t, stInv, err, ApprovalPhaseTokenInvalidated)
}

func makeIssuedApproval(t *testing.T, opID security.OperationID, path string, now time.Time) (ApprovalState, security.OperationBinding, security.Digest, security.GuardrailDecision) {
	t.Helper()
	bind := mustApprovalBinding(t, path)
	needDec, _ := security.NewDecisionNeedApproval(security.RiskDangerous, "dangerous write")
	snap := mustScopeSnap(t, path, []string{"protected-a"}, security.RiskDangerous, needDec)
	ctx, err := NewApprovalContext(ApprovalContextSpec{OperationID: opID, LexicalBinding: bind, LexicalSnapshot: snap})
	if err != nil {
		t.Fatalf("NewApprovalContext 失败: %v", err)
	}
	env, dig := mustApprovalEnvelope(t, opID, bind, security.RiskDangerous, now)
	st, _ := NewApprovalState(ctx)
	st, _, _, _ = TransitionApproval(st, ApprovalInputEvaluateLexical(false))
	inIssue, _ := ApprovalInputIssueChallenge(env)
	st, _, _, err = TransitionApproval(st, inIssue)
	assertApprovalPhase(t, st, err, ApprovalPhaseChallengeIssued)
	return st, bind, dig, needDec
}

func TestApprovalRound2ProbeFailureAndTokenInvalidation(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	// 1. 挑战签发后 Round-2 探针失败 -> 立即作废令牌并阻断任何陈旧令牌复用
	issued, bind, dig, needDec := makeIssuedApproval(t, testOpID(11), "/srv/config.yaml", now)
	inv, effs, _, err := TransitionApproval(issued, ApprovalInputRound2ProbeFailed("sftp lstat failed"))
	assertApprovalPhase(t, inv, err, ApprovalPhaseTokenInvalidated)
	assertApprovalSingleEffect(t, effs, ApprovalEffectInvalidateToken)
	inVerify, _ := ApprovalInputVerifyToken(dig, bind, now.Add(time.Second), true)
	if _, _, _, err := TransitionApproval(inv, inVerify); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("已作废令牌严禁复用，期望 ErrIllegalTransition，实际 %v", err)
	}

	// 2. 挑战签发后复检发现作用域升级（Protected-A -> Protected-B）-> 立即作废令牌
	issued2, _, _, _ := makeIssuedApproval(t, testOpID(11), "/srv/config.yaml", now)
	escSnap := mustScopeSnap(t, "/etc/passwd", []string{"protected-b"}, security.RiskDangerous, needDec)
	inEsc, _ := ApprovalInputCanonicalized(escSnap, mustApprovalBinding(t, "/etc/passwd"))
	inv2, effs2, _, err := TransitionApproval(issued2, inEsc)
	assertApprovalPhase(t, inv2, err, ApprovalPhaseTokenInvalidated)
	assertApprovalSingleEffect(t, effs2, ApprovalEffectInvalidateToken)

	// 3. 核准后仍允许检测 Round-2 探针失败并立即撤销令牌
	issued3, _, _, _ := makeIssuedApproval(t, testOpID(11), "/srv/config.yaml", now)
	approved, _, _, err := TransitionApproval(issued3, inVerify)
	assertApprovalPhase(t, approved, err, ApprovalPhaseApproved)
	revoked, _, _, err := TransitionApproval(approved, ApprovalInputRound2ProbeFailed("race detected"))
	assertApprovalPhase(t, revoked, err, ApprovalPhaseTokenInvalidated)
}

func TestApprovalTokenExpiryTamperAndUserDeny(t *testing.T) {
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	issued1, bind, dig, _ := makeIssuedApproval(t, testOpID(13), "/srv/config.yaml", now)
	expiredIn, _ := ApprovalInputVerifyToken(dig, bind, now.Add(10*time.Minute), true)
	st, _, _, err := TransitionApproval(issued1, expiredIn)
	assertApprovalPhase(t, st, err, ApprovalPhaseTokenInvalidated)

	issued2, _, _, _ := makeIssuedApproval(t, testOpID(13), "/srv/config.yaml", now)
	badDigIn, _ := ApprovalInputVerifyToken(testDigest("tampered"), bind, now.Add(time.Second), true)
	st, _, _, err = TransitionApproval(issued2, badDigIn)
	assertApprovalPhase(t, st, err, ApprovalPhaseTokenInvalidated)

	issued3, _, _, _ := makeIssuedApproval(t, testOpID(13), "/srv/config.yaml", now)
	rejectIn, _ := ApprovalInputVerifyToken(zeroVal[security.Digest](), zeroVal[security.OperationBinding](), now.Add(time.Second), false)
	st, effs, _, err := TransitionApproval(issued3, rejectIn)
	assertApprovalPhase(t, st, err, ApprovalPhaseDenied)
	assertApprovalSingleEffect(t, effs, ApprovalEffectInvalidateToken)
	if !st.InvalidatedDigest().IsSome() || !st.ActiveBinding().Equal(bind) {
		t.Fatalf("用户拒绝已签发挑战必须保留 InvalidatedDigest 与 ActiveBinding")
	}
}

func TestApprovalExhaustivePhaseInputMatrix(t *testing.T) {
	opID := testOpID(12)
	bind := mustApprovalBinding(t, "/tmp/ok.txt")
	allowSnap := mustScopeSnap(t, "/tmp/ok.txt", nil, security.RiskSafe, security.NewDecisionAllow("ok"))
	needDec, _ := security.NewDecisionNeedApproval(security.RiskSafe, "ask")
	needSnap := mustScopeSnap(t, "/tmp/ok.txt", nil, security.RiskSafe, needDec)
	ctx, _ := NewApprovalContext(ApprovalContextSpec{OperationID: opID, LexicalBinding: bind, LexicalSnapshot: allowSnap})
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	env, dig := mustApprovalEnvelope(t, opID, bind, security.RiskSafe, now)

	states := []ApprovalState{
		approvalAt(ctx, ApprovalPhaseLexicalPrecheck, allowSnap, bind),
		approvalAt(ctx, ApprovalPhaseCanonicalizing, allowSnap, bind),
		approvalAt(ctx, ApprovalPhaseEvaluatingEscalation, needSnap, bind),
		approvalAt(ctx, ApprovalPhaseChallengePending, needSnap, bind),
		{phase: ApprovalPhaseChallengeIssued, ctx: ctx, activeSnapshot: needSnap, activeBinding: bind, effectiveRisk: needSnap.Risk(), envelope: algebraic.Some(env), envelopeDigest: algebraic.Some(dig), valid: true},
		{phase: ApprovalPhaseApproved, ctx: ctx, activeSnapshot: allowSnap, activeBinding: bind, effectiveRisk: allowSnap.Risk(), envelope: algebraic.Some(env), envelopeDigest: algebraic.Some(dig), valid: true},
		{phase: ApprovalPhaseTokenInvalidated, ctx: ctx, reason: "inv", valid: true},
		{phase: ApprovalPhaseDenied, ctx: ctx, reason: "den", valid: true},
	}
	inCan, _ := ApprovalInputCanonicalized(allowSnap, bind)
	inIssue, _ := ApprovalInputIssueChallenge(env)
	inVerify, _ := ApprovalInputVerifyToken(dig, bind, now.Add(time.Second), true)
	inputs := []ApprovalInput{
		ApprovalInputEvaluateLexical(false),
		inCan,
		ApprovalInputRound2ProbeFailed("fail"),
		ApprovalInputEvaluateEscalation(),
		inIssue,
		inVerify,
	}
	// 零值状态与零值输入失败关闭
	if _, _, _, err := TransitionApproval(ApprovalState{}, inputs[0]); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("零值状态应返回 ErrInvalidState: %v", err)
	}
	if _, _, _, err := TransitionApproval(states[0], ApprovalInput{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("零值输入应返回 ErrInvalidInput: %v", err)
	}
	// 允许矩阵 (phaseIdx, inputIdx)
	allowed := map[[2]int]bool{
		{0, 0}: true,
		{1, 1}: true, {1, 2}: true,
		{2, 2}: true, {2, 3}: true,
		{3, 1}: true, {3, 2}: true, {3, 4}: true,
		{4, 1}: true, {4, 2}: true, {4, 5}: true,
		{5, 1}: true, {5, 2}: true,
	}
	for i, st := range states {
		for j, in := range inputs {
			next, effs, evs, err := TransitionApproval(st, in)
			if allowed[[2]int{i, j}] && err != nil {
				t.Fatalf("Approval 矩阵(%s, %d) 期望合法，实际 %v", st.Phase(), j, err)
			}
			if !allowed[[2]int{i, j}] && (!errors.Is(err, ErrIllegalTransition) || next.Phase() != st.Phase() || len(effs) != 0 || len(evs) != 0) {
				t.Fatalf("Approval 矩阵(%s, %d) 应失败关闭: next=%v err=%v", st.Phase(), j, next.Phase(), err)
			}
		}
	}
}
