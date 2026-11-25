package gate

import (
	"context"
	"fmt"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

// verifyApprovalSubmission 核验两步审批回执：在任何 Round-2 远端探测之前先阻断重放、伪造、错 opID、
// 错能力、错绑定、拒批与过期，并原子消耗挂起挑战，杜绝并发重放与 SFTP 错误预言机（INV-E5）。
func (g *Gate) verifyApprovalSubmission(
	ctx context.Context,
	traceID security.TraceID,
	req rawGateRequest,
	sub ApprovalSubmission,
) (approvalOutcome, *policyRejection) {
	resp := sub.Response()
	dig := resp.EnvelopeDigest()
	fallbackOp := g.fallbackOpID(req.operationID)

	if err := validateSubmissionEnvelopeConsistency(req, sub, dig); err != nil {
		return approvalOutcome{}, denyRejection(err, fallbackOp, req.binding, req.risk, "approval_mismatch")
	}
	pc, errCode, claimErr := g.claimPendingChallenge(dig, sub.Envelope())
	if claimErr != nil {
		return approvalOutcome{}, denyRejection(claimErr, fallbackOp, req.binding, req.risk, errCode)
	}
	if err := validateClaimedChallengeAgainstRequest(req, sub, pc); err != nil {
		return approvalOutcome{}, denyRejection(err, pc.opID, req.binding, pc.fsmState.EffectiveRisk(), "approval_mismatch")
	}
	now := g.clock.Now().UTC().Round(0)
	if !resp.Approved() || !pc.envelope.IsActiveAt(now) {
		return g.verifyTokenWithFSM(ctx, traceID, pc.opID, req, pc.fsmState, pc.envelope, pc.binding, resp, "")
	}
	st, verifyBinding, rej := g.reprobeClaimedChallenge(ctx, traceID, req, pc)
	if rej != nil {
		return approvalOutcome{}, rej
	}
	return g.verifyTokenWithFSM(ctx, traceID, pc.opID, req, st, pc.envelope, verifyBinding, resp, "approved_via_challenge")
}

func validateSubmissionEnvelopeConsistency(req rawGateRequest, sub ApprovalSubmission, dig security.Digest) error {
	env, hasEnv := sub.Envelope().Get()
	if !hasEnv {
		return nil
	}
	matched, err := env.MatchesDigest(dig)
	if err != nil || !matched {
		return fmt.Errorf("%w: 回执摘要与提交信封摘要不一致", ErrApprovalMismatch)
	}
	if env.Binding().Capability() != req.capKind {
		return fmt.Errorf("%w: 信封能力 %s 与请求能力 %s 不一致", ErrApprovalMismatch, env.Binding().Capability(), req.capKind)
	}
	if reqOp, ok := req.operationID.Get(); ok && !reqOp.Equal(env.OperationID()) {
		return fmt.Errorf("%w: 信封 OperationID 与请求不一致", ErrApprovalMismatch)
	}
	return nil
}

// claimPendingChallenge 在单一互斥锁下原子完成「防重放检测 -> 查找挂起挑战 -> 移除并记入已消费表」，
// 保证并发重放时数学上至多只有一个胜出者。
func (g *Gate) claimPendingChallenge(
	dig security.Digest,
	envOpt algebraic.Option[security.ApprovalEnvelope],
) (*pendingChallenge, string, error) {
	now := g.clock.Now().UTC().Round(0)
	g.mu.Lock()
	defer g.mu.Unlock()

	if rec, found := g.consumedDig[dig]; found {
		if rec.kind == consumedKindExpired {
			return nil, "approval_expired", ErrApprovalExpired
		}
		return nil, "approval_replayed", ErrApprovalReplayed
	}
	if env, ok := envOpt.Get(); ok {
		if nonce, okN := env.Nonce(); okN {
			if _, replayed := g.consumedNonce[nonce]; replayed {
				return nil, "approval_replayed", ErrApprovalReplayed
			}
		}
	}
	pc, found := g.pending[dig]
	if !found {
		return nil, "approval_unknown", fmt.Errorf("%w: 未找到匹配的挂起审批挑战（禁止提交伪造或未签发信封）", ErrApprovalMismatch)
	}
	delete(g.pending, dig)
	g.recordConsumedLocked(dig, pc.nonce, pc.expiresAt, consumedKindUsed, now)
	return pc, "", nil
}

func validateClaimedChallengeAgainstRequest(req rawGateRequest, sub ApprovalSubmission, pc *pendingChallenge) error {
	if pc.capKind != req.capKind {
		return fmt.Errorf("%w: 挑战能力 %s 与请求能力 %s 不一致", ErrApprovalMismatch, pc.capKind, req.capKind)
	}
	if reqOp, ok := req.operationID.Get(); ok && !reqOp.Equal(pc.opID) {
		return fmt.Errorf("%w: 请求 OperationID 与挂起挑战不一致", ErrApprovalMismatch)
	}
	if env, ok := sub.Envelope().Get(); ok && !env.Equal(pc.envelope) {
		return fmt.Errorf("%w: 提交信封与门控签发信封不一致", ErrApprovalMismatch)
	}
	if pc.hadCanonical != (req.canonicalize != nil) {
		return fmt.Errorf("%w: %w: Round-2 规范化模式与原始挂起挑战不一致", ErrApprovalInvalidated, ErrApprovalMismatch)
	}
	// INV-E5：在发起任何 Round-2 远端探测之前先强制锚定路径与全部绑定字段，阻断跨路径令牌探测预言机。
	if !pc.hadCanonical && !pc.binding.Equal(req.binding) {
		return fmt.Errorf("%w: 请求绑定作用域与已签发挑战不一致", ErrApprovalMismatch)
	}
	if pc.hadCanonical && !req.binding.Equal(pc.fsmState.Context().LexicalBinding()) && !req.binding.Equal(pc.binding) {
		return fmt.Errorf("%w: 规范化二次提交绑定与词法/挑战绑定均不一致", ErrApprovalMismatch)
	}
	return nil
}

func (g *Gate) reprobeClaimedChallenge(
	ctx context.Context,
	traceID security.TraceID,
	req rawGateRequest,
	pc *pendingChallenge,
) (fsm.ApprovalState, security.OperationBinding, *policyRejection) {
	zSt, zBind := zeroVal[fsm.ApprovalState](), zeroVal[security.OperationBinding]()
	if pc.hadCanonical {
		if req.canonicalize == nil {
			err := fmt.Errorf("%w: %w: 缺少必需的 Round-2 Canonicalize 复检回调", ErrApprovalInvalidated, ErrApprovalMismatch)
			return zSt, zBind, denyRejection(err, pc.opID, pc.binding, pc.fsmState.EffectiveRisk(), "round2_canonicalize_missing")
		}
		return g.runRound2Reprobe(ctx, traceID, pc.opID, req, pc.fsmState, pc.binding)
	}
	if req.canonicalize != nil {
		err := fmt.Errorf("%w: 非规范化挑战禁止在二次提交时追加 Canonicalize", ErrApprovalMismatch)
		return zSt, zBind, denyRejection(err, pc.opID, pc.binding, pc.fsmState.EffectiveRisk(), "approval_mismatch")
	}
	return g.verifyNonCanonicalScope(req, pc)
}

// verifyNonCanonicalScope 对未启用 Round-2 的两步二次提交重新执行纯函数护栏求值与单调升级校验，
// 阻断二次提交夹带 VerdictDeny、DecisionDeny 下限、更高风险或额外受保护路径绕过审批。
func (g *Gate) verifyNonCanonicalScope(
	req rawGateRequest,
	pc *pendingChallenge,
) (fsm.ApprovalState, security.OperationBinding, *policyRejection) {
	zSt, zBind := zeroVal[fsm.ApprovalState](), zeroVal[security.OperationBinding]()
	curSnap, err := g.policy.evaluateScopeSnapshot(
		g.profile, req.binding, req.risk, req.verdict, req.decisionFloor, req.paths, req.recursivePaths,
	)
	if err != nil {
		return zSt, zBind, denyRejection(fmt.Errorf("%w: %w", ErrAuthorizationDenied, err), pc.opID, req.binding, req.risk, "policy_eval_failed")
	}
	if curSnap.Verdict().Denied() || curSnap.Decision().Kind() == security.DecisionKindDeny {
		return zSt, zBind, denyRejection(fmt.Errorf("%w: 二次提交护栏求值被拒绝", ErrAuthorizationDenied), pc.opID, req.binding, curSnap.Risk(), "policy_denied")
	}
	if security.InspectScopeEscalation(pc.fsmState.ActiveSnapshot(), curSnap).Escalated() {
		err := fmt.Errorf("%w: %w: 非规范化二次提交触发作用域升级", ErrScopeEscalated, ErrApprovalInvalidated)
		return zSt, zBind, denyRejection(err, pc.opID, req.binding, curSnap.Risk(), "scope_escalated")
	}
	return pc.fsmState, req.binding, nil
}

// runRound2Reprobe 统一驱动交互式与两步审批批准后的 Round-2 远端规范化复检，
// 捕获探测失败或软链重定向升级（含 Protected-A -> Protected-B）并立即作废挑战令牌（INV-E5 / ADR-016）。
func (g *Gate) runRound2Reprobe(
	ctx context.Context,
	traceID security.TraceID,
	opID security.OperationID,
	req rawGateRequest,
	st fsm.ApprovalState,
	activeBinding security.OperationBinding,
) (fsm.ApprovalState, security.OperationBinding, *policyRejection) {
	zSt, zBind := zeroVal[fsm.ApprovalState](), zeroVal[security.OperationBinding]()
	canSnap, canBinding, err := g.runCanonicalizeProbe(ctx, req)
	if err != nil {
		prev := st.Phase()
		inv, _, evs, tErr := fsm.TransitionApproval(st, fsm.ApprovalInputRound2ProbeFailed(err.Error()))
		if tErr == nil {
			g.emitApprovalEvents(ctx, req.opStream, traceID, opID, prev, inv, evs)
		}
		return zSt, zBind, denyRejection(
			fmt.Errorf("%w: %w", ErrApprovalInvalidated, err), opID, activeBinding, st.EffectiveRisk(), "round2_probe_failed",
		)
	}
	canIn, err := fsm.ApprovalInputCanonicalized(canSnap, canBinding)
	if err != nil {
		return zSt, zBind, denyRejection(
			fmt.Errorf("%w: %w", ErrApprovalInvalidated, err), opID, activeBinding, st.EffectiveRisk(), "canonical_input_invalid",
		)
	}
	prev := st.Phase()
	next, _, evs, err := fsm.TransitionApproval(st, canIn)
	if err != nil {
		return zSt, zBind, denyRejection(
			fmt.Errorf("%w: %w", ErrApprovalInvalidated, err), opID, canBinding, canSnap.Risk(), "reprobe_transition_failed",
		)
	}
	g.emitApprovalEvents(ctx, req.opStream, traceID, opID, prev, next, evs)
	if next.Phase() == fsm.ApprovalPhaseTokenInvalidated {
		err := fmt.Errorf("%w: %w: %s", ErrScopeEscalated, ErrApprovalInvalidated, next.Reason())
		return zSt, zBind, denyRejection(err, opID, canBinding, next.EffectiveRisk(), "scope_escalated")
	}
	return next, canBinding, nil
}

func (g *Gate) verifyTokenWithFSM(
	ctx context.Context,
	traceID security.TraceID,
	opID security.OperationID,
	req rawGateRequest,
	st fsm.ApprovalState,
	env security.ApprovalEnvelope,
	verifyBinding security.OperationBinding,
	resp ports.ApprovalDecisionResponse,
	successReason string,
) (approvalOutcome, *policyRejection) {
	now := g.clock.Now().UTC().Round(0)
	verifyIn, err := fsm.ApprovalInputVerifyToken(resp.EnvelopeDigest(), verifyBinding, now, resp.Approved())
	if err != nil {
		return approvalOutcome{}, denyRejection(fmt.Errorf("%w: %w", ErrApprovalMismatch, err), opID, verifyBinding, st.EffectiveRisk(), "approval_verify_input_invalid")
	}
	prev := st.Phase()
	finalState, _, evs, err := fsm.TransitionApproval(st, verifyIn)
	if err != nil {
		return approvalOutcome{}, denyRejection(fmt.Errorf("%w: %w", ErrApprovalInvalidated, err), opID, verifyBinding, st.EffectiveRisk(), "approval_verify_failed")
	}
	g.emitApprovalEvents(ctx, req.opStream, traceID, opID, prev, finalState, evs)

	switch finalState.Phase() {
	case fsm.ApprovalPhaseApproved:
		return approvalOutcome{
			opID: opID, binding: finalState.ActiveBinding(), risk: finalState.EffectiveRisk(),
			approvedViaChg: true, reason: successReason,
		}, nil
	case fsm.ApprovalPhaseDenied:
		return approvalOutcome{}, needApprovalRejection(ErrApprovalRejected, opID, verifyBinding, st.EffectiveRisk(), "approval_rejected")
	case fsm.ApprovalPhaseTokenInvalidated:
		if !env.IsActiveAt(now) {
			return approvalOutcome{}, needApprovalRejection(ErrApprovalExpired, opID, verifyBinding, st.EffectiveRisk(), "approval_expired")
		}
		err := fmt.Errorf("%w: %s", ErrApprovalMismatch, sanitizeReason(finalState.Reason(), "token invalidated"))
		return approvalOutcome{}, denyRejection(err, opID, verifyBinding, st.EffectiveRisk(), "approval_mismatch")
	default:
		return approvalOutcome{}, denyRejection(ErrApprovalInvalidated, opID, verifyBinding, st.EffectiveRisk(), "approval_invalidated")
	}
}

func (g *Gate) runCanonicalizeProbe(ctx context.Context, req rawGateRequest) (security.ScopeSnapshot, security.OperationBinding, error) {
	zSnap, zBind := zeroVal[security.ScopeSnapshot](), zeroVal[security.OperationBinding]()
	res, err := req.canonicalize(ctx)
	if err != nil {
		return zSnap, zBind, err
	}
	if !res.Binding.IsValid() || res.Binding.Capability() != req.capKind {
		return zSnap, zBind, fmt.Errorf("%w: 规范化绑定无效或能力漂移", ErrScopeEscalated)
	}
	canRisk := req.risk
	if r, ok := res.Risk.Get(); ok {
		canRisk = canRisk.Join(r)
	}
	canVerdict := req.verdict
	if v, ok := res.Verdict.Get(); ok {
		canVerdict = canVerdict.Meet(v)
	}
	canFloor := mergeDecisionFloor(req.decisionFloor, res.DecisionFloor)
	paths := unionPaths(res.Binding.CanonicalPaths(), res.Paths)
	recPaths := unionPaths(res.Binding.RecursivePaths(), res.RecursivePaths)
	snap, err := g.policy.evaluateScopeSnapshot(g.profile, res.Binding, canRisk, canVerdict, canFloor, paths, recPaths)
	if err != nil {
		return zSnap, zBind, err
	}
	return snap, res.Binding, nil
}

func mergeDecisionFloor(
	a, b algebraic.Option[security.GuardrailDecision],
) algebraic.Option[security.GuardrailDecision] {
	va, okA := a.Get()
	vb, okB := b.Get()
	switch {
	case okA && okB:
		return algebraic.Some(security.JoinDecisions(va, vb))
	case okA:
		return a
	case okB:
		return b
	default:
		return algebraic.None[security.GuardrailDecision]()
	}
}

func (g *Gate) recordSingleUseEnvelope(dig security.Digest, env security.ApprovalEnvelope, invalidated bool) {
	exp, okE := env.ExpiresAt()
	nonce, okN := env.Nonce()
	if !okE || !okN {
		return
	}
	kind := consumedKindUsed
	if invalidated {
		kind = consumedKindInvalidated
	}
	now := g.clock.Now().UTC().Round(0)
	g.mu.Lock()
	g.recordConsumedLocked(dig, nonce, exp, kind, now)
	g.mu.Unlock()
}

// recordConsumedLocked 以严格有界 FIFO 队列维护已消费/过期信封记录，保证两张防重放表长度恒 <= maxReplayHistory；
// 未过期突发流量下跳过全表扫描实现均摊 O(1) 驱逐（正向白名单 g.pending 保证未知信封依然失败关闭）。
func (g *Gate) recordConsumedLocked(dig security.Digest, nonce [16]byte, exp time.Time, kind uint8, now time.Time) {
	if _, exists := g.consumedDig[dig]; exists {
		g.consumedDig[dig] = consumedRecord{expiresAt: exp, kind: kind}
		g.consumedNonce[nonce] = exp
		return
	}
	if len(g.consumedDig) >= g.policy.maxReplayHistory {
		if !g.earliestConsumedExp.IsZero() && !now.Before(g.earliestConsumedExp) {
			g.pruneExpiredConsumedLocked(now)
		}
		for len(g.consumedDig) >= g.policy.maxReplayHistory && g.consumedHead < len(g.consumedOrder) {
			g.evictOldestConsumedLocked()
		}
	}
	g.consumedDig[dig] = consumedRecord{expiresAt: exp, kind: kind}
	g.consumedNonce[nonce] = exp
	g.consumedOrder = append(g.consumedOrder, consumedEntry{dig: dig, nonce: nonce, expiresAt: exp})
	if g.earliestConsumedExp.IsZero() || exp.Before(g.earliestConsumedExp) {
		g.earliestConsumedExp = exp
	}
}

func (g *Gate) evictOldestConsumedLocked() {
	front := g.consumedOrder[g.consumedHead]
	g.consumedOrder[g.consumedHead] = consumedEntry{}
	g.consumedHead++
	delete(g.consumedDig, front.dig)
	delete(g.consumedNonce, front.nonce)
	if g.consumedHead >= len(g.consumedOrder) {
		g.consumedOrder = g.consumedOrder[:0]
		g.consumedHead = 0
		g.earliestConsumedExp = time.Time{}
		return
	}
	if g.consumedHead*2 >= len(g.consumedOrder) {
		rem := copy(g.consumedOrder, g.consumedOrder[g.consumedHead:])
		clear(g.consumedOrder[rem:])
		g.consumedOrder = g.consumedOrder[:rem]
		g.consumedHead = 0
	}
}

func (g *Gate) pruneExpiredPendingLocked(now time.Time) {
	for dig, pc := range g.pending {
		if !now.Before(pc.expiresAt) {
			delete(g.pending, dig)
			g.recordConsumedLocked(dig, pc.nonce, pc.expiresAt, consumedKindExpired, now)
		}
	}
}

func (g *Gate) pruneExpiredConsumedLocked(now time.Time) {
	kept := g.consumedOrder[:0]
	var minExp time.Time
	for i := g.consumedHead; i < len(g.consumedOrder); i++ {
		e := g.consumedOrder[i]
		if !now.Before(e.expiresAt) {
			delete(g.consumedDig, e.dig)
			delete(g.consumedNonce, e.nonce)
			continue
		}
		kept = append(kept, e)
		if minExp.IsZero() || e.expiresAt.Before(minExp) {
			minExp = e.expiresAt
		}
	}
	clear(g.consumedOrder[len(kept):])
	g.consumedOrder = kept
	g.consumedHead = 0
	g.earliestConsumedExp = minExp
}
