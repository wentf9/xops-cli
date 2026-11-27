package gate

import (
	"context"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate/internal/reasonmsg"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	consumedKindUsed uint8 = iota + 1
	consumedKindInvalidated
	consumedKindExpired
)

type pendingChallenge struct {
	opID         security.OperationID
	capKind      security.CapabilityKind
	binding      security.OperationBinding
	envelope     security.ApprovalEnvelope
	digest       security.Digest
	nonce        [16]byte
	expiresAt    time.Time
	fsmState     fsm.ApprovalState
	hadCanonical bool
}

type consumedRecord struct {
	expiresAt time.Time
	kind      uint8
}

type consumedEntry struct {
	dig       security.Digest
	nonce     [16]byte
	expiresAt time.Time
}

type approvalOutcome struct {
	opID           security.OperationID
	binding        security.OperationBinding
	risk           security.RiskLevel
	approvedViaChg bool
	reason         string
}

type policyRejection struct {
	err       error
	decision  security.DecisionKind
	risk      security.RiskLevel
	binding   security.OperationBinding
	opID      security.OperationID
	errorCode string
	reason    string
}

// evaluatePolicyAndApproval 驱动纯函数护栏求值与 ApprovalFSM，返回已获准作用域或结构化拒绝信息。
func (g *Gate) evaluatePolicyAndApproval(
	ctx context.Context,
	traceID security.TraceID,
	req rawGateRequest,
) (approvalOutcome, *policyRejection) {
	if sub, hasSub := req.approval.Get(); hasSub {
		return g.verifyApprovalSubmission(ctx, traceID, req, sub)
	}
	return g.evaluateFreshRequest(ctx, traceID, req)
}

func (g *Gate) evaluateFreshRequest(
	ctx context.Context,
	traceID security.TraceID,
	req rawGateRequest,
) (approvalOutcome, *policyRejection) {
	opID, err := g.resolveFreshOperationID(req.operationID)
	if err != nil {
		return approvalOutcome{}, &policyRejection{
			err: err, decision: security.DecisionKindDeny, risk: req.risk,
			binding: req.binding, errorCode: "invalid_operation_id", reason: err.Error(),
		}
	}
	lexSnap, err := g.policy.evaluateScopeSnapshot(
		g.profile, req.binding, req.risk, req.verdict, req.decisionFloor, req.paths, req.recursivePaths,
	)
	if err != nil {
		return approvalOutcome{}, denyRejection(err, opID, req.binding, req.risk, "policy_eval_failed")
	}
	st, err := initApprovalFSM(opID, req.binding, lexSnap, g.policy.Digest())
	if err != nil {
		return approvalOutcome{}, denyRejection(domi18n.WrapSentinel(ErrAuthorizationDenied, err), opID, req.binding, lexSnap.Risk(), "approval_init_failed")
	}
	prevPhase := st.Phase()
	next, _, evs, err := fsm.TransitionApproval(st, fsm.ApprovalInputEvaluateLexical(req.canonicalize != nil))
	if err != nil {
		return approvalOutcome{}, denyRejection(domi18n.WrapSentinel(ErrAuthorizationDenied, err), opID, req.binding, lexSnap.Risk(), "approval_lexical_failed")
	}
	g.emitApprovalEvents(ctx, req.opStream, traceID, opID, prevPhase, next, evs)
	return g.dispatchFreshPhase(ctx, traceID, opID, req, next)
}

func (g *Gate) dispatchFreshPhase(
	ctx context.Context,
	traceID security.TraceID,
	opID security.OperationID,
	req rawGateRequest,
	st fsm.ApprovalState,
) (approvalOutcome, *policyRejection) {
	switch st.Phase() {
	case fsm.ApprovalPhaseApproved:
		return approvalOutcome{
			opID: opID, binding: st.ActiveBinding(), risk: st.EffectiveRisk(), reason: "policy_allow",
		}, nil
	case fsm.ApprovalPhaseDenied:
		err := reasonmsg.ErrorForSentinel(ErrAuthorizationDenied, st.Reason(), domi18n.KeyGateReasonGuardrailDenied)
		return approvalOutcome{}, denyRejection(err, opID, st.ActiveBinding(), st.EffectiveRisk(), "policy_denied")
	case fsm.ApprovalPhaseCanonicalizing:
		return g.driveFreshCanonicalization(ctx, traceID, opID, req, st)
	case fsm.ApprovalPhaseChallengePending:
		return g.handleChallengePending(ctx, traceID, opID, req, st)
	default:
		err := domi18n.EF(ErrAuthorizationDenied, domi18n.KeyGateUnknownApprovalPhase, domi18n.Str("phase", st.Phase().String()))
		return approvalOutcome{}, denyRejection(err, opID, req.binding, req.risk, "invalid_approval_phase")
	}
}

func (g *Gate) driveFreshCanonicalization(
	ctx context.Context,
	traceID security.TraceID,
	opID security.OperationID,
	req rawGateRequest,
	st fsm.ApprovalState,
) (approvalOutcome, *policyRejection) {
	canSnap, canBinding, err := g.runCanonicalizeProbe(ctx, req)
	if err != nil {
		prev := st.Phase()
		denied, _, evs, tErr := fsm.TransitionApproval(st, fsm.ApprovalInputRound2ProbeFailed(err.Error()))
		if tErr == nil {
			g.emitApprovalEvents(ctx, req.opStream, traceID, opID, prev, denied, evs)
		}
		return approvalOutcome{}, denyRejection(domi18n.WrapSentinel(ErrAuthorizationDenied, err), opID, st.ActiveBinding(), st.EffectiveRisk(), "round2_probe_failed")
	}
	canIn, err := fsm.ApprovalInputCanonicalized(canSnap, canBinding)
	if err != nil {
		return approvalOutcome{}, denyRejection(domi18n.WrapSentinel(ErrAuthorizationDenied, err), opID, st.ActiveBinding(), st.EffectiveRisk(), "canonical_input_invalid")
	}
	prev := st.Phase()
	st, _, evs, err := fsm.TransitionApproval(st, canIn)
	if err != nil {
		return approvalOutcome{}, denyRejection(domi18n.WrapSentinel(ErrAuthorizationDenied, err), opID, canBinding, canSnap.Risk(), "canonical_transition_failed")
	}
	g.emitApprovalEvents(ctx, req.opStream, traceID, opID, prev, st, evs)
	if st.Phase() == fsm.ApprovalPhaseDenied {
		return approvalOutcome{}, denyRejection(reasonmsg.ErrorForSentinel(ErrAuthorizationDenied, st.Reason(), domi18n.KeyGateReasonCanonicalDenied), opID, st.ActiveBinding(), st.EffectiveRisk(), "canonical_denied")
	}
	prev = st.Phase()
	st, _, evs, err = fsm.TransitionApproval(st, fsm.ApprovalInputEvaluateEscalation())
	if err != nil {
		return approvalOutcome{}, denyRejection(domi18n.WrapSentinel(ErrAuthorizationDenied, err), opID, st.ActiveBinding(), st.EffectiveRisk(), "escalation_eval_failed")
	}
	g.emitApprovalEvents(ctx, req.opStream, traceID, opID, prev, st, evs)
	return g.dispatchPostEscalationPhase(ctx, traceID, opID, req, st)
}

func (g *Gate) dispatchPostEscalationPhase(
	ctx context.Context,
	traceID security.TraceID,
	opID security.OperationID,
	req rawGateRequest,
	st fsm.ApprovalState,
) (approvalOutcome, *policyRejection) {
	switch st.Phase() {
	case fsm.ApprovalPhaseApproved:
		return approvalOutcome{
			opID: opID, binding: st.ActiveBinding(), risk: st.EffectiveRisk(), reason: "canonical_allow",
		}, nil
	case fsm.ApprovalPhaseDenied:
		err := reasonmsg.ErrorForSentinel(ErrAuthorizationDenied, st.Reason(), domi18n.KeyGateReasonCanonGuardrailDeny)
		return approvalOutcome{}, denyRejection(err, opID, st.ActiveBinding(), st.EffectiveRisk(), "canonical_denied")
	case fsm.ApprovalPhaseChallengePending:
		return g.handleChallengePending(ctx, traceID, opID, req, st)
	default:
		err := domi18n.EF(ErrAuthorizationDenied, domi18n.KeyGateUnknownApprovalPhase, domi18n.Str("phase", st.Phase().String()))
		return approvalOutcome{}, denyRejection(err, opID, st.ActiveBinding(), st.EffectiveRisk(), "invalid_approval_phase")
	}
}

func (g *Gate) handleChallengePending(
	ctx context.Context,
	traceID security.TraceID,
	opID security.OperationID,
	req rawGateRequest,
	st fsm.ApprovalState,
) (approvalOutcome, *policyRejection) {
	canInteract := g.interaction != nil && g.interaction.CanInteract()
	if !canInteract && g.policy.NoElicitFallback() == NoElicitFallbackDeny {
		err := domi18n.WrapSentinel(ErrApprovalRequired, ports.ErrInteractionUnavailable)
		return approvalOutcome{}, needApprovalRejection(err, opID, st.ActiveBinding(), st.EffectiveRisk(), "interaction_unavailable")
	}
	env, issuedState, dig, err := g.mintAndIssueChallenge(ctx, traceID, opID, req, st)
	if err != nil {
		return approvalOutcome{}, denyRejection(err, opID, st.ActiveBinding(), st.EffectiveRisk(), "challenge_mint_failed")
	}
	if !canInteract {
		return g.registerPendingChallenge(opID, req, issuedState, env, dig)
	}
	return g.runInteractiveApproval(ctx, traceID, opID, req, issuedState, env, dig)
}

func (g *Gate) mintAndIssueChallenge(
	ctx context.Context,
	traceID security.TraceID,
	opID security.OperationID,
	req rawGateRequest,
	st fsm.ApprovalState,
) (security.ApprovalEnvelope, fsm.ApprovalState, security.Digest, error) {
	zEnv, zSt, zDig := zeroVal[security.ApprovalEnvelope](), zeroVal[fsm.ApprovalState](), zeroVal[security.Digest]()
	now := g.clock.Now().UTC().Round(0)
	if !isValidRFC3339Time(now) {
		return zEnv, zSt, zDig, domi18n.EF(ErrInvalidConfig, domi18n.KeyGateInvalidClockTime)
	}
	nonce, err := security.NewApprovalNonceFrom(g.entropy)
	if err != nil {
		return zEnv, zSt, zDig, domi18n.WrapSentinel(ErrApprovalRequired, err)
	}
	effRisk := st.EffectiveRisk()
	needDec, err := security.NewDecisionNeedApproval(effRisk, sanitizeReason(st.Reason(), "approval required"))
	if err != nil {
		return zEnv, zSt, zDig, err
	}
	env, err := security.NewApprovalEnvelope(security.ApprovalEnvelopeSpec{
		OperationID:  opID,
		Binding:      st.ActiveBinding(),
		Risk:         effRisk,
		Decision:     needDec,
		ScopeSummary: req.scopeSummary,
		IssuedAt:     now,
		TTL:          g.policy.ApprovalTTL(),
		Nonce:        nonce,
		PolicyDigest: algebraic.Some(g.policy.Digest()),
	})
	if err != nil {
		return zEnv, zSt, zDig, err
	}
	issueIn, err := fsm.ApprovalInputIssueChallenge(env)
	if err != nil {
		return zEnv, zSt, zDig, err
	}
	prev := st.Phase()
	next, _, evs, err := fsm.TransitionApproval(st, issueIn)
	if err != nil {
		return zEnv, zSt, zDig, err
	}
	dig, ok := next.EnvelopeDigest().Get()
	if !ok {
		return zEnv, zSt, zDig, ErrApprovalInvalidated
	}
	g.emitApprovalEvents(ctx, req.opStream, traceID, opID, prev, next, evs)
	g.emitChallengeEvent(ctx, req.opStream, traceID, opID, env, next.Phase(), next.Escalated(), next.Reason())
	return env, next, dig, nil
}

func (g *Gate) registerPendingChallenge(
	opID security.OperationID,
	req rawGateRequest,
	st fsm.ApprovalState,
	env security.ApprovalEnvelope,
	dig security.Digest,
) (approvalOutcome, *policyRejection) {
	exp, okE := env.ExpiresAt()
	nonce, okN := env.Nonce()
	if !okE || !okN {
		return approvalOutcome{}, denyRejection(ErrApprovalInvalidated, opID, st.ActiveBinding(), st.EffectiveRisk(), "invalid_envelope")
	}
	now := g.clock.Now().UTC().Round(0)
	g.mu.Lock()
	g.pruneExpiredPendingLocked(now)
	if len(g.pending) >= g.policy.maxPending {
		g.mu.Unlock()
		return approvalOutcome{}, denyRejection(ErrPendingLimitExceeded, opID, st.ActiveBinding(), st.EffectiveRisk(), "pending_limit_exceeded")
	}
	g.pending[dig] = &pendingChallenge{
		opID:         opID,
		capKind:      req.capKind,
		binding:      st.ActiveBinding(),
		envelope:     env,
		digest:       dig,
		nonce:        nonce,
		expiresAt:    exp,
		fsmState:     st,
		hadCanonical: req.canonicalize != nil,
	}
	g.mu.Unlock()

	challengeErr := newApprovalChallengeError(env, dig, st.Escalated(), st.Reason())
	return approvalOutcome{}, needApprovalRejection(challengeErr, opID, st.ActiveBinding(), st.EffectiveRisk(), "approval_challenge_issued")
}

func (g *Gate) runInteractiveApproval(
	ctx context.Context,
	traceID security.TraceID,
	opID security.OperationID,
	req rawGateRequest,
	st fsm.ApprovalState,
	env security.ApprovalEnvelope,
	dig security.Digest,
) (approvalOutcome, *policyRejection) {
	resp, pErr := g.interaction.PromptApproval(ctx, env)
	g.recordSingleUseEnvelope(dig, env, pErr != nil || !resp.IsValid() || !resp.Approved() || !dig.Equal(resp.EnvelopeDigest()))
	if pErr != nil {
		err := domi18n.WrapSentinel(ErrApprovalRejected, pErr)
		return approvalOutcome{}, needApprovalRejection(err, opID, st.ActiveBinding(), st.EffectiveRisk(), "interaction_failed")
	}
	if !resp.IsValid() {
		return approvalOutcome{}, needApprovalRejection(ErrApprovalMismatch, opID, st.ActiveBinding(), st.EffectiveRisk(), "invalid_approval_response")
	}
	verifyBinding := st.ActiveBinding()
	// 严格遵循 INV-E5 反预言机顺序：必须先确认批准、未过期且回执摘要匹配，才允许发起 Round-2 远端复检。
	now := g.clock.Now().UTC().Round(0)
	if req.canonicalize != nil && resp.Approved() && env.IsActiveAt(now) && dig.Equal(resp.EnvelopeDigest()) {
		var rej *policyRejection
		st, verifyBinding, rej = g.runRound2Reprobe(ctx, traceID, opID, req, st, verifyBinding)
		if rej != nil {
			return approvalOutcome{}, rej
		}
	}
	return g.verifyTokenWithFSM(ctx, traceID, opID, req, st, env, verifyBinding, resp, "approved_interactive")
}

func initApprovalFSM(
	opID security.OperationID,
	binding security.OperationBinding,
	lexSnap security.ScopeSnapshot,
	policyDigest security.Digest,
) (fsm.ApprovalState, error) {
	appCtx, err := fsm.NewApprovalContext(fsm.ApprovalContextSpec{
		OperationID:     opID,
		LexicalBinding:  binding,
		LexicalSnapshot: lexSnap,
		PolicyDigest:    algebraic.Some(policyDigest),
	})
	if err != nil {
		return zeroVal[fsm.ApprovalState](), err
	}
	return fsm.NewApprovalState(appCtx)
}

func (g *Gate) newEventMeta(traceID security.TraceID, opID security.OperationID) (events.EventMeta, error) {
	return events.NewEventMeta(events.EventMetaSpec{
		TraceID:     traceID,
		OperationID: algebraic.Some(opID),
		OccurredAt:  g.clock.Now().UTC().Round(0),
	})
}

func (g *Gate) emitApprovalEvents(
	ctx context.Context,
	stream *events.OperationStream,
	traceID security.TraceID,
	opID security.OperationID,
	from fsm.ApprovalPhase,
	toState fsm.ApprovalState,
	evs []fsm.ApprovalEvent,
) {
	if stream == nil || stream.IsClosed() || len(evs) == 0 {
		return
	}
	meta, err := g.newEventMeta(traceID, opID)
	if err != nil {
		return
	}
	for _, ev := range evs {
		if trEv, mErr := events.NewApprovalTransitionEvent(meta, from, toState.Phase(), ev, toState.IsTerminal()); mErr == nil {
			_ = stream.Emit(ctx, trEv)
		}
	}
}

func (g *Gate) emitChallengeEvent(
	ctx context.Context,
	stream *events.OperationStream,
	traceID security.TraceID,
	opID security.OperationID,
	env security.ApprovalEnvelope,
	phase fsm.ApprovalPhase,
	escalated bool,
	reason string,
) {
	if stream == nil || stream.IsClosed() {
		return
	}
	meta, err := g.newEventMeta(traceID, opID)
	if err != nil {
		return
	}
	if chEv, mErr := events.NewApprovalChallengeEvent(events.ApprovalChallengeSpec{
		Meta: meta, Envelope: env, Phase: phase, Escalated: escalated, Reason: reason,
	}); mErr == nil {
		_ = stream.Emit(ctx, chEv)
	}
}

func denyRejection(err error, opID security.OperationID, b security.OperationBinding, risk security.RiskLevel, code string) *policyRejection {
	return &policyRejection{
		err: err, decision: security.DecisionKindDeny, risk: risk, binding: b,
		opID: opID, errorCode: code, reason: sanitizeReason(err.Error(), "authorization denied"),
	}
}

func needApprovalRejection(err error, opID security.OperationID, b security.OperationBinding, risk security.RiskLevel, code string) *policyRejection {
	return &policyRejection{
		err: err, decision: security.DecisionKindNeedApproval, risk: risk, binding: b,
		opID: opID, errorCode: code, reason: sanitizeReason(err.Error(), "approval required"),
	}
}
