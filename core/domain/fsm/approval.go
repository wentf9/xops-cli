package fsm

import (
	"maps"
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// ApprovalPhase、ApprovalEffectKind 与 ApprovalEventKind 为 ApprovalFSM 失败关闭枚举。
type (
	//xops:opaque
	//xops:failclosed
	ApprovalPhase uint8
	//xops:opaque
	//xops:failclosed
	ApprovalEffectKind uint8
	//xops:opaque
	//xops:failclosed
	ApprovalEventKind uint8
)

const (
	ApprovalPhaseInvalid ApprovalPhase = iota
	ApprovalPhaseLexicalPrecheck
	ApprovalPhaseCanonicalizing
	ApprovalPhaseEvaluatingEscalation
	ApprovalPhaseChallengePending
	ApprovalPhaseChallengeIssued
	ApprovalPhaseApproved
	ApprovalPhaseTokenInvalidated
	ApprovalPhaseDenied
)
const (
	approvalInInvalid uint8 = iota
	approvalInEvalLexical
	approvalInCanonicalized
	approvalInRound2Failed
	approvalInEvalEscalation
	approvalInIssueChallenge
	approvalInVerifyToken
)
const (
	ApprovalEffectInvalid ApprovalEffectKind = iota
	ApprovalEffectCanonicalize
	ApprovalEffectRequestChallenge
	ApprovalEffectPresentChallenge
	ApprovalEffectInvalidateToken
)
const (
	ApprovalEventInvalid ApprovalEventKind = iota
	ApprovalEventCanonicalizeRequested
	ApprovalEventCanonicalized
	ApprovalEventEscalationDetected
	ApprovalEventChallengeRequested
	ApprovalEventChallengeIssued
	ApprovalEventApproved
	ApprovalEventDenied
	ApprovalEventTokenInvalidated
)

// ApprovalContextSpec 与 ApprovalContext/State/Input/Effect 为 ApprovalFSM 不可变失败关闭值对象。
type (
	ApprovalContextSpec struct {
		OperationID     security.OperationID
		LexicalBinding  security.OperationBinding
		LexicalSnapshot security.ScopeSnapshot
		PolicyDigest    algebraic.Option[security.Digest]
	}
	//xops:opaque
	//xops:failclosed
	ApprovalContext struct {
		operationID     security.OperationID
		lexicalBinding  security.OperationBinding
		lexicalSnapshot security.ScopeSnapshot
		policyDigest    algebraic.Option[security.Digest]
		valid           bool
	}
	//xops:opaque
	//xops:failclosed
	ApprovalState struct {
		phase             ApprovalPhase
		ctx               ApprovalContext
		activeSnapshot    security.ScopeSnapshot
		activeBinding     security.OperationBinding
		effectiveRisk     security.RiskLevel
		envelope          algebraic.Option[security.ApprovalEnvelope]
		envelopeDigest    algebraic.Option[security.Digest]
		invalidatedDigest algebraic.Option[security.Digest]
		escalated         bool
		escalationReasons []security.EscalationReason
		reason            string
		valid             bool
	}
	//xops:opaque
	//xops:failclosed
	ApprovalInput struct {
		kind                     uint8
		requiresCanonicalization bool
		canonicalSnapshot        security.ScopeSnapshot
		canonicalBinding         security.OperationBinding
		envelope                 security.ApprovalEnvelope
		submittedDigest          security.Digest
		submittedBinding         security.OperationBinding
		now                      time.Time
		userApproved             bool
		reason                   string
		valid                    bool
	}
	//xops:opaque
	//xops:failclosed
	ApprovalEffect struct {
		kind           ApprovalEffectKind
		envelope       algebraic.Option[security.ApprovalEnvelope]
		envelopeDigest algebraic.Option[security.Digest]
		valid          bool
	}
)

// ApprovalEvent 为 ApprovalFSM 发出的不可变脱敏事件。
type ApprovalEvent = Event[ApprovalEventKind]

// NewApprovalContext 校验操作标识、词法绑定、词法快照与可选策略摘要，强制能力、目标节点与端点三元组一致。
func NewApprovalContext(spec ApprovalContextSpec) (ApprovalContext, error) {
	if !spec.OperationID.IsValid() || !spec.LexicalBinding.IsValid() || !spec.LexicalSnapshot.IsValid() ||
		!bindingMatchesSnapshot(spec.LexicalBinding, spec.LexicalSnapshot) {
		return ApprovalContext{}, domi18n.EF(ErrInvalidContext, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "operation_id/lexical_binding/lexical_snapshot"))
	}
	if pd, ok := spec.PolicyDigest.Get(); ok && !pd.IsValid() {
		return ApprovalContext{}, domi18n.EF(ErrInvalidContext, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "policy_digest"))
	}
	return ApprovalContext{spec.OperationID, spec.LexicalBinding, spec.LexicalSnapshot, spec.PolicyDigest, true}, nil
}

// NewApprovalState 校验上下文并构造 ApprovalFSM 初始状态（ApprovalPhaseLexicalPrecheck）。
func NewApprovalState(ctx ApprovalContext) (ApprovalState, error) {
	if !ctx.IsValid() {
		return ApprovalState{}, ErrInvalidContext
	}
	return approvalAt(ctx, ApprovalPhaseLexicalPrecheck, ctx.lexicalSnapshot, ctx.lexicalBinding), nil
}
func (c ApprovalContext) IsValid() bool {
	return c.valid && c.operationID.IsValid() && c.lexicalBinding.IsValid() && c.lexicalSnapshot.IsValid()
}
func (c ApprovalContext) OperationID() security.OperationID               { return c.operationID }
func (c ApprovalContext) LexicalBinding() security.OperationBinding       { return c.lexicalBinding }
func (c ApprovalContext) LexicalSnapshot() security.ScopeSnapshot         { return c.lexicalSnapshot }
func (c ApprovalContext) PolicyDigest() algebraic.Option[security.Digest] { return c.policyDigest }
func (s ApprovalState) IsValid() bool                                     { return s.valid && s.phase.IsValid() && s.ctx.IsValid() }
func (s ApprovalState) IsTerminal() bool {
	return s.IsValid() && (s.phase == ApprovalPhaseTokenInvalidated || s.phase == ApprovalPhaseDenied)
}
func (s ApprovalState) IsApproved() bool                                      { return s.IsValid() && s.phase == ApprovalPhaseApproved }
func (s ApprovalState) Phase() ApprovalPhase                                  { return s.phase }
func (s ApprovalState) Context() ApprovalContext                              { return s.ctx }
func (s ApprovalState) ActiveSnapshot() security.ScopeSnapshot                { return s.activeSnapshot }
func (s ApprovalState) ActiveBinding() security.OperationBinding              { return s.activeBinding }
func (s ApprovalState) EffectiveRisk() security.RiskLevel                     { return s.effectiveRisk }
func (s ApprovalState) Envelope() algebraic.Option[security.ApprovalEnvelope] { return s.envelope }
func (s ApprovalState) EnvelopeDigest() algebraic.Option[security.Digest]     { return s.envelopeDigest }
func (s ApprovalState) InvalidatedDigest() algebraic.Option[security.Digest] {
	return s.invalidatedDigest
}
func (s ApprovalState) Escalated() bool { return s.escalated }
func (s ApprovalState) EscalationReasons() []security.EscalationReason {
	return slices.Clone(s.escalationReasons)
}
func (s ApprovalState) Reason() string { return s.reason }
func (i ApprovalInput) IsValid() bool {
	return i.valid && i.kind >= approvalInEvalLexical && i.kind <= approvalInVerifyToken
}
func (e ApprovalEffect) IsValid() bool                                         { return e.valid && e.kind.IsValid() }
func (e ApprovalEffect) Kind() ApprovalEffectKind                              { return e.kind }
func (e ApprovalEffect) Envelope() algebraic.Option[security.ApprovalEnvelope] { return e.envelope }
func (e ApprovalEffect) EnvelopeDigest() algebraic.Option[security.Digest]     { return e.envelopeDigest }

// ApprovalInput 显式校验构造器集（零值输入恒无效）。
func ApprovalInputEvaluateLexical(requiresCanonicalization bool) ApprovalInput {
	return ApprovalInput{kind: approvalInEvalLexical, requiresCanonicalization: requiresCanonicalization, valid: true}
}
func ApprovalInputCanonicalized(snapshot security.ScopeSnapshot, binding security.OperationBinding) (ApprovalInput, error) {
	if !snapshot.IsValid() || !binding.IsValid() || !bindingMatchesSnapshot(binding, snapshot) {
		return ApprovalInput{}, domi18n.EF(ErrInvalidInput, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "canonical_snapshot/binding"))
	}
	return ApprovalInput{kind: approvalInCanonicalized, canonicalSnapshot: snapshot, canonicalBinding: binding, valid: true}, nil
}
func ApprovalInputRound2ProbeFailed(reason string) ApprovalInput {
	return ApprovalInput{kind: approvalInRound2Failed, reason: sanitizeReason(reason), valid: true}
}
func ApprovalInputEvaluateEscalation() ApprovalInput {
	return ApprovalInput{kind: approvalInEvalEscalation, valid: true}
}
func ApprovalInputIssueChallenge(envelope security.ApprovalEnvelope) (ApprovalInput, error) {
	if !envelope.IsValid() || !envelope.CanApprove() {
		return ApprovalInput{}, domi18n.EF(ErrInvalidApprovalEnvelope, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "approval_envelope"))
	}
	return ApprovalInput{kind: approvalInIssueChallenge, envelope: envelope, valid: true}, nil
}
func ApprovalInputVerifyToken(submittedDigest security.Digest, submittedBinding security.OperationBinding, now time.Time, userApproved bool) (ApprovalInput, error) {
	if !isValidRFC3339Time(now) || (userApproved && (!submittedDigest.IsValid() || !submittedBinding.IsValid())) {
		return ApprovalInput{}, domi18n.EF(ErrInvalidInput, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "verify_token"))
	}
	return ApprovalInput{kind: approvalInVerifyToken, submittedDigest: submittedDigest, submittedBinding: submittedBinding, now: now.UTC().Round(0), userApproved: userApproved, valid: true}, nil
}

// TransitionApproval 执行 ApprovalFSM 纯 Mealy 状态转移：
// 复用 security.InspectScopeEscalation 捕获 Protected-A -> Protected-B 等升级；
// 挑战或核准后遭遇 Round-2 探针失败或作用域升级，立即转入吸收终态 ApprovalPhaseTokenInvalidated，零陈旧令牌复用。
func TransitionApproval(state ApprovalState, input ApprovalInput) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	if !state.IsValid() {
		return state, nil, nil, ErrInvalidState
	}
	if !input.IsValid() {
		return state, nil, nil, ErrInvalidInput
	}
	switch state.phase {
	case ApprovalPhaseLexicalPrecheck:
		return stepApprovalLexical(state, input)
	case ApprovalPhaseCanonicalizing:
		return stepApprovalCanonicalizing(state, input)
	case ApprovalPhaseEvaluatingEscalation:
		return stepApprovalEvaluateEscalation(state, input)
	case ApprovalPhaseChallengePending:
		return stepApprovalChallengePending(state, input)
	case ApprovalPhaseChallengeIssued:
		return stepApprovalChallengeIssued(state, input)
	case ApprovalPhaseApproved:
		return stepApprovalReprobe(state, state.envelopeDigest, input, "Canonicalized/Round2ProbeFailed")
	case ApprovalPhaseTokenInvalidated, ApprovalPhaseDenied:
		return state, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMTerminalState, domi18n.Str("state", state.phase.String()))
	default:
		return state, nil, nil, ErrInvalidState
	}
}

func stepApprovalLexical(s ApprovalState, in ApprovalInput) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	if in.kind != approvalInEvalLexical {
		return s, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMExpectedInput, domi18n.Str("state", s.phase.String()), domi18n.Str("expected", "EvaluateLexical"))
	}
	if s.ctx.lexicalSnapshot.Verdict().Denied() {
		return approvalDeny(s, "lexical verdict denied", nil)
	}
	switch d := s.ctx.lexicalSnapshot.Decision().(type) {
	case *security.DecisionDeny:
		return approvalDeny(s, pickIf(d.Reason() != "", d.Reason(), "lexical guardrail denied"), nil)
	case *security.DecisionNeedApproval, *security.DecisionAllow:
		if in.requiresCanonicalization {
			return approvalNext(approvalAt(s.ctx, ApprovalPhaseCanonicalizing, s.activeSnapshot, s.activeBinding), ApprovalEffectCanonicalize, ApprovalEventCanonicalizeRequested, "requires_canonicalize")
		}
		if na, ok := d.(*security.DecisionNeedApproval); ok {
			next := approvalAt(s.ctx, ApprovalPhaseChallengePending, s.ctx.lexicalSnapshot, s.ctx.lexicalBinding)
			next.reason = sanitizeReason(na.Reason())
			return approvalNext(next, ApprovalEffectRequestChallenge, ApprovalEventChallengeRequested, na.Reason())
		}
		return approvalAt(s.ctx, ApprovalPhaseApproved, s.ctx.lexicalSnapshot, s.ctx.lexicalBinding), nil, []ApprovalEvent{newEvent(ApprovalEventApproved, "lexical_direct_allow")}, nil
	default:
		return approvalDeny(s, "invalid lexical guardrail decision", nil)
	}
}
func stepApprovalCanonicalizing(s ApprovalState, in ApprovalInput) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	if in.kind == approvalInRound2Failed {
		return approvalDeny(s, pickIf(in.reason != "", in.reason, "round2 canonicalization probe failed"), nil)
	}
	if in.kind != approvalInCanonicalized {
		return s, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMExpectedInput, domi18n.Str("state", s.phase.String()), domi18n.Str("expected", "Canonicalized/Round2ProbeFailed"))
	}
	if res := security.InspectScopeEscalation(s.ctx.lexicalSnapshot, in.canonicalSnapshot); !sameNonPathBinding(s.ctx.lexicalBinding, in.canonicalBinding) || hasIdentityDrift(res) {
		return approvalDeny(s, "canonical identity or non-path binding drifted", res.Reasons())
	}
	next := approvalAt(s.ctx, ApprovalPhaseEvaluatingEscalation, in.canonicalSnapshot, in.canonicalBinding)
	next.effectiveRisk = s.ctx.lexicalSnapshot.Risk().Join(in.canonicalSnapshot.Risk())
	return next, nil, []ApprovalEvent{newEvent(ApprovalEventCanonicalized, in.canonicalBinding.Action())}, nil
}
func stepApprovalEvaluateEscalation(s ApprovalState, in ApprovalInput) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	if in.kind == approvalInRound2Failed {
		return approvalDeny(s, pickIf(in.reason != "", in.reason, "round2 probe failed during escalation check"), nil)
	}
	if in.kind != approvalInEvalEscalation {
		return s, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMExpectedInput, domi18n.Str("state", s.phase.String()), domi18n.Str("expected", "EvaluateEscalation/Round2ProbeFailed"))
	}
	res := security.InspectScopeEscalation(s.ctx.lexicalSnapshot, s.activeSnapshot)
	reasons := res.Reasons()
	if !sameNonPathBinding(s.ctx.lexicalBinding, s.activeBinding) || hasIdentityDrift(res) {
		return approvalDeny(s, "canonical identity or non-path binding drifted", reasons)
	}
	effVerdict, effRisk := s.ctx.lexicalSnapshot.Verdict().Meet(s.activeSnapshot.Verdict()), s.ctx.lexicalSnapshot.Risk().Join(s.activeSnapshot.Risk())
	if effVerdict.Denied() || !effRisk.IsValid() {
		return approvalDeny(s, "effective verdict denied", reasons)
	}
	return decideAfterEscalation(s, security.JoinDecisions(s.ctx.lexicalSnapshot.Decision(), s.activeSnapshot.Decision()), effRisk, res.Escalated(), reasons)
}
func decideAfterEscalation(s ApprovalState, effDec security.GuardrailDecision, effRisk security.RiskLevel, escalated bool, reasons []security.EscalationReason) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	switch d := effDec.(type) {
	case *security.DecisionDeny:
		return approvalDeny(s, pickIf(d.Reason() != "", d.Reason(), "canonical guardrail denied"), reasons)
	case *security.DecisionNeedApproval:
		return enterChallengePending(s, effRisk, escalated, reasons, d.Reason())
	case *security.DecisionAllow:
		if escalated {
			return enterChallengePending(s, effRisk, true, reasons, "canonical_scope_escalated")
		}
		next := approvalAt(s.ctx, ApprovalPhaseApproved, s.activeSnapshot, s.activeBinding)
		next.effectiveRisk = effRisk
		return next, nil, []ApprovalEvent{newEvent(ApprovalEventApproved, "canonical_allow")}, nil
	default:
		return approvalDeny(s, "invalid canonical guardrail decision", reasons)
	}
}
func enterChallengePending(s ApprovalState, effRisk security.RiskLevel, escalated bool, reasons []security.EscalationReason, detail string) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	next := approvalAt(s.ctx, ApprovalPhaseChallengePending, s.activeSnapshot, s.activeBinding)
	next.effectiveRisk, next.escalated, next.escalationReasons, next.reason = effRisk, escalated, reasons, sanitizeReason(detail)
	reqEv := newEvent(ApprovalEventChallengeRequested, detail)
	events := pickIf(escalated, []ApprovalEvent{newEvent(ApprovalEventEscalationDetected, detail), reqEv}, []ApprovalEvent{reqEv})
	return next, []ApprovalEffect{{kind: ApprovalEffectRequestChallenge, valid: true}}, events, nil
}
func stepApprovalChallengePending(s ApprovalState, in ApprovalInput) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	if in.kind == approvalInIssueChallenge {
		return bindIssuedChallenge(s, in.envelope)
	}
	return stepApprovalReprobe(s, algebraic.None[security.Digest](), in, "IssueChallenge/Round2Probe")
}
func bindIssuedChallenge(s ApprovalState, env security.ApprovalEnvelope) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	if !s.effectiveRisk.IsValid() || !env.OperationID().Equal(s.ctx.operationID) || !env.MatchesBinding(s.activeBinding) ||
		env.Risk() != s.effectiveRisk || !equalOptionFunc(s.ctx.policyDigest, env.PolicyDigest(), security.Digest.Equal) {
		return s, nil, nil, domi18n.EF(ErrInvalidApprovalEnvelope, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "approval_envelope"))
	}
	dig, err := env.Digest()
	if err != nil {
		return s, nil, nil, domi18n.WrapSentinel(ErrInvalidApprovalEnvelope, err)
	}
	next := s
	next.phase, next.envelope, next.envelopeDigest, next.escalationReasons = ApprovalPhaseChallengeIssued, algebraic.Some(env), algebraic.Some(dig), slices.Clone(s.escalationReasons)
	return next, []ApprovalEffect{{ApprovalEffectPresentChallenge, next.envelope, next.envelopeDigest, true}}, []ApprovalEvent{newEvent(ApprovalEventChallengeIssued, dig.String())}, nil
}
func stepApprovalChallengeIssued(s ApprovalState, in ApprovalInput) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	if in.kind == approvalInVerifyToken {
		return verifyIssuedToken(s, in)
	}
	return stepApprovalReprobe(s, s.envelopeDigest, in, "VerifyToken/Round2Probe")
}
func verifyIssuedToken(s ApprovalState, in ApprovalInput) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	env, okE := s.envelope.Get()
	dig, okD := s.envelopeDigest.Get()
	if !okE || !okD {
		return s, nil, nil, ErrInvalidState
	}
	if !in.userApproved {
		denied := approvalTerminal(s, ApprovalPhaseDenied, s.envelopeDigest, "user rejected approval challenge", nil)
		return denied, []ApprovalEffect{{kind: ApprovalEffectInvalidateToken, envelopeDigest: s.envelopeDigest, valid: true}}, []ApprovalEvent{newEvent(ApprovalEventDenied, "user_rejected")}, nil
	}
	if !env.IsActiveAt(in.now) || !env.MatchesBinding(in.submittedBinding) {
		return invalidateToken(s, s.envelopeDigest, "approval token expired or binding mismatch", nil)
	}
	if matched, err := env.MatchesDigest(in.submittedDigest); err != nil || !matched || !dig.Equal(in.submittedDigest) {
		return invalidateToken(s, s.envelopeDigest, "approval token digest mismatch", nil)
	}
	next := s
	next.phase, next.escalationReasons = ApprovalPhaseApproved, slices.Clone(s.escalationReasons)
	return next, nil, []ApprovalEvent{newEvent(ApprovalEventApproved, dig.String())}, nil
}
func stepApprovalReprobe(s ApprovalState, tokDig algebraic.Option[security.Digest], in ApprovalInput, expected string) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	if in.kind == approvalInRound2Failed {
		return invalidateToken(s, tokDig, pickIf(in.reason != "", in.reason, "round2 probe failed"), nil)
	}
	if in.kind == approvalInCanonicalized {
		return stepApprovalReprobeCanonical(s, tokDig, in)
	}
	return s, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMExpectedInput, domi18n.Str("state", s.phase.String()), domi18n.Str("expected", expected))
}
func stepApprovalReprobeCanonical(s ApprovalState, tokDig algebraic.Option[security.Digest], in ApprovalInput) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	res := security.InspectScopeEscalation(s.activeSnapshot, in.canonicalSnapshot)
	// 良性 Round-2 路径钉住仅限于未经挑战信封的词法直接放行（s.envelope.IsNone()）；
	// 一旦已签发并绑定挑战信封（s.envelope.IsSome()），规范绑定必须与 activeBinding 完全相等，阻断受保护路径被重定向至非受保护路径绕过信封。
	allowBenignPathPin := s.phase == ApprovalPhaseApproved && s.envelope.IsNone()
	bindingOK := pickIf(allowBenignPathPin, sameNonPathBinding(s.activeBinding, in.canonicalBinding), s.activeBinding.Equal(in.canonicalBinding))
	if res.Escalated() || !bindingOK || in.canonicalSnapshot.Verdict().Denied() || in.canonicalSnapshot.Decision().Kind() == security.DecisionKindDeny {
		return invalidateToken(s, tokDig, "post-challenge canonical scope escalated or binding drifted", res.Reasons())
	}
	if allowBenignPathPin {
		next := s
		next.activeSnapshot, next.activeBinding, next.escalationReasons = in.canonicalSnapshot, in.canonicalBinding, slices.Clone(s.escalationReasons)
		return next, nil, []ApprovalEvent{newEvent(ApprovalEventCanonicalized, "reprobe_pinned")}, nil
	}
	return s, nil, []ApprovalEvent{newEvent(ApprovalEventCanonicalized, "reprobe_unchanged")}, nil
}
func bindingMatchesSnapshot(b security.OperationBinding, snap security.ScopeSnapshot) bool {
	return b.Capability() == snap.Capability() && b.NodeID() == snap.TargetNode() &&
		equalOptionFunc(b.Endpoint(), snap.Endpoint(), netaddr.Endpoint.Equal)
}
func sameNonPathBinding(a, b security.OperationBinding) bool {
	return a.IsValid() && b.IsValid() && a.Capability() == b.Capability() && a.Tool() == b.Tool() &&
		a.Action() == b.Action() && a.NodeID() == b.NodeID() && slices.Equal(a.NodeIDs(), b.NodeIDs()) &&
		equalOptionFunc(a.Endpoint(), b.Endpoint(), netaddr.Endpoint.Equal) &&
		equalOptionFunc(a.CommandDigest(), b.CommandDigest(), security.Digest.Equal) &&
		equalOptionFunc(a.PlanDigest(), b.PlanDigest(), security.Digest.Equal) &&
		maps.Equal(a.Parameters(), b.Parameters())
}
func hasIdentityDrift(res security.ScopeEscalationResult) bool {
	return res.HasReason(security.EscalationInvalidInput) || res.HasReason(security.EscalationCapabilityDrift) ||
		res.HasReason(security.EscalationTargetNodeDrift) || res.HasReason(security.EscalationEndpointDrift)
}
func mergeEscalationReasons(a, b []security.EscalationReason) []security.EscalationReason {
	out := slices.Clone(a)
	for _, r := range b {
		if !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}
func approvalAt(ctx ApprovalContext, phase ApprovalPhase, snap security.ScopeSnapshot, bind security.OperationBinding) ApprovalState {
	return ApprovalState{phase: phase, ctx: ctx, activeSnapshot: snap, activeBinding: bind, effectiveRisk: snap.Risk(), valid: true}
}
func approvalNext(next ApprovalState, eff ApprovalEffectKind, ev ApprovalEventKind, detail string) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	return next, []ApprovalEffect{{kind: eff, valid: true}}, []ApprovalEvent{newEvent(ev, detail)}, nil
}
func approvalTerminal(s ApprovalState, phase ApprovalPhase, invDig algebraic.Option[security.Digest], reason string, extra []security.EscalationReason) ApprovalState {
	next := s
	next.phase, next.envelope, next.envelopeDigest, next.invalidatedDigest = phase, algebraic.None[security.ApprovalEnvelope](), algebraic.None[security.Digest](), invDig
	next.escalated, next.escalationReasons, next.reason, next.valid = s.escalated || len(extra) > 0, mergeEscalationReasons(s.escalationReasons, extra), sanitizeReason(reason), true
	return next
}
func approvalDeny(s ApprovalState, reason string, extra []security.EscalationReason) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	st := approvalTerminal(s, ApprovalPhaseDenied, algebraic.None[security.Digest](), reason, extra)
	return st, nil, []ApprovalEvent{newEvent(ApprovalEventDenied, st.reason)}, nil
}
func invalidateToken(s ApprovalState, dig algebraic.Option[security.Digest], reason string, extra []security.EscalationReason) (ApprovalState, []ApprovalEffect, []ApprovalEvent, error) {
	st := approvalTerminal(s, ApprovalPhaseTokenInvalidated, dig, reason, extra)
	return st, []ApprovalEffect{{kind: ApprovalEffectInvalidateToken, envelopeDigest: dig, valid: true}}, []ApprovalEvent{newEvent(ApprovalEventTokenInvalidated, st.reason)}, nil
}
