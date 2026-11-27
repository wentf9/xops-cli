package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate/internal/reasonmsg"
	"github.com/wentf9/xops-cli/core/ports"
)

type reasonProjectionCase struct {
	raw string
	id  domi18n.MessageID
}

func allGateReasonCases() []reasonProjectionCase {
	return []reasonProjectionCase{
		{"nil or uninitialized guardrail decision", domi18n.KeyGateReasonNilDecision},
		{"no guardrail decision evaluated", domi18n.KeyGateReasonEmptyDecisions},
		{"operation risk level is unknown or invalid", domi18n.KeyGateReasonUnknownRisk},
		{"approval threshold is unknown or invalid", domi18n.KeyGateReasonInvalidThreshold},
		{"operation risk meets or exceeds approval threshold", domi18n.KeyGateReasonRiskMeetsThreshold},
		{"operation risk is below approval threshold", domi18n.KeyGateReasonRiskBelowThreshold},
		{"node overrides set is uninitialized or invalid", domi18n.KeyGateReasonInvalidOverrides},
		{"node override permits threshold evaluation", domi18n.KeyGateReasonNodeOverrideAllow},
		{"node override approval floor with unknown risk", domi18n.KeyGateReasonNodeOverrideUnkRisk},
		{"node override requires explicit approval", domi18n.KeyGateReasonNodeOverrideAppr},
		{"node override denies operation", domi18n.KeyGateReasonNodeOverrideDeny},
		{"lexical verdict denied", domi18n.KeyGateReasonLexVerdictDenied},
		{"lexical guardrail denied", domi18n.KeyGateReasonLexGuardrailDenied},
		{"invalid lexical guardrail decision", domi18n.KeyGateReasonInvalidLexDecision},
		{"round2 canonicalization probe failed", domi18n.KeyGateReasonRound2CanonFailed},
		{"canonical identity or non-path binding drifted", domi18n.KeyGateReasonCanonBindingDrifted},
		{"round2 probe failed during escalation check", domi18n.KeyGateReasonRound2EscFailed},
		{"effective verdict denied", domi18n.KeyGateReasonEffVerdictDenied},
		{"canonical guardrail denied", domi18n.KeyGateReasonCanonGuardrailDeny},
		{"canonical_scope_escalated", domi18n.KeyGateReasonCanonScopeEscalated},
		{"invalid canonical guardrail decision", domi18n.KeyGateReasonInvalidCanonDecision},
		{"user rejected approval challenge", domi18n.KeyGateReasonUserRejected},
		{"approval token expired or binding mismatch", domi18n.KeyGateReasonTokenExpOrMismatch},
		{"approval token digest mismatch", domi18n.KeyGateReasonTokenDigestMismatch},
		{"round2 probe failed", domi18n.KeyGateReasonRound2ProbeFailed},
		{"post-challenge canonical scope escalated or binding drifted", domi18n.KeyGateReasonPostChallengeDrift},
		{"invalid policy profile", domi18n.KeyGateReasonInvalidProfile},
		{"security verdict denied", domi18n.KeyGateReasonVerdictDenied},
		{"direct operator profile allow", domi18n.KeyGateReasonDirectOperatorAllow},
		{"unexpected guardrail decision", domi18n.KeyGateReasonUnexpectedDecision},
		{"operation touches protected path", domi18n.KeyGateReasonProtectedPath},
		{"guardrail denied", domi18n.KeyGateReasonGuardrailDenied},
		{"canonical denied", domi18n.KeyGateReasonCanonicalDenied},
		{"approval required", domi18n.KeyGateReasonApprovalRequired},
		{"scope escalated", domi18n.KeyGateReasonScopeEscalated},
		{"token invalidated", domi18n.KeyGateReasonTokenInvalidated},
		{"authorization denied", domi18n.KeyGateReasonAuthDenied},
		{"gate halted", domi18n.KeyGateReasonGateHalted},
		{"privilege escalation requires approval", domi18n.KeyGateReasonPrivEscApproval},
		{"pre-escalation baseline", domi18n.KeyGateReasonPreEscBaseline},
		{"audit event is invalid", domi18n.KeyGateReasonInvalidAuditEvent},
	}
}

// TestKeyGateReasonBijectionAndCanonicalVerbatim 锁定全部 41 条 KeyGateReason* 与规范英文原因 100% 逐字同构，
// 且均可经 reasonmsg 投影为结构化 Message 而不退化为英文字符串兜底。
func TestKeyGateReasonBijectionAndCanonicalVerbatim(t *testing.T) {
	cases := allGateReasonCases()
	covered := make(map[domi18n.MessageID]string, len(cases))
	for _, tc := range cases {
		if prev, dup := covered[tc.id]; dup {
			t.Fatalf("重复注册键 %s（原=%q，新=%q）", tc.id, prev, tc.raw)
		}
		covered[tc.id] = tc.raw
		assertSingleReasonProjection(t, tc)
	}
	for _, key := range domi18n.CoreKeys() {
		if !strings.HasPrefix(string(key), "gate.reason.") {
			continue
		}
		if _, ok := covered[key]; !ok {
			t.Fatalf("core/domain/i18n 注册了 %s 但未纳入 reasonmsg 封闭投影表", key)
		}
	}
}

func assertSingleReasonProjection(t *testing.T, tc reasonProjectionCase) {
	t.Helper()
	if got := domi18n.CanonicalFallback(tc.id); got != tc.raw {
		t.Fatalf("CanonicalFallback(%s) = %q，期望逐字等于 %q", tc.id, got, tc.raw)
	}
	msg, ok := reasonmsg.ProjectMessage(tc.raw)
	if !ok || !msg.IsValid() || msg.ID() != tc.id || msg.Canonical() != tc.raw {
		t.Fatalf("ProjectMessage(%q) = (%v, %v)，期望 id=%s canonical=%q", tc.raw, msg, ok, tc.id, tc.raw)
	}
	trimmedMsg, okTrim := reasonmsg.ProjectMessage("  " + tc.raw + "\n")
	if !okTrim || trimmedMsg.ID() != tc.id {
		t.Fatalf("ProjectMessage(trimmed %q) 未命中 %s", tc.raw, tc.id)
	}
	param := reasonmsg.Param("reason", tc.raw, domi18n.KeyGateReasonApprovalRequired)
	nested, okMsg := param.MessageVal()
	if param.Kind() != domi18n.ParamKindMessage || !okMsg || nested.ID() != tc.id || nested.Canonical() != tc.raw {
		t.Fatalf("Param(%q) 必须产出结构化 Message %s，实际 kind=%v nested=%v", tc.raw, tc.id, param.Kind(), nested)
	}
	err := reasonmsg.ErrorForSentinel(ErrAuthorizationDenied, tc.raw, domi18n.KeyGateReasonGuardrailDenied)
	requireErrIs(t, err, ErrAuthorizationDenied, "ErrorForSentinel")
	view, okView := domi18n.InspectNode(err)
	requireTrue(t, okView && view.Cause != nil, "ErrorForSentinel 必须保留哨兵包装层")
	inner, okInner := domi18n.InspectNode(view.Cause)
	if !okInner || inner.Message.ID() != tc.id {
		t.Fatalf("ErrorForSentinel(%q) 内层消息 ID=%v，期望 %s（禁止回退非结构化明细）", tc.raw, inner.Message.ID(), tc.id)
	}
	wantText := ErrAuthorizationDenied.Error() + ": " + tc.raw
	if err.Error() != wantText {
		t.Fatalf("ErrorForSentinel(%q).Error() = %q，期望 %q", tc.raw, err.Error(), wantText)
	}
}

// TestLiveProducersMatchProjectedReasons 验证 security / events / fsm 实时产出的规范英文原因均可精确投影。
func TestLiveProducersMatchProjectedReasons(t *testing.T) {
	allowRule, err := security.NewNodeOverrideRuleWithFloor("allow-*", security.RiskDangerous, security.DecisionKindAllow)
	requireNoErr(t, err, "allowRule")
	apprRule, err := security.NewNodeOverrideRuleWithFloor("appr-*", security.RiskDangerous, security.DecisionKindNeedApproval)
	requireNoErr(t, err, "apprRule")
	denyRule, err := security.NewNodeOverrideRuleWithFloor("deny-*", security.RiskDangerous, security.DecisionKindDeny)
	requireNoErr(t, err, "denyRule")
	ov, err := security.NewNodeOverrides(allowRule, apprRule, denyRule)
	requireNoErr(t, err, "NewNodeOverrides")

	var zeroOverrides security.NodeOverrides
	var zeroAuditEv *events.AuditRecordEvent
	liveCases := []reasonProjectionCase{
		{security.NormalizeDecision(nil).Reason(), domi18n.KeyGateReasonNilDecision},
		{security.FoldDecisions().Reason(), domi18n.KeyGateReasonEmptyDecisions},
		{security.EvaluateThreshold(security.RiskUnknown, security.RiskModerate).Reason(), domi18n.KeyGateReasonUnknownRisk},
		{security.EvaluateThreshold(security.RiskSafe, security.RiskUnknown).Reason(), domi18n.KeyGateReasonInvalidThreshold},
		{security.EvaluateThreshold(security.RiskDangerous, security.RiskModerate).Reason(), domi18n.KeyGateReasonRiskMeetsThreshold},
		{security.EvaluateThreshold(security.RiskSafe, security.RiskDangerous).Reason(), domi18n.KeyGateReasonRiskBelowThreshold},
		{zeroOverrides.EvaluateNode(security.RiskModerate, security.RiskSafe, "n1").Reason(), domi18n.KeyGateReasonInvalidOverrides},
		{ov.EvaluateNode(security.RiskDangerous, security.RiskSafe, "allow-1").Reason(), domi18n.KeyGateReasonNodeOverrideAllow},
		{ov.EvaluateNode(security.RiskDangerous, security.RiskSafe, "appr-1").Reason(), domi18n.KeyGateReasonNodeOverrideAppr},
		{ov.EvaluateNode(security.RiskDangerous, security.RiskSafe, "deny-1").Reason(), domi18n.KeyGateReasonNodeOverrideDeny},
		{zeroAuditEv.Decision().Reason(), domi18n.KeyGateReasonInvalidAuditEvent},
		{directOperatorBaseDecision(security.NewDecisionAllow("")).Reason(), domi18n.KeyGateReasonDirectOperatorAllow},
	}
	for _, tc := range liveCases {
		assertSingleReasonProjection(t, tc)
	}
	assertFSMLiveReasons(t)
}

func assertFSMLiveReasons(t *testing.T) {
	t.Helper()
	b := mustBinding(t, security.CapabilityMutate, "file_write", "write", "web-01", "/tmp/a")
	needDec := security.EvaluateThreshold(security.RiskDangerous, security.RiskModerate)
	snap, err := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityMutate, TargetNode: "web-01", Endpoint: b.Endpoint(),
		Verdict: security.VerdictAllow, Risk: security.RiskDangerous, Decision: needDec,
	})
	requireNoErr(t, err, "NewScopeSnapshot")
	opID := security.OperationIDFromBytes([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	appCtx, err := fsm.NewApprovalContext(fsm.ApprovalContextSpec{
		OperationID: opID, LexicalBinding: b, LexicalSnapshot: snap,
	})
	requireNoErr(t, err, "NewApprovalContext")
	st, err := fsm.NewApprovalState(appCtx)
	requireNoErr(t, err, "NewApprovalState")

	pending, _, _, err := fsm.TransitionApproval(st, fsm.ApprovalInputEvaluateLexical(false))
	requireNoErr(t, err, "TransitionApproval(lexical->challenge_pending)")
	requireTrue(t, pending.Phase() == fsm.ApprovalPhaseChallengePending, "应进入 ChallengePending")
	assertSingleReasonProjection(t, reasonProjectionCase{pending.Reason(), domi18n.KeyGateReasonRiskMeetsThreshold})
}

// TestApprovalEnvelopeDigestZeroDriftAndGateProjection 锁定 ApprovalEnvelope.Digest() 零漂移，
// 并验证 Gate 签发的 ApprovalChallengeError 与拒绝错误均携带结构化 KeyGateReason* 投影。
func TestApprovalEnvelopeDigestZeroDriftAndGateProjection(t *testing.T) {
	b := mustBinding(t, security.CapabilityExecute, "terminal_exec", "once", "web-01", "/etc/nginx/nginx.conf")
	opID := security.OperationIDFromBytes([16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})
	nonce, err := security.NewApprovalNonceFrom(bytes.NewReader([]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf}))
	requireNoErr(t, err, "NewApprovalNonceFrom")
	dec, err := security.NewDecisionNeedApproval(security.RiskDangerous, "operation risk meets or exceeds approval threshold")
	requireNoErr(t, err, "NewDecisionNeedApproval")
	env, err := security.NewApprovalEnvelope(security.ApprovalEnvelopeSpec{
		OperationID: opID, Binding: b, Risk: security.RiskDangerous, Decision: dec,
		ScopeSummary: "exec once on web-01", IssuedAt: baseTestTime(),
		TTL: algebraic.FromStdDuration(2 * time.Minute), Nonce: nonce,
	})
	requireNoErr(t, err, "NewApprovalEnvelope")

	var canonBuf bytes.Buffer
	requireNoErr(t, env.WriteCanonical(&canonBuf), "WriteCanonical")
	wantDigest := security.DigestFromSHA256(sha256.Sum256(canonBuf.Bytes()))
	gotDigest, err := env.Digest()
	requireNoErr(t, err, "Digest")
	requireTrue(t, gotDigest.Equal(wantDigest), "ApprovalEnvelope.Digest 必须与 WriteCanonical SHA-256 逐字节一致")
	jsonRaw, err := env.CanonicalJSON()
	requireNoErr(t, err, "CanonicalJSON")
	requireTrue(t, strings.Contains(string(jsonRaw), `"reason":"operation risk meets or exceeds approval threshold"`), "ApprovalEnvelope.CanonicalJSON 必须保持规范英文原因")

	chErr := newApprovalChallengeError(env, gotDigest, false, dec.Reason())
	assertChallengeReasonProjected(t, chErr, domi18n.KeyGateReasonRiskMeetsThreshold, dec.Reason())

	afterDigest, err := env.Digest()
	requireNoErr(t, err, "Digest after LocalizableView")
	requireTrue(t, afterDigest.Equal(gotDigest), "LocalizableView 投影不得改变 ApprovalEnvelope.Digest")

	assertGateEndToEndProjectedErrors(t)
}

func assertGateEndToEndProjectedErrors(t *testing.T) {
	t.Helper()
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(91)
	sink := newFakeAuditSink(t, "gate-reason-proj-01")
	etcRule, err := pathalg.NewProtectedRule("/etc/**", "etc")
	requireNoErr(t, err, "NewProtectedRule")
	pol, err := NewGuardrailPolicy(GuardrailPolicySpec{
		ApprovalThreshold: security.RiskDangerous,
		NoElicitFallback:  NoElicitFallbackChallenge,
		ProtectedRules:    []pathalg.ProtectedRule{etcRule},
		ProtectedPathRisk: algebraic.Some(security.RiskModerate),
	})
	requireNoErr(t, err, "NewGuardrailPolicy")
	g := mustGate(t, GateConfig{
		Profile: PolicyProfileStrictAgent, Policy: pol, AuditSink: sink, Clock: clk, Entropy: ent,
	})

	// 1. 风险阈值触发挑战：ApprovalChallengeError 的 reason 参数必须投影为 KeyGateReasonRiskMeetsThreshold。
	riskReq := mustNewRequest(t, GateRequestSpec[security.CapExecute]{
		Binding: mustBinding(t, security.CapabilityExecute, "terminal_exec", "run", "web-01"),
		Risk:    security.RiskDangerous,
	})
	err = WithAuthorized(context.Background(), g, riskReq, func(context.Context, Authorized[security.CapExecute]) error { return nil })
	chRisk, ok := errors.AsType[*ApprovalChallengeError](err)
	requireTrue(t, ok && chRisk.IsValid(), "高风险操作应返回 *ApprovalChallengeError")
	assertChallengeReasonProjected(t, chRisk, domi18n.KeyGateReasonRiskMeetsThreshold, "operation risk meets or exceeds approval threshold")

	// 2. 受保护路径触发挑战：reason 参数必须投影为 KeyGateReasonProtectedPath。
	protReq := mustNewRequest(t, GateRequestSpec[security.CapMutate]{
		Binding: mustBinding(t, security.CapabilityMutate, "file_write", "write", "web-01", "/etc/hosts"),
		Risk:    security.RiskSafe,
	})
	err = WithAuthorized(context.Background(), g, protReq, func(context.Context, Authorized[security.CapMutate]) error { return nil })
	chProt, ok := errors.AsType[*ApprovalChallengeError](err)
	requireTrue(t, ok && chProt.IsValid(), "受保护路径操作应返回 *ApprovalChallengeError")
	assertChallengeReasonProjected(t, chProt, domi18n.KeyGateReasonProtectedPath, "operation touches protected path")

	// 3. 安全判定拒绝：返回错误内层节点必须为 KeyGateReasonVerdictDenied。
	denyReq := mustNewRequest(t, GateRequestSpec[security.CapInspect]{
		Binding: mustBinding(t, security.CapabilityInspect, "nodes", "list", "web-01"),
		Risk:    security.RiskSafe,
		Verdict: algebraic.Some(security.VerdictDeny),
	})
	err = WithAuthorized(context.Background(), g, denyReq, func(context.Context, Authorized[security.CapInspect]) error { return nil })
	requireErrIs(t, err, ErrAuthorizationDenied, "VerdictDeny 必须返回 ErrAuthorizationDenied")
	view, okView := domi18n.InspectNode(err)
	requireTrue(t, okView && view.Cause != nil, "拒绝错误应包装原因节点")
	inner, okInner := domi18n.InspectNode(view.Cause)
	requireTrue(t, okInner && inner.Message.ID() == domi18n.KeyGateReasonLexVerdictDenied, "拒绝原因应投影为 KeyGateReasonLexVerdictDenied")

	// 4. Round-2 审批后作用域升级：外层双哨兵 + 内层节点投影为 KeyGateReasonPostChallengeDrift。
	assertRound2DriftProjected(t, g)
}

func assertRound2DriftProjected(t *testing.T, g *Gate) {
	t.Helper()
	bLex := mustBinding(t, security.CapabilityMutate, "file_write", "write", "web-01", "/tmp/link")
	bProt := mustBinding(t, security.CapabilityMutate, "file_write", "write", "web-01", "/etc/shadow")
	step := 0
	canonFn := func(context.Context) (CanonicalizeResult, error) {
		step++
		if step == 1 {
			return CanonicalizeResult{Binding: bLex, Risk: algebraic.Some(security.RiskDangerous)}, nil
		}
		return CanonicalizeResult{Binding: bProt, Risk: algebraic.Some(security.RiskDangerous)}, nil
	}
	req1 := mustNewRequest(t, GateRequestSpec[security.CapMutate]{
		Binding: bLex, Risk: security.RiskSafe, Canonicalize: canonFn,
	})
	err := WithAuthorized(context.Background(), g, req1, func(context.Context, Authorized[security.CapMutate]) error { return nil })
	ch, ok := errors.AsType[*ApprovalChallengeError](err)
	requireTrue(t, ok && ch.IsValid(), "首轮应返回审批挑战")
	resp, rErr := ports.NewApprovalDecisionResponse(security.VerdictAllow, ch.EnvelopeDigest(), "operator")
	requireNoErr(t, rErr, "NewApprovalDecisionResponse")
	sub, sErr := NewApprovalSubmission(ApprovalSubmissionSpec{Envelope: algebraic.Some(ch.Envelope()), Response: resp})
	requireNoErr(t, sErr, "NewApprovalSubmission")
	req2 := mustNewRequest(t, GateRequestSpec[security.CapMutate]{
		Binding: bLex, Risk: security.RiskSafe, Canonicalize: canonFn, Approval: algebraic.Some(sub),
	})
	err = WithAuthorized(context.Background(), g, req2, func(context.Context, Authorized[security.CapMutate]) error { return nil })
	requireErrIs(t, err, ErrScopeEscalated, "审批后漂移应返回 ErrScopeEscalated")
	requireErrIs(t, err, ErrApprovalInvalidated, "审批后漂移应返回 ErrApprovalInvalidated")
	outer, _ := domi18n.InspectNode(err)
	mid, _ := domi18n.InspectNode(outer.Cause)
	inner, okInner := domi18n.InspectNode(mid.Cause)
	requireTrue(t, okInner && inner.Message.ID() == domi18n.KeyGateReasonPostChallengeDrift, "审批后漂移原因应投影为 KeyGateReasonPostChallengeDrift")
}

func assertChallengeReasonProjected(t *testing.T, ch *ApprovalChallengeError, wantID domi18n.MessageID, wantRaw string) {
	t.Helper()
	if ch.Reason() != wantRaw {
		t.Fatalf("ApprovalChallengeError.Reason() = %q，期望 %q", ch.Reason(), wantRaw)
	}
	msgOpt := ch.ReasonMessage()
	msg, okOpt := msgOpt.Get()
	if !okOpt || !msg.IsValid() || msg.ID() != wantID || msg.Canonical() != wantRaw {
		t.Fatalf("ApprovalChallengeError.ReasonMessage() = (%v, %v)，期望 id=%s canonical=%q", msg, okOpt, wantID, wantRaw)
	}
	rp := ch.ReasonParam("reason")
	view := ch.LocalizableView()
	requireTrue(t, errors.Is(view.Sentinel, ErrApprovalRequired) && view.Message.ID() == domi18n.KeyGateApprovalChallenge, "挑战视图哨兵与消息 ID 必须匹配")
	p, ok := view.Message.ParamByKey("reason")
	requireTrue(t, ok && p.Kind() == domi18n.ParamKindMessage && rp.Equal(p), "挑战 reason 参数必须与 ReasonParam 一致且为结构化嵌套消息")
	nested, okM := p.MessageVal()
	if !okM || nested.ID() != wantID || nested.Canonical() != wantRaw {
		t.Fatalf("挑战 reason 嵌套消息 = (%v, %v)，期望 id=%s canonical=%q", nested, okM, wantID, wantRaw)
	}
}

// TestApprovalChallengeError_ReasonMessageAndParamBoundaries 覆盖无效零值、typed-nil、空原因与自由文本的失败关闭语义。
func TestApprovalChallengeError_ReasonMessageAndParamBoundaries(t *testing.T) {
	var zeroCh ApprovalChallengeError
	var typedNil *ApprovalChallengeError
	for _, ch := range []*ApprovalChallengeError{&zeroCh, typedNil} {
		requireTrue(t, ch.Reason() == "" && ch.ReasonMessage().IsNone(), "无效 ApprovalChallengeError 必须返回空原因与 None")
		p := ch.ReasonParam("reason")
		nested, ok := p.MessageVal()
		requireTrue(t, ok && nested.ID() == domi18n.KeyGateReasonApprovalRequired, "无效 ApprovalChallengeError.ReasonParam 必须失败关闭至 KeyGateReasonApprovalRequired")
	}

	b := mustBinding(t, security.CapabilityMutate, "file_write", "write", "web-01", "/etc/hosts")
	opID := security.OperationIDFromBytes([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	nonce, err := security.NewApprovalNonceFrom(bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}))
	requireNoErr(t, err, "NewApprovalNonceFrom")
	dec, err := security.NewDecisionNeedApproval(security.RiskDangerous, "custom external reason")
	requireNoErr(t, err, "NewDecisionNeedApproval")
	env, err := security.NewApprovalEnvelope(security.ApprovalEnvelopeSpec{
		OperationID: opID, Binding: b, Risk: security.RiskDangerous, Decision: dec,
		ScopeSummary: "write /etc/hosts", IssuedAt: baseTestTime(),
		TTL: algebraic.FromStdDuration(time.Minute), Nonce: nonce,
	})
	requireNoErr(t, err, "NewApprovalEnvelope")
	dig, err := env.Digest()
	requireNoErr(t, err, "Digest")

	freeCh := newApprovalChallengeError(env, dig, false, "custom external reason")
	requireTrue(t, freeCh.Reason() == "custom external reason" && freeCh.ReasonMessage().IsNone(), "未登记自由文本 ReasonMessage 应返回 None")
	fp := freeCh.ReasonParam("reason")
	gotStr, okStr := fp.StringVal()
	requireTrue(t, fp.Kind() == domi18n.ParamKindString && okStr && gotStr == "custom external reason", "自由文本 ReasonParam 应回退 BoundStr")

	emptyReasonCh := &ApprovalChallengeError{envelope: env, digest: dig, reason: "", valid: true}
	emptyMsg, okEmpty := emptyReasonCh.ReasonMessage().Get()
	requireTrue(t, okEmpty && emptyMsg.ID() == domi18n.KeyGateReasonApprovalRequired, "有效态空原因 ReasonMessage 应回退 KeyGateReasonApprovalRequired")
	ep := emptyReasonCh.ReasonParam("reason")
	emptyNested, okEN := ep.MessageVal()
	requireTrue(t, okEN && emptyNested.ID() == domi18n.KeyGateReasonApprovalRequired, "有效态空原因 ReasonParam 应回退 KeyGateReasonApprovalRequired")
}

// TestReasonMsgFallbackAndFreeFormBoundary 验证空原因、非法兜底键与未知自由文本的失败关闭回退语义。
func TestReasonMsgFallbackAndFreeFormBoundary(t *testing.T) {
	if _, ok := reasonmsg.ProjectMessage(""); ok {
		t.Fatal("空字符串不应命中封闭投影集")
	}
	if _, ok := reasonmsg.ProjectMessage("custom external policy note"); ok {
		t.Fatal("未知自由文本不应命中封闭投影集")
	}

	emptyParam := reasonmsg.Param("reason", "   ", domi18n.KeyGateReasonGuardrailDenied)
	nested, ok := emptyParam.MessageVal()
	requireTrue(t, ok && nested.ID() == domi18n.KeyGateReasonGuardrailDenied, "空原因必须使用 fallbackID")

	invalidFallbackParam := reasonmsg.Param("reason", "", domi18n.MessageIDInvalid)
	nestedFB, okFB := invalidFallbackParam.MessageVal()
	requireTrue(t, okFB && nestedFB.ID() == domi18n.KeyGateReasonApprovalRequired, "非法 fallbackID 必须失败关闭至 KeyGateReasonApprovalRequired")

	freeParam := reasonmsg.Param("reason", "custom external policy note", domi18n.KeyGateReasonApprovalRequired)
	gotStr, okStr := freeParam.StringVal()
	requireTrue(t, freeParam.Kind() == domi18n.ParamKindString && okStr && gotStr == "custom external policy note", "未知自由文本必须安全回退 BoundStr")

	emptyErr := reasonmsg.ErrorForSentinel(ErrAuthorizationDenied, "", domi18n.KeyGateReasonGuardrailDenied)
	requireErrIs(t, emptyErr, ErrAuthorizationDenied, "空原因 ErrorForSentinel")
	vEmpty, _ := domi18n.InspectNode(emptyErr)
	innerEmpty, _ := domi18n.InspectNode(vEmpty.Cause)
	requireTrue(t, innerEmpty.Message.ID() == domi18n.KeyGateReasonGuardrailDenied, "空原因 ErrorForSentinel 应使用 fallbackID")

	freeErr := reasonmsg.ErrorForSentinel(ErrAuthorizationDenied, "custom external policy note", domi18n.KeyGateReasonGuardrailDenied)
	requireErrIs(t, freeErr, ErrAuthorizationDenied, "自由文本 ErrorForSentinel")
	wantFree := ErrAuthorizationDenied.Error() + ": custom external policy note"
	requireTrue(t, freeErr.Error() == wantFree, "自由文本 ErrorForSentinel 必须保留哨兵头段与明细")
}
