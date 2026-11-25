package gate

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/ports"
)

func TestInteractiveApprovalGrantRejectMismatchAndExpired(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(101)
	sink := newFakeAuditSink(t, "gate-interactive-01")
	pol := mustPolicy(t, security.RiskModerate, NoElicitFallbackDeny, "/etc/**")

	var mode string
	inter := &fakeInteraction{
		canInteract: true,
		promptFn: func(_ context.Context, env security.ApprovalEnvelope) (ports.ApprovalDecisionResponse, error) {
			return respondByMode(clk, env, mode)
		},
	}
	g := mustGate(t, GateConfig{
		Profile: PolicyProfileStrictAgent, Policy: pol, AuditSink: sink,
		Interaction: inter, Clock: clk, Entropy: ent,
	})
	req := mustNewRequest(t, GateRequestSpec[security.CapFileMut]{
		Binding: mustBinding(t, security.CapabilityFileMut, "file", "write", "web-01", "/etc/nginx.conf"),
		Risk:    security.RiskModerate,
	})

	mode = "approve"
	ran := false
	requireNoErr(t, WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[security.CapFileMut]) error {
		ran = true
		return nil
	}), "交互审批同意")
	requireTrue(t, ran, "同意后必须执行 run")

	for _, tc := range []struct {
		name, mode string
		wantErr    error
	}{
		{"reject", "reject", ErrApprovalRejected},
		{"wrong_digest", "wrong_digest", ErrApprovalMismatch},
		{"expire", "expire", ErrApprovalExpired},
		{"cancel", "cancel", ports.ErrInteractionCanceled},
	} {
		mode = tc.mode
		err := WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[security.CapFileMut]) error {
			t.Fatalf("%s 不得进入 run", tc.name)
			return nil
		})
		requireErrIs(t, err, tc.wantErr, tc.name)
	}
	assertNoOrphanAudit(t, g, sink)
}

func respondByMode(clk *fakeClock, env security.ApprovalEnvelope, mode string) (ports.ApprovalDecisionResponse, error) {
	dig, err := env.Digest()
	if err != nil {
		return zeroVal[ports.ApprovalDecisionResponse](), err
	}
	switch mode {
	case "approve":
		return ports.NewApprovalDecisionResponse(security.VerdictAllow, dig, "approved")
	case "reject":
		return ports.NewApprovalDecisionResponse(security.VerdictDeny, dig, "rejected")
	case "wrong_digest":
		return ports.NewApprovalDecisionResponse(security.VerdictAllow, security.DigestBytes([]byte("wrong")), "tampered")
	case "expire":
		clk.Advance(defaultApprovalTTL)
		return ports.NewApprovalDecisionResponse(security.VerdictAllow, dig, "too late")
	default:
		return zeroVal[ports.ApprovalDecisionResponse](), ports.ErrInteractionCanceled
	}
}

func TestTwoStepChallengeGrantAndAdversarialRejections(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(111)
	sink := newFakeAuditSink(t, "gate-twostep-01")
	pol := mustPolicy(t, security.RiskModerate, NoElicitFallbackChallenge, "/etc/**")
	g := mustGate(t, GateConfig{
		Profile: PolicyProfileStrictAgent, Policy: pol, AuditSink: sink, Clock: clk, Entropy: ent,
	})
	binding := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/etc/shadow")
	baseReq := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{Binding: binding, Risk: security.RiskModerate})

	// Step 1 -> Step 2 合法批准放行。
	ch := issueTwoStepChallenge(t, g, baseReq)
	step2Req := mustSubmissionReq[security.CapFileRead](t, ch.Envelope(), ch.EnvelopeDigest(), binding, security.VerdictAllow)
	ran := false
	requireNoErr(t, WithAuthorized(context.Background(), g, step2Req, func(opCtx context.Context, auth Authorized[security.CapFileRead]) error {
		ran = true
		oid, ok := trace.OpIDFromContext(opCtx)
		requireTrue(t, ok && oid.Equal(ch.Envelope().OperationID()) && auth.IsValid(), "opID 须继承信封标识")
		return nil
	}), "合法两步审批")
	requireTrue(t, ran, "批准后必须执行 run")

	// 重放已消费信封必须返回 ErrApprovalReplayed。
	requireErrIs(t, WithAuthorized(context.Background(), g, step2Req, noopRun[security.CapFileRead]), ErrApprovalReplayed, "重放已消费信封")

	// 提交拒绝回执（VerdictDeny）后再重放 VerdictAllow 必须返回 ErrApprovalReplayed。
	chRej := issueTwoStepChallenge(t, g, baseReq)
	rejReq := mustSubmissionReq[security.CapFileRead](t, chRej.Envelope(), chRej.EnvelopeDigest(), binding, security.VerdictDeny)
	requireErrIs(t, WithAuthorized(context.Background(), g, rejReq, noopRun[security.CapFileRead]), ErrApprovalRejected, "两步用户拒绝")
	allowAfterRej := mustSubmissionReq[security.CapFileRead](t, chRej.Envelope(), chRej.EnvelopeDigest(), binding, security.VerdictAllow)
	requireErrIs(t, WithAuthorized(context.Background(), g, allowAfterRej, noopRun[security.CapFileRead]), ErrApprovalReplayed, "拒绝后不得重放")

	// 伪造信封必须返回 ErrApprovalMismatch。
	forgedEnv := buildForgedEnvelope(t, ent, clk.Now(), binding)
	forgedDig, err := forgedEnv.Digest()
	requireNoErr(t, err, "forged.Digest")
	forgedReq := mustSubmissionReq[security.CapFileRead](t, forgedEnv, forgedDig, binding, security.VerdictAllow)
	requireErrIs(t, WithAuthorized(context.Background(), g, forgedReq, noopRun[security.CapFileRead]), ErrApprovalMismatch, "伪造信封")

	verifyAdversarialMismatches(t, g, clk, ent, baseReq, binding)
}

func verifyAdversarialMismatches(
	t *testing.T,
	g *Gate,
	clk *fakeClock,
	ent *fakeEntropy,
	baseReq GateRequest[security.CapFileRead],
	binding security.OperationBinding,
) {
	t.Helper()

	// 1. 错误 OperationID。
	ch1 := issueTwoStepChallenge(t, g, baseReq)
	otherOp, err := security.NewOperationIDFrom(ent)
	requireNoErr(t, err, "NewOperationIDFrom")
	wrongOpReq := mustDigestSubmissionReq[security.CapFileRead](t, otherOp, ch1.EnvelopeDigest(), binding)
	requireErrIs(t, WithAuthorized(context.Background(), g, wrongOpReq, noopRun[security.CapFileRead]), ErrApprovalMismatch, "错 OperationID")

	// 2. 错误作用域路径。
	ch2 := issueTwoStepChallenge(t, g, baseReq)
	otherScope := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/root/.ssh/id_rsa")
	wrongScopeReq := mustDigestSubmissionReq[security.CapFileRead](t, ch2.Envelope().OperationID(), ch2.EnvelopeDigest(), otherScope)
	requireErrIs(t, WithAuthorized(context.Background(), g, wrongScopeReq, noopRun[security.CapFileRead]), ErrApprovalMismatch, "错作用域路径")

	// 3. 跨能力重放（CapFileRead 令牌用于 CapFileMut）。
	ch3 := issueTwoStepChallenge(t, g, baseReq)
	mutBind := mustBinding(t, security.CapabilityFileMut, "file", "read", "web-01", "/etc/shadow")
	wrongCapReq := mustDigestSubmissionReq[security.CapFileMut](t, ch3.Envelope().OperationID(), ch3.EnvelopeDigest(), mutBind)
	requireErrIs(t, WithAuthorized(context.Background(), g, wrongCapReq, noopRun[security.CapFileMut]), ErrApprovalMismatch, "跨能力重放")

	// 4. 过期信封（到达 TTL 边界）。
	ch4 := issueTwoStepChallenge(t, g, baseReq)
	clk.Advance(defaultApprovalTTL)
	expiredReq := mustSubmissionReq[security.CapFileRead](t, ch4.Envelope(), ch4.EnvelopeDigest(), binding, security.VerdictAllow)
	requireErrIs(t, WithAuthorized(context.Background(), g, expiredReq, noopRun[security.CapFileRead]), ErrApprovalExpired, "过期信封")
}

func TestTwoStepPendingCapacityAndExpiredPrune(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(119)
	sink := newFakeAuditSink(t, "gate-cap-01")
	pol, err := NewGuardrailPolicy(GuardrailPolicySpec{
		ApprovalThreshold:    security.RiskModerate,
		NoElicitFallback:     NoElicitFallbackChallenge,
		MaxPendingChallenges: 2,
	})
	requireNoErr(t, err, "NewGuardrailPolicy")
	g := mustGate(t, GateConfig{
		Profile: PolicyProfileStrictAgent, Policy: pol, AuditSink: sink, Clock: clk, Entropy: ent,
	})
	binding := mustBinding(t, security.CapabilityExecute, "terminal_exec", "run", "web-01")
	req := mustNewRequest(t, GateRequestSpec[security.CapExecute]{Binding: binding, Risk: security.RiskModerate})

	ch1 := issueTwoStepChallenge(t, g, req)
	_ = issueTwoStepChallenge(t, g, req)
	// 容量已满（2/2）时拒绝签发第 3 个挂起挑战。
	requireErrIs(t, WithAuthorized(context.Background(), g, req, noopRun[security.CapExecute]), ErrPendingLimitExceeded, "待审批容量上限")

	// 时钟推进至过期后，新请求自动清理过期槽位并成功签发；且过期被清理的旧令牌仍精确返回 ErrApprovalExpired。
	clk.Advance(defaultApprovalTTL + time.Second)
	_ = issueTwoStepChallenge(t, g, req)
	expiredSubmit := mustSubmissionReq[security.CapExecute](t, ch1.Envelope(), ch1.EnvelopeDigest(), binding, security.VerdictAllow)
	requireErrIs(t, WithAuthorized(context.Background(), g, expiredSubmit, noopRun[security.CapExecute]), ErrApprovalExpired, "清理后提交旧过期信封")
}

func TestTwoStepConcurrentReplayRaceSingleWinner(t *testing.T) {
	defer verifyNoGoroutineLeak(t)
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(121)
	sink := newFakeAuditSink(t, "gate-replay-race-01")
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskModerate, NoElicitFallbackChallenge, "/etc/**"),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})
	binding := mustBinding(t, security.CapabilityFileMut, "file", "write", "app-01", "/etc/app.conf")
	baseReq := mustNewRequest(t, GateRequestSpec[security.CapFileMut]{Binding: binding, Risk: security.RiskModerate})

	ch := issueTwoStepChallenge(t, g, baseReq)
	submitReq := mustSubmissionReq[security.CapFileMut](t, ch.Envelope(), ch.EnvelopeDigest(), binding, security.VerdictAllow)

	var winners, replayed atomic.Int32
	start := make(chan struct{})
	err := conc.RunWait(context.Background(), func(_ context.Context, n *conc.Nursery) error {
		for range 10 {
			if gErr := n.Go(func(c context.Context) error {
				<-start
				return runReplayCompetitor(c, g, submitReq, &winners, &replayed)
			}); gErr != nil {
				return gErr
			}
		}
		close(start)
		return nil
	})
	requireNoErr(t, err, "并发重放竞态")
	requireTrue(t, winners.Load() == 1 && replayed.Load() == 9, "并发重放必须严格仅 1 胜出 9 重放拒绝")
}

func runReplayCompetitor(ctx context.Context, g *Gate, req GateRequest[security.CapFileMut], winners, replayed *atomic.Int32) error {
	err := WithAuthorized(ctx, g, req, func(context.Context, Authorized[security.CapFileMut]) error {
		winners.Add(1)
		return nil
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrApprovalReplayed) {
		replayed.Add(1)
		return nil
	}
	return err
}

func TestRound2CanonicalizationEscalationRedirectAndProbeFailure(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(131)
	sink := newFakeAuditSink(t, "gate-round2-01")
	ruleA, err := pathalg.NewProtectedRule("/etc/**", "zone-etc")
	requireNoErr(t, err, "NewProtectedRule(A)")
	ruleB, err := pathalg.NewProtectedRule("/root/**", "zone-root")
	requireNoErr(t, err, "NewProtectedRule(B)")
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustClassifiedPolicy(t, security.RiskDangerous, NoElicitFallbackChallenge, ruleA, ruleB),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})

	lexBind := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/tmp/link")
	canBindA := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/etc/passwd")
	canBindB := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/root/.ssh/authorized_keys")

	// 场景 1：非受保护 -> 受保护 /etc/passwd 触发升级挑战，并在 OperationStream 发射 ApprovalChallengeEvent。
	ch := verifyEscalatedStreamChallenge(t, g, ent, lexBind, canBindA)

	// 场景 2：Protected-A -> Protected-B 软链重定向必须作废令牌并报 ErrScopeEscalated + ErrApprovalInvalidated。
	subA := mustApprovalSub(t, ch.Envelope(), ch.EnvelopeDigest(), security.VerdictAllow)
	redirectReq := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		OperationID: algebraic.Some(ch.Envelope().OperationID()), Binding: lexBind, Risk: security.RiskSafe,
		Approval: algebraic.Some(subA),
		Canonicalize: func(context.Context) (CanonicalizeResult, error) {
			return CanonicalizeResult{Binding: canBindB, Paths: []string{"/root/.ssh/authorized_keys"}}, nil
		},
	})
	redErr := WithAuthorized(context.Background(), g, redirectReq, noopRun[security.CapFileRead])
	requireErrIs(t, redErr, ErrScopeEscalated, "Protected-A -> Protected-B ErrScopeEscalated")
	requireErrIs(t, redErr, ErrApprovalInvalidated, "Protected-A -> Protected-B ErrApprovalInvalidated")

	// 场景 3：Round-2 复检探针失败必须立即作废令牌，阻断 SFTP 错误预言机与重放。
	verifyRound2ProbeFailureInvalidatesToken(t, g, lexBind, canBindA)
}

func verifyEscalatedStreamChallenge(t *testing.T, g *Gate, ent *fakeEntropy, lexBind, canBindA security.OperationBinding) *ApprovalChallengeError {
	t.Helper()
	traceID, err := security.NewTraceIDFrom(ent)
	requireNoErr(t, err, "NewTraceIDFrom")
	explicitOp, err := security.NewOperationIDFrom(ent)
	requireNoErr(t, err, "NewOperationIDFrom")
	stream, err := events.NewOperationStream(events.OperationStreamConfig{
		TraceID: traceID, OperationID: explicitOp, OperationBuffer: 16,
	})
	requireNoErr(t, err, "NewOperationStream")
	defer stream.Close()

	req := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		TraceID: algebraic.Some(traceID), OperationID: algebraic.Some(explicitOp),
		Binding: lexBind, Risk: security.RiskSafe, OperationStream: stream,
		Canonicalize: func(context.Context) (CanonicalizeResult, error) {
			return CanonicalizeResult{Binding: canBindA, Paths: []string{"/etc/passwd"}}, nil
		},
	})
	ch := issueTwoStepChallenge(t, g, req)
	requireTrue(t, ch.Escalated(), "词法非受保护重定向到 /etc/passwd 必须标记 Escalated=true")

	stream.Close()
	sawChallengeEv := false
	for ev, sErr := range stream.All(context.Background()) {
		requireNoErr(t, sErr, "stream.All")
		if _, ok := ev.(*events.ApprovalChallengeEvent); ok {
			sawChallengeEv = true
		}
	}
	requireTrue(t, sawChallengeEv, "期望 OperationStream 收到 ApprovalChallengeEvent")
	return ch
}

func verifyRound2ProbeFailureInvalidatesToken(t *testing.T, g *Gate, lexBind, canBindA security.OperationBinding) {
	t.Helper()
	step1 := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		Binding: lexBind, Risk: security.RiskSafe,
		Canonicalize: func(context.Context) (CanonicalizeResult, error) {
			return CanonicalizeResult{Binding: canBindA, Paths: []string{"/etc/passwd"}}, nil
		},
	})
	chProbe := issueTwoStepChallenge(t, g, step1)
	subP := mustApprovalSub(t, chProbe.Envelope(), chProbe.EnvelopeDigest(), security.VerdictAllow)
	probeErr := errors.New("sftp lstat permission denied")
	probeFailReq := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		OperationID: algebraic.Some(chProbe.Envelope().OperationID()), Binding: lexBind, Risk: security.RiskSafe,
		Approval: algebraic.Some(subP),
		Canonicalize: func(context.Context) (CanonicalizeResult, error) {
			return CanonicalizeResult{}, probeErr
		},
	})
	gotErr := WithAuthorized(context.Background(), g, probeFailReq, noopRun[security.CapFileRead])
	requireErrIs(t, gotErr, ErrApprovalInvalidated, "Round-2 探针失败")
	requireErrIs(t, gotErr, probeErr, "Round-2 探针根因")
	requireErrIs(t, WithAuthorized(context.Background(), g, probeFailReq, noopRun[security.CapFileRead]), ErrApprovalReplayed, "作废后重放")
}

func TestNoElicitFallbackDenyAndNodeOverridesDeny(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(141)
	sink := newFakeAuditSink(t, "gate-deny-01")
	ruleDeny, err := security.NewNodeOverrideRuleWithFloor("prod-*", security.RiskSafe, security.DecisionKindDeny)
	requireNoErr(t, err, "NewNodeOverrideRuleWithFloor")
	ov, err := security.NewNodeOverrides(ruleDeny)
	requireNoErr(t, err, "NewNodeOverrides")
	pol, err := NewGuardrailPolicy(GuardrailPolicySpec{
		ApprovalThreshold: security.RiskModerate,
		NoElicitFallback:  NoElicitFallbackDeny,
		NodeOverrides:     algebraic.Some(ov),
	})
	requireNoErr(t, err, "NewGuardrailPolicy")
	g := mustGate(t, GateConfig{
		Profile: PolicyProfileStrictAgent, Policy: pol, AuditSink: sink, Clock: clk, Entropy: ent,
	})

	prodReq := mustNewRequest(t, GateRequestSpec[security.CapInspect]{
		Binding: mustBinding(t, security.CapabilityInspect, "nodes", "inspect", "prod-db-01"),
		Risk:    security.RiskSafe,
	})
	requireErrIs(t, WithAuthorized(context.Background(), g, prodReq, noopRun[security.CapInspect]), ErrAuthorizationDenied, "NodeOverride Deny")

	devReq := mustNewRequest(t, GateRequestSpec[security.CapExecute]{
		Binding: mustBinding(t, security.CapabilityExecute, "terminal_exec", "run", "dev-01"),
		Risk:    security.RiskModerate,
	})
	gotErr := WithAuthorized(context.Background(), g, devReq, noopRun[security.CapExecute])
	requireErrIs(t, gotErr, ErrApprovalRequired, "无交互 Deny 回退")
	requireErrIs(t, gotErr, ports.ErrInteractionUnavailable, "无交互根因")
}

func noopRun[C security.Capability](context.Context, Authorized[C]) error { return nil }

func mustApprovalSub(t *testing.T, env security.ApprovalEnvelope, dig security.Digest, verdict security.Verdict) ApprovalSubmission {
	t.Helper()
	resp, err := ports.NewApprovalDecisionResponse(verdict, dig, "test")
	requireNoErr(t, err, "NewApprovalDecisionResponse")
	sub, err := NewApprovalSubmission(ApprovalSubmissionSpec{Envelope: algebraic.Some(env), Response: resp})
	requireNoErr(t, err, "NewApprovalSubmission")
	return sub
}

func mustSubmissionReq[C security.Capability](t *testing.T, env security.ApprovalEnvelope, dig security.Digest, binding security.OperationBinding, verdict security.Verdict) GateRequest[C] {
	t.Helper()
	sub := mustApprovalSub(t, env, dig, verdict)
	return mustNewRequest(t, GateRequestSpec[C]{
		OperationID: algebraic.Some(env.OperationID()), Binding: binding, Risk: security.RiskModerate, Approval: algebraic.Some(sub),
	})
}

func mustDigestSubmissionReq[C security.Capability](t *testing.T, opID security.OperationID, dig security.Digest, binding security.OperationBinding) GateRequest[C] {
	t.Helper()
	resp, err := ports.NewApprovalDecisionResponse(security.VerdictAllow, dig, "ok")
	requireNoErr(t, err, "NewApprovalDecisionResponse")
	sub, err := NewApprovalSubmission(ApprovalSubmissionSpec{Response: resp})
	requireNoErr(t, err, "NewApprovalSubmission")
	return mustNewRequest(t, GateRequestSpec[C]{
		OperationID: algebraic.Some(opID), Binding: binding, Risk: security.RiskModerate, Approval: algebraic.Some(sub),
	})
}

func issueTwoStepChallenge[C security.Capability](t *testing.T, g *Gate, req GateRequest[C]) *ApprovalChallengeError {
	t.Helper()
	err := WithAuthorized(context.Background(), g, req, func(context.Context, Authorized[C]) error {
		t.Fatal("Step 1 签发挑战时不得进入 run")
		return nil
	})
	chErr, ok := errors.AsType[*ApprovalChallengeError](err)
	requireTrue(t, ok && chErr.IsValid() && errors.Is(err, ErrApprovalRequired), "期望返回有效 *ApprovalChallengeError")
	return chErr
}

func buildForgedEnvelope(t *testing.T, ent *fakeEntropy, now time.Time, binding security.OperationBinding) security.ApprovalEnvelope {
	t.Helper()
	opID, err := security.NewOperationIDFrom(ent)
	requireNoErr(t, err, "NewOperationIDFrom")
	nonce, err := security.NewApprovalNonceFrom(ent)
	requireNoErr(t, err, "NewApprovalNonceFrom")
	dec, err := security.NewDecisionNeedApproval(security.RiskDangerous, "forged")
	requireNoErr(t, err, "NewDecisionNeedApproval")
	env, err := security.NewApprovalEnvelope(security.ApprovalEnvelopeSpec{
		OperationID: opID, Binding: binding, Risk: security.RiskDangerous,
		Decision: dec, ScopeSummary: "forged envelope", IssuedAt: now,
		TTL: algebraic.FromStdDuration(defaultApprovalTTL), Nonce: nonce,
	})
	requireNoErr(t, err, "NewApprovalEnvelope(forged)")
	return env
}
