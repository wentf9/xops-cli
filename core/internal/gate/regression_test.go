package gate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/ports"
)

// TestPathSplitBrainCannotMaskBoundProtectedPaths 验证 INV-E3 单调并集不变量：
// 无论在词法请求还是 Round-2 CanonicalizeResult 中，传入良性显式 Paths/RecursivePaths 均不得掩盖 Binding 绑定的受保护路径。
func TestPathSplitBrainCannotMaskBoundProtectedPaths(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(201)
	sink := newFakeAuditSink(t, "gate-splitbrain-01")
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskDangerous, NoElicitFallbackChallenge, "/etc/**"),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})

	// 1. 词法直接路径裂脑：Binding 含 /etc/shadow，但 Spec.Paths 仅填良性 /tmp/work。
	bindProt := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/etc/shadow")
	req1 := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		Binding: bindProt, Risk: security.RiskSafe, Paths: []string{"/tmp/work"},
	})
	_ = issueTwoStepChallenge(t, g, req1)

	// 2. 词法递归路径裂脑：Binding.RecursivePaths 含 /etc，但 Spec.RecursivePaths 仅填良性 /tmp。
	bindRec, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityFileMut, Tool: "file", Action: "delete", NodeID: "web-01",
		Endpoint: algebraic.Some(mustEndpoint(t, "198.51.100.20", 22)), RecursivePaths: []string{"/etc"},
	})
	requireNoErr(t, err, "NewOperationBinding(recursive)")
	req2 := mustNewRequest(t, GateRequestSpec[security.CapFileMut]{
		Binding: bindRec, Risk: security.RiskSafe, RecursivePaths: []string{"/tmp"},
	})
	_ = issueTwoStepChallenge(t, g, req2)

	// 3. Round-2 规范化裂脑：res.Binding 含 /etc/shadow，但 res.Paths 仅填良性 /tmp/work。
	lexBenign := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/tmp/link")
	req3 := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		Binding: lexBenign, Risk: security.RiskSafe,
		Canonicalize: func(context.Context) (CanonicalizeResult, error) {
			return CanonicalizeResult{Binding: bindProt, Paths: []string{"/tmp/work"}}, nil
		},
	})
	ch3 := issueTwoStepChallenge(t, g, req3)
	requireTrue(t, ch3.Escalated(), "Round-2 绑定受保护路径即使搭配良性 res.Paths 也必须触发升级挑战")
}

// TestTwoStepRound2BypassAndCrossPathOracleBlocked 验证两步审批对 Round-2 规范化一致性的强制执行（INV-E5）：
// 禁止 Step 2 省略 Canonicalize、禁止非规范化挑战追加 Canonicalize、禁止跨路径令牌触发远端探测，并验证正常二次复检放行。
func TestTwoStepRound2BypassAndCrossPathOracleBlocked(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(211)
	sink := newFakeAuditSink(t, "gate-r2-bypass-01")
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskDangerous, NoElicitFallbackChallenge, "/etc/**"),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})
	lexBind := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/tmp/link")
	canBindA := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/etc/passwd")
	otherBind := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/secret/other")
	canFn := func(context.Context) (CanonicalizeResult, error) {
		return CanonicalizeResult{Binding: canBindA, Paths: []string{"/etc/passwd"}}, nil
	}
	step1Req := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		Binding: lexBind, Risk: security.RiskSafe, Canonicalize: canFn,
	})

	// 1. 绕过向量：Step 1 启用了 Canonicalize，Step 2 拷贝 canBindA 并传 Canonicalize: nil 企图跳过 Round-2 复检。
	chSkip := issueTwoStepChallenge(t, g, step1Req)
	skipReq := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		OperationID: algebraic.Some(chSkip.Envelope().OperationID()), Binding: canBindA, Risk: security.RiskSafe,
		Approval: algebraic.Some(mustApprovalSub(t, chSkip.Envelope(), chSkip.EnvelopeDigest(), security.VerdictAllow)),
	})
	skipErr := WithAuthorized(context.Background(), g, skipReq, noopRun[security.CapFileRead])
	requireErrIs(t, skipErr, ErrApprovalInvalidated, "跳过 Round-2 Canonicalize 必须作废令牌")
	requireErrIs(t, skipErr, ErrApprovalMismatch, "跳过 Round-2 Canonicalize 必须报模式不匹配")

	// 2. INV-E5 跨路径预言机阻断：Step 2 传入非词法且非挑战绑定 /secret/other 时必须在调用 Canonicalize 前拦截（0 次探测）。
	chCross := issueTwoStepChallenge(t, g, step1Req)
	probeCalls := 0
	crossReq := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		OperationID: algebraic.Some(chCross.Envelope().OperationID()), Binding: otherBind, Risk: security.RiskSafe,
		Approval: algebraic.Some(mustApprovalSub(t, chCross.Envelope(), chCross.EnvelopeDigest(), security.VerdictAllow)),
		Canonicalize: func(context.Context) (CanonicalizeResult, error) {
			probeCalls++
			return CanonicalizeResult{Binding: otherBind}, nil
		},
	})
	requireErrIs(t, WithAuthorized(context.Background(), g, crossReq, noopRun[security.CapFileRead]), ErrApprovalMismatch, "跨路径令牌必须拒绝")
	requireTrue(t, probeCalls == 0, "INV-E5 违规：跨路径令牌在拦截前不得触发远端 Canonicalize 探测")

	// 3. 反向模式失配：Step 1 未启用 Canonicalize，Step 2 强行追加 Canonicalize 必须拒绝且 0 次探测。
	verifyNonCanonicalRejectsAddedProbe(t, g, canBindA)

	// 4. 合法 Step 2 快乐路径（分别以 lexBind 和 canBindA 搭配未变化 Canonicalize 复检放行，且审计记录 DecisionKindNeedApproval）。
	verifyRound2Step2HappyPaths(t, g, sink, step1Req, lexBind, canBindA, canFn)
}

func verifyNonCanonicalRejectsAddedProbe(t *testing.T, g *Gate, bind security.OperationBinding) {
	t.Helper()
	ch := issueTwoStepChallenge(t, g, mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		Binding: bind, Risk: security.RiskModerate,
	}))
	calls := 0
	badReq := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		OperationID: algebraic.Some(ch.Envelope().OperationID()), Binding: bind, Risk: security.RiskModerate,
		Approval: algebraic.Some(mustApprovalSub(t, ch.Envelope(), ch.EnvelopeDigest(), security.VerdictAllow)),
		Canonicalize: func(context.Context) (CanonicalizeResult, error) {
			calls++
			return CanonicalizeResult{Binding: bind}, nil
		},
	})
	requireErrIs(t, WithAuthorized(context.Background(), g, badReq, noopRun[security.CapFileRead]), ErrApprovalMismatch, "非规范化挑战追加 Canonicalize")
	requireTrue(t, calls == 0, "模式失配不得触发 Canonicalize")
}

func verifyRound2Step2HappyPaths(
	t *testing.T,
	g *Gate,
	sink *fakeAuditSink,
	step1Req GateRequest[security.CapFileRead],
	lexBind, canBindA security.OperationBinding,
	canFn CanonicalizeFunc,
) {
	t.Helper()
	for _, submitBind := range []security.OperationBinding{lexBind, canBindA} {
		ch := issueTwoStepChallenge(t, g, step1Req)
		beforeLen := len(sink.snapshotEntries())
		ran := false
		req := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
			OperationID: algebraic.Some(ch.Envelope().OperationID()), Binding: submitBind, Risk: security.RiskSafe,
			Approval:     algebraic.Some(mustApprovalSub(t, ch.Envelope(), ch.EnvelopeDigest(), security.VerdictAllow)),
			Canonicalize: canFn,
		})
		requireNoErr(t, WithAuthorized(context.Background(), g, req, func(_ context.Context, auth Authorized[security.CapFileRead]) error {
			ran = true
			requireTrue(t, auth.IsValid(), "授权证明必须有效")
			return nil
		}), "Round-2 Step 2 正常放行")
		requireTrue(t, ran, "Round-2 复检一致必须执行 run")
		assertLastPairAuditDecision(t, sink, beforeLen, security.DecisionKindNeedApproval)
	}
}

// TestNonCanonicalTwoStepBypassVectorsRejected 验证未启用 Round-2 的两步二次提交无法夹带
// VerdictDeny、DecisionDeny 下限、更高 Risk 或额外受保护 Paths/RecursivePaths 绕过护栏。
func TestNonCanonicalTwoStepBypassVectorsRejected(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(221)
	sink := newFakeAuditSink(t, "gate-noncan-bypass-01")
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskModerate, NoElicitFallbackChallenge, "/etc/**"),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})
	bind := mustBinding(t, security.CapabilityFileMut, "file", "write", "web-01", "/tmp/work.txt")
	baseReq := mustNewRequest(t, GateRequestSpec[security.CapFileMut]{Binding: bind, Risk: security.RiskModerate})

	cases := []struct {
		name    string
		mutate  func(spec *GateRequestSpec[security.CapFileMut])
		wantErr error
	}{
		{
			name:    "verdict_deny",
			mutate:  func(s *GateRequestSpec[security.CapFileMut]) { s.Verdict = algebraic.Some(security.VerdictDeny) },
			wantErr: ErrAuthorizationDenied,
		},
		{
			name: "decision_floor_deny",
			mutate: func(s *GateRequestSpec[security.CapFileMut]) {
				s.DecisionFloor = algebraic.Some[security.GuardrailDecision](security.NewDecisionDenyWithCode("caller_deny", "blocked"))
			},
			wantErr: ErrAuthorizationDenied,
		},
		{
			name:    "higher_risk",
			mutate:  func(s *GateRequestSpec[security.CapFileMut]) { s.Risk = security.RiskDangerous },
			wantErr: ErrScopeEscalated,
		},
		{
			name:    "extra_protected_path",
			mutate:  func(s *GateRequestSpec[security.CapFileMut]) { s.Paths = []string{"/etc/shadow"} },
			wantErr: ErrScopeEscalated,
		},
		{
			name:    "extra_recursive_path",
			mutate:  func(s *GateRequestSpec[security.CapFileMut]) { s.RecursivePaths = []string{"/etc"} },
			wantErr: ErrScopeEscalated,
		},
	}

	for _, tc := range cases {
		ch := issueTwoStepChallenge(t, g, baseReq)
		spec := GateRequestSpec[security.CapFileMut]{
			OperationID: algebraic.Some(ch.Envelope().OperationID()),
			Binding:     bind,
			Risk:        security.RiskModerate,
			Approval:    algebraic.Some(mustApprovalSub(t, ch.Envelope(), ch.EnvelopeDigest(), security.VerdictAllow)),
		}
		tc.mutate(&spec)
		err := WithAuthorized(context.Background(), g, mustNewRequest(t, spec), func(context.Context, Authorized[security.CapFileMut]) error {
			t.Fatalf("%s 不得绕过护栏执行 run", tc.name)
			return nil
		})
		requireErrIs(t, err, tc.wantErr, tc.name)
	}
	assertNoOrphanAudit(t, g, sink)
}

// TestInteractiveApprovalRound2ReprobeAndAntiOracle 验证交互式审批在用户批准后的 Round-2 远端复检与 INV-E5 反预言机顺序：
// 1. 一致放行（2 次探测）并记录 DecisionKindNeedApproval；2. Protected-A -> Protected-B 重定向作废；
// 3. 探针失败作废；4. 错摘要/拒批/过期均在复检前阻断（0 次额外探测）。
func TestInteractiveApprovalRound2ReprobeAndAntiOracle(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(231)
	sink := newFakeAuditSink(t, "gate-inter-r2-01")
	ruleA, err := pathalg.NewProtectedRule("/etc/**", "zone-etc")
	requireNoErr(t, err, "NewProtectedRule(A)")
	ruleB, err := pathalg.NewProtectedRule("/root/**", "zone-root")
	requireNoErr(t, err, "NewProtectedRule(B)")
	pol := mustClassifiedPolicy(t, security.RiskDangerous, NoElicitFallbackDeny, ruleA, ruleB)

	lexBind := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/tmp/link")
	canBindA := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/etc/passwd")
	canBindB := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/root/.ssh/id_rsa")
	probeErr := errors.New("sftp lstat broken")

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

	// 1. 批准且 Round-2 复检未漂移：共探测 2 次，放行且记录 DecisionKindNeedApproval。
	mode = "approve"
	probes := 0
	beforeLen := len(sink.snapshotEntries())
	reqOK := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		Binding: lexBind, Risk: security.RiskSafe,
		Canonicalize: func(context.Context) (CanonicalizeResult, error) {
			probes++
			return CanonicalizeResult{Binding: canBindA, Paths: []string{"/etc/passwd"}}, nil
		},
	})
	ran := false
	requireNoErr(t, WithAuthorized(context.Background(), g, reqOK, func(context.Context, Authorized[security.CapFileRead]) error {
		ran = true
		return nil
	}), "交互式 Round-2 一致放行")
	requireTrue(t, ran && probes == 2, "期望执行 run 且恰好完成 2 次探测（预检 + 批准后复检）")
	assertLastPairAuditDecision(t, sink, beforeLen, security.DecisionKindNeedApproval)

	// 2. 批准期间发生 Protected-A -> Protected-B 软链重定向：第 2 次探测必须拦截并作废。
	probes = 0
	reqRedirect := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		Binding: lexBind, Risk: security.RiskSafe,
		Canonicalize: func(context.Context) (CanonicalizeResult, error) {
			probes++
			if probes == 1 {
				return CanonicalizeResult{Binding: canBindA, Paths: []string{"/etc/passwd"}}, nil
			}
			return CanonicalizeResult{Binding: canBindB, Paths: []string{"/root/.ssh/id_rsa"}}, nil
		},
	})
	redErr := WithAuthorized(context.Background(), g, reqRedirect, noopRun[security.CapFileRead])
	requireErrIs(t, redErr, ErrScopeEscalated, "交互式 Round-2 重定向 ErrScopeEscalated")
	requireErrIs(t, redErr, ErrApprovalInvalidated, "交互式 Round-2 重定向 ErrApprovalInvalidated")
	requireTrue(t, probes == 2, "重定向场景期望精确 2 次探测")

	// 3. 批准后 Round-2 复检探针失败：作废令牌并保留根因。
	probes = 0
	reqProbeFail := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		Binding: lexBind, Risk: security.RiskSafe,
		Canonicalize: func(context.Context) (CanonicalizeResult, error) {
			probes++
			if probes == 1 {
				return CanonicalizeResult{Binding: canBindA, Paths: []string{"/etc/passwd"}}, nil
			}
			return CanonicalizeResult{}, probeErr
		},
	})
	pfErr := WithAuthorized(context.Background(), g, reqProbeFail, noopRun[security.CapFileRead])
	requireErrIs(t, pfErr, ErrApprovalInvalidated, "交互式 Round-2 探针失败 ErrApprovalInvalidated")
	requireErrIs(t, pfErr, probeErr, "交互式 Round-2 探针失败根因")
	requireTrue(t, probes == 2, "探针失败场景期望精确 2 次探测")

	// 4. INV-E5 反预言机：错摘要、用户拒绝、过期均不得触发第 2 次探测（probes 严格为 1）。
	verifyInteractiveAntiOracle(t, g, reqOK, &mode, &probes)
	assertNoOrphanAudit(t, g, sink)
}

func verifyInteractiveAntiOracle(t *testing.T, g *Gate, reqOK GateRequest[security.CapFileRead], mode *string, probes *int) {
	t.Helper()
	for _, tc := range []struct {
		name, m string
		want    error
	}{
		{"wrong_digest", "wrong_digest", ErrApprovalMismatch},
		{"reject", "reject", ErrApprovalRejected},
		{"expire", "expire", ErrApprovalExpired},
	} {
		*mode = tc.m
		*probes = 0
		err := WithAuthorized(context.Background(), g, reqOK, noopRun[security.CapFileRead])
		requireErrIs(t, err, tc.want, "交互式反预言机 "+tc.name)
		requireTrue(t, *probes == 1, "INV-E5 违规："+tc.name+" 不得触发批准后额外 Round-2 探测")
	}
}

// TestLongOutcomeErrorCodeClampedWithoutHaltingStrictAgent 验证 80 字节合法领域 OutcomeUnknown.Code()
// 与 OutcomeNotStarted.Code() 被安全钳制为 <=64 字节 ASCII 审计码，完整落盘终态且绝不误触发 StrictAgentProfile 熔断。
func TestLongOutcomeErrorCodeClampedWithoutHaltingStrictAgent(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(241)
	sink := newFakeAuditSink(t, "gate-codeclamp-01")
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskDangerous, NoElicitFallbackDeny),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})
	req := mustNewRequest(t, GateRequestSpec[security.CapExecute]{
		Binding: mustBinding(t, security.CapabilityExecute, "terminal_exec", "run", "prod-01"),
		Risk:    security.RiskModerate,
	})
	longCode := strings.Repeat("transport_eof_", 6) // 84 字节（合法域码 <=128，但超过审计 64 字节上限）
	unk, err := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, longCode, "transport dropped after write")
	requireNoErr(t, err, "NewOutcomeUnknown(84B)")
	ns, err := execution.NewOutcomeNotStarted(execution.StartPhaseDial, longCode, "dial refused")
	requireNoErr(t, err, "NewOutcomeNotStarted(84B)")

	requireNoErr(t, WithAuthorized(context.Background(), g, req, func(_ context.Context, auth Authorized[security.CapExecute]) error {
		return auth.ReportOutcome(unk)
	}), "长 Code OutcomeUnknown")
	requireNoErr(t, WithAuthorized(context.Background(), g, req, func(_ context.Context, auth Authorized[security.CapExecute]) error {
		return auth.ReportOutcome(ns)
	}), "长 Code OutcomeNotStarted")

	requireTrue(t, !g.IsHalted() && g.Stats().PostWriteErrors == 0, "合法长 Outcome.Code 绝不得误触发 Halted 熔断")
	assertNoOrphanAudit(t, g, sink)
	entries := sink.snapshotEntries()
	requireTrue(t, len(entries) == 4, "期望 2 组完整配对审计条目")
	requireTrue(t, entries[0].Decision() == security.DecisionKindAllow && entries[1].Decision() == security.DecisionKindAllow, "直通操作必须记录 DecisionKindAllow")
	requireTrue(t, entries[1].Outcome() == ports.AuditOutcomeUnknown && entries[1].ErrorCode() == longCode[:64], "OutcomeUnknown 必须完整保留且错误码钳制为 64 字节")
	requireTrue(t, entries[3].Outcome() == ports.AuditOutcomeFailed && entries[3].ErrorCode() == longCode[:64], "OutcomeNotStarted 错误码必须钳制为 64 字节")
}

// TestReplayHistoryStrictlyBoundedInSingleTTLAndExpiredChurn 验证 MaxReplayHistory 在单 TTL 突发消费与
// 大量过期挂起挑战周转下均严格有界（consumedDig/consumedNonce/活跃 FIFO 长度恒 <= MaxReplayHistory）。
func TestReplayHistoryStrictlyBoundedInSingleTTLAndExpiredChurn(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(251)
	sink := newFakeAuditSink(t, "gate-replay-cap-01")
	pol, err := NewGuardrailPolicy(GuardrailPolicySpec{
		ApprovalThreshold:    security.RiskModerate,
		NoElicitFallback:     NoElicitFallbackChallenge,
		MaxPendingChallenges: 2,
		MaxReplayHistory:     3,
	})
	requireNoErr(t, err, "NewGuardrailPolicy")
	g := mustGate(t, GateConfig{
		Profile: PolicyProfileStrictAgent, Policy: pol, AuditSink: sink, Clock: clk, Entropy: ent,
	})
	bind := mustBinding(t, security.CapabilityExecute, "terminal_exec", "run", "web-01")
	req := mustNewRequest(t, GateRequestSpec[security.CapExecute]{Binding: bind, Risk: security.RiskModerate})

	// 1. 单 TTL 窗口内连续签发并消费 10 次（不推进时钟）：验证两表与活跃队列严格 <= 3。
	var consumed []*ApprovalChallengeError
	for range 10 {
		ch := issueTwoStepChallenge(t, g, req)
		subReq := mustSubmissionReq[security.CapExecute](t, ch.Envelope(), ch.EnvelopeDigest(), bind, security.VerdictAllow)
		requireNoErr(t, WithAuthorized(context.Background(), g, subReq, noopRun[security.CapExecute]), "单 TTL 消费")
		consumed = append(consumed, ch)
		assertReplayTableBounded(t, g, 3)
	}
	// 最近 3 条保留在防重放表中（返回 ErrApprovalReplayed）；最早被驱逐的仍因不在 g.pending 白名单中而失败关闭（ErrApprovalMismatch）。
	recentReq := mustSubmissionReq[security.CapExecute](t, consumed[9].Envelope(), consumed[9].EnvelopeDigest(), bind, security.VerdictAllow)
	requireErrIs(t, WithAuthorized(context.Background(), g, recentReq, noopRun[security.CapExecute]), ErrApprovalReplayed, "近期消费信封仍返回 Replayed")
	evictedReq := mustSubmissionReq[security.CapExecute](t, consumed[0].Envelope(), consumed[0].EnvelopeDigest(), bind, security.VerdictAllow)
	requireErrIs(t, WithAuthorized(context.Background(), g, evictedReq, noopRun[security.CapExecute]), ErrApprovalMismatch, "已驱逐旧信封仍失败关闭")

	// 2. 过期挂起挑战高频周转（6 轮 × 2 挂起挑战 = 12 个过期条目）：pruneExpiredPendingLocked 须走有界记录路径。
	for range 6 {
		_ = issueTwoStepChallenge(t, g, req)
		_ = issueTwoStepChallenge(t, g, req)
		clk.Advance(defaultApprovalTTL + time.Second)
		_ = issueTwoStepChallenge(t, g, req)
		assertReplayTableBounded(t, g, 3)
		clk.Advance(defaultApprovalTTL + time.Second)
	}
}

func assertReplayTableBounded(t *testing.T, g *Gate, maxCap int) {
	t.Helper()
	g.mu.Lock()
	digLen, nonceLen, orderActive := len(g.consumedDig), len(g.consumedNonce), len(g.consumedOrder)-g.consumedHead
	g.mu.Unlock()
	if digLen > maxCap || nonceLen > maxCap || orderActive > maxCap {
		t.Fatalf("防重放表超出 MaxReplayHistory=%d 上限: dig=%d nonce=%d orderActive=%d", maxCap, digLen, nonceLen, orderActive)
	}
}

// TestOperationStreamIDInheritanceAndMismatchValidation 验证 NewGateRequest 对 OperationStream 的自动 ID 继承
// 以及显式 TraceID/OperationID/Approval.Envelope.OperationID 冲突时的严格失败关闭校验。
func TestOperationStreamIDInheritanceAndMismatchValidation(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(161)
	sink := newFakeAuditSink(t, "gate-stream-id-01")
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskModerate, NoElicitFallbackChallenge, "/etc/**"),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})

	tid1, err := security.NewTraceIDFrom(ent)
	requireNoErr(t, err, "NewTraceIDFrom(1)")
	tid2, err := security.NewTraceIDFrom(ent)
	requireNoErr(t, err, "NewTraceIDFrom(2)")
	op1, err := security.NewOperationIDFrom(ent)
	requireNoErr(t, err, "NewOperationIDFrom(1)")
	op2, err := security.NewOperationIDFrom(ent)
	requireNoErr(t, err, "NewOperationIDFrom(2)")
	stream, err := events.NewOperationStream(events.OperationStreamConfig{
		TraceID: tid1, OperationID: op1, OperationBuffer: 16,
	})
	requireNoErr(t, err, "NewOperationStream")
	defer stream.Close()

	bind := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/etc/shadow")
	// 1. 仅传入 OperationStream（不显式设置 TraceID/OperationID）：自动继承并成功向流发射挑战与转移事件。
	reqAuto := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{
		Binding: bind, Risk: security.RiskModerate, OperationStream: stream,
	})
	ch := issueTwoStepChallenge(t, g, reqAuto)
	requireTrue(t, ch.Envelope().OperationID().Equal(op1), "自动继承 OperationStream.OperationID 失败")
	stream.Close()
	sawChallenge, sawTransition := false, false
	for ev, sErr := range stream.All(context.Background()) {
		requireNoErr(t, sErr, "stream.All")
		if _, ok := ev.(*events.ApprovalChallengeEvent); ok {
			sawChallenge = true
		}
		if _, ok := ev.(*events.FSMTransitionEvent); ok {
			sawTransition = true
		}
	}
	requireTrue(t, sawChallenge && sawTransition, "期望 OperationStream 自动对齐并收到挑战与转移事件")

	// 2. 冲突校验：显式 TraceID、OperationID 或审批信封 OperationID 与 OperationStream 不一致均须拒绝。
	stream2, err := events.NewOperationStream(events.OperationStreamConfig{
		TraceID: tid1, OperationID: op1, OperationBuffer: 8,
	})
	requireNoErr(t, err, "NewOperationStream(2)")
	defer stream2.Close()

	_, err = NewGateRequest(GateRequestSpec[security.CapFileRead]{
		TraceID: algebraic.Some(tid2), Binding: bind, Risk: security.RiskModerate, OperationStream: stream2,
	})
	requireErrIs(t, err, ErrInvalidRequest, "TraceID 与 OperationStream 冲突")

	_, err = NewGateRequest(GateRequestSpec[security.CapFileRead]{
		OperationID: algebraic.Some(op2), Binding: bind, Risk: security.RiskModerate, OperationStream: stream2,
	})
	requireErrIs(t, err, ErrInvalidRequest, "OperationID 与 OperationStream 冲突")

	forged := buildForgedEnvelope(t, ent, clk.Now(), bind)
	forgedDig, err := forged.Digest()
	requireNoErr(t, err, "forged.Digest")
	_, err = NewGateRequest(GateRequestSpec[security.CapFileRead]{
		Binding: bind, Risk: security.RiskModerate, OperationStream: stream2,
		Approval: algebraic.Some(mustApprovalSub(t, forged, forgedDig, security.VerdictAllow)),
	})
	requireErrIs(t, err, ErrInvalidRequest, "审批信封 OperationID 与 OperationStream 冲突 ErrInvalidRequest")
	requireErrIs(t, err, ErrApprovalMismatch, "审批信封 OperationID 与 OperationStream 冲突 ErrApprovalMismatch")
}

// TestRecordDeniedAuditFailureExposureAndHaltClearsPending 验证：
// 1. recordDeniedAudit 遇时钟/熵异常时绝不静默丢弃拒绝审计错误（必须 join ErrAuditPreWriteFailed）；
// 2. triggerHalt 进入不可逆熔断态时清理残留 g.pending，使 Stats().PendingChallenges 归零。
func TestRecordDeniedAuditFailureExposureAndHaltClearsPending(t *testing.T) {
	clk, ent := newFakeClock(baseTestTime()), newFakeEntropy(171)
	sink := newFakeAuditSink(t, "gate-denied-halt-01")
	g := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskModerate, NoElicitFallbackChallenge, "/etc/**"),
		AuditSink: sink, Clock: clk, Entropy: ent,
	})
	bind := mustBinding(t, security.CapabilityFileRead, "file", "read", "web-01", "/etc/shadow")
	req := mustNewRequest(t, GateRequestSpec[security.CapFileRead]{Binding: bind, Risk: security.RiskModerate})

	// 1. 挂起一条待审批挑战后执行 Halt：PendingChallenges 必须从 1 归零。
	_ = issueTwoStepChallenge(t, g, req)
	requireTrue(t, g.Stats().PendingChallenges == 1, "签发挑战后 PendingChallenges 应为 1")
	g.Halt("manual_halt_test", errSimulatedENOSPC)
	requireTrue(t, g.IsHalted() && g.Stats().PendingChallenges == 0, "熔断后必须清空 g.pending 使 PendingChallenges 归零")

	// 2. 拒绝路径中若时钟返回零值导致无法构造 Denied 审计记录，必须同时暴露原始拒绝错误与 ErrAuditPreWriteFailed。
	clk2, ent2 := newFakeClock(baseTestTime()), newFakeEntropy(172)
	sink2 := newFakeAuditSink(t, "gate-denied-clock-02")
	g2 := mustGate(t, GateConfig{
		Profile:   PolicyProfileStrictAgent,
		Policy:    mustPolicy(t, security.RiskDangerous, NoElicitFallbackDeny),
		AuditSink: sink2, Clock: clk2, Entropy: ent2,
	})
	denyReq := mustNewRequest(t, GateRequestSpec[security.CapInspect]{
		Binding: mustBinding(t, security.CapabilityInspect, "nodes", "list", "web-01"),
		Risk:    security.RiskSafe,
		Verdict: algebraic.Some(security.VerdictDeny),
	})
	clk2.Set(time.Time{})
	err := WithAuthorized(context.Background(), g2, denyReq, noopRun[security.CapInspect])
	requireErrIs(t, err, ErrAuthorizationDenied, "保留原始拒绝错误")
	requireErrIs(t, err, ErrAuditPreWriteFailed, "拒绝审计构造失败必须暴露 ErrAuditPreWriteFailed")
}

func assertLastPairAuditDecision(t *testing.T, sink *fakeAuditSink, beforeLen int, want security.DecisionKind) {
	t.Helper()
	entries := sink.snapshotEntries()
	if len(entries) != beforeLen+2 {
		t.Fatalf("期望新增 2 条配对审计记录，before=%d after=%d", beforeLen, len(entries))
	}
	authEv, finEv := entries[beforeLen], entries[beforeLen+1]
	if authEv.Phase() != ports.AuditPhaseAuthorized || finEv.Phase() != ports.AuditPhaseFinalized {
		t.Fatalf("审计阶段不匹配: auth=%s fin=%s", authEv.Phase(), finEv.Phase())
	}
	if authEv.Decision() != want || finEv.Decision() != want {
		t.Fatalf("审计决策来源不匹配: auth=%s fin=%s want=%s", authEv.Decision(), finEv.Decision(), want)
	}
}
