package gate_test

import (
	"context"
	"encoding"
	"errors"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/foundation/trace"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

// 编译期接口契约断言集中于外置测试文件，遵循全仓工程约定（无生产包级可变 var）。
var (
	_ gate.Authorizer          = (*gate.Gate)(nil)
	_ gate.OutcomeCarrier      = (*gate.OutcomeError)(nil)
	_ encoding.TextAppender    = gate.PolicyProfileInvalid
	_ encoding.TextMarshaler   = gate.PolicyProfileInvalid
	_ encoding.TextUnmarshaler = (*gate.PolicyProfileKind)(nil)
	_ encoding.TextAppender    = gate.NoElicitFallbackDeny
	_ encoding.TextMarshaler   = gate.NoElicitFallbackDeny
	_ encoding.TextUnmarshaler = (*gate.NoElicitFallback)(nil)
)

func extRequireTrue(t *testing.T, cond bool, msg string) {
	t.Helper()
	if !cond {
		t.Fatal(msg)
	}
}

func extRequireErrIs(t *testing.T, err, target error, label string) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s 期望匹配 %v，实际=%v", label, target, err)
	}
}

func extRequireNoErr(t *testing.T, err error, label string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s 返回非预期错误: %v", label, err)
	}
}

func TestZeroAuthorizedFailClosedExternally(t *testing.T) {
	var zeroAuth gate.Authorized[security.CapExecute]
	extRequireTrue(t, !zeroAuth.IsValid() && zeroAuth.IsZero() && zeroAuth.IsRevoked(), "零值 Authorized[C] 必须无效且报告已吊销")
	extRequireErrIs(t, zeroAuth.Validate(), gate.ErrInvalidPermit, "零值 Validate")
	extRequireTrue(t, !zeroAuth.Capability().IsValid() && !zeroAuth.OperationID().IsValid() && !zeroAuth.TraceID().IsValid(), "零值标识访问器须无效")
	extRequireTrue(t, !zeroAuth.Binding().IsValid() && !zeroAuth.Profile().IsValid() && !zeroAuth.Risk().IsValid(), "零值策略访问器须无效")
	unk, err := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, "drop", "lost")
	extRequireNoErr(t, err, "NewOutcomeUnknown")
	extRequireErrIs(t, zeroAuth.ReportOutcome(unk), gate.ErrInvalidPermit, "零值 ReportOutcome")
}

func TestTypedNilGateAndErasedCapabilityFailClosedExternally(t *testing.T) {
	var typedNilGate *gate.Gate
	var zeroGate gate.Gate
	extRequireTrue(t, typedNilGate.IsHalted() && zeroGate.IsHalted(), "typed-nil 与零值 Gate 必须报告 Halted=true")
	extRequireTrue(t, !typedNilGate.Profile().IsValid() && !zeroGate.Profile().IsValid() && typedNilGate.Stats().Halted && zeroGate.Stats().Halted, "typed-nil 与零值 Gate 访问器须失败关闭")
	typedNilGate.Halt("noop", nil)
	zeroGate.Halt("noop", nil)

	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityInspect, Tool: "nodes", Action: "list",
	})
	extRequireNoErr(t, err, "NewOperationBinding")
	req, err := gate.NewGateRequest(gate.GateRequestSpec[security.CapInspect]{Binding: binding, Risk: security.RiskSafe})
	extRequireNoErr(t, err, "NewGateRequest")

	var nilCtx context.Context
	nop := func(context.Context, gate.Authorized[security.CapInspect]) error { return nil }
	extRequireErrIs(t, gate.WithAuthorized(nilCtx, typedNilGate, req, nop), gate.ErrNilContext, "nil ctx")
	extRequireErrIs(t, gate.WithAuthorized(context.Background(), nil, req, nop), gate.ErrNilAuthorizer, "nil Authorizer")
	extRequireErrIs(t, gate.WithAuthorized(context.Background(), typedNilGate, req, nil), gate.ErrNilCallback, "nil callback")
	extRequireErrIs(t, gate.WithAuthorized(context.Background(), typedNilGate, req, nop), gate.ErrGateNotInitialized, "typed-nil Gate")

	_, err = gate.NewGateRequest(gate.GateRequestSpec[security.Capability]{Binding: binding, Risk: security.RiskSafe})
	extRequireErrIs(t, err, gate.ErrCapabilityMismatch, "擦除接口 NewGateRequest")
	var zeroErasedReq gate.GateRequest[security.Capability]
	err = gate.WithAuthorized(context.Background(), typedNilGate, zeroErasedReq, func(context.Context, gate.Authorized[security.Capability]) error { return nil })
	extRequireErrIs(t, err, gate.ErrCapabilityMismatch, "擦除接口 WithAuthorized")

	var nilOutErr *gate.OutcomeError
	var nilChErr *gate.ApprovalChallengeError
	var nilPanicErr *gate.OperationPanicError
	extRequireTrue(t, !nilOutErr.IsValid() && nilOutErr.ExecutionOutcome() == nil && nilOutErr.Unwrap() == nil && nilOutErr.Error() != "", "typed-nil *OutcomeError")
	extRequireTrue(t, !nilChErr.IsValid() && !nilChErr.Escalated() && nilChErr.Unwrap() == nil && nilChErr.Error() != "", "typed-nil *ApprovalChallengeError")
	extRequireTrue(t, !nilPanicErr.IsValid() && nilPanicErr.Unwrap() == nil && nilPanicErr.Error() != "", "typed-nil *OperationPanicError")
}

func TestNewGateZeroEscapeHatchValidation(t *testing.T) {
	pol, err := gate.NewGuardrailPolicyFromPatterns(security.RiskModerate, gate.NoElicitFallbackDeny, gate.StrictDefaultProtectedPatterns())
	extRequireNoErr(t, err, "NewGuardrailPolicyFromPatterns")
	pid, err := ports.ParseProcessInstanceID("ext-proc-01")
	extRequireNoErr(t, err, "ParseProcessInstanceID")

	cases := []struct {
		name string
		cfg  gate.GateConfig
		want error
	}{
		{"missing_profile", gate.GateConfig{Policy: pol}, gate.ErrInvalidProfile},
		{"zero_policy", gate.GateConfig{Profile: gate.PolicyProfileStrictAgent}, gate.ErrInvalidPolicy},
		{"nil_audit", gate.GateConfig{Profile: gate.PolicyProfileStrictAgent, Policy: pol}, gate.ErrInvalidConfig},
		{"bad_proc_id", gate.GateConfig{Profile: gate.PolicyProfileStrictAgent, Policy: pol, AuditSink: extStubAuditSink{}}, gate.ErrInvalidConfig},
		{"nil_clock", gate.GateConfig{Profile: gate.PolicyProfileStrictAgent, Policy: pol, AuditSink: extStubAuditSink{id: pid}}, gate.ErrInvalidConfig},
		{"nil_entropy", gate.GateConfig{Profile: gate.PolicyProfileStrictAgent, Policy: pol, AuditSink: extStubAuditSink{id: pid}, Clock: extStubClock{}}, gate.ErrInvalidConfig},
	}
	for _, tc := range cases {
		_, gotErr := gate.NewGate(tc.cfg)
		extRequireErrIs(t, gotErr, tc.want, tc.name)
	}
}

func TestPolicyEnumsTextCodecRoundTripAndFailClosed(t *testing.T) {
	for _, p := range []gate.PolicyProfileKind{
		gate.PolicyProfileDirectOperator, gate.PolicyProfileStrictOperator, gate.PolicyProfileStrictAgent,
	} {
		raw, err := p.MarshalText()
		extRequireNoErr(t, err, "PolicyProfileKind.MarshalText")
		var dst gate.PolicyProfileKind
		extRequireNoErr(t, dst.UnmarshalText(raw), "PolicyProfileKind.UnmarshalText")
		extRequireTrue(t, dst == p, "PolicyProfileKind 往返不一致")
	}
	var badProf gate.PolicyProfileKind
	_, err := badProf.MarshalText()
	extRequireErrIs(t, err, gate.ErrInvalidProfile, "零值 PolicyProfileKind.MarshalText")
	extRequireErrIs(t, badProf.UnmarshalText([]byte("permissive")), gate.ErrInvalidProfile, "非法配置档")
	extRequireTrue(t, !badProf.IsValid(), "非法解码后必须保持零值")

	for _, fb := range []gate.NoElicitFallback{gate.NoElicitFallbackDeny, gate.NoElicitFallbackChallenge} {
		raw, err := fb.MarshalText()
		extRequireNoErr(t, err, "NoElicitFallback.MarshalText")
		var dst gate.NoElicitFallback
		extRequireNoErr(t, dst.UnmarshalText(raw), "NoElicitFallback.UnmarshalText")
		extRequireTrue(t, dst == fb, "NoElicitFallback 往返不一致")
	}
	var badFB gate.NoElicitFallback
	extRequireErrIs(t, badFB.UnmarshalText([]byte("allow")), gate.ErrInvalidFallback, "拒绝 allow 回退")
	extRequireTrue(t, badFB == gate.NoElicitFallbackDeny, "失败后重置为 Deny")

	_, err = gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: security.RiskModerate,
		ApprovalTTL:       algebraic.Some(algebraic.FromStdDuration(-time.Second)),
	})
	extRequireErrIs(t, err, gate.ErrInvalidPolicy, "负 ApprovalTTL")
}

func TestExternalConsumerAccessorsPassLinearLease(t *testing.T) {
	pid, err := ports.ParseProcessInstanceID("ext-consumer-01")
	extRequireNoErr(t, err, "ParseProcessInstanceID")
	pol, err := gate.NewGuardrailPolicyFromPatterns(security.RiskDangerous, gate.NoElicitFallbackDeny, nil)
	extRequireNoErr(t, err, "NewGuardrailPolicyFromPatterns")
	g, err := gate.NewGate(gate.GateConfig{
		Profile:   gate.PolicyProfileStrictAgent,
		Policy:    pol,
		AuditSink: extStubAuditSink{id: pid, allowOK: true},
		Clock:     extStubClock{},
		Entropy:   &extStubEntropy{seed: 9},
	})
	extRequireNoErr(t, err, "NewGate")
	bind, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityInspect, Tool: "nodes", Action: "list", NodeID: "edge-01",
	})
	extRequireNoErr(t, err, "NewOperationBinding")
	req, err := gate.NewGateRequest(gate.GateRequestSpec[security.CapInspect]{Binding: bind, Risk: security.RiskSafe})
	extRequireNoErr(t, err, "NewGateRequest")

	err = gate.WithAuthorized(context.Background(), g, req, func(opCtx context.Context, auth gate.Authorized[security.CapInspect]) error {
		tid, oid, ok := trace.TraceFromContext(opCtx)
		extRequireTrue(t, ok && auth.TraceID().Equal(tid) && auth.OperationID().Equal(oid), "外置包 TraceID/OperationID 异常")
		extRequireTrue(t, auth.Binding().Equal(bind) && auth.Profile() == gate.PolicyProfileStrictAgent && auth.Risk() == security.RiskSafe, "外置包 Binding/Profile/Risk 异常")
		extRequireTrue(t, auth.Capability() == security.CapabilityInspect && auth.Validate() == nil, "外置包 Capability/Validate 异常")
		return nil
	})
	extRequireNoErr(t, err, "外置包 WithAuthorized")

	// 验证只读扩展 Authorizer.Policy() 与 GuardrailPolicy.MatchScopedPaths 契约及零值失败关闭。
	var az gate.Authorizer = g
	extRequireTrue(t, az.Policy().IsValid() && az.Policy().Digest().Equal(pol.Digest()), "Authorizer.Policy() 应返回一致只读策略")
	protPol, err := gate.NewGuardrailPolicyFromPatterns(security.RiskModerate, gate.NoElicitFallbackDeny, []string{"/etc/**", "/root/**"})
	extRequireNoErr(t, err, "NewGuardrailPolicyFromPatterns(protected)")
	scoped, anyProt, err := protPol.MatchScopedPaths([]string{"/tmp/ok", "/etc/sudoers"}, []string{"/root"})
	extRequireNoErr(t, err, "MatchScopedPaths")
	extRequireTrue(t, anyProt && len(scoped) == 3 && !scoped[0].IsProtected() && scoped[1].IsProtected() && scoped[2].IsProtected() && scoped[2].IsRecursive(), "MatchScopedPaths 受保护分区标记异常")
	var zeroPol gate.GuardrailPolicy
	_, _, zErr := zeroPol.MatchScopedPaths([]string{"/etc/passwd"}, nil)
	extRequireErrIs(t, zErr, gate.ErrInvalidPolicy, "零值策略 MatchScopedPaths 必须失败关闭")
}

type extStubAuditSink struct {
	id      ports.ProcessInstanceID
	allowOK bool
}

func (s extStubAuditSink) ProcessInstanceID() ports.ProcessInstanceID { return s.id }
func (s extStubAuditSink) StageOperation(context.Context, security.OperationID) error {
	if s.allowOK {
		return nil
	}
	return ports.ErrClosed
}
func (s extStubAuditSink) UnstageOperation(context.Context, security.OperationID) error {
	if s.allowOK {
		return nil
	}
	return ports.ErrClosed
}
func (s extStubAuditSink) Record(context.Context, ports.AuditEntry) error {
	if s.allowOK {
		return nil
	}
	return ports.ErrClosed
}
func (extStubAuditSink) Close() error { return nil }

type extStubClock struct{}

func (extStubClock) Now() time.Time                             { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) }
func (extStubClock) Since(time.Time) time.Duration              { return 10 * time.Millisecond }
func (extStubClock) NewTimer(time.Duration) ports.Timer         { return nil }
func (extStubClock) Sleep(context.Context, time.Duration) error { return nil }

type extStubEntropy struct{ seed byte }

func (e *extStubEntropy) Read(p []byte) (int, error) {
	for i := range p {
		e.seed++
		if e.seed == 0 {
			e.seed = 1
		}
		p[i] = e.seed
	}
	return len(p), nil
}
