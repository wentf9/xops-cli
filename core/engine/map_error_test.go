package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/sim"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	"github.com/wentf9/xops-cli/core/ports"
)

func TestMapEngineError_GroupedWrapSentinelAlgebra(t *testing.T) {
	// 1. 单源映射：底层哨兵折叠为公开 engine 哨兵，保留双方 errors.Is 与规范英文等价性。
	single := mapEngineError(ports.ErrNotFound)
	if !errors.Is(single, ErrNotFound) || !errors.Is(single, ports.ErrNotFound) {
		t.Fatalf("single 映射丢失 errors.Is 链: %v", single)
	}
	if got := single.Error(); got != ErrNotFound.Error() || domi18n.CanonicalError(single) != got {
		t.Fatalf("single 折叠异常: got=%q want=%q", got, ErrNotFound.Error())
	}

	// 2. 多源归并至同一公开哨兵（ports.ErrNotFound + ucinv.ErrAssetNotFound -> ErrNotFound）。
	multiSame := mapEngineError(errors.Join(ports.ErrNotFound, ucinv.ErrAssetNotFound))
	if !errors.Is(multiSame, ErrNotFound) || !errors.Is(multiSame, ports.ErrNotFound) || !errors.Is(multiSame, ucinv.ErrAssetNotFound) {
		t.Fatalf("multiSame 映射丢失 errors.Is 链: %v", multiSame)
	}
	if got := multiSame.Error(); got != ErrNotFound.Error() || domi18n.CanonicalError(multiSame) != got {
		t.Fatalf("multiSame 同义多源未无损归并: got=%q want=%q", got, ErrNotFound.Error())
	}

	// 3. 跨中间结构化 Wrap：保留业务上下文并精准抑制尾部同义源哨兵。
	wrapped := domi18n.Wrap(ports.ErrNotFound, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "host"))
	mappedWrapped := mapEngineError(wrapped)
	wantWrapped := ErrNotFound.Error() + ": host is invalid"
	if got := mappedWrapped.Error(); got != wantWrapped || domi18n.CanonicalError(mappedWrapped) != got {
		t.Fatalf("cross-Wrap 折叠异常: got=%q want=%q", got, wantWrapped)
	}

	// 4. 多目标映射保首次命中顺序（ErrAuthorizationDenied 在规则表中先于 ErrNotFound）。
	multiTarget := mapEngineError(errors.Join(ports.ErrNotFound, gate.ErrAuthorizationDenied))
	if !errors.Is(multiTarget, ErrAuthorizationDenied) || !errors.Is(multiTarget, ErrNotFound) {
		t.Fatalf("multiTarget 丢失公开哨兵: %v", multiTarget)
	}
	wantMulti := ErrAuthorizationDenied.Error() + ": " + ErrNotFound.Error()
	if got := multiTarget.Error(); got != wantMulti || domi18n.CanonicalError(multiTarget) != got {
		t.Fatalf("multiTarget 顺序或折叠异常: got=%q want=%q", got, wantMulti)
	}

	// 5. 幂等性：二次映射不得重复包裹公开哨兵。
	if again := mapEngineError(mappedWrapped); again.Error() != mappedWrapped.Error() {
		t.Fatalf("mapEngineError 非幂等: first=%q second=%q", mappedWrapped.Error(), again.Error())
	}

	// 6. *gate.ApprovalChallengeError 映射至 ErrApprovalRequired 并完整保留 ExtractApprovalChallenge。
	assertApprovalChallengeMapping(t)
}

func assertApprovalChallengeMapping(t *testing.T) {
	t.Helper()
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(20261128)
	auditSink, err := sim.NewSimAuditCluster().NewSinkFromEntropy(rng.Fork())
	if err != nil {
		t.Fatalf("NewSinkFromEntropy: %v", err)
	}
	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{
		ApprovalThreshold: security.RiskModerate,
		NoElicitFallback:  gate.NoElicitFallbackChallenge,
	})
	if err != nil {
		t.Fatalf("NewGuardrailPolicy: %v", err)
	}
	g, err := gate.NewGate(gate.GateConfig{
		Profile: gate.PolicyProfileStrictAgent, Policy: pol,
		AuditSink: auditSink, Clock: clk, Entropy: rng.Fork(),
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityKindOf[security.CapMutate](),
		Tool:       "file", Action: "write", NodeID: "web-1",
		Parameters: map[string]string{"path": "/tmp/a.txt"},
	})
	if err != nil {
		t.Fatalf("NewOperationBinding: %v", err)
	}
	gReq, err := gate.NewGateRequest[security.CapMutate](gate.GateRequestSpec[security.CapMutate]{
		Binding: binding, Risk: security.RiskModerate, ScopeSummary: "write /tmp/a.txt",
		Approval: algebraic.None[gate.ApprovalSubmission](),
	})
	if err != nil {
		t.Fatalf("NewGateRequest: %v", err)
	}
	chErr := gate.WithAuthorized[security.CapMutate](context.Background(), g, gReq, func(context.Context, gate.Authorized[security.CapMutate]) error {
		return nil
	})
	if chErr == nil {
		t.Fatal("预期触发 *gate.ApprovalChallengeError，实际返回 nil")
	}
	mapped := mapEngineError(chErr)
	if !errors.Is(mapped, ErrApprovalRequired) || !errors.Is(mapped, gate.ErrApprovalRequired) {
		t.Fatalf("ApprovalChallengeError 映射丢失哨兵: %v", mapped)
	}
	if ch, ok := ExtractApprovalChallenge(mapped); !ok || !ch.IsValid() {
		t.Fatalf("ExtractApprovalChallenge 失败: ok=%v ch=%+v", ok, ch)
	}
	if mapped.Error() != domi18n.CanonicalError(mapped) {
		t.Fatalf("ApprovalChallengeError CanonicalError 失配: err=%q canonical=%q", mapped.Error(), domi18n.CanonicalError(mapped))
	}
}
