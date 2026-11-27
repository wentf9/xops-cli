package tools

import (
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	"github.com/wentf9/xops-cli/core/internal/sim"
	"github.com/wentf9/xops-cli/core/ports"
)

func newTestExecRegistry(t *testing.T) *Registry {
	t.Helper()
	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(20261128)
	auditSink, err := sim.NewSimAuditCluster().NewSinkFromEntropy(rng.Fork())
	if err != nil {
		t.Fatalf("NewSinkFromEntropy: %v", err)
	}
	t.Cleanup(func() { _ = auditSink.Close() })
	pol, err := gate.NewGuardrailPolicy(gate.GuardrailPolicySpec{ApprovalThreshold: security.RiskDangerous})
	if err != nil {
		t.Fatalf("NewGuardrailPolicy: %v", err)
	}
	g, err := gate.NewGate(gate.GateConfig{
		Profile: gate.PolicyProfileStrictAgent, Policy: pol, AuditSink: auditSink, Clock: clk, Entropy: rng.Fork(),
	})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	reg, err := NewRegistry(RegistryConfig{Gate: g})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

func assertOutcomeUnknownError(t *testing.T, got error, wantKey domi18n.MessageID, wantSubs []string) {
	t.Helper()
	if !errors.Is(got, protocol.ErrOutcomeUnknown) {
		t.Fatalf("期望 errors.Is(protocol.ErrOutcomeUnknown)，实际=%v", got)
	}
	if id, ok := domi18n.ErrorID(got); !ok || id != wantKey {
		t.Fatalf("ErrorID 期望 %q，实际 ok=%v id=%q", wantKey, ok, id)
	}
	code, payload := protocol.ClassifyError(got)
	if code != protocol.CodeUncertainOutcome || !payload.Uncertain {
		t.Fatalf("ClassifyError 期望 CodeUncertainOutcome & Uncertain=true，实际 code=%d payload=%+v", code, payload)
	}
	for _, sub := range wantSubs {
		if !strings.Contains(got.Error(), sub) || !strings.Contains(payload.Message, sub) {
			t.Fatalf("缺少禁止自动重试语义 %q: err=%q payload=%q", sub, got.Error(), payload.Message)
		}
	}
}

func TestCheckExecOutcomeError_PreservesOutcomeUnknownNoRetrySemantics(t *testing.T) {
	reg := newTestExecRegistry(t)
	unkWithReason, err := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, "disconnect_mid_flight", "peer closed channel")
	if err != nil {
		t.Fatalf("NewOutcomeUnknown(reason): %v", err)
	}
	unkNoReason, err := execution.NewOutcomeUnknown(execution.ExecPhaseRunning, "timeout_after_start", "")
	if err != nil {
		t.Fatalf("NewOutcomeUnknown(no reason): %v", err)
	}
	cases := []struct {
		name     string
		out      execution.ExecutionOutcome
		execErr  error
		wantKey  domi18n.MessageID
		wantSubs []string
	}{
		{
			name:     "with_exec_err",
			out:      unkWithReason,
			execErr:  ports.ErrDialFailed,
			wantKey:  domi18n.KeyMCPProtoOutcomeUnkDetail,
			wantSubs: []string{"remote execution outcome is unknown", "automatic retry is forbidden", "disconnect_mid_flight", ports.ErrDialFailed.Error()},
		},
		{
			name:     "without_exec_err_with_reason",
			out:      unkWithReason,
			execErr:  nil,
			wantKey:  domi18n.KeyMCPProtoOutcomeUnkReason,
			wantSubs: []string{"remote execution outcome is unknown", "automatic retry is forbidden", "disconnect_mid_flight", "peer closed channel"},
		},
		{
			name:     "without_exec_err_no_reason",
			out:      unkNoReason,
			execErr:  nil,
			wantKey:  domi18n.KeyMCPProtoOutcomeUnkDetail,
			wantSubs: []string{"remote execution outcome is unknown", "automatic retry is forbidden", "timeout_after_start"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertOutcomeUnknownError(t, reg.checkExecOutcomeError(tc.out, tc.execErr), tc.wantKey, tc.wantSubs)
		})
	}
}
