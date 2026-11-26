package tools_test

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"testing"

	"go.uber.org/goleak"

	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/protocol"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime/tools"
	"github.com/wentf9/xops-cli/core/internal/sim"
)

func TestRegistry_FailClosedGuardsAndTransferBindingZero(t *testing.T) {
	defer goleak.VerifyNone(t)

	assertZeroGuards(t)

	clk := sim.NewSimClock(sim.DefaultBaseTime())
	rng := sim.NewSeededRand(20260502)
	auditClust := sim.NewSimAuditCluster()
	auditSink, err := auditClust.NewSinkFromEntropy(rng.Fork())
	if err != nil {
		t.Fatalf("NewSinkFromEntropy: %v", err)
	}
	defer func() { _ = auditSink.Close() }()

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
	reg, err := tools.NewRegistry(tools.RegistryConfig{Gate: g})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	if _, code, err := reg.CallTool(context.Background(), "nonexistent", jsontext.Value(`{}`)); !errors.Is(err, protocol.ErrToolNotFound) || code != protocol.CodeMethodNotFound {
		t.Fatalf("未知工具期望 protocol.ErrToolNotFound(-32601)，实际 code=%d err=%v", code, err)
	}
	if _, _, err := reg.CallTool(context.Background(), protocol.ToolNameFile, jsontext.Value(`{"action":"read","target":"h"}`)); !errors.Is(err, tools.ErrServiceUnavailable) {
		t.Fatalf("未注入 TransferService 期望 ErrServiceUnavailable，实际=%v", err)
	}
	var zeroOp security.OperationID
	if _, ok := reg.LookupTransfer(zeroOp); ok {
		t.Fatalf("空绑定表 LookupTransfer 必须返回 false")
	}
	reg.ClearTrackedHandles()

	triggerStrictAgentHalt(t, g, auditClust, auditSink)
	if _, code, err := reg.CallTool(context.Background(), protocol.ToolNameNodes, jsontext.Value(`{"action":"list_nodes"}`)); !errors.Is(err, gate.ErrGateHalted) || code != protocol.CodeGateHalted {
		t.Fatalf("Halted 后 CallTool 期望 gate.ErrGateHalted(-32001)，实际 code=%d err=%v", code, err)
	}
}

func assertZeroGuards(t *testing.T) {
	t.Helper()
	var zeroBinding tools.TransferBinding
	if zeroBinding.IsValid() || zeroBinding.TotalBytes() != 0 || zeroBinding.NodeID() != "" {
		t.Fatalf("零值 TransferBinding 必须无效")
	}
	var zeroReg tools.Registry
	if _, _, err := zeroReg.CallTool(context.Background(), protocol.ToolNameNodes, jsontext.Value(`{}`)); !errors.Is(err, tools.ErrRegistryNotInitialized) {
		t.Fatalf("零值 Registry 期望 ErrRegistryNotInitialized，实际=%v", err)
	}
	if _, err := tools.NewRegistry(tools.RegistryConfig{}); err == nil {
		t.Fatalf("缺少 Gate 的 RegistryConfig 必须失败关闭")
	}
}

func triggerStrictAgentHalt(t *testing.T, g *gate.Gate, clust *sim.SimAuditCluster, sink *sim.SimAuditSink) {
	t.Helper()
	sink.SetBoundaryHook(func(b sim.AuditBoundary, _ security.OperationID) {
		if b == sim.AuditBoundaryAfterAuthorized {
			clust.SetENOSPC(true)
		}
	})
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityKindOf[security.CapInspect](), Tool: "test", Action: "probe", NodeID: "n1",
	})
	if err != nil {
		t.Fatalf("NewOperationBinding: %v", err)
	}
	gReq, err := gate.NewGateRequest[security.CapInspect](gate.GateRequestSpec[security.CapInspect]{
		Binding: binding, Risk: security.RiskSafe, ScopeSummary: "trigger halt",
	})
	if err != nil {
		t.Fatalf("NewGateRequest: %v", err)
	}
	_ = gate.WithAuthorized[security.CapInspect](context.Background(), g, gReq, func(context.Context, gate.Authorized[security.CapInspect]) error {
		return nil
	})
	sink.SetBoundaryHook(nil)
	clust.SetENOSPC(false)
	if !g.IsHalted() {
		t.Fatalf("期望 Gate 进入 Halted")
	}
}
