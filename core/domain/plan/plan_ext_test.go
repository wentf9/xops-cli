package plan_test

import (
	"bytes"
	"encoding"
	jsonv2 "encoding/json/v2"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// TestExternalInterfaceContracts 在外部包编译期锁定 plan 包所有导出类型的编解码与幻影接口契约。
func TestExternalInterfaceContracts(t *testing.T) {
	var (
		hd plan.HopDigest
		pd plan.PlanDigest
		tp plan.TransportPolicySpec
		hs plan.HopSpec
		sp plan.SealedConnectionPlan
		kc plan.HandleKindCode
		hi plan.HandleID
		mh plan.ManagedHandle[plan.KindPTY]
	)
	var (
		_ encoding.TextAppender    = hd
		_ encoding.TextMarshaler   = hd
		_ encoding.TextUnmarshaler = &hd
		_ encoding.TextAppender    = pd
		_ encoding.TextMarshaler   = pd
		_ encoding.TextUnmarshaler = &pd
		_ encoding.TextAppender    = kc
		_ encoding.TextMarshaler   = kc
		_ encoding.TextUnmarshaler = &kc
		_ encoding.TextAppender    = hi
		_ encoding.TextMarshaler   = hi
		_ encoding.TextUnmarshaler = &hi
		_ encoding.TextAppender    = mh
		_ encoding.TextMarshaler   = mh
		_ jsonv2.MarshalerTo       = tp
		_ jsonv2.UnmarshalerFrom   = &tp
		_ jsonv2.MarshalerTo       = hs
		_ jsonv2.UnmarshalerFrom   = &hs
		_ jsonv2.MarshalerTo       = sp
		_ jsonv2.UnmarshalerFrom   = &sp
		_ jsonv2.MarshalerTo       = mh
		_ jsonv2.UnmarshalerFrom   = &mh
		_ plan.HandleKind          = plan.KindPTY{}
		_ plan.HandleKind          = plan.KindTunnel{}
		_ plan.HandleKind          = plan.KindTransfer{}
		_ plan.HandleKind          = plan.KindMux{}
		_ plan.HandleKind          = plan.KindSession{}
	)
}

// TestExternalPlanContract 验证外部包完整构造 Merkle 连接计划与世代句柄的端到端契约。
func TestExternalPlanContract(t *testing.T) {
	ep, _ := netaddr.ParseEndpoint("192.0.2.99:22")
	pol, err := option.ResolveEffectivePolicy(option.OriginManaged, ep, option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer(), option.UnsetOptionLayer())
	if err != nil {
		t.Fatalf("ResolveEffectivePolicy 失败: %v", err)
	}
	user, _ := option.ParseUsername("ops")
	auth, _ := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	hop, err := plan.NewHopSpecFromAuth(0, "prod-01", user, auth, pol)
	if err != nil || !inventory.EqualAuthMethod(hop.Auth(), auth) || hop.Transport().ServerAliveCountMax() != option.DefaultServerAliveCountMax {
		t.Fatalf("NewHopSpecFromAuth 失败: err=%v aliveMax=%d", err, hop.Transport().ServerAliveCountMax())
	}
	sealed, err := plan.SealConnectionPlan(hop)
	if err != nil || !sealed.IsValid() || sealed.Len() != 1 {
		t.Fatalf("SealConnectionPlan 失败: err=%v", err)
	}
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityTunnel, Tool: "tunnel", Action: "start",
		NodeID: "prod-01", PlanDigest: algebraic.Some(sealed.PlanDigest().SecurityDigest()),
	})
	if err != nil {
		t.Fatalf("NewOperationBinding 失败: %v", err)
	}
	hid, err := plan.NewHandleIDFrom(bytes.NewReader([]byte("abcdef0123456789")))
	if err != nil {
		t.Fatalf("NewHandleIDFrom 失败: %v", err)
	}
	handle, err := plan.NewManagedHandle[plan.KindTunnel](hid, 7, sealed.PlanDigest(), binding)
	if err != nil || handle.Kind() != plan.HandleKindTunnel {
		t.Fatalf("NewManagedHandle 失败: err=%v kind=%v", err, handle.Kind())
	}
	raw, err := jsonv2.Marshal(handle, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("Marshal handle 失败: %v", err)
	}
	var dec plan.ManagedHandle[plan.KindTunnel]
	if err := jsonv2.Unmarshal(raw, &dec); err != nil || !dec.Equal(handle) {
		t.Fatalf("外部包 ManagedHandle JSON 往返失败: err=%v", err)
	}
}
