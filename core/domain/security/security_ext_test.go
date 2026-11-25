package security_test

import (
	"bytes"
	"encoding"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// TestExternalInterfaceContracts 在外部包编译期锁定所有导出值对象的文本/JSON 编解码与密封接口契约。
func TestExternalInterfaceContracts(t *testing.T) {
	var (
		v  security.Verdict
		r  security.RiskLevel
		ck security.CapabilityKind
		dk security.DecisionKind
		er security.EscalationReason
		id security.OperationID
		ti security.TraceID
		dg security.Digest
		dd security.DecisionDeny
		na security.DecisionNeedApproval
		da security.DecisionAllow
		or security.NodeOverrideRule
		os security.NodeOverrides
		ob security.OperationBinding
		ae security.ApprovalEnvelope
		sp security.ScopedPath
		ss security.ScopeSnapshot
		sr security.ScopeEscalationResult
	)
	var (
		_ encoding.TextAppender      = v
		_ encoding.TextMarshaler     = v
		_ encoding.TextUnmarshaler   = &v
		_ encoding.TextAppender      = r
		_ encoding.TextMarshaler     = r
		_ encoding.TextUnmarshaler   = &r
		_ encoding.TextAppender      = ck
		_ encoding.TextMarshaler     = ck
		_ encoding.TextUnmarshaler   = &ck
		_ encoding.TextAppender      = dk
		_ encoding.TextMarshaler     = dk
		_ encoding.TextUnmarshaler   = &dk
		_ encoding.TextAppender      = er
		_ encoding.TextMarshaler     = er
		_ encoding.TextUnmarshaler   = &er
		_ encoding.TextAppender      = id
		_ encoding.TextMarshaler     = id
		_ encoding.TextUnmarshaler   = &id
		_ encoding.TextAppender      = ti
		_ encoding.TextMarshaler     = ti
		_ encoding.TextUnmarshaler   = &ti
		_ encoding.TextAppender      = dg
		_ encoding.TextMarshaler     = dg
		_ encoding.TextUnmarshaler   = &dg
		_ security.Capability        = security.CapInspect{}
		_ security.Capability        = security.CapExecute{}
		_ security.Capability        = security.CapFileRead{}
		_ security.Capability        = security.CapFileMut{}
		_ security.Capability        = security.CapTransfer{}
		_ security.Capability        = security.CapTunnel{}
		_ security.Capability        = security.CapMutate{}
		_ security.GuardrailDecision = &dd
		_ security.GuardrailDecision = &na
		_ security.GuardrailDecision = &da
		_ jsonv2.MarshalerTo         = dd
		_ jsonv2.MarshalerTo         = na
		_ jsonv2.MarshalerTo         = da
		_ jsonv2.MarshalerTo         = or
		_ jsonv2.UnmarshalerFrom     = &or
		_ jsonv2.MarshalerTo         = os
		_ jsonv2.UnmarshalerFrom     = &os
		_ jsonv2.MarshalerTo         = ob
		_ jsonv2.UnmarshalerFrom     = &ob
		_ jsonv2.MarshalerTo         = ae
		_ jsonv2.UnmarshalerFrom     = &ae
		_ jsonv2.MarshalerTo         = sp
		_ jsonv2.UnmarshalerFrom     = &sp
		_ jsonv2.MarshalerTo         = ss
		_ jsonv2.UnmarshalerFrom     = &ss
		_ jsonv2.MarshalerTo         = sr
		_ jsonv2.UnmarshalerFrom     = &sr
	)
}

// TestExternalSecurityContract 验证外部包经导出构造器与封闭和类型使用 core/domain/security 全量契约。
func TestExternalSecurityContract(t *testing.T) {
	if security.CapabilityKindOf[security.CapTransfer]() != security.CapabilityTransfer {
		t.Fatal("外部包泛型 CapabilityKindOf 映射错误")
	}
	decision := assertExternalOverrideAndDecision(t)
	assertExternalDecisionStreamCodec(t, decision)
	ep := mustExternalEndpoint(t, "192.0.2.20:22")
	assertExternalEnvelopeRoundTrip(t, ep, decision)
	assertExternalProtectedRedirect(t, ep)
}

func assertExternalOverrideAndDecision(t *testing.T) security.GuardrailDecision {
	t.Helper()
	overrides, err := security.NewNodeOverridesFromMap(map[string]security.RiskLevel{
		"prod-*": security.RiskSafe,
		"*":      security.RiskModerate,
	})
	if err != nil {
		t.Fatalf("NewNodeOverridesFromMap 失败: %v", err)
	}
	decision := overrides.EvaluateNode(security.RiskDangerous, security.RiskSafe, "prod-01")
	switch v := decision.(type) {
	case *security.DecisionDeny:
		t.Fatalf("非预期拒绝: %s", v.Reason())
	case *security.DecisionNeedApproval:
		if v.Risk() != security.RiskSafe {
			t.Fatalf("期望审批风险 Safe，实际=%v", v.Risk())
		}
	case *security.DecisionAllow:
		t.Fatalf("prod-01 应要求审批而非直接放行: %s", v.Reason())
	default:
		t.Fatal("未知 GuardrailDecision 变体")
	}
	batch := overrides.EvaluateBatch(security.RiskDangerous, security.RiskSafe, "dev-01", "prod-01")
	if !security.EqualDecision(batch, decision) {
		t.Fatalf("EvaluateBatch 应折叠出与 prod-01 一致的 NeedApproval: got=%#v", batch)
	}
	return decision
}

func assertExternalDecisionStreamCodec(t *testing.T, decision security.GuardrailDecision) {
	t.Helper()
	var buf bytes.Buffer
	enc := jsontext.NewEncoder(&buf)
	if err := security.MarshalDecisionTo(enc, decision); err != nil {
		t.Fatalf("MarshalDecisionTo 失败: %v", err)
	}
	dec := jsontext.NewDecoder(&buf)
	decoded, err := security.UnmarshalDecisionFrom(dec)
	if err != nil || !security.EqualDecision(decoded, decision) {
		t.Fatalf("UnmarshalDecisionFrom 往返失败: err=%v decoded=%#v", err, decoded)
	}
}

func mustExternalEndpoint(t *testing.T, raw string) netaddr.Endpoint {
	t.Helper()
	ep, err := netaddr.ParseEndpoint(raw)
	if err != nil {
		t.Fatalf("ParseEndpoint(%q) 失败: %v", raw, err)
	}
	return ep
}

func assertExternalEnvelopeRoundTrip(t *testing.T, ep netaddr.Endpoint, decision security.GuardrailDecision) {
	t.Helper()
	binding, err := security.NewOperationBinding(security.OperationBindingSpec{
		Capability: security.CapabilityKindOf[security.CapFileMut](), Tool: "file", Action: "patch",
		NodeID: "prod-01", Endpoint: algebraic.Some(ep), CanonicalPaths: []string{"/etc/hosts"},
	})
	if err != nil {
		t.Fatalf("NewOperationBinding 失败: %v", err)
	}
	opID, err := security.NewOperationIDFrom(bytes.NewReader([]byte("0123456789abcdef")))
	if err != nil {
		t.Fatalf("NewOperationIDFrom 失败: %v", err)
	}
	nonce, err := security.NewApprovalNonceFrom(bytes.NewReader([]byte("fedcba9876543210")))
	if err != nil {
		t.Fatalf("NewApprovalNonceFrom 失败: %v", err)
	}
	issued := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	// 风险与审批决策不一致（Dangerous vs Safe）必须被构造器拒绝
	if _, err := security.NewApprovalEnvelope(security.ApprovalEnvelopeSpec{
		OperationID: opID, Binding: binding, Risk: security.RiskDangerous, Decision: decision,
		ScopeSummary: "patch /etc/hosts on prod-01", IssuedAt: issued,
		TTL: algebraic.FromStdDuration(time.Minute), Nonce: nonce,
	}); !errors.Is(err, security.ErrInvalidApprovalEnvelope) {
		t.Fatalf("信封风险与审批决策风险冲突期望 ErrInvalidApprovalEnvelope，实际=%v", err)
	}
	env, err := security.NewApprovalEnvelope(security.ApprovalEnvelopeSpec{
		OperationID: opID, Binding: binding, Risk: security.RiskSafe, Decision: decision,
		ScopeSummary: "patch /etc/hosts on prod-01", IssuedAt: issued,
		TTL: algebraic.FromStdDuration(time.Minute), Nonce: nonce,
	})
	if err != nil {
		t.Fatalf("NewApprovalEnvelope 失败: %v", err)
	}
	raw, err := jsonv2.Marshal(env, jsonv2.Deterministic(true))
	var roundTripped security.ApprovalEnvelope
	if err != nil || jsonv2.Unmarshal(raw, &roundTripped) != nil || !roundTripped.Equal(env) {
		t.Fatalf("外部包 ApprovalEnvelope JSON 往返失败: err=%v", err)
	}
}

func assertExternalProtectedRedirect(t *testing.T, ep netaddr.Endpoint) {
	t.Helper()
	pA, err := security.NewScopedPath("/etc/app/link", false, "/etc/**")
	if err != nil {
		t.Fatalf("NewScopedPath(pA) 失败: %v", err)
	}
	pB, err := security.NewScopedPath("/root/.ssh/authorized_keys", false, "/root/**")
	if err != nil {
		t.Fatalf("NewScopedPath(pB) 失败: %v", err)
	}
	naDanger, err := security.NewDecisionNeedApproval(security.RiskDangerous, "need approval")
	if err != nil {
		t.Fatalf("NewDecisionNeedApproval 失败: %v", err)
	}
	lexSnap, err := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityFileMut, TargetNode: "prod-01", Endpoint: algebraic.Some(ep),
		Verdict: security.VerdictDeny, Risk: security.RiskDangerous, Decision: naDanger, Paths: []security.ScopedPath{pA},
	})
	if err != nil {
		t.Fatalf("NewScopeSnapshot(lex) 失败: %v", err)
	}
	canSnap, err := security.NewScopeSnapshot(security.ScopeSnapshotSpec{
		Capability: security.CapabilityFileMut, TargetNode: "prod-01", Endpoint: algebraic.Some(ep),
		Verdict: security.VerdictDeny, Risk: security.RiskDangerous, Decision: naDanger, Paths: []security.ScopedPath{pB},
	})
	if err != nil {
		t.Fatalf("NewScopeSnapshot(can) 失败: %v", err)
	}
	if !security.CanonicalScopeEscalated(lexSnap, canSnap) {
		t.Fatal("外部包验证 Protected-A -> Protected-B 必须判定为升级")
	}
	assertExternalTraceAndScopeJSONRoundTrip(t, pA, lexSnap, security.InspectScopeEscalation(lexSnap, canSnap), security.InspectScopeEscalation(lexSnap, lexSnap))
}

func assertExternalTraceAndScopeJSONRoundTrip(t *testing.T, sp security.ScopedPath, snap security.ScopeSnapshot, escRes, okRes security.ScopeEscalationResult) {
	t.Helper()
	tid, err := security.NewTraceIDFrom(bytes.NewReader([]byte("0123456789abcdef")))
	if err != nil || !tid.IsValid() || tid.IsZero() {
		t.Fatalf("NewTraceIDFrom 失败: (%v, %v)", tid, err)
	}
	var zTID security.TraceID
	if zTID.Equal(zTID) {
		t.Fatal("零值 TraceID.Equal 必须失败关闭")
	}
	rawTID, err := jsonv2.Marshal(tid, jsonv2.Deterministic(true))
	var decTID security.TraceID
	if err != nil || jsonv2.Unmarshal(rawTID, &decTID) != nil || !decTID.Equal(tid) {
		t.Fatalf("TraceID JSON 往返失败: raw=%s err=%v", rawTID, err)
	}

	rawSP, err := jsonv2.Marshal(sp, jsonv2.Deterministic(true))
	var decSP security.ScopedPath
	if err != nil || jsonv2.Unmarshal(rawSP, &decSP) != nil || !decSP.Equal(sp) {
		t.Fatalf("ScopedPath JSON 往返失败: raw=%s err=%v", rawSP, err)
	}
	rawSnap, err := jsonv2.Marshal(snap, jsonv2.Deterministic(true))
	var decSnap security.ScopeSnapshot
	if err != nil || jsonv2.Unmarshal(rawSnap, &decSnap) != nil || !decSnap.Equal(snap) {
		t.Fatalf("ScopeSnapshot JSON 往返失败: raw=%s err=%v", rawSnap, err)
	}
	for _, res := range []security.ScopeEscalationResult{escRes, okRes} {
		rawRes, err := jsonv2.Marshal(res, jsonv2.Deterministic(true))
		var decRes security.ScopeEscalationResult
		if err != nil || jsonv2.Unmarshal(rawRes, &decRes) != nil || !decRes.Equal(res) {
			t.Fatalf("ScopeEscalationResult JSON 往返失败: raw=%s err=%v", rawRes, err)
		}
	}
	assertExternalScopeJSONRejections(t, rawSnap)
}

func assertExternalScopeJSONRejections(t *testing.T, rawSnap []byte) {
	t.Helper()
	// 严格拒绝 null、缺失必填字段、未知额外字段及语义矛盾结果。
	badScopedPaths := []string{`null`, `{}`, `{"path":"/etc/a","extra":1}`}
	for _, raw := range badScopedPaths {
		var dst security.ScopedPath
		if err := jsonv2.Unmarshal([]byte(raw), &dst); err == nil || dst.IsValid() {
			t.Fatalf("非法 ScopedPath %s 应失败关闭", raw)
		}
	}
	badSnaps := []string{`null`, `{"capability":"file_read"}`, string(rawSnap[:len(rawSnap)-1]) + `,"extra":true}`}
	for _, raw := range badSnaps {
		var dst security.ScopeSnapshot
		if err := jsonv2.Unmarshal([]byte(raw), &dst); err == nil || dst.IsValid() {
			t.Fatalf("非法 ScopeSnapshot %s 应失败关闭", raw)
		}
	}
	badResults := []string{
		`null`, `{}`, `{"escalated":false,"reasons":["protected_redirect"]}`,
		`{"escalated":true}`, `{"escalated":false,"added_protected_paths":["/etc/a"]}`,
		`{"escalated":false,"extra":1}`,
	}
	for _, raw := range badResults {
		var dst security.ScopeEscalationResult
		if err := jsonv2.Unmarshal([]byte(raw), &dst); err == nil || dst.IsValid() {
			t.Fatalf("非法 ScopeEscalationResult %s 应失败关闭", raw)
		}
	}
}
