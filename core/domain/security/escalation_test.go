package security

import (
	"errors"
	"slices"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

func mustScopedPath(t *testing.T, p string, recursive bool, zones ...string) ScopedPath {
	t.Helper()
	sp, err := NewScopedPath(p, recursive, zones...)
	if err != nil {
		t.Fatalf("NewScopedPath(%q) 失败: %v", p, err)
	}
	return sp
}

func mustSnapshot(t *testing.T, spec ScopeSnapshotSpec) ScopeSnapshot {
	t.Helper()
	s, err := NewScopeSnapshot(spec)
	if err != nil {
		t.Fatalf("NewScopeSnapshot 失败: %v", err)
	}
	return s
}

func TestCanonicalScopeEscalatedAdversarialMatrix(t *testing.T) {
	ep22, _ := netaddr.ParseEndpoint("192.0.2.10:22")
	ep2222, _ := netaddr.ParseEndpoint("192.0.2.10:2222")
	naMod, _ := NewDecisionNeedApproval(RiskModerate, "need moderate approval")
	naDanger, _ := NewDecisionNeedApproval(RiskDangerous, "need dangerous approval")

	baseSpec := func(paths ...ScopedPath) ScopeSnapshotSpec {
		return ScopeSnapshotSpec{
			Capability: CapabilityFileRead,
			TargetNode: "web-01",
			Endpoint:   algebraic.Some(ep22),
			Verdict:    VerdictAllow,
			Risk:       RiskSafe,
			Decision:   NewDecisionAllow("allow"),
			Paths:      paths,
		}
	}

	cases := []struct {
		name          string
		lexical       ScopeSnapshot
		canonical     ScopeSnapshot
		wantEscalated bool
		wantReason    EscalationReason
		wantAdded     []string
	}{
		{
			name:          "零值词法快照必须失败关闭",
			lexical:       ScopeSnapshot{},
			canonical:     mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/a", false))),
			wantEscalated: true,
			wantReason:    EscalationInvalidInput,
		},
		{
			name:          "零值规范快照必须失败关闭",
			lexical:       mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/a", false))),
			canonical:     ScopeSnapshot{},
			wantEscalated: true,
			wantReason:    EscalationInvalidInput,
		},
		{
			name:          "能力跨界漂移(file_read->file_mut)",
			lexical:       mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/a", false))),
			canonical:     mustSnapshot(t, ScopeSnapshotSpec{Capability: CapabilityFileMut, TargetNode: "web-01", Endpoint: algebraic.Some(ep22), Verdict: VerdictAllow, Risk: RiskSafe, Decision: NewDecisionAllow("allow"), Paths: []ScopedPath{mustScopedPath(t, "/tmp/a", false)}}),
			wantEscalated: true,
			wantReason:    EscalationCapabilityDrift,
		},
		{
			name:          "目标节点身份漂移",
			lexical:       mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/a", false))),
			canonical:     mustSnapshot(t, ScopeSnapshotSpec{Capability: CapabilityFileRead, TargetNode: "db-01", Endpoint: algebraic.Some(ep22), Verdict: VerdictAllow, Risk: RiskSafe, Decision: NewDecisionAllow("allow"), Paths: []ScopedPath{mustScopedPath(t, "/tmp/a", false)}}),
			wantEscalated: true,
			wantReason:    EscalationTargetNodeDrift,
		},
		{
			name:          "目标端点端口漂移(22->2222)",
			lexical:       mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/a", false))),
			canonical:     mustSnapshot(t, ScopeSnapshotSpec{Capability: CapabilityFileRead, TargetNode: "web-01", Endpoint: algebraic.Some(ep2222), Verdict: VerdictAllow, Risk: RiskSafe, Decision: NewDecisionAllow("allow"), Paths: []ScopedPath{mustScopedPath(t, "/tmp/a", false)}}),
			wantEscalated: true,
			wantReason:    EscalationEndpointDrift,
		},
		{
			name:          "Verdict 收紧(Allow->Deny)",
			lexical:       mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/a", false))),
			canonical:     mustSnapshot(t, ScopeSnapshotSpec{Capability: CapabilityFileRead, TargetNode: "web-01", Endpoint: algebraic.Some(ep22), Verdict: VerdictDeny, Risk: RiskSafe, Decision: NewDecisionAllow("allow"), Paths: []ScopedPath{mustScopedPath(t, "/tmp/a", false)}}),
			wantEscalated: true,
			wantReason:    EscalationVerdictTightened,
		},
		{
			name:          "风险等级升格(Safe->Moderate)",
			lexical:       mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/a", false))),
			canonical:     mustSnapshot(t, ScopeSnapshotSpec{Capability: CapabilityFileRead, TargetNode: "web-01", Endpoint: algebraic.Some(ep22), Verdict: VerdictAllow, Risk: RiskModerate, Decision: NewDecisionAllow("allow"), Paths: []ScopedPath{mustScopedPath(t, "/tmp/a", false)}}),
			wantEscalated: true,
			wantReason:    EscalationRiskIncreased,
		},
		{
			name:          "决策收紧(Allow->NeedApproval)",
			lexical:       mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/a", false))),
			canonical:     mustSnapshot(t, ScopeSnapshotSpec{Capability: CapabilityFileRead, TargetNode: "web-01", Endpoint: algebraic.Some(ep22), Verdict: VerdictAllow, Risk: RiskSafe, Decision: naMod, Paths: []ScopedPath{mustScopedPath(t, "/tmp/a", false)}}),
			wantEscalated: true,
			wantReason:    EscalationDecisionTightened,
		},
		{
			name:          "同为 NeedApproval 但内部审批风险升格(Moderate->Dangerous)",
			lexical:       mustSnapshot(t, ScopeSnapshotSpec{Capability: CapabilityFileMut, TargetNode: "web-01", Endpoint: algebraic.Some(ep22), Verdict: VerdictDeny, Risk: RiskModerate, Decision: naMod, Paths: []ScopedPath{mustScopedPath(t, "/tmp/a", false)}}),
			canonical:     mustSnapshot(t, ScopeSnapshotSpec{Capability: CapabilityFileMut, TargetNode: "web-01", Endpoint: algebraic.Some(ep22), Verdict: VerdictDeny, Risk: RiskModerate, Decision: naDanger, Paths: []ScopedPath{mustScopedPath(t, "/tmp/a", false)}}),
			wantEscalated: true,
			wantReason:    EscalationDecisionRiskIncreased,
		},
		{
			name:          "非受保护路径软链逃逸至受保护区",
			lexical:       mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/link", false))),
			canonical:     mustSnapshot(t, baseSpec(mustScopedPath(t, "/etc/passwd", false, "/etc/**"))),
			wantEscalated: true,
			wantReason:    EscalationProtectedTransition,
			wantAdded:     []string{"/etc/passwd"},
		},
		{
			name: "同风险同决策 Protected-A -> Protected-B 跨受保护分区软链重定向",
			lexical: mustSnapshot(t, ScopeSnapshotSpec{
				Capability: CapabilityFileMut, TargetNode: "web-01", Endpoint: algebraic.Some(ep22),
				Verdict: VerdictDeny, Risk: RiskDangerous, Decision: naDanger,
				Paths: []ScopedPath{mustScopedPath(t, "/etc/app/link", false, "/etc/**")},
			}),
			canonical: mustSnapshot(t, ScopeSnapshotSpec{
				Capability: CapabilityFileMut, TargetNode: "web-01", Endpoint: algebraic.Some(ep22),
				Verdict: VerdictDeny, Risk: RiskDangerous, Decision: naDanger,
				Paths: []ScopedPath{mustScopedPath(t, "/root/.ssh/authorized_keys", false, "/root/**")},
			}),
			wantEscalated: true,
			wantReason:    EscalationProtectedRedirect,
			wantAdded:     []string{"/root/.ssh/authorized_keys"},
		},
		{
			name: "同风险同决策同受保护分区 Protected-A -> Protected-B 路径软链重定向",
			lexical: mustSnapshot(t, ScopeSnapshotSpec{
				Capability: CapabilityFileMut, TargetNode: "web-01", Endpoint: algebraic.Some(ep22),
				Verdict: VerdictDeny, Risk: RiskDangerous, Decision: naDanger,
				Paths: []ScopedPath{mustScopedPath(t, "/etc/app/link", false, "/etc/**")},
			}),
			canonical: mustSnapshot(t, ScopeSnapshotSpec{
				Capability: CapabilityFileMut, TargetNode: "web-01", Endpoint: algebraic.Some(ep22),
				Verdict: VerdictDeny, Risk: RiskDangerous, Decision: naDanger,
				Paths: []ScopedPath{mustScopedPath(t, "/etc/shadow", false, "/etc/**")},
			}),
			wantEscalated: true,
			wantReason:    EscalationProtectedRedirect,
			wantAdded:     []string{"/etc/shadow"},
		},
		{
			name: "同路径新增更深层受保护分区标签",
			lexical: mustSnapshot(t, ScopeSnapshotSpec{
				Capability: CapabilityFileMut, TargetNode: "web-01", Endpoint: algebraic.Some(ep22),
				Verdict: VerdictDeny, Risk: RiskDangerous, Decision: naDanger,
				Paths: []ScopedPath{mustScopedPath(t, "/etc/ssh/sshd_config", false, "/etc/**")},
			}),
			canonical: mustSnapshot(t, ScopeSnapshotSpec{
				Capability: CapabilityFileMut, TargetNode: "web-01", Endpoint: algebraic.Some(ep22),
				Verdict: VerdictDeny, Risk: RiskDangerous, Decision: naDanger,
				Paths: []ScopedPath{mustScopedPath(t, "/etc/ssh/sshd_config", false, "/etc/**", "/etc/ssh/**")},
			}),
			wantEscalated: true,
			wantReason:    EscalationProtectedRedirect,
			wantAdded:     []string{"/etc/ssh/sshd_config"},
		},
		{
			name:          "非递归路径扩张为递归遍历",
			lexical:       mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/dir", false))),
			canonical:     mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/dir", true))),
			wantEscalated: true,
			wantReason:    EscalationRecursiveExpanded,
		},
		{
			name:          "空路径集合与非空路径集合间发生结构漂移",
			lexical:       mustSnapshot(t, baseSpec()),
			canonical:     mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/added", false))),
			wantEscalated: true,
			wantReason:    EscalationPathPresenceDrift,
		},
		{
			name: "良性同一受保护路径无任何变化不应重复弹窗",
			lexical: mustSnapshot(t, ScopeSnapshotSpec{
				Capability: CapabilityFileMut, TargetNode: "web-01", Endpoint: algebraic.Some(ep22),
				Verdict: VerdictDeny, Risk: RiskDangerous, Decision: naDanger,
				Paths: []ScopedPath{mustScopedPath(t, "/etc/app.conf", false, "/etc/**")},
			}),
			canonical: mustSnapshot(t, ScopeSnapshotSpec{
				Capability: CapabilityFileMut, TargetNode: "web-01", Endpoint: algebraic.Some(ep22),
				Verdict: VerdictDeny, Risk: RiskDangerous, Decision: naDanger,
				Paths: []ScopedPath{mustScopedPath(t, "/etc/app.conf", false, "/etc/**")},
			}),
			wantEscalated: false,
		},
		{
			name:          "良性非受保护软链规范化(/var/run->/run)不误报升级",
			lexical:       mustSnapshot(t, baseSpec(mustScopedPath(t, "/var/run/app.pid", false))),
			canonical:     mustSnapshot(t, baseSpec(mustScopedPath(t, "/run/app.pid", false))),
			wantEscalated: false,
		},
		{
			name:          "仅风险降级且非受保护不视为升级",
			lexical:       mustSnapshot(t, ScopeSnapshotSpec{Capability: CapabilityFileRead, TargetNode: "web-01", Endpoint: algebraic.Some(ep22), Verdict: VerdictAllow, Risk: RiskModerate, Decision: NewDecisionAllow("allow"), Paths: []ScopedPath{mustScopedPath(t, "/tmp/a", false)}}),
			canonical:     mustSnapshot(t, baseSpec(mustScopedPath(t, "/tmp/a", false))),
			wantEscalated: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := InspectScopeEscalation(tc.lexical, tc.canonical)
			if res.Escalated() != tc.wantEscalated || CanonicalScopeEscalated(tc.lexical, tc.canonical) != tc.wantEscalated {
				t.Fatalf("Escalated = %v, want %v (reasons=%v)", res.Escalated(), tc.wantEscalated, res.Reasons())
			}
			if tc.wantReason != EscalationUnknown && !res.HasReason(tc.wantReason) {
				t.Fatalf("期望包含原因 %v，实际=%v", tc.wantReason, res.Reasons())
			}
			if len(tc.wantAdded) > 0 && !slices.Equal(res.AddedProtectedPaths(), tc.wantAdded) {
				t.Fatalf("AddedProtectedPaths = %v, want %v", res.AddedProtectedPaths(), tc.wantAdded)
			}
		})
	}
}

func TestEscalationRecursiveMultiPathRegression(t *testing.T) {
	ep22, _ := netaddr.ParseEndpoint("192.0.2.10:22")
	snap := func(paths ...ScopedPath) ScopeSnapshot {
		return mustSnapshot(t, ScopeSnapshotSpec{
			Capability: CapabilityFileMut, TargetNode: "web-01", Endpoint: algebraic.Some(ep22),
			Verdict: VerdictAllow, Risk: RiskModerate, Decision: NewDecisionAllow("allow"), Paths: paths,
		})
	}
	cases := []struct {
		name          string
		lexical       ScopeSnapshot
		canonical     ScopeSnapshot
		wantEscalated bool
		wantReason    EscalationReason
	}{
		{
			name:          "多路径中已有递归项不得掩盖另一非递归软链升级为递归",
			lexical:       snap(mustScopedPath(t, "/tmp/logs", true), mustScopedPath(t, "/srv/link", false)),
			canonical:     snap(mustScopedPath(t, "/tmp/logs", true), mustScopedPath(t, "/srv/tenant_b", true)),
			wantEscalated: true,
			wantReason:    EscalationRecursiveExpanded,
		},
		{
			name:          "规范化新增额外未匹配递归根必须判定升级",
			lexical:       snap(mustScopedPath(t, "/tmp/a", true)),
			canonical:     snap(mustScopedPath(t, "/tmp/a", true), mustScopedPath(t, "/srv/escape", true)),
			wantEscalated: true,
			wantReason:    EscalationRecursiveExpanded,
		},
		{
			name:          "旧路径递归降级同时在另一新路径扩张为递归必须判定升级",
			lexical:       snap(mustScopedPath(t, "/tmp/a", true), mustScopedPath(t, "/tmp/b", false)),
			canonical:     snap(mustScopedPath(t, "/tmp/a", false), mustScopedPath(t, "/tmp/c", true)),
			wantEscalated: true,
			wantReason:    EscalationRecursiveExpanded,
		},
		{
			name:          "单递归根软链裂变为两个未匹配递归根必须判定升级",
			lexical:       snap(mustScopedPath(t, "/var/run/a", true)),
			canonical:     snap(mustScopedPath(t, "/run/a", true), mustScopedPath(t, "/run/b", true)),
			wantEscalated: true,
			wantReason:    EscalationRecursiveExpanded,
		},
		{
			name:          "良性一对一递归软链规范化(/var/run/d->/run/d)不误报升级",
			lexical:       snap(mustScopedPath(t, "/var/run/d", true)),
			canonical:     snap(mustScopedPath(t, "/run/d", true)),
			wantEscalated: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := InspectScopeEscalation(tc.lexical, tc.canonical)
			if res.Escalated() != tc.wantEscalated || CanonicalScopeEscalated(tc.lexical, tc.canonical) != tc.wantEscalated {
				t.Fatalf("Escalated = %v, want %v (reasons=%v)", res.Escalated(), tc.wantEscalated, res.Reasons())
			}
			if tc.wantReason != EscalationUnknown && !res.HasReason(tc.wantReason) {
				t.Fatalf("期望包含原因 %v，实际=%v", tc.wantReason, res.Reasons())
			}
		})
	}
}

func TestEscalationZeroResultAndReasonCodec(t *testing.T) {
	// 零值 ScopeEscalationResult 必须失败关闭为 escalated=true
	var zeroRes ScopeEscalationResult
	if !zeroRes.Escalated() || !zeroRes.HasReason(EscalationInvalidInput) {
		t.Fatal("零值 ScopeEscalationResult 必须失败关闭")
	}
	if _, err := EscalationUnknown.MarshalText(); !errors.Is(err, ErrInvalidScopeSnapshot) {
		t.Fatalf("EscalationUnknown.MarshalText 期望 ErrInvalidScopeSnapshot，实际=%v", err)
	}
	for r := EscalationInvalidInput; r <= EscalationPathPresenceDrift; r++ {
		text, err := r.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v) 失败: %v", r, err)
		}
		var out EscalationReason
		if err := out.UnmarshalText(text); err != nil || out != r {
			t.Fatalf("EscalationReason 往返失败: text=%q out=%v want=%v err=%v", text, out, r, err)
		}
	}
}
