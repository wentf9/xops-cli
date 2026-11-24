package security

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

func TestCapabilityPhantomSet(t *testing.T) {
	assertPhantomCapabilities(t)
	assertCapabilityKindCodec(t)
}

func assertPhantomCapabilities(t *testing.T) {
	t.Helper()
	if CapabilityKindOf[CapInspect]() != CapabilityInspect || CapabilityKindOf[CapExecute]() != CapabilityExecute ||
		CapabilityKindOf[CapFileRead]() != CapabilityFileRead || CapabilityKindOf[CapFileMut]() != CapabilityFileMut ||
		CapabilityKindOf[CapTransfer]() != CapabilityTransfer || CapabilityKindOf[CapTunnel]() != CapabilityTunnel ||
		CapabilityKindOf[CapMutate]() != CapabilityMutate || CapabilityKindOf[Capability]() != CapabilityInvalid {
		t.Fatal("CapabilityKindOf 映射与幻影能力类型不一致")
	}
	if (CapInspect{}).Kind() != CapabilityInspect || (CapExecute{}).Kind() != CapabilityExecute ||
		(CapFileRead{}).Kind() != CapabilityFileRead || (CapFileMut{}).Kind() != CapabilityFileMut ||
		(CapTransfer{}).Kind() != CapabilityTransfer || (CapTunnel{}).Kind() != CapabilityTunnel ||
		(CapMutate{}).Kind() != CapabilityMutate {
		t.Fatal("幻影能力值 Kind() 方法返回值错误")
	}
}

func assertCapabilityKindCodec(t *testing.T) {
	t.Helper()
	var zeroCap CapabilityKind
	if !zeroCap.IsZero() || zeroCap.IsValid() || zeroCap.String() != "invalid" {
		t.Fatal("CapabilityKind 零值必须无效")
	}
	if _, err := zeroCap.MarshalText(); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("零值 CapabilityKind.MarshalText 期望 ErrInvalidCapability，实际=%v", err)
	}
	for k := CapabilityInspect; k <= CapabilityMutate; k++ {
		raw, err := jsonv2.Marshal(k, jsonv2.Deterministic(true))
		var out CapabilityKind
		if err != nil || jsonv2.Unmarshal(raw, &out) != nil || out != k {
			t.Fatalf("CapabilityKind 往返失败: k=%v raw=%s out=%v err=%v", k, raw, out, err)
		}
	}
}

func TestOperationIDAndDigestCodecs(t *testing.T) {
	assertOperationIDCodec(t)
	assertDigestCodec(t)
}

func assertOperationIDCodec(t *testing.T) {
	t.Helper()
	var zeroID OperationID
	if zeroID.IsValid() || !zeroID.IsZero() || zeroID.Equal(zeroID) {
		t.Fatal("OperationID 零值未满足失败关闭不变量")
	}
	if _, err := zeroID.AppendText(nil); !errors.Is(err, ErrInvalidOperationID) {
		t.Fatalf("零值 OperationID.AppendText 期望 ErrInvalidOperationID，实际=%v", err)
	}
	if _, err := NewOperationIDFrom(nil); !errors.Is(err, ErrNilEntropy) {
		t.Fatalf("NewOperationIDFrom(nil) 期望 ErrNilEntropy，实际=%v", err)
	}
	if _, err := NewOperationIDFrom(bytes.NewReader([]byte{1, 2, 3})); !errors.Is(err, ErrInvalidOperationID) {
		t.Fatalf("短熵源期望 ErrInvalidOperationID，实际=%v", err)
	}
	seed := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	fromBytes := OperationIDFromBytes(seed)
	fromReader, err := NewOperationIDFrom(bytes.NewReader(seed[:]))
	if err != nil || !fromBytes.Equal(fromReader) || fromBytes.String() != "00112233445566778899aabbccddeeff" {
		t.Fatalf("OperationID 确定性生成不一致: %q vs %q (err=%v)", fromBytes, fromReader, err)
	}
	appended, err := fromBytes.AppendText([]byte("op:"))
	if err != nil || string(appended) != "op:00112233445566778899aabbccddeeff" {
		t.Fatalf("OperationID.AppendText 异常: %q err=%v", appended, err)
	}
	rawID, err := jsonv2.Marshal(fromBytes, jsonv2.Deterministic(true))
	var decodedID OperationID
	if err != nil || jsonv2.Unmarshal(rawID, &decodedID) != nil || !decodedID.Equal(fromBytes) {
		t.Fatalf("OperationID JSON 往返失败: raw=%s out=%q err=%v", rawID, decodedID, err)
	}
	for _, bad := range []string{"", "has space", "tab\tid", "ctrl\x00id", "中文", strings.Repeat("a", maxOperationIDLen+1)} {
		if _, err := ParseOperationID(bad); !errors.Is(err, ErrInvalidOperationID) {
			t.Fatalf("ParseOperationID(%q) 期望 ErrInvalidOperationID，实际=%v", bad, err)
		}
	}
}

func assertDigestCodec(t *testing.T) {
	t.Helper()
	var zeroDig Digest
	if zeroDig.IsValid() || !zeroDig.IsZero() || zeroDig.Equal(zeroDig) {
		t.Fatal("Digest 零值未满足失败关闭不变量")
	}
	d1 := DigestBytes([]byte("hello xops"))
	d2, err := ParseDigest(d1.String())
	if err != nil || !d1.Equal(d2) || d1.Compare(d2) != 0 {
		t.Fatalf("Digest 往返失败: d1=%q d2=%q err=%v", d1, d2, err)
	}
	if _, err := ParseDigest(strings.ToUpper(d1.String())); !errors.Is(err, ErrInvalidDigest) {
		t.Fatalf("大写十六进制 Digest 应被拒绝，实际=%v", err)
	}
	if _, err := ParseDigest("md5:" + d1.Hex()); !errors.Is(err, ErrInvalidDigest) {
		t.Fatalf("非 sha256 前缀应被拒绝，实际=%v", err)
	}
}

func TestOperationBindingCanonicalHashAndIsolation(t *testing.T) {
	ep, _ := netaddr.ParseEndpoint("[2001:db8::1]:2222")
	cmdDig := DigestBytes([]byte("systemctl restart nginx"))
	planDig := DigestBytes([]byte("hop-chain-merkle-root"))
	nodesIn := []string{"web-02", "web-01", "web-02"}
	pathsIn := []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/app.conf", "/etc/nginx/nginx.conf"}
	paramsIn := map[string]string{"zeta": "2", "alpha": "1"}

	b1, err := NewOperationBinding(OperationBindingSpec{
		Capability: CapabilityFileMut, Tool: "file", Action: "write", NodeID: "web-01",
		NodeIDs: nodesIn, Endpoint: algebraic.Some(ep), CanonicalPaths: pathsIn,
		RecursivePaths: []string{"/var/www/b", "/var/www/a"},
		CommandDigest:  algebraic.Some(cmdDig), PlanDigest: algebraic.Some(planDig), Parameters: paramsIn,
	})
	if err != nil {
		t.Fatalf("NewOperationBinding(b1) 失败: %v", err)
	}
	nodesIn[0], pathsIn[0], paramsIn["alpha"] = "tampered", "/tampered", "tampered"
	b1.CanonicalPaths()[0] = "/tampered-getter"
	b1.Parameters()["alpha"] = "tampered-getter"
	if !slices.Equal(b1.CanonicalPaths(), []string{"/etc/nginx/conf.d/app.conf", "/etc/nginx/nginx.conf"}) {
		t.Fatalf("CanonicalPaths 被外部修改污染: %v", b1.CanonicalPaths())
	}
	if val, ok := b1.Param("alpha"); !ok || val != "1" {
		t.Fatalf("Param 被外部修改污染: val=%q ok=%v", val, ok)
	}

	b2, err := NewOperationBinding(OperationBindingSpec{
		Capability: CapabilityFileMut, Tool: "file", Action: "write", NodeID: "web-01",
		NodeIDs: []string{"web-01", "web-02"}, Endpoint: algebraic.Some(ep),
		CanonicalPaths: []string{"/etc/nginx/nginx.conf", "/etc/nginx/conf.d/app.conf"},
		RecursivePaths: []string{"/var/www/a", "/var/www/b"},
		CommandDigest:  algebraic.Some(cmdDig), PlanDigest: algebraic.Some(planDig),
		Parameters: map[string]string{"alpha": "1", "zeta": "2"},
	})
	if err != nil {
		t.Fatalf("NewOperationBinding(b2) 失败: %v", err)
	}
	assertBindingCanonicalEqualityAndRoundTrip(t, b1, b2)
}

func assertBindingCanonicalEqualityAndRoundTrip(t *testing.T, b1, b2 OperationBinding) {
	t.Helper()
	dig1, err1 := b1.Digest()
	dig2, err2 := b2.Digest()
	if err1 != nil || err2 != nil || !b1.Equal(b2) || !dig1.Equal(dig2) {
		t.Fatalf("乱序构造的 OperationBinding 未收敛: eq=%v errs=(%v,%v)", b1.Equal(b2), err1, err2)
	}
	bc1, _ := NewOperationBinding(OperationBindingSpec{Capability: CapabilityExecute, Tool: "ab", Action: "c"})
	bc2, _ := NewOperationBinding(OperationBindingSpec{Capability: CapabilityExecute, Tool: "a", Action: "bc"})
	dc1, _ := bc1.Digest()
	dc2, _ := bc2.Digest()
	if dc1.Equal(dc2) {
		t.Fatal("长度前缀编码发生字段边界碰撞")
	}
	raw, err := jsonv2.Marshal(b1, jsonv2.Deterministic(true))
	var decoded OperationBinding
	if err != nil || jsonv2.Unmarshal(raw, &decoded) != nil || !decoded.Equal(b1) {
		t.Fatalf("OperationBinding JSON 往返失败: raw=%s err=%v", raw, err)
	}
	var zero OperationBinding
	if _, err := zero.Digest(); !errors.Is(err, ErrInvalidOperationBinding) {
		t.Fatalf("零值 Digest 期望 ErrInvalidOperationBinding，实际=%v", err)
	}
	if err := b1.WriteCanonical(nil); !errors.Is(err, ErrNilWriter) {
		t.Fatalf("WriteCanonical(nil) 期望 ErrNilWriter，实际=%v", err)
	}
}

func buildGoldenEnvelopeFixture(t *testing.T) (ApprovalEnvelope, OperationBinding, Digest, Digest, time.Time) {
	t.Helper()
	ep, _ := netaddr.ParseEndpoint("192.0.2.10:22")
	cmdDig := DigestBytes([]byte("rm -rf /tmp/staging"))
	policyDig := DigestBytes([]byte("policy-v2"))
	binding, err := NewOperationBinding(OperationBindingSpec{
		Capability: CapabilityExecute, Tool: "terminal_exec", Action: "once", NodeID: "web-01",
		Endpoint: algebraic.Some(ep), CanonicalPaths: []string{"/etc/nginx/nginx.conf"},
		CommandDigest: algebraic.Some(cmdDig), Parameters: map[string]string{"sudo": "true", "dialect": "posix"},
	})
	if err != nil {
		t.Fatalf("NewOperationBinding 失败: %v", err)
	}
	opID := OperationIDFromBytes([16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10})
	nonce, err := NewApprovalNonceFrom(bytes.NewReader([]byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf}))
	if err != nil {
		t.Fatalf("NewApprovalNonceFrom 失败: %v", err)
	}
	decision, _ := NewDecisionNeedApproval(RiskDangerous, "dangerous command on web-01")
	issuedAt := time.Date(2026, 11, 25, 8, 30, 0, 0, time.FixedZone("CST", 8*3600))
	env, err := NewApprovalEnvelope(ApprovalEnvelopeSpec{
		OperationID: opID, Binding: binding, Risk: RiskDangerous, Decision: decision,
		ScopeSummary: "exec once on web-01\nline2", IssuedAt: issuedAt,
		TTL: algebraic.FromStdDuration(2 * time.Minute), Nonce: nonce, PolicyDigest: algebraic.Some(policyDig),
	})
	if err != nil {
		t.Fatalf("NewApprovalEnvelope 失败: %v", err)
	}
	return env, binding, cmdDig, policyDig, issuedAt.UTC()
}

func TestApprovalEnvelopeGoldenJSONv2AndExpiry(t *testing.T) {
	env, binding, cmdDig, policyDig, utcIssued := buildGoldenEnvelopeFixture(t)
	if env.ScopeSummary() != `exec once on web-01\nline2` || env.IssuedAt().Location() != time.UTC {
		t.Fatalf("ScopeSummary 或 IssuedAt 规范化异常: %q %v", env.ScopeSummary(), env.IssuedAt())
	}
	wantGolden := `{"operation_id":"0102030405060708090a0b0c0d0e0f10","binding":{"capability":"execute","tool":"terminal_exec","action":"once","node_id":"web-01","endpoint":"192.0.2.10:22","canonical_paths":["/etc/nginx/nginx.conf"],"command_digest":"` + cmdDig.String() + `","parameters":{"dialect":"posix","sudo":"true"}},"risk":"dangerous","decision":{"kind":"need_approval","risk":"dangerous","reason":"dangerous command on web-01"},"scope_summary":"exec once on web-01\\nline2","issued_at":"2026-11-25T00:30:00Z","ttl":"2m0s","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf","policy_digest":"` + policyDig.String() + `"}`
	for range 20 {
		raw, err := env.CanonicalJSON()
		if err != nil || string(raw) != wantGolden {
			t.Fatalf("ApprovalEnvelope 黄金 JSON 不匹配:\ngot:  %s\nwant: %s\nerr:  %v", raw, wantGolden, err)
		}
	}
	assertEnvelopeRoundTripAndWindow(t, env, binding, utcIssued)
	assertEnvelopeFailClosedCases(t, env, binding, utcIssued)
}

func assertEnvelopeRoundTripAndWindow(t *testing.T, env ApprovalEnvelope, binding OperationBinding, utcIssued time.Time) {
	t.Helper()
	raw, err := jsonv2.Marshal(env, jsonv2.Deterministic(true))
	var decoded ApprovalEnvelope
	if err != nil || jsonv2.Unmarshal(raw, &decoded) != nil || !decoded.Equal(env) {
		t.Fatalf("ApprovalEnvelope JSON 往返失败: err=%v eq=%v", err, decoded.Equal(env))
	}
	dig, err := env.Digest()
	ok, mErr := decoded.MatchesDigest(dig)
	if err != nil || mErr != nil || !ok || !decoded.MatchesBinding(binding) || !decoded.CanApprove() {
		t.Fatalf("MatchesDigest/MatchesBinding/CanApprove 异常: ok=%v errs=(%v,%v)", ok, err, mErr)
	}
	if env.IsActiveAt(utcIssued.Add(-time.Nanosecond)) || env.IsExpiredAt(utcIssued) ||
		!env.IsActiveAt(utcIssued) || !env.IsActiveAt(utcIssued.Add(2*time.Minute-time.Nanosecond)) ||
		env.IsActiveAt(utcIssued.Add(2*time.Minute)) || !env.IsExpiredAt(utcIssued.Add(2*time.Minute)) ||
		!env.IsExpiredAt(time.Time{}) || env.IsActiveAt(time.Time{}) {
		t.Fatal("ApprovalEnvelope 纯函数时间窗口边界判定异常")
	}
}

func assertEnvelopeFailClosedCases(t *testing.T, env ApprovalEnvelope, binding OperationBinding, utcIssued time.Time) {
	t.Helper()
	nonce, _ := env.Nonce()
	denyEnv, err := NewApprovalEnvelope(ApprovalEnvelopeSpec{
		OperationID: env.OperationID(), Binding: binding, Risk: RiskDangerous,
		Decision: NewDecisionDenyWithCode("blocked", "blocked command"), ScopeSummary: "blocked op",
		IssuedAt: utcIssued, TTL: env.TTL(), Nonce: nonce,
	})
	if err != nil || denyEnv.CanApprove() {
		t.Fatalf("DecisionDeny 信封绝不可批准: err=%v", err)
	}
	var zeroEnv ApprovalEnvelope
	if zeroEnv.IsValid() || zeroEnv.CanApprove() || !zeroEnv.IsExpiredAt(utcIssued) || zeroEnv.IsActiveAt(utcIssued) {
		t.Fatal("零值 ApprovalEnvelope 未满足失败关闭不变量")
	}
	if _, err := zeroEnv.Digest(); !errors.Is(err, ErrInvalidApprovalEnvelope) {
		t.Fatalf("零值 Digest 期望 ErrInvalidApprovalEnvelope，实际=%v", err)
	}
	if _, err := NewApprovalNonceFrom(bytes.NewReader(make([]byte, 16))); !errors.Is(err, ErrInvalidApprovalEnvelope) {
		t.Fatalf("全零 Nonce 应被拒绝，实际=%v", err)
	}
	// 篡改 JSON（deny 带 risk、allow 带 code、全零/大写 nonce、非正 TTL）均须反序列化失败并重置零值
	tampered := []string{
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{"kind":"deny","risk":"dangerous"},"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{"kind":"allow","code":"x"},"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{"kind":"allow"},"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":"00000000000000000000000000000000"}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{"kind":"allow"},"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"0s","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
	}
	for _, bad := range tampered {
		target := env
		if err := jsonv2.Unmarshal([]byte(bad), &target); err == nil || target.IsValid() {
			t.Fatalf("篡改 JSON 未失败关闭: bad=%s err=%v valid=%v", bad, err, target.IsValid())
		}
	}
}

func TestMatchGlobCrossPlatformUTF8(t *testing.T) {
	good := []struct {
		pattern, target string
		want            bool
	}{
		{"prod-*", "prod-web-01", true},
		{"prod-?", "prod-1", true},
		{"prod-?", "prod-12", false},
		{"a*b", "a/x\\y\nzb", true},
		{`a\b`, `a\b`, true},
		{"node-[0-9]", "node-7", true},
		{"node-[^0-9]", "node-a", true},
		{"node-[!0-9]", "node-7", false},
		{"节点-*", "节点-生产-01", true},
		{"***a", "xyzab", false},
		{"***a", "xyza", true},
		{"***a***", "xyzab", true},
	}
	for _, tc := range good {
		got, err := MatchGlob(tc.pattern, tc.target)
		if err != nil || got != tc.want {
			t.Fatalf("MatchGlob(%q, %q) = (%v, %v), want (%v, nil)", tc.pattern, tc.target, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "[unclosed", "[z-a]", "ctrl\npat", string([]byte{0xff})} {
		if err := ValidateGlob(bad); !errors.Is(err, ErrInvalidGlob) {
			t.Fatalf("ValidateGlob(%q) 期望 ErrInvalidGlob，实际=%v", bad, err)
		}
	}
	if _, err := MatchGlob("*", string([]byte{0xff})); !errors.Is(err, ErrInvalidGlob) {
		t.Fatalf("非法 UTF-8 目标应返回 ErrInvalidGlob，实际=%v", err)
	}
}

func TestBindingAndEnvelopeJSONNullAndOmittedFailClosed(t *testing.T) {
	env, binding, _, _, _ := buildGoldenEnvelopeFixture(t)
	for _, raw := range []string{
		`null`, `{}`, `{"capability":"execute","tool":"t"}`,
		`{"capability":null,"tool":"t","action":"a"}`,
		`{"capability":"execute","tool":null,"action":"a"}`,
		`{"capability":"execute","tool":"t","action":null}`,
	} {
		target := binding
		if err := jsonv2.Unmarshal([]byte(raw), &target); !errors.Is(err, ErrInvalidOperationBinding) || target.IsValid() {
			t.Fatalf("OperationBinding.Unmarshal(%s) 未失败关闭: valid=%v err=%v", raw, target.IsValid(), err)
		}
	}
	badEnvelopes := []string{
		`null`, `{}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":null,"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{},"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{"kind":null},"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{"kind":"need_approval"},"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{"kind":"need_approval","risk":"safe"},"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":null,"binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{"kind":"allow"},"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":"op-1","binding":null,"risk":"dangerous","decision":{"kind":"allow"},"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{"kind":"allow"},"scope_summary":"   ","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{"kind":"allow"},"scope_summary":"s","issued_at":null,"ttl":"1m","nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{"kind":"allow"},"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":null,"nonce":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"}`,
		`{"operation_id":"op-1","binding":{"capability":"execute","tool":"t","action":"a"},"risk":"dangerous","decision":{"kind":"allow"},"scope_summary":"s","issued_at":"2026-11-25T00:00:00Z","ttl":"1m","nonce":null}`,
	}
	for _, raw := range badEnvelopes {
		target := env
		if err := jsonv2.Unmarshal([]byte(raw), &target); !errors.Is(err, ErrInvalidApprovalEnvelope) || target.IsValid() {
			t.Fatalf("ApprovalEnvelope.Unmarshal(%s) 未失败关闭: valid=%v err=%v", raw, target.IsValid(), err)
		}
	}
	var badEnv ApprovalEnvelope
	if err := jsonv2.Unmarshal([]byte("nul"), &badEnv); err == nil || errors.Is(err, ErrInvalidApprovalEnvelope) {
		t.Fatalf("ApprovalEnvelope 畸形 JSON \"nul\" 应返回底层语法错误，实际=%v", err)
	}
}

func TestApprovalEnvelopeWindowSummaryAndRiskInvariants(t *testing.T) {
	env, binding, _, _, utcIssued := buildGoldenEnvelopeFixture(t)
	nonce, _ := env.Nonce()
	naSafe, _ := NewDecisionNeedApproval(RiskSafe, "safe approval")
	naDanger, _ := NewDecisionNeedApproval(RiskDangerous, "danger approval")

	base := func() ApprovalEnvelopeSpec {
		return ApprovalEnvelopeSpec{
			OperationID: env.OperationID(), Binding: binding, Risk: RiskDangerous, Decision: naDanger,
			ScopeSummary: "valid summary", IssuedAt: utcIssued,
			TTL: algebraic.FromStdDuration(time.Minute), Nonce: nonce,
		}
	}
	invalidSpecs := []ApprovalEnvelopeSpec{
		func() ApprovalEnvelopeSpec {
			s := base()
			s.IssuedAt = time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC)
			return s
		}(),
		func() ApprovalEnvelopeSpec {
			s := base()
			s.IssuedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			return s
		}(),
		func() ApprovalEnvelopeSpec {
			s := base()
			s.IssuedAt = time.Date(9999, 12, 31, 23, 59, 30, 0, time.UTC)
			s.TTL = algebraic.FromStdDuration(time.Minute)
			return s
		}(),
		func() ApprovalEnvelopeSpec {
			s := base()
			s.IssuedAt = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
			s.TTL = algebraic.FromStdDuration(time.Duration(math.MaxInt64))
			return s
		}(),
		func() ApprovalEnvelopeSpec { s := base(); s.ScopeSummary = "   \t\n  "; return s }(),
		func() ApprovalEnvelopeSpec { s := base(); s.ScopeSummary = "\u200b\u202e\ufeff"; return s }(),
		func() ApprovalEnvelopeSpec { s := base(); s.ScopeSummary = "\x00\x1b"; return s }(),
		func() ApprovalEnvelopeSpec { s := base(); s.Risk = RiskDangerous; s.Decision = naSafe; return s }(),
		func() ApprovalEnvelopeSpec { s := base(); s.Risk = RiskSafe; s.Decision = naDanger; return s }(),
	}
	for i, sp := range invalidSpecs {
		if got, err := NewApprovalEnvelope(sp); !errors.Is(err, ErrInvalidApprovalEnvelope) || got.IsValid() {
			t.Fatalf("invalidSpecs[%d] 期望 ErrInvalidApprovalEnvelope，实际: valid=%v err=%v", i, got.IsValid(), err)
		}
	}
	// 包含可见字符与 Bidi 控制符的摘要应被放行并将 Bidi 显式转义
	s := base()
	s.ScopeSummary = "ok\u202e!"
	got, err := NewApprovalEnvelope(s)
	if err != nil || got.ScopeSummary() != `ok\u202e!` {
		t.Fatalf("含可见字符的 Bidi 摘要处理异常: summary=%q err=%v", got.ScopeSummary(), err)
	}
}

func TestSanitizePromptTextUnicodeCfAndInvalidUTF8(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"safe text 节点-01", "safe text 节点-01"},
		{"a\u202eb", `a\u202eb`},
		{"a\u2066b\u2069c", `a\u2066b\u2069c`},
		{"zw\u200b\ufefftag\U000e0001", `zw\u200b\ufefftag\U000e0001`},
		{"line\u2028para\u2029", `line\u2028para\u2029`},
		{string([]byte{'a', 0xff, 0xfe, 'b'}), `a\xff\xfeb`},
	}
	for _, tc := range cases {
		if got := SanitizePromptText(tc.in); got != tc.want {
			t.Fatalf("SanitizePromptText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, badGlob := range []string{"prod-\u202e*", "prod-\u200b*", "prod-\ufeff*"} {
		if err := ValidateGlob(badGlob); !errors.Is(err, ErrInvalidGlob) {
			t.Fatalf("ValidateGlob(%q) 应拒绝 Unicode Cf 字符，实际=%v", badGlob, err)
		}
	}
}

func TestUTF8NodeIDConsistency(t *testing.T) {
	utf8Node := "节点-生产-01"
	o, err := NewNodeOverrides(mustOverrideRule(t, "节点-*", RiskSafe, DecisionKindAllow))
	if err != nil {
		t.Fatalf("NewNodeOverrides 失败: %v", err)
	}
	if th, err := o.ResolveThreshold(RiskDangerous, utf8Node); err != nil || th != RiskSafe {
		t.Fatalf("UTF-8 nodeID ResolveThreshold 失败: th=%v err=%v", th, err)
	}
	b, err := NewOperationBinding(OperationBindingSpec{
		Capability: CapabilityInspect, Tool: "host", Action: "stat", NodeID: utf8Node, NodeIDs: []string{utf8Node},
	})
	if err != nil || b.NodeID() != utf8Node {
		t.Fatalf("UTF-8 nodeID OperationBinding 构造失败: err=%v", err)
	}
	snap, err := NewScopeSnapshot(ScopeSnapshotSpec{
		Capability: CapabilityInspect, TargetNode: utf8Node, Verdict: VerdictAllow,
		Risk: RiskSafe, Decision: NewDecisionAllow("ok"),
	})
	if err != nil || snap.TargetNode() != utf8Node {
		t.Fatalf("UTF-8 nodeID ScopeSnapshot 构造失败: err=%v", err)
	}
	for _, bad := range []string{"has space", "ctrl\nnode", "bidi\u202enode", string([]byte{0xff})} {
		if _, err := NewOperationBinding(OperationBindingSpec{Capability: CapabilityInspect, Tool: "t", Action: "a", NodeID: bad}); !errors.Is(err, ErrInvalidOperationBinding) {
			t.Fatalf("OperationBinding 应拒绝非法 nodeID %q: err=%v", bad, err)
		}
		if _, err := NewScopeSnapshot(ScopeSnapshotSpec{Capability: CapabilityInspect, TargetNode: bad, Verdict: VerdictAllow, Risk: RiskSafe, Decision: NewDecisionAllow("ok")}); !errors.Is(err, ErrInvalidScopeSnapshot) {
			t.Fatalf("ScopeSnapshot 应拒绝非法 target_node %q: err=%v", bad, err)
		}
	}
}
