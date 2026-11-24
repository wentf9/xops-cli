package security

import (
	jsonv2 "encoding/json/v2"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
)

func FuzzParseOperationID(f *testing.F) {
	for _, seed := range []string{
		"0102030405060708090a0b0c0d0e0f10", "op-123_abc.xyz", "", " ",
		"bad space", "ctrl\x00byte", "newline\nid", "中文标识",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		assertOperationIDFuzzCase(t, raw)
	})
}

func assertOperationIDFuzzCase(t *testing.T, raw string) {
	t.Helper()
	id, err := ParseOperationID(raw)
	if err != nil {
		if !errors.Is(err, ErrInvalidOperationID) || id.IsValid() {
			t.Fatalf("ParseOperationID(%q) 失败返回值非法: id=%v err=%v", raw, id, err)
		}
		return
	}
	if !id.IsValid() || id.IsZero() || id.String() != raw {
		t.Fatalf("ParseOperationID(%q) 成功状态异常", raw)
	}
	appended, err := id.AppendText([]byte("p:"))
	marshaled, mErr := id.MarshalText()
	if err != nil || mErr != nil || string(appended) != "p:"+string(marshaled) {
		t.Fatalf("AppendText/MarshalText 不一致: errs=(%v,%v)", err, mErr)
	}
	var out OperationID
	if err := out.UnmarshalText(marshaled); err != nil || !out.Equal(id) {
		t.Fatalf("OperationID 文本往返失败: raw=%q err=%v", raw, err)
	}
	encoded, err := jsonv2.Marshal(id, jsonv2.Deterministic(true))
	var jsonOut OperationID
	if err != nil || jsonv2.Unmarshal(encoded, &jsonOut) != nil || !jsonOut.Equal(id) {
		t.Fatalf("OperationID JSON 往返失败: encoded=%s err=%v", encoded, err)
	}
}

func FuzzApprovalEnvelope(f *testing.F) {
	f.Add("op-1", "file", "write", "web-01", "/etc/app.conf", "k", "v", "approve write", uint8(3), uint8(1), int64(60_000_000_000), int64(1764030600), byte(1))
	f.Add("", "file", "write", "", "", "", "", "", uint8(0), uint8(0), int64(0), int64(0), byte(0))
	f.Add("op-2", "terminal_exec", "once", "db-01", "/var/log/a", "sudo", "true", "run\ncmd", uint8(2), uint8(2), int64(5_000_000_000), int64(1764030999), byte(7))
	// 覆盖极端时间戳（RFC 3339 越界年份、TTL 溢出）与不可见摘要输入
	f.Add("op-3", "file", "write", "web-01", "/etc/a", "k", "v", "   \u202e\u200b", uint8(3), uint8(2), int64(math.MaxInt64), int64(253402300799), byte(9))
	f.Add("op-4", "file", "write", "web-01", "/etc/a", "k", "v", "year-overflow", uint8(2), uint8(5), int64(60_000_000_000), int64(300_000_000_000), byte(2))

	f.Fuzz(func(t *testing.T, opRaw, tool, action, nodeID, path, pk, pv, summary string, riskRaw, decKindRaw uint8, ttlNs, unixSec int64, nonceByte byte) {
		opID, err := ParseOperationID(opRaw)
		if err != nil {
			return
		}
		binding, err := NewOperationBinding(OperationBindingSpec{
			Capability: CapabilityFileMut, Tool: tool, Action: action, NodeID: nodeID,
			CanonicalPaths: nonEmptySlice(path), Parameters: singleParamMap(pk, pv),
		})
		if err != nil {
			if binding.IsValid() {
				t.Fatal("非法 OperationBinding 构造失败后不应有效")
			}
			return
		}
		risk := riskFromByte(riskRaw)
		var nonce [16]byte
		nonce[0] = nonceByte
		env, err := NewApprovalEnvelope(ApprovalEnvelopeSpec{
			OperationID: opID, Binding: binding, Risk: risk, Decision: decisionFromFuzzBytes(decKindRaw, risk, summary),
			ScopeSummary: summary, IssuedAt: fuzzTimestamp(unixSec), TTL: algebraic.FromStdDuration(time.Duration(ttlNs)), Nonce: nonce,
		})
		if err != nil {
			if env.IsValid() {
				t.Fatal("非法 ApprovalEnvelope 构造失败后不应有效")
			}
			return
		}
		assertEnvelopeFuzzInvariants(t, env, binding)
	})
}

func fuzzTimestamp(unixSec int64) time.Time {
	// 故意放行 RFC 3339 边界之外的时间戳，验证 NewApprovalEnvelope 恒在构造期失败关闭而非 CanonicalJSON 崩溃。
	if unixSec == 0 {
		return time.Time{}
	}
	return time.Unix(unixSec, 0).UTC()
}

func assertEnvelopeFuzzInvariants(t *testing.T, env ApprovalEnvelope, binding OperationBinding) {
	t.Helper()
	raw1, err1 := env.CanonicalJSON()
	raw2, err2 := env.CanonicalJSON()
	if err1 != nil || err2 != nil || string(raw1) != string(raw2) {
		t.Fatalf("ApprovalEnvelope.CanonicalJSON 非确定性或失败: errs=(%v,%v)", err1, err2)
	}
	var decoded ApprovalEnvelope
	if err := jsonv2.Unmarshal(raw1, &decoded); err != nil || !decoded.Equal(env) || !decoded.MatchesBinding(binding) {
		t.Fatalf("ApprovalEnvelope 往返失败: raw=%s err=%v", raw1, err)
	}
	d1, err := env.Digest()
	ok, mErr := decoded.MatchesDigest(d1)
	if err != nil || mErr != nil || !ok {
		t.Fatalf("decoded.MatchesDigest 失败: ok=%v errs=(%v,%v)", ok, err, mErr)
	}
}

func FuzzLatticeLaws(f *testing.F) {
	f.Add(uint8(0), uint8(1), uint8(2), "a", "b", "c")
	f.Add(uint8(1), uint8(2), uint8(3), "deny1", "deny2", "")
	f.Add(uint8(255), uint8(0), uint8(1), "", "allow", "need")

	f.Fuzz(func(t *testing.T, a, b, c uint8, s1, s2, s3 string) {
		assertVerdictFuzzLaws(t, Verdict(a%4), Verdict(b%4), Verdict(c%4))
		assertRiskFuzzLaws(t, RiskLevel(a%5), RiskLevel(b%5), RiskLevel(c%5))
		da := decisionFromFuzzBytes(a, riskFromByte(a), s1)
		db := decisionFromFuzzBytes(b, riskFromByte(b), s2)
		dc := decisionFromFuzzBytes(c, riskFromByte(c), s3)
		assertDecisionFuzzLaws(t, da, db, dc)
	})
}

func assertVerdictFuzzLaws(t *testing.T, va, vb, vc Verdict) {
	t.Helper()
	if va.Meet(vb) != vb.Meet(va) || va.Meet(vb).Meet(vc) != va.Meet(vb.Meet(vc)) ||
		va.Meet(va) != va.Normalize() || va.Meet(VerdictDeny) != VerdictDeny {
		t.Fatalf("Verdict.Meet 代数律破坏: %v %v %v", va, vb, vc)
	}
}

func assertRiskFuzzLaws(t *testing.T, ra, rb, rc RiskLevel) {
	t.Helper()
	if ra.Join(rb) != rb.Join(ra) || ra.Join(rb).Join(rc) != ra.Join(rb.Join(rc)) ||
		ra.Join(ra) != ra.Normalize() || ra.Join(RiskUnknown) != RiskUnknown {
		t.Fatalf("RiskLevel.Join 代数律破坏: %v %v %v", ra, rb, rc)
	}
	if ra.StrictestThreshold(rb) != rb.StrictestThreshold(ra) ||
		ra.StrictestThreshold(rb).StrictestThreshold(rc) != ra.StrictestThreshold(rb.StrictestThreshold(rc)) ||
		ra.StrictestThreshold(RiskUnknown) != RiskUnknown {
		t.Fatalf("RiskLevel.StrictestThreshold 代数律破坏: %v %v %v", ra, rb, rc)
	}
}

func assertDecisionFuzzLaws(t *testing.T, da, db, dc GuardrailDecision) {
	t.Helper()
	if !EqualDecision(JoinDecisions(da, db), JoinDecisions(db, da)) ||
		!EqualDecision(JoinDecisions(JoinDecisions(da, db), dc), JoinDecisions(da, JoinDecisions(db, dc))) ||
		!EqualDecision(JoinDecisions(da, da), NormalizeDecision(da)) ||
		FoldDecisions(da, db, dc).Kind() != FoldDecisions(dc, da, db).Kind() {
		t.Fatal("GuardrailDecision 并半格代数律破坏")
	}
}

func nonEmptySlice(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func singleParamMap(k, v string) map[string]string {
	if k == "" {
		return nil
	}
	return map[string]string{k: v}
}

func riskFromByte(b uint8) RiskLevel {
	switch b % 4 {
	case 1:
		return RiskSafe
	case 2:
		return RiskModerate
	case 3:
		return RiskDangerous
	default:
		return RiskUnknown
	}
}

func decisionFromFuzzBytes(b uint8, risk RiskLevel, reason string) GuardrailDecision {
	switch b % 6 {
	case 0:
		return nil
	case 1:
		return NewDecisionDeny(reason)
	case 2:
		if !risk.IsValid() {
			risk = RiskModerate
		}
		d, err := NewDecisionNeedApproval(risk, reason)
		if err != nil {
			return NewDecisionDeny(reason)
		}
		return d
	case 3:
		return NewDecisionAllow(reason)
	case 4:
		// 故意构造与外层 risk 错配的 NeedApproval，验证 NewApprovalEnvelope 拒绝风险冲突信封
		other := pickIf(risk == RiskSafe, RiskDangerous, RiskSafe)
		d, err := NewDecisionNeedApproval(other, reason)
		if err != nil {
			return NewDecisionDeny(reason)
		}
		return d
	default:
		return &DecisionAllow{}
	}
}
