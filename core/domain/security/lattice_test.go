package security

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
)

func TestVerdictMeetLatticeLaws(t *testing.T) {
	assertVerdictBasics(t)
	samples := []Verdict{VerdictDeny, VerdictAllow, Verdict(2), Verdict(255)}
	for _, a := range samples {
		assertVerdictUnaryLaws(t, a)
		assertVerdictBinaryAndAssocLaws(t, a, samples)
	}
	assertVerdictFoldAndDecide(t)
}

func assertVerdictBasics(t *testing.T) {
	t.Helper()
	var zero Verdict
	if zero != VerdictDeny || !zero.IsZero() || !zero.IsValid() || zero.Allowed() || !zero.Denied() {
		t.Fatalf("Verdict 零值未满足失败关闭不变量: zero=%v", zero)
	}
	if VerdictAllow.IsZero() || !VerdictAllow.IsValid() || !VerdictAllow.Allowed() || VerdictAllow.Denied() {
		t.Fatal("VerdictAllow 状态异常")
	}
	invalid := Verdict(42)
	if invalid.IsValid() || invalid.Allowed() || !invalid.Denied() || invalid.Normalize() != VerdictDeny || invalid.String() != "deny(invalid)" {
		t.Fatalf("非法 Verdict 未失败关闭: invalid=%v str=%q", invalid, invalid.String())
	}
}

func assertVerdictUnaryLaws(t *testing.T, a Verdict) {
	t.Helper()
	if a.Meet(VerdictDeny) != VerdictDeny || VerdictDeny.Meet(a) != VerdictDeny {
		t.Fatalf("Verdict 违反零值吸收律: a=%v", a)
	}
	if a.IsValid() {
		if a.Meet(VerdictAllow) != a || VerdictAllow.Meet(a) != a || a.Meet(a) != a {
			t.Fatalf("Verdict 违反单位元或幂等律: a=%v", a)
		}
		return
	}
	if a.Meet(a) != VerdictDeny {
		t.Fatalf("非法 Verdict 自身 Meet 必须失败关闭: a=%v", a)
	}
}

func assertVerdictFoldAndDecide(t *testing.T) {
	t.Helper()
	if FoldVerdicts() != VerdictDeny || FoldVerdicts(VerdictAllow, VerdictAllow) != VerdictAllow {
		t.Fatal("FoldVerdicts 基础语义异常")
	}
	for _, seq := range [][]Verdict{
		{VerdictAllow, VerdictDeny, VerdictAllow},
		{VerdictDeny, VerdictAllow, VerdictAllow},
		{VerdictAllow, VerdictAllow, VerdictDeny},
	} {
		if FoldVerdicts(seq...) != VerdictDeny {
			t.Fatalf("FoldVerdicts(%v) 应返回 VerdictDeny", seq)
		}
	}
	if VerdictFromError(VerdictAllow, errors.New("boom")) != VerdictDeny || VerdictFromError(VerdictAllow, nil) != VerdictAllow {
		t.Fatal("VerdictFromError 语义异常")
	}
	if Decide(nil) != VerdictDeny ||
		Decide(func() (Verdict, error) { return VerdictAllow, errors.New("err") }) != VerdictDeny ||
		Decide(func() (Verdict, error) { return Verdict(9), nil }) != VerdictDeny ||
		Decide(func() (Verdict, error) { return VerdictAllow, nil }) != VerdictAllow {
		t.Fatal("Decide 失败关闭或放行路径异常")
	}
}

func assertVerdictBinaryAndAssocLaws(t *testing.T, a Verdict, samples []Verdict) {
	t.Helper()
	for _, b := range samples {
		if a.Meet(b) != b.Meet(a) {
			t.Fatalf("Verdict.Meet 违反交换律: a=%v b=%v", a, b)
		}
		for _, c := range samples {
			if a.Meet(b).Meet(c) != a.Meet(b.Meet(c)) {
				t.Fatalf("Verdict.Meet 违反结合律: a=%v b=%v c=%v", a, b, c)
			}
			if a.Compare(b) <= 0 && a.Meet(c).Compare(b.Meet(c)) > 0 {
				t.Fatalf("Verdict.Meet 违反单调律: a=%v b=%v c=%v", a, b, c)
			}
		}
	}
}

func TestVerdictCodecAndErrors(t *testing.T) {
	for _, v := range []Verdict{VerdictDeny, VerdictAllow} {
		appended, err := v.AppendText([]byte("v="))
		marshaled, mErr := v.MarshalText()
		if err != nil || mErr != nil || string(appended) != "v="+string(marshaled) {
			t.Fatalf("Verdict 文本编码不一致: v=%v errs=(%v,%v)", v, err, mErr)
		}
		raw, err := jsonv2.Marshal(v, jsonv2.Deterministic(true))
		var out Verdict
		if err != nil || jsonv2.Unmarshal(raw, &out) != nil || out != v {
			t.Fatalf("Verdict JSON 往返失败: raw=%s out=%v want=%v err=%v", raw, out, v, err)
		}
	}
	if _, err := Verdict(7).MarshalText(); !errors.Is(err, ErrInvalidVerdict) {
		t.Fatalf("非法 Verdict.MarshalText 期望 ErrInvalidVerdict，实际=%v", err)
	}
	for _, bad := range []string{"", "ALLOW", " allow", "deny\n", "true", "unknown"} {
		v := VerdictAllow
		if err := v.UnmarshalText([]byte(bad)); !errors.Is(err, ErrInvalidVerdict) || v != VerdictDeny {
			t.Fatalf("UnmarshalText(%q) 应失败并重置为 VerdictDeny: v=%v err=%v", bad, v, err)
		}
	}
	var nilV *Verdict
	if err := nilV.UnmarshalText([]byte("allow")); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil Verdict.UnmarshalText 期望 ErrNilReceiver，实际=%v", err)
	}
}

func TestRiskLevelJoinAndThresholdLatticeLaws(t *testing.T) {
	assertRiskZeroBasics(t)
	samples := []RiskLevel{RiskUnknown, RiskSafe, RiskModerate, RiskDangerous, RiskLevel(77)}
	for _, a := range samples {
		assertRiskUnaryLaws(t, a)
		assertRiskBinaryAndAssocLaws(t, a, samples)
	}
	assertRiskFolds(t)
	assertEvaluateThresholdMonotonicity(t, samples)
	assertRiskCodec(t)
}

func assertRiskZeroBasics(t *testing.T) {
	t.Helper()
	var zero RiskLevel
	if zero != RiskUnknown || !zero.IsZero() || zero.IsValid() || zero.String() != "unknown" {
		t.Fatalf("RiskLevel 零值必须为无效 RiskUnknown: zero=%v", zero)
	}
	if zero.Join(RiskSafe) != RiskUnknown || RiskSafe.Join(zero) != RiskUnknown {
		t.Fatal("RiskUnknown 零值被静默降级为低风险")
	}
	if zero.CompareSeverity(RiskDangerous) <= 0 || zero.CompareThresholdStrictness(RiskSafe) <= 0 {
		t.Fatal("RiskUnknown 秩未处于严格最高吸收位")
	}
}

func assertRiskUnaryLaws(t *testing.T, a RiskLevel) {
	t.Helper()
	if a.Join(RiskUnknown) != RiskUnknown || RiskUnknown.Join(a) != RiskUnknown ||
		a.StrictestThreshold(RiskUnknown) != RiskUnknown || RiskUnknown.StrictestThreshold(a) != RiskUnknown {
		t.Fatalf("RiskLevel 违反 RiskUnknown 吸收律: a=%v", a)
	}
	if a.IsValid() && (a.Join(RiskSafe) != a || a.Join(a) != a ||
		a.StrictestThreshold(RiskDangerous) != a || a.StrictestThreshold(a) != a) {
		t.Fatalf("RiskLevel 违反单位元或幂等律: a=%v", a)
	}
}

func assertRiskFolds(t *testing.T) {
	t.Helper()
	if FoldRisks() != RiskUnknown || FoldThresholds() != RiskUnknown {
		t.Fatal("空 FoldRisks/FoldThresholds 必须失败关闭返回 RiskUnknown")
	}
	if FoldRisks(RiskSafe, RiskDangerous, RiskModerate) != RiskDangerous ||
		FoldRisks(RiskModerate, RiskSafe, RiskDangerous) != RiskDangerous ||
		FoldRisks(RiskSafe, RiskUnknown, RiskDangerous) != RiskUnknown {
		t.Fatal("FoldRisks 顺序无关或吸收律校验失败")
	}
	if FoldThresholds(RiskDangerous, RiskSafe, RiskModerate) != RiskSafe ||
		FoldThresholds(RiskModerate, RiskDangerous, RiskSafe) != RiskSafe ||
		FoldThresholds(RiskDangerous, RiskUnknown) != RiskUnknown {
		t.Fatal("FoldThresholds 顺序无关或吸收律校验失败")
	}
}

func assertRiskBinaryAndAssocLaws(t *testing.T, a RiskLevel, samples []RiskLevel) {
	t.Helper()
	for _, b := range samples {
		if a.Join(b) != b.Join(a) || a.StrictestThreshold(b) != b.StrictestThreshold(a) {
			t.Fatalf("RiskLevel 违反交换律: a=%v b=%v", a, b)
		}
		assertRiskAssocAndMono(t, a, b, samples)
	}
}

func assertRiskAssocAndMono(t *testing.T, a, b RiskLevel, samples []RiskLevel) {
	t.Helper()
	for _, c := range samples {
		if a.Join(b).Join(c) != a.Join(b.Join(c)) ||
			a.StrictestThreshold(b).StrictestThreshold(c) != a.StrictestThreshold(b.StrictestThreshold(c)) {
			t.Fatalf("RiskLevel 违反结合律: %v %v %v", a, b, c)
		}
		if a.CompareSeverity(b) <= 0 && a.Join(c).CompareSeverity(b.Join(c)) > 0 {
			t.Fatalf("RiskLevel.Join 违反单调律: %v %v %v", a, b, c)
		}
		if a.CompareThresholdStrictness(b) <= 0 && a.StrictestThreshold(c).CompareThresholdStrictness(b.StrictestThreshold(c)) > 0 {
			t.Fatalf("RiskLevel.StrictestThreshold 违反单调律: %v %v %v", a, b, c)
		}
	}
}

func assertEvaluateThresholdMonotonicity(t *testing.T, samples []RiskLevel) {
	t.Helper()
	if EvaluateThreshold(RiskUnknown, RiskDangerous).Kind() != DecisionKindDeny ||
		EvaluateThreshold(RiskSafe, RiskUnknown).Kind() != DecisionKindDeny ||
		EvaluateThreshold(RiskSafe, RiskModerate).Kind() != DecisionKindAllow ||
		EvaluateThreshold(RiskModerate, RiskModerate).Kind() != DecisionKindNeedApproval {
		t.Fatal("EvaluateThreshold 基础边界判定异常")
	}
	for _, x := range samples {
		for _, y := range samples {
			assertEvaluateMonotonePair(t, x, y, samples)
		}
	}
}

func assertEvaluateMonotonePair(t *testing.T, x, y RiskLevel, samples []RiskLevel) {
	t.Helper()
	for _, fixed := range samples {
		if x.CompareSeverity(y) <= 0 && EvaluateThreshold(x, fixed).Kind().CompareStrictness(EvaluateThreshold(y, fixed).Kind()) > 0 {
			t.Fatalf("EvaluateThreshold 对风险升序违反单调律: %v <= %v (th=%v)", x, y, fixed)
		}
		if x.CompareThresholdStrictness(y) <= 0 && EvaluateThreshold(fixed, x).Kind().CompareStrictness(EvaluateThreshold(fixed, y).Kind()) > 0 {
			t.Fatalf("EvaluateThreshold 对阈值收紧违反单调律: %v <= %v (risk=%v)", x, y, fixed)
		}
	}
}

func assertRiskCodec(t *testing.T) {
	t.Helper()
	if _, err := RiskUnknown.MarshalText(); !errors.Is(err, ErrInvalidRiskLevel) {
		t.Fatalf("RiskUnknown.MarshalText 期望 ErrInvalidRiskLevel，实际=%v", err)
	}
	for _, r := range []RiskLevel{RiskSafe, RiskModerate, RiskDangerous} {
		raw, err := jsonv2.Marshal(r, jsonv2.Deterministic(true))
		var out RiskLevel
		if err != nil || jsonv2.Unmarshal(raw, &out) != nil || out != r {
			t.Fatalf("RiskLevel JSON 往返失败: raw=%s out=%v want=%v err=%v", raw, out, r, err)
		}
	}
	for _, bad := range []string{"", "unknown", "SAFE", "low", "high", "moderate "} {
		r := RiskSafe
		if err := r.UnmarshalText([]byte(bad)); !errors.Is(err, ErrInvalidRiskLevel) || r != RiskUnknown {
			t.Fatalf("RiskLevel.UnmarshalText(%q) 应重置为 RiskUnknown: r=%v err=%v", bad, r, err)
		}
	}
	var nilR *RiskLevel
	if err := nilR.UnmarshalText([]byte("safe")); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil RiskLevel.UnmarshalText 期望 ErrNilReceiver，实际=%v", err)
	}
}

func TestGuardrailDecisionSealedAndLatticeLaws(t *testing.T) {
	assertInvalidDecisionsFailClosed(t)
	samples := buildDecisionSamples(t)
	denyA := NewDecisionDenyWithCode("policy_block", "blocked by rule A")
	for _, a := range samples {
		if !EqualDecision(JoinDecisions(a, a), NormalizeDecision(a)) {
			t.Fatalf("JoinDecisions 违反幂等律: a=%#v", a)
		}
		if JoinDecisions(a, denyA).Kind() != DecisionKindDeny || JoinDecisions(denyA, a).Kind() != DecisionKindDeny {
			t.Fatalf("JoinDecisions 违反 Deny 吸收律: a=%#v", a)
		}
		assertDecisionBinaryAndAssocLaws(t, a, samples)
	}
	assertDecisionFoldAndSwitch(t)
	assertDecisionKindLatticeAndCodec(t)
}

func assertInvalidDecisionsFailClosed(t *testing.T) {
	t.Helper()
	var typedNilAllow *DecisionAllow
	var typedNilApproval *DecisionNeedApproval
	var typedNilDeny *DecisionDeny
	for name, d := range map[string]GuardrailDecision{
		"nil": nil, "zeroAllow": &DecisionAllow{}, "zeroApproval": &DecisionNeedApproval{},
		"typedNilAllow": typedNilAllow, "typedNilApproval": typedNilApproval, "typedNilDeny": typedNilDeny,
	} {
		if d != nil && (d.IsValid() || d.Kind() != DecisionKindDeny || d.ToVerdict() != VerdictDeny) {
			t.Fatalf("无效决策 %s 未失败关闭", name)
		}
		if norm := NormalizeDecision(d); norm.Kind() != DecisionKindDeny || norm.ToVerdict() != VerdictDeny {
			t.Fatalf("NormalizeDecision(%s) 未折叠为 *DecisionDeny", name)
		}
	}
	if _, err := NewDecisionNeedApproval(RiskUnknown, "bad"); !errors.Is(err, ErrInvalidRiskLevel) {
		t.Fatalf("NewDecisionNeedApproval(RiskUnknown) 期望 ErrInvalidRiskLevel，实际=%v", err)
	}
}

func buildDecisionSamples(t *testing.T) []GuardrailDecision {
	t.Helper()
	naMod, err := NewDecisionNeedApproval(RiskModerate, "moderate approval")
	if err != nil {
		t.Fatalf("NewDecisionNeedApproval(Moderate) 失败: %v", err)
	}
	naDanger, err := NewDecisionNeedApproval(RiskDangerous, "dangerous approval")
	if err != nil {
		t.Fatalf("NewDecisionNeedApproval(Dangerous) 失败: %v", err)
	}
	var typedNilAllow *DecisionAllow
	return []GuardrailDecision{
		nil, &DecisionAllow{}, &DecisionNeedApproval{}, typedNilAllow,
		NewDecisionDenyWithCode("policy_block", "blocked by rule A"),
		NewDecisionDenyWithCode("root_path", "blocked by rule B"),
		NewDecisionDeny(""), naMod, naDanger,
		NewDecisionAllow("allow A"), NewDecisionAllow("allow B"), NewDecisionAllow(""),
	}
}

func assertDecisionFoldAndSwitch(t *testing.T) {
	t.Helper()
	naMod, _ := NewDecisionNeedApproval(RiskModerate, "moderate")
	naDanger, _ := NewDecisionNeedApproval(RiskDangerous, "dangerous")
	allowA, allowB := NewDecisionAllow("a"), NewDecisionAllow("b")
	if FoldDecisions().Kind() != DecisionKindDeny {
		t.Fatal("空 FoldDecisions() 必须失败关闭返回 *DecisionDeny")
	}
	baseFold := FoldDecisions(allowA, naMod, naDanger, allowB)
	wantFold := FoldDecisions(naDanger, allowB, allowA, naMod)
	if !EqualDecision(baseFold, wantFold) || baseFold.Kind() != DecisionKindNeedApproval {
		t.Fatal("FoldDecisions 顺序依赖或类别错误")
	}
	if na, ok := baseFold.(*DecisionNeedApproval); !ok || na.Risk() != RiskDangerous {
		t.Fatalf("FoldDecisions NeedApproval 应保留最高风险 Dangerous: %#v", baseFold)
	}
	for _, d := range []GuardrailDecision{NewDecisionDeny("d"), naMod, allowA, nil} {
		want := DecisionKindDeny
		if d != nil {
			want = d.Kind()
		}
		if got := classifyDecisionExhaustive(d); got != want {
			t.Fatalf("exhaustive switch = %v, want %v", got, want)
		}
	}
}

func assertDecisionBinaryAndAssocLaws(t *testing.T, a GuardrailDecision, samples []GuardrailDecision) {
	t.Helper()
	for _, b := range samples {
		ab, ba := JoinDecisions(a, b), JoinDecisions(b, a)
		if !EqualDecision(ab, ba) {
			t.Fatalf("JoinDecisions 违反交换律: ab=%#v ba=%#v", ab, ba)
		}
		if ab.Kind().CompareStrictness(NormalizeDecision(a).Kind()) < 0 ||
			ab.Kind().CompareStrictness(NormalizeDecision(b).Kind()) < 0 {
			t.Fatal("JoinDecisions 违反单调收紧律")
		}
		for _, c := range samples {
			if !EqualDecision(JoinDecisions(JoinDecisions(a, b), c), JoinDecisions(a, JoinDecisions(b, c))) {
				t.Fatal("JoinDecisions 违反结合律")
			}
		}
	}
}

func classifyDecisionExhaustive(d GuardrailDecision) DecisionKind {
	switch v := d.(type) {
	case *DecisionDeny:
		return v.Kind()
	case *DecisionNeedApproval:
		return v.Kind()
	case *DecisionAllow:
		return v.Kind()
	default:
		return DecisionKindDeny
	}
}

func assertDecisionKindLatticeAndCodec(t *testing.T) {
	t.Helper()
	kinds := []DecisionKind{DecisionKindDeny, DecisionKindNeedApproval, DecisionKindAllow, DecisionKind(9)}
	for _, a := range kinds {
		assertDecisionKindLawsFor(t, a, kinds)
	}
	for _, k := range []DecisionKind{DecisionKindDeny, DecisionKindNeedApproval, DecisionKindAllow} {
		raw, err := jsonv2.Marshal(k, jsonv2.Deterministic(true))
		var out DecisionKind
		if err != nil || jsonv2.Unmarshal(raw, &out) != nil || out != k {
			t.Fatalf("DecisionKind JSON 往返失败: raw=%s out=%v want=%v err=%v", raw, out, k, err)
		}
	}
	if _, err := DecisionKind(8).MarshalText(); !errors.Is(err, ErrInvalidDecision) {
		t.Fatalf("非法 DecisionKind.MarshalText 期望 ErrInvalidDecision，实际=%v", err)
	}
	var nilK *DecisionKind
	if err := nilK.UnmarshalText([]byte("allow")); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil DecisionKind.UnmarshalText 期望 ErrNilReceiver，实际=%v", err)
	}
}

func assertDecisionKindLawsFor(t *testing.T, a DecisionKind, kinds []DecisionKind) {
	t.Helper()
	for _, b := range kinds {
		if a.Join(b) != b.Join(a) {
			t.Fatalf("DecisionKind.Join 违反交换律: %v %v", a, b)
		}
		for _, c := range kinds {
			if a.Join(b).Join(c) != a.Join(b.Join(c)) {
				t.Fatalf("DecisionKind.Join 违反结合律: %v %v %v", a, b, c)
			}
		}
	}
}

func mustOverrideRule(t *testing.T, pattern string, th RiskLevel, floor DecisionKind) NodeOverrideRule {
	t.Helper()
	r, err := NewNodeOverrideRuleWithFloor(pattern, th, floor)
	if err != nil {
		t.Fatalf("NewNodeOverrideRuleWithFloor(%q) 失败: %v", pattern, err)
	}
	return r
}

func TestNodeOverridesLatticeAndOrderIndependence(t *testing.T) {
	assertNodeOverridesZeroFailClosed(t)
	rStar := mustOverrideRule(t, "*", RiskDangerous, DecisionKindAllow)
	rProd := mustOverrideRule(t, "prod-*", RiskModerate, DecisionKindAllow)
	rProdDB := mustOverrideRule(t, "prod-db-*", RiskSafe, DecisionKindAllow)
	rProdStrict := mustOverrideRule(t, "prod-*", RiskSafe, DecisionKindNeedApproval)
	rBlocked := mustOverrideRule(t, "legacy-*", RiskSafe, DecisionKindDeny)

	o1, err := NewNodeOverrides(rStar, rProd, rProdDB, rProdStrict)
	o2, err2 := NewNodeOverrides(rProdStrict, rProdDB, rStar, rProd)
	if err != nil || err2 != nil || !o1.Equal(o2) || o1.Len() != 3 {
		t.Fatalf("NodeOverrides 未消除顺序依赖: errs=(%v,%v) len=%d", err, err2, o1.Len())
	}
	assertNodeOverrideResolution(t, o1)
	assertNodeOverridesJoinLaws(t, rStar, rProd, rProdDB, rProdStrict, rBlocked)
	assertNodeOverridesMapAndCodec(t)
}

func assertNodeOverridesZeroFailClosed(t *testing.T) {
	t.Helper()
	var zero NodeOverrides
	if zero.IsValid() || !zero.IsZero() ||
		zero.EvaluateNode(RiskModerate, RiskSafe, "prod-01").Kind() != DecisionKindDeny ||
		zero.EvaluateBatch(RiskModerate, RiskSafe, "prod-01").Kind() != DecisionKindDeny {
		t.Fatal("零值 NodeOverrides 未失败关闭")
	}
	if _, err := zero.ResolveThreshold(RiskModerate, "prod-01"); !errors.Is(err, ErrInvalidNodeOverride) {
		t.Fatalf("零值 ResolveThreshold 期望 ErrInvalidNodeOverride，实际=%v", err)
	}
	if _, err := zero.ResolveBatchThreshold(RiskModerate, "prod-01"); !errors.Is(err, ErrInvalidNodeOverride) {
		t.Fatalf("零值 ResolveBatchThreshold 期望 ErrInvalidNodeOverride，实际=%v", err)
	}
	if _, err := jsonv2.Marshal(zero); !errors.Is(err, ErrInvalidNodeOverride) {
		t.Fatalf("零值 Marshal 期望 ErrInvalidNodeOverride，实际=%v", err)
	}
}

func assertNodeOverrideResolution(t *testing.T, o NodeOverrides) {
	t.Helper()
	if th, err := o.ResolveThreshold(RiskModerate, ""); err != nil || th != RiskModerate {
		t.Fatalf("空 nodeID 期望基准阈值 Moderate，实际=(%v,%v)", th, err)
	}
	if th, err := o.ResolveThreshold(RiskModerate, "dev-01"); err != nil || th != RiskDangerous {
		t.Fatalf("dev-01 期望命中 * -> Dangerous，实际=(%v,%v)", th, err)
	}
	if th, err := o.ResolveThreshold(RiskDangerous, "prod-db-01"); err != nil || th != RiskSafe {
		t.Fatalf("prod-db-01 期望折叠为 Safe，实际=(%v,%v)", th, err)
	}
	thA, errA := o.ResolveBatchThreshold(RiskModerate, "dev-01", "prod-db-01")
	thB, errB := o.ResolveBatchThreshold(RiskModerate, "prod-db-01", "dev-01")
	if errA != nil || errB != nil || thA != RiskSafe || thB != RiskSafe {
		t.Fatalf("多节点阈值折叠顺序相关: A=(%v,%v) B=(%v,%v)", thA, errA, thB, errB)
	}
}

func assertNodeOverridesJoinLaws(t *testing.T, rStar, rProd, rProdDB, rProdStrict, rBlocked NodeOverrideRule) {
	t.Helper()
	setA, _ := NewNodeOverrides(rStar, rProd)
	setB, _ := NewNodeOverrides(rProdDB, rProdStrict)
	setC, _ := NewNodeOverrides(rBlocked)
	empty := EmptyNodeOverrides()
	var zero NodeOverrides
	for _, x := range []NodeOverrides{empty, setA, setB, setC} {
		if !x.Join(empty).Equal(x) || !empty.Join(x).Equal(x) || !x.Join(x).Equal(x) {
			t.Fatal("NodeOverrides.Join 违反单位元或幂等律")
		}
		if x.Join(zero).IsValid() || zero.Join(x).IsValid() {
			t.Fatal("NodeOverrides.Join 违反零值吸收律")
		}
	}
	if !setA.Join(setB).Equal(setB.Join(setA)) || !setA.Join(setB).Join(setC).Equal(setA.Join(setB.Join(setC))) {
		t.Fatal("NodeOverrides.Join 违反交换律或结合律")
	}
	joined := setA.Join(setB).Join(setC)
	if joined.EvaluateNode(RiskDangerous, RiskSafe, "dev-01").Kind() != DecisionKindAllow ||
		joined.EvaluateBatch(RiskDangerous, RiskSafe, "dev-01", "legacy-01").Kind() != DecisionKindDeny ||
		joined.EvaluateBatch(RiskDangerous, RiskSafe, "legacy-01", "dev-01").Kind() != DecisionKindDeny {
		t.Fatal("NodeOverrides.EvaluateNode/EvaluateBatch 顺序无关或拒绝下限判定异常")
	}
}

func assertNodeOverridesMapAndCodec(t *testing.T) {
	t.Helper()
	fromMap, err := NewNodeOverridesFromMap(map[string]RiskLevel{"zeta-*": RiskDangerous, "alpha-*": RiskSafe, "mid-*": RiskModerate})
	if err != nil {
		t.Fatalf("NewNodeOverridesFromMap 失败: %v", err)
	}
	raw, err := jsonv2.Marshal(fromMap, jsonv2.Deterministic(true))
	var decoded NodeOverrides
	if err != nil || jsonv2.Unmarshal(raw, &decoded) != nil || !decoded.Equal(fromMap) {
		t.Fatalf("NodeOverrides JSON 往返失败: raw=%s err=%v", raw, err)
	}
	if _, err := NewNodeOverridesFromMap(map[string]RiskLevel{"prod-[unclosed": RiskSafe}); !errors.Is(err, ErrInvalidNodeOverride) {
		t.Fatalf("非法 glob 期望 ErrInvalidNodeOverride，实际=%v", err)
	}
	if _, err := NewNodeOverridesFromMap(map[string]RiskLevel{"prod-*": RiskUnknown}); !errors.Is(err, ErrInvalidRiskLevel) {
		t.Fatalf("RiskUnknown 阈值期望 ErrInvalidRiskLevel，实际=%v", err)
	}
}

func TestScopeSnapshotLatticeFoldLaws(t *testing.T) {
	ep, _ := netaddr.ParseEndpoint("10.0.0.10:22")
	naMod, _ := NewDecisionNeedApproval(RiskModerate, "protected ancestor")
	s1 := mustSnapshot(t, ScopeSnapshotSpec{
		Capability: CapabilityFileRead, TargetNode: "web-01", Endpoint: algebraic.Some(ep),
		Verdict: VerdictAllow, Risk: RiskSafe, Decision: NewDecisionAllow("lexical safe"),
		Paths: []ScopedPath{mustScopedPath(t, "/var/app/link", false)},
	})
	s2 := mustSnapshot(t, ScopeSnapshotSpec{
		Capability: CapabilityFileRead, TargetNode: "web-01", Endpoint: algebraic.Some(ep),
		Verdict: VerdictAllow, Risk: RiskModerate, Decision: naMod,
		Paths: []ScopedPath{mustScopedPath(t, "/etc", false, "/etc/**"), mustScopedPath(t, "/etc/app.conf", false, "/etc/**")},
	})
	s3 := mustSnapshot(t, ScopeSnapshotSpec{
		Capability: CapabilityFileRead, TargetNode: "web-01", Endpoint: algebraic.Some(ep),
		Verdict: VerdictDeny, Risk: RiskDangerous, Decision: NewDecisionDenyWithCode("protected_write", "denied"),
		Paths: []ScopedPath{mustScopedPath(t, "/etc/app.conf", true, "/etc/app/**")},
	})
	if !s1.Join(s2).Equal(s2.Join(s1)) || !s1.Join(s2).Join(s3).Equal(s1.Join(s2.Join(s3))) || !s2.Join(s2).Equal(s2) {
		t.Fatal("ScopeSnapshot.Join 违反交换/结合/幂等律")
	}
	folded := FoldScopeSnapshots(s1, s2, s3)
	if FoldScopeSnapshots().IsValid() || !folded.Equal(FoldScopeSnapshots(s3, s1, s2)) ||
		folded.Verdict() != VerdictDeny || folded.Risk() != RiskDangerous || folded.Decision().Kind() != DecisionKindDeny {
		t.Fatal("FoldScopeSnapshots 折叠不变量失败")
	}
	paths := folded.Paths()
	idx := slices.IndexFunc(paths, func(p ScopedPath) bool { return p.Path() == "/etc/app.conf" })
	if idx < 0 || !paths[idx].IsRecursive() || !slices.Equal(paths[idx].ProtectedZones(), []string{"/etc/**", "/etc/app/**"}) {
		t.Fatalf("同路径格合并异常: paths=%+v", paths)
	}
	otherNode := mustSnapshot(t, ScopeSnapshotSpec{
		Capability: CapabilityFileRead, TargetNode: "db-01", Endpoint: algebraic.Some(ep),
		Verdict: VerdictAllow, Risk: RiskSafe, Decision: NewDecisionAllow("ok"),
	})
	if s1.Join(otherNode).IsValid() {
		t.Fatal("不同 TargetNode 的 ScopeSnapshot 合并必须失败关闭")
	}
}

func TestNodeOverridesBatchMonotonicityAndInvalidNodeID(t *testing.T) {
	o, err := NewNodeOverrides(mustOverrideRule(t, "dev-*", RiskDangerous, DecisionKindAllow))
	if err != nil {
		t.Fatalf("NewNodeOverrides 失败: %v", err)
	}
	// 单节点允许 dev-* 放宽至 Dangerous -> EvaluateNode 放行 Moderate
	if th, err := o.ResolveThreshold(RiskModerate, "dev-01"); err != nil || th != RiskDangerous {
		t.Fatalf("单节点 dev-01 应放宽为 Dangerous: th=%v err=%v", th, err)
	}
	if d := o.EvaluateNode(RiskModerate, RiskModerate, "dev-01"); d.Kind() != DecisionKindAllow {
		t.Fatalf("单节点 EvaluateNode(dev-01) 期望 Allow，实际=%v", d.Kind())
	}
	// 批量求值必须严格单调 >= baseThreshold（Moderate），绝不因 dev-* 放宽而弱化全局策略
	if th, err := o.ResolveBatchThreshold(RiskModerate, "dev-01"); err != nil || th != RiskModerate {
		t.Fatalf("批量 ResolveBatchThreshold(dev-01) 必须保持 >= Moderate: th=%v err=%v", th, err)
	}
	if d := o.EvaluateBatch(RiskModerate, RiskModerate, "dev-01"); d.Kind() != DecisionKindNeedApproval {
		t.Fatalf("批量 EvaluateBatch(dev-01) 必须保持 NeedApproval，实际=%v", d.Kind())
	}
	// EmptyNodeOverrides 对非法 UTF-8 / 控制字符 / 空白 / Unicode Cf 节点标识必须失败关闭
	empty := EmptyNodeOverrides()
	for _, bad := range []string{string([]byte{0xff}), "web\n01", "web 01", "web\u202e01", strings.Repeat("a", maxOperationIDLen+1)} {
		if _, err := empty.ResolveThreshold(RiskModerate, bad); !errors.Is(err, ErrInvalidNodeOverride) {
			t.Fatalf("EmptyNodeOverrides.ResolveThreshold(%q) 未失败关闭: err=%v", bad, err)
		}
		if _, err := empty.ResolveBatchThreshold(RiskModerate, bad); !errors.Is(err, ErrInvalidNodeOverride) {
			t.Fatalf("EmptyNodeOverrides.ResolveBatchThreshold(%q) 未失败关闭: err=%v", bad, err)
		}
		if empty.EvaluateNode(RiskModerate, RiskSafe, bad).Kind() != DecisionKindDeny ||
			empty.EvaluateBatch(RiskModerate, RiskSafe, bad).Kind() != DecisionKindDeny {
			t.Fatalf("EmptyNodeOverrides.Evaluate*(%q) 未失败关闭为 Deny", bad)
		}
	}
}

func TestJoinDecisionsPreservesHigherRiskReason(t *testing.T) {
	lowA, _ := NewDecisionNeedApproval(RiskSafe, "audit log check")
	highZ, _ := NewDecisionNeedApproval(RiskDangerous, "overwrite /etc/shadow")
	ab := JoinDecisions(lowA, highZ)
	ba := JoinDecisions(highZ, lowA)
	naAB, okAB := ab.(*DecisionNeedApproval)
	naBA, okBA := ba.(*DecisionNeedApproval)
	if !okAB || !okBA || !EqualDecision(ab, ba) {
		t.Fatalf("JoinDecisions 未保持交换律或类型: ab=%#v ba=%#v", ab, ba)
	}
	if naAB.Risk() != RiskDangerous || naAB.Reason() != "overwrite /etc/shadow" || naBA.Reason() != "overwrite /etc/shadow" {
		t.Fatalf("高风险原因被低风险字典序靠前原因遮蔽: ab=(%v,%q) ba=(%v,%q)", naAB.Risk(), naAB.Reason(), naBA.Risk(), naBA.Reason())
	}
}

func TestDecisionJSONv2DirectAndPolymorphicFailClosed(t *testing.T) {
	assertDecisionDirectMarshal(t)
	assertDecisionStreamMarshalErrors(t)
	assertDecisionStreamUnmarshalFailClosed(t)
}

func assertDecisionDirectMarshal(t *testing.T) {
	t.Helper()
	na, _ := NewDecisionNeedApproval(RiskDangerous, "confirm")
	for _, valid := range []any{NewDecisionDenyWithCode("blk", "denied"), DecisionDeny{}, na, NewDecisionAllow("ok")} {
		raw, err := jsonv2.Marshal(valid, jsonv2.Deterministic(true))
		if err != nil {
			t.Fatalf("合法变体直接 Marshal 失败: %T err=%v", valid, err)
		}
		got, uErr := UnmarshalDecisionFrom(jsontext.NewDecoder(bytes.NewReader(raw)))
		if uErr != nil || got == nil || !got.IsValid() {
			t.Fatalf("直接 Marshal 产物无法往返解码: raw=%s err=%v", raw, uErr)
		}
	}
	for _, invalid := range []any{DecisionAllow{}, &DecisionAllow{}, DecisionNeedApproval{}, &DecisionNeedApproval{}} {
		if _, err := jsonv2.Marshal(invalid); !errors.Is(err, ErrInvalidDecision) {
			t.Fatalf("零值/无效变体 %T 期望 ErrInvalidDecision，实际=%v", invalid, err)
		}
	}
}

func assertDecisionStreamMarshalErrors(t *testing.T) {
	t.Helper()
	if err := MarshalDecisionTo(nil, NewDecisionDeny("d")); !errors.Is(err, ErrNilWriter) {
		t.Fatalf("MarshalDecisionTo(nil) 期望 ErrNilWriter，实际=%v", err)
	}
	var typedNilAllow *DecisionAllow
	for _, bad := range []GuardrailDecision{nil, typedNilAllow, &DecisionAllow{}, &DecisionNeedApproval{}} {
		var buf bytes.Buffer
		if err := MarshalDecisionTo(jsontext.NewEncoder(&buf), bad); !errors.Is(err, ErrInvalidDecision) {
			t.Fatalf("MarshalDecisionTo(%#v) 期望 ErrInvalidDecision，实际=%v", bad, err)
		}
	}
}

func assertDecisionStreamUnmarshalFailClosed(t *testing.T) {
	t.Helper()
	if _, err := UnmarshalDecisionFrom(nil); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("UnmarshalDecisionFrom(nil) 期望 ErrNilReceiver，实际=%v", err)
	}
	for _, raw := range []string{
		`null`, `{}`, `{"kind":null}`, `{"kind":"need_approval"}`, `{"kind":"need_approval","risk":null}`,
		`{"kind":"deny","risk":"safe"}`, `{"kind":"allow","code":"x"}`, `{"kind":"allow","risk":"safe"}`,
	} {
		if got, err := UnmarshalDecisionFrom(jsontext.NewDecoder(strings.NewReader(raw))); !errors.Is(err, ErrInvalidDecision) || got != nil {
			t.Fatalf("UnmarshalDecisionFrom(%s) 未失败关闭: got=%#v err=%v", raw, got, err)
		}
	}
	// 畸形前缀 "nul" 必须透传底层语法错误而非误报 ErrInvalidDecision
	if _, err := UnmarshalDecisionFrom(jsontext.NewDecoder(strings.NewReader("nul"))); err == nil || errors.Is(err, ErrInvalidDecision) {
		t.Fatalf("畸形 JSON \"nul\" 应返回底层语法错误，实际=%v", err)
	}
}

func TestNodeOverrideJSONNullAndOmittedFieldsFailClosed(t *testing.T) {
	seedRule := mustOverrideRule(t, "prod-*", RiskSafe, DecisionKindAllow)
	for _, raw := range []string{
		`null`, `{}`,
		`{"pattern":"prod-*","approval_threshold":"safe"}`,
		`{"pattern":"prod-*","approval_threshold":"safe","decision_floor":null}`,
		`{"pattern":null,"approval_threshold":"safe","decision_floor":"allow"}`,
		`{"pattern":"prod-*","approval_threshold":null,"decision_floor":"allow"}`,
	} {
		target := seedRule
		if err := jsonv2.Unmarshal([]byte(raw), &target); !errors.Is(err, ErrInvalidNodeOverride) || target.IsValid() {
			t.Fatalf("NodeOverrideRule.Unmarshal(%s) 未失败关闭: valid=%v err=%v", raw, target.IsValid(), err)
		}
	}
	seedSet, _ := NewNodeOverrides(seedRule)
	for _, raw := range []string{`null`, `[null]`, `[{"pattern":"prod-*","approval_threshold":"safe"}]`} {
		target := seedSet
		if err := jsonv2.Unmarshal([]byte(raw), &target); !errors.Is(err, ErrInvalidNodeOverride) || target.IsValid() {
			t.Fatalf("NodeOverrides.Unmarshal(%s) 未失败关闭: valid=%v err=%v", raw, target.IsValid(), err)
		}
	}
	var badSet NodeOverrides
	if err := jsonv2.Unmarshal([]byte("nul"), &badSet); err == nil || errors.Is(err, ErrInvalidNodeOverride) {
		t.Fatalf("NodeOverrides 畸形 JSON \"nul\" 应返回语法错误，实际=%v", err)
	}
}
