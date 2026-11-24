package algebraic

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"math"
	"slices"
	"testing"
	"time"
)

func TestOptionZeroAndExplicitZeroSemantics(t *testing.T) {
	none := None[int]()
	if none.IsSome() || !none.IsNone() || !none.IsZero() {
		t.Fatalf("None 零值谓词错误: some=%v none=%v zero=%v", none.IsSome(), none.IsNone(), none.IsZero())
	}
	if v, ok := none.Get(); ok || v != 0 || none.OrElse(42) != 42 {
		t.Fatalf("None 提取错误: v=%d ok=%v orElse=%d", v, ok, none.OrElse(42))
	}

	// 显式设置零值必须与未设置精确区分
	someZero := Some(0)
	if !someZero.IsSome() || someZero.IsNone() || someZero.IsZero() {
		t.Fatalf("Some(0) 谓词错误: some=%v none=%v zero=%v", someZero.IsSome(), someZero.IsNone(), someZero.IsZero())
	}
	if v, ok := someZero.Get(); !ok || v != 0 || someZero.OrElse(42) != 0 {
		t.Fatalf("Some(0) 提取错误: v=%d ok=%v orElse=%d", v, ok, someZero.OrElse(42))
	}
	if EqualOption(none, someZero) {
		t.Fatal("None 与 Some(0) 不得相等")
	}

	// OptionFromPtr 应按值拷贝并隔离后续指针修改
	if !OptionFromPtr((*int)(nil)).IsNone() {
		t.Fatal("OptionFromPtr(nil) 应返回 None")
	}
	raw := 7
	fromPtr := OptionFromPtr(&raw)
	raw = 99
	if got := fromPtr.OrElse(-1); got != 7 {
		t.Fatalf("OptionFromPtr 必须按值拷贝，实际=%d", got)
	}
}

func TestOptionMonoidLaws(t *testing.T) {
	none := None[int]()
	samples := []Option[int]{none, Some(0), Some(1), Some(2)}
	for _, a := range samples {
		if !EqualOption(none.Or(a), a) || !EqualOption(a.Or(none), a) {
			t.Fatalf("Option.Or 违反单位元律: a=%+v", a)
		}
		if !EqualOption(a.Or(a), a) {
			t.Fatalf("Option.Or 违反幂等律: a=%+v", a)
		}
		assertOptionAssociative(t, a, samples)
	}
}

func assertOptionAssociative(t *testing.T, a Option[int], samples []Option[int]) {
	t.Helper()
	for _, b := range samples {
		for _, c := range samples {
			if !EqualOption(a.Or(b).Or(c), a.Or(b.Or(c))) {
				t.Fatalf("Option.Or 违反结合律: a=%+v b=%+v c=%+v", a, b, c)
			}
		}
	}
}

func TestOptionJSONv2RoundTripAndOmitZero(t *testing.T) {
	type payload struct {
		Port    Option[uint16]   `json:"port,omitzero"`
		Timeout Option[Duration] `json:"timeout,omitzero"`
		Label   Option[string]   `json:"label"`
	}

	rawEmpty, err := jsonv2.Marshal(payload{}, jsonv2.Deterministic(true))
	if err != nil || string(rawEmpty) != `{"label":null}` {
		t.Fatalf("Marshal(empty) = (%s, %v), 期望 %s", rawEmpty, err, `{"label":null}`)
	}

	explicitZero := payload{
		Port:    Some[uint16](0),
		Timeout: Some(ZeroDuration()),
		Label:   Some(""),
	}
	rawZero, err := jsonv2.Marshal(explicitZero, jsonv2.Deterministic(true))
	wantZero := `{"port":0,"timeout":"0s","label":""}`
	if err != nil || string(rawZero) != wantZero {
		t.Fatalf("Marshal(explicitZero) = (%s, %v), 期望 %s", rawZero, err, wantZero)
	}

	var decoded payload
	if err := jsonv2.Unmarshal(rawZero, &decoded); err != nil {
		t.Fatalf("Unmarshal(rawZero) 失败: %v", err)
	}
	if !EqualOption(decoded.Port, Some[uint16](0)) ||
		!EqualOption(decoded.Timeout, Some(ZeroDuration())) ||
		!EqualOption(decoded.Label, Some("")) {
		t.Fatalf("Unmarshal(rawZero) 未保留显式零值: %+v", decoded)
	}
}

func TestOptionJSONv2ResetAndNilReceiver(t *testing.T) {
	opt := Some(123)
	if err := jsonv2.Unmarshal([]byte(`null`), &opt); err != nil || !opt.IsNone() {
		t.Fatalf("Unmarshal(null) = (%+v, %v), 期望 None", opt, err)
	}
	opt = Some(456)
	if err := jsonv2.Unmarshal([]byte(`"not-an-int"`), &opt); err == nil || !opt.IsNone() {
		t.Fatalf("Unmarshal 失败后应重置为 None: opt=%+v err=%v", opt, err)
	}
	var nilOpt *Option[int]
	dec := jsontext.NewDecoder(bytes.NewReader([]byte(`1`)))
	if err := nilOpt.UnmarshalJSONFrom(dec); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil Option.UnmarshalJSONFrom = %v, 期望 ErrNilReceiver", err)
	}
}

func TestNonEmptyZeroAndConstructors(t *testing.T) {
	var zero NonEmpty[string]
	if zero.IsValid() || !zero.IsZero() || zero.Len() != 0 || zero.Slice() != nil || zero.Tail() != nil {
		t.Fatalf("NonEmpty 零值状态非法: valid=%v zero=%v len=%d", zero.IsValid(), zero.IsZero(), zero.Len())
	}
	if _, ok := zero.Head(); ok {
		t.Fatal("零值 Head() 应返回 false")
	}
	if _, ok := zero.At(0); ok {
		t.Fatal("零值 At(0) 应返回 false")
	}
	if EqualNonEmpty(zero, zero) || zero.Append("x").IsValid() {
		t.Fatal("零值 NonEmpty 的 Equal 与 Append 必须严格失败关闭")
	}
	if _, err := NonEmptyFromSlice([]string(nil)); !errors.Is(err, ErrEmptySlice) {
		t.Fatalf("NonEmptyFromSlice(nil) = %v, 期望 ErrEmptySlice", err)
	}
	if _, err := NonEmptyFromSlice([]string{}); !errors.Is(err, ErrEmptySlice) {
		t.Fatalf("NonEmptyFromSlice([]) = %v, 期望 ErrEmptySlice", err)
	}
}

func TestNonEmptyImmutabilityAndIteration(t *testing.T) {
	src := []string{"a", "b", "c"}
	ne, err := NonEmptyFromSlice(src)
	if err != nil {
		t.Fatalf("NonEmptyFromSlice 意外失败: %v", err)
	}
	src[0] = "mutated-src"
	exported := ne.Slice()
	exported[1] = "mutated-export"
	tail := ne.Tail()
	tail[0] = "mutated-tail"
	if got := ne.Slice(); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("防御性拷贝失效，内部元素被污染: %v", got)
	}

	h, okHead := ne.Head()
	v, okAt := ne.At(2)
	_, okNeg := ne.At(-1)
	_, okOOB := ne.At(3)
	if !okHead || h != "a" || !okAt || v != "c" || okNeg || okOOB {
		t.Fatalf("Head/At 结果异常: head=(%q,%v) at2=(%q,%v) neg=%v oob=%v", h, okHead, v, okAt, okNeg, okOOB)
	}

	var collected []string
	for item := range ne.All() {
		collected = append(collected, item)
	}
	if !slices.Equal(collected, []string{"a", "b", "c"}) {
		t.Fatalf("All() = %v, 期望 [a b c]", collected)
	}
	earlyCount := 0
	for range ne.All() {
		earlyCount++
		break
	}
	if earlyCount != 1 {
		t.Fatalf("All() 提前终止计数 = %d, 期望 1", earlyCount)
	}
}

func TestNonEmptyForEachSyncClosureAndFailClosed(t *testing.T) {
	var zero NonEmpty[string]
	if err := zero.ForEach(func(string) error { return nil }); !errors.Is(err, ErrEmptySlice) {
		t.Fatalf("零值 ForEach = %v, 期望 ErrEmptySlice", err)
	}
	ne := NewNonEmpty("a", "b", "c")
	if err := ne.ForEach(nil); !errors.Is(err, ErrNilCallback) {
		t.Fatalf("ForEach(nil) = %v, 期望 ErrNilCallback", err)
	}

	var visited []string
	if err := ne.ForEach(func(item string) error {
		visited = append(visited, item)
		return nil
	}); err != nil || !slices.Equal(visited, []string{"a", "b", "c"}) {
		t.Fatalf("ForEach 全量遍历异常: visited=%v err=%v", visited, err)
	}

	stopErr := errors.New("stop-early")
	visited = nil
	err := ne.ForEach(func(item string) error {
		visited = append(visited, item)
		if item == "b" {
			return stopErr
		}
		return nil
	})
	if !errors.Is(err, stopErr) || !slices.Equal(visited, []string{"a", "b"}) {
		t.Fatalf("ForEach 错误短路异常: visited=%v err=%v", visited, err)
	}
}

func TestNonEmptySemigroupLaws(t *testing.T) {
	var zero NonEmpty[string]
	a := NewNonEmpty("a")
	b := NewNonEmpty("b", "c")
	c := NewNonEmpty("d")
	if !EqualNonEmpty(a.Concat(b).Concat(c), a.Concat(b.Concat(c))) {
		t.Fatal("NonEmpty.Concat 违反结合律")
	}
	if !slices.Equal(a.Append("x", "y").Slice(), []string{"a", "x", "y"}) {
		t.Fatalf("Append 结果不符合预期: %v", a.Append("x", "y").Slice())
	}
	if a.Concat(zero).IsValid() || zero.Concat(a).IsValid() || zero.Concat(zero).IsValid() {
		t.Fatal("无效零值必须在 Concat 中作为失败关闭吸收元")
	}
}

func TestNonEmptyJSONv2RoundTripAndErrors(t *testing.T) {
	var zero NonEmpty[string]
	if _, err := jsonv2.Marshal(zero); !errors.Is(err, ErrEmptySlice) {
		t.Fatalf("Marshal(零值 NonEmpty) = %v, 期望包装 ErrEmptySlice", err)
	}
	ne := NewNonEmpty("a", "b", "c")
	data, err := jsonv2.Marshal(ne, jsonv2.Deterministic(true))
	if err != nil || string(data) != `["a","b","c"]` {
		t.Fatalf("Marshal(ne) = (%s, %v)", data, err)
	}
	var roundTripped NonEmpty[string]
	if err := jsonv2.Unmarshal(data, &roundTripped); err != nil || !EqualNonEmpty(ne, roundTripped) {
		t.Fatalf("NonEmpty JSON 往返失败: got=%v err=%v", roundTripped.Slice(), err)
	}

	for _, bad := range []string{`[]`, `null`, `"not-array"`, `[123]`} {
		target := NewNonEmpty("keep")
		if err := jsonv2.Unmarshal([]byte(bad), &target); err == nil || target.IsValid() {
			t.Fatalf("Unmarshal(%s) 应失败并重置零值: target=%v err=%v", bad, target.Slice(), err)
		}
	}
	// 畸形 null 前缀（如 "nul"）必须保留底层 *jsontext.SyntacticError，不得吞噬并误报 ErrEmptySlice
	malformedTarget := NewNonEmpty("keep")
	malformedErr := jsonv2.Unmarshal([]byte(`nul`), &malformedTarget)
	if _, ok := errors.AsType[*jsontext.SyntacticError](malformedErr); !ok || errors.Is(malformedErr, ErrEmptySlice) || malformedTarget.IsValid() {
		t.Fatalf("Unmarshal(nul) 期望 *jsontext.SyntacticError 且非 ErrEmptySlice 并重置零值: target=%v err=%v", malformedTarget.Slice(), malformedErr)
	}
	var nilNE *NonEmpty[string]
	dec := jsontext.NewDecoder(bytes.NewReader([]byte(`["x"]`)))
	if err := nilNE.UnmarshalJSONFrom(dec); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil NonEmpty.UnmarshalJSONFrom = %v, 期望 ErrNilReceiver", err)
	}
}

func TestFirstWinsSemanticsAndConversion(t *testing.T) {
	unset := UnsetFirstWins[string]()
	if unset.IsSet() || !unset.IsUnset() || !unset.IsZero() || !unset.ToOption().IsNone() {
		t.Fatal("UnsetFirstWins 零值谓词错误")
	}
	if v, ok := unset.Get(); ok || v != "" || unset.OrElse("fallback") != "fallback" {
		t.Fatalf("Unset 提取错误: v=%q ok=%v", v, ok)
	}

	a := NewFirstWins("cli")
	b := NewFirstWins("node")
	c := NewFirstWins("openssh")
	if EqualFirstWins(a.Combine(b), b.Combine(a)) {
		t.Fatal("不同已设置值的 FirstWins 不应满足交换律")
	}
	if got := FoldFirstWins(unset, a, b, c).OrElse(""); got != "cli" {
		t.Fatalf("FoldFirstWins = %q, 期望 cli", got)
	}
	if !FoldFirstWins[string]().IsUnset() {
		t.Fatal("空 FoldFirstWins 应返回单位元 Unset")
	}
	if !EqualFirstWins(FirstWinsFromOption(Some("x")), NewFirstWins("x")) ||
		!FirstWinsFromOption(None[string]()).IsUnset() ||
		!EqualOption(a.ToOption(), Some("cli")) {
		t.Fatal("FirstWins 与 Option 互转不一致")
	}
}

func TestFirstWinsMonoidLaws(t *testing.T) {
	unset := UnsetFirstWins[string]()
	samples := []FirstWins[string]{unset, NewFirstWins(""), NewFirstWins("cli"), NewFirstWins("node")}
	for _, x := range samples {
		if !EqualFirstWins(unset.Combine(x), x) || !EqualFirstWins(x.Combine(unset), x) {
			t.Fatalf("FirstWins 违反单位元律: x=%+v", x)
		}
		if !EqualFirstWins(x.Combine(x), x) {
			t.Fatalf("FirstWins 违反幂等律: x=%+v", x)
		}
		assertFirstWinsLeftAbsorbAndAssoc(t, x, samples)
	}
}

func assertFirstWinsLeftAbsorbAndAssoc(t *testing.T, x FirstWins[string], samples []FirstWins[string]) {
	t.Helper()
	for _, y := range samples {
		if x.IsSet() && !EqualFirstWins(x.Combine(y), x) {
			t.Fatalf("FirstWins 违反已设置左吸收律: x=%+v y=%+v", x, y)
		}
		for _, z := range samples {
			if !EqualFirstWins(x.Combine(y).Combine(z), x.Combine(y.Combine(z))) {
				t.Fatalf("FirstWins 违反结合律: x=%+v y=%+v z=%+v", x, y, z)
			}
		}
	}
}

func TestFirstWinsJSONv2(t *testing.T) {
	a := NewFirstWins("cli")
	raw, err := jsonv2.Marshal(a, jsonv2.Deterministic(true))
	if err != nil || string(raw) != `"cli"` {
		t.Fatalf("Marshal(FirstWins) = (%s, %v)", raw, err)
	}
	var dst FirstWins[string]
	if err := jsonv2.Unmarshal(raw, &dst); err != nil || !EqualFirstWins(dst, a) {
		t.Fatalf("Unmarshal(FirstWins) = (%+v, %v)", dst, err)
	}
	if err := jsonv2.Unmarshal([]byte(`null`), &dst); err != nil || !dst.IsUnset() {
		t.Fatalf("Unmarshal(null) = (%+v, %v)", dst, err)
	}
	dst = a
	if err := jsonv2.Unmarshal([]byte(`123`), &dst); err == nil || !dst.IsUnset() {
		t.Fatalf("Unmarshal 非法值后应重置为 Unset: dst=%+v err=%v", dst, err)
	}
	var nilFW *FirstWins[string]
	dec := jsontext.NewDecoder(bytes.NewReader([]byte(`"x"`)))
	if err := nilFW.UnmarshalJSONFrom(dec); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil FirstWins.UnmarshalJSONFrom = %v, 期望 ErrNilReceiver", err)
	}
}

func TestDurationJSONv2RoundTrip(t *testing.T) {
	// 对比确认 Go 1.27 encoding/json/v2 对裸 time.Duration 原生返回 SemanticError
	_, bareErr := jsonv2.Marshal(5 * time.Second)
	if _, ok := errors.AsType[*jsonv2.SemanticError](bareErr); !ok {
		t.Fatalf("期望 Go 1.27 json/v2 对裸 time.Duration 返回 *SemanticError，实际=%v", bareErr)
	}

	cases := []time.Duration{
		0,
		time.Nanosecond,
		500 * time.Millisecond,
		30 * time.Second,
		-5 * time.Minute,
		2*time.Hour + 3*time.Minute + 4*time.Second,
		time.Duration(math.MaxInt64),
		time.Duration(math.MinInt64),
	}
	for _, std := range cases {
		assertDurationRoundTrip(t, std)
	}
}

func assertDurationRoundTrip(t *testing.T, std time.Duration) {
	t.Helper()
	d := FromStdDuration(std)
	if d.Std() != std || d.IsZero() != (std == 0) || d.IsPositive() != (std > 0) || d.IsNegative() != (std < 0) {
		t.Fatalf("Duration 属性异常: d=%v std=%v", d, std)
	}
	appended, err := d.AppendText([]byte("prefix:"))
	marshaled, mErr := d.MarshalText()
	if err != nil || mErr != nil || string(appended) != "prefix:"+string(marshaled) {
		t.Fatalf("AppendText/MarshalText 不一致: appended=%q marshaled=%q errs=(%v,%v)", appended, marshaled, err, mErr)
	}
	raw, err := jsonv2.Marshal(d, jsonv2.Deterministic(true))
	if err != nil {
		t.Fatalf("jsonv2.Marshal(%v) 失败: %v", std, err)
	}
	var out Duration
	if err := jsonv2.Unmarshal(raw, &out); err != nil || !out.Equal(d) || out.Compare(d) != 0 {
		t.Fatalf("Duration JSON 往返失败: got=%v want=%v err=%v", out, d, err)
	}
	var buf bytes.Buffer
	if err := jsonv2.MarshalWrite(&buf, d, jsonv2.Deterministic(true)); err != nil || !bytes.Equal(buf.Bytes(), raw) {
		t.Fatalf("MarshalWrite(%v) 不一致: got=%q want=%q err=%v", std, buf.Bytes(), raw, err)
	}
}

func TestDurationDeterministicMapOverflowAndErrors(t *testing.T) {
	m := map[string]Duration{
		"zeta":  FromStdDuration(10 * time.Second),
		"alpha": FromStdDuration(250 * time.Millisecond),
		"mid":   ZeroDuration(),
	}
	wantMap := `{"alpha":"250ms","mid":"0s","zeta":"10s"}`
	for range 10 {
		raw, err := jsonv2.Marshal(m, jsonv2.Deterministic(true))
		if err != nil || string(raw) != wantMap {
			t.Fatalf("Deterministic map 编码 = (%s, %v), 期望 %s", raw, err, wantMap)
		}
	}

	sum, err := FromStdDuration(2 * time.Second).CheckedAdd(FromStdDuration(3 * time.Second))
	if err != nil || !sum.Equal(FromStdDuration(5*time.Second)) {
		t.Fatalf("CheckedAdd(2s, 3s) = (%v, %v)", sum, err)
	}
	if _, err := FromStdDuration(time.Duration(math.MaxInt64)).CheckedAdd(FromStdDuration(1)); !errors.Is(err, ErrDurationOverflow) {
		t.Fatalf("正溢出期望 ErrDurationOverflow，实际=%v", err)
	}
	if _, err := FromStdDuration(time.Duration(math.MinInt64)).CheckedAdd(FromStdDuration(-1)); !errors.Is(err, ErrDurationOverflow) {
		t.Fatalf("负溢出期望 ErrDurationOverflow，实际=%v", err)
	}

	for _, bad := range []string{"", " ", "5s ", " 5s", "10", "abc", "1d", "9999999999999999999h"} {
		if _, err := ParseDuration(bad); !errors.Is(err, ErrInvalidDuration) {
			t.Fatalf("ParseDuration(%q) = %v, 期望 ErrInvalidDuration", bad, err)
		}
	}
	dst := FromStdDuration(9 * time.Second)
	if err := jsonv2.Unmarshal([]byte(`5000`), &dst); err == nil {
		t.Fatal("Unmarshal JSON 数字到 Duration 应失败")
	}
	if err := dst.UnmarshalText([]byte("invalid")); !errors.Is(err, ErrInvalidDuration) || !dst.IsZero() {
		t.Fatalf("UnmarshalText 失败后应归零并返回 ErrInvalidDuration: dst=%v err=%v", dst, err)
	}
	var nilDur *Duration
	if err := nilDur.UnmarshalText([]byte("5s")); !errors.Is(err, ErrNilReceiver) {
		t.Fatalf("nil Duration UnmarshalText = %v, 期望 ErrNilReceiver", err)
	}
}

func FuzzParseDuration(f *testing.F) {
	for _, seed := range []string{"0s", "1ns", "-5s", "1h30m", "250ms", "", "invalid", "1000000000h"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		d, err := ParseDuration(raw)
		if err != nil {
			if !errors.Is(err, ErrInvalidDuration) {
				t.Fatalf("ParseDuration(%q) 错误未包装 ErrInvalidDuration: %v", raw, err)
			}
			return
		}
		text, err := d.MarshalText()
		if err != nil {
			t.Fatalf("MarshalText(%v) 意外失败: %v", d, err)
		}
		d2, err := ParseDuration(string(text))
		if err != nil || !d.Equal(d2) {
			t.Fatalf("Duration 规范往返破坏幂等性: raw=%q text=%q d=%v d2=%v err=%v", raw, text, d, d2, err)
		}
	})
}
