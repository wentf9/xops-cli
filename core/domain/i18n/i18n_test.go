package i18n

import (
	"errors"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLocaleParsingAndResolution(t *testing.T) {
	validCases := []struct {
		raw  string
		want Locale
	}{
		{"en", LocaleEn},
		{"EN", LocaleEn},
		{"  en-US  ", LocaleEn},
		{"en_GB.UTF-8", LocaleEn},
		{"en_US.utf8@euro", LocaleEn},
		{"zh", LocaleZh},
		{"ZH", LocaleZh},
		{"zh-CN", LocaleZh},
		{"zh_CN.UTF-8", LocaleZh},
		{"zh_CN.UTF-8@cjknarrow", LocaleZh},
		{"zh-Hans-CN", LocaleZh},
		{"zh-TW", LocaleZh},
		{"zh_Hant_HK", LocaleZh},
	}
	for _, tc := range validCases {
		got, err := ParseLocale(tc.raw)
		if err != nil || got != tc.want || !got.IsValid() || got.IsZero() {
			t.Fatalf("ParseLocale(%q) = (%v, %v), 期望 %v", tc.raw, got, err, tc.want)
		}
	}

	invalidCases := []string{
		"", "   ", "\t\n", "C", "POSIX", "C.UTF-8", "fr_FR.UTF-8", "ja",
		"english", "zh_", "en--us", "en us", "en.", "en@", ".UTF-8", "@euro",
		"en.UTF 8", "zh_CN@bad mod", strings.Repeat("a", maxLocaleTagBytes+1), "\xff\xfe",
	}
	for _, raw := range invalidCases {
		got, err := ParseLocale(raw)
		if err == nil || !errors.Is(err, ErrInvalidLocale) || got != LocaleInvalid || got.IsValid() {
			t.Fatalf("ParseLocale(%q) 应失败关闭: got=%v err=%v", raw, got, err)
		}
		if id, ok := ErrorID(err); !ok || id != KeyLocaleInvalidValue {
			t.Fatalf("ParseLocale(%q) ErrorID = (%q, %v), 期望 %q", raw, id, ok, KeyLocaleInvalidValue)
		}
	}
}

func TestMatchEnvLocaleAndResolve(t *testing.T) {
	envCases := []struct {
		raw    string
		want   Locale
		wantOK bool
	}{
		{"", LocaleInvalid, false},
		{"   \t ", LocaleInvalid, false},
		{"C", LocaleEn, true},
		{"c", LocaleEn, true},
		{"POSIX", LocaleEn, true},
		{"C.UTF-8", LocaleEn, true},
		{"POSIX.utf8@mod", LocaleEn, true},
		{"zh_CN.UTF-8@cjknarrow", LocaleZh, true},
		{"zh-TW", LocaleZh, true},
		{"en_US.UTF-8", LocaleEn, true},
		{"fr_FR.UTF-8", LocaleEn, true},
		{"@euro", LocaleEn, true},
		{".UTF-8", LocaleEn, true},
	}
	for _, tc := range envCases {
		got, ok := MatchEnvLocale(tc.raw)
		if got != tc.want || ok != tc.wantOK {
			t.Fatalf("MatchEnvLocale(%q) = (%v, %v), 期望 (%v, %v)", tc.raw, got, ok, tc.want, tc.wantOK)
		}
	}

	resolveCases := []struct {
		tags []string
		want Locale
	}{
		{nil, LocaleEn},
		{[]string{"", "   "}, LocaleEn},
		{[]string{"", "C", "zh_CN.UTF-8"}, LocaleEn},
		{[]string{"", "POSIX.UTF-8", "zh-CN"}, LocaleEn},
		{[]string{"fr_FR.UTF-8", "zh_CN.UTF-8"}, LocaleEn},
		{[]string{"", "  ", "zh_CN.UTF-8", "en_US.UTF-8"}, LocaleZh},
		{[]string{"en-US", "zh-CN"}, LocaleEn},
	}
	for _, tc := range resolveCases {
		if got := ResolveLocale(tc.tags...); got != tc.want {
			t.Fatalf("ResolveLocale(%v) = %v, 期望 %v", tc.tags, got, tc.want)
		}
	}
}

func TestLocaleHelpers(t *testing.T) {
	if !LocaleInvalid.IsZero() || LocaleInvalid.IsValid() || LocaleInvalid.String() != "invalid" {
		t.Fatalf("LocaleInvalid 零值状态异常: %v", LocaleInvalid)
	}
	if Locale(99).IsValid() || Locale(99).String() != "invalid" || Locale(99).Next() != LocaleEn {
		t.Fatal("越界 Locale 应严格失败关闭")
	}
	if LocaleEn.String() != "en" || LocaleZh.String() != "zh" {
		t.Fatalf("Locale.String 异常: en=%q zh=%q", LocaleEn.String(), LocaleZh.String())
	}
	if LocaleEn.Next() != LocaleZh || LocaleZh.Next() != LocaleEn || LocaleInvalid.Next() != LocaleEn {
		t.Fatal("Locale.Next 轮换语义异常")
	}
	if LocaleInvalid.Compare(LocaleEn) >= 0 || LocaleEn.Compare(LocaleZh) >= 0 || Locale(99).Compare(LocaleInvalid) != 0 {
		t.Fatal("Locale.Compare 顺序异常")
	}
}

func TestParamConstructorsAndAccessors(t *testing.T) {
	nested := NewMessage(KeyCommonNotFound)
	params := []Param{
		Str("s", "hello"),
		Int("i", -42),
		Int64("i64", math.MinInt64),
		Uint64("u64", math.MaxUint64),
		Float("f", math.Copysign(0, -1), 2),
		Bool("b", true),
		Dur("d", 1500*time.Millisecond),
		DurNanos("dn", -250),
		Msg("m", nested),
	}
	for _, p := range params {
		if !p.IsValid() || p.IsZero() || !p.Equal(p) {
			t.Fatalf("合法 Param 状态异常: key=%q kind=%v", p.Key(), p.Kind())
		}
	}
	assertParamTypedAccessors(t, params, nested)
	assertInvalidParamsFailClosed(t)
}

func assertParamTypedAccessors(t *testing.T, params []Param, nested Message) {
	t.Helper()
	assertScalarParamAccessors(t, params)
	assertFloatAndCompoundParamAccessors(t, params, nested)
}

func assertScalarParamAccessors(t *testing.T, params []Param) {
	t.Helper()
	if v, ok := params[0].StringVal(); !ok || v != "hello" || params[0].FormatCanonical() != "hello" {
		t.Fatalf("Str 异常: %q %v", v, ok)
	}
	if v, ok := params[1].Int64Val(); !ok || v != -42 || params[1].FormatCanonical() != "-42" {
		t.Fatalf("Int 异常: %d %v", v, ok)
	}
	if v, ok := params[3].Uint64Val(); !ok || v != math.MaxUint64 {
		t.Fatalf("Uint64 异常: %d %v", v, ok)
	}
	if v, ok := params[5].BoolVal(); !ok || !v || params[5].FormatCanonical() != "true" {
		t.Fatalf("Bool 异常: %v %v", v, ok)
	}
}

func assertFloatAndCompoundParamAccessors(t *testing.T, params []Param, nested Message) {
	t.Helper()
	fv, fok := params[4].Float64Val()
	fp, pok := params[4].FloatPrec()
	if !fok || !pok || fv != 0 || math.Signbit(fv) || fp != 2 || params[4].FormatCanonical() != "0.00" {
		t.Fatalf("Float -0.0 归一化异常: fv=%v sign=%v prec=%d fmt=%q", fv, math.Signbit(fv), fp, params[4].FormatCanonical())
	}
	if !params[4].Equal(Float("f", 0.0, 2)) {
		t.Fatal("Float(-0.0) 应与 Float(0.0) 相等")
	}
	if d, ok := params[6].DurationVal(); !ok || d != 1500*time.Millisecond || params[6].FormatCanonical() != "1.5s" {
		t.Fatalf("Dur 异常: %v %v", d, ok)
	}
	if ns, ok := params[7].DurationNanos(); !ok || ns != -250 {
		t.Fatalf("DurNanos 异常: %d %v", ns, ok)
	}
	if mv, ok := params[8].MessageVal(); !ok || !mv.Equal(nested) || params[8].FormatCanonical() != nested.Canonical() {
		t.Fatalf("Msg 异常: ok=%v fmt=%q", ok, params[8].FormatCanonical())
	}
}

func assertInvalidParamsFailClosed(t *testing.T) {
	t.Helper()
	var zero Param
	if zero.IsValid() || !zero.IsZero() || zero.Equal(zero) || zero.Key() != "" || zero.Kind() != ParamKindInvalid || zero.FormatCanonical() != "" {
		t.Fatal("零值 Param 未严格失败关闭")
	}
	badParams := []Param{
		Str("", "v"),
		Str("-bad", "v"),
		Str("bad key", "v"),
		Str(strings.Repeat("k", MaxParamKeyBytes+1), "v"),
		Str("s", strings.Repeat("a", MaxParamStringBytes+1)),
		Str("s", "\xff"),
		Int("", 1),
		Uint64("", 1),
		Bool("", true),
		Dur("", time.Second),
		Float("f", math.NaN(), 2),
		Float("f", math.Inf(1), 2),
		Float("f", math.Inf(-1), 2),
		Float("f", 1.23, -2),
		Float("f", 1.23, MaxFloatPrec+1),
		Msg("m", Message{}),
	}
	for i, p := range badParams {
		if p.IsValid() || !p.IsZero() {
			t.Fatalf("非法 Param #%d 应失败关闭", i)
		}
	}
	if ParamKindInvalid.IsValid() || !ParamKindInvalid.IsZero() || ParamKind(99).IsValid() || ParamKind(99).String() != "invalid" {
		t.Fatal("ParamKind 边界语义异常")
	}
}

func TestMessageDepthParamsAndPlural(t *testing.T) {
	// 验证最大嵌套深度 MaxMessageDepth（4）精确边界：depth 0..4 允许，depth 5 拒绝。
	cur := NewMessage(KeyCommonNotFound)
	for depth := uint8(1); depth <= MaxMessageDepth; depth++ {
		cur = NewMessageWithFallback(KeyCommonErrorJoin, "{head}: {tail}", Str("head", "h"), Msg("tail", cur))
		if !cur.IsValid() || cur.Depth() != depth {
			t.Fatalf("深度 %d 构造失败: valid=%v depth=%d", depth, cur.IsValid(), cur.Depth())
		}
	}
	if p := Msg("too_deep", cur); p.IsValid() {
		t.Fatal("超过 MaxMessageDepth 的嵌套 Msg 参数应失败关闭")
	}

	// 验证超过 MaxMessageParams 与重复参数键均失败关闭。
	tooMany := make([]Param, MaxMessageParams+1)
	for i := range tooMany {
		tooMany[i] = Int("k"+string(rune('a'+i)), i)
	}
	if m := NewMessage(KeyCommonInvalidArgument, tooMany...); m.IsValid() {
		t.Fatal("超过 MaxMessageParams 的 Message 应失败关闭")
	}
	if m := NewMessage(KeyCommonInvalidArgument, Str("dup", "1"), Str("dup", "2")); m.IsValid() {
		t.Fatal("含重复参数键的 Message 应失败关闭")
	}

	// 验证复数消息自动解析 {count} 及深度值相等。
	pm := NewPluralMessageWithFallback(KeyCommonLimitExceeded, "limit {count} items ({kind})", 5, Str("kind", "nodes"))
	if !pm.IsValid() || pm.Canonical() != "limit 5 items (nodes)" {
		t.Fatalf("复数消息 Canonical 异常: %q", pm.Canonical())
	}
	if c, ok := pm.Count(); !ok || c != 5 {
		t.Fatalf("Count 异常: %d %v", c, ok)
	}
	if pm.Equal(NewPluralMessageWithFallback(KeyCommonLimitExceeded, "limit {count} items ({kind})", 6, Str("kind", "nodes"))) {
		t.Fatal("不同 count 的复数消息不应相等")
	}
	// 验证纯 UI Key（空 fallback）仍可构造合法 Message，Canonical 降级为 string(id)。
	uiMsg := NewMessageWithFallback(MessageID("tui.status.ready"), "")
	if !uiMsg.IsValid() || uiMsg.Canonical() != "tui.status.ready" {
		t.Fatalf("空 fallback UI 消息异常: valid=%v canonical=%q", uiMsg.IsValid(), uiMsg.Canonical())
	}
}

func TestMessageIDValidationAndCoreKeys(t *testing.T) {
	if !MessageIDInvalid.IsZero() || MessageIDInvalid.IsValid() || CanonicalFallback(MessageIDInvalid) != "" {
		t.Fatal("MessageIDInvalid 零值语义异常")
	}
	for _, bad := range []MessageID{"", "A.b", "1abc", "a..b", "a.", ".a", "a-b", "a b", MessageID(strings.Repeat("a", maxMessageIDBytes+1))} {
		if bad.IsValid() {
			t.Fatalf("非法 MessageID %q 不应有效", bad)
		}
	}
	keys := CoreKeys()
	if len(keys) == 0 || slices.Contains(keys, MessageIDInvalid) {
		t.Fatal("CoreKeys 不得为空或包含 MessageIDInvalid")
	}
	seen := make(map[MessageID]bool, len(keys))
	for _, id := range keys {
		if !id.IsValid() || seen[id] {
			t.Fatalf("CoreKeys 包含非法或重复键: %q", id)
		}
		seen[id] = true
		fb := CanonicalFallback(id)
		if fb == "" {
			t.Fatalf("CoreKey %q 缺少 CanonicalFallback", id)
		}
		if _, err := ExtractPlaceholders(fb); err != nil {
			t.Fatalf("CoreKey %q 兜底模板语法非法 %q: %v", id, fb, err)
		}
	}
}

func TestFormatTemplateAndExtractPlaceholders(t *testing.T) {
	resolver := func(k string) (string, bool) {
		switch k {
		case "name":
			return "xops", true
		case "n":
			return "3", true
		default:
			return "", false
		}
	}
	formatCases := []struct {
		tmpl string
		want string
	}{
		{"plain text", "plain text"},
		{"hello {name}, {n}!", "hello xops, 3!"},
		{"{{escaped}} {{{name}}}", "{escaped} {xops}"},
		{"missing {unknown} stays", "missing {unknown} stays"},
		{"unclosed {name", "unclosed {name"},
		{"lone } brace", "lone } brace"},
		{"nested {a{name}}", "nested {axops}"},
		{"empty {} bad {a b}", "empty {} bad {a b}"},
	}
	for _, tc := range formatCases {
		if got := FormatTemplate(tc.tmpl, resolver); got != tc.want {
			t.Fatalf("FormatTemplate(%q) = %q, 期望 %q", tc.tmpl, got, tc.want)
		}
	}
	if got := FormatTemplate("keep {name}", nil); got != "keep {name}" {
		t.Fatalf("nil resolver 异常: %q", got)
	}

	keys, err := ExtractPlaceholders("copy {src} to {dst} ({{lit}}) again {src}")
	if err != nil || !slices.Equal(keys, []string{"dst", "src"}) {
		t.Fatalf("ExtractPlaceholders 异常: keys=%v err=%v", keys, err)
	}
	for _, bad := range []string{"{unclosed", "lone}", "{}", "{bad key}", "{a{b}}", "\xff"} {
		if _, err := ExtractPlaceholders(bad); !errors.Is(err, ErrInvalidTemplate) {
			t.Fatalf("ExtractPlaceholders(%q) 应返回 ErrInvalidTemplate, 实际=%v", bad, err)
		}
	}
}
