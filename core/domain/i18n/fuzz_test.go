package i18n

import (
	jsonv2 "encoding/json/v2"
	"errors"
	"math"
	"slices"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/wentf9/xops-cli/core/domain/i18n/internal/textalg"
)

func FuzzLocaleParsing(f *testing.F) {
	for _, seed := range []string{
		"", "   ", "en", "EN-US", "zh", "zh-CN", "zh_CN.UTF-8@cjknarrow",
		"zh-TW", "C", "POSIX", "C.UTF-8", "fr_FR.UTF-8", "@euro", ".UTF-8", "en_", "\xff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		assertFuzzParseLocale(t, raw)
		assertFuzzMatchEnvLocale(t, raw)
	})
}

func assertFuzzParseLocale(t *testing.T, raw string) {
	t.Helper()
	loc, err := ParseLocale(raw)
	if err != nil {
		if !errors.Is(err, ErrInvalidLocale) || loc != LocaleInvalid {
			t.Fatalf("ParseLocale(%q) 失败返回值非法: loc=%v err=%v", raw, loc, err)
		}
		return
	}
	if !loc.IsValid() || loc.IsZero() {
		t.Fatalf("ParseLocale(%q) 返回非法 Locale %v", raw, loc)
	}
	envLoc, envOK := MatchEnvLocale(raw)
	if !envOK || envLoc != loc {
		t.Fatalf("ParseLocale(%q)=%v 与 MatchEnvLocale=(%v,%v) 不一致", raw, loc, envLoc, envOK)
	}
	text, mErr := loc.MarshalText()
	var round Locale
	if mErr != nil || round.UnmarshalText(text) != nil || round != loc {
		t.Fatalf("Locale 文本往返失败: raw=%q loc=%v err=%v", raw, loc, mErr)
	}
}

func assertFuzzMatchEnvLocale(t *testing.T, raw string) {
	t.Helper()
	envLoc, envOK := MatchEnvLocale(raw)
	if envOK && !envLoc.IsValid() {
		t.Fatalf("MatchEnvLocale(%q) 命中但返回无效 Locale %v", raw, envLoc)
	}
	if !envOK && envLoc != LocaleInvalid {
		t.Fatalf("MatchEnvLocale(%q) 未命中但返回非零 Locale %v", raw, envLoc)
	}
	if res := ResolveLocale(raw); !res.IsValid() {
		t.Fatalf("ResolveLocale(%q) 返回无效 Locale %v", raw, res)
	}
}

func FuzzFormatTemplate(f *testing.F) {
	f.Add("hello {name}!", "name", "world")
	f.Add("{{escaped}} {{{k}}}", "k", "v")
	f.Add("{unclosed", "unclosed", "x")
	f.Add("lone } and }} and {{", "a", "b")
	f.Add("{a{b}}", "b", "val")
	f.Add("", "", "")

	f.Fuzz(func(t *testing.T, tmpl, key, val string) {
		out1 := FormatTemplate(tmpl, func(k string) (string, bool) {
			if k == key {
				return val, true
			}
			return "", false
		})
		out2 := FormatTemplate(tmpl, func(k string) (string, bool) {
			if k == key {
				return val, true
			}
			return "", false
		})
		if out1 != out2 {
			t.Fatalf("FormatTemplate 非确定性: %q != %q", out1, out2)
		}
		_ = FormatTemplate(tmpl, nil)
	})
}

func FuzzExtractPlaceholders(f *testing.F) {
	for _, seed := range []string{
		"", "plain", "{a}", "{b} and {a} and {b}", "{{lit}} {{{x}}}",
		"{unclosed", "lone}", "{}", "{bad key}", "{a{b}}", "\xff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, tmpl string) {
		assertFuzzExtractPlaceholders(t, tmpl)
	})
}

func assertFuzzExtractPlaceholders(t *testing.T, tmpl string) {
	t.Helper()
	keys, err := ExtractPlaceholders(tmpl)
	if err != nil {
		if !errors.Is(err, ErrInvalidTemplate) {
			t.Fatalf("ExtractPlaceholders(%q) 应返回 ErrInvalidTemplate, 实际=%v", tmpl, err)
		}
		return
	}
	if !slices.IsSorted(keys) {
		t.Fatalf("ExtractPlaceholders(%q) 未排序: %v", tmpl, keys)
	}
	for i, k := range keys {
		if !textalg.IsValidParamKey(k) || (i > 0 && keys[i-1] == k) {
			t.Fatalf("ExtractPlaceholders(%q) 含非法或重复键: %v", tmpl, keys)
		}
	}
	FormatTemplate(tmpl, func(k string) (string, bool) {
		if !slices.Contains(keys, k) {
			t.Fatalf("FormatTemplate 解析出未在 ExtractPlaceholders 中出现的键 %q (tmpl=%q)", k, tmpl)
		}
		return "ok", true
	})
	// 验证 ensureErrorMessage 在任意模糊模板与空参下绝不泄露未绑定占位符。
	salvErr := NewErrorWithFallback(nil, nil, MessageID("fuzz.check"), tmpl)
	if view, ok := InspectNode(salvErr); !ok || hasMissingErrorPlaceholder(view.Message, MaxMessageDepth) {
		t.Fatalf("ensureErrorMessage 存在未闭合占位符 (tmpl=%q): err=%q", tmpl, salvErr.Error())
	}
}

func FuzzMessageJSONRoundTrip(f *testing.F) {
	f.Add("common.invalid_argument", "fallback {s}", true, int64(3), "hello", int64(-9), uint64(7), 1.5, 2, true, int64(5*time.Second))
	f.Add("i18n.locale.invalid", "", false, int64(0), "", int64(0), uint64(0), math.Copysign(0, -1), -1, false, int64(0))
	f.Add("bad ID", "x", false, int64(1), "\xff", int64(1), uint64(1), math.NaN(), 0, true, int64(-1))

	f.Fuzz(func(t *testing.T, rawID, fallback string, hasCount bool, count int64, sVal string, iVal int64, uVal uint64, fVal float64, prec int, bVal bool, durNs int64) {
		params := collectValidFuzzParams(sVal, iVal, uVal, fVal, prec, bVal, durNs)
		var msg Message
		if hasCount {
			msg = NewPluralMessageWithFallback(MessageID(rawID), fallback, count, params...)
		} else {
			msg = NewMessageWithFallback(MessageID(rawID), fallback, params...)
		}
		if !msg.IsValid() {
			if _, err := jsonv2.Marshal(msg); !errors.Is(err, ErrInvalidMessage) {
				t.Fatalf("无效 Message Marshal 应返回 ErrInvalidMessage: err=%v", err)
			}
			return
		}
		encoded1, err1 := jsonv2.Marshal(msg, jsonv2.Deterministic(true))
		encoded2, err2 := jsonv2.Marshal(msg, jsonv2.Deterministic(true))
		if err1 != nil || err2 != nil || string(encoded1) != string(encoded2) {
			t.Fatalf("有效 Message 确定性 JSON 编码失败: errs=(%v,%v)", err1, err2)
		}
		var decoded Message
		if err := jsonv2.Unmarshal(encoded1, &decoded); err != nil || !decoded.Equal(msg) {
			t.Fatalf("有效 Message JSON 往返失败: raw=%s err=%v", encoded1, err)
		}
	})
}

func collectValidFuzzParams(sVal string, iVal int64, uVal uint64, fVal float64, prec int, bVal bool, durNs int64) []Param {
	candidates := []Param{
		Str("s", sVal),
		Int64("i", iVal),
		Uint64("u", uVal),
		Float("f", fVal, prec),
		Bool("b", bVal),
		DurNanos("d", durNs),
		Msg("nested", NewMessage(KeyCommonNotFound)),
	}
	out := make([]Param, 0, len(candidates))
	for _, p := range candidates {
		if p.IsValid() {
			out = append(out, p)
		}
	}
	return out
}

func FuzzBoundDisplayText(f *testing.F) {
	f.Add("hello world", 8)
	f.Add("中文边界裁剪🚀", 7)
	f.Add("bad\xff\xfeutf8", 5)
	f.Add("", 0)
	f.Add("abc", -1)

	f.Fuzz(func(t *testing.T, raw string, maxBytes int) {
		if maxBytes > 16384 {
			maxBytes = 16384
		}
		out := BoundDisplayText(raw, maxBytes)
		if !utf8.ValidString(out) {
			t.Fatalf("BoundDisplayText(%q, %d) 返回非法 UTF-8: %q", raw, maxBytes, out)
		}
		if maxBytes <= 0 && out != "" {
			t.Fatalf("maxBytes=%d 应返回空串, 实际=%q", maxBytes, out)
		}
		if maxBytes > 0 && len(out) > maxBytes {
			t.Fatalf("BoundDisplayText 超出 maxBytes=%d: len=%d", maxBytes, len(out))
		}
		if BoundDisplayText(out, maxBytes) != out {
			t.Fatalf("BoundDisplayText 非幂等: out=%q", out)
		}
		if p := BoundStr("k", raw); !p.IsValid() {
			t.Fatalf("BoundStr 合法键名应始终构造有效 Param: raw=%q", raw)
		}
	})
}
