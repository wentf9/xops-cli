package textalg_test

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"slices"
	"testing"

	"github.com/wentf9/xops-cli/core/domain/i18n/internal/textalg"
)

func TestLocaleAlgorithms(t *testing.T) {
	norm, ok := textalg.NormalizeLocaleCore("  zh-Hans-CN.UTF-8@cjknarrow  ")
	if !ok || norm != "zh_hans_cn" {
		t.Fatalf("NormalizeLocaleCore 异常: norm=%q ok=%v", norm, ok)
	}
	if primary, ok := textalg.MatchNormalizedPrimary(norm); !ok || primary != "zh" {
		t.Fatalf("MatchNormalizedPrimary 异常: primary=%q ok=%v", primary, ok)
	}
	for _, bad := range []string{"", "   ", "en.", "en@", ".UTF-8", "@mod", "en@bad mod"} {
		if _, ok := textalg.NormalizeLocaleCore(bad); ok {
			t.Fatalf("非法区域标签 %q 不应通过 NormalizeLocaleCore", bad)
		}
	}
	if textalg.HasValidLocaleSubtags("") || textalg.HasValidLocaleSubtags("en__us") || textalg.IsValidLocaleSuffix("a/b") {
		t.Fatal("子段或后缀校验未拒绝非法输入")
	}
}

func TestTemplateLexicalIsomorphismAndZeroAlloc(t *testing.T) {
	cases := []struct {
		tmpl     string
		wantKeys []string
	}{
		{"plain text", nil},
		{"hello {name}, {n} and {name}", []string{"name", "n"}},
		{"{{escaped}} {{{k}}} {{{{lit}}}} {{{{{x}}}}}", []string{"k", "x"}},
		{"} bad {unclosed {a} {bad key} {b} {c{d}}", []string{"a", "b", "d"}},
		{"{{foo} {bar}}", []string{"bar"}},
		{"empty {} lone } ok {k.1-a}", []string{"k.1-a"}},
	}
	for _, tc := range cases {
		assertTemplateLexicalCase(t, tc.tmpl, tc.wantKeys)
	}
	assertHasMissingZeroAllocs(t)
}

func assertTemplateLexicalCase(t *testing.T, tmpl string, wantKeys []string) {
	t.Helper()
	got := textalg.CollectFormatPlaceholderKeys(tmpl)
	if !slices.Equal(got, wantKeys) {
		t.Fatalf("CollectFormatPlaceholderKeys(%q) = %v, 期望 %v", tmpl, got, wantKeys)
	}
	// 校验与 FormatTemplate 实际消费的占位符集合 100% 同构。
	var formatted []string
	textalg.FormatTemplate(tmpl, func(k string) (string, bool) {
		if !slices.Contains(formatted, k) {
			formatted = append(formatted, k)
		}
		return "OK", true
	})
	if !slices.Equal(formatted, got) {
		t.Fatalf("词法不同构 (%q): FormatTemplate=%v Collect=%v", tmpl, formatted, got)
	}
	if textalg.HasMissingPlaceholder(tmpl, func(k string) bool { return slices.Contains(got, k) }) {
		t.Fatalf("全部键已绑定时 HasMissingPlaceholder(%q) 应返回 false", tmpl)
	}
	for _, missing := range got {
		if !textalg.HasMissingPlaceholder(tmpl, func(k string) bool { return k != missing }) {
			t.Fatalf("缺少键 %q 时 HasMissingPlaceholder(%q) 应返回 true", missing, tmpl)
		}
	}
}

func assertHasMissingZeroAllocs(t *testing.T) {
	t.Helper()
	// 验证 HasMissingPlaceholder 零堆分配快路径。
	boundKeys := []string{"host", "port"}
	allocs := testing.AllocsPerRun(50, func() {
		if textalg.HasMissingPlaceholder("connect {host}:{port} ({{lit}})", func(k string) bool {
			return slices.Contains(boundKeys, k)
		}) {
			t.Fatal("不应判定为缺失")
		}
	})
	if allocs != 0 {
		t.Fatalf("HasMissingPlaceholder 快路径应为 0 堆分配, 实际=%.1f", allocs)
	}
}

func TestJSONGuardRejectsNullMembers(t *testing.T) {
	baseErr := errors.New("invalid json")
	type wire struct {
		Key string  `json:"key"`
		Val *string `json:"val,omitzero"`
	}
	var okWire wire
	decOK := jsontext.NewDecoder(bytes.NewReader([]byte(`{"key":"k","val":"v"}`)))
	if err := textalg.UnmarshalCheckedObject(decOK, &okWire, baseErr); err != nil || okWire.Key != "k" || okWire.Val == nil || *okWire.Val != "v" {
		t.Fatalf("合法对象反序列化失败: wire=%+v err=%v", okWire, err)
	}
	for _, raw := range []string{`null`, `{"key":"k","val":null}`, `{"key":"k","unknown":1}`} {
		var w wire
		dec := jsontext.NewDecoder(bytes.NewReader([]byte(raw)))
		if err := textalg.UnmarshalCheckedObject(dec, &w, baseErr); err == nil {
			t.Fatalf("非法 JSON %s 应被拒绝", raw)
		}
	}
}
