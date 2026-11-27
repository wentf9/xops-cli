package i18n

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

func TestEmbeddedCatalogBijectionAndFallbackParity(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() 失败: %v", err)
	}
	if !cat.IsValid() {
		t.Fatal("LoadCatalog() 应返回有效 Catalog")
	}

	expected := collectExpectedKeys(t)
	enTable := cat.entries[domi18n.LocaleEn]
	zhTable := cat.entries[domi18n.LocaleZh]

	assertTableBijection(t, "en", expected, enTable)
	assertTableBijection(t, "zh", expected, zhTable)
	assertFallbackVerbatimEquality(t, enTable)
	assertPlaceholderParity(t, enTable, zhTable)
}

func collectExpectedKeys(t *testing.T) map[string]domi18n.MessageID {
	t.Helper()
	expected := make(map[string]domi18n.MessageID)
	for _, id := range domi18n.CoreKeys() {
		if !id.IsValid() {
			t.Fatalf("CoreKeys() 包含非法 MessageID: %q", id)
		}
		if _, dup := expected[string(id)]; dup {
			t.Fatalf("CoreKeys() 存在重复键: %q", id)
		}
		expected[string(id)] = id
	}
	for _, id := range RootKeys() {
		if !id.IsValid() {
			t.Fatalf("RootKeys() 包含非法 MessageID: %q", id)
		}
		if _, dup := expected[string(id)]; dup {
			t.Fatalf("RootKeys() 与 CoreKeys() 存在重复或冲突键: %q", id)
		}
		expected[string(id)] = id
	}
	return expected
}

func assertTableBijection(t *testing.T, locale string, expected map[string]domi18n.MessageID, table map[string]Entry) {
	t.Helper()
	for key := range expected {
		entry, ok := table[key]
		if !ok {
			t.Errorf("%s 词库缺少注册键 %q", locale, key)
			continue
		}
		if strings.TrimSpace(entry.Other) == "" {
			t.Errorf("%s 词库键 %q 的 Other 模板为空", locale, key)
		}
	}
	for key := range table {
		if _, ok := expected[key]; !ok {
			t.Errorf("%s 词库存在未注册孤儿键 %q", locale, key)
		}
	}
}

func assertFallbackVerbatimEquality(t *testing.T, enTable map[string]Entry) {
	t.Helper()
	for _, id := range domi18n.CoreKeys() {
		fb := domi18n.CanonicalFallback(id)
		en := enTable[string(id)].Other
		if fb == "" || fb != en {
			t.Errorf("CoreKey %q CanonicalFallback=%q 与 en YAML=%q 不一致", id, fb, en)
		}
	}
	rootAll := make(map[domi18n.MessageID]bool, len(RootKeys()))
	for _, id := range RootKeys() {
		rootAll[id] = true
	}
	for _, id := range RootErrorKeys() {
		if !rootAll[id] {
			t.Errorf("RootErrorKeys() 包含未在 RootKeys() 中登记的键 %q", id)
		}
		fb := rootFallback(id)
		en := enTable[string(id)].Other
		if fb == "" || fb != en {
			t.Errorf("RootErrorKey %q rootFallback=%q 与 en YAML=%q 不一致", id, fb, en)
		}
	}
}

func assertPlaceholderParity(t *testing.T, enTable, zhTable map[string]Entry) {
	t.Helper()
	for key, enEntry := range enTable {
		zhEntry := zhTable[key]
		enPH, err := domi18n.ExtractPlaceholders(enEntry.Other)
		if err != nil {
			t.Fatalf("en %q Other 模板非法: %v", key, err)
		}
		zhPH, err := domi18n.ExtractPlaceholders(zhEntry.Other)
		if err != nil {
			t.Fatalf("zh %q Other 模板非法: %v", key, err)
		}
		if !slices.Equal(enPH, zhPH) {
			t.Errorf("键 %q 占位符不一致: en=%v zh=%v", key, enPH, zhPH)
		}
		assertPluralPlaceholderParity(t, "en", key, enEntry, enPH)
		assertPluralPlaceholderParity(t, "zh", key, zhEntry, zhPH)
	}
}

func assertPluralPlaceholderParity(t *testing.T, locale, key string, entry Entry, otherPH []string) {
	t.Helper()
	if entry.One == "" {
		return
	}
	onePH, err := domi18n.ExtractPlaceholders(entry.One)
	if err != nil {
		t.Fatalf("%s %q One 模板非法: %v", locale, key, err)
	}
	if !slices.Equal(onePH, otherPH) {
		t.Errorf("%s %q 复数 one/other 占位符不一致: one=%v other=%v", locale, key, onePH, otherPH)
	}
}

func TestLocalizerZeroValueAndNestedRendering(t *testing.T) {
	assertZeroValueContracts(t)
	assertDefaultAndNestedRendering(t)
	assertRootConstructors(t)
}

func assertZeroValueContracts(t *testing.T) {
	t.Helper()
	var nilCat *Catalog
	var zeroCat Catalog
	if nilCat.IsValid() || zeroCat.IsValid() {
		t.Fatal("nil 或零值 Catalog 不得有效")
	}
	if nilCat.For(domi18n.LocaleEn).IsValid() || zeroCat.For(domi18n.LocaleEn).IsValid() {
		t.Fatal("无效 Catalog.For 必须失败关闭返回无效 Localizer")
	}
	msg := NewMessage(KeyCatalogLoadFailed, domi18n.Str("file", "a.yaml"))
	rawErr := E(KeyCatalogLoadFailed, domi18n.Str("file", "a.yaml"))
	for _, loc := range []*Localizer{nil, {}} {
		assertInvalidLocalizerBehavior(t, loc, msg, rawErr)
	}
}

func assertInvalidLocalizerBehavior(t *testing.T, loc *Localizer, msg domi18n.Message, rawErr error) {
	t.Helper()
	if loc.IsValid() || loc.Locale() != domi18n.LocaleInvalid || loc.Catalog() != nil {
		t.Fatal("nil 或零值 Localizer 必须返回无效状态")
	}
	if loc.WithLocale(domi18n.LocaleZh).IsValid() {
		t.Fatal("无效 Localizer.WithLocale 必须失败关闭")
	}
	if got := loc.Render(msg); got != msg.Canonical() {
		t.Fatalf("零值 Localizer.Render = %q, 期望 %q", got, msg.Canonical())
	}
	if got := loc.Render(domi18n.Message{}); got != "" {
		t.Fatalf("无效 Message Render 应为空串, 实际 %q", got)
	}
	if got := loc.RenderError(rawErr); got != rawErr.Error() {
		t.Fatalf("零值 Localizer.RenderError = %q, 期望 %q", got, rawErr.Error())
	}
	if got := loc.RenderError(nil); got != "" {
		t.Fatalf("nil error RenderError 应为空串, 实际 %q", got)
	}
	if got := loc.T(KeyCatalogCorrupt); got != string(KeyCatalogCorrupt) {
		t.Fatalf("零值 Localizer.T 应失败关闭返回键名, 实际 %q", got)
	}
	if got := loc.TPlural(KeyCatalogCorrupt, 2); got != string(KeyCatalogCorrupt) {
		t.Fatalf("零值 Localizer.TPlural 应失败关闭返回键名, 实际 %q", got)
	}
	if got := loc.T(domi18n.MessageIDInvalid); got != "" {
		t.Fatalf("MessageIDInvalid Render 应为空串, 实际 %q", got)
	}
}

func assertDefaultAndNestedRendering(t *testing.T) {
	t.Helper()
	enLoc, err := DefaultLocalizer()
	if err != nil || !enLoc.IsValid() || enLoc.Locale() != domi18n.LocaleEn || enLoc.Catalog() == nil {
		t.Fatalf("DefaultLocalizer 异常: err=%v", err)
	}
	zhLoc := enLoc.WithLocale(domi18n.LocaleZh)
	if !zhLoc.IsValid() || zhLoc.Locale() != domi18n.LocaleZh || zhLoc.Catalog() != enLoc.Catalog() {
		t.Fatal("WithLocale 应共享只读 Catalog 并切换语种")
	}
	if enLoc.WithLocale(domi18n.LocaleInvalid).IsValid() {
		t.Fatal("WithLocale(LocaleInvalid) 应失败关闭")
	}

	nested := domi18n.NewMessage(
		domi18n.KeyCommonErrorJoin,
		domi18n.Msg("head", NewMessage(KeyCatalogLoadFailed, domi18n.Str("file", "zh.yaml"))),
		domi18n.Msg("tail", domi18n.NewMessage(domi18n.KeyCommonPermissionDeny)),
	)
	if got := enLoc.Render(nested); got != "i18n: failed to load catalog file zh.yaml: permission denied" {
		t.Fatalf("en 嵌套消息渲染异常: %q", got)
	}
	if got := zhLoc.Render(nested); got != "加载国际化词库文件 zh.yaml 失败：权限不足" {
		t.Fatalf("zh 嵌套消息渲染异常: %q", got)
	}
}

func assertRootConstructors(t *testing.T) {
	t.Helper()
	s := Sentinel(KeyCatalogCorrupt)
	if !errors.Is(s, ErrCatalogCorrupt) || s.Error() != "i18n: catalog data is corrupt" {
		t.Fatalf("Sentinel 异常: %v", s)
	}
	ef := EF(ErrCatalogCorrupt, KeyCatalogUnknownField, domi18n.Str("field", "two"))
	if !errors.Is(ef, ErrCatalogCorrupt) || ef.Error() != "i18n: unknown field two in entry" {
		t.Fatalf("EF 异常: %v", ef)
	}
	if id, ok := domi18n.ErrorID(ef); !ok || id != KeyCatalogUnknownField {
		t.Fatalf("ErrorID(ef) = (%q, %v)", id, ok)
	}
	cause := errors.New("eof")
	w := Wrap(cause, KeyCatalogLoadFailed, domi18n.Str("file", "a.yaml"))
	if !errors.Is(w, cause) || w.Error() != "i18n: failed to load catalog file a.yaml: eof" {
		t.Fatalf("Wrap 异常: %v", w)
	}
	ws := WrapS(ErrCatalogCorrupt, cause, KeyCatalogInvalidYAML, domi18n.Str("file", "a.yaml"))
	if !errors.Is(ws, ErrCatalogCorrupt) || !errors.Is(ws, cause) {
		t.Fatalf("WrapS 应同时保留哨兵与根因: %v", ws)
	}
}

func TestLoadCatalogFromFSPluralAndMultiFile(t *testing.T) {
	fsys := fstest.MapFS{
		"locales/en/a.yaml": &fstest.MapFile{Data: []byte(
			"common.error_join: \"{head}: {tail}\"\n" +
				"common.not_found:\n  one: \"{count} host missing\"\n  other: \"{count} hosts missing\"\n",
		)},
		"locales/en/b.yaml": &fstest.MapFile{Data: []byte(
			"common.timeout:\n  one: \"{count} second elapsed\"\n  other: \"{count} seconds elapsed\"\n",
		)},
		"locales/zh/a.yaml": &fstest.MapFile{Data: []byte(
			"common.error_join: \"{head}：{tail}\"\n" +
				"common.not_found: \"缺少 {count} 台主机\"\n",
		)},
		"locales/zh/b.yaml": &fstest.MapFile{Data: []byte(
			"common.timeout:\n  one: \"已等待 {count} 秒（单数）\"\n  other: \"已等待 {count} 秒\"\n",
		)},
	}

	cat, err := LoadCatalogFromFS(fsys)
	if err != nil {
		t.Fatalf("LoadCatalogFromFS 有效多文件复数词库失败: %v", err)
	}
	enLoc := cat.For(domi18n.LocaleEn)
	zhLoc := cat.For(domi18n.LocaleZh)

	if got := enLoc.TPlural(domi18n.KeyCommonNotFound, 1); got != "1 host missing" {
		t.Fatalf("en plural(1) = %q", got)
	}
	if got := enLoc.TPlural(domi18n.KeyCommonNotFound, 0); got != "0 hosts missing" {
		t.Fatalf("en plural(0) = %q", got)
	}
	if got := enLoc.TPlural(domi18n.KeyCommonNotFound, 3); got != "3 hosts missing" {
		t.Fatalf("en plural(3) = %q", got)
	}
	if got := zhLoc.TPlural(domi18n.KeyCommonNotFound, 1); got != "缺少 1 台主机" {
		t.Fatalf("zh scalar plural(1) = %q", got)
	}
	if got := zhLoc.Render(NewPluralMessage(domi18n.KeyCommonTimeout, 1)); got != "已等待 1 秒（单数）" {
		t.Fatalf("zh mapping plural(1) = %q", got)
	}
	if got := zhLoc.Render(NewPluralMessage(domi18n.KeyCommonTimeout, 5)); got != "已等待 5 秒" {
		t.Fatalf("zh mapping plural(5) = %q", got)
	}
	if got := enLoc.T(domi18n.KeyCommonNotFound, domi18n.Int("count", 2)); got != "2 hosts missing" {
		t.Fatalf("non-plural T 应使用 Other 模板: %q", got)
	}
	if got := enLoc.T(KeyCatalogCorrupt); got != rootFallback(KeyCatalogCorrupt) {
		t.Fatalf("最小词库缺失键 T 应回退规范英文: %q", got)
	}
}
