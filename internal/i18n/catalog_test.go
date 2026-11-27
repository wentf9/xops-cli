package i18n

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	"unicode"

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
	assertCoreFallbackParity(t, enTable)
	assertRootFallbackParity(t, enTable)
}

func assertCoreFallbackParity(t *testing.T, enTable map[string]Entry) {
	t.Helper()
	for _, id := range domi18n.CoreKeys() {
		fb := domi18n.CanonicalFallback(id)
		en := enTable[string(id)].Other
		if fb == "" || fb != en {
			t.Errorf("CoreKey %q CanonicalFallback=%q 与 en YAML=%q 不一致", id, fb, en)
		}
		if shadow := rootFallback(id); shadow != "" {
			t.Errorf("CoreKey %q 不应在 rootFallback 中重复登记影子兜底: %q", id, shadow)
		}
	}
}

func assertRootFallbackParity(t *testing.T, enTable map[string]Entry) {
	t.Helper()
	rootAll := make(map[domi18n.MessageID]bool, len(RootKeys()))
	for _, id := range RootKeys() {
		rootAll[id] = true
	}
	rootErrSet := make(map[domi18n.MessageID]bool, len(RootErrorKeys()))
	for _, id := range RootErrorKeys() {
		if !rootAll[id] {
			t.Errorf("RootErrorKeys() 包含未在 RootKeys() 中登记的键 %q", id)
		}
		rootErrSet[id] = true
		fb := rootFallback(id)
		en := enTable[string(id)].Other
		if fb == "" || fb != en {
			t.Errorf("RootErrorKey %q rootFallback=%q 与 en YAML=%q 不一致", id, fb, en)
		}
	}
	// 反向兜底穷尽断言：所有非错误类 RootKeys 均须满足 rootFallback(id) == ""，杜绝未受检影子兜底。
	for _, id := range RootKeys() {
		if !rootErrSet[id] {
			if fb := rootFallback(id); fb != "" {
				t.Errorf("非错误类 RootKey %q 不应在 rootFallback 中登记影子兜底: %q", id, fb)
			}
		}
	}
}

func assertPlaceholderParity(t *testing.T, enTable, zhTable map[string]Entry) {
	t.Helper()
	for key, enEntry := range enTable {
		zhEntry := zhTable[key]
		enPH := mustExtractBoundedPlaceholders(t, "en", key, "Other", enEntry.Other)
		zhPH := mustExtractBoundedPlaceholders(t, "zh", key, "Other", zhEntry.Other)
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
	onePH := mustExtractBoundedPlaceholders(t, locale, key, "One", entry.One)
	if !slices.Equal(onePH, otherPH) {
		t.Errorf("%s %q 复数 one/other 占位符不一致: one=%v other=%v", locale, key, onePH, otherPH)
	}
}

func mustExtractBoundedPlaceholders(t *testing.T, locale, key, form, tmpl string) []string {
	t.Helper()
	ph, err := domi18n.ExtractPlaceholders(tmpl)
	if err != nil {
		t.Fatalf("%s %q %s 模板非法: %v", locale, key, form, err)
	}
	if len(ph) > domi18n.MaxMessageParams {
		t.Errorf("%s %q %s 模板占位符个数 %d 超出 MaxMessageParams(%d)", locale, key, form, len(ph), domi18n.MaxMessageParams)
	}
	return ph
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
	var invalidMsg domi18n.Message
	if got := loc.Render(invalidMsg); got != "" {
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
	ws := WrapS(ErrCatalogCorrupt, cause, KeyCatalogInvalidYAML, Str("file", "a.yaml"))
	if !errors.Is(ws, ErrCatalogCorrupt) || !errors.Is(ws, cause) {
		t.Fatalf("WrapS 应同时保留哨兵与根因: %v", ws)
	}
	coreBridge := EF(ErrCatalogCorrupt, domi18n.KeyCommonInvalidArgument)
	if !errors.Is(coreBridge, ErrCatalogCorrupt) || coreBridge.Error() != "invalid argument" {
		t.Fatalf("根桥接函数传核心键应回退 CanonicalFallback: %v", coreBridge)
	}
	assertParamForwarders(t)
}

func assertParamForwarders(t *testing.T) {
	t.Helper()
	nestedMsg := NewMessage(KeyCatalogCorrupt)
	oversized := strings.Repeat("x", domi18n.MaxParamStringBytes+64)
	pairs := []struct {
		name string
		got  domi18n.Param
		want domi18n.Param
	}{
		{"Str", Str("k", "v"), domi18n.Str("k", "v")},
		{"BoundStr", BoundStr("k", oversized), domi18n.BoundStr("k", oversized)},
		{"Int", Int("n", -7), domi18n.Int("n", -7)},
		{"Int64", Int64("n64", -9000000000), domi18n.Int64("n64", -9000000000)},
		{"Uint64", Uint64("u64", 42), domi18n.Uint64("u64", 42)},
		{"Float", Float("f", 3.14159, 2), domi18n.Float("f", 3.14159, 2)},
		{"Bool", Bool("ok", true), domi18n.Bool("ok", true)},
		{"Dur", Dur("d", 5*time.Second), domi18n.Dur("d", 5*time.Second)},
		{"DurNanos", DurNanos("dn", 1250000), domi18n.DurNanos("dn", 1250000)},
		{"Msg", Msg("m", nestedMsg), domi18n.Msg("m", nestedMsg)},
	}
	for _, tc := range pairs {
		if !tc.got.Equal(tc.want) {
			t.Errorf("参数转发器 %s 行为与 core/domain/i18n 不一致: got=%v want=%v", tc.name, tc.got, tc.want)
		}
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

func TestM2DomainCatalogRenderingContracts(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() 失败: %v", err)
	}
	enLoc := cat.For(domi18n.LocaleEn)
	zhLoc := cat.For(domi18n.LocaleZh)
	assertCLIHelpContracts(t, enLoc, zhLoc)
	assertTUIAndInteractContracts(t, enLoc, zhLoc)
	assertM2SampleErrorRendering(t, enLoc, zhLoc)
}

func assertCLIHelpContracts(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	// 全部 16 条 CLI 帮助文档在中英文词库中均须包含 --lang <zh|en>、尾部换行并统一策略档位术语。
	helpKeys := []domi18n.MessageID{
		KeyCLIHelpRoot, KeyCLIHelpVersion, KeyCLIHelpSSH, KeyCLIHelpExec, KeyCLIHelpTunnel, KeyCLIHelpMux,
		KeyCLIHelpSCP, KeyCLIHelpSFTP, KeyCLIHelpHosts, KeyCLIHelpVault, KeyCLIHelpConfig, KeyCLIHelpPlaybook,
		KeyCLIHelpDoctor, KeyCLIHelpAudit, KeyCLIHelpMCP, KeyCLIHelpTUI,
	}
	for _, id := range helpKeys {
		assertHelpTextValid(t, "en", id, enLoc.T(id))
		assertHelpTextValid(t, "zh", id, zhLoc.T(id))
	}
	assertCLIHelpFlagCoverage(t, "en", enLoc)
	assertCLIHelpFlagCoverage(t, "zh", zhLoc)
}

func assertHelpTextValid(t *testing.T, locale string, id domi18n.MessageID, text string) {
	t.Helper()
	if !strings.Contains(text, "--lang <zh|en>") || !strings.HasSuffix(text, "\n") {
		t.Errorf("%s %q 帮助文档缺少 --lang <zh|en> 或尾部换行", locale, id)
	}
	if strings.Contains(text, "| strict |") {
		t.Errorf("%s %q 帮助文档仍残留未统一的策略别名 '| strict |'", locale, id)
	}
	if id != KeyCLIHelpVersion && !strings.Contains(text, "direct_operator | strict_operator | strict_agent") {
		t.Errorf("%s %q 帮助文档缺少统一策略配置档枚举", locale, id)
	}
}

func assertCLIHelpFlagCoverage(t *testing.T, locale string, loc *Localizer) {
	t.Helper()
	rootText := loc.T(KeyCLIHelpRoot)
	if !strings.Contains(rootText, "--ssh-config") || !strings.Contains(rootText, "'--'") {
		t.Errorf("%s cli.help.root 缺少 --ssh-config 或 --lang 位置说明", locale)
	}
	muxText := loc.T(KeyCLIHelpMux)
	for _, token := range []string{"check|status", "-L / -R / -D / -w", "--tun-mode <mode>"} {
		if !strings.Contains(muxText, token) {
			t.Errorf("%s cli.help.mux 缺少 %q", locale, token)
		}
	}
	if !strings.Contains(loc.T(KeyCLIHelpSFTP), "--symlink-policy <policy>") {
		t.Errorf("%s cli.help.sftp 缺少 --symlink-policy <policy>", locale)
	}
}

func assertTUIAndInteractContracts(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	// TUI 帮助页与底栏须明确区分大写 L 语言切换与小写 l 日志流。
	for name, loc := range map[string]*Localizer{"en": enLoc, "zh": zhLoc} {
		body := loc.T(KeyTUIHelpBody)
		footer := loc.T(KeyTUIFooterHelp)
		if !strings.Contains(body, "L ") || !strings.Contains(body, "m / l / x") || !strings.Contains(footer, "L ") {
			t.Errorf("%s TUI 帮助/底栏缺少 L 语言切换与 l 日志流说明", name)
		}
	}
	// CLI 凭据库交互提示经 NewMessage 构造后，Canonical() 与英文词库一致且中文正常渲染。
	vaultTitle := NewMessage(KeyInteractVaultInitTitle)
	if vaultTitle.Canonical() != "Vault init" || zhLoc.Render(vaultTitle) != "初始化凭据库" {
		t.Fatalf("凭据库提示渲染异常: en=%q zh=%q", vaultTitle.Canonical(), zhLoc.Render(vaultTitle))
	}
	// 已清理死键 interact.risk.critical 不得存在于英中词库。
	if _, ok := enLoc.Catalog().entries[domi18n.LocaleEn]["interact.risk.critical"]; ok {
		t.Fatal("死键 interact.risk.critical 应已从词库移除")
	}
}

func assertM2SampleErrorRendering(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	sampleErrs := []error{
		EF(Sentinel(KeyCLIUsage), KeyCLIInvalidFlagValueEnum, Str("flag", "--lang"), Str("allowed", "zh|en"), Str("value", "fr")),
		EF(Sentinel(KeyCLIUsage), KeyCLIInvalidField, Msg("field", NewMessage(KeyCLIFieldRemoteDestPath)), BoundStr("value", "/bad")),
		E(KeyCmdResolveDirFailed, Msg("target", NewMessage(KeyCmdTargetWorkingDir))),
		E(KeyCmdInvalidDirPath, Msg("target", NewMessage(KeyCmdTargetVaultStore, BoundStr("name", "corp"))), BoundStr("path", "/bad")),
		E(KeyCmdInitComponentFailed, Msg("component", NewMessage(KeyCmdCompOfflineAEADVault, BoundStr("name", "corp")))),
		Wrap(Sentinel(KeySFTPCommandCanceled), KeySFTPUnknownOption, Str("cmd", "put"), Str("option", "-z")),
		EF(Sentinel(KeyMCPInvalidTransport), KeyMCPInvalidTransportValue, Str("value", "grpc")),
		Wrap(Sentinel(KeyMuxDaemonInvalidConfig), KeyMuxDaemonStopMasterFailed, Str("socket", "/tmp/mux.sock")),
		EF(Sentinel(KeyTUIInvalidConfig), KeyTUIConfigNilOpStream, Int("index", 2)),
	}
	for _, e := range sampleErrs {
		gotEn := enLoc.RenderError(e)
		gotZh := zhLoc.RenderError(e)
		if gotEn != e.Error() {
			t.Errorf("en RenderError(%q) != err.Error()(%q)", gotEn, e.Error())
		}
		if gotZh == "" || strings.ContainsAny(gotZh, "{}") {
			t.Errorf("zh RenderError 异常或存在占位符残留: %q", gotZh)
		}
	}
	assertNestedFieldAndDisplayContracts(t, enLoc, zhLoc)
}

func assertNestedFieldAndDisplayContracts(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	usageSent := Sentinel(KeyCLIUsage)
	nestedErr := EF(usageSent, KeyCLIInvalidField, Msg("field", NewMessage(KeyCLIFieldLocalFilePath)), BoundStr("value", "/bad"))
	if !errors.Is(nestedErr, usageSent) {
		t.Error("EF 嵌套字段错误应保留哨兵匹配")
	}
	if wantEn := "invalid local file path /bad"; nestedErr.Error() != wantEn {
		t.Errorf("嵌套字段规范英文 = %q, 期望 %q", nestedErr.Error(), wantEn)
	}
	if wantZh := "本地文件路径 取值 /bad 非法"; zhLoc.RenderError(nestedErr) != wantZh {
		t.Errorf("嵌套字段中文渲染 = %q, 期望 %q", zhLoc.RenderError(nestedErr), wantZh)
	}
	vaultErr := E(KeyCmdInitComponentFailed, Msg("component", NewMessage(KeyCmdCompOfflineAEADVault, BoundStr("name", "corp"))))
	if vaultErr.Error() != "failed to initialize offline_aead vault corp" || zhLoc.RenderError(vaultErr) != "初始化组件 offline_aead 凭据库 corp 失败" {
		t.Errorf("参数化组件嵌套渲染异常: en=%q zh=%q", vaultErr.Error(), zhLoc.RenderError(vaultErr))
	}
	warnEn := enLoc.T(KeyCLIConfigImportWarnLine, BoundStr("code", "W01"), BoundStr("subject", "web"), BoundStr("message", "skipped"))
	warnZh := zhLoc.T(KeyCLIConfigImportWarnLine, BoundStr("code", "W01"), BoundStr("subject", "web"), BoundStr("message", "skipped"))
	if warnEn != "  [warn] W01 (web): skipped" || warnZh != "  [警告] W01（web）：skipped" {
		t.Errorf("配置导入告警行渲染异常: en=%q zh=%q", warnEn, warnZh)
	}
	if enLoc.T(KeyCLIExecStatusOK) != "ok" || zhLoc.T(KeyCLIExecStatusOK) != "成功" ||
		enLoc.T(KeyCLIConfigImportLabelPlan) != "plan" || zhLoc.T(KeyCLIConfigImportLabelPlan) != "预检计划" {
		t.Error("CLI 展示标签中英文渲染异常")
	}
}

// TestErrorTemplatesSelfContained 强校验 (CoreKeys() ∪ RootErrorKeys()) \ {"common.detail", "common.error_join"}
// 的每条错误/诊断双语模板在剥离全部 {key} 占位符后均为自包含文本（EN 至少含 1 个 >=2 字母英文词，ZH 至少含 2 个汉字），
// 永久封堵 "{file}:{line}"、"{section}.{key}" 或纯占位符碎片模板回流。
func TestErrorTemplatesSelfContained(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() 失败: %v", err)
	}
	enTable := cat.entries[domi18n.LocaleEn]
	zhTable := cat.entries[domi18n.LocaleZh]
	keys := make([]domi18n.MessageID, 0, len(domi18n.CoreKeys())+len(RootErrorKeys()))
	keys = append(keys, domi18n.CoreKeys()...)
	keys = append(keys, RootErrorKeys()...)
	for _, id := range keys {
		key := string(id)
		if key == "common.detail" || key == "common.error_join" {
			continue
		}
		assertTemplateEntrySelfContained(t, key, enTable[key], zhTable[key])
	}
}

func assertTemplateEntrySelfContained(t *testing.T, key string, enEntry, zhEntry Entry) {
	t.Helper()
	assertSelfContainedForm(t, key, "Other", enEntry.Other, zhEntry.Other)
	if enEntry.One != "" || zhEntry.One != "" {
		assertSelfContainedForm(t, key, "One", enEntry.One, zhEntry.One)
	}
}

func assertSelfContainedForm(t *testing.T, key, form, enTmpl, zhTmpl string) {
	t.Helper()
	enStripped := stripTemplatePlaceholders(enTmpl)
	if !hasEnglishWordMinLen(enStripped, 2) {
		t.Errorf("键 %q (%s) EN 模板剥离占位符后缺少 >=2 字母英文实词: tmpl=%q stripped=%q", key, form, enTmpl, enStripped)
	}
	zhStripped := stripTemplatePlaceholders(zhTmpl)
	if countHanRunes(zhStripped) < 2 {
		t.Errorf("键 %q (%s) ZH 模板剥离占位符后汉字不足 2 个: tmpl=%q stripped=%q", key, form, zhTmpl, zhStripped)
	}
}

func stripTemplatePlaceholders(tmpl string) string {
	var b strings.Builder
	b.Grow(len(tmpl))
	for i := 0; i < len(tmpl); {
		if tmpl[i] == '{' {
			if i+1 < len(tmpl) && tmpl[i+1] == '{' {
				i += 2
				continue
			}
			if end := strings.IndexByte(tmpl[i+1:], '}'); end >= 0 {
				i += end + 2
				continue
			}
		}
		if tmpl[i] == '}' && i+1 < len(tmpl) && tmpl[i+1] == '}' {
			i += 2
			continue
		}
		b.WriteByte(tmpl[i])
		i++
	}
	return b.String()
}

func hasEnglishWordMinLen(s string, minLetters int) bool {
	run := 0
	for i := range len(s) {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			run++
			if run >= minLetters {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}

func countHanRunes(s string) int {
	n := 0
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			n++
		}
	}
	return n
}
