package cmdasset

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"io"
	"strings"
	"testing"
	"unicode"

	"go.uber.org/goleak"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func TestRenderImportReportText_BilingualLabelsAndWarnings(t *testing.T) {
	defer goleak.VerifyNone(t)

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	rev, err := engine.ParseRevision("rev-1")
	if err != nil {
		t.Fatalf("ParseRevision 失败: %v", err)
	}
	warn, err := inventory.NewImportWarning("duplicate_host", "web-1", "skipped duplicate")
	if err != nil {
		t.Fatalf("NewImportWarning 失败: %v", err)
	}
	rep := inventory.ImportReport{
		SourceFormat: "csv",
		AddCount:     1,
		Warnings:     []inventory.ImportWarning{warn},
	}

	var zhPlanBuf, zhImportBuf, enPlanBuf bytes.Buffer
	zhLoc := cat.For(domi18n.LocaleZh)
	enLoc := cat.For(domi18n.LocaleEn)

	renderImportReportText(zhLoc, &zhPlanBuf, i18n.KeyCLIConfigImportLabelPlan, rev, false, rep)
	renderImportReportText(zhLoc, &zhImportBuf, i18n.KeyCLIConfigImportLabelImport, rev, true, rep)
	renderImportReportText(enLoc, &enPlanBuf, i18n.KeyCLIConfigImportLabelPlan, rev, false, rep)

	zhPlan := zhPlanBuf.String()
	if !strings.Contains(zhPlan, "预检计划") || !strings.Contains(zhPlan, "[警告]") {
		t.Fatalf("中文 plan 摘要缺少本地化标签: %q", zhPlan)
	}
	if strings.Contains(zhPlan, "[warn]") || strings.Contains(zhPlan, "plan (") {
		t.Fatalf("中文 plan 摘要不得泄露英文标签: %q", zhPlan)
	}
	if !strings.Contains(zhImportBuf.String(), "导入 (csv)") {
		t.Fatalf("中文 import 摘要缺少本地化标签: %q", zhImportBuf.String())
	}
	if !strings.Contains(enPlanBuf.String(), "plan (csv)") || !strings.Contains(enPlanBuf.String(), "[warn]") {
		t.Fatalf("英文 plan 摘要契约失配: %q", enPlanBuf.String())
	}
}

// TestConfigImport_LocalizedWarningsTextAndCanonicalJSON 验证 config import 双轨告警渲染：
//   - 文本模式下带 LocalizedMessage 的告警优先经 Localizer 按语种渲染（ZH 输出中文、EN 输出规范英文），
//     未携带 LocalizedMessage 的告警安全回退 warn.Message()，nil Localizer 亦零 panic 回退英文；
//   - JSON 模式下即便运行时处于中文语种，序列化输出仍恒为规范英文且零 localized 字段、零汉字。
func TestConfigImport_LocalizedWarningsTextAndCanonicalJSON(t *testing.T) {
	defer goleak.VerifyNone(t)

	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	rev, err := engine.ParseRevision("rev-2")
	if err != nil {
		t.Fatalf("ParseRevision 失败: %v", err)
	}
	rep := buildLocalizedImportTestReport(t)
	assertImportTextBilingual(t, cat, rev, rep)
	assertImportJSONCanonical(t, cat, rev, rep)
}

func buildLocalizedImportTestReport(t *testing.T) inventory.ImportReport {
	t.Helper()
	incMsg := i18n.NewMessage(
		i18n.KeyHostOpenSSHDiagIncludeSkip,
		i18n.Int("line", 1),
		i18n.BoundStr("patterns", "conf.d/*.conf"),
	)
	incWarn, err := inventory.NewLocalizedImportWarning("include_skipped", "conf.d/*.conf", incMsg)
	if err != nil {
		t.Fatalf("NewLocalizedImportWarning(include_skipped) 失败: %v", err)
	}
	userWarn, err := inventory.NewLocalizedImportWarning("user_missing", "web-2", i18n.NewMessage(i18n.KeyHostStoreImportWarnUser))
	if err != nil {
		t.Fatalf("NewLocalizedImportWarning(user_missing) 失败: %v", err)
	}
	plainWarn, err := inventory.NewImportWarning("plain_fallback", "web-3", "fallback plain warning")
	if err != nil {
		t.Fatalf("NewImportWarning 失败: %v", err)
	}
	return inventory.ImportReport{
		SourceFormat: "openssh",
		AddCount:     1,
		Warnings:     []inventory.ImportWarning{incWarn, userWarn, plainWarn},
	}
}

func assertImportTextBilingual(t *testing.T, cat *i18n.Catalog, rev engine.Revision, rep inventory.ImportReport) {
	t.Helper()
	var zhBuf, enBuf, nilBuf bytes.Buffer
	renderImportReportText(cat.For(domi18n.LocaleZh), &zhBuf, i18n.KeyCLIConfigImportLabelPlan, rev, false, rep)
	renderImportReportText(cat.For(domi18n.LocaleEn), &enBuf, i18n.KeyCLIConfigImportLabelPlan, rev, false, rep)
	renderImportReportText(nil, &nilBuf, i18n.KeyCLIConfigImportLabelPlan, rev, false, rep)

	zhOut := zhBuf.String()
	assertContainsAll(t, "zh", zhOut, []string{
		`第 1 行：纯流式导入已跳过 Include "conf.d/*.conf"（不展开本地文件）`,
		"缺少 User 且未配置默认用户名，已跳过",
		"fallback plain warning",
	})
	if strings.Contains(zhOut, "skipped in stream-only import") || strings.Contains(zhOut, "no default username configured") {
		t.Fatalf("中文文本输出不得残留英文告警句: %q", zhOut)
	}

	wantEn := []string{
		`line 1: Include "conf.d/*.conf" skipped in stream-only import (local files are not expanded)`,
		"missing User and no default username configured; skipped",
		"fallback plain warning",
	}
	assertContainsAll(t, "en", enBuf.String(), wantEn)
	assertContainsAll(t, "nil", nilBuf.String(), wantEn)
}

func assertContainsAll(t *testing.T, label, out string, wants []string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Fatalf("%s 文本输出缺少预期内容 %q: %q", label, want, out)
		}
	}
}

func assertImportJSONCanonical(t *testing.T, cat *i18n.Catalog, rev engine.Revision, rep inventory.ImportReport) {
	t.Helper()
	var jsonBuf bytes.Buffer
	rt := &clikit.Runtime{
		Stdout:    &jsonBuf,
		Catalog:   cat,
		Localizer: cat.For(domi18n.LocaleZh),
	}
	type planView struct {
		OK           bool                   `json:"ok"`
		BaseRevision engine.Revision        `json:"base_revision"`
		Report       inventory.ImportReport `json:"report"`
	}
	code := rt.WriteResult(true, planView{OK: true, BaseRevision: rev, Report: rep}, func(w io.Writer) {
		renderImportReportText(rt.Loc(), w, i18n.KeyCLIConfigImportLabelPlan, rev, false, rep)
	})
	if code != clikit.ExitOK {
		t.Fatalf("WriteResult(json=true) 返回非零退出码: %d", code)
	}
	rawJSON := jsonBuf.String()
	if strings.Contains(rawJSON, "localized") || strings.ContainsFunc(rawJSON, func(r rune) bool { return unicode.Is(unicode.Han, r) }) {
		t.Fatalf("中文语种下 --json 告警输出不得含 localized 或汉字: %q", rawJSON)
	}
	var decoded planView
	if err := jsonv2.Unmarshal(jsonBuf.Bytes(), &decoded); err != nil {
		t.Fatalf("反序列化 JSON 报告失败: %v raw=%q", err, rawJSON)
	}
	wantJSONMsgs := []string{
		`line 1: Include "conf.d/*.conf" skipped in stream-only import (local files are not expanded)`,
		"missing User and no default username configured; skipped",
		"fallback plain warning",
	}
	if len(decoded.Report.Warnings) != len(wantJSONMsgs) {
		t.Fatalf("JSON 告警数 = %d, 期望 %d", len(decoded.Report.Warnings), len(wantJSONMsgs))
	}
	for i, want := range wantJSONMsgs {
		w := decoded.Report.Warnings[i]
		if w.Message() != want || w.LocalizedMessage().IsSome() {
			t.Fatalf("JSON 告警[%d] 失配: msg=%q want=%q hasLoc=%v", i, w.Message(), want, w.LocalizedMessage().IsSome())
		}
	}
}
