package cmdasset

import (
	"bytes"
	"strings"
	"testing"

	"go.uber.org/goleak"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/engine"
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
