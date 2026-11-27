package sftpshell

import (
	"testing"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/internal/i18n"
)

func TestFormatApprovalRequired_Bilingual(t *testing.T) {
	cat, err := i18n.LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog 失败: %v", err)
	}
	enShell := &Shell{loc: cat.For(domi18n.LocaleEn), valid: true}
	zhShell := &Shell{loc: cat.For(domi18n.LocaleZh), valid: true}

	structuredParam := domi18n.Msg("reason", domi18n.NewMessage(domi18n.KeyGateReasonRiskMeetsThreshold))
	if got, want := enShell.formatApprovalRequired(structuredParam, "sha256:deadbeef"), "approval required (operation risk meets or exceeds approval threshold, digest=sha256:deadbeef)"; got != want {
		t.Fatalf("en formatApprovalRequired(structured) = %q, want %q", got, want)
	}
	if got, want := zhShell.formatApprovalRequired(structuredParam, "sha256:deadbeef"), "需要人工审批（操作风险达到或超过审批阈值，摘要=sha256:deadbeef）"; got != want {
		t.Fatalf("zh formatApprovalRequired(structured) = %q, want %q", got, want)
	}

	freeParam := i18n.BoundStr("reason", "destructive op")
	if got, want := enShell.formatApprovalRequired(freeParam, "sha256:deadbeef"), "approval required (destructive op, digest=sha256:deadbeef)"; got != want {
		t.Fatalf("en formatApprovalRequired(free) = %q, want %q", got, want)
	}
	if got, want := zhShell.formatApprovalRequired(freeParam, "sha256:deadbeef"), "需要人工审批（destructive op，摘要=sha256:deadbeef）"; got != want {
		t.Fatalf("zh formatApprovalRequired(free) = %q, want %q", got, want)
	}
}
