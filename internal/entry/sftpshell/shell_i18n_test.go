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

	if got, want := enShell.formatApprovalRequired("destructive op", "sha256:deadbeef"), "approval required (destructive op, digest=sha256:deadbeef)"; got != want {
		t.Fatalf("en formatApprovalRequired = %q, want %q", got, want)
	}
	if got, want := zhShell.formatApprovalRequired("destructive op", "sha256:deadbeef"), "需要人工审批（destructive op，摘要=sha256:deadbeef）"; got != want {
		t.Fatalf("zh formatApprovalRequired = %q, want %q", got, want)
	}
}
