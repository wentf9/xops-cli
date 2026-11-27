package i18n

import (
	"errors"
	"strings"
	"testing"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
)

// TestHostSentinelsDistinctAndRenderParity 验证全部 12 个宿主层哨兵错误在 errors.Is 下两两隔离无串味，
// 且所有宿主代表性参数化错误在 EN 下满足 enLoc.RenderError(err) == err.Error()、在 ZH 下无占位符残留。
func TestHostSentinelsDistinctAndRenderParity(t *testing.T) {
	cat, err := LoadCatalog()
	if err != nil {
		t.Fatalf("LoadCatalog() 失败: %v", err)
	}
	enLoc := cat.For(domi18n.LocaleEn)
	zhLoc := cat.For(domi18n.LocaleZh)

	assertHostSentinelsDistinct(t, enLoc, zhLoc)
	assertHostSampleErrorsRender(t, enLoc, zhLoc)
}

func assertHostSentinelsDistinct(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	sentinelIDs := []domi18n.MessageID{
		KeyHostAuditCorruptLog,
		KeyHostOpenSSHIncludeCycle,
		KeyHostOpenSSHIncludeDepthExceeded,
		KeyHostOpenSSHInvalidConfig,
		KeyHostStoreUnsupportedSchema,
		KeyHostStorePlaintextSecretForbidden,
		KeyHostStoreInvalidCSV,
		KeyHostStoreCorruptJournalFrame,
		KeyHostYAMLUnsupportedSchema,
		KeyHostSysOrphanedProcessGroup,
		KeyHostSysInputCanceled,
		KeyHostVaultHelperProtocol,
	}
	sentinels := make([]error, len(sentinelIDs))
	for i, id := range sentinelIDs {
		sentinels[i] = Sentinel(id)
		if got := enLoc.RenderError(sentinels[i]); got != sentinels[i].Error() {
			t.Errorf("哨兵 %q 英文渲染不一致: got=%q want=%q", id, got, sentinels[i].Error())
		}
		if gotZh := zhLoc.RenderError(sentinels[i]); gotZh == "" || strings.ContainsAny(gotZh, "{}") {
			t.Errorf("哨兵 %q 中文渲染异常: %q", id, gotZh)
		}
	}
	for i := range sentinels {
		for j := range sentinels {
			got := errors.Is(sentinels[i], sentinels[j])
			if (i == j) != got {
				t.Errorf("errors.Is(%q, %q) = %v, 期望 %v", sentinelIDs[i], sentinelIDs[j], got, i == j)
			}
		}
	}
}

func assertHostSampleErrorsRender(t *testing.T, enLoc, zhLoc *Localizer) {
	t.Helper()
	samples := []error{
		EF(Sentinel(KeyHostAuditCorruptLog), KeyHostAuditLineUnmarshalFailed, Int("line", 42)),
		E(KeyHostAuditUnreconciledLock, BoundStr("path", "run/proc.lock")),
		EF(Sentinel(KeyHostOpenSSHIncludeDepthExceeded), KeyHostOpenSSHIncludeDepthAt, BoundStr("path", "/etc/ssh/conf.d/a.conf"), Int("depth", 17)),
		EF(Sentinel(KeyHostOpenSSHInvalidConfig), KeyHostOpenSSHLineError, BoundStr("file", "~/.ssh/config"), Int("line", 12)),
		EF(Sentinel(KeyHostOpenSSHInvalidConfig), KeyHostOpenSSHInvalidClause, BoundStr("file", "~/.ssh/config"), Int("line", 9), Str("clause", "Match")),
		E(KeyHostOpenSSHDiagIncludeSkip, Int("line", 3), BoundStr("patterns", "conf.d/*.conf")),
		E(KeyHostStoreImportWarnDirective, Str("directive", "IdentityFile"), BoundStr("value", "~/.ssh/%r_id")),
		EF(Sentinel(KeyHostStoreInvalidCSV), KeyHostStoreCSVColumnCountMismatch, Int("row", 3), Int("got", 2), Int("want", 4)),
		EF(Sentinel(KeyHostStoreCorruptJournalFrame), KeyHostStoreWALEmpty, Uint64("generation", 2)),
		EF(Sentinel(KeyHostYAMLUnsupportedSchema), KeyHostYAMLInvalidVersion, Int("version", 1)),
		E(KeyHostYAMLNodeOverrideFieldInvalid, BoundStr("pattern", "prod-*"), Str("field", "approval_threshold")),
		E(KeyHostSysTerminalNonPosSize, Int("cols", 0), Int("rows", 24)),
		E(KeyHostAgentEnvUnset, Str("env", "SSH_AUTH_SOCK")),
		E(KeyHostSSHFPDNSQuestionMismatch, BoundStr("name", "a.example"), Int("qtype", 44), Int("qclass", 1)),
		E(KeyHostTUNInvalidIPVersion, Str("byte", "0x00")),
		E(KeyHostVaultKDFParamsInvalid, Uint64("time", 0), Uint64("memory_kib", 32), Int("threads", 0)),
		E(KeyHostVaultKeychainOSStatus, Int("status", -25308)),
		E(KeyHostVaultSSHandshakeFailed, Str("step", "Auth")),
		E(KeyHostLimitOutOfRange, Str("field", "MaxAuditBytes"), Int64("value", -1), Int64("max", 268435456)),
	}
	for _, sample := range samples {
		if gotEn := enLoc.RenderError(sample); gotEn != sample.Error() {
			t.Errorf("en RenderError(%q) != err.Error()(%q)", gotEn, sample.Error())
		}
		if gotZh := zhLoc.RenderError(sample); gotZh == "" || strings.ContainsAny(gotZh, "{}") {
			t.Errorf("zh RenderError 异常或残留占位符: %q", gotZh)
		}
	}
}
