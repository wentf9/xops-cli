package i18nguard

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

func TestPermanentSkipAndRule2AllowlistMatrix(t *testing.T) {
	cases := []struct {
		pkg           string
		wantSkipAll   bool
		wantRule2Skip bool
	}{
		// 全局永久跳过：外置 *_test、core/ports/tck、core/internal/sim、tools/xopsvet。
		{pkg: vetutil.ModulePrefix + "/core/ports/tck", wantSkipAll: true, wantRule2Skip: true},
		{pkg: vetutil.ModulePrefix + "/core/internal/sim", wantSkipAll: true, wantRule2Skip: true},
		{pkg: vetutil.ModulePrefix + "/tools/xopsvet/analyzers/i18nguard", wantSkipAll: true, wantRule2Skip: true},
		{pkg: vetutil.ModulePrefix + "/core/engine_test", wantSkipAll: true, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/sys_test", wantSkipAll: true, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/internal/entry/cli_test", wantSkipAll: true, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/cmd/xops_test", wantSkipAll: true, wantRule2Skip: false},

		// 规则 2 永久基础设施白名单（仍受规则 1 与规则 3 约束）：core/domain/i18n（含 internal/corecatalog）与 core/conc。
		{pkg: vetutil.ModulePrefix + "/core/domain/i18n", wantSkipAll: false, wantRule2Skip: true},
		{pkg: vetutil.ModulePrefix + "/core/domain/i18n/internal/corecatalog", wantSkipAll: false, wantRule2Skip: true},
		{pkg: vetutil.ModulePrefix + "/core/conc", wantSkipAll: false, wantRule2Skip: true},

		// 其余全仓生产包：规则 1、规则 2 与规则 3 100% 强制执行，无豁免。
		{pkg: vetutil.ModulePrefix + "/internal/i18n", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/core/domain/algebraic", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/core/domain/pathalg", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/core/ports", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/core/events", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/core/osfs", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/core/engine", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/core/internal/pool", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/core/internal/gate", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/core/internal/sshnet/dial", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/core/internal/usecase/session", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/core/internal/mcpruntime/protocol", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/sys", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/sys/interact", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/sys/agent", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/store", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/vault/offline", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/audit", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/internal/entry/cli", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/internal/entry/tui", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/internal/entry/sftpshell", wantSkipAll: false, wantRule2Skip: false},
		{pkg: vetutil.ModulePrefix + "/cmd/xops", wantSkipAll: false, wantRule2Skip: false},
	}
	for _, tc := range cases {
		info := vetutil.ClassifyPackage(tc.pkg)
		if got := isAlwaysSkippedPkg(info); got != tc.wantSkipAll {
			t.Errorf("isAlwaysSkippedPkg(%q) = %v, want %v", tc.pkg, got, tc.wantSkipAll)
		}
		if got := isRule2AllowedPkg(info); got != tc.wantRule2Skip {
			t.Errorf("isRule2AllowedPkg(%q) = %v, want %v", tc.pkg, got, tc.wantRule2Skip)
		}
	}
}
