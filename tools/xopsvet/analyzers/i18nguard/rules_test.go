package i18nguard

import (
	"testing"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestI18nGuardFullScopeAndConcWhitelist(t *testing.T) {
	testdata := analysistest.TestData()
	analysistest.Run(
		t,
		testdata,
		newAnalyzer(true),
		"github.com/wentf9/xops-cli/core/conc",
		"github.com/wentf9/xops-cli/internal/entry/cli",
		"github.com/wentf9/xops-cli/cmd/xops",
		"github.com/wentf9/xops-cli/internal/host/sys/interact",
		"github.com/wentf9/xops-cli/core/ports/tck",
		"github.com/wentf9/xops-cli/core/internal/sim",
		"github.com/wentf9/xops-cli/tools/xopsvet/sample",
	)
}

func TestIsRules23Enforced_M2ScopeMatrix(t *testing.T) {
	cases := []struct {
		pkg  string
		want bool
	}{
		// M1 + M2 合闸范围：必须强制执行规则 2/3。
		{pkg: vetutil.ModulePrefix + "/core/domain/i18n", want: true},
		{pkg: vetutil.ModulePrefix + "/core/domain/i18n/internal/corecatalog", want: true},
		{pkg: vetutil.ModulePrefix + "/internal/i18n", want: true},
		{pkg: vetutil.ModulePrefix + "/internal/entry/cli", want: true},
		{pkg: vetutil.ModulePrefix + "/internal/entry/cli/clikit", want: true},
		{pkg: vetutil.ModulePrefix + "/internal/entry/cli/cmdssh", want: true},
		{pkg: vetutil.ModulePrefix + "/internal/entry/tui", want: true},
		{pkg: vetutil.ModulePrefix + "/internal/entry/sftpshell", want: true},
		{pkg: vetutil.ModulePrefix + "/internal/entry/mcpcmd", want: true},
		{pkg: vetutil.ModulePrefix + "/internal/entry/muxdaemon", want: true},
		{pkg: vetutil.ModulePrefix + "/cmd/xops", want: true},
		{pkg: vetutil.ModulePrefix + "/internal/host/sys/interact", want: true},
		{pkg: vetutil.ModulePrefix + "/internal/host/sys/interact/sub", want: true},

		// 外置测试包：必须豁免。
		{pkg: vetutil.ModulePrefix + "/internal/entry/cli_test", want: false},
		{pkg: vetutil.ModulePrefix + "/cmd/xops_test", want: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/sys/interact_test", want: false},

		// 留待 M3 Wave 3A-3E 迁移的包：M2 阶段暂未对规则 2/3 合闸。
		{pkg: vetutil.ModulePrefix + "/internal/host/sys", want: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/sys/agent", want: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/sys/tun", want: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/store", want: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/vault/offline", want: false},
		{pkg: vetutil.ModulePrefix + "/internal/host/audit", want: false},
		{pkg: vetutil.ModulePrefix + "/core/engine", want: false},
		{pkg: vetutil.ModulePrefix + "/core/ports", want: false},
		{pkg: vetutil.ModulePrefix + "/core/osfs", want: false},
		{pkg: vetutil.ModulePrefix + "/core/domain/pathalg", want: false},
		{pkg: vetutil.ModulePrefix + "/core/internal/usecase/session", want: false},
	}
	for _, tc := range cases {
		got := isRules23Enforced(vetutil.ClassifyPackage(tc.pkg))
		if got != tc.want {
			t.Errorf("isRules23Enforced(%q) = %v, want %v", tc.pkg, got, tc.want)
		}
	}
}
