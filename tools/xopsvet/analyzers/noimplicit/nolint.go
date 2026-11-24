package noimplicit

import (
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// checkNolintComments 在 AGENTS.md §3 规定的 7 个特权白名单包之外拦截行内 //nolint 指令。
// 外置 *_test 包已由 vetutil.AllowNolint 剥离特权，确保测试代码同样不得绕过 lint。
func checkNolintComments(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	if vetutil.AllowNolint(pkgInfo) {
		return
	}
	for _, file := range pass.Files {
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				if vetutil.HasNolintComment(c) {
					pass.ReportRangef(c, "noimplicit: 白名单包外禁止使用行内 //nolint 注解")
				}
			}
		}
	}
}
