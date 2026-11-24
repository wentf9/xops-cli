package noimplicit

import (
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// checkNolintComments 按单个源码文件强制 RFC v2.3.3 §5 规定的行内 //nolint 禁令：
// 仅 8 个特权包的生产源码文件允许 //nolint:；其余全部包及全仓所有测试文件
// （含 8 个特权包的白盒 *_test.go、外置 *_test、cmd/xops、core/internal/sim）均 100% 禁止。
func checkNolintComments(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	for _, file := range pass.Files {
		if vetutil.AllowNolintInFile(pass, file, pkgInfo) {
			continue
		}
		msg := "noimplicit: 白名单包外禁止使用行内 //nolint 注解"
		if vetutil.AllowNolint(pkgInfo) {
			msg = "noimplicit: 测试文件（含特权包白盒 *_test.go）禁止使用行内 //nolint 注解"
		}
		for _, cg := range file.Comments {
			for _, c := range cg.List {
				if vetutil.HasNolintComment(c) {
					pass.ReportRangef(c, "%s", msg)
				}
			}
		}
	}
}
