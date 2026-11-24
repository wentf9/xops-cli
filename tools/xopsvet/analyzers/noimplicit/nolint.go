package noimplicit

import (
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

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
