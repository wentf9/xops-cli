// Package noimplicit 实现 XOps v2 去隐式行为检查分析器。
//
// 本分析器在生产与测试文件中统一执行以下静态约束（仅跳过合成 .test 入口包）：
//   - 禁止定义 func init()；
//   - 禁止可变包级 var（仅豁免编译期接口断言 var _ I = (*T)(nil) 与不可变哨兵错误）；
//   - 禁止 core/internal/foundation/trace 之外使用 context.WithValue / ctx.Value；
//   - 禁止匿名接口断言 x.(interface{...})（含 type switch）；
//   - 禁止 7 个特权白名单包之外使用行内 //nolint: 注解；
//   - 禁止 Event / Audit / MCP / Config DTO 结构体裸用 time.Duration（须用 algebraic.Duration）。
package noimplicit

import (
	"go/ast"
	"go/token"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// NewAnalyzer 创建并返回 noimplicit 去隐式静态分析器实例。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name: "noimplicit",
		Doc:  "检查并禁止 init()、可变包级 var、白名单外 context.WithValue/nolint、匿名接口断言及 DTO 裸 time.Duration",
		Run:  run,
	}
}

func run(pass *analysis.Pass) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) {
		return nil, nil
	}
	pkgInfo := vetutil.ClassifyPackage(pass.Pkg.Path())
	checkPackageDecls(pass)
	checkContextAndAnonIfaces(pass, pkgInfo)
	checkNolintComments(pass, pkgInfo)
	checkDTOs(pass, pkgInfo)
	return nil, nil
}

func checkPackageDecls(pass *analysis.Pass) {
	sentinels := collectSentinelVars(pass)
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name != nil && d.Name.Name == "init" {
					pass.ReportRangef(d.Name, "noimplicit: 禁止定义 func init()")
				}
			case *ast.GenDecl:
				if d.Tok == token.VAR {
					checkPkgVarDecl(pass, d, sentinels)
				}
			}
		}
	}
	checkSentinelMutations(pass, sentinels)
}
