// Package noimplicit 实现 XOps v2 去隐式行为检查分析器。
//
// 本分析器在生产与测试文件中统一执行以下静态约束（仅跳过合成 .test 入口包）：
//   - 禁止定义 func init()；
//   - 禁止可变包级 var（仅豁免编译期零副作用接口断言、不可变哨兵错误含 i18n.Sentinel 与跨包只读重导出、
//     cmd/xops 只读 //xops:buildvar 及 internal/i18n 六重门控只读 //go:embed embed.FS，
//     并覆盖 Go 1.27 new(expr) 与非结构体复合字面量 Key 纯度校验、全包级只读变量不可变保护）；
//   - 禁止 core/internal/foundation/trace 之外使用 context.WithValue / ctx.Value，
//     并基于 vetssa 封堵 Value(any) any 窄接口声明、擦除（含 ChangeType/TypeAssert）与 IsInvoke 调用；
//   - 禁止匿名接口断言（含泛型 IndexExpr/IndexListExpr 与 type switch）；
//   - 按文件禁止 8 个特权包生产源码之外（含白盒与外置测试）使用行内 //nolint: 注解；
//   - 禁止持久化/序列化 DTO 裸用 time.Duration（移除全局 *Config 误杀，顶层嵌套一致，先检 TypeArgs 并区分 JSON/YAML 语义）。
package noimplicit

import (
	"go/ast"
	"go/token"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

// NewAnalyzer 创建并返回 noimplicit 去隐式静态分析器实例。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name: "noimplicit",
		Doc:  "检查并禁止 init()、可变包级 var、白名单外 context.WithValue/nolint、匿名接口断言及序列化 DTO 裸 time.Duration",
		Requires: []*analysis.Analyzer{
			inspect.Analyzer,
			buildssa.Analyzer,
		},
		Run: run,
	}
}

func run(pass *analysis.Pass) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) {
		return nil, nil
	}
	pkgInfo := vetutil.ClassifyPass(pass)
	checkPackageDecls(pass, pkgInfo)
	checkContextAndAnonIfaces(pass, pkgInfo)
	checkNolintComments(pass, pkgInfo)
	checkDTOs(pass, pkgInfo)
	return nil, nil
}

func checkPackageDecls(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	sentinels := collectSentinelVars(pass)
	buildVars := collectBuildVars(pass, pkgInfo)
	embedVars := collectEmbedVars(pass, pkgInfo)
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil && d.Name != nil && d.Name.Name == "init" {
					pass.ReportRangef(d.Name, "noimplicit: 禁止定义 func init()")
				}
			case *ast.GenDecl:
				if d.Tok == token.VAR {
					checkPkgVarDecl(pass, d, sentinels, buildVars, embedVars)
				}
			}
		}
	}
	checkImmutableVarMutations(pass, sentinels, buildVars, embedVars)
}
