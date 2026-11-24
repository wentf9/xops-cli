// Package sumexhaust 实现 XOps v2 封闭和类型（Sealed Sum Type）穷尽检查分析器。
//
// 本分析器基于 go/types 接口方法集识别含 unexported sealed*() 方法的封闭接口，强制执行：
//   - 对封闭接口执行 type switch 时穷尽全部具体实现变体（区分值接收者 T/*T 与指针接收者 *T）；
//   - 自动过滤仅用于嵌入标记的未导出 sealed* 混入结构体，并禁通过 case any/interface{}/nil 绕过；
//   - 对安全决策类封闭和类型强制要求非空且显式拒绝/报错/panic 的 fail-closed default 分支。
package sumexhaust

import (
	"go/ast"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

// failClosedSumFact 用于跨包传递标有 //xops:failclosed 的封闭和类型接口元数据。
type failClosedSumFact struct{}

// AFact 标记 failClosedSumFact 为 go/analysis 跨包分析事实。
func (*failClosedSumFact) AFact() {}

// String 返回事实的可读标识（用于 analysistest 验证）。
func (*failClosedSumFact) String() string { return "failclosedsum" }

// NewAnalyzer 创建并返回 sumexhaust 封闭和类型穷尽检查分析器实例。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:      "sumexhaust",
		Doc:       "检查封闭和类型（sealed*() 接口）的 type switch 穷尽性及安全决策 fail-closed default 分支",
		Requires:  []*analysis.Analyzer{inspect.Analyzer},
		FactTypes: []analysis.Fact{(*failClosedSumFact)(nil)},
		Run:       run,
	}
}

func run(pass *analysis.Pass) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) || pass.TypesInfo == nil {
		return nil, nil
	}
	localFailClosed := collectFailClosedFacts(pass)
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.TypeSwitchStmt)(nil)}, func(n ast.Node) {
		if ts, ok := n.(*ast.TypeSwitchStmt); ok {
			checkTypeSwitch(pass, ts, localFailClosed)
		}
	})
	return nil, nil
}

// collectFailClosedFacts 扫描本包内标有 //xops:failclosed 的封闭和类型接口并导出 Fact。
func collectFailClosedFacts(pass *analysis.Pass) map[types.Object]bool {
	local := make(map[types.Object]bool)
	vetutil.ForEachTypeSpec(pass, func(_ *ast.File, gen *ast.GenDecl, ts *ast.TypeSpec) {
		if ts.Assign.IsValid() || !vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveFailClosed) {
			return
		}
		if obj := pass.TypesInfo.Defs[ts.Name]; obj != nil {
			if iface, ok := types.Unalias(obj.Type()).Underlying().(*types.Interface); ok && len(findSealedMethods(iface)) > 0 {
				local[obj] = true
				pass.ExportObjectFact(obj, &failClosedSumFact{})
			}
		}
	})
	return local
}
