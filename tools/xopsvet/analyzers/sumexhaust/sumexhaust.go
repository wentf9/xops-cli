// Package sumexhaust 实现 XOps v2 封闭和类型（Sealed Sum Type）穷尽检查分析器。
//
// 本分析器基于 go/types 接口方法集识别含 unexported sealed*() 方法的封闭接口，
// 并强制执行以下静态不变量：
//   - 对封闭接口执行 type switch 时，必须穷尽所属包中全部具体实现变体（区分值接收者 T/*T 与指针接收者 *T）；
//   - 自动过滤仅用于嵌入标记的未导出 sealed* 混入结构体（如 sealedCapability）；
//   - 禁止通过 case any: / case interface{}: / case nil: 绕过穷尽检查；
//   - 对安全决策类封闭和类型（//xops:failclosed、core/domain/security、core/internal/gate 或决策命名），
//     强制要求存在非空且显式拒绝/报错/panic 的 fail-closed default 分支。
package sumexhaust

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
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
		FactTypes: []analysis.Fact{(*failClosedSumFact)(nil)},
		Run:       run,
	}
}

func run(pass *analysis.Pass) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) {
		return nil, nil
	}
	if pass.TypesInfo == nil {
		return nil, nil
	}
	localFailClosed := collectFailClosedFacts(pass)
	ins := vetutil.InspectorOf(pass)
	nodeFilter := []ast.Node{(*ast.TypeSwitchStmt)(nil)}
	ins.Preorder(nodeFilter, func(n ast.Node) {
		ts, ok := n.(*ast.TypeSwitchStmt)
		if !ok {
			return
		}
		checkTypeSwitch(pass, ts, localFailClosed)
	})
	return nil, nil
}

// collectFailClosedFacts 扫描本包内标有 //xops:failclosed 的封闭和类型接口并导出 Fact。
func collectFailClosedFacts(pass *analysis.Pass) map[types.Object]bool {
	local := make(map[types.Object]bool)
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			collectDeclFailClosedFacts(pass, gen, local)
		}
	}
	return local
}

func collectDeclFailClosedFacts(pass *analysis.Pass, gen *ast.GenDecl, local map[types.Object]bool) {
	for _, spec := range gen.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok || ts.Assign.IsValid() {
			continue
		}
		if !vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveFailClosed) {
			continue
		}
		obj := pass.TypesInfo.Defs[ts.Name]
		if obj == nil {
			continue
		}
		iface, ok := types.Unalias(obj.Type()).Underlying().(*types.Interface)
		if !ok || len(findSealedMethods(iface)) == 0 {
			continue
		}
		local[obj] = true
		pass.ExportObjectFact(obj, &failClosedSumFact{})
	}
}
