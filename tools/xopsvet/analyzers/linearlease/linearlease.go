// Package linearlease 实现 XOps v2 结构化并发与闭包线性借用静态分析器。
//
// 本分析器在包级与跨包层面强制执行三项核心并发与资源安全不变量：
//   - 规则 1：禁止在白名单包 core/internal/foundation/conc 之外使用裸 go 语句；
//   - 规则 2：通过 analysis.Fact 跨包传播 //xops:borrowed 与 //xops:syncclosure 契约，
//     禁止借用闭包形参及其局部别名逃逸至外部变量、具名返回值、结构体字段、容器、
//     channel、return 语句、go 语句或非同步子闭包；
//   - 规则 3：放行作为实参直接传入同步 With* / Use / //xops:syncclosure / IIFE / defer
//     的栈内子回调，但在递归进入内层回调体时持续强制外层借用参数零逃逸。
package linearlease

import (
	"go/ast"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// borrowedFuncFact 用于跨包传递 //xops:borrowed 与 //xops:syncclosure 高阶函数契约。
// 所有字段均导出以满足 encoding/gob 跨包分析事实序列化要求。
type borrowedFuncFact struct {
	SyncClosure      bool          // 是否为保证同步栈内执行的高阶函数
	CallbackBorrowed map[int][]int // 外层形参索引 -> 对应回调形参内受 //xops:borrowed 约束的参数索引列表
	DirectBorrowed   []int         // 仅用于命名函数类型（type Cb func(...)），记录自身受约束的形参索引
}

// AFact 标记 borrowedFuncFact 为 go/analysis 跨包分析事实。
func (*borrowedFuncFact) AFact() {}

// String 返回事实的确定性简短文本标识（用于 analysistest 核验）。
func (f *borrowedFuncFact) String() string {
	if f == nil {
		return ""
	}
	hasBorrowed := len(f.CallbackBorrowed) > 0 || len(f.DirectBorrowed) > 0
	switch {
	case f.SyncClosure && hasBorrowed:
		return "syncclosure,borrowed"
	case f.SyncClosure:
		return "syncclosure"
	case hasBorrowed:
		return "borrowed"
	default:
		return ""
	}
}

// NewAnalyzer 创建并返回 linearlease 并发与线性借用零逃逸静态分析器实例。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:      "linearlease",
		Doc:       "检查白名单外裸 go 语句及 //xops:borrowed 闭包形参零逃逸（支持同步嵌套 Bracket 回调）",
		FactTypes: []analysis.Fact{(*borrowedFuncFact)(nil)},
		Run:       run,
	}
}

func run(pass *analysis.Pass) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) || pass.TypesInfo == nil {
		return nil, nil
	}
	pkgInfo := vetutil.ClassifyPackage(pass.Pkg.Path())
	checkBareGoStatements(pass, pkgInfo)
	facts := collectAndExportFacts(pass)
	analyzePackageFunctions(pass, facts)
	return nil, nil
}

// checkBareGoStatements 强制规则 1：仅 core/internal/foundation/conc（不含外置 _test）允许裸 go。
func checkBareGoStatements(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	if vetutil.AllowBareGo(pkgInfo) {
		return
	}
	ins := vetutil.InspectorOf(pass)
	ins.Preorder([]ast.Node{(*ast.GoStmt)(nil)}, func(n ast.Node) {
		stmt, ok := n.(*ast.GoStmt)
		if !ok {
			return
		}
		pass.ReportRangef(
			stmt,
			"linearlease: 白名单包 core/internal/foundation/conc 之外禁止使用裸 go 语句，请使用 conc.Nursery 或 conc.DualActor",
		)
	})
}
