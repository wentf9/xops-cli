// Package linearlease 实现 XOps v2 结构化并发与闭包线性借用静态分析器。
//
// 本分析器依托 shared internal/secretfact 与 internal/vetssa 强制执行三项并发与资源安全不变量：
//   - 规则 1：禁止在唯一白名单包 core/conc（不含外置 _test）之外使用裸 go 语句；
//   - 规则 2：通过 analysis.Fact 跨包传播 //xops:borrowed 与 //xops:syncclosure 契约，
//     彻底废除基于 With*/Use 函数名前缀的隐式放行（L2a），仅认显式 Fact、精确 (*secret.SecretBox).Use、
//     runtime/secret.Do、IIFE 与白名单标准库同步 iter.Seq；
//   - 规则 3：基于 vetssa 执行 SSA 级零逃逸追踪（含 new/append/comma-ok/<-ch/Defer/Go/Phi/CallerParam 隔离）。
package linearlease

import (
	"go/ast"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

// borrowedFuncFact 用于跨包传递 //xops:borrowed 与 //xops:syncclosure 高阶函数契约。
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
func NewAnalyzer(sf *analysis.Analyzer) *analysis.Analyzer {
	if sf == nil {
		sf = secretfact.NewAnalyzer()
	}
	return &analysis.Analyzer{
		Name:      "linearlease",
		Doc:       "检查白名单外裸 go 语句及 //xops:borrowed 闭包形参零逃逸（SSA 级显式契约）",
		FactTypes: []analysis.Fact{(*borrowedFuncFact)(nil)},
		Requires:  []*analysis.Analyzer{inspect.Analyzer, buildssa.Analyzer, sf},
		Run:       func(pass *analysis.Pass) (any, error) { return run(pass, sf) },
	}
}

func run(pass *analysis.Pass, sf *analysis.Analyzer) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) || pass.TypesInfo == nil {
		return nil, nil
	}
	pkgInfo := vetutil.ClassifyPass(pass)
	if !vetutil.AllowBareGo(pkgInfo) {
		vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.GoStmt)(nil)}, func(n ast.Node) {
			pass.ReportRangef(n, "linearlease: 白名单包 core/conc 之外禁止使用裸 go 语句，请使用 core/conc.Nursery")
		})
	}
	facts := collectAndExportFacts(pass)
	secretFacts, _ := pass.ResultOf[sf].(*secretfact.Result)
	analyzePackageLeases(pass, pkgInfo, vetssa.PackageSSA(pass), facts, secretFacts)
	return nil, nil
}
