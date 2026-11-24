// Package failclosed 实现 XOps v2 失败关闭（Fail-Closed）与不透明构造静态分析器。
//
// 本分析器在包级与跨包层面强制执行三项核心安全约束：
//   - 规则 1：禁止返回裸 bool 或 (..., bool) 的函数吞噬新产生的局部 error（或 <-chan error），
//     同时精确豁免入参仅分类检验的纯 errors.Is / errors.As / errors.AsType 谓词；
//   - 规则 2：通过 analysis.Fact 跨包追踪 //xops:opaque 类型，禁止在定义包外通过字面量、
//     new(pkg.T) 或非自身类型转换 pkg.T(x) 绕过构造器；
//   - 规则 3：校验标有 //xops:failclosed 的标量枚举与结构体满足零值最严/默认拒绝语义。
package failclosed

import (
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// opaqueTypeFact 用于跨包传递 //xops:opaque 类型标记，阻止外部包绕过构造器直接构造实例。
type opaqueTypeFact struct{}

// AFact 标记 opaqueTypeFact 为 go/analysis 跨包分析事实。
func (*opaqueTypeFact) AFact() {}

// String 返回事实的可读标识（用于 analysistest 验证）。
func (*opaqueTypeFact) String() string { return "opaque" }

// NewAnalyzer 创建并返回 failclosed 失败关闭静态分析器实例。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:      "failclosed",
		Doc:       "检查局部 error 吞噬转 bool、包外 //xops:opaque 构造及 //xops:failclosed 零值最严不变量",
		FactTypes: []analysis.Fact{(*opaqueTypeFact)(nil)},
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
	exportOpaqueFacts(pass)
	checkErrorSwallowing(pass)
	checkExternalOpaqueConstructions(pass)
	checkFailClosedTypes(pass)
	return nil, nil
}
