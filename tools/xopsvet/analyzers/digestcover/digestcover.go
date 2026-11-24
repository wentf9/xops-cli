// Package digestcover 实现 XOps v2 规范摘要（Canonical Hash）字段覆盖静态分析器。
//
// 本分析器在编译期静态校验所有标记 //xops:canonicalhash 的结构体类型：
//   - 必须为结构体类型（禁止标注在非结构体声明上）；
//   - 必须存在对应的 WriteCanonical 方法（支持值/指针接收者与同包跨文件定义）；
//   - WriteCanonical 及所调用的同包辅助方法/函数禁止使用 reflect；
//   - 除匿名空白字段 _ 与显式标注 //xops:hash-exclude:<非空理由> 的字段外，
//     结构体全部字段均须在 WriteCanonical 中显式读取/编码（拒收 _ = h.Field 空弃与仅 LHS 写入）。
package digestcover

import (
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

// NewAnalyzer 创建并返回 digestcover 规范摘要字段覆盖静态分析器实例。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     "digestcover",
		Doc:      "检查 //xops:canonicalhash 结构体的 WriteCanonical 全字段覆盖及 //xops:hash-exclude:<reason> 合法性",
		Requires: []*analysis.Analyzer{inspect.Analyzer},
		Run:      run,
	}
}

func run(pass *analysis.Pass) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) {
		return nil, nil
	}
	if pass.TypesInfo == nil {
		return nil, nil
	}
	targets, writeMethods, funcDecls := collectTargetsAndFuncs(pass)
	for _, target := range targets {
		orig := target.named.Origin()
		checkTargetCoverage(pass, target, writeMethods[orig], funcDecls)
	}
	return nil, nil
}
