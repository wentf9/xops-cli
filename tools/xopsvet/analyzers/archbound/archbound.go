// Package archbound 实现 XOps v2 三模块六边形架构依赖与边界检查分析器。
//
// 本分析器按单个 AST 源码文件粒度检查导入路径（区分生产文件与测试文件，
// 并跳过 go test 合成的 .test 入口包），同时在 go/types 与 go/ssa 层强制执行：
//   - core/domain/** 仅允许 29 个纯函数 stdlib、golang.org/x/text/unicode/norm 及子包专属白名单，
//     并禁用 time 非确定性时钟符号；
//   - core/osfs 仅允许本地 AF_UNIX 相关 net 符号（18 包级符号 + 3 含 ctx 方法 + 3 包级直接绑定 + 四道防线）；
//   - core/conc 与 core/internal/foundation/{actor,trace} 零例外共享纯内存非 I/O stdlib 约束，
//     并全路径封死未登记 core/internal/foundation/* 子包；
//   - core/internal/mcpruntime 物理禁止引用 ports.OperatorReadFS。
package archbound

import (
	"strconv"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

// NewAnalyzer 创建并返回 archbound 架构边界静态分析器实例。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name: "archbound",
		Doc:  "检查 XOps v2 三模块单向依赖矩阵、domain 纯函数白名单、osfs 本地 net 四道防线及 mcpruntime 符号隔离",
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
	if pkgInfo.Layer == vetutil.LayerUnknown {
		return nil, nil
	}
	if isUnregisteredCoreLayer(pkgInfo.Layer) {
		if len(pass.Files) > 0 {
			pass.ReportRangef(pass.Files[0].Name, "archbound: 未登记的 core/ 包路径 %q，未在 RFC §2.1/§2.3 授权包清单内", pkgInfo.BasePath)
		}
		return nil, nil
	}
	checkFileImports(pass, pkgInfo)
	checkSymbolBoundaries(pass, pkgInfo)
	return nil, nil
}

func checkFileImports(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	for _, file := range pass.Files {
		isTest := pkgInfo.IsExternalTest || vetutil.IsTestFile(pass, file)
		for _, impSpec := range file.Imports {
			impPath, err := strconv.Unquote(impSpec.Path.Value)
			if err != nil {
				continue
			}
			if reason, ok := checkImportAllowed(pkgInfo, isTest, impPath); !ok {
				pass.ReportRangef(impSpec, "archbound: %s", reason)
			}
		}
	}
}
