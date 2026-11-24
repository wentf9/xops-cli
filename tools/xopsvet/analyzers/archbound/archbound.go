// Package archbound 实现 XOps v2 三模块六边形架构依赖与边界检查分析器。
//
// 本分析器按单个 AST 源码文件粒度检查导入路径（区分生产文件与测试文件，
// 并跳过 go test 合成的 .test 入口包），同时在 go/types 符号层强制执行：
//   - core/domain/** 仅允许 29 个纯函数 stdlib、golang.org/x/text/unicode/norm 及子包专属白名单，
//     并禁用 time 非确定性时钟符号；
//   - core/osfs 仅允许本地 AF_UNIX 相关 net 符号（三道 fail-closed 符号/参数/成员防线）；
//   - core/conc 与 core/internal/foundation/actor 施加纯内存非 I/O stdlib 与零外部依赖约束；
//   - core/internal/mcpruntime 物理禁止引用 ports.OperatorReadFS。
package archbound

import (
	"strconv"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// NewAnalyzer 创建并返回 archbound 架构边界静态分析器实例。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name: "archbound",
		Doc:  "检查 XOps v2 三模块单向依赖矩阵、domain 纯函数白名单、osfs 本地 net 边界及 mcpruntime 符号隔离",
		Run:  run,
	}
}

func run(pass *analysis.Pass) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) {
		return nil, nil
	}
	pkgInfo := vetutil.ClassifyPackage(pass.Pkg.Path())
	if pkgInfo.Layer == vetutil.LayerUnknown {
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
