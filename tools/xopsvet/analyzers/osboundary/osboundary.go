// Package osboundary 实现 XOps v2 OS 边界与远端路径分隔符边界检查分析器。
//
// 本分析器按生产/测试双层契约执行以下静态约束（跳过合成 .test 入口包）：
//   - 生产源码（跳过 *_test.go 与测试契约夹具层 core/ports/tck）：
//     1. core/osfs 之外禁止直接调用裸 OS 文件、文件锁、ACL、os.Root 及 Unix Socket 监听 API；
//     2. internal/host/sys 之外禁止调用环境变量读写与外部进程执行 API（os.Getenv/os/exec 等）；
//   - 全仓所有源码文件（含测试文件与 core/ports/tck）：
//     禁止对 RemotePath 及其派生值调用 path/filepath.*（防止 Windows 反斜杠污染远端 POSIX 路径）。
package osboundary

import (
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// NewAnalyzer 创建并返回 osboundary 系统边界静态分析器实例。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name: "osboundary",
		Doc:  "检查并禁止白名单外裸 OS 文件/锁/ACL/os.Root、env/exec 调用及对 RemotePath 使用 path/filepath",
		Run:  run,
	}
}

func run(pass *analysis.Pass) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) {
		return nil, nil
	}
	pkgInfo := vetutil.ClassifyPackage(pass.Pkg.Path())
	checkOSSymbols(pass, pkgInfo)
	checkRemotePathFilepath(pass)
	return nil, nil
}
