// 命令 xopsvet 是 XOps v2 的自建静态编译器护栏入口，通过 go vet -vettool 执行 10 个正交分析器联合检查。
package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/archbound"
	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/digestcover"
	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/failclosed"
	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/i18nguard"
	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/linearlease"
	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/noimplicit"
	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/osboundary"
	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/secretbox"
	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/secrettaint"
	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/sumexhaust"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
)

func main() {
	// 构造单一共享前置 secretfact 实例，避免包级可变 var 并向 secretbox/secrettaint/linearlease 统一注入。
	sf := secretfact.NewAnalyzer()
	multichecker.Main(
		archbound.NewAnalyzer(),
		noimplicit.NewAnalyzer(),
		osboundary.NewAnalyzer(),
		sumexhaust.NewAnalyzer(),
		failclosed.NewAnalyzer(),
		digestcover.NewAnalyzer(),
		secretbox.NewAnalyzer(sf),
		secrettaint.NewAnalyzer(sf),
		linearlease.NewAnalyzer(sf),
		i18nguard.NewAnalyzer(),
	)
}
