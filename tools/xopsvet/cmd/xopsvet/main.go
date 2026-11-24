// 命令 xopsvet 是 XOps v2 的自建静态编译器护栏入口，通过 go vet -vettool 执行多分析器联合检查。
package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/archbound"
	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/noimplicit"
	"github.com/wentf9/xops-cli/tools/xopsvet/analyzers/osboundary"
)

func main() {
	multichecker.Main(
		archbound.NewAnalyzer(),
		noimplicit.NewAnalyzer(),
		osboundary.NewAnalyzer(),
	)
}
