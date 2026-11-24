// Package secretbox 实现 XOps v2 SecretBox 类型边界、防擦除守卫与 Use 白名单静态分析器。
//
// 本分析器从原 secrettaint 中正交拆出，聚焦与「*secret.SecretBox 句柄本身」相关的静态不变量：
//   - 规则 1（值持有类型与汇点封禁）：使用 vetutil.ContainsValueType（绝不进入 Interface.Methods 与 Signature），
//     禁止 SecretBox 进入受限/序列化/error 类型或匿名嵌入结构体，并禁止流入日志/错误/序列化/事件审计汇点；
//   - 防擦除守卫：接入 vetssa.CheckNoErasure 并精确联合豁免 core/domain/secret 白盒 *_test.go json/v2.Marshal*；
//   - 规则 3（明文消费白名单）：依托 secretfact 将 SecretBox.Use 与 //xops:secretuse 封锁于 5 个合法白名单包。
package secretbox

import (
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

const (
	secretPkgPath = vetutil.ModulePrefix + "/core/domain/secret"
	secretBoxName = "SecretBox"
)

// NewAnalyzer 创建并返回 secretbox 分析器实例。
func NewAnalyzer(sf *analysis.Analyzer) *analysis.Analyzer {
	if sf == nil {
		sf = secretfact.NewAnalyzer()
	}
	return &analysis.Analyzer{
		Name:     "secretbox",
		Doc:      "检查 SecretBox 值持有类型边界、匿名嵌入、接口/泛型防擦除、汇点封禁及 Use 明文消费包白名单",
		Requires: []*analysis.Analyzer{inspect.Analyzer, buildssa.Analyzer, sf},
		Run:      func(pass *analysis.Pass) (any, error) { return run(pass, sf) },
	}
}

func run(pass *analysis.Pass, sf *analysis.Analyzer) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) || pass.TypesInfo == nil {
		return nil, nil
	}
	pkgInfo := vetutil.ClassifyPackage(pass.Pkg.Path())
	s := vetssa.PackageSSA(pass)
	facts, _ := pass.ResultOf[sf].(*secretfact.Result)

	restricted := checkTypeAndEmbeddingBan(pass, pkgInfo)
	handledMI := checkSSASinksAndRestrictedStores(pass, s, pkgInfo, restricted)
	checkSecretBoxErasure(pass, s, pkgInfo, handledMI)
	checkSecretUseWhitelist(pass, s, pkgInfo, facts)
	return nil, nil
}

// isSecretBoxValueType 仅在值持有布局中检查 SecretBox，不穿透接口方法集与函数签名（CRIT-3）。
func isSecretBoxValueType(t types.Type) bool {
	return vetutil.ContainsValueNamed(t, secretPkgPath, secretBoxName)
}

// isExactSecretBox 判断 t 是否为裸 secret.SecretBox 或 *secret.SecretBox（不含容器包装）。
func isExactSecretBox(t types.Type) bool {
	named, ok := vetutil.UnwrapNamedType(t)
	return ok && vetutil.IsPkgSymbol(named.Obj(), secretPkgPath, secretBoxName)
}
