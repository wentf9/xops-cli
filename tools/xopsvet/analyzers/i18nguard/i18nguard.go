package i18nguard

import (
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

const (
	coreDomainI18nPkgPath  = vetutil.ModulePrefix + "/core/domain/i18n"
	internalI18nPkgPath    = vetutil.ModulePrefix + "/internal/i18n"
	hostSysInteractPkgPath = vetutil.ModulePrefix + "/internal/host/sys/interact"
)

// NewAnalyzer 创建并返回 i18nguard 国际化静态护栏分析器实例（M2 阶段分阶段作用域）。
func NewAnalyzer() *analysis.Analyzer {
	return newAnalyzer(false)
}

// newAnalyzer 构造分析器实例；enforceAllRules23 仅用于白盒测试验证全仓合闸后的规则 2/3 行为。
func newAnalyzer(enforceAllRules23 bool) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     "i18nguard",
		Doc:      "检查 i18n MessageID 强类型完整性、禁止裸错误构造绕过与禁止生产源码硬编码 CJK/全角标点字面量",
		Requires: []*analysis.Analyzer{inspect.Analyzer},
		Run: func(pass *analysis.Pass) (any, error) {
			return run(pass, enforceAllRules23)
		},
	}
}

func run(pass *analysis.Pass, enforceAllRules23 bool) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) || pass.TypesInfo == nil {
		return nil, nil
	}
	pkgInfo := vetutil.ClassifyPass(pass)
	if isAlwaysSkippedPkg(pkgInfo) {
		return nil, nil
	}
	// 规则 1：M1 起在全仓所有生产包立即生效。
	checkMessageIDIntegrity(pass, pkgInfo)
	// 规则 2 与规则 3：M2 阶段按 isRules23Enforced 分阶段合闸。
	if enforceAllRules23 || isRules23Enforced(pkgInfo) {
		checkRawErrorConstructions(pass, pkgInfo)
		checkCJKLiterals(pass)
	}
	return nil, nil
}

// isAlwaysSkippedPkg 返回永久豁免 i18nguard 检查的包集合（外置测试包、测试夹具与分析器自身）。
func isAlwaysSkippedPkg(pkgInfo vetutil.PkgInfo) bool {
	return pkgInfo.IsExternalTest ||
		pkgInfo.Layer == vetutil.LayerCorePortsTCK ||
		pkgInfo.Layer == vetutil.LayerCoreSim ||
		pkgInfo.Layer == vetutil.LayerToolsXopsvet
}

// isRules23Enforced 隔离 M1/M2 分阶段合闸范围：
//   - M1：仅对 core/domain/i18n 与 internal/i18n 强制规则 2/3；
//   - M2（当前）：扩展至 internal/entry/**、cmd/xops 与 internal/host/sys/interact（含子包）；
//   - M3：全仓迁移收尾后删除本函数并对全仓生产源码无条件合闸。
func isRules23Enforced(pkgInfo vetutil.PkgInfo) bool {
	if pkgInfo.IsExternalTest {
		return false
	}
	return pkgInfo.Layer == vetutil.LayerInternalI18n ||
		isCoreDomainI18nPkg(pkgInfo) ||
		pkgInfo.Layer == vetutil.LayerEntry ||
		pkgInfo.Layer == vetutil.LayerCmdXops ||
		isHostSysInteractPkg(pkgInfo)
}

func isCoreDomainI18nPkg(pkgInfo vetutil.PkgInfo) bool {
	return !pkgInfo.IsExternalTest && pkgInfo.Layer == vetutil.LayerCoreDomain &&
		matchPkgPrefix(pkgInfo.BasePath, coreDomainI18nPkgPath)
}

func isHostSysInteractPkg(pkgInfo vetutil.PkgInfo) bool {
	return !pkgInfo.IsExternalTest && pkgInfo.Layer == vetutil.LayerHostSys &&
		matchPkgPrefix(pkgInfo.BasePath, hostSysInteractPkgPath)
}

func isMessageIDOwnerPkg(pkgPath string) bool {
	return matchPkgPrefix(pkgPath, coreDomainI18nPkgPath) || matchPkgPrefix(pkgPath, internalI18nPkgPath)
}

func matchPkgPrefix(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}
