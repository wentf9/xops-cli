package i18nguard

import (
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
)

const (
	coreDomainI18nPkgPath = vetutil.ModulePrefix + "/core/domain/i18n"
	internalI18nPkgPath   = vetutil.ModulePrefix + "/internal/i18n"
)

// NewAnalyzer 创建并返回全仓合闸的 i18nguard 国际化静态护栏分析器实例。
func NewAnalyzer() *analysis.Analyzer {
	return &analysis.Analyzer{
		Name:     "i18nguard",
		Doc:      "全仓检查 i18n MessageID 强类型完整性、禁止裸错误构造绕过、禁硬编码 CJK/全角标点、哨兵防吞噬与参数散文拦截",
		Requires: []*analysis.Analyzer{inspect.Analyzer},
		Run:      run,
	}
}

func run(pass *analysis.Pass) (any, error) {
	if vetutil.IsSyntheticTestMain(pass) || pass.TypesInfo == nil {
		return nil, nil
	}
	pkgInfo := vetutil.ClassifyPass(pass)
	if isAlwaysSkippedPkg(pkgInfo) {
		return nil, nil
	}
	// 全仓所有非跳过生产包无条件执行规则 1、规则 2（含永久基础设施白名单）、规则 3、规则 4 与规则 5。
	checkMessageIDIntegrity(pass, pkgInfo)
	checkRawErrorConstructions(pass, pkgInfo)
	checkCJKLiterals(pass)
	checkSentinelAndDetailGuards(pass)
	checkConstParamProse(pass)
	return nil, nil
}

// isAlwaysSkippedPkg 返回永久豁免 i18nguard 检查的包集合（外置测试包、测试夹具与分析器自身）。
func isAlwaysSkippedPkg(pkgInfo vetutil.PkgInfo) bool {
	return pkgInfo.IsExternalTest ||
		pkgInfo.Layer == vetutil.LayerCorePortsTCK ||
		pkgInfo.Layer == vetutil.LayerCoreSim ||
		pkgInfo.Layer == vetutil.LayerToolsXopsvet
}

// isCoreDomainI18nPkg 精确匹配 core/domain/i18n 主包（其 internal/{textalg,errchain,corecatalog/**} 子包不豁免规则 2）。
func isCoreDomainI18nPkg(pkgInfo vetutil.PkgInfo) bool {
	return !pkgInfo.IsExternalTest && pkgInfo.Layer == vetutil.LayerCoreDomain &&
		pkgInfo.BasePath == coreDomainI18nPkgPath
}

// isMessageIDOwnerPkg 判断包是否为 MessageID 常量合法属主（core/domain/i18n 或 internal/i18n 及其非 internal 子包），
// 显式排除两包下任何含 "internal" 路径段的子包，防止 internal/* 伪造 MessageID。
func isMessageIDOwnerPkg(pkgPath string) bool {
	return isOwnedPkgWithoutInternal(pkgPath, coreDomainI18nPkgPath) ||
		isOwnedPkgWithoutInternal(pkgPath, internalI18nPkgPath)
}

func isOwnedPkgWithoutInternal(pkgPath, ownerPrefix string) bool {
	if pkgPath == ownerPrefix {
		return true
	}
	rel, ok := strings.CutPrefix(pkgPath, ownerPrefix+"/")
	if !ok || rel == "" {
		return false
	}
	return !slices.Contains(strings.Split(rel, "/"), "internal")
}

func matchPkgPrefix(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}
