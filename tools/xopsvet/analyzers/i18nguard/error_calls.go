package i18nguard

import (
	"go/ast"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// checkRawErrorConstructions 执行规则 2：禁止通过 errors.New、fmt.Errorf（含函数值引用）
// 或底层 string 自定义错误类型绕过结构化 i18n 错误体系（显式放行 errors.Join）。
func checkRawErrorConstructions(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	if isRule2AllowedPkg(pkgInfo) {
		return
	}
	checkBannedErrorUses(pass)
	checkStringErrorTypes(pass)
}

// isRule2AllowedPkg 返回规则 2 永久基础设施白名单包（core/domain/i18n、core/conc 及测试/工具包）。
func isRule2AllowedPkg(pkgInfo vetutil.PkgInfo) bool {
	return isCoreDomainI18nPkg(pkgInfo) ||
		pkgInfo.Layer == vetutil.LayerCoreConc ||
		pkgInfo.Layer == vetutil.LayerCoreSim ||
		pkgInfo.Layer == vetutil.LayerCorePortsTCK ||
		pkgInfo.Layer == vetutil.LayerToolsXopsvet
}

// checkBannedErrorUses 基于 TypesInfo.Uses 拦截直接调用与函数值赋值（如 f := errors.New），显式允许 errors.Join。
func checkBannedErrorUses(pass *analysis.Pass) {
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.Ident)(nil)}, func(n ast.Node) {
		id, ok := n.(*ast.Ident)
		if !ok || vetutil.IsPosInTestFile(pass, id.Pos()) {
			return
		}
		obj := pass.TypesInfo.Uses[id]
		if vetutil.IsPkgSymbol(obj, "errors", "New") {
			pass.ReportRangef(id, "i18nguard: 禁止引用 errors.New，请使用 i18n 结构化错误构造器（Sentinel/E/EF/Wrap/WrapS）")
		} else if vetutil.IsPkgSymbol(obj, "fmt", "Errorf") {
			pass.ReportRangef(id, "i18nguard: 禁止引用 fmt.Errorf，请使用 i18n 结构化错误构造器（E/EF/Wrap/WrapS）")
		}
	})
}

// checkStringErrorTypes 禁止在 core/domain/i18n 之外声明底层为 string 且实现 Error() string 的自定义错误类型。
func checkStringErrorTypes(pass *analysis.Pass) {
	vetutil.ForEachTypeSpec(pass, func(file *ast.File, _ *ast.GenDecl, ts *ast.TypeSpec) {
		if vetutil.IsTestFile(pass, file) || ts.Assign.IsValid() {
			return
		}
		obj, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName)
		if !ok || obj == nil || obj.Type() == nil {
			return
		}
		basic, isBasic := obj.Type().Underlying().(*types.Basic)
		if !isBasic || basic.Info()&types.IsString == 0 {
			return
		}
		if hasProdErrorMethod(pass, obj.Type()) {
			pass.ReportRangef(ts.Name, "i18nguard: 禁止声明基于 string 的自定义错误类型 %s，请使用 i18n 结构化错误体系", ts.Name.Name)
		}
	})
}

func hasProdErrorMethod(pass *analysis.Pass, t types.Type) bool {
	if !vetutil.ImplementsError(t) {
		return false
	}
	ms := types.NewMethodSet(types.NewPointer(t))
	sel := ms.Lookup(pass.Pkg, "Error")
	return sel != nil && sel.Obj() != nil && !vetutil.IsPosInTestFile(pass, sel.Obj().Pos())
}
