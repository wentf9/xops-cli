package i18nguard

import (
	"go/ast"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// checkRawErrorConstructions 执行规则 2：禁止通过 errors.New、fmt.Errorf（含函数值引用）、
// 底层 string 自定义错误类型或未实现 LocalizableView() ErrorNode 的自定义具体错误类型绕过结构化 i18n 体系（显式放行 errors.Join）。
func checkRawErrorConstructions(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	if isRule2AllowedPkg(pkgInfo) {
		return
	}
	checkBannedErrorUses(pass)
	checkCustomErrorTypes(pass)
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

// checkCustomErrorTypes 禁止声明底层为 string 的自定义错误类型，并要求所有其他实现生产 error 接口的具体类型
// 在匹配的接收者方法集上同步实现 LocalizableView() core/domain/i18n.ErrorNode。
func checkCustomErrorTypes(pass *analysis.Pass) {
	vetutil.ForEachTypeSpec(pass, func(file *ast.File, _ *ast.GenDecl, ts *ast.TypeSpec) {
		if vetutil.IsTestFile(pass, file) || ts.Assign.IsValid() {
			return
		}
		obj, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName)
		if !ok || obj == nil || obj.Type() == nil {
			return
		}
		t := types.Unalias(obj.Type())
		if _, isIface := t.Underlying().(*types.Interface); isIface {
			return
		}
		ms := prodErrorMethodSet(pass, t)
		if ms == nil {
			return
		}
		if isStringUnderlying(t) {
			pass.ReportRangef(ts.Name, "i18nguard: 禁止声明基于 string 的自定义错误类型 %s，请使用 i18n 结构化错误体系", ts.Name.Name)
			return
		}
		if !hasProdLocalizableView(pass, ms) {
			pass.ReportRangef(ts.Name, "i18nguard: 自定义错误类型 %s 必须在匹配的接收者方法集上实现 LocalizableView() core/domain/i18n.ErrorNode", ts.Name.Name)
		}
	})
}

func isStringUnderlying(t types.Type) bool {
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Info()&types.IsString != 0
}

// prodErrorMethodSet 返回令具体类型 t 实现生产 error 接口的最小匹配方法集（优先值方法集，其次指针方法集）。
func prodErrorMethodSet(pass *analysis.Pass, t types.Type) *types.MethodSet {
	errIface := builtinErrorInterface()
	if errIface == nil {
		return nil
	}
	if types.Implements(t, errIface) {
		if ms := types.NewMethodSet(t); isProdMethod(pass, ms.Lookup(pass.Pkg, "Error")) {
			return ms
		}
		return nil
	}
	ptr := types.NewPointer(t)
	if !types.Implements(ptr, errIface) {
		return nil
	}
	if ms := types.NewMethodSet(ptr); isProdMethod(pass, ms.Lookup(pass.Pkg, "Error")) {
		return ms
	}
	return nil
}

func builtinErrorInterface() *types.Interface {
	errObj := types.Universe.Lookup("error")
	if errObj == nil {
		return nil
	}
	iface, _ := errObj.Type().Underlying().(*types.Interface)
	return iface
}

func isProdMethod(pass *analysis.Pass, sel *types.Selection) bool {
	return sel != nil && sel.Obj() != nil && !vetutil.IsPosInTestFile(pass, sel.Obj().Pos())
}

func hasProdLocalizableView(pass *analysis.Pass, ms *types.MethodSet) bool {
	sel := ms.Lookup(pass.Pkg, "LocalizableView")
	if !isProdMethod(pass, sel) {
		return false
	}
	fn, ok := sel.Obj().(*types.Func)
	if !ok {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Variadic() || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
		return false
	}
	named, ok := types.Unalias(sig.Results().At(0).Type()).(*types.Named)
	return ok && named != nil && vetutil.IsPkgSymbol(named.Obj(), coreDomainI18nPkgPath, "ErrorNode")
}
