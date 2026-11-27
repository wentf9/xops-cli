package i18nguard

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// checkForbiddenWithFallbackUses 禁止在 core/domain/i18n 与 internal/i18n 之外引用任何 *WithFallback 桥接符号（含直接调用与函数值）。
func checkForbiddenWithFallbackUses(pass *analysis.Pass) {
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.Ident)(nil)}, func(n ast.Node) {
		id, ok := n.(*ast.Ident)
		if !ok || vetutil.IsPosInTestFile(pass, id.Pos()) {
			return
		}
		obj := pass.TypesInfo.Uses[id]
		if obj != nil && vetutil.ObjectPkgPath(obj) == coreDomainI18nPkgPath && strings.HasSuffix(obj.Name(), "WithFallback") {
			pass.ReportRangef(id, "i18nguard: 禁止在 core/domain/i18n 与 internal/i18n 之外引用 %s，请改用无 Fallback 后缀的导出构造器", obj.Name())
		}
	})
}

// checkMessageIDGenericInstances 扫描 TypesInfo.Instances，封禁属主包外将含 MessageID 的类型实参
// 实例化至非标准库、非属主包且对应约束含底层 string 项（如 ~string/cmp.Ordered）的泛型函数或类型。
func checkMessageIDGenericInstances(pass *analysis.Pass) {
	var diags []vetutil.Diag
	for ident, inst := range pass.TypesInfo.Instances {
		if ident == nil || !ident.Pos().IsValid() || vetutil.IsPosInTestFile(pass, ident.Pos()) {
			continue
		}
		if isForbiddenMessageIDInstance(pass.TypesInfo.Uses[ident], inst.TypeArgs) {
			diags = append(diags, vetutil.Diag{Pos: ident.Pos(), End: ident.End(), Msg: msgIDGenericErr})
		}
	}
	vetutil.ReportSortedDedup(pass, diags, false)
}

func isForbiddenMessageIDInstance(obj types.Object, typeArgs *types.TypeList) bool {
	if obj == nil || typeArgs == nil || typeArgs.Len() == 0 {
		return false
	}
	objPkg := vetutil.ObjectPkgPath(obj)
	if objPkg != "" && (vetutil.IsStdlibImport(objPkg) || isMessageIDOwnerPkg(objPkg)) {
		return false
	}
	tps := objectTypeParams(obj)
	if tps == nil {
		return false
	}
	for i := range min(tps.Len(), typeArgs.Len()) {
		if vetutil.TypeContainsNamed(typeArgs.At(i), coreDomainI18nPkgPath, "MessageID") &&
			hasStringUnderlyingTerm(tps.At(i).Constraint(), map[types.Type]bool{}) {
			return true
		}
	}
	return false
}

func objectTypeParams(obj types.Object) *types.TypeParamList {
	switch o := obj.(type) {
	case *types.Func:
		if sig, ok := o.Type().(*types.Signature); ok {
			if sig.TypeParams().Len() > 0 {
				return sig.TypeParams()
			}
			return sig.RecvTypeParams()
		}
	case *types.TypeName:
		if al, ok := o.Type().(*types.Alias); ok {
			return al.TypeParams()
		}
		if named, ok := o.Type().(*types.Named); ok {
			return named.TypeParams()
		}
	}
	return nil
}

// hasStringUnderlyingTerm 递归检查泛型约束接口是否包含底层类型为 string 的项（含联合项 ~string 与嵌入接口如 cmp.Ordered）。
func hasStringUnderlyingTerm(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	u := types.Unalias(t)
	if seen[u] {
		return false
	}
	seen[u] = true
	switch v := u.(type) {
	case *types.Basic:
		return v.Info()&types.IsString != 0
	case *types.Named:
		return hasStringUnderlyingTerm(v.Underlying(), seen)
	case *types.Union:
		for i := range v.Len() {
			if hasStringUnderlyingTerm(v.Term(i).Type(), seen) {
				return true
			}
		}
	case *types.Interface:
		for i := range v.NumEmbeddeds() {
			if hasStringUnderlyingTerm(v.EmbeddedType(i), seen) {
				return true
			}
		}
	}
	return false
}

// checkMessageIDTypeConversion 对齐 failclosed/opaque.go，剥离任意层指针后校验 MessageID 值/指针类型转换：
// 属主包外指针转换仅放行 nil 与严格同构的目标指针类型，封堵 *(*MessageID)(&s) 与 (**MessageID)(...)。
func checkMessageIDTypeConversion(pass *analysis.Pass, call *ast.CallExpr, target types.Type, isOwner bool, reported map[token.Pos]bool) {
	if isOwner || len(call.Args) != 1 || target == nil {
		return
	}
	targetType := types.Unalias(target)
	base, isPtr := peelPointerLayers(targetType)
	if !isMessageIDType(base) {
		return
	}
	if isPtr {
		if !isAllowedMessageIDPtrArg(pass.TypesInfo, call.Args[0], targetType) {
			reportOnce(pass, call, reported, msgIDConvErr)
		}
		return
	}
	if !isAllowedMessageIDExpr(pass.TypesInfo, call.Args[0], false) {
		reportOnce(pass, call, reported, msgIDConvErr)
	}
}

func peelPointerLayers(t types.Type) (types.Type, bool) {
	cur, isPtr := types.Unalias(t), false
	for ptr, ok := cur.(*types.Pointer); ok; ptr, ok = cur.(*types.Pointer) {
		isPtr, cur = true, types.Unalias(ptr.Elem())
	}
	return cur, isPtr
}

func isAllowedMessageIDPtrArg(info *types.Info, arg ast.Expr, targetType types.Type) bool {
	if isNilExpr(info, arg) {
		return true
	}
	tv, ok := info.Types[ast.Unparen(arg)]
	return ok && tv.Type != nil && types.Identical(types.Unalias(tv.Type), targetType)
}

func isNilExpr(info *types.Info, expr ast.Expr) bool {
	e := ast.Unparen(expr)
	if tv, ok := info.Types[e]; ok && tv.Type == types.Typ[types.UntypedNil] {
		return true
	}
	id, ok := e.(*ast.Ident)
	if !ok {
		return false
	}
	_, isNil := info.Uses[id].(*types.Nil)
	return isNil
}

// checkI18nConstructorCall 校验对 core/domain/i18n 与 internal/i18n 构造/渲染函数的 MessageID 实参：
// 禁止传入空常量 MessageIDInvalid，并禁止将 internal/i18n 常量传入 core/domain/i18n 自动兜底构造器。
func checkI18nConstructorCall(pass *analysis.Pass, call *ast.CallExpr, reported map[token.Pos]bool) {
	callee := vetutil.ResolveCalledObject(pass.TypesInfo, call)
	if callee == nil {
		return
	}
	isI18nCall := isI18nConstructorOrRenderer(callee)
	isCoreAuto := isCoreAutoFallbackConstructor(callee)
	if !isI18nCall && !isCoreAuto {
		return
	}
	for _, arg := range call.Args {
		checkI18nConstructorArg(pass, arg, isI18nCall, isCoreAuto, reported)
	}
}

func checkI18nConstructorArg(pass *analysis.Pass, arg ast.Expr, isI18nCall, isCoreAuto bool, reported map[token.Pos]bool) {
	tv, ok := pass.TypesInfo.Types[arg]
	if !ok || !isMessageIDType(tv.Type) {
		return
	}
	if isI18nCall && tv.Value != nil && tv.Value.Kind() == constant.String && constant.StringVal(tv.Value) == "" {
		reportOnce(pass, arg, reported, msgIDInvalidArgErr)
		return
	}
	if isCoreAuto && isInternalI18nConstExpr(pass.TypesInfo, arg) {
		reportOnce(pass, arg, reported, msgIDCrossDomain)
	}
}

func isI18nConstructorOrRenderer(obj types.Object) bool {
	switch vetutil.ObjectPkgPath(obj) {
	case coreDomainI18nPkgPath:
		return slices.Contains([]string{
			"NewMessage", "NewMessageWithFallback", "NewPluralMessage", "NewPluralMessageWithFallback",
			"Sentinel", "SentinelWithFallback", "NewErrorWithFallback",
			"E", "EF", "Wrap", "WrapS",
			"EWithFallback", "EFWithFallback", "WrapWithFallback", "WrapSWithFallback",
		}, obj.Name())
	case internalI18nPkgPath:
		return slices.Contains([]string{
			"NewMessage", "NewPluralMessage",
			"Sentinel", "E", "EF", "Wrap", "WrapS",
			"T", "TPlural",
		}, obj.Name())
	default:
		return false
	}
}

func isCoreAutoFallbackConstructor(obj types.Object) bool {
	return vetutil.IsPkgSymbol(obj, coreDomainI18nPkgPath,
		"Sentinel", "E", "EF", "Wrap", "WrapS", "NewMessage", "NewPluralMessage",
	)
}

func isInternalI18nConstExpr(info *types.Info, expr ast.Expr) bool {
	c := resolveMessageIDConst(info, expr)
	return c != nil && matchPkgPrefix(vetutil.ObjectPkgPath(c), internalI18nPkgPath)
}

func resolveMessageIDConst(info *types.Info, expr ast.Expr) *types.Const {
	cur := unwrapMessageIDIdentityConv(info, expr)
	var obj types.Object
	switch e := cur.(type) {
	case *ast.Ident:
		obj = info.Uses[e]
	case *ast.SelectorExpr:
		if info.Selections[e] != nil {
			return nil
		}
		obj = info.Uses[e.Sel]
	default:
		return nil
	}
	c, _ := obj.(*types.Const)
	if c == nil || !isMessageIDType(c.Type()) {
		return nil
	}
	return c
}

func unwrapMessageIDIdentityConv(info *types.Info, expr ast.Expr) ast.Expr {
	for {
		e := ast.Unparen(expr)
		call, ok := e.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return e
		}
		tv, ok := info.Types[call.Fun]
		if !ok || !tv.IsType() || !isMessageIDType(tv.Type) {
			return e
		}
		expr = call.Args[0]
	}
}
