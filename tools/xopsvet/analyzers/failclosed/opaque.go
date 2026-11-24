package failclosed

import (
	"go/ast"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

func exportOpaqueFacts(pass *analysis.Pass) {
	vetutil.ForEachTypeSpec(pass, func(_ *ast.File, gen *ast.GenDecl, ts *ast.TypeSpec) {
		if ts.Assign.IsValid() || !vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveOpaque) {
			return
		}
		if tn, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName); ok && tn != nil {
			pass.ExportObjectFact(tn, &opaqueTypeFact{})
		}
	})
}

func checkExternalOpaqueConstructions(pass *analysis.Pass) {
	vetutil.InspectorOf(pass).Preorder([]ast.Node{
		(*ast.CompositeLit)(nil), (*ast.CallExpr)(nil),
		(*ast.ValueSpec)(nil), (*ast.AssignStmt)(nil), (*ast.ReturnStmt)(nil),
	}, func(n ast.Node) { checkOpaqueNode(pass, n) })
}

func checkOpaqueNode(pass *analysis.Pass, n ast.Node) {
	switch node := n.(type) {
	case *ast.CompositeLit:
		checkOpaqueCompositeLit(pass, node)
	case *ast.CallExpr:
		if !checkOpaqueCall(pass, node) {
			checkImplicitOpaqueExprs(pass, node.Args)
		}
	case *ast.ValueSpec:
		checkImplicitOpaqueExprs(pass, node.Values)
	case *ast.AssignStmt:
		checkImplicitOpaqueExprs(pass, node.Rhs)
	case *ast.ReturnStmt:
		checkImplicitOpaqueExprs(pass, node.Results)
	}
}

func checkOpaqueCompositeLit(pass *analysis.Pass, lit *ast.CompositeLit) {
	if named, ok := vetutil.UnwrapNamedType(pass.TypesInfo.TypeOf(lit)); ok {
		if orig := externalOpaqueOrigin(pass, named); orig != nil {
			pass.ReportRangef(lit, "failclosed: 禁止在包外通过字面量构造 //xops:opaque 类型 %s，请调用导出构造器", orig.Name())
		}
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			checkImplicitOpaqueConstExpr(pass, kv.Value)
		} else {
			checkImplicitOpaqueConstExpr(pass, elt)
		}
	}
}

func checkImplicitOpaqueExprs(pass *analysis.Pass, exprs []ast.Expr) {
	for _, e := range exprs {
		checkImplicitOpaqueConstExpr(pass, e)
	}
}

// checkImplicitOpaqueConstExpr 拦截将无类型常量隐式赋给包外标量 //xops:opaque 类型（跳过显式类型转换以免重复报错，M7）。
func checkImplicitOpaqueConstExpr(pass *analysis.Pass, expr ast.Expr) {
	if call, isCall := ast.Unparen(expr).(*ast.CallExpr); isCall {
		if ctv, ok := pass.TypesInfo.Types[call.Fun]; ok && ctv.IsType() {
			return
		}
	}
	tv, ok := pass.TypesInfo.Types[expr]
	if !ok || tv.Value == nil || tv.Type == nil {
		return
	}
	named, ok := types.Unalias(tv.Type).(*types.Named)
	if !ok {
		return
	}
	orig := externalOpaqueOrigin(pass, named)
	if orig == nil || isSameNamedTypeArg(pass.TypesInfo, expr, named) {
		return
	}
	pass.ReportRangef(expr, "failclosed: 禁止在包外通过无类型常量隐式构造 //xops:opaque 类型 %s，请调用导出构造器", orig.Name())
}

func checkOpaqueCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	if len(call.Args) != 1 {
		return false
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok && id.Name == "new" {
		if b, isB := pass.TypesInfo.Uses[id].(*types.Builtin); isB && b.Name() == "new" {
			checkOpaqueNewArg(pass, call)
			return true
		}
	}
	return checkOpaqueTypeConversion(pass, call)
}

func checkOpaqueNewArg(pass *analysis.Pass, call *ast.CallExpr) {
	// 仅拦截 new(pkg.T) 类型实参；Go 1.26+ new(expr) 若来自合法构造器返回值则放行。
	tv, ok := pass.TypesInfo.Types[call.Args[0]]
	if !ok || !tv.IsType() {
		return
	}
	if named, ok := types.Unalias(tv.Type).(*types.Named); ok {
		if orig := externalOpaqueOrigin(pass, named); orig != nil {
			pass.ReportRangef(call, "failclosed: 禁止在包外通过 new(%s) 构造 //xops:opaque 类型，请调用导出构造器", orig.Name())
		}
	}
}

func checkOpaqueTypeConversion(pass *analysis.Pass, call *ast.CallExpr) bool {
	tv, ok := pass.TypesInfo.Types[call.Fun]
	if !ok || !tv.IsType() || tv.Type == nil {
		return false
	}
	targetType := types.Unalias(tv.Type)
	cur, isPtr := targetType, false
	for ptr, ok := cur.(*types.Pointer); ok; ptr, ok = cur.(*types.Pointer) {
		isPtr, cur = true, types.Unalias(ptr.Elem())
	}
	named, ok := cur.(*types.Named)
	if !ok {
		return true
	}
	orig := externalOpaqueOrigin(pass, named)
	if orig == nil || (isPtr && isNilExpr(pass.TypesInfo, call.Args[0])) || isSameNamedTypeArg(pass.TypesInfo, call.Args[0], targetType) {
		return true
	}
	pass.ReportRangef(call, "failclosed: 禁止在包外通过类型转换构造 //xops:opaque 类型 %s，请调用导出构造器", orig.Name())
	return true
}

func isNilExpr(info *types.Info, expr ast.Expr) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	_, isNil := info.Uses[id].(*types.Nil)
	return isNil || id.Name == "nil"
}

func isSameNamedTypeArg(info *types.Info, expr ast.Expr, targetType types.Type) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return false
	case *ast.Ident:
		obj := info.Uses[e]
		return obj != nil && types.Identical(types.Unalias(obj.Type()), targetType)
	case *ast.SelectorExpr:
		if sel := info.Selections[e]; sel != nil {
			return types.Identical(types.Unalias(sel.Type()), targetType)
		}
		obj := info.Uses[e.Sel]
		return obj != nil && types.Identical(types.Unalias(obj.Type()), targetType)
	default:
		tv, ok := info.Types[e]
		return ok && tv.Value == nil && tv.Type != nil && types.Identical(types.Unalias(tv.Type), targetType)
	}
}

func externalOpaqueOrigin(pass *analysis.Pass, named *types.Named) *types.TypeName {
	if named == nil || named.Origin() == nil {
		return nil
	}
	orig := named.Origin().Obj()
	if orig == nil || orig.Pkg() == nil || orig.Pkg() == pass.Pkg || !pass.ImportObjectFact(orig, new(opaqueTypeFact)) {
		return nil
	}
	return orig
}
