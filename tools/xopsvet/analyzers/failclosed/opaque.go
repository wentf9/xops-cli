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
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.CompositeLit)(nil), (*ast.CallExpr)(nil)}, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.CompositeLit:
			if named, ok := vetutil.UnwrapNamedType(pass.TypesInfo.TypeOf(node)); ok {
				if orig := externalOpaqueOrigin(pass, named); orig != nil {
					pass.ReportRangef(node, "failclosed: 禁止在包外通过字面量构造 //xops:opaque 类型 %s，请调用导出构造器", orig.Name())
				}
			}
		case *ast.CallExpr:
			checkOpaqueCall(pass, node)
		}
	})
}

func checkOpaqueCall(pass *analysis.Pass, call *ast.CallExpr) {
	if len(call.Args) != 1 {
		return
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok && id.Name == "new" {
		if b, isB := pass.TypesInfo.Uses[id].(*types.Builtin); isB && b.Name() == "new" {
			checkOpaqueNewArg(pass, call)
			return
		}
	}
	checkOpaqueTypeConversion(pass, call)
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

func checkOpaqueTypeConversion(pass *analysis.Pass, call *ast.CallExpr) {
	tv, ok := pass.TypesInfo.Types[call.Fun]
	if !ok || !tv.IsType() || tv.Type == nil {
		return
	}
	targetType := types.Unalias(tv.Type)
	cur, isPtr := targetType, false
	for ptr, ok := cur.(*types.Pointer); ok; ptr, ok = cur.(*types.Pointer) {
		isPtr, cur = true, types.Unalias(ptr.Elem())
	}
	named, ok := cur.(*types.Named)
	if !ok {
		return
	}
	orig := externalOpaqueOrigin(pass, named)
	if orig == nil || (isPtr && isNilExpr(pass.TypesInfo, call.Args[0])) || isSameNamedTypeArg(pass.TypesInfo, call.Args[0], targetType) {
		return
	}
	pass.ReportRangef(call, "failclosed: 禁止在包外通过类型转换构造 //xops:opaque 类型 %s，请调用导出构造器", orig.Name())
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
