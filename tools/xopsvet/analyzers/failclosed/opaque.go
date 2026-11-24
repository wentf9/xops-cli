package failclosed

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

func exportOpaqueFacts(pass *analysis.Pass) {
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			exportDeclOpaqueFacts(pass, gen)
		}
	}
}

func exportDeclOpaqueFacts(pass *analysis.Pass, gen *ast.GenDecl) {
	for _, spec := range gen.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if !ok || ts.Assign.IsValid() {
			continue
		}
		if !vetutil.TypeSpecHasDirective(gen, ts, vetutil.DirectiveOpaque) {
			continue
		}
		tn, ok := pass.TypesInfo.Defs[ts.Name].(*types.TypeName)
		if ok && tn != nil {
			pass.ExportObjectFact(tn, &opaqueTypeFact{})
		}
	}
}

func checkExternalOpaqueConstructions(pass *analysis.Pass) {
	ins := vetutil.InspectorOf(pass)
	nodeFilter := []ast.Node{
		(*ast.CompositeLit)(nil),
		(*ast.CallExpr)(nil),
	}
	ins.Preorder(nodeFilter, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.CompositeLit:
			checkOpaqueCompositeLit(pass, node)
		case *ast.CallExpr:
			checkOpaqueNewCall(pass, node)
			checkOpaqueTypeConversion(pass, node)
		}
	})
}

func checkOpaqueCompositeLit(pass *analysis.Pass, lit *ast.CompositeLit) {
	tv, ok := pass.TypesInfo.Types[lit]
	if !ok || tv.Type == nil {
		return
	}
	named, ok := vetutil.UnwrapNamedType(tv.Type)
	if !ok {
		return
	}
	if orig := externalOpaqueOrigin(pass, named); orig != nil {
		pass.ReportRangef(lit, "failclosed: 禁止在包外通过字面量构造 //xops:opaque 类型 %s，请调用导出构造器", orig.Name())
	}
}

func checkOpaqueNewCall(pass *analysis.Pass, call *ast.CallExpr) {
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok || id.Name != "new" || len(call.Args) != 1 {
		return
	}
	b, ok := pass.TypesInfo.Uses[id].(*types.Builtin)
	if !ok || b.Name() != "new" {
		return
	}
	tv, ok := pass.TypesInfo.Types[call.Args[0]]
	// 仅拦截 new(pkg.T) 类型实参形式；Go 1.26+ new(expr) 若来自合法构造器返回值则放行。
	if !ok || !tv.IsType() || tv.Type == nil {
		return
	}
	named, ok := types.Unalias(tv.Type).(*types.Named)
	if !ok {
		return
	}
	if orig := externalOpaqueOrigin(pass, named); orig != nil {
		pass.ReportRangef(call, "failclosed: 禁止在包外通过 new(%s) 构造 //xops:opaque 类型，请调用导出构造器", orig.Name())
	}
}

func checkOpaqueTypeConversion(pass *analysis.Pass, call *ast.CallExpr) {
	if len(call.Args) != 1 {
		return
	}
	tv, ok := pass.TypesInfo.Types[call.Fun]
	if !ok || !tv.IsType() || tv.Type == nil {
		return
	}
	targetType := types.Unalias(tv.Type)
	named, ok := targetType.(*types.Named)
	if !ok {
		return
	}
	orig := externalOpaqueOrigin(pass, named)
	if orig == nil {
		return
	}
	if isSameNamedTypeArg(pass.TypesInfo, call.Args[0], targetType) {
		return
	}
	pass.ReportRangef(call, "failclosed: 禁止在包外通过类型转换构造 //xops:opaque 类型 %s，请调用导出构造器", orig.Name())
}

func isSameNamedTypeArg(info *types.Info, expr ast.Expr, targetType types.Type) bool {
	switch e := ast.Unparen(expr).(type) {
	case *ast.BasicLit:
		return false
	case *ast.Ident:
		if obj := info.Uses[e]; obj != nil {
			return types.Identical(types.Unalias(obj.Type()), targetType)
		}
		return false
	case *ast.SelectorExpr:
		if sel := info.Selections[e]; sel != nil {
			return types.Identical(types.Unalias(sel.Type()), targetType)
		}
		if obj := info.Uses[e.Sel]; obj != nil {
			return types.Identical(types.Unalias(obj.Type()), targetType)
		}
		return false
	default:
		tv, ok := info.Types[e]
		if !ok || tv.Value != nil || tv.Type == nil {
			return false
		}
		return types.Identical(types.Unalias(tv.Type), targetType)
	}
}

func externalOpaqueOrigin(pass *analysis.Pass, named *types.Named) *types.TypeName {
	if named == nil || named.Origin() == nil {
		return nil
	}
	orig := named.Origin().Obj()
	if orig == nil || orig.Pkg() == nil || orig.Pkg() == pass.Pkg {
		return nil
	}
	if !pass.ImportObjectFact(orig, new(opaqueTypeFact)) {
		return nil
	}
	return orig
}
