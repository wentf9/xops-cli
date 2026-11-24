package noimplicit

import (
	"go/ast"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

func checkContextAndAnonIfaces(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	allowCtx := vetutil.AllowContextValue(pkgInfo)
	ctxIface := findContextInterface(pass)
	ins := vetutil.InspectorOf(pass)
	nodeFilter := []ast.Node{
		(*ast.Ident)(nil),
		(*ast.SelectorExpr)(nil),
		(*ast.TypeAssertExpr)(nil),
		(*ast.TypeSwitchStmt)(nil),
	}
	ins.Preorder(nodeFilter, func(n ast.Node) {
		checkContextOrIfaceNode(pass, n, allowCtx, ctxIface)
	})
}

func checkContextOrIfaceNode(pass *analysis.Pass, n ast.Node, allowCtx bool, ctxIface *types.Interface) {
	switch node := n.(type) {
	case *ast.Ident:
		if !allowCtx {
			checkContextIdentUse(pass, node)
		}
	case *ast.SelectorExpr:
		if !allowCtx {
			checkContextSelection(pass, node, ctxIface)
		}
	case *ast.TypeAssertExpr:
		if node.Type != nil && containsAnonIface(node.Type) {
			pass.ReportRangef(node.Type, "noimplicit: 禁止匿名接口断言 x.(interface{...})，请使用具名接口")
		}
	case *ast.TypeSwitchStmt:
		checkTypeSwitchCases(pass, node)
	}
}

func checkContextIdentUse(pass *analysis.Pass, id *ast.Ident) {
	if pass.TypesInfo == nil {
		return
	}
	obj := pass.TypesInfo.Uses[id]
	if vetutil.IsPkgSymbol(obj, "context", "WithValue") {
		pass.ReportRangef(id, "noimplicit: 白名单包 core/internal/foundation/trace 之外禁止使用 context.WithValue")
	}
}

func checkContextSelection(pass *analysis.Pass, sel *ast.SelectorExpr, ctxIface *types.Interface) {
	if pass.TypesInfo == nil || sel.Sel == nil || sel.Sel.Name != "Value" {
		return
	}
	if s, ok := pass.TypesInfo.Selections[sel]; ok && s != nil {
		if vetutil.IsPkgSymbol(s.Obj(), "context", "Value") || implementsContextIface(s.Recv(), ctxIface) {
			pass.ReportRangef(sel.Sel, "noimplicit: 白名单包 core/internal/foundation/trace 之外禁止调用 ctx.Value")
		}
		return
	}
	if obj := pass.TypesInfo.Uses[sel.Sel]; vetutil.IsPkgSymbol(obj, "context", "Value") {
		pass.ReportRangef(sel.Sel, "noimplicit: 白名单包 core/internal/foundation/trace 之外禁止引用 context.Context.Value")
	}
}

func implementsContextIface(t types.Type, ctxIface *types.Interface) bool {
	if t == nil || ctxIface == nil {
		return false
	}
	return types.Implements(t, ctxIface) || types.Implements(types.NewPointer(t), ctxIface)
}

func findContextInterface(pass *analysis.Pass) *types.Interface {
	if pass.Pkg == nil {
		return nil
	}
	for _, imp := range pass.Pkg.Imports() {
		if imp.Path() != "context" {
			continue
		}
		obj := imp.Scope().Lookup("Context")
		if obj == nil {
			return nil
		}
		iface, _ := obj.Type().Underlying().(*types.Interface)
		return iface
	}
	return nil
}

func checkTypeSwitchCases(pass *analysis.Pass, ts *ast.TypeSwitchStmt) {
	if ts.Body == nil {
		return
	}
	for _, stmt := range ts.Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, expr := range cc.List {
			if containsAnonIface(expr) {
				pass.ReportRangef(expr, "noimplicit: 禁止在 type switch 中使用匿名接口 case interface{...}")
			}
		}
	}
}

func containsAnonIface(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.InterfaceType:
		return true
	case *ast.ParenExpr:
		return containsAnonIface(e.X)
	case *ast.StarExpr:
		return containsAnonIface(e.X)
	case *ast.ArrayType:
		return containsAnonIface(e.Elt)
	case *ast.Ellipsis:
		return containsAnonIface(e.Elt)
	case *ast.ChanType:
		return containsAnonIface(e.Value)
	case *ast.MapType:
		return containsAnonIface(e.Key) || containsAnonIface(e.Value)
	default:
		return false
	}
}
