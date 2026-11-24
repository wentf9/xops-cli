package osboundary

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

func checkRemotePathFilepath(pass *analysis.Pass) {
	if pass.TypesInfo == nil {
		return
	}
	ins := vetutil.InspectorOf(pass)
	nodeFilter := []ast.Node{
		(*ast.FuncDecl)(nil),
		(*ast.FuncLit)(nil),
	}
	ins.Preorder(nodeFilter, func(n ast.Node) {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body != nil {
				checkFuncRemotePath(pass, fn.Type, fn.Body)
			}
		case *ast.FuncLit:
			if fn.Body != nil {
				checkFuncRemotePath(pass, fn.Type, fn.Body)
			}
		}
	})
}

func checkFuncRemotePath(pass *analysis.Pass, ftype *ast.FuncType, body *ast.BlockStmt) {
	remoteVars := collectRemoteDerivedVars(pass.TypesInfo, ftype, body)
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isFilepathCall(pass.TypesInfo, call) && callArgsHaveRemotePath(pass.TypesInfo, call, remoteVars) {
			pass.ReportRangef(call, "osboundary: 禁止对 RemotePath 调用 path/filepath.*，远端 POSIX 路径请使用 path.* 或 RemotePath 方法")
		}
		return true
	})
}

func collectRemoteDerivedVars(info *types.Info, ftype *ast.FuncType, body *ast.BlockStmt) map[types.Object]bool {
	remoteVars := make(map[types.Object]bool)
	seedFieldListRemoteVars(info, ftype, remoteVars)
	for range 4 {
		changed := false
		ast.Inspect(body, func(n ast.Node) bool {
			if scanStmtRemoteVars(info, n, remoteVars) {
				changed = true
			}
			return true
		})
		if !changed {
			break
		}
	}
	return remoteVars
}

func seedFieldListRemoteVars(info *types.Info, ftype *ast.FuncType, remoteVars map[types.Object]bool) {
	if ftype == nil {
		return
	}
	seedGroup := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, field := range fl.List {
			if !isRemotePathType(info.TypeOf(field.Type)) {
				continue
			}
			for _, name := range field.Names {
				if obj := info.Defs[name]; obj != nil {
					remoteVars[obj] = true
				}
			}
		}
	}
	seedGroup(ftype.Params)
	seedGroup(ftype.Results)
}

func scanStmtRemoteVars(info *types.Info, n ast.Node, remoteVars map[types.Object]bool) bool {
	switch stmt := n.(type) {
	case *ast.AssignStmt:
		return scanAssignRemoteVars(info, stmt.Lhs, stmt.Rhs, remoteVars)
	case *ast.ValueSpec:
		return scanValueSpecRemoteVars(info, stmt, remoteVars)
	default:
		return false
	}
}

func scanAssignRemoteVars(info *types.Info, lhs, rhs []ast.Expr, remoteVars map[types.Object]bool) bool {
	if len(lhs) != len(rhs) {
		return false
	}
	changed := false
	for i := range lhs {
		if !exprHasRemotePath(info, rhs[i], remoteVars) {
			continue
		}
		id, ok := ast.Unparen(lhs[i]).(*ast.Ident)
		if !ok {
			continue
		}
		obj := info.Defs[id]
		if obj == nil {
			obj = info.Uses[id]
		}
		if obj != nil && !remoteVars[obj] {
			remoteVars[obj] = true
			changed = true
		}
	}
	return changed
}

func scanValueSpecRemoteVars(info *types.Info, vs *ast.ValueSpec, remoteVars map[types.Object]bool) bool {
	if len(vs.Names) != len(vs.Values) {
		return false
	}
	changed := false
	for i, name := range vs.Names {
		if !exprHasRemotePath(info, vs.Values[i], remoteVars) {
			continue
		}
		if obj := info.Defs[name]; obj != nil && !remoteVars[obj] {
			remoteVars[obj] = true
			changed = true
		}
	}
	return changed
}

func isRemotePathType(t types.Type) bool {
	return vetutil.TypeContains(t, func(n *types.Named) bool {
		return n.Obj() != nil && n.Obj().Name() == "RemotePath"
	})
}

func isFilepathCall(info *types.Info, call *ast.CallExpr) bool {
	obj := vetutil.ResolveCalledObject(info, call)
	return vetutil.ObjectPkgPath(obj) == "path/filepath"
}

func callArgsHaveRemotePath(info *types.Info, call *ast.CallExpr, remoteVars map[types.Object]bool) bool {
	for _, arg := range call.Args {
		if exprHasRemotePath(info, arg, remoteVars) {
			return true
		}
	}
	return false
}

func exprHasRemotePath(info *types.Info, expr ast.Expr, remoteVars map[types.Object]bool) bool {
	if expr == nil {
		return false
	}
	if isRemotePathType(info.TypeOf(expr)) {
		return true
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return remoteVars[info.Uses[e]]
	case *ast.BinaryExpr:
		return e.Op == token.ADD && (exprHasRemotePath(info, e.X, remoteVars) || exprHasRemotePath(info, e.Y, remoteVars))
	case *ast.SliceExpr:
		return exprHasRemotePath(info, e.X, remoteVars)
	case *ast.IndexExpr:
		return exprHasRemotePath(info, e.X, remoteVars)
	case *ast.SelectorExpr:
		return exprHasRemotePath(info, e.X, remoteVars)
	case *ast.CallExpr:
		return callExprHasRemotePath(info, e, remoteVars)
	case *ast.CompositeLit:
		return compositeHasRemotePath(info, e, remoteVars)
	default:
		return false
	}
}

func callExprHasRemotePath(info *types.Info, call *ast.CallExpr, remoteVars map[types.Object]bool) bool {
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		if exprHasRemotePath(info, sel.X, remoteVars) {
			return true
		}
	}
	return callArgsHaveRemotePath(info, call, remoteVars)
}

func compositeHasRemotePath(info *types.Info, lit *ast.CompositeLit, remoteVars map[types.Object]bool) bool {
	for _, elt := range lit.Elts {
		if exprHasRemotePath(info, elt, remoteVars) {
			return true
		}
	}
	return false
}
