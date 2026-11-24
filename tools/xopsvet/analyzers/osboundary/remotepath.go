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

// collectRemoteDerivedVars 在函数作用域内执行 4 轮不动点数据流传播，
// 追踪由 RemotePath 参数/返回值/字面量派生出的局部变量（如 s1 := rp.String(); s2 := s1 + "/a"），
// 以拦截经过多步变量传递或 range 循环后才传入 path/filepath.* 的调用。
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
	case *ast.RangeStmt:
		return scanRangeRemoteVars(info, stmt, remoteVars)
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
		if exprHasRemotePath(info, rhs[i], remoteVars) && markExprRemoteVar(info, lhs[i], remoteVars) {
			changed = true
		}
	}
	return changed
}

func scanRangeRemoteVars(info *types.Info, stmt *ast.RangeStmt, remoteVars map[types.Object]bool) bool {
	if stmt.Tok != token.ASSIGN && stmt.Tok != token.DEFINE {
		return false
	}
	if !exprHasRemotePath(info, stmt.X, remoteVars) {
		return false
	}
	changed := markExprRemoteVar(info, stmt.Key, remoteVars)
	if markExprRemoteVar(info, stmt.Value, remoteVars) {
		changed = true
	}
	return changed
}

func markExprRemoteVar(info *types.Info, expr ast.Expr, remoteVars map[types.Object]bool) bool {
	if expr == nil {
		return false
	}
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok || id.Name == "_" {
		return false
	}
	obj := info.Defs[id]
	if obj == nil {
		obj = info.Uses[id]
	}
	if obj == nil || remoteVars[obj] {
		return false
	}
	remoteVars[obj] = true
	return true
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

// isRemotePathType 判断类型 t 本身或其容器元素/泛型实参是否为 RemotePath。
// 刻意不递归穿透普通结构体字段，防止含 RemotePath 字段的结构体（如 CopyTask{LocalDir, RemoteDest}）
// 污染同结构体内完全合法的本地路径字段与方法（如 task.LocalDir / task.LocalFile()）。
func isRemotePathType(t types.Type) bool {
	return hasRemotePathType(t, make(map[types.Type]bool))
}

func hasRemotePathType(t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if named, ok := t.(*types.Named); ok {
		return namedIsRemotePath(named, seen)
	}
	switch v := t.(type) {
	case *types.Pointer:
		return hasRemotePathType(v.Elem(), seen)
	case *types.Slice:
		return hasRemotePathType(v.Elem(), seen)
	case *types.Array:
		return hasRemotePathType(v.Elem(), seen)
	case *types.Chan:
		return hasRemotePathType(v.Elem(), seen)
	case *types.Map:
		return hasRemotePathType(v.Key(), seen) || hasRemotePathType(v.Elem(), seen)
	default:
		return false
	}
}

func namedIsRemotePath(named *types.Named, seen map[types.Type]bool) bool {
	if named.Obj() != nil && named.Obj().Name() == "RemotePath" {
		return true
	}
	if seen[named] {
		return false
	}
	seen[named] = true
	if typeArgs := named.TypeArgs(); typeArgs != nil {
		for i := 0; i < typeArgs.Len(); i++ {
			if hasRemotePathType(typeArgs.At(i), seen) {
				return true
			}
		}
	}
	// 仅展开非结构体底层类型（如自定义切片别名），绝不展开结构体字段。
	if _, isStruct := named.Underlying().(*types.Struct); isStruct {
		return false
	}
	return hasRemotePathType(named.Underlying(), seen)
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

// compositeHasRemotePath 仅追踪切片、数组与 Map 字面量（如 []string{rp.String()}）中的远端路径，
// 跳过结构体复合字面量（如 CopyTask{"/local", rp}），防止整值结构体变量被误标为污染。
func compositeHasRemotePath(info *types.Info, lit *ast.CompositeLit, remoteVars map[types.Object]bool) bool {
	if t := info.TypeOf(lit); t != nil {
		if _, isStruct := types.Unalias(t).Underlying().(*types.Struct); isStruct {
			return false
		}
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if exprHasRemotePath(info, kv.Key, remoteVars) || exprHasRemotePath(info, kv.Value, remoteVars) {
				return true
			}
			continue
		}
		if exprHasRemotePath(info, elt, remoteVars) {
			return true
		}
	}
	return false
}
