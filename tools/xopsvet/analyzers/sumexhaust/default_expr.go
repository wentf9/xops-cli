package sumexhaust

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

// isPermissiveExpr 判断安全决策 default 分支中的表达式是否代表放行（fail-open）值。
func isPermissiveExpr(info *types.Info, expr ast.Expr, st defaultScanState) bool {
	return isPermissiveExprSeen(info, expr, st, make(map[*ast.FuncLit]bool))
}

func isPermissiveExprSeen(info *types.Info, expr ast.Expr, st defaultScanState, visited map[*ast.FuncLit]bool) bool {
	if isBoolConstExpr(info, expr, true) || isPermissiveVarRef(info, expr, st.permissiveVars) {
		return true
	}
	if lit := resolveCalledFuncLit(info, expr, st.funcLitVars); lit != nil {
		return funcLitHasFailOpenReturn(info, lit, st, visited)
	}
	if lit := unwrapCompositeLit(expr); lit != nil {
		return isCompositeLitPermissive(info, lit, st, visited)
	}
	if newArg, ok := unwrapNewBuiltinArg(info, expr); ok {
		return isPermissiveExprSeen(info, newArg, st, visited)
	}
	if convArg, ok := unwrapSingleTypeConversion(info, expr); ok && isPermissiveExprSeen(info, convArg, st, visited) {
		return true
	}
	if isNonCallErrorValueExpr(info, expr) || isAlwaysFailClosedErrorCall(info, expr) {
		return false
	}
	id := rightmostIdent(expr)
	return id != nil && isPermissiveIdentName(id.Name)
}

func isPermissiveVarRef(info *types.Info, expr ast.Expr, permissiveVars map[*types.Var]bool) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok || info == nil || len(permissiveVars) == 0 {
		return false
	}
	v, ok := info.Uses[id].(*types.Var)
	return ok && permissiveVars[v]
}

// isCompositeLitPermissive 递归检查复合字面量是否携带放行字段或放行类型名；fail-closed 键为 true 不误报。
func isCompositeLitPermissive(info *types.Info, lit *ast.CompositeLit, st defaultScanState, visited map[*ast.FuncLit]bool) bool {
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if keyID, ok := ast.Unparen(kv.Key).(*ast.Ident); ok && isFailClosedIdentName(keyID.Name) && isBoolConstExpr(info, kv.Value, true) {
				continue
			}
			if isPermissiveExprSeen(info, kv.Value, st, visited) {
				return true
			}
		} else if isPermissiveExprSeen(info, elt, st, visited) {
			return true
		}
	}
	id := rightmostIdent(lit.Type)
	return lit.Type != nil && id != nil && isPermissiveIdentName(id.Name)
}

// isFailClosedValueExpr 判断非 error 槽位的返回值表达式是否表达显式拒绝（fail-closed）语义，首行即拦截所有 nil。
func isFailClosedValueExpr(info *types.Info, expr ast.Expr) bool {
	if isNilIdent(info, expr) {
		return false
	}
	if isBoolConstExpr(info, expr, false) || isFailClosedErrorCall(info, expr) {
		return true
	}
	if newArg, ok := unwrapNewBuiltinArg(info, expr); ok {
		return isFailClosedValueExpr(info, newArg)
	}
	if lit := unwrapCompositeLit(expr); lit != nil {
		return isCompositeLitFailClosed(info, lit)
	}
	if convArg, ok := unwrapSingleTypeConversion(info, expr); ok && isFailClosedValueExpr(info, convArg) {
		return true
	}
	id := rightmostIdent(expr)
	return id != nil && isFailClosedIdentName(id.Name)
}

// isCompositeLitFailClosed 对称检查复合字面量（含 &T{...}）是否显式表达拒绝语义。
func isCompositeLitFailClosed(info *types.Info, lit *ast.CompositeLit) bool {
	if id := rightmostIdent(lit.Type); lit.Type != nil && id != nil && isFailClosedIdentName(id.Name) {
		return true
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if isKeyValueFailClosed(info, kv) {
				return true
			}
		} else if isFailClosedValueExpr(info, elt) {
			return true
		}
	}
	return false
}

func isKeyValueFailClosed(info *types.Info, kv *ast.KeyValueExpr) bool {
	keyID, _ := ast.Unparen(kv.Key).(*ast.Ident)
	if isBoolConstExpr(info, kv.Value, true) {
		return keyID != nil && isFailClosedIdentName(keyID.Name)
	}
	if isBoolConstExpr(info, kv.Value, false) {
		return keyID != nil && isPermissiveIdentName(keyID.Name)
	}
	return isFailClosedValueExpr(info, kv.Value)
}

func isNonCallErrorValueExpr(info *types.Info, expr ast.Expr) bool {
	if info == nil || expr == nil || isNilIdent(info, expr) {
		return false
	}
	unwrapped := ast.Unparen(expr)
	if _, isCall := unwrapped.(*ast.CallExpr); isCall {
		return false
	}
	tv, ok := info.Types[unwrapped]
	return ok && tv.IsValue() && vetutil.ImplementsError(tv.Type)
}

func isAlwaysFailClosedErrorCall(info *types.Info, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || info == nil {
		return false
	}
	obj := vetutil.ResolveCalledObject(info, call)
	return vetutil.IsPkgSymbol(obj, "errors", "New", "Join") || vetutil.IsPkgSymbol(obj, "fmt", "Errorf")
}

func isFailClosedErrorCall(info *types.Info, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || info == nil || isTypeExpr(info, call.Fun) {
		return false
	}
	tv, ok := info.Types[call]
	if !ok || !vetutil.IsErrorInterfaceType(tv.Type) {
		return false
	}
	id := rightmostIdent(call)
	return isAlwaysFailClosedErrorCall(info, call) || id == nil || !isPermissiveIdentName(id.Name)
}

func unwrapCompositeLit(expr ast.Expr) *ast.CompositeLit {
	cur := ast.Unparen(expr)
	if u, ok := cur.(*ast.UnaryExpr); ok && u.Op == token.AND {
		cur = ast.Unparen(u.X)
	}
	lit, _ := cur.(*ast.CompositeLit)
	return lit
}

// unwrapNewBuiltinArg 识别内置 new(T) 或 Go 1.27 new(expr) 单参调用并提取其唯一实参。
func unwrapNewBuiltinArg(info *types.Info, expr ast.Expr) (ast.Expr, bool) {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || info == nil || len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return nil, false
	}
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return nil, false
	}
	b, isBuiltin := info.Uses[id].(*types.Builtin)
	return call.Args[0], isBuiltin && b != nil && b.Name() == "new"
}
