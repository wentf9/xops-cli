package sumexhaust

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

// isPermissiveExpr 判断安全决策 default 分支中的表达式是否代表放行（fail-open）值，
// 覆盖布尔常量、已追踪放行变量、内联/局部闭包、复合字面量、new(T)/new(expr) 及前置否定极性命名校验。
func isPermissiveExpr(info *types.Info, expr ast.Expr, st defaultScanState) bool {
	return isPermissiveExprSeen(info, expr, st, make(map[*ast.FuncLit]bool))
}

func isPermissiveExprSeen(
	info *types.Info,
	expr ast.Expr,
	st defaultScanState,
	visited map[*ast.FuncLit]bool,
) bool {
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
	if info == nil || len(permissiveVars) == 0 {
		return false
	}
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	v, ok := info.Uses[id].(*types.Var)
	return ok && permissiveVars[v]
}

// isCompositeLitPermissive 递归检查结构体/容器复合字面量是否携带放行字段或放行类型名。
// 若键名本身为 fail-closed 语义（如 Denied: true / NotAllowed: true），放行其布尔 true 值以免误报。
func isCompositeLitPermissive(
	info *types.Info,
	lit *ast.CompositeLit,
	st defaultScanState,
	visited map[*ast.FuncLit]bool,
) bool {
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if isKeyValuePermissive(info, kv, st, visited) {
				return true
			}
			continue
		}
		if isPermissiveExprSeen(info, elt, st, visited) {
			return true
		}
	}
	if lit.Type != nil {
		if id := rightmostIdent(lit.Type); id != nil && isPermissiveIdentName(id.Name) {
			return true
		}
	}
	return false
}

func isKeyValuePermissive(
	info *types.Info,
	kv *ast.KeyValueExpr,
	st defaultScanState,
	visited map[*ast.FuncLit]bool,
) bool {
	if keyID, ok := ast.Unparen(kv.Key).(*ast.Ident); ok {
		if isFailClosedIdentName(keyID.Name) && isBoolConstExpr(info, kv.Value, true) {
			return false
		}
	}
	return isPermissiveExprSeen(info, kv.Value, st, visited)
}

// isFailClosedValueExpr 判断非 error 槽位的返回值表达式是否表达显式拒绝（fail-closed）语义。
// 入口首行即拦截所有 nil（含 error(nil) 与 (*T)(nil) 类型强转），避免穿透落入右侧标识符匹配。
func isFailClosedValueExpr(info *types.Info, expr ast.Expr) bool {
	if isNilIdent(info, expr) {
		return false
	}
	if isBoolConstExpr(info, expr, false) {
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
	if isFailClosedErrorCall(info, expr) {
		return true
	}
	id := rightmostIdent(expr)
	return id != nil && isFailClosedIdentName(id.Name)
}

// isCompositeLitFailClosed 对称检查复合字面量（含 &T{...}）是否显式表达拒绝语义：
// 识别拒绝类型名、否定键 true（如 Denied: true / NotAllowed: true）、放行键 false（如 Allowed: false）
// 以及递归子字段中的拒绝值（如 Verdict: VerdictDeny）。
func isCompositeLitFailClosed(info *types.Info, lit *ast.CompositeLit) bool {
	if lit.Type != nil {
		if id := rightmostIdent(lit.Type); id != nil && isFailClosedIdentName(id.Name) {
			return true
		}
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if isKeyValueFailClosed(info, kv) {
				return true
			}
			continue
		}
		if isFailClosedValueExpr(info, elt) {
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

// isNonCallErrorValueExpr 判断表达式是否为非调用、非 nil 的 error 实现值（如 ErrNotAllowed 哨兵）。
// 必须满足 tv.IsValue() 以排除 new(T) 中的类型实参。
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

// isAlwaysFailClosedErrorCall 仅对标准错误构造原语（errors.New/errors.Join/fmt.Errorf）直接放行，
// 其余返回 error 的调用仍须通过极性命名校验，阻断 allowRequest(ctx)/allowOnError() 绕过。
func isAlwaysFailClosedErrorCall(info *types.Info, expr ast.Expr) bool {
	if info == nil || expr == nil {
		return false
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	obj := vetutil.ResolveCalledObject(info, call)
	return vetutil.IsPkgSymbol(obj, "errors", "New", "Join") || vetutil.IsPkgSymbol(obj, "fmt", "Errorf")
}

func isFailClosedErrorCall(info *types.Info, expr ast.Expr) bool {
	if info == nil || expr == nil {
		return false
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || isTypeExpr(info, call.Fun) {
		return false
	}
	tv, ok := info.Types[call]
	if !ok || !vetutil.IsErrorInterfaceType(tv.Type) {
		return false
	}
	if isAlwaysFailClosedErrorCall(info, call) {
		return true
	}
	id := rightmostIdent(call)
	return id == nil || !isPermissiveIdentName(id.Name)
}

// unwrapCompositeLit 剥离外层括号与单层取址运算符 &，提取复合字面量节点。
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
	if info == nil || expr == nil {
		return nil, false
	}
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return nil, false
	}
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return nil, false
	}
	b, isBuiltin := info.Uses[id].(*types.Builtin)
	if !isBuiltin || b == nil || b.Name() != "new" {
		return nil, false
	}
	return call.Args[0], true
}
