package sumexhaust

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"maps"
	"strings"
	"unicode"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

// isPermissiveExpr 判断安全决策 default 分支中的表达式是否代表放行（fail-open）值，
// 覆盖布尔常量、已追踪的放行局部变量、放行语义命名调用，以及内联或局部闭包返回的放行路径。
func isPermissiveExpr(info *types.Info, expr ast.Expr, st defaultScanState) bool {
	return isPermissiveExprSeen(info, expr, st, make(map[*ast.FuncLit]bool))
}

func isPermissiveExprSeen(
	info *types.Info,
	expr ast.Expr,
	st defaultScanState,
	visited map[*ast.FuncLit]bool,
) bool {
	if isBoolConstExpr(info, expr, true) {
		return true
	}
	if isPermissiveVarRef(info, expr, st.permissiveVars) {
		return true
	}
	if lit := resolveCalledFuncLit(info, expr, st.funcLitVars); lit != nil {
		return funcLitHasFailOpenReturn(info, lit, st, visited)
	}
	id := rightmostIdent(expr)
	if id == nil {
		return false
	}
	return hasAnyToken(id.Name, isPermissiveToken)
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

func resolveCalledFuncLit(info *types.Info, expr ast.Expr, funcLitVars map[*types.Var]*ast.FuncLit) *ast.FuncLit {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return nil
	}
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.FuncLit:
		return fn
	case *ast.Ident:
		if info == nil || len(funcLitVars) == 0 {
			return nil
		}
		v, ok := info.Uses[fn].(*types.Var)
		if !ok {
			return nil
		}
		return funcLitVars[v]
	default:
		return nil
	}
}

// funcLitHasFailOpenReturn 静态检查闭包体内是否存在返回放行值或返回 nil error 且无拒绝值的路径。
func funcLitHasFailOpenReturn(
	info *types.Info,
	lit *ast.FuncLit,
	st defaultScanState,
	visited map[*ast.FuncLit]bool,
) bool {
	if info == nil || lit == nil || lit.Body == nil || visited[lit] {
		return false
	}
	visited[lit] = true
	litSig, _ := info.TypeOf(lit).(*types.Signature)
	subState := defaultScanState{
		pass:           st.pass,
		sig:            litSig,
		inTest:         st.inTest,
		permissiveVars: maps.Clone(st.permissiveVars),
		funcLitVars:    maps.Clone(st.funcLitVars),
	}
	if subState.permissiveVars == nil {
		subState.permissiveVars = make(map[*types.Var]bool)
	}
	if subState.funcLitVars == nil {
		subState.funcLitVars = make(map[*types.Var]*ast.FuncLit)
	}
	failOpen := false
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if n == nil || failOpen {
			return false
		}
		if innerLit, ok := n.(*ast.FuncLit); ok && innerLit != lit {
			return false
		}
		failOpen = inspectFuncLitNode(info, n, litSig, subState, visited)
		return !failOpen
	})
	return failOpen
}

func inspectFuncLitNode(
	info *types.Info,
	n ast.Node,
	litSig *types.Signature,
	st defaultScanState,
	visited map[*ast.FuncLit]bool,
) bool {
	switch node := n.(type) {
	case *ast.AssignStmt:
		trackPairBindingsSilent(info, node.Lhs, node.Rhs, node.Tok == token.DEFINE, st, visited)
	case *ast.ValueSpec:
		trackPairBindingsSilent(info, identSliceToExprs(node.Names), node.Values, true, st, visited)
	case *ast.ReturnStmt:
		return funcLitReturnIsFailOpen(info, litSig, node, st, visited)
	}
	return false
}

func trackPairBindingsSilent(
	info *types.Info,
	lhs []ast.Expr,
	rhs []ast.Expr,
	isDef bool,
	st defaultScanState,
	visited map[*ast.FuncLit]bool,
) {
	for i, expr := range rhs {
		lhsVar := resolveLHSVar(info, lhs, i, isDef)
		if lhsVar == nil {
			continue
		}
		if lit, ok := ast.Unparen(expr).(*ast.FuncLit); ok {
			st.funcLitVars[lhsVar] = lit
			delete(st.permissiveVars, lhsVar)
			continue
		}
		delete(st.funcLitVars, lhsVar)
		if isPermissiveExprSeen(info, expr, st, visited) {
			st.permissiveVars[lhsVar] = true
		} else {
			delete(st.permissiveVars, lhsVar)
		}
	}
}

func funcLitReturnIsFailOpen(
	info *types.Info,
	litSig *types.Signature,
	ret *ast.ReturnStmt,
	st defaultScanState,
	visited map[*ast.FuncLit]bool,
) bool {
	if len(ret.Results) == 0 {
		return false
	}
	for _, expr := range ret.Results {
		if isPermissiveExprSeen(info, expr, st, visited) {
			return true
		}
	}
	return returnsBareNilError(info, litSig, ret.Results)
}

func isFailClosedValueExpr(info *types.Info, expr ast.Expr) bool {
	if isBoolConstExpr(info, expr, false) {
		return true
	}
	if call, ok := ast.Unparen(expr).(*ast.CallExpr); ok {
		if tv, ok := info.Types[call]; ok && vetutil.IsErrorInterfaceType(tv.Type) {
			return true
		}
	}
	id := rightmostIdent(expr)
	return id != nil && hasAnyToken(id.Name, isFailClosedToken)
}

func rightmostIdent(expr ast.Expr) *ast.Ident {
	cur := unwrapExprChain(expr)
	switch e := cur.(type) {
	case *ast.Ident:
		return e
	case *ast.SelectorExpr:
		return e.Sel
	default:
		return nil
	}
}

func unwrapExprChain(expr ast.Expr) ast.Expr {
	cur := ast.Unparen(expr)
	for cur != nil {
		switch e := cur.(type) {
		case *ast.UnaryExpr:
			if e.Op != token.AND {
				return cur
			}
			cur = ast.Unparen(e.X)
		case *ast.CompositeLit:
			if e.Type == nil {
				return cur
			}
			cur = ast.Unparen(e.Type)
		case *ast.CallExpr:
			cur = ast.Unparen(e.Fun)
		case *ast.IndexExpr:
			cur = ast.Unparen(e.X)
		case *ast.IndexListExpr:
			cur = ast.Unparen(e.X)
		default:
			return cur
		}
	}
	return nil
}

func isBoolConstExpr(info *types.Info, expr ast.Expr, want bool) bool {
	if info == nil || expr == nil {
		return false
	}
	if tv, ok := info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.Bool {
		return constant.BoolVal(tv.Value) == want
	}
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	c, ok := info.Uses[id].(*types.Const)
	if !ok || c.Val() == nil || c.Val().Kind() != constant.Bool {
		return false
	}
	return constant.BoolVal(c.Val()) == want
}

func isNilIdent(info *types.Info, expr ast.Expr) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	_, isNil := info.Uses[id].(*types.Nil)
	return isNil || id.Name == "nil"
}

func hasAnyToken(name string, pred func(string) bool) bool {
	for _, tok := range splitCamelTokens(name) {
		if pred(tok) {
			return true
		}
	}
	return false
}

func isPermissiveToken(tok string) bool {
	switch tok {
	case "allow", "allowed", "permit", "permitted", "grant", "granted", "approve", "approved":
		return true
	default:
		return false
	}
}

func isFailClosedToken(tok string) bool {
	switch tok {
	case "deny", "denied", "reject", "rejected", "invalid", "unknown", "fail", "failed", "err", "error", "forbid", "forbidden", "closed", "disabled":
		return true
	default:
		return false
	}
}

func splitCamelTokens(name string) []string {
	var tokens []string
	for _, part := range strings.Split(name, "_") {
		if part == "" {
			continue
		}
		tokens = append(tokens, splitCamelWord(part)...)
	}
	return tokens
}

func splitCamelWord(word string) []string {
	runes := []rune(word)
	var out []string
	start := 0
	for i := 1; i < len(runes); i++ {
		if isWordBoundary(runes, i) {
			out = append(out, strings.ToLower(string(runes[start:i])))
			start = i
		}
	}
	if start < len(runes) {
		out = append(out, strings.ToLower(string(runes[start:])))
	}
	return out
}

func isWordBoundary(runes []rune, i int) bool {
	prev, cur := runes[i-1], runes[i]
	if unicode.IsLower(prev) && unicode.IsUpper(cur) {
		return true
	}
	return i+1 < len(runes) && unicode.IsUpper(prev) && unicode.IsUpper(cur) && unicode.IsLower(runes[i+1])
}
