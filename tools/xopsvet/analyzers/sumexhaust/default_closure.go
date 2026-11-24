package sumexhaust

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
)

// resolveCalledFuncLit 解析 default 分支中直接调用的匿名闭包或已追踪的局部闭包变量。
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
	return inspectFuncLitBody(info, lit, st, visited, false)
}

func inspectFuncLitBody(
	info *types.Info,
	lit *ast.FuncLit,
	st defaultScanState,
	visited map[*ast.FuncLit]bool,
	sharePermissive bool,
) bool {
	if info == nil || lit == nil || lit.Body == nil || visited[lit] {
		return false
	}
	visited[lit] = true
	defer delete(visited, lit)
	litSig, _ := info.TypeOf(lit).(*types.Signature)
	subState := buildFuncLitSubState(litSig, st, visited, sharePermissive)
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

func buildFuncLitSubState(
	litSig *types.Signature,
	st defaultScanState,
	visited map[*ast.FuncLit]bool,
	sharePermissive bool,
) defaultScanState {
	permVars := st.permissiveVars
	if !sharePermissive {
		permVars = maps.Clone(st.permissiveVars)
	}
	if permVars == nil {
		permVars = make(map[*types.Var]bool)
	}
	fnVars := maps.Clone(st.funcLitVars)
	if fnVars == nil {
		fnVars = make(map[*types.Var]*ast.FuncLit)
	}
	return defaultScanState{
		pass:           st.pass,
		sig:            litSig,
		inTest:         st.inTest,
		permissiveVars: permVars,
		funcLitVars:    fnVars,
		visitedLits:    visited,
	}
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
	case *ast.ExprStmt:
		return inspectNestedFuncLitStmt(info, node.X, nil, st, visited)
	case *ast.DeferStmt:
		return inspectNestedFuncLitStmt(info, node.Call, litSig, st, visited)
	case *ast.GoStmt:
		return inspectNestedFuncLitStmt(info, node.Call, litSig, st, visited)
	case *ast.ReturnStmt:
		return funcLitReturnIsFailOpen(info, litSig, node, st, visited)
	}
	return false
}

// inspectNestedFuncLitStmt 追踪闭包体内部嵌套调用的匿名/局部函数变量（ExprStmt/DeferStmt/GoStmt），
// 共享外层 permissiveVars 以捕获对命名返回值的放行覆写。
func inspectNestedFuncLitStmt(
	info *types.Info,
	callExpr ast.Expr,
	deferGoOuterSig *types.Signature,
	st defaultScanState,
	visited map[*ast.FuncLit]bool,
) bool {
	lit := resolveCalledFuncLit(info, callExpr, st.funcLitVars)
	if lit == nil {
		return false
	}
	if inspectFuncLitBody(info, lit, st, visited, true) {
		return true
	}
	if deferGoOuterSig != nil {
		return hasPermissiveNamedResult(deferGoOuterSig, st.permissiveVars)
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
		// 闭包采用命名返回值并裸 return 时，检查是否有任意命名返回值已被赋值为放行值。
		return hasPermissiveNamedResult(litSig, st.permissiveVars)
	}
	for _, expr := range ret.Results {
		if isPermissiveExprSeen(info, expr, st, visited) {
			return true
		}
	}
	return returnsBareNilError(info, litSig, ret.Results)
}

func hasPermissiveNamedResult(sig *types.Signature, permissiveVars map[*types.Var]bool) bool {
	if sig == nil || sig.Results() == nil || len(permissiveVars) == 0 {
		return false
	}
	results := sig.Results()
	for i := 0; i < results.Len(); i++ {
		rv := results.At(i)
		if rv != nil && rv.Name() != "" && permissiveVars[rv] {
			return true
		}
	}
	return false
}

// inspectCalledFuncLitStmt 检查 defer/go 或独立表达式调用的闭包体内是否存在放行赋值或放行返回。
func inspectCalledFuncLitStmt(expr ast.Expr, st defaultScanState) bool {
	if st.pass == nil || st.pass.TypesInfo == nil {
		return false
	}
	lit := resolveCalledFuncLit(st.pass.TypesInfo, expr, st.funcLitVars)
	if lit == nil || lit.Body == nil || st.visitedLits[lit] {
		return false
	}
	if st.visitedLits != nil {
		st.visitedLits[lit] = true
	}
	litSig, _ := st.pass.TypesInfo.TypeOf(lit).(*types.Signature)
	subState := defaultScanState{
		pass:           st.pass,
		sig:            litSig,
		inTest:         st.inTest,
		permissiveVars: maps.Clone(st.permissiveVars),
		funcLitVars:    maps.Clone(st.funcLitVars),
		visitedLits:    st.visitedLits,
	}
	if subState.permissiveVars == nil {
		subState.permissiveVars = make(map[*types.Var]bool)
	}
	if subState.funcLitVars == nil {
		subState.funcLitVars = make(map[*types.Var]*ast.FuncLit)
	}
	return inspectDefaultBlock(nonEmptyStmts(lit.Body.List), subState).reportedFailOpen
}
