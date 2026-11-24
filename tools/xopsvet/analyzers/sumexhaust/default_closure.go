package sumexhaust

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
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
		if info != nil && len(funcLitVars) > 0 {
			if v, ok := info.Uses[fn].(*types.Var); ok {
				return funcLitVars[v]
			}
		}
	}
	return nil
}

// funcLitHasFailOpenReturn 静态检查闭包体内是否存在返回放行值或返回 nil error 且无拒绝值的路径。
func funcLitHasFailOpenReturn(info *types.Info, lit *ast.FuncLit, st defaultScanState, visited map[*ast.FuncLit]bool) bool {
	return inspectFuncLitBody(info, lit, st, visited, false)
}

func inspectFuncLitBody(info *types.Info, lit *ast.FuncLit, st defaultScanState, visited map[*ast.FuncLit]bool, sharePerm bool) bool {
	if info == nil || lit == nil || lit.Body == nil || visited[lit] {
		return false
	}
	visited[lit] = true
	defer delete(visited, lit)
	litSig, _ := info.TypeOf(lit).(*types.Signature)
	sub := cloneDefaultScanState(litSig, st, visited, sharePerm)
	failOpen := false
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if n == nil || failOpen {
			return false
		}
		if inner, ok := n.(*ast.FuncLit); ok && inner != lit {
			return false
		}
		failOpen = inspectFuncLitNode(info, n, litSig, sub, visited)
		return !failOpen
	})
	return failOpen
}

func inspectFuncLitNode(info *types.Info, n ast.Node, litSig *types.Signature, st defaultScanState, visited map[*ast.FuncLit]bool) bool {
	switch node := n.(type) {
	case *ast.AssignStmt:
		trackPairBindingsSilent(info, node.Lhs, node.Rhs, node.Tok == token.DEFINE, st, visited)
	case *ast.ValueSpec:
		trackPairBindingsSilent(info, vetutil.IdentSliceToExprs(node.Names), node.Values, true, st, visited)
	case *ast.ExprStmt:
		return inspectNestedFuncLitStmt(info, node.X, nil, st, visited)
	case *ast.DeferStmt:
		return inspectNestedFuncLitStmt(info, node.Call, litSig, st, visited)
	case *ast.GoStmt:
		return inspectNestedFuncLitStmt(info, node.Call, litSig, st, visited)
	case *ast.ReturnStmt:
		if len(node.Results) == 0 {
			return hasPermissiveNamedResult(litSig, st.permissiveVars)
		}
		return slices.ContainsFunc(node.Results, func(expr ast.Expr) bool { return isPermissiveExprSeen(info, expr, st, visited) }) ||
			returnsBareNilError(info, litSig, node.Results)
	}
	return false
}

func inspectNestedFuncLitStmt(info *types.Info, callExpr ast.Expr, deferGoOuterSig *types.Signature, st defaultScanState, visited map[*ast.FuncLit]bool) bool {
	lit := resolveCalledFuncLit(info, callExpr, st.funcLitVars)
	if lit == nil {
		return false
	}
	return inspectFuncLitBody(info, lit, st, visited, true) ||
		(deferGoOuterSig != nil && hasPermissiveNamedResult(deferGoOuterSig, st.permissiveVars))
}

func trackPairBindingsSilent(info *types.Info, lhs, rhs []ast.Expr, isDef bool, st defaultScanState, visited map[*ast.FuncLit]bool) {
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

func hasPermissiveNamedResult(sig *types.Signature, permissiveVars map[*types.Var]bool) bool {
	if sig == nil || sig.Results() == nil || len(permissiveVars) == 0 {
		return false
	}
	for i := range sig.Results().Len() {
		if rv := sig.Results().At(i); rv != nil && rv.Name() != "" && permissiveVars[rv] {
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
	return inspectDefaultBlock(nonEmptyStmts(lit.Body.List), cloneDefaultScanState(litSig, st, st.visitedLits, false)).reportedFailOpen
}
