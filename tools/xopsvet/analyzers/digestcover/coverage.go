package digestcover

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

type visitKey struct {
	fn       *types.Func
	paramIdx int
}

type coverageState struct {
	target    canonicalTarget
	funcDecls map[*types.Func]*ast.FuncDecl
	covered   map[*types.Var]bool
	promoted  map[*types.Var]map[*types.Var]bool
	visited   map[visitKey]bool
}

func checkTargetCoverage(pass *analysis.Pass, target canonicalTarget, writeFn *ast.FuncDecl, funcDecls map[*types.Func]*ast.FuncDecl) {
	if writeFn == nil || writeFn.Body == nil {
		pass.ReportRangef(target.ts.Name, "digestcover: 标记 //xops:canonicalhash 的结构体 %s 缺少 WriteCanonical 方法", target.ts.Name.Name)
		return
	}
	state := &coverageState{
		target: target, funcDecls: funcDecls,
		covered: make(map[*types.Var]bool), promoted: make(map[*types.Var]map[*types.Var]bool), visited: make(map[visitKey]bool),
	}
	if fnObj, ok := pass.TypesInfo.Defs[writeFn.Name].(*types.Func); ok && fnObj != nil {
		state.visited[visitKey{fn: fnObj.Origin(), paramIdx: -1}] = true
	}
	checkNoReflectReachable(pass, writeFn, funcDecls)
	analyzeFuncBody(pass, writeFn.Body, extractRecvVar(pass.TypesInfo, writeFn), state)
	for _, f := range target.fields {
		if !target.excluded[f] && !isFieldCovered(pass.Pkg, f, state) {
			pass.ReportRangef(writeFn.Name, "digestcover: 结构体 %s 的 WriteCanonical 未覆盖字段 %s（请显式编码或添加 //xops:hash-exclude:<reason>）", target.ts.Name.Name, f.Name())
		}
	}
}

func extractRecvVar(info *types.Info, fn *ast.FuncDecl) *types.Var {
	if fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) == 0 || fn.Recv.List[0].Names[0].Name == "_" {
		return nil
	}
	v, _ := info.Defs[fn.Recv.List[0].Names[0]].(*types.Var)
	return v
}

func analyzeFuncBody(pass *analysis.Pass, body *ast.BlockStmt, targetVar *types.Var, state *coverageState) {
	if targetVar == nil {
		return
	}
	aliases, ignored, fieldPrefixes := collectImmutableAliases(pass.TypesInfo, body, targetVar), collectIgnoredSelectors(body), collectFieldPathPrefixes(pass.TypesInfo, body)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if !ignored[node] {
				recordSelectorCoverage(pass.TypesInfo, node, aliases, fieldPrefixes, state)
			}
		case *ast.CallExpr:
			recurseIntoHelperCalls(pass, node, aliases, state)
		}
		return true
	})
}

func collectImmutableAliases(info *types.Info, body *ast.BlockStmt, rootVar *types.Var) map[*types.Var]bool {
	writes := countVarWrites(info, body)
	// H7: 若接收者或形参在函数体内被重赋值，拒绝将其作为不可变别名根（阻断重赋值后伪造覆盖）。
	if writes[rootVar] > 0 {
		return map[*types.Var]bool{}
	}
	aliases := map[*types.Var]bool{rootVar: true}
	for {
		added := false
		ast.Inspect(body, func(n ast.Node) bool {
			added = tryAddAliasFromNode(info, n, aliases, writes) || added
			return true
		})
		if !added {
			return aliases
		}
	}
}

func countVarWrites(info *types.Info, body *ast.BlockStmt) map[*types.Var]int {
	writes := make(map[*types.Var]int)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			countExprWrites(info, node.Lhs, writes)
		case *ast.ValueSpec:
			if len(node.Values) > 0 {
				countExprWrites(info, vetutil.IdentSliceToExprs(node.Names), writes)
			}
		case *ast.RangeStmt:
			countExprWrites(info, []ast.Expr{node.Key, node.Value}, writes)
		}
		return true
	})
	return writes
}

func countExprWrites(info *types.Info, exprs []ast.Expr, writes map[*types.Var]int) {
	for _, e := range exprs {
		id, ok := ast.Unparen(e).(*ast.Ident)
		if !ok || id.Name == "_" {
			continue
		}
		if v, ok := info.Defs[id].(*types.Var); ok && v != nil {
			writes[v]++
		} else if v, ok := info.Uses[id].(*types.Var); ok && v != nil {
			writes[v]++
		}
	}
}

func tryAddAliasFromNode(info *types.Info, n ast.Node, aliases map[*types.Var]bool, writes map[*types.Var]int) bool {
	switch node := n.(type) {
	case *ast.AssignStmt:
		return tryAddAliasFromPair(info, node.Lhs, node.Rhs, node.Tok == token.DEFINE, aliases, writes)
	case *ast.ValueSpec:
		return tryAddAliasFromPair(info, vetutil.IdentSliceToExprs(node.Names), node.Values, true, aliases, writes)
	default:
		return false
	}
}

func tryAddAliasFromPair(info *types.Info, lhs, rhs []ast.Expr, isDef bool, aliases map[*types.Var]bool, writes map[*types.Var]int) bool {
	if len(lhs) != len(rhs) {
		return false
	}
	added := false
	for i := range lhs {
		id, ok := ast.Unparen(lhs[i]).(*ast.Ident)
		if !ok || id.Name == "_" {
			continue
		}
		v := resolveAliasLHSVar(info, id, isDef, writes)
		if v != nil && !aliases[v] && isAliasExpr(info, rhs[i], aliases) {
			aliases[v], added = true, true
		}
	}
	return added
}

func resolveAliasLHSVar(info *types.Info, id *ast.Ident, isDef bool, writes map[*types.Var]int) *types.Var {
	var v *types.Var
	if isDef {
		v, _ = info.Defs[id].(*types.Var)
	} else {
		v, _ = info.Uses[id].(*types.Var)
	}
	if v != nil && writes[v] == 1 {
		return v
	}
	return nil
}

func collectIgnoredSelectors(body *ast.BlockStmt) map[*ast.SelectorExpr]bool {
	ignored := make(map[*ast.SelectorExpr]bool)
	markSel := func(e ast.Expr) {
		if sel := unwrapStarParenSelector(e); sel != nil {
			ignored[sel] = true
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			markAssignIgnoredSelectors(node, markSel)
		case *ast.ValueSpec:
			for i, id := range node.Names {
				if i < len(node.Values) && id != nil && id.Name == "_" {
					markSel(node.Values[i])
				}
			}
		case *ast.IncDecStmt:
			markSel(node.X)
		}
		return true
	})
	return ignored
}

func markAssignIgnoredSelectors(assign *ast.AssignStmt, markSel func(ast.Expr)) {
	for i, lhs := range assign.Lhs {
		if assign.Tok != token.DEFINE {
			markSel(lhs)
		}
		if i < len(assign.Rhs) {
			if id, ok := ast.Unparen(lhs).(*ast.Ident); ok && id.Name == "_" {
				markSel(assign.Rhs[i])
			}
		}
	}
}

// unwrapStarParenSelector 解包外层括号、指针解引用（*）与取址（&），提取底层 SelectorExpr。
func unwrapStarParenSelector(expr ast.Expr) *ast.SelectorExpr {
	for cur := ast.Unparen(expr); cur != nil; {
		switch e := cur.(type) {
		case *ast.StarExpr:
			cur = ast.Unparen(e.X)
		case *ast.UnaryExpr:
			if e.Op != token.AND {
				return nil
			}
			cur = ast.Unparen(e.X)
		case *ast.SelectorExpr:
			return e
		default:
			return nil
		}
	}
	return nil
}

func isAliasExpr(info *types.Info, expr ast.Expr, aliases map[*types.Var]bool) bool {
	for cur := ast.Unparen(expr); cur != nil; cur = ast.Unparen(cur) {
		switch e := cur.(type) {
		case *ast.StarExpr:
			cur = e.X
		case *ast.UnaryExpr:
			if e.Op != token.AND {
				return false
			}
			cur = e.X
		case *ast.Ident:
			v, ok := info.Uses[e].(*types.Var)
			return ok && aliases[v]
		default:
			return false
		}
	}
	return false
}

func recurseIntoHelperCalls(pass *analysis.Pass, call *ast.CallExpr, aliases map[*types.Var]bool, state *coverageState) {
	callee, ok := vetutil.ResolveCalledObject(pass.TypesInfo, call).(*types.Func)
	if !ok || callee == nil {
		return
	}
	origCallee := callee.Origin()
	if origCallee == nil || origCallee.Pkg() != pass.Pkg {
		return
	}
	helperDecl := state.funcDecls[origCallee]
	if helperDecl == nil || helperDecl.Body == nil {
		return
	}
	argOffset := visitHelperReceiver(pass, call, origCallee, helperDecl, aliases, state)
	params := extractParamVars(pass.TypesInfo, helperDecl)
	for k := argOffset; k < len(call.Args); k++ {
		if pIdx := k - argOffset; pIdx < len(params) && params[pIdx] != nil && isAliasExpr(pass.TypesInfo, call.Args[k], aliases) {
			visitHelper(pass, origCallee, pIdx, helperDecl.Body, params[pIdx], state)
		}
	}
}

func visitHelperReceiver(pass *analysis.Pass, call *ast.CallExpr, origCallee *types.Func, helperDecl *ast.FuncDecl, aliases map[*types.Var]bool, state *coverageState) int {
	selExpr, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return 0
	}
	recvExpr, argOffset := selExpr.X, 0
	if sel := pass.TypesInfo.Selections[selExpr]; sel != nil && sel.Kind() == types.MethodExpr {
		argOffset = 1
		if len(call.Args) == 0 {
			return argOffset
		}
		recvExpr = call.Args[0]
	}
	if isAliasExpr(pass.TypesInfo, recvExpr, aliases) {
		if recvVar := extractRecvVar(pass.TypesInfo, helperDecl); recvVar != nil {
			visitHelper(pass, origCallee, -1, helperDecl.Body, recvVar, state)
		}
	}
	return argOffset
}

func visitHelper(pass *analysis.Pass, callee *types.Func, paramIdx int, body *ast.BlockStmt, targetVar *types.Var, state *coverageState) {
	if key := (visitKey{fn: callee, paramIdx: paramIdx}); !state.visited[key] {
		state.visited[key] = true
		analyzeFuncBody(pass, body, targetVar, state)
	}
}

func extractParamVars(info *types.Info, fn *ast.FuncDecl) []*types.Var {
	if fn.Type == nil || fn.Type.Params == nil {
		return nil
	}
	var out []*types.Var
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			out = append(out, nil)
			continue
		}
		for _, id := range field.Names {
			var v *types.Var
			if id.Name != "_" {
				v, _ = info.Defs[id].(*types.Var)
			}
			out = append(out, v)
		}
	}
	return out
}
