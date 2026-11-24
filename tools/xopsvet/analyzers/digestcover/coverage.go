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

func checkTargetCoverage(
	pass *analysis.Pass,
	target canonicalTarget,
	writeFn *ast.FuncDecl,
	funcDecls map[*types.Func]*ast.FuncDecl,
) {
	if writeFn == nil || writeFn.Body == nil {
		pass.ReportRangef(target.ts.Name, "digestcover: 标记 //xops:canonicalhash 的结构体 %s 缺少 WriteCanonical 方法", target.ts.Name.Name)
		return
	}
	state := &coverageState{
		target:    target,
		funcDecls: funcDecls,
		covered:   make(map[*types.Var]bool),
		promoted:  make(map[*types.Var]map[*types.Var]bool),
		visited:   make(map[visitKey]bool),
	}
	recvVar := extractRecvVar(pass.TypesInfo, writeFn)
	if fnObj, ok := pass.TypesInfo.Defs[writeFn.Name].(*types.Func); ok && fnObj != nil {
		state.visited[visitKey{fn: fnObj.Origin(), paramIdx: -1}] = true
	}
	checkNoReflectReachable(pass, writeFn, funcDecls)
	analyzeFuncBody(pass, writeFn.Body, recvVar, state)

	for _, f := range target.fields {
		if target.excluded[f] {
			continue
		}
		if isFieldCovered(pass.Pkg, f, state) {
			continue
		}
		pass.ReportRangef(
			writeFn.Name,
			"digestcover: 结构体 %s 的 WriteCanonical 未覆盖字段 %s（请显式编码或添加 //xops:hash-exclude:<reason>）",
			target.ts.Name.Name,
			f.Name(),
		)
	}
}

func extractRecvVar(info *types.Info, fn *ast.FuncDecl) *types.Var {
	if fn.Recv == nil || len(fn.Recv.List) != 1 || len(fn.Recv.List[0].Names) == 0 {
		return nil
	}
	name := fn.Recv.List[0].Names[0]
	if name.Name == "_" {
		return nil
	}
	v, _ := info.Defs[name].(*types.Var)
	return v
}

func analyzeFuncBody(pass *analysis.Pass, body *ast.BlockStmt, targetVar *types.Var, state *coverageState) {
	if targetVar == nil {
		return
	}
	aliases := collectImmutableAliases(pass.TypesInfo, body, targetVar)
	ignored := collectIgnoredSelectors(body)
	fieldPrefixes := collectFieldPathPrefixes(pass.TypesInfo, body)

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
	aliases := map[*types.Var]bool{rootVar: true}
	writes := countVarWrites(info, body)
	for {
		added := false
		ast.Inspect(body, func(n ast.Node) bool {
			if tryAddAliasFromNode(info, n, aliases, writes) {
				added = true
			}
			return true
		})
		if !added {
			break
		}
	}
	return aliases
}

func countVarWrites(info *types.Info, body *ast.BlockStmt) map[*types.Var]int {
	writes := make(map[*types.Var]int)
	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			if id, ok := ast.Unparen(lhs).(*ast.Ident); ok {
				if v, ok := info.Uses[id].(*types.Var); ok && v != nil {
					writes[v]++
				}
			}
		}
		return true
	})
	return writes
}

func tryAddAliasFromNode(info *types.Info, n ast.Node, aliases map[*types.Var]bool, writes map[*types.Var]int) bool {
	switch node := n.(type) {
	case *ast.AssignStmt:
		return tryAddAliasFromPair(info, node.Lhs, node.Rhs, node.Tok == token.DEFINE, aliases, writes)
	case *ast.ValueSpec:
		lhs := make([]ast.Expr, len(node.Names))
		for i, id := range node.Names {
			lhs[i] = id
		}
		return tryAddAliasFromPair(info, lhs, node.Values, true, aliases, writes)
	default:
		return false
	}
}

func tryAddAliasFromPair(
	info *types.Info,
	lhs []ast.Expr,
	rhs []ast.Expr,
	isDef bool,
	aliases map[*types.Var]bool,
	writes map[*types.Var]int,
) bool {
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
		if v == nil || aliases[v] {
			continue
		}
		if isAliasExpr(info, rhs[i], aliases) {
			aliases[v] = true
			added = true
		}
	}
	return added
}

func resolveAliasLHSVar(info *types.Info, id *ast.Ident, isDef bool, writes map[*types.Var]int) *types.Var {
	if isDef {
		if v, ok := info.Defs[id].(*types.Var); ok && v != nil && writes[v] == 0 {
			return v
		}
		return nil
	}
	if v, ok := info.Uses[id].(*types.Var); ok && v != nil && writes[v] == 1 {
		return v
	}
	return nil
}

func collectIgnoredSelectors(body *ast.BlockStmt) map[*ast.SelectorExpr]bool {
	ignored := make(map[*ast.SelectorExpr]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			markAssignIgnoredSelectors(node, ignored)
		case *ast.ValueSpec:
			markValueSpecIgnoredSelectors(node, ignored)
		case *ast.IncDecStmt:
			if sel := unwrapStarParenSelector(node.X); sel != nil {
				ignored[sel] = true
			}
		}
		return true
	})
	return ignored
}

func markAssignIgnoredSelectors(assign *ast.AssignStmt, ignored map[*ast.SelectorExpr]bool) {
	if assign.Tok != token.DEFINE {
		for _, lhs := range assign.Lhs {
			if sel := unwrapStarParenSelector(lhs); sel != nil {
				ignored[sel] = true
			}
		}
	}
	for i, lhs := range assign.Lhs {
		if i >= len(assign.Rhs) {
			break
		}
		if id, ok := ast.Unparen(lhs).(*ast.Ident); ok && id.Name == "_" {
			if sel := unwrapStarParenSelector(assign.Rhs[i]); sel != nil {
				ignored[sel] = true
			}
		}
	}
}

func markValueSpecIgnoredSelectors(spec *ast.ValueSpec, ignored map[*ast.SelectorExpr]bool) {
	for i, id := range spec.Names {
		if i >= len(spec.Values) {
			break
		}
		if id != nil && id.Name == "_" {
			if sel := unwrapStarParenSelector(spec.Values[i]); sel != nil {
				ignored[sel] = true
			}
		}
	}
}

func unwrapStarParenSelector(expr ast.Expr) *ast.SelectorExpr {
	cur := ast.Unparen(expr)
	for cur != nil {
		switch e := cur.(type) {
		case *ast.StarExpr:
			cur = ast.Unparen(e.X)
		case *ast.UnaryExpr:
			if e.Op != token.AND {
				return nil
			}
			cur = ast.Unparen(e.X)
		default:
			sel, _ := cur.(*ast.SelectorExpr)
			return sel
		}
	}
	return nil
}

func isAliasExpr(info *types.Info, expr ast.Expr, aliases map[*types.Var]bool) bool {
	cur := expr
	for {
		cur = ast.Unparen(cur)
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
}

func recurseIntoHelperCalls(
	pass *analysis.Pass,
	call *ast.CallExpr,
	aliases map[*types.Var]bool,
	state *coverageState,
) {
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
	if selExpr, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && isAliasExpr(pass.TypesInfo, selExpr.X, aliases) {
		if recvVar := extractRecvVar(pass.TypesInfo, helperDecl); recvVar != nil {
			visitHelper(pass, origCallee, -1, helperDecl.Body, recvVar, state)
		}
	}
	params := extractParamVars(pass.TypesInfo, helperDecl)
	for k, arg := range call.Args {
		if k < len(params) && params[k] != nil && isAliasExpr(pass.TypesInfo, arg, aliases) {
			visitHelper(pass, origCallee, k, helperDecl.Body, params[k], state)
		}
	}
}

func visitHelper(
	pass *analysis.Pass,
	callee *types.Func,
	paramIdx int,
	body *ast.BlockStmt,
	targetVar *types.Var,
	state *coverageState,
) {
	key := visitKey{fn: callee, paramIdx: paramIdx}
	if state.visited[key] {
		return
	}
	state.visited[key] = true
	analyzeFuncBody(pass, body, targetVar, state)
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
			if id.Name == "_" {
				out = append(out, nil)
				continue
			}
			v, _ := info.Defs[id].(*types.Var)
			out = append(out, v)
		}
	}
	return out
}
