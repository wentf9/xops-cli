package secrettaint

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"

	"golang.org/x/tools/go/analysis"
)

// maxBoxFixpointIters 限制规则 1 中携带 SecretBox 的 any/局部/包级变量传播最大迭代轮次。
const maxBoxFixpointIters = 32

func checkFuncSecretBoxSinks(pass *analysis.Pass, restricted map[*types.TypeName]bool) {
	pkgBoxVars := collectPackageSecretBoxVars(pass)
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			checkDeclSecretBoxSinks(pass, decl, pkgBoxVars, restricted)
		}
	}
}

func checkDeclSecretBoxSinks(
	pass *analysis.Pass,
	decl ast.Decl,
	pkgBoxVars map[*types.Var]bool,
	restricted map[*types.TypeName]bool,
) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Body != nil {
			checkSubtreeSecretBoxSinks(pass, d.Body, pkgBoxVars, restricted)
		}
	case *ast.GenDecl:
		if d.Tok != token.VAR {
			return
		}
		for _, spec := range d.Specs {
			if vs, ok := spec.(*ast.ValueSpec); ok {
				checkSubtreeSecretBoxSinks(pass, vs, pkgBoxVars, restricted)
			}
		}
	}
}

// checkSubtreeSecretBoxSinks 在单遍流中共享 boxVars，同时检查 Rule 1 汇点调用与受限复合字面量
// （覆盖 any 擦除变量进入受限结构体/切片以及受限 Map 的键与值）。
func checkSubtreeSecretBoxSinks(
	pass *analysis.Pass,
	root ast.Node,
	pkgBoxVars map[*types.Var]bool,
	restricted map[*types.TypeName]bool,
) {
	boxVars := maps.Clone(pkgBoxVars)
	if boxVars == nil {
		boxVars = make(map[*types.Var]bool)
	}
	collectSecretBoxVars(pass.TypesInfo, root, boxVars)
	ast.Inspect(root, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			checkRule1CallSink(pass, node, boxVars)
		case *ast.CompositeLit:
			checkRestrictedCompositeLit(pass, node, boxVars, restricted)
		}
		return true
	})
}

func checkRule1CallSink(pass *analysis.Pass, call *ast.CallExpr, boxVars map[*types.Var]bool) {
	kind := classifyRule1SinkCall(pass.TypesInfo, call)
	if kind == sinkNone {
		return
	}
	for _, arg := range call.Args {
		if exprHasSecretBox(pass.TypesInfo, arg, boxVars) {
			pass.ReportRangef(arg, "secrettaint: 禁止将 secret.SecretBox 传入%s汇点", kind.label())
		}
	}
}

func checkRestrictedCompositeLit(
	pass *analysis.Pass,
	lit *ast.CompositeLit,
	boxVars map[*types.Var]bool,
	restricted map[*types.TypeName]bool,
) {
	litType := pass.TypesInfo.TypeOf(lit)
	if !isRestrictedLitType(litType, restricted) {
		return
	}
	isMap := isMapExprType(litType)
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if isMap && exprHasSecretBox(pass.TypesInfo, kv.Key, boxVars) {
				pass.ReportRangef(kv.Key, "secrettaint: 禁止将 secret.SecretBox 存入 Event/Audit/Plan/Error/序列化结构体字段")
			}
			if exprHasSecretBox(pass.TypesInfo, kv.Value, boxVars) {
				pass.ReportRangef(kv.Value, "secrettaint: 禁止将 secret.SecretBox 存入 Event/Audit/Plan/Error/序列化结构体字段")
			}
			continue
		}
		if exprHasSecretBox(pass.TypesInfo, elt, boxVars) {
			pass.ReportRangef(elt, "secrettaint: 禁止将 secret.SecretBox 存入 Event/Audit/Plan/Error/序列化结构体字段")
		}
	}
}

func collectPackageSecretBoxVars(pass *analysis.Pass) map[*types.Var]bool {
	boxVars := make(map[*types.Var]bool)
	for range maxBoxFixpointIters {
		changed := false
		for _, file := range pass.Files {
			if propagateFilePkgBoxVars(pass.TypesInfo, file, boxVars) {
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return boxVars
}

func propagateFilePkgBoxVars(info *types.Info, file *ast.File, boxVars map[*types.Var]bool) bool {
	changed := false
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			if vs, ok := spec.(*ast.ValueSpec); ok && propagateBoxValueSpec(info, vs, boxVars) {
				changed = true
			}
		}
	}
	return changed
}

func collectSecretBoxVars(info *types.Info, root ast.Node, boxVars map[*types.Var]bool) {
	for range maxBoxFixpointIters {
		if !propagateSecretBoxVarsStep(info, root, boxVars) {
			break
		}
	}
}

func propagateSecretBoxVarsStep(info *types.Info, root ast.Node, boxVars map[*types.Var]bool) bool {
	changed := false
	ast.Inspect(root, func(n ast.Node) bool {
		if propagateSecretBoxNode(info, n, boxVars) {
			changed = true
		}
		return true
	})
	return changed
}

func propagateSecretBoxNode(info *types.Info, n ast.Node, boxVars map[*types.Var]bool) bool {
	switch stmt := n.(type) {
	case *ast.AssignStmt:
		return propagateBoxPairs(info, stmt.Lhs, stmt.Rhs, boxVars)
	case *ast.ValueSpec:
		return propagateBoxValueSpec(info, stmt, boxVars)
	case *ast.CallExpr:
		if lit, ok := ast.Unparen(stmt.Fun).(*ast.FuncLit); ok {
			return propagateBoxFuncLitArgs(info, stmt, lit, boxVars)
		}
	}
	return false
}

func propagateBoxFuncLitArgs(info *types.Info, call *ast.CallExpr, lit *ast.FuncLit, boxVars map[*types.Var]bool) bool {
	if lit == nil || lit.Type == nil || lit.Type.Params == nil || len(call.Args) == 0 {
		return false
	}
	paramVars, isVariadic := flattenParamVars(info, lit.Type.Params)
	if len(paramVars) == 0 {
		return false
	}
	changed := false
	for i, arg := range call.Args {
		if !exprHasSecretBox(info, arg, boxVars) {
			continue
		}
		pVar := paramVarAt(paramVars, isVariadic, i)
		if pVar != nil && !boxVars[pVar] {
			boxVars[pVar] = true
			changed = true
		}
	}
	return changed
}

func propagateBoxValueSpec(info *types.Info, vs *ast.ValueSpec, boxVars map[*types.Var]bool) bool {
	if len(vs.Names) == 2 && len(vs.Values) == 1 {
		if rhs, ok := unwrapBoxCommaOKRHS(vs.Values[0]); ok {
			return propagateSingleBoxVar(info, vs.Names[0], rhs, boxVars)
		}
		return false
	}
	if len(vs.Names) != len(vs.Values) {
		return false
	}
	changed := false
	for i := range vs.Names {
		if propagateSingleBoxVar(info, vs.Names[i], vs.Values[i], boxVars) {
			changed = true
		}
	}
	return changed
}

func propagateBoxPairs(info *types.Info, lhs, rhs []ast.Expr, boxVars map[*types.Var]bool) bool {
	if len(lhs) == 2 && len(rhs) == 1 {
		if unwrapped, ok := unwrapBoxCommaOKRHS(rhs[0]); ok {
			return propagateSingleBoxVar(info, lhs[0], unwrapped, boxVars)
		}
		return false
	}
	if len(lhs) != len(rhs) {
		return false
	}
	changed := false
	for i := range lhs {
		if propagateSingleBoxVar(info, lhs[i], rhs[i], boxVars) {
			changed = true
		}
	}
	return changed
}

func propagateSingleBoxVar(info *types.Info, lhs, rhs ast.Expr, boxVars map[*types.Var]bool) bool {
	id, ok := ast.Unparen(lhs).(*ast.Ident)
	if !ok || id.Name == "_" {
		return false
	}
	v := lookupAssignVar(info, id)
	if v != nil && exprHasSecretBox(info, rhs, boxVars) && !boxVars[v] {
		boxVars[v] = true
		return true
	}
	return false
}

// unwrapBoxCommaOKRHS 提取 comma-ok 形式类型断言（v, ok := a.(T)）或 Map 索引（v, ok := m[k]）的底层容器表达式。
func unwrapBoxCommaOKRHS(expr ast.Expr) (ast.Expr, bool) {
	switch rhs := ast.Unparen(expr).(type) {
	case *ast.TypeAssertExpr:
		if rhs.Type != nil {
			return rhs.X, true
		}
	case *ast.IndexExpr:
		return rhs.X, true
	}
	return nil, false
}

func lookupAssignVar(info *types.Info, id *ast.Ident) *types.Var {
	if v, ok := info.Defs[id].(*types.Var); ok && v != nil {
		return v
	}
	if v, ok := info.Uses[id].(*types.Var); ok && v != nil {
		return v
	}
	return nil
}

func exprHasSecretBox(info *types.Info, expr ast.Expr, boxVars map[*types.Var]bool) bool {
	return exprHasSecretBoxDepth(info, expr, boxVars, 0)
}

func exprHasSecretBoxDepth(info *types.Info, expr ast.Expr, boxVars map[*types.Var]bool, depth int) bool {
	if expr == nil {
		return false
	}
	if isSecretBoxType(info.TypeOf(expr)) {
		return true
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		v, ok := info.Uses[e].(*types.Var)
		return ok && v != nil && boxVars != nil && boxVars[v]
	case *ast.UnaryExpr:
		return exprHasSecretBoxDepth(info, e.X, boxVars, depth)
	case *ast.StarExpr:
		return exprHasSecretBoxDepth(info, e.X, boxVars, depth)
	case *ast.TypeAssertExpr:
		return exprHasSecretBoxDepth(info, e.X, boxVars, depth)
	case *ast.IndexExpr:
		return exprHasSecretBoxDepth(info, e.X, boxVars, depth)
	case *ast.SliceExpr:
		return exprHasSecretBoxDepth(info, e.X, boxVars, depth)
	case *ast.CompositeLit:
		return compositeLitHasSecretBox(info, e, boxVars, depth)
	case *ast.CallExpr:
		return callHasSecretBox(info, e, boxVars, depth)
	default:
		return false
	}
}

func compositeLitHasSecretBox(info *types.Info, lit *ast.CompositeLit, boxVars map[*types.Var]bool, depth int) bool {
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if exprHasSecretBoxDepth(info, kv.Key, boxVars, depth) || exprHasSecretBoxDepth(info, kv.Value, boxVars, depth) {
				return true
			}
			continue
		}
		if exprHasSecretBoxDepth(info, elt, boxVars, depth) {
			return true
		}
	}
	return false
}

func callHasSecretBox(info *types.Info, call *ast.CallExpr, boxVars map[*types.Var]bool, depth int) bool {
	if conversionHasSecretBox(info, call, boxVars, depth) {
		return true
	}
	lit, ok := ast.Unparen(call.Fun).(*ast.FuncLit)
	if !ok || lit.Body == nil || lit.Type == nil || depth >= 8 {
		return false
	}
	localVars := boxVars
	if localVars == nil {
		localVars = make(map[*types.Var]bool)
		propagateBoxFuncLitArgs(info, call, lit, localVars)
		collectSecretBoxVars(info, lit.Body, localVars)
	} else {
		propagateBoxFuncLitArgs(info, call, lit, localVars)
	}
	return funcLitReturnsSecretBox(info, lit, localVars, depth+1)
}

func funcLitReturnsSecretBox(info *types.Info, lit *ast.FuncLit, boxVars map[*types.Var]bool, depth int) bool {
	resultVars := collectResultVars(info, lit.Type.Results)
	found := false
	walkOutsideClosures(lit.Body, func(n ast.Node) {
		if found {
			return
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return
		}
		if len(ret.Results) == 0 {
			found = anyResultVarInBoxVars(resultVars, boxVars)
			return
		}
		for _, res := range ret.Results {
			if exprHasSecretBoxDepth(info, res, boxVars, depth) {
				found = true
				return
			}
		}
	})
	return found
}

func anyResultVarInBoxVars(resultVars, boxVars map[*types.Var]bool) bool {
	for v := range resultVars {
		if boxVars[v] {
			return true
		}
	}
	return false
}

func conversionHasSecretBox(info *types.Info, call *ast.CallExpr, boxVars map[*types.Var]bool, depth int) bool {
	if len(call.Args) != 1 {
		return false
	}
	tv, ok := info.Types[call.Fun]
	if !ok || !tv.IsType() {
		return false
	}
	return exprHasSecretBoxDepth(info, call.Args[0], boxVars, depth)
}
