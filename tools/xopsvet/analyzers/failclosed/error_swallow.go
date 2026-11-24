package failclosed

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

func checkErrorSwallowing(pass *analysis.Pass) {
	// 预先收集全包局部无返回/非 error-bool 闭包变量绑定，使嵌套 func() bool 调用外层局部闭包时同样受检。
	voidFuncVars := collectLocalVoidFuncVars(pass)
	visitedLits := make(map[*ast.FuncLit]bool)
	ins := vetutil.InspectorOf(pass)
	nodeFilter := []ast.Node{
		(*ast.FuncDecl)(nil),
		(*ast.FuncLit)(nil),
	}
	ins.Preorder(nodeFilter, func(n ast.Node) {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body == nil || fn.Name == nil {
				return
			}
			obj := pass.TypesInfo.Defs[fn.Name]
			if obj == nil {
				return
			}
			sig, _ := obj.Type().(*types.Signature)
			inspectBoolFuncBody(pass, fn, fn.Body, sig, voidFuncVars, visitedLits)
		case *ast.FuncLit:
			if fn.Body == nil {
				return
			}
			sig, _ := pass.TypesInfo.TypeOf(fn).(*types.Signature)
			inspectBoolFuncBody(pass, fn, fn.Body, sig, voidFuncVars, visitedLits)
		}
	})
}

func collectLocalVoidFuncVars(pass *analysis.Pass) map[*types.Var][]*ast.FuncLit {
	out := make(map[*types.Var][]*ast.FuncLit)
	if pass == nil || pass.TypesInfo == nil || pass.Pkg == nil {
		return out
	}
	pkgScope := pass.Pkg.Scope()
	ins := vetutil.InspectorOf(pass)
	nodeFilter := []ast.Node{
		(*ast.AssignStmt)(nil),
		(*ast.ValueSpec)(nil),
	}
	ins.Preorder(nodeFilter, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.AssignStmt:
			recordVoidFuncLitPair(pass.TypesInfo, pkgScope, node.Lhs, node.Rhs, node.Tok == token.DEFINE, out)
		case *ast.ValueSpec:
			recordVoidFuncLitValueSpec(pass.TypesInfo, pkgScope, node, out)
		}
	})
	return out
}

func hasBoolWithoutError(sig *types.Signature) bool {
	if sig == nil || sig.Results() == nil || sig.Results().Len() == 0 {
		return false
	}
	results := sig.Results()
	hasBool := false
	for i := 0; i < results.Len(); i++ {
		rt := results.At(i).Type()
		if vetutil.IsErrorInterfaceType(rt) {
			return false
		}
		if isBoolType(rt) {
			hasBool = true
		}
	}
	return hasBool
}

func isBoolType(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && basic.Kind() == types.Bool
}

func sigReturnsError(sig *types.Signature) bool {
	if sig == nil || sig.Results() == nil {
		return false
	}
	for i := 0; i < sig.Results().Len(); i++ {
		if vetutil.IsErrorInterfaceType(sig.Results().At(i).Type()) {
			return true
		}
	}
	return false
}

func inspectBoolFuncBody(
	pass *analysis.Pass,
	fnNode ast.Node,
	body *ast.BlockStmt,
	sig *types.Signature,
	voidFuncVars map[*types.Var][]*ast.FuncLit,
	visitedLits map[*ast.FuncLit]bool,
) {
	if !hasBoolWithoutError(sig) {
		return
	}
	inspectBoolScopeBody(pass, fnNode, body, voidFuncVars, visitedLits)
}

func inspectBoolScopeBody(
	pass *analysis.Pass,
	fnNode ast.Node,
	body *ast.BlockStmt,
	voidFuncVars map[*types.Var][]*ast.FuncLit,
	visitedLits map[*ast.FuncLit]bool,
) {
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		// 嵌套 FuncLit 默认保持隔离，避免回调（如 slices.SortFunc）误归因到外层 bool 函数；
		// 立即调用/defer/go 或局部调用的无 bool/error 返回 FuncLit 由下方 CallExpr 分支显式递归进入。
		if lit, ok := n.(*ast.FuncLit); ok && lit != fnNode {
			return false
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			checkSwallowedCallError(pass, node)
			inspectCalledVoidFuncLit(pass, node, voidFuncVars, visitedLits)
		case *ast.UnaryExpr:
			if node.Op == token.ARROW {
				checkSwallowedChanError(pass, node)
			}
		case *ast.RangeStmt:
			checkSwallowedRangeChanError(pass, node)
		}
		return true
	})
}

func recordVoidFuncLitValueSpec(
	info *types.Info,
	pkgScope *types.Scope,
	spec *ast.ValueSpec,
	voidFuncVars map[*types.Var][]*ast.FuncLit,
) {
	if len(spec.Values) == 0 {
		return
	}
	lhs := make([]ast.Expr, len(spec.Names))
	for i, id := range spec.Names {
		lhs[i] = id
	}
	recordVoidFuncLitPair(info, pkgScope, lhs, spec.Values, true, voidFuncVars)
}

func recordVoidFuncLitPair(
	info *types.Info,
	pkgScope *types.Scope,
	lhs []ast.Expr,
	rhs []ast.Expr,
	isDef bool,
	voidFuncVars map[*types.Var][]*ast.FuncLit,
) {
	if info == nil {
		return
	}
	for i, expr := range rhs {
		if i >= len(lhs) {
			break
		}
		lit, ok := ast.Unparen(expr).(*ast.FuncLit)
		if !ok || !isVoidInspectableFuncLit(info, lit) {
			continue
		}
		id, ok := ast.Unparen(lhs[i]).(*ast.Ident)
		if !ok || id.Name == "_" {
			continue
		}
		v := resolveVarObj(info, id, isDef)
		if isLocalVar(v, pkgScope) {
			voidFuncVars[v] = append(voidFuncVars[v], lit)
		}
	}
}

func isLocalVar(v *types.Var, pkgScope *types.Scope) bool {
	return v != nil && v.Parent() != nil && v.Parent() != pkgScope
}

func resolveVarObj(info *types.Info, id *ast.Ident, isDef bool) *types.Var {
	if isDef {
		v, _ := info.Defs[id].(*types.Var)
		return v
	}
	v, _ := info.Uses[id].(*types.Var)
	return v
}

func isVoidInspectableFuncLit(info *types.Info, lit *ast.FuncLit) bool {
	if lit == nil || lit.Body == nil {
		return false
	}
	litSig, _ := info.TypeOf(lit).(*types.Signature)
	return !hasBoolWithoutError(litSig) && !sigReturnsError(litSig)
}

func inspectCalledVoidFuncLit(
	pass *analysis.Pass,
	call *ast.CallExpr,
	voidFuncVars map[*types.Var][]*ast.FuncLit,
	visitedLits map[*ast.FuncLit]bool,
) {
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.FuncLit:
		if isVoidInspectableFuncLit(pass.TypesInfo, fn) && !visitedLits[fn] {
			visitedLits[fn] = true
			inspectBoolScopeBody(pass, fn, fn.Body, voidFuncVars, visitedLits)
		}
	case *ast.Ident:
		v, ok := pass.TypesInfo.Uses[fn].(*types.Var)
		if !ok {
			return
		}
		for _, lit := range voidFuncVars[v] {
			if !visitedLits[lit] {
				visitedLits[lit] = true
				inspectBoolScopeBody(pass, lit, lit.Body, voidFuncVars, visitedLits)
			}
		}
	}
}

func checkSwallowedRangeChanError(pass *analysis.Pass, rng *ast.RangeStmt) {
	if rng == nil || rng.X == nil {
		return
	}
	tv, ok := pass.TypesInfo.Types[rng.X]
	if !ok || tv.Type == nil {
		return
	}
	ch, ok := types.Unalias(tv.Type).Underlying().(*types.Chan)
	if !ok || ch == nil {
		return
	}
	if typeIsOrContainsError(ch.Elem()) {
		pass.ReportRangef(rng, "failclosed: 返回 bool 的函数禁止在 range chan error 中吞噬局部 error")
	}
}

func checkSwallowedCallError(pass *analysis.Pass, call *ast.CallExpr) {
	callee := vetutil.ResolveCalledObject(pass.TypesInfo, call)
	if vetutil.IsPkgSymbol(callee, "errors", "Is", "As", "AsType") {
		return
	}
	tv, ok := pass.TypesInfo.Types[call]
	if !ok || !typeIsOrContainsError(tv.Type) {
		return
	}
	pass.ReportRangef(call, "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error（请改为返回 error 或使用 errors.Is/As/AsType 纯分类谓词）")
}

func checkSwallowedChanError(pass *analysis.Pass, un *ast.UnaryExpr) {
	tv, ok := pass.TypesInfo.Types[un]
	if !ok || !typeIsOrContainsError(tv.Type) {
		return
	}
	pass.ReportRangef(un, "failclosed: 返回 bool 的函数禁止吞噬从 channel 接收的局部 error")
}

func typeIsOrContainsError(t types.Type) bool {
	if t == nil {
		return false
	}
	if vetutil.IsErrorInterfaceType(t) {
		return true
	}
	tup, ok := t.(*types.Tuple)
	if !ok {
		return false
	}
	for i := 0; i < tup.Len(); i++ {
		if vetutil.IsErrorInterfaceType(tup.At(i).Type()) {
			return true
		}
	}
	return false
}
