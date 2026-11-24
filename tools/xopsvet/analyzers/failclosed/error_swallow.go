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
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.FuncDecl)(nil), (*ast.FuncLit)(nil)}, func(n ast.Node) {
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body != nil && fn.Name != nil {
				if obj := pass.TypesInfo.Defs[fn.Name]; obj != nil {
					sig, _ := obj.Type().(*types.Signature)
					inspectBoolFuncBody(pass, fn, fn.Body, sig, voidFuncVars, visitedLits)
				}
			}
		case *ast.FuncLit:
			if fn.Body != nil {
				sig, _ := pass.TypesInfo.TypeOf(fn).(*types.Signature)
				inspectBoolFuncBody(pass, fn, fn.Body, sig, voidFuncVars, visitedLits)
			}
		}
	})
}

func collectLocalVoidFuncVars(pass *analysis.Pass) map[*types.Var][]*ast.FuncLit {
	out := make(map[*types.Var][]*ast.FuncLit)
	if pass == nil || pass.TypesInfo == nil || pass.Pkg == nil {
		return out
	}
	pkgScope := pass.Pkg.Scope()
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.AssignStmt)(nil), (*ast.ValueSpec)(nil)}, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.AssignStmt:
			recordVoidFuncLitPair(pass.TypesInfo, pkgScope, node.Lhs, node.Rhs, node.Tok == token.DEFINE, out)
		case *ast.ValueSpec:
			if len(node.Values) > 0 {
				recordVoidFuncLitPair(pass.TypesInfo, pkgScope, vetutil.IdentSliceToExprs(node.Names), node.Values, true, out)
			}
		}
	})
	return out
}

func hasBoolWithoutError(sig *types.Signature) bool {
	if sig == nil || sig.Results() == nil || sig.Results().Len() == 0 {
		return false
	}
	hasBool := false
	for i := range sig.Results().Len() {
		rt := sig.Results().At(i).Type()
		if vetutil.IsErrorInterfaceType(rt) {
			return false
		}
		if b, ok := types.Unalias(rt).Underlying().(*types.Basic); ok && b.Kind() == types.Bool {
			hasBool = true
		}
	}
	return hasBool
}

func sigReturnsError(sig *types.Signature) bool {
	if sig == nil || sig.Results() == nil {
		return false
	}
	for i := range sig.Results().Len() {
		if vetutil.IsErrorInterfaceType(sig.Results().At(i).Type()) {
			return true
		}
	}
	return false
}

func inspectBoolFuncBody(pass *analysis.Pass, fnNode ast.Node, body *ast.BlockStmt, sig *types.Signature, voidFuncVars map[*types.Var][]*ast.FuncLit, visitedLits map[*ast.FuncLit]bool) {
	if hasBoolWithoutError(sig) {
		inspectBoolScopeBody(pass, fnNode, body, voidFuncVars, visitedLits)
	}
}

func inspectBoolScopeBody(pass *analysis.Pass, fnNode ast.Node, body *ast.BlockStmt, voidFuncVars map[*types.Var][]*ast.FuncLit, visitedLits map[*ast.FuncLit]bool) {
	ast.Inspect(body, func(n ast.Node) bool {
		// 嵌套 FuncLit 默认保持隔离，避免回调误归因；局部调用的无 bool/error 返回 FuncLit 由下方显式进入。
		if lit, ok := n.(*ast.FuncLit); ok && lit != fnNode {
			return false
		}
		checkBoolScopeNode(pass, n, voidFuncVars, visitedLits)
		return n != nil
	})
}

func checkBoolScopeNode(pass *analysis.Pass, n ast.Node, voidFuncVars map[*types.Var][]*ast.FuncLit, visitedLits map[*ast.FuncLit]bool) {
	switch node := n.(type) {
	case *ast.CallExpr:
		checkSwallowedCallError(pass, node)
		inspectCalledVoidFuncLit(pass, node, voidFuncVars, visitedLits)
	case *ast.UnaryExpr:
		if node.Op == token.ARROW {
			if tv, ok := pass.TypesInfo.Types[node]; ok && typeIsOrContainsError(tv.Type) {
				pass.ReportRangef(node, "failclosed: 返回 bool 的函数禁止吞噬从 channel 接收的局部 error")
			}
		}
	case *ast.RangeStmt:
		checkSwallowedRangeChanError(pass, node)
	}
}

func recordVoidFuncLitPair(info *types.Info, pkgScope *types.Scope, lhs, rhs []ast.Expr, isDef bool, voidFuncVars map[*types.Var][]*ast.FuncLit) {
	for i := range min(len(lhs), len(rhs)) {
		lit, ok := ast.Unparen(rhs[i]).(*ast.FuncLit)
		if !ok || !isVoidInspectableFuncLit(info, lit) {
			continue
		}
		id, ok := ast.Unparen(lhs[i]).(*ast.Ident)
		if !ok || id.Name == "_" {
			continue
		}
		v := resolveVarObj(info, id, isDef)
		if v != nil && v.Parent() != nil && v.Parent() != pkgScope {
			voidFuncVars[v] = append(voidFuncVars[v], lit)
		}
	}
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

func inspectCalledVoidFuncLit(pass *analysis.Pass, call *ast.CallExpr, voidFuncVars map[*types.Var][]*ast.FuncLit, visitedLits map[*ast.FuncLit]bool) {
	switch fn := ast.Unparen(call.Fun).(type) {
	case *ast.FuncLit:
		if isVoidInspectableFuncLit(pass.TypesInfo, fn) && !visitedLits[fn] {
			visitedLits[fn] = true
			inspectBoolScopeBody(pass, fn, fn.Body, voidFuncVars, visitedLits)
		}
	case *ast.Ident:
		if v, ok := pass.TypesInfo.Uses[fn].(*types.Var); ok {
			for _, lit := range voidFuncVars[v] {
				if !visitedLits[lit] {
					visitedLits[lit] = true
					inspectBoolScopeBody(pass, lit, lit.Body, voidFuncVars, visitedLits)
				}
			}
		}
	}
}

func checkSwallowedRangeChanError(pass *analysis.Pass, rng *ast.RangeStmt) {
	if rng != nil && rng.X != nil {
		if tv, ok := pass.TypesInfo.Types[rng.X]; ok && tv.Type != nil {
			if ch, ok := types.Unalias(tv.Type).Underlying().(*types.Chan); ok && ch != nil && typeIsOrContainsError(ch.Elem()) {
				pass.ReportRangef(rng, "failclosed: 返回 bool 的函数禁止在 range chan error 中吞噬局部 error")
			}
		}
	}
}

func checkSwallowedCallError(pass *analysis.Pass, call *ast.CallExpr) {
	if vetutil.IsPkgSymbol(vetutil.ResolveCalledObject(pass.TypesInfo, call), "errors", "Is", "As", "AsType") {
		return
	}
	if tv, ok := pass.TypesInfo.Types[call]; ok && typeIsOrContainsError(tv.Type) {
		pass.ReportRangef(call, "failclosed: 返回 bool 的函数禁止吞噬新产生的局部 error（请改为返回 error 或使用 errors.Is/As/AsType 纯分类谓词）")
	}
}

func typeIsOrContainsError(t types.Type) bool {
	if t == nil {
		return false
	}
	if vetutil.IsErrorInterfaceType(t) {
		return true
	}
	if tup, ok := t.(*types.Tuple); ok {
		for i := range tup.Len() {
			if vetutil.IsErrorInterfaceType(tup.At(i).Type()) {
				return true
			}
		}
	}
	return false
}
