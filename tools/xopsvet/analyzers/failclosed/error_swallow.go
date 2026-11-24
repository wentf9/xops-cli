package failclosed

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

func checkErrorSwallowing(pass *analysis.Pass) {
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
			inspectBoolFuncBody(pass, fn, fn.Body, sig)
		case *ast.FuncLit:
			if fn.Body == nil {
				return
			}
			sig, _ := pass.TypesInfo.TypeOf(fn).(*types.Signature)
			inspectBoolFuncBody(pass, fn, fn.Body, sig)
		}
	})
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

func inspectBoolFuncBody(pass *analysis.Pass, fnNode ast.Node, body *ast.BlockStmt, sig *types.Signature) {
	if !hasBoolWithoutError(sig) {
		return
	}
	inspectBoolScopeBody(pass, fnNode, body)
}

func inspectBoolScopeBody(pass *analysis.Pass, fnNode ast.Node, body *ast.BlockStmt) {
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		// 嵌套 FuncLit 默认保持隔离，避免回调（如 slices.SortFunc）误归因到外层 bool 函数；
		// 立即调用/defer/go 的无 bool/error 返回 FuncLit 由下方 CallExpr 分支显式递归进入。
		if lit, ok := n.(*ast.FuncLit); ok && lit != fnNode {
			return false
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			checkSwallowedCallError(pass, node)
			inspectInlineVoidFuncLit(pass, node)
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

func inspectInlineVoidFuncLit(pass *analysis.Pass, call *ast.CallExpr) {
	lit, ok := ast.Unparen(call.Fun).(*ast.FuncLit)
	if !ok || lit.Body == nil {
		return
	}
	litSig, _ := pass.TypesInfo.TypeOf(lit).(*types.Signature)
	if hasBoolWithoutError(litSig) || sigReturnsError(litSig) {
		return
	}
	inspectBoolScopeBody(pass, lit, lit.Body)
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
