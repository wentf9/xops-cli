package secrettaint

import (
	"go/ast"
	"go/token"
	"go/types"
)

func (s *taintState) checkNode(n ast.Node, exemptDeferLits map[*ast.FuncLit]bool) {
	switch node := n.(type) {
	case *ast.CallExpr:
		s.checkCall(node)
	case *ast.AssignStmt:
		s.checkAssign(node)
	case *ast.ValueSpec:
		s.checkValueSpec(node)
	case *ast.CompositeLit:
		s.checkCompositeLit(node)
	case *ast.SendStmt:
		if s.exprContainsTainted(node.Value) {
			s.reportLeak(node.Value, "secrettaint: 禁止将明文机密发送至 channel")
		}
	case *ast.ReturnStmt:
		for _, res := range node.Results {
			if s.exprContainsTainted(res) {
				s.reportLeak(res, "secrettaint: 禁止通过 return 返回明文机密")
			}
		}
	case *ast.FuncLit:
		if !exemptDeferLits[node] && s.funcLitCapturesTaint(node) {
			s.reportLeak(node, "secrettaint: 禁止在内层闭包中捕获明文机密变量（仅豁免 defer clear）")
		}
	}
}

func (s *taintState) checkCall(call *ast.CallExpr) {
	if isExemptBuiltinCall(s.pass.TypesInfo, call) || isExemptPredicateCall(s.pass.TypesInfo, call) {
		return
	}
	if isCopyBuiltin(s.pass.TypesInfo, call) && len(call.Args) == 2 && s.exprIsTainted(call.Args[1]) {
		s.checkMutationDestEscape(call.Args[0], "secrettaint: 禁止通过 copy 将明文机密写入外层变量或字段")
		return
	}
	if isAppendBuiltin(s.pass.TypesInfo, call) && len(call.Args) >= 2 && s.argsContainTaint(call.Args[1:]) {
		s.checkMutationDestEscape(call.Args[0], "secrettaint: 禁止通过 append 将明文机密写入外层变量或字段")
		return
	}
	if isBufferOrBuilderWriteMethod(s.pass.TypesInfo, call) && s.argsContainTaint(call.Args) {
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
			s.checkMutationDestEscape(sel.X, "secrettaint: 禁止将明文机密写入外层缓冲")
		}
		return
	}
	kind := classifyRule2SinkCall(s.pass.TypesInfo, call)
	if kind == sinkNone {
		return
	}
	for _, arg := range call.Args {
		if s.exprContainsTainted(arg) {
			s.reportLeak(arg, "secrettaint: 禁止将明文机密（及其衍生值）传入%s汇点", kind.label())
		}
	}
}

func (s *taintState) checkMutationDestEscape(dst ast.Expr, msg string) {
	switch d := ast.Unparen(dst).(type) {
	case *ast.CallExpr, *ast.CompositeLit:
		// 诸如 append([]byte(nil), plain...) 或 append(make([]byte, 0), plain...) 属于新建局部切片，本身不逃逸。
		return
	case *ast.Ident:
		if d.Name == "_" {
			return
		}
		v := lookupVar(s.pass.TypesInfo, d)
		if v == nil || !s.isLocalVar(v) || s.resultVars[v] {
			s.reportLeak(dst, "%s", msg)
		}
	default:
		s.reportLeak(dst, "%s", msg)
	}
}

func (s *taintState) checkAssign(stmt *ast.AssignStmt) {
	if len(stmt.Lhs) != len(stmt.Rhs) {
		return
	}
	for i := range stmt.Lhs {
		s.checkAssignPair(stmt.Lhs[i], stmt.Rhs[i])
	}
}

func (s *taintState) checkValueSpec(vs *ast.ValueSpec) {
	if len(vs.Names) != len(vs.Values) {
		return
	}
	for i := range vs.Names {
		s.checkAssignPair(vs.Names[i], vs.Values[i])
	}
}

func (s *taintState) checkAssignPair(lhs, rhs ast.Expr) {
	if !s.exprContainsTainted(rhs) {
		return
	}
	switch target := ast.Unparen(lhs).(type) {
	case *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr:
		s.reportLeak(rhs, "secrettaint: 禁止将明文机密写入结构体字段、容器元素或指针目标")
	case *ast.Ident:
		if target.Name == "_" {
			return
		}
		v := lookupVar(s.pass.TypesInfo, target)
		if v == nil || !s.isLocalVar(v) || s.resultVars[v] {
			s.reportLeak(rhs, "secrettaint: 禁止将明文机密逃逸至外层变量或具名返回值")
		}
	}
}

func (s *taintState) checkCompositeLit(lit *ast.CompositeLit) {
	if isByteSliceType(s.pass.TypesInfo.TypeOf(lit)) {
		return
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if s.exprContainsTainted(kv.Key) || s.exprContainsTainted(kv.Value) {
				s.reportLeak(kv.Value, "secrettaint: 禁止将明文机密存入结构体或非字节切片容器字面量")
			}
			continue
		}
		if s.exprContainsTainted(elt) {
			s.reportLeak(elt, "secrettaint: 禁止将明文机密存入结构体或非字节切片容器字面量")
		}
	}
}

func (s *taintState) funcLitCapturesTaint(lit *ast.FuncLit) bool {
	if lit == nil || lit.Body == nil {
		return false
	}
	found := false
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		if call, ok := n.(*ast.CallExpr); ok && isExemptBuiltinCall(s.pass.TypesInfo, call) {
			return false
		}
		if id, ok := n.(*ast.Ident); ok {
			if v, ok := s.pass.TypesInfo.Uses[id].(*types.Var); ok && v != nil && s.tainted[v] {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func (s *taintState) exprContainsTainted(expr ast.Expr) bool {
	if s.exprIsTainted(expr) {
		return true
	}
	lit, ok := ast.Unparen(expr).(*ast.CompositeLit)
	if !ok {
		return false
	}
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			if s.exprContainsTainted(kv.Key) || s.exprContainsTainted(kv.Value) {
				return true
			}
			continue
		}
		if s.exprContainsTainted(elt) {
			return true
		}
	}
	return false
}

func (s *taintState) exprIsTainted(expr ast.Expr) bool {
	if expr == nil {
		return false
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		v, ok := s.pass.TypesInfo.Uses[e].(*types.Var)
		return ok && v != nil && s.tainted[v]
	case *ast.SliceExpr:
		return s.exprIsTainted(e.X)
	case *ast.IndexExpr:
		return s.exprIsTainted(e.X)
	case *ast.UnaryExpr, *ast.StarExpr, *ast.TypeAssertExpr:
		return s.exprIsTainted(unwrapInnerExpr(e))
	case *ast.BinaryExpr:
		return e.Op == token.ADD && (s.exprIsTainted(e.X) || s.exprIsTainted(e.Y))
	case *ast.CallExpr:
		return s.callResultIsTainted(e)
	default:
		return false
	}
}

func unwrapInnerExpr(expr ast.Expr) ast.Expr {
	switch e := expr.(type) {
	case *ast.UnaryExpr:
		return e.X
	case *ast.StarExpr:
		return e.X
	case *ast.TypeAssertExpr:
		return e.X
	default:
		return nil
	}
}

func (s *taintState) callResultIsTainted(call *ast.CallExpr) bool {
	if isExemptBuiltinCall(s.pass.TypesInfo, call) || isExemptPredicateCall(s.pass.TypesInfo, call) {
		return false
	}
	if isAllowedAuthOrCryptoConsumer(s.pass.TypesInfo, call) && !isSecretCarrierType(s.pass.TypesInfo.TypeOf(call)) {
		return false
	}
	if len(call.Args) == 1 {
		if tv, ok := s.pass.TypesInfo.Types[call.Fun]; ok && tv.IsType() {
			return s.exprIsTainted(call.Args[0])
		}
	}
	if isAppendBuiltin(s.pass.TypesInfo, call) {
		return s.argsContainTaint(call.Args)
	}
	if isTaintPropagatingCall(s.pass.TypesInfo, call) {
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok && s.exprIsTainted(sel.X) {
			return true
		}
		return s.argsContainTaint(call.Args)
	}
	return false
}

func (s *taintState) argsContainTaint(args []ast.Expr) bool {
	for _, arg := range args {
		if s.exprContainsTainted(arg) {
			return true
		}
	}
	return false
}

func (s *taintState) isLocalVar(v *types.Var) bool {
	if v == nil || v.IsField() {
		return false
	}
	for cur := v.Parent(); cur != nil; cur = cur.Parent() {
		if cur == s.ownerScope {
			return true
		}
	}
	return false
}

func (s *taintState) reportLeak(rng ast.Node, format string, args ...any) {
	if rng == nil || s.reported[rng.Pos()] {
		return
	}
	s.reported[rng.Pos()] = true
	s.pass.ReportRangef(rng, format, args...)
}

func lookupVar(info *types.Info, id *ast.Ident) *types.Var {
	if v, ok := info.Defs[id].(*types.Var); ok && v != nil {
		return v
	}
	if v, ok := info.Uses[id].(*types.Var); ok && v != nil {
		return v
	}
	return nil
}

func isCopyBuiltin(info *types.Info, call *ast.CallExpr) bool {
	return isBuiltinNamed(info, call, "copy")
}

func isAppendBuiltin(info *types.Info, call *ast.CallExpr) bool {
	return isBuiltinNamed(info, call, "append")
}

func isBuiltinNamed(info *types.Info, call *ast.CallExpr, name string) bool {
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok || id.Name != name {
		return false
	}
	b, ok := info.Uses[id].(*types.Builtin)
	return ok && b != nil && b.Name() == name
}

func isByteSliceType(t types.Type) bool {
	if t == nil {
		return false
	}
	sl, ok := types.Unalias(t).Underlying().(*types.Slice)
	if !ok {
		return false
	}
	elem, ok := types.Unalias(sl.Elem()).Underlying().(*types.Basic)
	return ok && (elem.Kind() == types.Byte || elem.Kind() == types.Uint8)
}
