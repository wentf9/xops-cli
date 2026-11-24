package secrettaint

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
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
	if s.checkSpecialCallLeak(call) {
		return
	}
	kind := classifyRule2SinkCall(s.pass.TypesInfo, call)
	if kind == sinkNone {
		s.checkCallArgTaintRecursion(call)
		return
	}
	for _, arg := range call.Args {
		if s.exprContainsTainted(arg) {
			s.reportLeak(arg, "secrettaint: 禁止将明文机密（及其衍生值）传入%s汇点", kind.label())
		}
	}
}

func (s *taintState) checkSpecialCallLeak(call *ast.CallExpr) bool {
	if isCopyBuiltin(s.pass.TypesInfo, call) && len(call.Args) == 2 && s.exprIsTainted(call.Args[1]) {
		s.checkMutationDestEscape(call.Args[0], "secrettaint: 禁止通过 copy 将明文机密写入外层变量或字段")
		return true
	}
	if isAppendBuiltin(s.pass.TypesInfo, call) && len(call.Args) >= 2 && s.argsContainTaint(call.Args[1:]) {
		s.checkMutationDestEscape(call.Args[0], "secrettaint: 禁止通过 append 将明文机密写入外层变量或字段")
		return true
	}
	if isFmtAppendCall(s.pass.TypesInfo, call) && len(call.Args) >= 2 && s.argsContainTaint(call.Args[1:]) {
		s.checkMutationDestEscape(call.Args[0], "secrettaint: 禁止通过 fmt.Append 将明文机密写入外层变量或字段")
		return true
	}
	if isIOCopyCall(s.pass.TypesInfo, call) && len(call.Args) >= 2 && s.exprIsTainted(call.Args[1]) {
		s.checkMutationDestEscape(call.Args[0], "secrettaint: 禁止通过 io.Copy 将明文机密写入外层缓冲或写入器")
		if isIOCopyBufferCall(s.pass.TypesInfo, call) && len(call.Args) >= 3 {
			s.checkMutationDestEscape(call.Args[2], "secrettaint: 禁止通过 io.CopyBuffer 将明文机密写入外层缓冲或切片")
		}
		return true
	}
	return s.checkBufferMethodLeak(call)
}

func (s *taintState) checkBufferMethodLeak(call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if isBufferOrBuilderWriteMethod(s.pass.TypesInfo, call) {
		if s.argsContainTaint(call.Args) {
			s.checkMutationDestEscape(sel.X, "secrettaint: 禁止将明文机密写入外层缓冲")
		}
		return true
	}
	if isBufferOrReaderWriteToMethod(s.pass.TypesInfo, call) {
		if s.exprIsTainted(sel.X) {
			s.reportLeak(call, "secrettaint: 禁止通过 WriteTo 导出明文缓冲或读取器内容")
		}
		return true
	}
	if isBufferOrReaderReadIntoMethod(s.pass.TypesInfo, call) && len(call.Args) >= 1 {
		if s.exprIsTainted(sel.X) {
			s.checkMutationDestEscape(call.Args[0], "secrettaint: 禁止通过 Read 将明文机密写入外层变量或字段")
		}
		return true
	}
	return s.checkBufferReadFromLeak(call, sel)
}

func (s *taintState) checkBufferReadFromLeak(call *ast.CallExpr, sel *ast.SelectorExpr) bool {
	if isBufferReadFromMethod(s.pass.TypesInfo, call) && len(call.Args) >= 1 {
		if s.exprIsTainted(call.Args[0]) {
			s.checkMutationDestEscape(sel.X, "secrettaint: 禁止通过 ReadFrom 将明文机密写入外层缓冲")
		}
		return true
	}
	return false
}

// checkMutationDestEscape 检查 copy/append/io.Copy/Buffer.Write 等写入目标是否逃逸出局部作用域。
// 仅在剥离取址与索引之前放行干净的一维字节切片字面量，剥离后仅放行 vetutil.IsFreshLocalSliceAlloc
// 认定的全新局部切片分配，堵死 &wrapWriter{...}、[][]byte{outer}[0]、getOuterSlice() 与 MyBytes(outer) 绕过。
func (s *taintState) checkMutationDestEscape(dst ast.Expr, msg string) {
	if lit, ok := ast.Unparen(dst).(*ast.CompositeLit); ok {
		if isByteSliceType(s.pass.TypesInfo.TypeOf(lit)) && !s.exprContainsTainted(lit) {
			return
		}
		s.reportLeak(dst, "%s", msg)
		return
	}
	switch d := unwrapSliceBaseExpr(s.pass.TypesInfo, dst).(type) {
	case *ast.CallExpr:
		if vetutil.IsFreshLocalSliceAlloc(s.pass.TypesInfo, d) {
			return
		}
		s.reportLeak(dst, "%s", msg)
	case *ast.Ident:
		if d.Name == "_" || isNilIdent(s.pass.TypesInfo, d) {
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

func isNilIdent(info *types.Info, id *ast.Ident) bool {
	if info == nil || id == nil || id.Name != "nil" {
		return false
	}
	_, ok := info.Uses[id].(*types.Nil)
	return ok
}

func (s *taintState) checkAssign(stmt *ast.AssignStmt) {
	if len(stmt.Lhs) >= 2 && len(stmt.Rhs) == 1 {
		if rhs, ok := unwrapMultiReturnRHS(stmt.Rhs[0]); ok {
			s.checkAssignPair(stmt.Lhs[0], rhs)
		}
		return
	}
	if len(stmt.Lhs) != len(stmt.Rhs) {
		return
	}
	for i := range stmt.Lhs {
		s.checkAssignPair(stmt.Lhs[i], stmt.Rhs[i])
	}
}

func (s *taintState) checkValueSpec(vs *ast.ValueSpec) {
	if len(vs.Names) >= 2 && len(vs.Values) == 1 {
		if rhs, ok := unwrapMultiReturnRHS(vs.Values[0]); ok {
			s.checkAssignPair(vs.Names[0], rhs)
		}
		return
	}
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
