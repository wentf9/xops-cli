package linearlease

import (
	"go/ast"
	"go/token"
	"go/types"
)

func (s *closureState) checkEscapeNode(n ast.Node) {
	switch node := n.(type) {
	case *ast.AssignStmt:
		s.checkAssignEscape(node)
	case *ast.ValueSpec:
		s.checkValueSpecEscape(node)
	case *ast.RangeStmt:
		s.checkRangeEscape(node)
	case *ast.CompositeLit:
		s.checkCompositeLitEscape(node)
	case *ast.CallExpr:
		s.checkCallEscape(node)
	case *ast.SendStmt:
		s.checkSendEscape(node)
	case *ast.ReturnStmt:
		s.checkReturnEscape(node)
	case *ast.GoStmt:
		s.checkGoStmtEscape(node)
	}
}

func (s *closureState) checkAssignEscape(stmt *ast.AssignStmt) {
	if len(stmt.Lhs) == 2 && len(stmt.Rhs) == 1 {
		if ta, ok := ast.Unparen(stmt.Rhs[0]).(*ast.TypeAssertExpr); ok {
			s.checkAssignPairEscape(stmt.Lhs[0], ta.X)
			return
		}
	}
	if len(stmt.Lhs) == 1 && len(stmt.Rhs) == 1 {
		if ta, ok := ast.Unparen(stmt.Rhs[0]).(*ast.TypeAssertExpr); ok && ta.Type == nil {
			// 跳过 switch v := x.(type) 头部伪赋值，逃逸检查由各 case 的 Implicit 变量承担。
			return
		}
	}
	if len(stmt.Lhs) != len(stmt.Rhs) {
		return
	}
	for i := range stmt.Lhs {
		s.checkAssignPairEscape(stmt.Lhs[i], stmt.Rhs[i])
	}
}

func (s *closureState) checkValueSpecEscape(vs *ast.ValueSpec) {
	if len(vs.Names) != len(vs.Values) {
		return
	}
	for i := range vs.Names {
		s.checkAssignPairEscape(vs.Names[i], vs.Values[i])
	}
}

func (s *closureState) checkAssignPairEscape(lhs, rhs ast.Expr) {
	if s.checkUncalledMethodValue(rhs) {
		return
	}
	targetScope, isBorrowed := s.exprBorrowedScope(rhs)
	if !isBorrowed {
		if lit, ok := ast.Unparen(rhs).(*ast.FuncLit); ok {
			s.checkDirectClosureAssign(lhs, lit)
			return
		}
		tainted, isClosure := s.exprTaintedClosure(rhs)
		if !isClosure {
			return
		}
		targetScope = tainted.ownerScope
	}
	s.checkTargetScopeEscape(lhs, rhs, targetScope)
}

func (s *closureState) checkTargetScopeEscape(lhs, rhs ast.Expr, targetScope *types.Scope) {
	switch target := ast.Unparen(lhs).(type) {
	case *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr:
		s.reportEscape(rhs, "linearlease: 禁止将 //xops:borrowed 借用变量写入结构体字段、容器元素或指针目标")
	case *ast.Ident:
		if target.Name == "_" {
			return
		}
		lhsVar := s.lhsIdentVar(target)
		if lhsVar == nil || !isDeclaredWithinScope(lhsVar, targetScope) || s.resultVars[lhsVar] {
			s.reportEscape(rhs, "linearlease: 禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值")
		}
	}
}

func (s *closureState) checkRangeEscape(stmt *ast.RangeStmt) {
	scope, ok := s.exprBorrowedScope(stmt.X)
	if !ok {
		return
	}
	xType := s.pass.TypesInfo.TypeOf(stmt.X)
	if stmt.Key != nil {
		if keyType := rangeKeyType(xType); keyType != nil && !isBasicScalarType(keyType) {
			s.checkTargetScopeEscape(stmt.Key, stmt.X, scope)
		}
	}
	if stmt.Value != nil {
		if elemType := rangeElemType(xType); elemType != nil && !isBasicScalarType(elemType) {
			s.checkTargetScopeEscape(stmt.Value, stmt.X, scope)
		}
	}
}

func (s *closureState) checkDirectClosureAssign(lhs ast.Expr, lit *ast.FuncLit) {
	capScope := s.capturedBorrowedScope(lit)
	if capScope == nil {
		return
	}
	id, ok := ast.Unparen(lhs).(*ast.Ident)
	if !ok {
		s.reportEscape(lit, "linearlease: 禁止将捕获了 //xops:borrowed 变量的闭包写入外部位置")
		return
	}
	if id.Name == "_" {
		return
	}
	lhsVar := s.lhsIdentVar(id)
	if lhsVar == nil || !isDeclaredWithinScope(lhsVar, capScope) || s.resultVars[lhsVar] {
		s.reportEscape(lit, "linearlease: 禁止将捕获了 //xops:borrowed 变量的闭包逃逸至外层作用域")
	}
}

func (s *closureState) checkCompositeLitEscape(lit *ast.CompositeLit) {
	for _, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			s.checkNonEscapingValue(kv.Key, "linearlease: 禁止将 //xops:borrowed 借用变量存入复合字面量")
			s.checkNonEscapingValue(kv.Value, "linearlease: 禁止将 //xops:borrowed 借用变量存入复合字面量")
			continue
		}
		s.checkNonEscapingValue(elt, "linearlease: 禁止将 //xops:borrowed 借用变量存入复合字面量")
	}
}

func (s *closureState) checkCallEscape(call *ast.CallExpr) {
	if s.goCalls[call] || isTypeConversionCall(s.pass.TypesInfo, call) {
		return
	}
	if s.checkBuiltinCallEscape(call) {
		return
	}
	spec := resolveCallLeaseSpec(s.pass, s.facts, call, s.deferCalls[call])
	if len(s.resolveArgFuncLits(call.Fun)) > 0 {
		spec.syncClosure = true
	}
	if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
		if _, isBorrowedRecv := s.exprBorrowedScope(sel.X); !isBorrowedRecv {
			s.checkUncalledMethodValue(sel.X)
		}
	}
	s.checkCallArgsEscape(call, spec)
}

func (s *closureState) checkBuiltinCallEscape(call *ast.CallExpr) bool {
	if s.isBuiltinCall(call, "append") {
		for _, arg := range call.Args[1:] {
			s.checkNonEscapingValue(arg, "linearlease: 禁止通过 append 将 //xops:borrowed 借用变量存入切片")
		}
		return true
	}
	if s.isBuiltinCall(call, "copy") && len(call.Args) == 2 {
		s.checkCopyEscape(call)
		return true
	}
	return false
}

func (s *closureState) checkCallArgsEscape(call *ast.CallExpr, spec callLeaseSpec) {
	for _, arg := range call.Args {
		if s.checkUncalledMethodValue(arg) && !spec.syncClosure {
			continue
		}
		if spec.syncClosure && len(s.resolveArgFuncLits(arg)) > 0 {
			continue
		}
		s.checkCallArgCapture(arg, spec.syncClosure)
	}
}

func (s *closureState) checkCopyEscape(call *ast.CallExpr) {
	scope, ok := s.exprBorrowedScope(call.Args[1])
	if !ok {
		return
	}
	switch target := unwrapMutationBase(s.pass.TypesInfo, call.Args[0]).(type) {
	case *ast.CallExpr:
		return
	case *ast.Ident:
		if target.Name == "_" {
			return
		}
		lhsVar := s.lhsIdentVar(target)
		if lhsVar == nil || !isDeclaredWithinScope(lhsVar, scope) || s.resultVars[lhsVar] {
			s.reportEscape(call.Args[0], "linearlease: 禁止通过 copy 将 //xops:borrowed 借用变量逃逸至外层位置")
		}
	default:
		s.reportEscape(call.Args[0], "linearlease: 禁止通过 copy 将 //xops:borrowed 借用变量写入结构体字段、容器元素或指针目标")
	}
}

func (s *closureState) checkCallArgCapture(arg ast.Expr, isSync bool) {
	if isSync {
		return
	}
	if lit, ok := ast.Unparen(arg).(*ast.FuncLit); ok {
		if s.capturedBorrowedScope(lit) != nil {
			s.reportEscape(lit, "linearlease: 禁止在非同步子闭包（如 goroutine 或异步回调）中捕获 //xops:borrowed 变量")
		}
		return
	}
	if _, ok := s.exprTaintedClosure(arg); ok {
		s.reportEscape(arg, "linearlease: 禁止将捕获了 //xops:borrowed 变量的闭包传入非同步调用")
	}
}

func (s *closureState) checkSendEscape(stmt *ast.SendStmt) {
	s.checkNonEscapingValue(stmt.Value, "linearlease: 禁止将 //xops:borrowed 借用变量发送至 channel")
}

func (s *closureState) checkReturnEscape(stmt *ast.ReturnStmt) {
	for _, res := range stmt.Results {
		s.checkNonEscapingValue(res, "linearlease: 禁止通过 return 返回 //xops:borrowed 借用变量")
	}
}

func (s *closureState) checkGoStmtEscape(stmt *ast.GoStmt) {
	if stmt.Call == nil {
		return
	}
	if sel, ok := ast.Unparen(stmt.Call.Fun).(*ast.SelectorExpr); ok {
		s.checkNonEscapingValue(sel.X, "linearlease: 禁止在 go 语句中异步调用 //xops:borrowed 接收者方法")
	} else {
		s.checkNonEscapingValue(stmt.Call.Fun, "linearlease: 禁止在 go 语句中调用捕获了 //xops:borrowed 变量的闭包")
	}
	for _, arg := range stmt.Call.Args {
		s.checkNonEscapingValue(arg, "linearlease: 禁止将 //xops:borrowed 借用变量传入 go 语句")
	}
}

func (s *closureState) checkNonEscapingValue(expr ast.Expr, msg string) {
	if s.checkUncalledMethodValue(expr) {
		return
	}
	if _, ok := s.exprBorrowedScope(expr); ok {
		s.reportEscape(expr, msg)
		return
	}
	if _, ok := s.exprTaintedClosure(expr); ok {
		s.reportEscape(expr, msg)
		return
	}
	if lit, ok := ast.Unparen(expr).(*ast.FuncLit); ok && s.capturedBorrowedScope(lit) != nil {
		s.reportEscape(lit, msg)
	}
}

func (s *closureState) checkUncalledMethodValue(expr ast.Expr) bool {
	sel, ok := unwrapMethodValueExpr(s.pass.TypesInfo, expr)
	if !ok {
		return false
	}
	selection := s.pass.TypesInfo.Selections[sel]
	if selection == nil || selection.Kind() != types.MethodVal {
		return false
	}
	if _, ok := s.exprBorrowedScope(sel.X); !ok {
		return false
	}
	s.reportEscape(sel, "linearlease: 禁止将 //xops:borrowed 接收者的未调用方法值转存或逃逸")
	return true
}

func unwrapMethodValueExpr(info *types.Info, expr ast.Expr) (*ast.SelectorExpr, bool) {
	for expr != nil {
		switch e := ast.Unparen(expr).(type) {
		case *ast.SelectorExpr:
			return e, true
		case *ast.TypeAssertExpr:
			expr = e.X
		case *ast.CallExpr:
			if len(e.Args) == 1 {
				if tv, ok := info.Types[e.Fun]; ok && tv.IsType() {
					expr = e.Args[0]
					continue
				}
			}
			return nil, false
		default:
			return nil, false
		}
	}
	return nil, false
}

func isTypeConversionCall(info *types.Info, call *ast.CallExpr) bool {
	if info == nil || call == nil || len(call.Args) != 1 {
		return false
	}
	tv, ok := info.Types[call.Fun]
	return ok && tv.IsType()
}

func (s *closureState) isBuiltinCall(call *ast.CallExpr, name string) bool {
	id, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok || id.Name != name {
		return false
	}
	b, ok := s.pass.TypesInfo.Uses[id].(*types.Builtin)
	return ok && b != nil && b.Name() == name
}

func (s *closureState) exprTaintedClosure(expr ast.Expr) (taintedClosureInfo, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		v, ok := s.pass.TypesInfo.Uses[e].(*types.Var)
		if !ok || v == nil {
			return taintedClosureInfo{}, false
		}
		info, exists := s.taintedClosures[v]
		return info, exists
	case *ast.FuncLit:
		if capScope := s.capturedBorrowedScope(e); capScope != nil {
			return taintedClosureInfo{lit: e, ownerScope: capScope}, true
		}
		return taintedClosureInfo{}, false
	case *ast.TypeAssertExpr:
		return s.exprTaintedClosure(e.X)
	case *ast.StarExpr:
		return s.exprTaintedClosure(e.X)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return s.exprTaintedClosure(e.X)
		}
		return taintedClosureInfo{}, false
	case *ast.CallExpr:
		return s.conversionTaintedClosure(e)
	default:
		return taintedClosureInfo{}, false
	}
}

func (s *closureState) conversionTaintedClosure(call *ast.CallExpr) (taintedClosureInfo, bool) {
	if len(call.Args) != 1 {
		return taintedClosureInfo{}, false
	}
	tv, ok := s.pass.TypesInfo.Types[call.Fun]
	if !ok || !tv.IsType() {
		return taintedClosureInfo{}, false
	}
	return s.exprTaintedClosure(call.Args[0])
}

func (s *closureState) exprBorrowedScope(expr ast.Expr) (*types.Scope, bool) {
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		v, ok := s.pass.TypesInfo.Uses[e].(*types.Var)
		if !ok || v == nil {
			return nil, false
		}
		sc, exists := s.borrowed[v]
		return sc, exists
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return s.exprBorrowedScope(e.X)
		}
		return nil, false
	case *ast.StarExpr:
		return s.exprBorrowedScope(e.X)
	case *ast.TypeAssertExpr:
		return s.exprBorrowedScope(e.X)
	case *ast.SliceExpr:
		return s.exprBorrowedScope(e.X)
	case *ast.IndexExpr:
		if isBasicScalarType(s.pass.TypesInfo.TypeOf(e)) {
			return nil, false
		}
		return s.exprBorrowedScope(e.X)
	case *ast.CallExpr:
		return s.conversionBorrowedScope(e)
	default:
		return nil, false
	}
}

func (s *closureState) conversionBorrowedScope(call *ast.CallExpr) (*types.Scope, bool) {
	if len(call.Args) != 1 {
		return nil, false
	}
	tv, ok := s.pass.TypesInfo.Types[call.Fun]
	if !ok || !tv.IsType() {
		return nil, false
	}
	return s.exprBorrowedScope(call.Args[0])
}

func rangeKeyType(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Map:
		return u.Key()
	case *types.Chan:
		return u.Elem()
	case *types.Slice, *types.Array:
		return types.Typ[types.Int]
	case *types.Basic:
		if u.Info()&types.IsString != 0 {
			return types.Typ[types.Int]
		}
		return nil
	default:
		return nil
	}
}

func rangeElemType(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	switch u := types.Unalias(t).Underlying().(type) {
	case *types.Slice:
		return u.Elem()
	case *types.Array:
		return u.Elem()
	case *types.Map:
		return u.Elem()
	case *types.Chan:
		return u.Elem()
	case *types.Basic:
		if u.Info()&types.IsString != 0 {
			return types.Typ[types.Rune]
		}
		return nil
	default:
		return nil
	}
}

func isDeclaredWithinScope(v *types.Var, ownerScope *types.Scope) bool {
	if v == nil || ownerScope == nil || v.IsField() {
		return false
	}
	for cur := v.Parent(); cur != nil; cur = cur.Parent() {
		if cur == ownerScope {
			return true
		}
	}
	return false
}

func (s *closureState) reportEscape(rng ast.Node, msg string) {
	if rng == nil || s.reported[rng.Pos()] {
		return
	}
	s.reported[rng.Pos()] = true
	s.pass.ReportRangef(rng, "%s", msg)
}
