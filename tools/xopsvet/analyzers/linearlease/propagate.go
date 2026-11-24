package linearlease

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"
)

func (s *closureState) propagateNode(n ast.Node) bool {
	switch stmt := n.(type) {
	case *ast.AssignStmt:
		return s.propagateAssign(stmt)
	case *ast.ValueSpec:
		return s.propagateValueSpec(stmt)
	case *ast.RangeStmt:
		return s.propagateRange(stmt)
	case *ast.TypeSwitchStmt:
		return s.propagateTypeSwitch(stmt)
	case *ast.CallExpr:
		return s.propagateCall(stmt)
	default:
		return false
	}
}

func (s *closureState) propagateAssign(stmt *ast.AssignStmt) bool {
	if stmt.Tok != token.ASSIGN && stmt.Tok != token.DEFINE {
		return false
	}
	if len(stmt.Lhs) == 2 && len(stmt.Rhs) == 1 {
		if ta, ok := ast.Unparen(stmt.Rhs[0]).(*ast.TypeAssertExpr); ok {
			return s.propagateSinglePair(stmt.Lhs[0], ta.X)
		}
	}
	if len(stmt.Lhs) != len(stmt.Rhs) {
		return false
	}
	changed := false
	for i := range stmt.Lhs {
		if s.propagateSinglePair(stmt.Lhs[i], stmt.Rhs[i]) {
			changed = true
		}
	}
	return changed
}

func (s *closureState) propagateValueSpec(vs *ast.ValueSpec) bool {
	if len(vs.Names) != len(vs.Values) {
		return false
	}
	changed := false
	for i := range vs.Names {
		if s.propagateSinglePair(vs.Names[i], vs.Values[i]) {
			changed = true
		}
	}
	return changed
}

func (s *closureState) propagateSinglePair(lhs, rhs ast.Expr) bool {
	lhsVar := s.lhsIdentVar(lhs)
	if lhsVar == nil {
		return false
	}
	changed := false
	for _, lit := range s.resolveArgFuncLits(rhs) {
		if s.recordLocalFuncLit(lhsVar, lit) {
			changed = true
		}
	}
	if rhsScope, ok := s.exprBorrowedScope(rhs); ok {
		if s.addBorrowedVar(lhsVar, rhsScope) {
			changed = true
		}
	}
	if info, ok := s.exprTaintedClosure(rhs); ok {
		if s.addTaintedClosureVar(lhsVar, info) {
			changed = true
		}
	}
	return changed
}

// recordLocalFuncLit 单调追加局部函数变量对应的 FuncLit（防止条件重赋值震荡）并传播捕获污点。
func (s *closureState) recordLocalFuncLit(lhsVar *types.Var, lit *ast.FuncLit) bool {
	if !isLocalFunctionVar(lhsVar, s.pass.Pkg) || lit == nil {
		return false
	}
	changed := false
	if !slices.Contains(s.localFuncLits[lhsVar], lit) {
		s.localFuncLits[lhsVar] = append(s.localFuncLits[lhsVar], lit)
		changed = true
	}
	capScope := s.capturedBorrowedScope(lit)
	if capScope == nil {
		return changed
	}
	if s.addTaintedClosureVar(lhsVar, taintedClosureInfo{lit: lit, ownerScope: capScope}) {
		changed = true
	}
	return changed
}

func isLocalFunctionVar(v *types.Var, pkg *types.Package) bool {
	if v == nil || v.IsField() {
		return false
	}
	if pkg != nil && v.Parent() == pkg.Scope() {
		return false
	}
	return true
}

func (s *closureState) addBorrowedVar(v *types.Var, scope *types.Scope) bool {
	if v == nil || !isDeclaredWithinScope(v, scope) || s.resultVars[v] {
		return false
	}
	if _, exists := s.borrowed[v]; exists {
		return false
	}
	s.borrowed[v] = scope
	return true
}

func (s *closureState) addTaintedClosureVar(v *types.Var, info taintedClosureInfo) bool {
	if v == nil || !isDeclaredWithinScope(v, info.ownerScope) || s.resultVars[v] {
		return false
	}
	if _, exists := s.taintedClosures[v]; exists {
		return false
	}
	s.taintedClosures[v] = info
	return true
}

// propagateRange 沿 range 语句传播借用集合元素、污点闭包集合以及局部 FuncLit 集合至循环变量。
func (s *closureState) propagateRange(stmt *ast.RangeStmt) bool {
	changed := false
	if scope, ok := s.exprBorrowedScope(stmt.X); ok {
		changed = s.propagateBorrowedRange(stmt, scope)
	}
	if info, ok := s.exprTaintedClosure(stmt.X); ok {
		if s.propagateClosureRange(stmt, info) {
			changed = true
		}
	}
	if lits := s.resolveArgFuncLits(stmt.X); len(lits) > 0 {
		if s.propagateFuncLitRange(stmt, lits) {
			changed = true
		}
	}
	return changed
}

func (s *closureState) propagateBorrowedRange(stmt *ast.RangeStmt, scope *types.Scope) bool {
	changed := false
	xType := s.pass.TypesInfo.TypeOf(stmt.X)
	if keyType := rangeKeyType(xType); keyType != nil && !isBasicScalarType(keyType) {
		if s.addBorrowedVar(s.lhsIdentVar(stmt.Key), scope) {
			changed = true
		}
	}
	if elemType := rangeElemType(xType); elemType != nil && !isBasicScalarType(elemType) {
		if s.addBorrowedVar(s.lhsIdentVar(stmt.Value), scope) {
			changed = true
		}
	}
	return changed
}

// propagateClosureRange 将变参或切片闭包集合的捕获污点传播至 range 循环元素变量。
func (s *closureState) propagateClosureRange(stmt *ast.RangeStmt, info taintedClosureInfo) bool {
	elemType := rangeElemType(s.pass.TypesInfo.TypeOf(stmt.X))
	if elemType == nil || isBasicScalarType(elemType) {
		return false
	}
	return s.addTaintedClosureVar(s.lhsIdentVar(stmt.Value), info)
}

// propagateFuncLitRange 将变参或切片闭包集合指向的局部 FuncLit 列表传播至 range 循环元素变量，
// 以便后续同步调用循环元素（如 `c()`）时能进入对应闭包体校验而不误报。
func (s *closureState) propagateFuncLitRange(stmt *ast.RangeStmt, lits []*ast.FuncLit) bool {
	elemType := rangeElemType(s.pass.TypesInfo.TypeOf(stmt.X))
	if elemType == nil || isBasicScalarType(elemType) {
		return false
	}
	valVar := s.lhsIdentVar(stmt.Value)
	if valVar == nil {
		return false
	}
	changed := false
	for _, lit := range lits {
		if s.recordLocalFuncLit(valVar, lit) {
			changed = true
		}
	}
	return changed
}

func (s *closureState) propagateCall(call *ast.CallExpr) bool {
	if !s.isBuiltinCall(call, "copy") || len(call.Args) != 2 {
		return false
	}
	scope, ok := s.exprBorrowedScope(call.Args[1])
	if !ok {
		return false
	}
	id, ok := unwrapMutationBase(s.pass.TypesInfo, call.Args[0]).(*ast.Ident)
	if !ok || id.Name == "_" {
		return false
	}
	return s.addBorrowedVar(s.lhsIdentVar(id), scope)
}

// unwrapMutationBase 剥离切片表达式与非 map 索引表达式，定位 copy 目标的底层容器变量。
func unwrapMutationBase(info *types.Info, expr ast.Expr) ast.Expr {
	for expr != nil {
		switch e := ast.Unparen(expr).(type) {
		case *ast.SliceExpr:
			expr = e.X
		case *ast.IndexExpr:
			if info != nil && isMapType(info.TypeOf(e.X)) {
				return e
			}
			expr = e.X
		default:
			return e
		}
	}
	return nil
}

func isMapType(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := types.Unalias(t).Underlying().(*types.Map)
	return ok
}

func (s *closureState) propagateTypeSwitch(ts *ast.TypeSwitchStmt) bool {
	asgn, ok := ts.Assign.(*ast.AssignStmt)
	if !ok || len(asgn.Rhs) != 1 {
		return false
	}
	ta, ok := ast.Unparen(asgn.Rhs[0]).(*ast.TypeAssertExpr)
	if !ok {
		return false
	}
	scope, ok := s.exprBorrowedScope(ta.X)
	if !ok {
		return false
	}
	changed := len(asgn.Lhs) == 1 && s.addBorrowedVar(s.lhsIdentVar(asgn.Lhs[0]), scope)
	return s.propagateTypeSwitchCases(ts.Body, scope) || changed
}

func (s *closureState) propagateTypeSwitchCases(body *ast.BlockStmt, scope *types.Scope) bool {
	if body == nil {
		return false
	}
	changed := false
	for _, stmt := range body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		if v, ok := s.pass.TypesInfo.Implicits[cc].(*types.Var); ok && s.addBorrowedVar(v, scope) {
			changed = true
		}
	}
	return changed
}

func (s *closureState) lhsIdentVar(expr ast.Expr) *types.Var {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok || id.Name == "_" {
		return nil
	}
	if v, ok := s.pass.TypesInfo.Defs[id].(*types.Var); ok && v != nil {
		return v
	}
	if v, ok := s.pass.TypesInfo.Uses[id].(*types.Var); ok && v != nil {
		return v
	}
	return nil
}

func (s *closureState) capturedBorrowedScope(lit *ast.FuncLit) *types.Scope {
	if lit == nil || lit.Body == nil {
		return nil
	}
	var litScope *types.Scope
	if lit.Type != nil {
		litScope = s.pass.TypesInfo.Scopes[lit.Type]
	}
	var deepest *types.Scope
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		v, ok := s.pass.TypesInfo.Uses[id].(*types.Var)
		if !ok || v == nil {
			return true
		}
		// 仅追踪捕获自外层作用域的借用变量；闭包自身形参或局部变量不算跨闭包捕获。
		if litScope != nil && isDeclaredWithinScope(v, litScope) {
			return true
		}
		if sc, exists := s.borrowed[v]; exists {
			deepest = pickInnermostScope(deepest, sc)
		}
		if tc, exists := s.taintedClosures[v]; exists {
			deepest = pickInnermostScope(deepest, tc.ownerScope)
		}
		return true
	})
	return deepest
}

func pickInnermostScope(a, b *types.Scope) *types.Scope {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if isChildScope(b, a) {
		return b
	}
	return a
}

func isChildScope(child, ancestor *types.Scope) bool {
	for cur := child; cur != nil; cur = cur.Parent() {
		if cur == ancestor {
			return true
		}
	}
	return false
}
