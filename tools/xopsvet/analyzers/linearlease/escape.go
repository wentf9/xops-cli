package linearlease

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

type taintedClosureInfo struct {
	lit        *ast.FuncLit
	ownerScope *types.Scope
}

type closureState struct {
	pass            *analysis.Pass
	facts           *factIndex
	borrowed        map[*types.Var]*types.Scope
	resultVars      map[*types.Var]bool
	localFuncLits   map[*types.Var]*ast.FuncLit
	taintedClosures map[*types.Var]taintedClosureInfo
	syncLits        map[*ast.FuncLit][]int
	deferCalls      map[*ast.CallExpr]bool
	goCalls         map[*ast.CallExpr]bool
	visitedLits     map[*ast.FuncLit]bool
	reported        map[token.Pos]bool
}

func analyzePackageFunctions(pass *analysis.Pass, facts *factIndex) {
	visitedLits := make(map[*ast.FuncLit]bool)
	reported := make(map[token.Pos]bool)

	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			analyzeFuncDecl(pass, facts, fn, visitedLits, reported)
		}
	}
	analyzeRemainingFuncLits(pass, facts, visitedLits, reported)
}

func analyzeFuncDecl(
	pass *analysis.Pass,
	facts *factIndex,
	fn *ast.FuncDecl,
	visitedLits map[*ast.FuncLit]bool,
	reported map[token.Pos]bool,
) {
	st := newClosureState(pass, facts, visitedLits, reported)
	fnObj, _ := pass.TypesInfo.Defs[fn.Name].(*types.Func)
	if fnObj != nil {
		if direct := facts.directParams[fnObj]; len(direct) > 0 {
			st.seedParamsFromFuncType(fn.Type, direct)
			st.collectResultVars(fn.Type)
		}
	}
	st.analyzeSyncTree(fn.Body)
}

func analyzeRemainingFuncLits(
	pass *analysis.Pass,
	facts *factIndex,
	visitedLits map[*ast.FuncLit]bool,
	reported map[token.Pos]bool,
) {
	ins := vetutil.InspectorOf(pass)
	ins.Preorder([]ast.Node{(*ast.FuncLit)(nil)}, func(n ast.Node) {
		lit, ok := n.(*ast.FuncLit)
		if !ok || lit.Body == nil || visitedLits[lit] {
			return
		}
		st := newClosureState(pass, facts, visitedLits, reported)
		comments := facts.commentsFor(pass.Fset, lit.Pos())
		explicit := collectExplicitParamIndices(pass.Fset, comments, lit.Type.Params, vetutil.DirectiveBorrowed)
		if len(explicit) > 0 {
			st.seedParamsFromFuncType(lit.Type, explicit)
			st.collectResultVars(lit.Type)
		}
		visitedLits[lit] = true
		st.analyzeSyncTree(lit.Body)
	})
}

func newClosureState(
	pass *analysis.Pass,
	facts *factIndex,
	visitedLits map[*ast.FuncLit]bool,
	reported map[token.Pos]bool,
) *closureState {
	return &closureState{
		pass:            pass,
		facts:           facts,
		borrowed:        make(map[*types.Var]*types.Scope),
		resultVars:      make(map[*types.Var]bool),
		localFuncLits:   make(map[*types.Var]*ast.FuncLit),
		taintedClosures: make(map[*types.Var]taintedClosureInfo),
		syncLits:        make(map[*ast.FuncLit][]int),
		deferCalls:      make(map[*ast.CallExpr]bool),
		goCalls:         make(map[*ast.CallExpr]bool),
		visitedLits:     visitedLits,
		reported:        reported,
	}
}

func (s *closureState) seedParamsFromFuncType(ft *ast.FuncType, indices []int) {
	if ft == nil || ft.Params == nil || len(indices) == 0 {
		return
	}
	ownerScope := s.pass.TypesInfo.Scopes[ft]
	if ownerScope == nil {
		return
	}
	vars := flattenFieldVars(s.pass.TypesInfo, ft.Params)
	for _, idx := range indices {
		if idx >= 0 && idx < len(vars) && vars[idx] != nil {
			s.borrowed[vars[idx]] = ownerScope
		}
	}
}

func (s *closureState) collectResultVars(ft *ast.FuncType) {
	if ft == nil || ft.Results == nil {
		return
	}
	for _, v := range flattenFieldVars(s.pass.TypesInfo, ft.Results) {
		if v != nil {
			s.resultVars[v] = true
		}
	}
}

func flattenFieldVars(info *types.Info, fl *ast.FieldList) []*types.Var {
	if fl == nil {
		return nil
	}
	var vars []*types.Var
	for _, f := range fl.List {
		if len(f.Names) == 0 {
			vars = append(vars, nil)
			continue
		}
		for _, id := range f.Names {
			v, _ := info.Defs[id].(*types.Var)
			vars = append(vars, v)
		}
	}
	return vars
}

func (s *closureState) analyzeSyncTree(root *ast.BlockStmt) {
	s.collectSpecialCalls(root)
	// 最多执行 4 轮不动点迭代，覆盖同步嵌套、局部变量别名、类型断言与本地闭包传播。
	for range 4 {
		changed := false
		s.walkSyncBody(root, func(n ast.Node) {
			if s.propagateNode(n) {
				changed = true
			}
		})
		if !changed {
			break
		}
	}
	if len(s.borrowed) == 0 && len(s.taintedClosures) == 0 {
		return
	}
	s.walkSyncBody(root, func(n ast.Node) {
		s.checkEscapeNode(n)
	})
}

func (s *closureState) collectSpecialCalls(root *ast.BlockStmt) {
	ast.Inspect(root, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.DeferStmt:
			if stmt.Call != nil {
				s.deferCalls[stmt.Call] = true
			}
		case *ast.GoStmt:
			if stmt.Call != nil {
				s.goCalls[stmt.Call] = true
			}
		}
		return true
	})
}

// walkSyncBody 遍历同步块内节点，不直接穿透非同步 FuncLit；
// 仅当 FuncLit 作为同步调用实参/IIFE/defer 或已标记同步的本地闭包变量被调用时才显式进入。
// seenInWalk 防止局部递归闭包（如 fn = func() { fn() }）导致无限递归。
func (s *closureState) walkSyncBody(body *ast.BlockStmt, visit func(ast.Node)) {
	s.walkSyncBodySeen(body, make(map[*ast.BlockStmt]bool), visit)
}

func (s *closureState) walkSyncBodySeen(body *ast.BlockStmt, seenInWalk map[*ast.BlockStmt]bool, visit func(ast.Node)) {
	if body == nil || seenInWalk[body] {
		return
	}
	seenInWalk[body] = true
	var enterQueue []*ast.FuncLit
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		visit(n)
		if call, ok := n.(*ast.CallExpr); ok {
			enterQueue = append(enterQueue, s.discoverSyncCallLits(call)...)
		}
		return true
	})
	for _, lit := range enterQueue {
		s.visitedLits[lit] = true
		if indices := s.syncLits[lit]; len(indices) > 0 {
			s.seedParamsFromFuncType(lit.Type, indices)
		}
		s.collectResultVars(lit.Type)
		s.walkSyncBodySeen(lit.Body, seenInWalk, visit)
	}
}

func (s *closureState) discoverSyncCallLits(call *ast.CallExpr) []*ast.FuncLit {
	if s.goCalls[call] {
		return nil
	}
	spec := resolveCallLeaseSpec(s.pass, s.facts, call, s.deferCalls[call])
	var lits []*ast.FuncLit
	if funLit, ok := ast.Unparen(call.Fun).(*ast.FuncLit); ok {
		lits = append(lits, funLit)
		return lits
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok {
		if v, ok := s.pass.TypesInfo.Uses[id].(*types.Var); ok {
			if lit := s.localFuncLits[v]; lit != nil {
				lits = append(lits, lit)
			}
		}
	}
	if !spec.syncClosure {
		return lits
	}
	for i, arg := range call.Args {
		lit := s.resolveArgFuncLit(arg)
		if lit == nil {
			continue
		}
		if indices := spec.callbackBorrowed[i]; len(indices) > 0 {
			s.syncLits[lit] = mergeIntSlices(s.syncLits[lit], indices)
		}
		lits = append(lits, lit)
	}
	return lits
}

func (s *closureState) resolveArgFuncLit(arg ast.Expr) *ast.FuncLit {
	e := ast.Unparen(arg)
	if lit, ok := e.(*ast.FuncLit); ok {
		return lit
	}
	if id, ok := e.(*ast.Ident); ok {
		if v, ok := s.pass.TypesInfo.Uses[id].(*types.Var); ok {
			return s.localFuncLits[v]
		}
	}
	return nil
}

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
	if lit, ok := ast.Unparen(rhs).(*ast.FuncLit); ok {
		return s.recordLocalFuncLit(lhsVar, lit)
	}
	if rhsScope, ok := s.exprBorrowedScope(rhs); ok {
		return s.addBorrowedVar(lhsVar, rhsScope)
	}
	if info, ok := s.exprTaintedClosure(rhs); ok {
		return s.addTaintedClosureVar(lhsVar, info)
	}
	return false
}

func (s *closureState) recordLocalFuncLit(lhsVar *types.Var, lit *ast.FuncLit) bool {
	changed := false
	if s.localFuncLits[lhsVar] != lit {
		s.localFuncLits[lhsVar] = lit
		changed = true
	}
	capScope := s.capturedBorrowedScope(lit)
	if capScope == nil {
		return changed
	}
	if _, exists := s.taintedClosures[lhsVar]; !exists {
		s.taintedClosures[lhsVar] = taintedClosureInfo{lit: lit, ownerScope: capScope}
		changed = true
	}
	return changed
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

func (s *closureState) propagateRange(stmt *ast.RangeStmt) bool {
	scope, ok := s.exprBorrowedScope(stmt.X)
	if !ok {
		return false
	}
	if elemType := rangeElemType(s.pass.TypesInfo.TypeOf(stmt.X)); isBasicScalarType(elemType) {
		return false
	}
	valVar := s.lhsIdentVar(stmt.Value)
	if valVar == nil || !isDeclaredWithinScope(valVar, scope) || s.resultVars[valVar] {
		return false
	}
	if _, exists := s.borrowed[valVar]; exists {
		return false
	}
	s.borrowed[valVar] = scope
	return true
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
