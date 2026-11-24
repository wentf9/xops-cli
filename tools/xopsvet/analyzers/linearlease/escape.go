package linearlease

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// maxAliasIters 限制局部借用别名、闭包引用与 range 传播的最大不动点迭代轮次。
const maxAliasIters = 32

type taintedClosureInfo struct {
	lit        *ast.FuncLit
	ownerScope *types.Scope
}

type closureState struct {
	pass            *analysis.Pass
	facts           *factIndex
	borrowed        map[*types.Var]*types.Scope
	resultVars      map[*types.Var]bool
	localFuncLits   map[*types.Var][]*ast.FuncLit
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
		localFuncLits:   make(map[*types.Var][]*ast.FuncLit),
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
	vars, _ := flattenFieldVarsWithVariadic(info, fl)
	return vars
}

func flattenFieldVarsWithVariadic(info *types.Info, fl *ast.FieldList) ([]*types.Var, bool) {
	if fl == nil {
		return nil, false
	}
	var vars []*types.Var
	isVariadic := false
	for i, f := range fl.List {
		if i == len(fl.List)-1 {
			if _, ok := ast.Unparen(f.Type).(*ast.Ellipsis); ok {
				isVariadic = true
			}
		}
		if len(f.Names) == 0 {
			vars = append(vars, nil)
			continue
		}
		for _, id := range f.Names {
			v, _ := info.Defs[id].(*types.Var)
			vars = append(vars, v)
		}
	}
	return vars, isVariadic
}

func (s *closureState) analyzeSyncTree(root *ast.BlockStmt) {
	s.collectSpecialCalls(root)
	// 最多执行 32 轮不动点迭代，覆盖深层变量别名链、本地闭包重赋值、类型断言与 range/copy 传播。
	for range maxAliasIters {
		prevBorrowed := len(s.borrowed)
		prevTainted := len(s.taintedClosures)
		changed := false
		s.walkSyncBody(root, func(n ast.Node) {
			if s.propagateNode(n) {
				changed = true
			}
		})
		if !changed && len(s.borrowed) == prevBorrowed && len(s.taintedClosures) == prevTainted {
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
		s.enterSyncFuncLit(lit, seenInWalk, visit)
	}
}

func (s *closureState) enterSyncFuncLit(lit *ast.FuncLit, seenInWalk map[*ast.BlockStmt]bool, visit func(ast.Node)) {
	s.visitedLits[lit] = true
	if lit.Type != nil {
		comments := s.facts.commentsFor(s.pass.Fset, lit.Pos())
		if explicit := collectExplicitParamIndices(s.pass.Fset, comments, lit.Type.Params, vetutil.DirectiveBorrowed); len(explicit) > 0 {
			s.seedParamsFromFuncType(lit.Type, explicit)
		}
		if indices := s.syncLits[lit]; len(indices) > 0 {
			s.seedParamsFromFuncType(lit.Type, indices)
		}
		s.collectResultVars(lit.Type)
	}
	s.walkSyncBodySeen(lit.Body, seenInWalk, visit)
}

func (s *closureState) discoverSyncCallLits(call *ast.CallExpr) []*ast.FuncLit {
	if s.goCalls[call] {
		return nil
	}
	spec := resolveCallLeaseSpec(s.pass, s.facts, call, s.deferCalls[call])
	funLits := s.resolveArgFuncLits(call.Fun)
	lits := make([]*ast.FuncLit, 0, len(funLits))
	for _, funLit := range funLits {
		s.seedCallArgsToFuncLit(funLit, call.Args)
		lits = append(lits, funLit)
	}
	if len(funLits) > 0 {
		spec.syncClosure = true
	}
	if !spec.syncClosure {
		return lits
	}
	for i, arg := range call.Args {
		lits = s.collectSyncArgLits(arg, spec.callbackBorrowed[i], lits)
	}
	return lits
}

func (s *closureState) collectSyncArgLits(arg ast.Expr, indices []int, dst []*ast.FuncLit) []*ast.FuncLit {
	for _, lit := range s.resolveArgFuncLits(arg) {
		if len(indices) > 0 {
			s.syncLits[lit] = mergeIntSlices(s.syncLits[lit], indices)
		}
		dst = append(dst, lit)
	}
	return dst
}

// seedCallArgsToFuncLit 将直接调用（IIFE 或本地闭包变量）传入的借用实参及污点闭包实参绑定到对应形参。
func (s *closureState) seedCallArgsToFuncLit(lit *ast.FuncLit, args []ast.Expr) {
	if lit == nil || lit.Type == nil || lit.Type.Params == nil || len(args) == 0 {
		return
	}
	litScope := s.pass.TypesInfo.Scopes[lit.Type]
	if litScope == nil {
		return
	}
	paramVars, isVariadic := flattenFieldVarsWithVariadic(s.pass.TypesInfo, lit.Type.Params)
	if len(paramVars) == 0 {
		return
	}
	for i, arg := range args {
		pVar := paramVarAt(paramVars, isVariadic, i)
		if pVar == nil {
			continue
		}
		if argScope, ok := s.exprBorrowedScope(arg); ok {
			targetScope := argScope
			if !isDeclaredWithinScope(pVar, argScope) {
				targetScope = litScope
			}
			s.borrowed[pVar] = targetScope
		}
		s.seedParamClosureArg(pVar, litScope, arg)
	}
}

func (s *closureState) seedParamClosureArg(pVar *types.Var, litScope *types.Scope, arg ast.Expr) {
	if isLocalFunctionVar(pVar, s.pass.Pkg) {
		for _, argLit := range s.resolveArgFuncLits(arg) {
			if argLit != nil && !slices.Contains(s.localFuncLits[pVar], argLit) {
				s.localFuncLits[pVar] = append(s.localFuncLits[pVar], argLit)
			}
		}
	}
	if info, ok := s.exprTaintedClosure(arg); ok {
		targetScope := info.ownerScope
		if !isDeclaredWithinScope(pVar, targetScope) {
			targetScope = litScope
		}
		if _, exists := s.taintedClosures[pVar]; !exists {
			s.taintedClosures[pVar] = taintedClosureInfo{lit: info.lit, ownerScope: targetScope}
		}
	}
}

func paramVarAt(vars []*types.Var, isVariadic bool, idx int) *types.Var {
	if idx < len(vars) {
		return vars[idx]
	}
	if isVariadic && len(vars) > 0 {
		return vars[len(vars)-1]
	}
	return nil
}

// resolveArgFuncLits 剥离括号、类型断言与单参类型转换，解析实参或被调表达式指向的局部 FuncLit 集合。
func (s *closureState) resolveArgFuncLits(expr ast.Expr) []*ast.FuncLit {
	for expr != nil {
		switch e := ast.Unparen(expr).(type) {
		case *ast.FuncLit:
			return []*ast.FuncLit{e}
		case *ast.Ident:
			if v, ok := s.pass.TypesInfo.Uses[e].(*types.Var); ok && v != nil {
				return s.localFuncLits[v]
			}
			return nil
		case *ast.TypeAssertExpr:
			expr = e.X
		case *ast.CallExpr:
			if len(e.Args) == 1 {
				if tv, ok := s.pass.TypesInfo.Types[e.Fun]; ok && tv.IsType() {
					expr = e.Args[0]
					continue
				}
			}
			return nil
		default:
			return nil
		}
	}
	return nil
}
