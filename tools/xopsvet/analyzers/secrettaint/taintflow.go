package secrettaint

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// maxTaintFixpointIters 限制明文污点流分析的最大不动点迭代轮次。
const maxTaintFixpointIters = 32

type taintState struct {
	pass        *analysis.Pass
	facts       *secretFactIndex
	pkgIdx      *packageCallbackIndex
	localLits   map[*types.Var][]*ast.FuncLit
	localFuncs  map[*types.Var][]*types.Func
	tainted     map[*types.Var]bool
	ownerScope  *types.Scope
	resultVars  map[*types.Var]bool
	reported    map[token.Pos]bool
	activeLits  map[*ast.FuncLit]bool
	activeDecls map[*ast.FuncDecl]bool
}

func checkSecretTaintFlows(pass *analysis.Pass, facts *secretFactIndex) {
	reported := make(map[token.Pos]bool)
	checkedLits := make(map[*ast.FuncLit]bool)
	checkedDecls := make(map[*ast.FuncDecl]bool)
	pkgIdx := collectPackageCallbackIndex(pass)

	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			checkSecretUseCallsInBody(pass, facts, pkgIdx, fn.Body, checkedLits, checkedDecls, reported)
			checkDirectSecretUseFuncDecl(pass, facts, pkgIdx, file.Comments, fn, reported)
		}
	}
	checkRemainingSecretUseFuncLits(pass, facts, pkgIdx, checkedLits, reported)
}

func checkDirectSecretUseFuncDecl(
	pass *analysis.Pass,
	facts *secretFactIndex,
	pkgIdx *packageCallbackIndex,
	comments []*ast.CommentGroup,
	fn *ast.FuncDecl,
	reported map[token.Pos]bool,
) {
	if fn.Type == nil || fn.Type.Params == nil {
		return
	}
	hasFuncDir := vetutil.FuncDeclHasDirective(fn, vetutil.DirectiveSecretUse)
	hasFuncParam := hasFunctionTypedParam(fn.Type.Params)
	vars := collectDirectSecretParamVars(pass, comments, fn.Type.Params, hasFuncDir && !hasFuncParam)
	if len(vars) == 0 {
		return
	}
	ownerScope := pass.TypesInfo.Scopes[fn.Type]
	runTaintAnalysisWithState(
		pass, facts, pkgIdx, fn.Body, ownerScope, vars, fn.Type.Results, reported,
		make(map[*ast.FuncLit]bool), map[*ast.FuncDecl]bool{fn: true},
	)
}

func checkRemainingSecretUseFuncLits(
	pass *analysis.Pass,
	facts *secretFactIndex,
	pkgIdx *packageCallbackIndex,
	checkedLits map[*ast.FuncLit]bool,
	reported map[token.Pos]bool,
) {
	ins := vetutil.InspectorOf(pass)
	ins.Preorder([]ast.Node{(*ast.FuncLit)(nil)}, func(n ast.Node) {
		lit, ok := n.(*ast.FuncLit)
		if !ok || lit.Body == nil || lit.Type == nil || checkedLits[lit] {
			return
		}
		comments := facts.commentsFor(pass.Fset, lit.Pos())
		vars := collectDirectSecretParamVars(pass, comments, lit.Type.Params, false)
		if len(vars) == 0 {
			return
		}
		checkedLits[lit] = true
		runTaintAnalysisWithState(
			pass, facts, pkgIdx, lit.Body, pass.TypesInfo.Scopes[lit.Type], vars, lit.Type.Results, reported,
			map[*ast.FuncLit]bool{lit: true}, make(map[*ast.FuncDecl]bool),
		)
	})
}

func hasFunctionTypedParam(fl *ast.FieldList) bool {
	if fl == nil {
		return false
	}
	for _, f := range fl.List {
		if _, ok := ast.Unparen(f.Type).(*ast.FuncType); ok {
			return true
		}
	}
	return false
}

func collectDirectSecretParamVars(
	pass *analysis.Pass,
	comments []*ast.CommentGroup,
	fl *ast.FieldList,
	allByteOrString bool,
) []*types.Var {
	if fl == nil {
		return nil
	}
	var vars []*types.Var
	for idx, f := range fl.List {
		if _, isFunc := ast.Unparen(f.Type).(*ast.FuncType); isFunc {
			continue
		}
		marked := allByteOrString || vetutil.ParamFieldHasDirective(pass.Fset, comments, fl, idx, vetutil.DirectiveSecretUse)
		if !marked || !isSecretCarrierType(pass.TypesInfo.TypeOf(f.Type)) {
			continue
		}
		for _, id := range f.Names {
			if v, ok := pass.TypesInfo.Defs[id].(*types.Var); ok && v != nil {
				vars = append(vars, v)
			}
		}
	}
	return vars
}

func collectCallbackSecretParamVars(info *types.Info, fl *ast.FieldList) []*types.Var {
	if fl == nil {
		return nil
	}
	var vars []*types.Var
	for _, f := range fl.List {
		if !isSecretCarrierType(info.TypeOf(f.Type)) {
			continue
		}
		for _, id := range f.Names {
			if v, ok := info.Defs[id].(*types.Var); ok && v != nil {
				vars = append(vars, v)
			}
		}
	}
	return vars
}

func isSecretCarrierType(t types.Type) bool {
	if t == nil {
		return false
	}
	u := types.Unalias(t).Underlying()
	if basic, ok := u.(*types.Basic); ok {
		return basic.Kind() == types.String
	}
	if sl, ok := u.(*types.Slice); ok {
		elem, ok := types.Unalias(sl.Elem()).Underlying().(*types.Basic)
		return ok && (elem.Kind() == types.Byte || elem.Kind() == types.Uint8)
	}
	return false
}

func runTaintAnalysisWithState(
	pass *analysis.Pass,
	facts *secretFactIndex,
	pkgIdx *packageCallbackIndex,
	body *ast.BlockStmt,
	ownerScope *types.Scope,
	seeds []*types.Var,
	results *ast.FieldList,
	reported map[token.Pos]bool,
	activeLits map[*ast.FuncLit]bool,
	activeDecls map[*ast.FuncDecl]bool,
) {
	if body == nil || ownerScope == nil || len(seeds) == 0 {
		return
	}
	localLits, localFuncs := collectLocalCallbackMaps(pass.TypesInfo, body, pkgIdx)
	st := &taintState{
		pass:        pass,
		facts:       facts,
		pkgIdx:      pkgIdx,
		localLits:   localLits,
		localFuncs:  localFuncs,
		tainted:     make(map[*types.Var]bool),
		ownerScope:  ownerScope,
		resultVars:  collectResultVars(pass.TypesInfo, results),
		reported:    reported,
		activeLits:  activeLits,
		activeDecls: activeDecls,
	}
	for _, v := range seeds {
		if v != nil {
			st.tainted[v] = true
		}
	}
	for range maxTaintFixpointIters {
		changed := false
		walkOutsideClosures(body, func(n ast.Node) {
			if st.propagateNode(n) {
				changed = true
			}
		})
		if !changed {
			break
		}
	}
	exemptDeferLits := collectExemptClearDeferLits(pass.TypesInfo, body)
	walkOutsideClosures(body, func(n ast.Node) {
		st.checkNode(n, exemptDeferLits)
	})
}

func (s *taintState) propagateNode(n ast.Node) bool {
	switch stmt := n.(type) {
	case *ast.AssignStmt:
		return s.propagateAssign(stmt)
	case *ast.ValueSpec:
		return s.propagateValueSpec(stmt)
	case *ast.RangeStmt:
		return s.propagateRange(stmt)
	case *ast.CallExpr:
		return s.propagateCallMutation(stmt)
	default:
		return false
	}
}

func (s *taintState) propagateAssign(stmt *ast.AssignStmt) bool {
	if len(stmt.Lhs) >= 2 && len(stmt.Rhs) == 1 {
		if rhs, ok := unwrapMultiReturnRHS(stmt.Rhs[0]); ok {
			return s.propagatePair(stmt.Lhs[0], rhs)
		}
		return false
	}
	if len(stmt.Lhs) != len(stmt.Rhs) {
		return false
	}
	changed := false
	for i := range stmt.Lhs {
		if s.propagatePair(stmt.Lhs[i], stmt.Rhs[i]) {
			changed = true
		}
	}
	return changed
}

func (s *taintState) propagateValueSpec(vs *ast.ValueSpec) bool {
	if len(vs.Names) >= 2 && len(vs.Values) == 1 {
		if rhs, ok := unwrapMultiReturnRHS(vs.Values[0]); ok {
			return s.propagatePair(vs.Names[0], rhs)
		}
		return false
	}
	if len(vs.Names) != len(vs.Values) {
		return false
	}
	changed := false
	for i := range vs.Names {
		if s.propagatePair(vs.Names[i], vs.Values[i]) {
			changed = true
		}
	}
	return changed
}

// unwrapMultiReturnRHS 提取多返回值赋值右端受支持的单表达式（非 type-switch 的类型断言或函数调用），
// 使 `v, err := io.ReadAll(...)` 与 `v, ok := x.([]byte)` 等惯用多返回值写法能正确向首个左值传播污点。
func unwrapMultiReturnRHS(expr ast.Expr) (ast.Expr, bool) {
	switch rhs := ast.Unparen(expr).(type) {
	case *ast.TypeAssertExpr:
		if rhs.Type != nil {
			return rhs, true
		}
	case *ast.CallExpr:
		return rhs, true
	}
	return nil, false
}

func (s *taintState) propagatePair(lhs, rhs ast.Expr) bool {
	id, ok := ast.Unparen(lhs).(*ast.Ident)
	if !ok || id.Name == "_" {
		return false
	}
	v := lookupVar(s.pass.TypesInfo, id)
	if v == nil || !s.isLocalVar(v) || s.resultVars[v] || s.tainted[v] {
		return false
	}
	if s.exprIsTainted(rhs) {
		s.tainted[v] = true
		return true
	}
	return false
}

func (s *taintState) propagateRange(stmt *ast.RangeStmt) bool {
	if !s.exprIsTainted(stmt.X) {
		return false
	}
	id, ok := ast.Unparen(stmt.Value).(*ast.Ident)
	if !ok || id.Name == "_" {
		return false
	}
	v := lookupVar(s.pass.TypesInfo, id)
	if v == nil || !s.isLocalVar(v) || s.resultVars[v] || s.tainted[v] {
		return false
	}
	s.tainted[v] = true
	return true
}

func (s *taintState) propagateCallMutation(call *ast.CallExpr) bool {
	if isCopyBuiltin(s.pass.TypesInfo, call) && len(call.Args) == 2 && s.exprIsTainted(call.Args[1]) {
		return s.taintLocalTarget(call.Args[0])
	}
	if isAppendBuiltin(s.pass.TypesInfo, call) && len(call.Args) >= 2 && s.argsContainTaint(call.Args[1:]) {
		return s.taintLocalTarget(call.Args[0])
	}
	if isFmtAppendCall(s.pass.TypesInfo, call) && len(call.Args) >= 2 && s.argsContainTaint(call.Args[1:]) {
		return s.taintLocalTarget(call.Args[0])
	}
	if isIOCopyCall(s.pass.TypesInfo, call) && len(call.Args) >= 2 && s.exprIsTainted(call.Args[1]) {
		changed := s.taintLocalTarget(call.Args[0])
		if isIOCopyBufferCall(s.pass.TypesInfo, call) && len(call.Args) >= 3 {
			if s.taintLocalTarget(call.Args[2]) {
				changed = true
			}
		}
		return changed
	}
	return s.propagateBufferCallMutation(call)
}

func (s *taintState) propagateBufferCallMutation(call *ast.CallExpr) bool {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if isBufferOrBuilderWriteMethod(s.pass.TypesInfo, call) && s.argsContainTaint(call.Args) {
		return s.taintLocalTarget(sel.X)
	}
	if isBufferOrReaderReadIntoMethod(s.pass.TypesInfo, call) && len(call.Args) >= 1 && s.exprIsTainted(sel.X) {
		return s.taintLocalTarget(call.Args[0])
	}
	if isBufferReadFromMethod(s.pass.TypesInfo, call) && len(call.Args) >= 1 && s.exprIsTainted(call.Args[0]) {
		return s.taintLocalTarget(sel.X)
	}
	return false
}

func (s *taintState) taintLocalTarget(expr ast.Expr) bool {
	id, ok := unwrapSliceBaseExpr(s.pass.TypesInfo, expr).(*ast.Ident)
	if !ok || id.Name == "_" {
		return false
	}
	v := lookupVar(s.pass.TypesInfo, id)
	if v == nil || !s.isLocalVar(v) || s.resultVars[v] || s.tainted[v] {
		return false
	}
	s.tainted[v] = true
	return true
}

// unwrapSliceBaseExpr 剥离取址（&）、切片表达式与非 map 索引表达式，保留对底层目标变量的追踪，
// 同时拦截对 map 元素（如 localMap["k"]）的非法绕过写入。
func unwrapSliceBaseExpr(info *types.Info, expr ast.Expr) ast.Expr {
	for expr != nil {
		switch e := ast.Unparen(expr).(type) {
		case *ast.UnaryExpr:
			if e.Op != token.AND {
				return e
			}
			expr = e.X
		case *ast.SliceExpr:
			expr = e.X
		case *ast.IndexExpr:
			if info != nil && isMapExprType(info.TypeOf(e.X)) {
				return e
			}
			expr = e.X
		default:
			return e
		}
	}
	return nil
}

func isMapExprType(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := types.Unalias(t).Underlying().(*types.Map)
	return ok
}
