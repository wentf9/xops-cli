package secrettaint

import (
	"go/ast"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

type taintState struct {
	pass       *analysis.Pass
	facts      *secretFactIndex
	tainted    map[*types.Var]bool
	ownerScope *types.Scope
	resultVars map[*types.Var]bool
	reported   map[token.Pos]bool
}

func checkSecretTaintFlows(pass *analysis.Pass, facts *secretFactIndex) {
	reported := make(map[token.Pos]bool)
	checkedLits := make(map[*ast.FuncLit]bool)

	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			checkSecretUseCallsInBody(pass, facts, fn.Body, checkedLits, reported)
			checkDirectSecretUseFuncDecl(pass, facts, file.Comments, fn, reported)
		}
	}
	checkRemainingSecretUseFuncLits(pass, facts, checkedLits, reported)
}

func checkDirectSecretUseFuncDecl(
	pass *analysis.Pass,
	facts *secretFactIndex,
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
	runTaintAnalysis(pass, facts, fn.Body, ownerScope, vars, fn.Type.Results, reported)
}

func checkRemainingSecretUseFuncLits(
	pass *analysis.Pass,
	facts *secretFactIndex,
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
		runTaintAnalysis(pass, facts, lit.Body, pass.TypesInfo.Scopes[lit.Type], vars, lit.Type.Results, reported)
	})
}

func checkSecretUseCallsInBody(
	pass *analysis.Pass,
	facts *secretFactIndex,
	body *ast.BlockStmt,
	checkedLits map[*ast.FuncLit]bool,
	reported map[token.Pos]bool,
) {
	localLits := collectLocalFuncLits(pass.TypesInfo, body)
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !facts.isSecretUseCall(pass, call) {
			return true
		}
		for _, arg := range call.Args {
			lit := resolveCallbackLit(pass.TypesInfo, arg, localLits)
			if lit == nil || lit.Body == nil || lit.Type == nil || checkedLits[lit] {
				continue
			}
			checkedLits[lit] = true
			vars := collectCallbackSecretParamVars(pass.TypesInfo, lit.Type.Params)
			runTaintAnalysis(pass, facts, lit.Body, pass.TypesInfo.Scopes[lit.Type], vars, lit.Type.Results, reported)
		}
		return true
	})
}

func collectLocalFuncLits(info *types.Info, body *ast.BlockStmt) map[*types.Var]*ast.FuncLit {
	lits := make(map[*types.Var]*ast.FuncLit)
	ast.Inspect(body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			recordAssignFuncLits(info, stmt, lits)
		case *ast.ValueSpec:
			recordValueSpecFuncLits(info, stmt, lits)
		}
		return true
	})
	return lits
}

func recordAssignFuncLits(info *types.Info, stmt *ast.AssignStmt, lits map[*types.Var]*ast.FuncLit) {
	if len(stmt.Lhs) != len(stmt.Rhs) {
		return
	}
	for i := range stmt.Lhs {
		lit, ok := ast.Unparen(stmt.Rhs[i]).(*ast.FuncLit)
		if !ok {
			continue
		}
		id, ok := ast.Unparen(stmt.Lhs[i]).(*ast.Ident)
		if !ok {
			continue
		}
		if v := lookupVar(info, id); v != nil {
			lits[v] = lit
		}
	}
}

func recordValueSpecFuncLits(info *types.Info, stmt *ast.ValueSpec, lits map[*types.Var]*ast.FuncLit) {
	if len(stmt.Names) != len(stmt.Values) {
		return
	}
	for i := range stmt.Names {
		lit, ok := ast.Unparen(stmt.Values[i]).(*ast.FuncLit)
		if !ok {
			continue
		}
		if v, ok := info.Defs[stmt.Names[i]].(*types.Var); ok && v != nil {
			lits[v] = lit
		}
	}
}

func resolveCallbackLit(info *types.Info, arg ast.Expr, localLits map[*types.Var]*ast.FuncLit) *ast.FuncLit {
	e := ast.Unparen(arg)
	if lit, ok := e.(*ast.FuncLit); ok {
		return lit
	}
	if id, ok := e.(*ast.Ident); ok {
		if v, ok := info.Uses[id].(*types.Var); ok {
			return localLits[v]
		}
	}
	return nil
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

func runTaintAnalysis(
	pass *analysis.Pass,
	facts *secretFactIndex,
	body *ast.BlockStmt,
	ownerScope *types.Scope,
	seeds []*types.Var,
	results *ast.FieldList,
	reported map[token.Pos]bool,
) {
	if body == nil || ownerScope == nil || len(seeds) == 0 {
		return
	}
	st := &taintState{
		pass:       pass,
		facts:      facts,
		tainted:    make(map[*types.Var]bool),
		ownerScope: ownerScope,
		resultVars: collectResultVars(pass.TypesInfo, results),
		reported:   reported,
	}
	for _, v := range seeds {
		st.tainted[v] = true
	}
	for range 6 {
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

func collectResultVars(info *types.Info, fl *ast.FieldList) map[*types.Var]bool {
	out := make(map[*types.Var]bool)
	if fl == nil {
		return out
	}
	for _, f := range fl.List {
		for _, id := range f.Names {
			if v, ok := info.Defs[id].(*types.Var); ok && v != nil {
				out[v] = true
			}
		}
	}
	return out
}

func walkOutsideClosures(body *ast.BlockStmt, visit func(ast.Node)) {
	if body == nil {
		return
	}
	ast.Inspect(body, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		if _, isLit := n.(*ast.FuncLit); isLit {
			visit(n)
			return false
		}
		visit(n)
		return true
	})
}

func collectExemptClearDeferLits(info *types.Info, body *ast.BlockStmt) map[*ast.FuncLit]bool {
	exempt := make(map[*ast.FuncLit]bool)
	ast.Inspect(body, func(n ast.Node) bool {
		ds, ok := n.(*ast.DeferStmt)
		if !ok || ds.Call == nil {
			return true
		}
		lit, ok := ast.Unparen(ds.Call.Fun).(*ast.FuncLit)
		if ok && lit.Body != nil && isClearOnlyBody(info, lit.Body) {
			exempt[lit] = true
		}
		return true
	})
	return exempt
}

func isClearOnlyBody(info *types.Info, body *ast.BlockStmt) bool {
	if len(body.List) == 0 {
		return true
	}
	for _, stmt := range body.List {
		es, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := ast.Unparen(es.X).(*ast.CallExpr)
		if !ok || !isExemptBuiltinCall(info, call) {
			return false
		}
	}
	return true
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
	if isBufferOrBuilderWriteMethod(s.pass.TypesInfo, call) && s.argsContainTaint(call.Args) {
		if sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr); ok {
			return s.taintLocalTarget(sel.X)
		}
	}
	return false
}

func (s *taintState) taintLocalTarget(expr ast.Expr) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
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
