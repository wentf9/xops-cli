package sumexhaust

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

func isSecurityDecisionSealed(pass *analysis.Pass, info *sealedInfo, localFailClosed map[types.Object]bool) bool {
	if info.named != nil && info.named.Obj() != nil {
		origObj := info.named.Origin().Obj()
		if localFailClosed[origObj] || pass.ImportObjectFact(origObj, new(failClosedSumFact)) ||
			isSecurityPkg(origObj.Pkg()) || isSecurityTypeName(origObj.Name()) {
			return true
		}
	}
	return slices.ContainsFunc(info.sealedMethods, func(m *types.Func) bool { return isSecurityPkg(m.Pkg()) })
}

func isSecurityPkg(pkg *types.Package) bool {
	if pkg == nil {
		return false
	}
	pkgInfo := vetutil.ClassifyPackage(pkg.Path())
	secPrefix := vetutil.ModulePrefix + "/core/domain/security"
	return pkgInfo.Layer == vetutil.LayerCoreGate || pkgInfo.BasePath == secPrefix || strings.HasPrefix(pkgInfo.BasePath, secPrefix+"/")
}

func isSecurityTypeName(name string) bool {
	return slices.ContainsFunc([]string{"Decision", "Verdict", "Guardrail", "Approval", "Capability"},
		func(kw string) bool { return strings.Contains(name, kw) })
}

func checkFailClosedDefault(pass *analysis.Pass, ts *ast.TypeSwitchStmt, info *sealedInfo, switchedType types.Type, defaultClause *ast.CaseClause) {
	if defaultClause == nil {
		pass.ReportRangef(ts, "sumexhaust: 安全决策封闭类型 %s 的 type switch 必须包含 fail-closed default 分支", formatInterfaceName(pass.Pkg, info.named, switchedType))
		return
	}
	stmts := nonEmptyStmts(defaultClause.Body)
	if len(stmts) == 0 {
		pass.ReportRangef(defaultClause, "sumexhaust: 安全决策 default 分支禁止为空，必须显式返回拒绝/错误或 panic")
		return
	}
	enclosing, sig := enclosingFuncInfo(pass, ts)
	// 测试源码与 core/ports/tck 测试契约夹具层均允许以 t.Fatal/t.Error 作为 fail-closed default 处置。
	inTest := vetutil.IsPosInTestFile(pass, defaultClause.Pos()) || vetutil.ClassifyPackage(pass.Pkg.Path()).Layer == vetutil.LayerCorePortsTCK
	state := defaultScanState{
		pass: pass, sig: sig, inTest: inTest, permissiveVars: make(map[*types.Var]bool),
		funcLitVars: collectOuterFuncLitVars(pass.TypesInfo, enclosing, ts.Pos()), visitedLits: make(map[*ast.FuncLit]bool),
	}
	if res := inspectDefaultBlock(stmts, state); !res.reportedFailOpen && !res.hasFailClosedAction {
		pass.ReportRangef(defaultClause, "sumexhaust: 安全决策 default 分支必须包含显式 fail-closed 处置（返回拒绝/错误或 panic），禁止静默 break 或放行")
	}
}

func nonEmptyStmts(stmts []ast.Stmt) []ast.Stmt {
	return slices.DeleteFunc(slices.Clone(stmts), func(s ast.Stmt) bool { _, ok := s.(*ast.EmptyStmt); return ok })
}

func enclosingFuncInfo(pass *analysis.Pass, target ast.Node) (ast.Node, *types.Signature) {
	var enclosing ast.Node
	for _, file := range pass.Files {
		if target.Pos() < file.Pos() || target.Pos() > file.End() {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil || target.Pos() < n.Pos() || target.Pos() > n.End() {
				return false
			}
			switch n.(type) {
			case *ast.FuncDecl, *ast.FuncLit:
				enclosing = n
			}
			return true
		})
	}
	switch fn := enclosing.(type) {
	case *ast.FuncDecl:
		if obj := pass.TypesInfo.Defs[fn.Name]; obj != nil {
			sig, _ := obj.Type().(*types.Signature)
			return enclosing, sig
		}
	case *ast.FuncLit:
		sig, _ := pass.TypesInfo.TypeOf(fn).(*types.Signature)
		return enclosing, sig
	}
	return enclosing, nil
}

func collectOuterFuncLitVars(info *types.Info, enclosing ast.Node, beforePos token.Pos) map[*types.Var]*ast.FuncLit {
	out := make(map[*types.Var]*ast.FuncLit)
	if info == nil || enclosing == nil {
		return out
	}
	ast.Inspect(enclosing, func(n ast.Node) bool {
		if n == nil || n.Pos() >= beforePos {
			return false
		}
		if lit, ok := n.(*ast.FuncLit); ok && lit != enclosing {
			return false
		}
		switch node := n.(type) {
		case *ast.AssignStmt:
			recordFuncLitPair(info, node.Lhs, node.Rhs, node.Tok == token.DEFINE, out)
		case *ast.ValueSpec:
			recordFuncLitPair(info, vetutil.IdentSliceToExprs(node.Names), node.Values, true, out)
		}
		return true
	})
	return out
}

func recordFuncLitPair(info *types.Info, lhs, rhs []ast.Expr, isDef bool, out map[*types.Var]*ast.FuncLit) {
	for i, expr := range rhs {
		v := resolveLHSVar(info, lhs, i, isDef)
		if v == nil {
			continue
		}
		if lit, ok := ast.Unparen(expr).(*ast.FuncLit); ok {
			out[v] = lit
		} else {
			delete(out, v)
		}
	}
}

type defaultScanState struct {
	pass           *analysis.Pass
	sig            *types.Signature
	inTest         bool
	permissiveVars map[*types.Var]bool
	funcLitVars    map[*types.Var]*ast.FuncLit
	visitedLits    map[*ast.FuncLit]bool
}

type defaultScanResult struct{ hasFailClosedAction, reportedFailOpen bool }

func inspectDefaultBlock(stmts []ast.Stmt, st defaultScanState) defaultScanResult {
	var res defaultScanResult
	for _, s := range stmts {
		sub := inspectDefaultStmt(s, st)
		res.hasFailClosedAction = res.hasFailClosedAction || sub.hasFailClosedAction
		res.reportedFailOpen = res.reportedFailOpen || sub.reportedFailOpen
	}
	return res
}

func inspectDefaultStmt(s ast.Stmt, st defaultScanState) defaultScanResult {
	var res defaultScanResult
	switch node := s.(type) {
	case *ast.ReturnStmt:
		res.reportedFailOpen = checkReturnStmt(node, st, &res)
	case *ast.AssignStmt:
		res.reportedFailOpen = checkExprPairPermissive(node, node.Lhs, node.Rhs, node.Tok == token.DEFINE, st)
	case *ast.DeclStmt:
		res.reportedFailOpen = checkDeclStmt(node, st)
	case *ast.ExprStmt:
		res.hasFailClosedAction, res.reportedFailOpen = isFailClosedCall(st, node.X), inspectCalledFuncLitStmt(node.X, st)
	case *ast.DeferStmt:
		res.reportedFailOpen = inspectCalledFuncLitStmt(node.Call, st)
	case *ast.GoStmt:
		res.reportedFailOpen = inspectCalledFuncLitStmt(node.Call, st)
	case *ast.LabeledStmt:
		return inspectDefaultStmt(node.Stmt, st)
	case *ast.BlockStmt:
		return inspectDefaultBlock(nonEmptyStmts(node.List), st)
	case *ast.IfStmt:
		return inspectIfStmt(node, st)
	case *ast.SwitchStmt:
		return inspectSwitchStmt(node.Init, node.Body, st)
	case *ast.TypeSwitchStmt:
		return inspectSwitchStmt(node.Init, node.Body, st)
	case *ast.ForStmt:
		return inspectLoopStmt(node.Init, node.Body, st)
	case *ast.RangeStmt:
		return inspectLoopStmt(nil, node.Body, st)
	case *ast.SelectStmt:
		return inspectSelectStmt(node, st)
	}
	return res
}

func inspectSwitchStmt(initStmt ast.Stmt, body *ast.BlockStmt, st defaultScanState) defaultScanResult {
	reported := initStmt != nil && inspectDefaultStmt(initStmt, st).reportedFailOpen
	if body != nil {
		for _, s := range body.List {
			if cc, ok := s.(*ast.CaseClause); ok {
				reported = inspectDefaultBlock(nonEmptyStmts(cc.Body), st).reportedFailOpen || reported
			}
		}
	}
	return defaultScanResult{reportedFailOpen: reported}
}

func inspectLoopStmt(initStmt ast.Stmt, body *ast.BlockStmt, st defaultScanState) defaultScanResult {
	reported := (initStmt != nil && inspectDefaultStmt(initStmt, st).reportedFailOpen) ||
		(body != nil && inspectDefaultBlock(nonEmptyStmts(body.List), st).reportedFailOpen)
	return defaultScanResult{reportedFailOpen: reported}
}

func inspectSelectStmt(sel *ast.SelectStmt, st defaultScanState) defaultScanResult {
	if sel == nil || sel.Body == nil {
		return defaultScanResult{}
	}
	reported := false
	for _, s := range sel.Body.List {
		if cc, ok := s.(*ast.CommClause); ok {
			reported = (cc.Comm != nil && inspectDefaultStmt(cc.Comm, st).reportedFailOpen) ||
				inspectDefaultBlock(nonEmptyStmts(cc.Body), st).reportedFailOpen || reported
		}
	}
	return defaultScanResult{reportedFailOpen: reported}
}

func inspectIfStmt(ifNode *ast.IfStmt, st defaultScanState) defaultScanResult {
	initReported := ifNode.Init != nil && inspectDefaultStmt(ifNode.Init, st).reportedFailOpen
	thenRes := inspectDefaultBlock(nonEmptyStmts(ifNode.Body.List), st)
	if ifNode.Else == nil {
		return defaultScanResult{reportedFailOpen: initReported || thenRes.reportedFailOpen}
	}
	var elseRes defaultScanResult
	switch el := ifNode.Else.(type) {
	case *ast.BlockStmt:
		elseRes = inspectDefaultBlock(nonEmptyStmts(el.List), st)
	case *ast.IfStmt:
		elseRes = inspectIfStmt(el, st)
	}
	return defaultScanResult{
		hasFailClosedAction: thenRes.hasFailClosedAction && elseRes.hasFailClosedAction,
		reportedFailOpen:    initReported || thenRes.reportedFailOpen || elseRes.reportedFailOpen,
	}
}

func checkReturnStmt(ret *ast.ReturnStmt, st defaultScanState, res *defaultScanResult) bool {
	if len(ret.Results) == 0 {
		return false
	}
	if slices.ContainsFunc(ret.Results, func(expr ast.Expr) bool { return isPermissiveExpr(st.pass.TypesInfo, expr, st) }) {
		st.pass.ReportRangef(ret, "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）")
		return true
	}
	if returnsBareNilError(st.pass.TypesInfo, st.sig, ret.Results) {
		st.pass.ReportRangef(ret, "sumexhaust: 安全决策 default 分支禁止返回 nil error 且无显式拒绝值")
		return true
	}
	res.hasFailClosedAction = true
	return false
}

func returnsBareNilError(info *types.Info, sig *types.Signature, results []ast.Expr) bool {
	if sig == nil || sig.Results() == nil || sig.Results().Len() != len(results) {
		return false
	}
	hasNilErr, hasReject := false, false
	for i := range results {
		if vetutil.IsErrorInterfaceType(sig.Results().At(i).Type()) {
			hasNilErr = hasNilErr || isNilIdent(info, results[i])
		} else if isFailClosedValueExpr(info, results[i]) {
			hasReject = true
		}
	}
	return hasNilErr && !hasReject
}

func checkDeclStmt(decl *ast.DeclStmt, st defaultScanState) bool {
	gen, ok := decl.Decl.(*ast.GenDecl)
	if !ok || gen.Tok != token.VAR {
		return false
	}
	reported := false
	for _, spec := range gen.Specs {
		if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Values) > 0 {
			reported = checkExprPairPermissive(vs, vetutil.IdentSliceToExprs(vs.Names), vs.Values, true, st) || reported
		}
	}
	return reported
}

func checkExprPairPermissive(reportNode ast.Node, lhs, rhs []ast.Expr, isDef bool, st defaultScanState) bool {
	reported := false
	for i, expr := range rhs {
		if checkSingleExprPermissive(resolveLHSVar(st.pass.TypesInfo, lhs, i, isDef), expr, st) && !reported {
			st.pass.ReportRangef(reportNode, "sumexhaust: 安全决策 default 分支禁止赋值放行值（fail-open）")
			reported = true
		}
	}
	return reported
}

func checkSingleExprPermissive(lhsVar *types.Var, expr ast.Expr, st defaultScanState) bool {
	if lit, ok := ast.Unparen(expr).(*ast.FuncLit); ok {
		if lhsVar != nil {
			st.funcLitVars[lhsVar] = lit
			delete(st.permissiveVars, lhsVar)
		}
		return false
	}
	delete(st.funcLitVars, lhsVar)
	if isPermissiveExpr(st.pass.TypesInfo, expr, st) {
		if lhsVar != nil {
			st.permissiveVars[lhsVar] = true
		}
		return true
	}
	delete(st.permissiveVars, lhsVar)
	return false
}

func resolveLHSVar(info *types.Info, lhs []ast.Expr, idx int, isDef bool) *types.Var {
	if info == nil || idx >= len(lhs) {
		return nil
	}
	id, ok := ast.Unparen(lhs[idx]).(*ast.Ident)
	if !ok || id.Name == "_" {
		return nil
	}
	obj := info.Uses[id]
	if isDef {
		obj = info.Defs[id]
	}
	v, _ := obj.(*types.Var)
	return v
}

func isFailClosedCall(st defaultScanState, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok && id.Name == "panic" {
		_, isB := st.pass.TypesInfo.Uses[id].(*types.Builtin)
		return isB
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	return st.inTest && ok && slices.Contains([]string{"Fatal", "Fatalf", "Error", "Errorf", "Fail", "FailNow"}, sel.Sel.Name)
}

func cloneDefaultScanState(litSig *types.Signature, st defaultScanState, visited map[*ast.FuncLit]bool, sharePerm bool) defaultScanState {
	perm, fns := st.permissiveVars, maps.Clone(st.funcLitVars)
	if !sharePerm {
		perm = maps.Clone(st.permissiveVars)
	}
	if perm == nil {
		perm = make(map[*types.Var]bool)
	}
	if fns == nil {
		fns = make(map[*types.Var]*ast.FuncLit)
	}
	return defaultScanState{pass: st.pass, sig: litSig, inTest: st.inTest, permissiveVars: perm, funcLitVars: fns, visitedLits: visited}
}
