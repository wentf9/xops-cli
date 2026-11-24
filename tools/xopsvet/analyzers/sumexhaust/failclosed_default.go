package sumexhaust

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

func isSecurityDecisionSealed(pass *analysis.Pass, info *sealedInfo, localFailClosed map[types.Object]bool) bool {
	if info.named != nil && info.named.Obj() != nil {
		obj := info.named.Obj()
		origObj := obj
		if origin := info.named.Origin(); origin != nil && origin.Obj() != nil {
			origObj = origin.Obj()
		}
		if localFailClosed[origObj] || pass.ImportObjectFact(origObj, new(failClosedSumFact)) {
			return true
		}
		if isSecurityPkg(origObj.Pkg()) || isSecurityTypeName(origObj.Name()) {
			return true
		}
	}
	for _, m := range info.sealedMethods {
		if isSecurityPkg(m.Pkg()) {
			return true
		}
	}
	return false
}

func isSecurityPkg(pkg *types.Package) bool {
	if pkg == nil {
		return false
	}
	pkgInfo := vetutil.ClassifyPackage(pkg.Path())
	if pkgInfo.Layer == vetutil.LayerCoreGate {
		return true
	}
	secPrefix := vetutil.ModulePrefix + "/core/domain/security"
	return pkgInfo.BasePath == secPrefix || strings.HasPrefix(pkgInfo.BasePath, secPrefix+"/")
}

func isSecurityTypeName(name string) bool {
	return strings.Contains(name, "Decision") ||
		strings.Contains(name, "Verdict") ||
		strings.Contains(name, "Guardrail") ||
		strings.Contains(name, "Approval") ||
		strings.Contains(name, "Capability")
}

func checkFailClosedDefault(
	pass *analysis.Pass,
	ts *ast.TypeSwitchStmt,
	info *sealedInfo,
	switchedType types.Type,
	defaultClause *ast.CaseClause,
) {
	typeLabel := formatInterfaceName(pass.Pkg, info.named, switchedType)
	if defaultClause == nil {
		pass.ReportRangef(ts, "sumexhaust: 安全决策封闭类型 %s 的 type switch 必须包含 fail-closed default 分支", typeLabel)
		return
	}
	stmts := nonEmptyStmts(defaultClause.Body)
	if len(stmts) == 0 {
		pass.ReportRangef(defaultClause, "sumexhaust: 安全决策 default 分支禁止为空，必须显式返回拒绝/错误或 panic")
		return
	}
	enclosing, sig := enclosingFuncInfo(pass, ts)
	inTest := vetutil.IsPosInTestFile(pass, defaultClause.Pos())
	state := defaultScanState{
		pass:           pass,
		sig:            sig,
		inTest:         inTest,
		permissiveVars: make(map[*types.Var]bool),
		funcLitVars:    collectOuterFuncLitVars(pass.TypesInfo, enclosing, ts.Pos()),
		visitedLits:    make(map[*ast.FuncLit]bool),
	}
	res := inspectDefaultBlock(stmts, state)
	if res.reportedFailOpen {
		return
	}
	if !res.hasFailClosedAction {
		pass.ReportRangef(defaultClause, "sumexhaust: 安全决策 default 分支必须包含显式 fail-closed 处置（返回拒绝/错误或 panic），禁止静默 break 或放行")
	}
}

func nonEmptyStmts(stmts []ast.Stmt) []ast.Stmt {
	var out []ast.Stmt
	for _, s := range stmts {
		if _, isEmpty := s.(*ast.EmptyStmt); !isEmpty {
			out = append(out, s)
		}
	}
	return out
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
			recordFuncLitPair(info, identSliceToExprs(node.Names), node.Values, true, out)
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

func identSliceToExprs(ids []*ast.Ident) []ast.Expr {
	out := make([]ast.Expr, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return out
}

type defaultScanState struct {
	pass           *analysis.Pass
	sig            *types.Signature
	inTest         bool
	permissiveVars map[*types.Var]bool
	funcLitVars    map[*types.Var]*ast.FuncLit
	visitedLits    map[*ast.FuncLit]bool
}

type defaultScanResult struct {
	hasFailClosedAction bool
	reportedFailOpen    bool
}

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
		res.reportedFailOpen = checkAssignStmt(node, st)
	case *ast.DeclStmt:
		res.reportedFailOpen = checkDeclStmt(node, st)
	case *ast.ExprStmt:
		res.hasFailClosedAction = isFailClosedCall(st, node.X)
		res.reportedFailOpen = inspectCalledFuncLitStmt(node.X, st)
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

// inspectSwitchStmt 扫描嵌套 switch/type-switch 分支以透传 fail-open 违规，
// 因无法保证所有运行时分支均终止，故不置位 hasFailClosedAction。
func inspectSwitchStmt(initStmt ast.Stmt, body *ast.BlockStmt, st defaultScanState) defaultScanResult {
	reported := false
	if initStmt != nil {
		reported = inspectDefaultStmt(initStmt, st).reportedFailOpen
	}
	if body == nil {
		return defaultScanResult{reportedFailOpen: reported}
	}
	for _, s := range body.List {
		cc, ok := s.(*ast.CaseClause)
		if !ok {
			continue
		}
		if inspectDefaultBlock(nonEmptyStmts(cc.Body), st).reportedFailOpen {
			reported = true
		}
	}
	return defaultScanResult{reportedFailOpen: reported}
}

func inspectLoopStmt(initStmt ast.Stmt, body *ast.BlockStmt, st defaultScanState) defaultScanResult {
	reported := false
	if initStmt != nil {
		reported = inspectDefaultStmt(initStmt, st).reportedFailOpen
	}
	if body != nil && inspectDefaultBlock(nonEmptyStmts(body.List), st).reportedFailOpen {
		reported = true
	}
	return defaultScanResult{reportedFailOpen: reported}
}

func inspectSelectStmt(sel *ast.SelectStmt, st defaultScanState) defaultScanResult {
	if sel == nil || sel.Body == nil {
		return defaultScanResult{}
	}
	reported := false
	for _, s := range sel.Body.List {
		cc, ok := s.(*ast.CommClause)
		if !ok {
			continue
		}
		if cc.Comm != nil && inspectDefaultStmt(cc.Comm, st).reportedFailOpen {
			reported = true
		}
		if inspectDefaultBlock(nonEmptyStmts(cc.Body), st).reportedFailOpen {
			reported = true
		}
	}
	return defaultScanResult{reportedFailOpen: reported}
}

func inspectIfStmt(ifNode *ast.IfStmt, st defaultScanState) defaultScanResult {
	initReported := false
	if ifNode.Init != nil {
		// 先检查 if 初始化语句（如 ok := true 或闭包绑定），确保赋值违规与变量追踪生效。
		initReported = inspectDefaultStmt(ifNode.Init, st).reportedFailOpen
	}
	thenRes := inspectDefaultBlock(nonEmptyStmts(ifNode.Body.List), st)
	if ifNode.Else == nil {
		// 缺少 else 分支的 if 无法保证假分支同样 fail-closed 终止，仅透传 fail-open 违规。
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
		// 命名返回值裸 return 无法在局部静态保证已被拒绝值覆盖，单独裸 return 不视为处置。
		return false
	}
	for _, expr := range ret.Results {
		if isPermissiveExpr(st.pass.TypesInfo, expr, st) {
			st.pass.ReportRangef(ret, "sumexhaust: 安全决策 default 分支禁止返回放行值（fail-open）")
			return true
		}
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
	hasNilErr := false
	hasRejectNonErr := false
	for i := 0; i < len(results); i++ {
		if vetutil.IsErrorInterfaceType(sig.Results().At(i).Type()) {
			if isNilIdent(info, results[i]) {
				hasNilErr = true
			}
			continue
		}
		if isFailClosedValueExpr(info, results[i]) {
			hasRejectNonErr = true
		}
	}
	return hasNilErr && !hasRejectNonErr
}

func checkAssignStmt(assign *ast.AssignStmt, st defaultScanState) bool {
	// 仅赋值不能保证 default 分支未滑落（fallthrough），故不置 hasFailClosedAction；仅检查是否赋值放行值并追踪局部变量。
	return checkExprPairPermissive(assign, assign.Lhs, assign.Rhs, assign.Tok == token.DEFINE, st)
}

func checkDeclStmt(decl *ast.DeclStmt, st defaultScanState) bool {
	gen, ok := decl.Decl.(*ast.GenDecl)
	if !ok || gen.Tok != token.VAR {
		return false
	}
	reported := false
	for _, spec := range gen.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || len(vs.Values) == 0 {
			continue
		}
		if checkExprPairPermissive(vs, identSliceToExprs(vs.Names), vs.Values, true, st) {
			reported = true
		}
	}
	return reported
}

func checkExprPairPermissive(
	reportNode ast.Node,
	lhs []ast.Expr,
	rhs []ast.Expr,
	isDef bool,
	st defaultScanState,
) bool {
	reported := false
	for i, expr := range rhs {
		lhsVar := resolveLHSVar(st.pass.TypesInfo, lhs, i, isDef)
		if checkSingleExprPermissive(lhsVar, expr, st) && !reported {
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
	if lhsVar != nil {
		delete(st.funcLitVars, lhsVar)
	}
	if isPermissiveExpr(st.pass.TypesInfo, expr, st) {
		if lhsVar != nil {
			st.permissiveVars[lhsVar] = true
		}
		return true
	}
	if lhsVar != nil {
		delete(st.permissiveVars, lhsVar)
	}
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
	if isDef {
		v, _ := info.Defs[id].(*types.Var)
		return v
	}
	v, _ := info.Uses[id].(*types.Var)
	return v
}

func isFailClosedCall(st defaultScanState, expr ast.Expr) bool {
	call, ok := ast.Unparen(expr).(*ast.CallExpr)
	if !ok {
		return false
	}
	if id, ok := ast.Unparen(call.Fun).(*ast.Ident); ok && id.Name == "panic" {
		if _, isBuiltin := st.pass.TypesInfo.Uses[id].(*types.Builtin); isBuiltin {
			return true
		}
	}
	if !st.inTest {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "Fatal", "Fatalf", "Error", "Errorf", "Fail", "FailNow":
		return true
	default:
		return false
	}
}
