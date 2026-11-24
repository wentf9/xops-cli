package sumexhaust

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
	"unicode"

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
	sig := enclosingFuncSig(pass, ts)
	inTest := vetutil.IsPosInTestFile(pass, defaultClause.Pos())
	state := defaultScanState{pass: pass, sig: sig, inTest: inTest}
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

func enclosingFuncSig(pass *analysis.Pass, target ast.Node) *types.Signature {
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
			return sig
		}
	case *ast.FuncLit:
		sig, _ := pass.TypesInfo.TypeOf(fn).(*types.Signature)
		return sig
	}
	return nil
}

type defaultScanState struct {
	pass   *analysis.Pass
	sig    *types.Signature
	inTest bool
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
		res.reportedFailOpen = checkAssignStmt(node, st, &res)
	case *ast.ExprStmt:
		res.hasFailClosedAction = isFailClosedCall(st, node.X)
	case *ast.BlockStmt:
		return inspectDefaultBlock(nonEmptyStmts(node.List), st)
	case *ast.IfStmt:
		return inspectIfStmt(node, st)
	}
	return res
}

func inspectIfStmt(ifNode *ast.IfStmt, st defaultScanState) defaultScanResult {
	res := inspectDefaultBlock(nonEmptyStmts(ifNode.Body.List), st)
	if ifNode.Else == nil {
		return res
	}
	switch el := ifNode.Else.(type) {
	case *ast.BlockStmt:
		sub := inspectDefaultBlock(nonEmptyStmts(el.List), st)
		res.hasFailClosedAction = res.hasFailClosedAction || sub.hasFailClosedAction
		res.reportedFailOpen = res.reportedFailOpen || sub.reportedFailOpen
	case *ast.IfStmt:
		sub := inspectIfStmt(el, st)
		res.hasFailClosedAction = res.hasFailClosedAction || sub.hasFailClosedAction
		res.reportedFailOpen = res.reportedFailOpen || sub.reportedFailOpen
	}
	return res
}

func checkReturnStmt(ret *ast.ReturnStmt, st defaultScanState, res *defaultScanResult) bool {
	if len(ret.Results) == 0 {
		// 命名返回值裸 return 必须依赖先前的 fail-closed 赋值，单独裸 return 不视为处置。
		return false
	}
	for _, expr := range ret.Results {
		if isPermissiveExpr(st.pass.TypesInfo, expr) {
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

func checkAssignStmt(assign *ast.AssignStmt, st defaultScanState, res *defaultScanResult) bool {
	for _, rhs := range assign.Rhs {
		if isPermissiveExpr(st.pass.TypesInfo, rhs) {
			st.pass.ReportRangef(assign, "sumexhaust: 安全决策 default 分支禁止赋值放行值（fail-open）")
			return true
		}
		if isFailClosedValueExpr(st.pass.TypesInfo, rhs) {
			res.hasFailClosedAction = true
		}
	}
	return false
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

func isPermissiveExpr(info *types.Info, expr ast.Expr) bool {
	if isBoolConstExpr(info, expr, true) {
		return true
	}
	id := rightmostIdent(expr)
	if id == nil {
		return false
	}
	return hasAnyToken(id.Name, isPermissiveToken)
}

func isFailClosedValueExpr(info *types.Info, expr ast.Expr) bool {
	if isBoolConstExpr(info, expr, false) {
		return true
	}
	if call, ok := ast.Unparen(expr).(*ast.CallExpr); ok {
		if tv, ok := info.Types[call]; ok && vetutil.IsErrorInterfaceType(tv.Type) {
			return true
		}
		if id := rightmostIdent(call.Fun); id != nil && hasAnyToken(id.Name, isFailClosedToken) {
			return true
		}
		return false
	}
	if lit, ok := ast.Unparen(expr).(*ast.CompositeLit); ok {
		if id := rightmostIdent(lit.Type); id != nil && hasAnyToken(id.Name, isFailClosedToken) {
			return true
		}
		return false
	}
	id := rightmostIdent(expr)
	return id != nil && hasAnyToken(id.Name, isFailClosedToken)
}

func rightmostIdent(expr ast.Expr) *ast.Ident {
	cur := ast.Unparen(expr)
	if un, ok := cur.(*ast.UnaryExpr); ok && un.Op == token.AND {
		cur = ast.Unparen(un.X)
	}
	if lit, ok := cur.(*ast.CompositeLit); ok && lit.Type != nil {
		cur = ast.Unparen(lit.Type)
	}
	switch e := cur.(type) {
	case *ast.Ident:
		return e
	case *ast.SelectorExpr:
		return e.Sel
	default:
		return nil
	}
}

func isBoolConstExpr(info *types.Info, expr ast.Expr, want bool) bool {
	if info == nil || expr == nil {
		return false
	}
	if tv, ok := info.Types[expr]; ok && tv.Value != nil && tv.Value.Kind() == constant.Bool {
		return constant.BoolVal(tv.Value) == want
	}
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	c, ok := info.Uses[id].(*types.Const)
	if !ok || c.Val() == nil || c.Val().Kind() != constant.Bool {
		return false
	}
	return constant.BoolVal(c.Val()) == want
}

func isNilIdent(info *types.Info, expr ast.Expr) bool {
	id, ok := ast.Unparen(expr).(*ast.Ident)
	if !ok {
		return false
	}
	_, isNil := info.Uses[id].(*types.Nil)
	return isNil || id.Name == "nil"
}

func hasAnyToken(name string, pred func(string) bool) bool {
	for _, tok := range splitCamelTokens(name) {
		if pred(tok) {
			return true
		}
	}
	return false
}

func isPermissiveToken(tok string) bool {
	switch tok {
	case "allow", "allowed", "permit", "permitted", "grant", "granted", "approve", "approved":
		return true
	default:
		return false
	}
}

func isFailClosedToken(tok string) bool {
	switch tok {
	case "deny", "denied", "reject", "rejected", "invalid", "unknown", "fail", "failed", "err", "error", "forbid", "forbidden", "closed", "disabled":
		return true
	default:
		return false
	}
}

func splitCamelTokens(name string) []string {
	var tokens []string
	for _, part := range strings.Split(name, "_") {
		if part == "" {
			continue
		}
		tokens = append(tokens, splitCamelWord(part)...)
	}
	return tokens
}

func splitCamelWord(word string) []string {
	runes := []rune(word)
	var out []string
	start := 0
	for i := 1; i < len(runes); i++ {
		if isWordBoundary(runes, i) {
			out = append(out, strings.ToLower(string(runes[start:i])))
			start = i
		}
	}
	if start < len(runes) {
		out = append(out, strings.ToLower(string(runes[start:])))
	}
	return out
}

func isWordBoundary(runes []rune, i int) bool {
	prev, cur := runes[i-1], runes[i]
	if unicode.IsLower(prev) && unicode.IsUpper(cur) {
		return true
	}
	if i+1 < len(runes) && unicode.IsUpper(prev) && unicode.IsUpper(cur) && unicode.IsLower(runes[i+1]) {
		return true
	}
	return false
}
