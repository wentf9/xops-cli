package secrettaint

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"

	"golang.org/x/tools/go/analysis"
)

// maxCallbackAliasIters 与 maxTaintFixpointIters 保持一致，覆盖深层回调别名链。
const maxCallbackAliasIters = maxTaintFixpointIters

// packageCallbackIndex 索引本包全部函数声明及包级闭包/函数变量，支持 SecretBox.Use 追踪具名辅助函数与方法。
type packageCallbackIndex struct {
	funcDecls map[*types.Func]*ast.FuncDecl
	funcFiles map[*ast.FuncDecl][]*ast.CommentGroup
	pkgLits   map[*types.Var]*ast.FuncLit
	pkgFuncs  map[*types.Var]*types.Func
}

func collectPackageCallbackIndex(pass *analysis.Pass) *packageCallbackIndex {
	idx := &packageCallbackIndex{
		funcDecls: make(map[*types.Func]*ast.FuncDecl),
		funcFiles: make(map[*ast.FuncDecl][]*ast.CommentGroup),
		pkgLits:   make(map[*types.Var]*ast.FuncLit),
		pkgFuncs:  make(map[*types.Var]*types.Func),
	}
	indexPackageFuncDecls(pass, idx)
	for range maxCallbackAliasIters {
		changed := false
		for _, file := range pass.Files {
			if recordFilePkgCallbacks(pass.TypesInfo, file, idx.pkgLits, idx.pkgFuncs) {
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return idx
}

func indexPackageFuncDecls(pass *analysis.Pass, idx *packageCallbackIndex) {
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil {
				continue
			}
			if fnObj, ok := pass.TypesInfo.Defs[fn.Name].(*types.Func); ok && fnObj != nil {
				idx.funcDecls[fnObj.Origin()] = fn
				idx.funcFiles[fn] = file.Comments
			}
		}
	}
}

func recordFilePkgCallbacks(
	info *types.Info,
	file *ast.File,
	lits map[*types.Var]*ast.FuncLit,
	funcs map[*types.Var]*types.Func,
) bool {
	changed := false
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if ok && recordValueSpecCallbacks(info, vs, lits, funcs) {
				changed = true
			}
		}
	}
	return changed
}

func checkSecretUseCallsInBody(
	pass *analysis.Pass,
	facts *secretFactIndex,
	pkgIdx *packageCallbackIndex,
	body *ast.BlockStmt,
	checkedLits map[*ast.FuncLit]bool,
	checkedDecls map[*ast.FuncDecl]bool,
	reported map[token.Pos]bool,
) {
	localLits, localFuncs := collectLocalCallbackMaps(pass.TypesInfo, body, pkgIdx)
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !facts.isSecretUseCall(pass, call) {
			return true
		}
		for _, arg := range call.Args {
			analyzeSecretUseCallbackArg(pass, facts, pkgIdx, arg, localLits, localFuncs, checkedLits, checkedDecls, reported)
		}
		return true
	})
}

func analyzeSecretUseCallbackArg(
	pass *analysis.Pass,
	facts *secretFactIndex,
	pkgIdx *packageCallbackIndex,
	arg ast.Expr,
	localLits map[*types.Var]*ast.FuncLit,
	localFuncs map[*types.Var]*types.Func,
	checkedLits map[*ast.FuncLit]bool,
	checkedDecls map[*ast.FuncDecl]bool,
	reported map[token.Pos]bool,
) {
	if lit := resolveCallbackLit(pass.TypesInfo, arg, localLits); lit != nil {
		if lit.Body == nil || lit.Type == nil || checkedLits[lit] {
			return
		}
		checkedLits[lit] = true
		vars := collectCallbackSecretParamVars(pass.TypesInfo, lit.Type.Params)
		runTaintAnalysis(pass, facts, pkgIdx, lit.Body, pass.TypesInfo.Scopes[lit.Type], vars, lit.Type.Results, reported)
		return
	}
	fn := resolveCallbackFunc(pass.TypesInfo, arg, localFuncs)
	if fn == nil {
		return
	}
	analyzeResolvedCallbackFunc(pass, facts, pkgIdx, arg, fn, checkedDecls, reported)
}

func analyzeResolvedCallbackFunc(
	pass *analysis.Pass,
	facts *secretFactIndex,
	pkgIdx *packageCallbackIndex,
	arg ast.Expr,
	fn *types.Func,
	checkedDecls map[*ast.FuncDecl]bool,
	reported map[token.Pos]bool,
) {
	if pkgIdx != nil {
		if decl := pkgIdx.funcDecls[fn.Origin()]; decl != nil && decl.Type != nil {
			if checkedDecls[decl] {
				return
			}
			checkedDecls[decl] = true
			vars := collectCallbackSecretParamVars(pass.TypesInfo, decl.Type.Params)
			runTaintAnalysis(pass, facts, pkgIdx, decl.Body, pass.TypesInfo.Scopes[decl.Type], vars, decl.Type.Results, reported)
			return
		}
	}
	if facts.hasFuncSecretUseFact(pass, fn) {
		return
	}
	if fn.Pkg() != nil && fn.Pkg() != pass.Pkg {
		reportLeakOnce(pass, reported, arg, "secrettaint: 禁止将未标注 //xops:secretuse 的跨包函数传入 SecretBox.Use")
		return
	}
	reportLeakOnce(pass, reported, arg, "secrettaint: 禁止将未标注 //xops:secretuse 的接口方法或无体函数传入 SecretBox.Use")
}

func collectLocalCallbackMaps(
	info *types.Info,
	body *ast.BlockStmt,
	pkgIdx *packageCallbackIndex,
) (map[*types.Var]*ast.FuncLit, map[*types.Var]*types.Func) {
	lits := make(map[*types.Var]*ast.FuncLit)
	funcs := make(map[*types.Var]*types.Func)
	if pkgIdx != nil {
		maps.Copy(lits, pkgIdx.pkgLits)
		maps.Copy(funcs, pkgIdx.pkgFuncs)
	}
	if body == nil {
		return lits, funcs
	}
	for range maxCallbackAliasIters {
		if !propagateLocalCallbackStep(info, body, lits, funcs) {
			break
		}
	}
	return lits, funcs
}

func propagateLocalCallbackStep(
	info *types.Info,
	body *ast.BlockStmt,
	lits map[*types.Var]*ast.FuncLit,
	funcs map[*types.Var]*types.Func,
) bool {
	changed := false
	ast.Inspect(body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			if recordAssignCallbacks(info, stmt, lits, funcs) {
				changed = true
			}
		case *ast.ValueSpec:
			if recordValueSpecCallbacks(info, stmt, lits, funcs) {
				changed = true
			}
		}
		return true
	})
	return changed
}

func recordAssignCallbacks(
	info *types.Info,
	stmt *ast.AssignStmt,
	lits map[*types.Var]*ast.FuncLit,
	funcs map[*types.Var]*types.Func,
) bool {
	if len(stmt.Lhs) != len(stmt.Rhs) {
		return false
	}
	changed := false
	for i := range stmt.Lhs {
		if recordCallbackPair(info, stmt.Lhs[i], stmt.Rhs[i], lits, funcs) {
			changed = true
		}
	}
	return changed
}

func recordValueSpecCallbacks(
	info *types.Info,
	vs *ast.ValueSpec,
	lits map[*types.Var]*ast.FuncLit,
	funcs map[*types.Var]*types.Func,
) bool {
	if len(vs.Names) != len(vs.Values) {
		return false
	}
	changed := false
	for i := range vs.Names {
		if recordCallbackPair(info, vs.Names[i], vs.Values[i], lits, funcs) {
			changed = true
		}
	}
	return changed
}

func recordCallbackPair(
	info *types.Info,
	lhs, rhs ast.Expr,
	lits map[*types.Var]*ast.FuncLit,
	funcs map[*types.Var]*types.Func,
) bool {
	id, ok := ast.Unparen(lhs).(*ast.Ident)
	if !ok || id.Name == "_" {
		return false
	}
	v := lookupVar(info, id)
	if v == nil {
		return false
	}
	if lit := resolveCallbackLit(info, rhs, lits); lit != nil && lits[v] != lit {
		lits[v] = lit
		return true
	}
	if fn := resolveCallbackFunc(info, rhs, funcs); fn != nil && funcs[v] != fn {
		funcs[v] = fn
		return true
	}
	return false
}

// unwrapCallbackExpr 剥离括号、类型断言与单参类型转换，还原底层回调字面量或函数引用表达式。
func unwrapCallbackExpr(info *types.Info, expr ast.Expr) ast.Expr {
	for expr != nil {
		switch e := ast.Unparen(expr).(type) {
		case *ast.TypeAssertExpr:
			expr = e.X
		case *ast.CallExpr:
			if info != nil && len(e.Args) == 1 {
				if tv, ok := info.Types[e.Fun]; ok && tv.IsType() {
					expr = e.Args[0]
					continue
				}
			}
			return e
		default:
			return e
		}
	}
	return nil
}

func resolveCallbackLit(info *types.Info, arg ast.Expr, localLits map[*types.Var]*ast.FuncLit) *ast.FuncLit {
	switch e := unwrapCallbackExpr(info, arg).(type) {
	case *ast.FuncLit:
		return e
	case *ast.Ident:
		if info != nil && localLits != nil {
			if v, ok := info.Uses[e].(*types.Var); ok && v != nil {
				return localLits[v]
			}
		}
	}
	return nil
}

func resolveCallbackFunc(info *types.Info, arg ast.Expr, localFuncs map[*types.Var]*types.Func) *types.Func {
	if info == nil {
		return nil
	}
	switch e := unwrapCallbackExpr(info, arg).(type) {
	case *ast.Ident:
		if fn, ok := info.Uses[e].(*types.Func); ok && fn != nil {
			return fn
		}
		if v, ok := info.Uses[e].(*types.Var); ok && v != nil && localFuncs != nil {
			return localFuncs[v]
		}
	case *ast.SelectorExpr:
		return resolveSelectorCallbackFunc(info, e)
	}
	return nil
}

func resolveSelectorCallbackFunc(info *types.Info, selExpr *ast.SelectorExpr) *types.Func {
	if sel := info.Selections[selExpr]; sel != nil {
		if fn, ok := sel.Obj().(*types.Func); ok && fn != nil {
			return fn
		}
	}
	fn, _ := info.Uses[selExpr.Sel].(*types.Func)
	return fn
}

// flattenParamVars 按位置展开函数形参表为 *types.Var 切片（未命名形参以 nil 占位），并标记是否为可变参数。
func flattenParamVars(info *types.Info, fl *ast.FieldList) ([]*types.Var, bool) {
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

func paramVarAt(vars []*types.Var, isVariadic bool, idx int) *types.Var {
	if idx < len(vars) {
		return vars[idx]
	}
	if isVariadic && len(vars) > 0 {
		return vars[len(vars)-1]
	}
	return nil
}

func reportLeakOnce(pass *analysis.Pass, reported map[token.Pos]bool, rng ast.Node, format string, args ...any) {
	if rng == nil || reported[rng.Pos()] {
		return
	}
	reported[rng.Pos()] = true
	pass.ReportRangef(rng, format, args...)
}
