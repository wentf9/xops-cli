package secrettaint

import (
	"go/ast"
	"go/token"
	"go/types"
	"slices"

	"golang.org/x/tools/go/analysis"
)

// maxCallbackAliasIters 与 maxTaintFixpointIters 保持一致，覆盖深层回调别名链。
const maxCallbackAliasIters = maxTaintFixpointIters

// packageCallbackIndex 索引本包全部函数声明及包级闭包/函数变量的单调并格集合，
// 支持 SecretBox.Use 与明文污点调用递归追踪具名辅助函数、方法与分支覆写回调。
type packageCallbackIndex struct {
	funcDecls map[*types.Func]*ast.FuncDecl
	pkgLits   map[*types.Var][]*ast.FuncLit
	pkgFuncs  map[*types.Var][]*types.Func
}

func collectPackageCallbackIndex(pass *analysis.Pass) *packageCallbackIndex {
	idx := &packageCallbackIndex{
		funcDecls: make(map[*types.Func]*ast.FuncDecl),
		pkgLits:   make(map[*types.Var][]*ast.FuncLit),
		pkgFuncs:  make(map[*types.Var][]*types.Func),
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
			}
		}
	}
}

func recordFilePkgCallbacks(
	info *types.Info,
	file *ast.File,
	lits map[*types.Var][]*ast.FuncLit,
	funcs map[*types.Var][]*types.Func,
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

// analyzeSecretUseCallbackArg 同时遍历实参可能指向的全部匿名闭包与具名函数集合，
// 不因命中 lits 而提前返回，防止条件分支在 FuncLit 与具名函数之间切换时漏检任一路径。
func analyzeSecretUseCallbackArg(
	pass *analysis.Pass,
	facts *secretFactIndex,
	pkgIdx *packageCallbackIndex,
	arg ast.Expr,
	localLits map[*types.Var][]*ast.FuncLit,
	localFuncs map[*types.Var][]*types.Func,
	checkedLits map[*ast.FuncLit]bool,
	checkedDecls map[*ast.FuncDecl]bool,
	reported map[token.Pos]bool,
) {
	for _, lit := range resolveCallbackLits(pass.TypesInfo, arg, localLits) {
		if lit == nil || lit.Body == nil || lit.Type == nil || checkedLits[lit] {
			continue
		}
		checkedLits[lit] = true
		vars := collectCallbackSecretParamVars(pass.TypesInfo, lit.Type.Params)
		runTaintAnalysisWithState(
			pass, facts, pkgIdx, lit.Body, pass.TypesInfo.Scopes[lit.Type], vars, lit.Type.Results, reported,
			map[*ast.FuncLit]bool{lit: true}, make(map[*ast.FuncDecl]bool),
		)
	}
	for _, fn := range resolveCallbackFuncs(pass.TypesInfo, arg, localFuncs) {
		if fn == nil {
			continue
		}
		analyzeResolvedCallbackFunc(pass, facts, pkgIdx, arg, fn, checkedDecls, reported)
	}
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
			runTaintAnalysisWithState(
				pass, facts, pkgIdx, decl.Body, pass.TypesInfo.Scopes[decl.Type], vars, decl.Type.Results, reported,
				make(map[*ast.FuncLit]bool), map[*ast.FuncDecl]bool{decl: true},
			)
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

// collectLocalCallbackMaps 按键深拷贝包级回调切片集并执行局部单调并格不动点传播，
// 严禁使用浅拷贝 maps.Copy 以防污染 pkgIdx 中共享的底层切片数组。
func collectLocalCallbackMaps(
	info *types.Info,
	body *ast.BlockStmt,
	pkgIdx *packageCallbackIndex,
) (map[*types.Var][]*ast.FuncLit, map[*types.Var][]*types.Func) {
	var lits map[*types.Var][]*ast.FuncLit
	var funcs map[*types.Var][]*types.Func
	if pkgIdx != nil {
		lits = cloneLitMap(pkgIdx.pkgLits)
		funcs = cloneFuncMap(pkgIdx.pkgFuncs)
	} else {
		lits = make(map[*types.Var][]*ast.FuncLit)
		funcs = make(map[*types.Var][]*types.Func)
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

func cloneLitMap(src map[*types.Var][]*ast.FuncLit) map[*types.Var][]*ast.FuncLit {
	dst := make(map[*types.Var][]*ast.FuncLit, len(src))
	for k, v := range src {
		dst[k] = slices.Clone(v)
	}
	return dst
}

func cloneFuncMap(src map[*types.Var][]*types.Func) map[*types.Var][]*types.Func {
	dst := make(map[*types.Var][]*types.Func, len(src))
	for k, v := range src {
		dst[k] = slices.Clone(v)
	}
	return dst
}

func propagateLocalCallbackStep(
	info *types.Info,
	body *ast.BlockStmt,
	lits map[*types.Var][]*ast.FuncLit,
	funcs map[*types.Var][]*types.Func,
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
	lits map[*types.Var][]*ast.FuncLit,
	funcs map[*types.Var][]*types.Func,
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
	lits map[*types.Var][]*ast.FuncLit,
	funcs map[*types.Var][]*types.Func,
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

// recordCallbackPair 按单调并格向变量追加全部可能指向的 FuncLit 与具名 *types.Func，
// 不覆盖旧值、不在命中 lits 后提前返回，消除分支覆写导致的不动点震荡与漏检。
func recordCallbackPair(
	info *types.Info,
	lhs, rhs ast.Expr,
	lits map[*types.Var][]*ast.FuncLit,
	funcs map[*types.Var][]*types.Func,
) bool {
	id, ok := ast.Unparen(lhs).(*ast.Ident)
	if !ok || id.Name == "_" {
		return false
	}
	v := lookupVar(info, id)
	if v == nil {
		return false
	}
	changed := false
	for _, lit := range resolveCallbackLits(info, rhs, lits) {
		if appendUniqueLit(lits, v, lit) {
			changed = true
		}
	}
	for _, fn := range resolveCallbackFuncs(info, rhs, funcs) {
		if appendUniqueFunc(funcs, v, fn) {
			changed = true
		}
	}
	return changed
}

func appendUniqueLit(m map[*types.Var][]*ast.FuncLit, v *types.Var, lit *ast.FuncLit) bool {
	if lit == nil || slices.Contains(m[v], lit) {
		return false
	}
	m[v] = append(m[v], lit)
	return true
}

func appendUniqueFunc(m map[*types.Var][]*types.Func, v *types.Var, fn *types.Func) bool {
	if fn == nil || slices.Contains(m[v], fn) {
		return false
	}
	m[v] = append(m[v], fn)
	return true
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

func resolveCallbackLits(info *types.Info, arg ast.Expr, localLits map[*types.Var][]*ast.FuncLit) []*ast.FuncLit {
	switch e := unwrapCallbackExpr(info, arg).(type) {
	case *ast.FuncLit:
		return []*ast.FuncLit{e}
	case *ast.Ident:
		if info != nil && localLits != nil {
			if v, ok := info.Uses[e].(*types.Var); ok && v != nil {
				return localLits[v]
			}
		}
	}
	return nil
}

func resolveCallbackFuncs(info *types.Info, arg ast.Expr, localFuncs map[*types.Var][]*types.Func) []*types.Func {
	if info == nil {
		return nil
	}
	switch e := unwrapCallbackExpr(info, arg).(type) {
	case *ast.Ident:
		if fn, ok := info.Uses[e].(*types.Func); ok && fn != nil {
			return []*types.Func{fn}
		}
		if v, ok := info.Uses[e].(*types.Var); ok && v != nil && localFuncs != nil {
			return localFuncs[v]
		}
	case *ast.SelectorExpr:
		if fn := resolveSelectorCallbackFunc(info, e); fn != nil {
			return []*types.Func{fn}
		}
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
