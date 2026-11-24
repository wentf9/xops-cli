package secrettaint

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/analysis"
)

// checkCallArgTaintRecursion 对非汇点非豁免调用执行过程内/同包过程间污点递归追踪：
// 同时覆盖内联 IIFE、局部闭包变量（localLits）、同包具名函数/方法（含 localFuncs 变量转发）、
// MethodVal 污点接收者注入以及 MethodExpr 的 1 参数偏移。
func (s *taintState) checkCallArgTaintRecursion(call *ast.CallExpr) {
	if call == nil || isSingleArgTypeConversion(s.pass.TypesInfo, call) {
		return
	}
	s.checkFuncLitCallArgs(call)
	if isAllowedAuthOrCryptoConsumer(s.pass.TypesInfo, call) {
		return
	}
	s.checkNamedFuncCallArgs(call)
}

// checkFuncLitCallArgs 对直接传入明文污点实参的局部闭包调用或 IIFE 进行参数到形参的递归污点追踪。
func (s *taintState) checkFuncLitCallArgs(call *ast.CallExpr) {
	for _, lit := range resolveCallbackLits(s.pass.TypesInfo, call.Fun, s.localLits) {
		if lit == nil || lit.Body == nil || lit.Type == nil || s.activeLits[lit] {
			continue
		}
		seeds := s.taintedCallArgParamVars(call.Args, lit.Type.Params)
		if len(seeds) == 0 {
			continue
		}
		s.activeLits[lit] = true
		runTaintAnalysisWithState(
			s.pass, s.facts, s.pkgIdx, lit.Body,
			s.pass.TypesInfo.Scopes[lit.Type], seeds,
			lit.Type.Results, s.reported, s.activeLits, s.activeDecls,
		)
		delete(s.activeLits, lit)
	}
}

// checkNamedFuncCallArgs 对携带明文污点实参或污点接收者的同包具名函数/方法调用执行递归污点追踪，
// 借助 activeDecls 防止直接或相互递归陷入死循环。
func (s *taintState) checkNamedFuncCallArgs(call *ast.CallExpr) {
	if s.pkgIdx == nil {
		return
	}
	targets := resolveCalledFuncs(s.pass.TypesInfo, call.Fun, s.localFuncs)
	if len(targets) == 0 {
		return
	}
	directRecv := directMethodValRecv(s.pass.TypesInfo, call.Fun)
	for _, fn := range targets {
		if fn == nil || isSecretBoxUseMethod(fn) {
			continue
		}
		decl := s.pkgIdx.funcDecls[fn.Origin()]
		if decl == nil || decl.Body == nil || decl.Type == nil || s.activeDecls[decl] {
			continue
		}
		seeds := s.collectNamedDeclTaintSeeds(call, decl, directRecv)
		if len(seeds) == 0 {
			continue
		}
		s.activeDecls[decl] = true
		runTaintAnalysisWithState(
			s.pass, s.facts, s.pkgIdx, decl.Body,
			s.pass.TypesInfo.Scopes[decl.Type], seeds,
			decl.Type.Results, s.reported, s.activeLits, s.activeDecls,
		)
		delete(s.activeDecls, decl)
	}
}

// collectNamedDeclTaintSeeds 按普通函数、MethodVal 与 MethodExpr 三种调用形态映射接收者与形参污点种子。
func (s *taintState) collectNamedDeclTaintSeeds(
	call *ast.CallExpr,
	decl *ast.FuncDecl,
	directRecv ast.Expr,
) []*types.Var {
	var recvExpr ast.Expr
	paramArgs := call.Args
	if s.isMethodExprCall(call, decl) {
		if len(call.Args) == 0 {
			return nil
		}
		recvExpr = call.Args[0]
		paramArgs = call.Args[1:]
	} else if decl.Recv != nil {
		recvExpr = directRecv
	}
	var seeds []*types.Var
	if recvExpr != nil && s.exprContainsTainted(recvExpr) {
		if rv := recvParamVar(s.pass.TypesInfo, decl.Recv); rv != nil {
			seeds = append(seeds, rv)
		}
	}
	return append(seeds, s.taintedCallArgParamVars(paramArgs, decl.Type.Params)...)
}

// isMethodExprCall 判断方法调用是否采用 MethodExpr 形态（含直接 T.Method(recv, ...) 与变量转发 me := T.Method; me(recv, ...)），
// 此时 call.Args[0] 为显式接收者，后续实参相对 decl.Type.Params 存在 1 位偏移。
func (s *taintState) isMethodExprCall(call *ast.CallExpr, decl *ast.FuncDecl) bool {
	if decl.Recv == nil || len(decl.Recv.List) == 0 {
		return false
	}
	if selExpr, ok := unwrapCallbackExpr(s.pass.TypesInfo, call.Fun).(*ast.SelectorExpr); ok {
		if sel := s.pass.TypesInfo.Selections[selExpr]; sel != nil {
			return sel.Kind() == types.MethodExpr
		}
	}
	funType := s.pass.TypesInfo.TypeOf(call.Fun)
	if funType == nil {
		return false
	}
	sig, ok := types.Unalias(funType).Underlying().(*types.Signature)
	if !ok || sig.Params() == nil {
		return false
	}
	paramVars, _ := flattenParamVars(s.pass.TypesInfo, decl.Type.Params)
	return sig.Params().Len() == len(paramVars)+1
}

func (s *taintState) taintedCallArgParamVars(args []ast.Expr, params *ast.FieldList) []*types.Var {
	paramVars, isVariadic := flattenParamVars(s.pass.TypesInfo, params)
	if len(paramVars) == 0 {
		return nil
	}
	var seeds []*types.Var
	for i, arg := range args {
		if !s.exprContainsTainted(arg) {
			continue
		}
		if pVar := paramVarAt(paramVars, isVariadic, i); pVar != nil {
			seeds = append(seeds, pVar)
		}
	}
	return seeds
}

func resolveCalledFuncs(
	info *types.Info,
	fun ast.Expr,
	localFuncs map[*types.Var][]*types.Func,
) []*types.Func {
	if fns := resolveCallbackFuncs(info, fun, localFuncs); len(fns) > 0 {
		return fns
	}
	if fn := resolveGenericInstantiatedFunc(info, fun); fn != nil {
		return []*types.Func{fn}
	}
	return nil
}

func resolveGenericInstantiatedFunc(info *types.Info, fun ast.Expr) *types.Func {
	if info == nil {
		return nil
	}
	var base ast.Expr
	switch e := unwrapCallbackExpr(info, fun).(type) {
	case *ast.IndexExpr:
		base = e.X
	case *ast.IndexListExpr:
		base = e.X
	default:
		return nil
	}
	switch b := ast.Unparen(base).(type) {
	case *ast.Ident:
		fn, _ := info.Uses[b].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		return resolveSelectorCallbackFunc(info, b)
	default:
		return nil
	}
}

func directMethodValRecv(info *types.Info, fun ast.Expr) ast.Expr {
	if info == nil {
		return nil
	}
	selExpr, ok := unwrapCallbackExpr(info, fun).(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if sel := info.Selections[selExpr]; sel != nil && sel.Kind() == types.MethodVal {
		return selExpr.X
	}
	return nil
}

func recvParamVar(info *types.Info, recv *ast.FieldList) *types.Var {
	if info == nil || recv == nil || len(recv.List) == 0 || len(recv.List[0].Names) == 0 {
		return nil
	}
	v, _ := info.Defs[recv.List[0].Names[0]].(*types.Var)
	return v
}

func isSingleArgTypeConversion(info *types.Info, call *ast.CallExpr) bool {
	if info == nil || call == nil || len(call.Args) != 1 || call.Ellipsis.IsValid() {
		return false
	}
	tv, ok := info.Types[ast.Unparen(call.Fun)]
	return ok && tv.IsType()
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
