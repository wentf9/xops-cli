package noimplicit

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

const cmdXopsPkgPath = vetutil.ModulePrefix + "/cmd/xops"

// collectSentinelVars 预收集本包中所有具备哨兵错误签名（Err*/err* 且类型为内置 error）的包级变量。
func collectSentinelVars(pass *analysis.Pass) map[*types.Var]bool {
	sentinels := make(map[*types.Var]bool)
	if pass.TypesInfo == nil {
		return sentinels
	}
	vetutil.ForEachPkgVarSpec(pass, false, func(_ *ast.GenDecl, vs *ast.ValueSpec) {
		if len(vs.Names) != 1 || len(vs.Values) != 1 || !isSentinelName(vs.Names[0].Name) ||
			(vs.Type != nil && !vetutil.IsErrorInterfaceType(pass.TypesInfo.TypeOf(vs.Type))) {
			return
		}
		if v, ok := pass.TypesInfo.Defs[vs.Names[0]].(*types.Var); ok && v != nil && vetutil.IsErrorInterfaceType(v.Type()) {
			sentinels[v] = true
		}
	})
	return sentinels
}

// collectBuildVars 独立收集 cmd/xops package main 非测试文件中满足 6 重硬约束的 //xops:buildvar 变量。
func collectBuildVars(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) map[*types.Var]bool {
	buildVars := make(map[*types.Var]bool)
	if pass == nil || pass.TypesInfo == nil || pass.Pkg == nil ||
		pkgInfo.IsExternalTest || pkgInfo.BasePath != cmdXopsPkgPath || pass.Pkg.Name() != "main" {
		return buildVars
	}
	vetutil.ForEachPkgVarSpec(pass, true, func(gen *ast.GenDecl, vs *ast.ValueSpec) {
		if v := validBuildVar(pass.TypesInfo, gen, vs); v != nil {
			buildVars[v] = true
		}
	})
	return buildVars
}

func validBuildVar(info *types.Info, gen *ast.GenDecl, vs *ast.ValueSpec) *types.Var {
	hasDir := vs != nil && (vetutil.HasDirective(vs.Doc, vetutil.DirectiveBuildVar) ||
		vetutil.HasDirective(vs.Comment, vetutil.DirectiveBuildVar) ||
		(gen != nil && len(gen.Specs) == 1 && vetutil.HasDirective(gen.Doc, vetutil.DirectiveBuildVar)))
	if !hasDir || len(vs.Names) != 1 || vs.Names[0].Name == "_" || vs.Names[0].IsExported() {
		return nil
	}
	v, ok := info.Defs[vs.Names[0]].(*types.Var)
	if !ok || v == nil {
		return nil
	}
	basic, ok := v.Type().(*types.Basic)
	if !ok || basic.Kind() != types.String || !isValidBuildVarInit(info, vs.Values) {
		return nil
	}
	return v
}

func isValidBuildVarInit(info *types.Info, values []ast.Expr) bool {
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	tv, ok := info.Types[values[0]]
	return ok && tv.Value != nil && tv.Value.Kind() == constant.String
}

func checkPkgVarDecl(pass *analysis.Pass, gen *ast.GenDecl, sentinels, buildVars map[*types.Var]bool) {
	for _, spec := range gen.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || isInterfaceAssertionSpec(pass.TypesInfo, vs) ||
			isImmutableSentinelSpec(pass.TypesInfo, vs, sentinels) ||
			isRecordedBuildVarSpec(pass.TypesInfo, vs, buildVars) {
			continue
		}
		pass.ReportRangef(vs, "noimplicit: 禁止声明可变包级 var（仅允许编译期接口断言 var _ I = (*T)(nil)、不可变哨兵错误及 cmd/xops 只读 //xops:buildvar）")
	}
}

func isRecordedBuildVarSpec(info *types.Info, vs *ast.ValueSpec, buildVars map[*types.Var]bool) bool {
	if info == nil || len(vs.Names) != 1 {
		return false
	}
	v, ok := info.Defs[vs.Names[0]].(*types.Var)
	return ok && buildVars[v]
}

// isInterfaceAssertionSpec 仅豁免形如 `var _ I = (*T)(nil)` 的编译期零副作用接口断言。
func isInterfaceAssertionSpec(info *types.Info, vs *ast.ValueSpec) bool {
	return info != nil && vs.Type != nil && len(vs.Names) > 0 && len(vs.Names) == len(vs.Values) &&
		!slices.ContainsFunc(vs.Names, func(n *ast.Ident) bool { return n.Name != "_" }) &&
		!slices.ContainsFunc(vs.Values, func(v ast.Expr) bool { return !vetutil.IsCompileTimePureExpr(info, v) })
}

func isImmutableSentinelSpec(info *types.Info, vs *ast.ValueSpec, sentinels map[*types.Var]bool) bool {
	if info == nil || len(vs.Names) != 1 || len(vs.Values) != 1 || !isSentinelName(vs.Names[0].Name) ||
		(vs.Type != nil && !vetutil.IsErrorInterfaceType(info.TypeOf(vs.Type))) {
		return false
	}
	call, ok := ast.Unparen(vs.Values[0]).(*ast.CallExpr)
	if !ok {
		return false
	}
	callee := vetutil.ResolveCalledObject(info, call)
	if vetutil.IsPkgSymbol(callee, "errors", "New") {
		return len(call.Args) == 1 && isConstExpr(info, call.Args[0])
	}
	return vetutil.IsPkgSymbol(callee, "fmt", "Errorf") && len(call.Args) > 0 && isConstExpr(info, call.Args[0]) &&
		!slices.ContainsFunc(call.Args[1:], func(arg ast.Expr) bool { return !isPureErrorArg(info, arg, sentinels) })
}

func isPureErrorArg(info *types.Info, expr ast.Expr, sentinels map[*types.Var]bool) bool {
	if isConstExpr(info, expr) {
		return true
	}
	var obj types.Object
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		obj = info.Uses[e]
	case *ast.SelectorExpr:
		obj = info.Uses[e.Sel]
	}
	v, ok := obj.(*types.Var)
	return ok && v != nil && (sentinels[v] || (v.Pkg() != nil && v.Exported() && !v.IsField() && v.Parent() == v.Pkg().Scope() && vetutil.IsErrorInterfaceType(v.Type())))
}

func isConstExpr(info *types.Info, expr ast.Expr) bool {
	tv, ok := info.Types[expr]
	return ok && tv.Value != nil
}

func isSentinelName(name string) bool {
	return name != "_" && (strings.HasPrefix(name, "Err") || strings.HasPrefix(name, "err"))
}

func checkImmutableVarMutations(pass *analysis.Pass, sentinels, buildVars map[*types.Var]bool) {
	if pass.TypesInfo == nil {
		return
	}
	vetutil.InspectorOf(pass).Preorder([]ast.Node{
		(*ast.AssignStmt)(nil), (*ast.RangeStmt)(nil), (*ast.IncDecStmt)(nil), (*ast.UnaryExpr)(nil),
	}, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				reportIfImmutableVarExpr(pass, lhs, sentinels, buildVars, false)
			}
		case *ast.RangeStmt:
			if node.Tok == token.ASSIGN {
				reportIfImmutableVarExpr(pass, node.Key, sentinels, buildVars, false)
				reportIfImmutableVarExpr(pass, node.Value, sentinels, buildVars, false)
			}
		case *ast.IncDecStmt:
			reportIfImmutableVarExpr(pass, node.X, sentinels, buildVars, false)
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				reportIfImmutableVarExpr(pass, node.X, sentinels, buildVars, true)
			}
		}
	})
}

func reportIfImmutableVarExpr(pass *analysis.Pass, expr ast.Expr, sentinels, buildVars map[*types.Var]bool, isAddr bool) {
	target, v, name := resolvePkgVarExpr(pass.TypesInfo, expr)
	if v == nil {
		return
	}
	label := ""
	switch {
	case buildVars[v]:
		label = "只读构建变量"
	case isTrackedSentinelVar(v, sentinels):
		label = "哨兵错误"
	default:
		return
	}
	if isAddr {
		pass.ReportRangef(target, "noimplicit: 禁止对%s %s 取地址", label, name)
	} else {
		pass.ReportRangef(target, "noimplicit: 禁止在运行期修改%s %s", label, name)
	}
}

func resolvePkgVarExpr(info *types.Info, expr ast.Expr) (ast.Expr, *types.Var, string) {
	if expr == nil {
		return nil, nil, ""
	}
	switch target := ast.Unparen(expr).(type) {
	case *ast.Ident:
		v, _ := info.Uses[target].(*types.Var)
		return target, v, target.Name
	case *ast.SelectorExpr:
		if info.Selections[target] != nil {
			return nil, nil, ""
		}
		v, _ := info.Uses[target.Sel].(*types.Var)
		return target, v, target.Sel.Name
	default:
		return nil, nil, ""
	}
}

// isTrackedSentinelVar 保护全包（含跨包标准库）所有包级非字段 error 接口变量不可在运行期篡改或取地址。
func isTrackedSentinelVar(v *types.Var, sentinels map[*types.Var]bool) bool {
	return v != nil && (sentinels[v] || (v.Pkg() != nil && !v.IsField() && v.Parent() == v.Pkg().Scope() && vetutil.IsErrorInterfaceType(v.Type())))
}
