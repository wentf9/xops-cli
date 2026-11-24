package noimplicit

import (
	"go/ast"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"
)

func checkContextAndAnonIfaces(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	allowCtx := vetutil.AllowContextValue(pkgInfo)
	ctxIface := findContextInterface(pass)
	vetutil.InspectorOf(pass).Preorder([]ast.Node{
		(*ast.Ident)(nil), (*ast.SelectorExpr)(nil), (*ast.TypeSpec)(nil),
		(*ast.TypeAssertExpr)(nil), (*ast.TypeSwitchStmt)(nil),
	}, func(n ast.Node) {
		checkContextOrIfaceNode(pass, n, allowCtx, ctxIface)
	})
	if !allowCtx {
		checkContextErasureAndInvokeSSA(pass, ctxIface)
	}
}

func checkContextOrIfaceNode(pass *analysis.Pass, n ast.Node, allowCtx bool, ctxIface *types.Interface) {
	switch node := n.(type) {
	case *ast.Ident:
		if !allowCtx && pass.TypesInfo != nil && vetutil.IsPkgSymbol(pass.TypesInfo.Uses[node], "context", "WithValue") {
			pass.ReportRangef(node, "noimplicit: 白名单包 core/internal/foundation/trace 之外禁止使用 context.WithValue")
		}
	case *ast.SelectorExpr:
		if !allowCtx {
			checkContextSelection(pass, node, ctxIface)
		}
	case *ast.TypeSpec:
		if !allowCtx {
			checkNarrowValueIfaceDecl(pass, node)
		}
	case *ast.TypeAssertExpr:
		if node.Type != nil && containsAnonIface(node.Type) {
			pass.ReportRangef(node.Type, "noimplicit: 禁止匿名接口断言 x.(interface{...})，请使用具名接口")
		}
	case *ast.TypeSwitchStmt:
		checkAnonIfaceTypeSwitch(pass, node)
	}
}

func checkAnonIfaceTypeSwitch(pass *analysis.Pass, node *ast.TypeSwitchStmt) {
	if node.Body == nil {
		return
	}
	for _, stmt := range node.Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, expr := range cc.List {
			if containsAnonIface(expr) {
				pass.ReportRangef(expr, "noimplicit: 禁止在 type switch 中使用匿名接口 case interface{...}")
			}
		}
	}
}

func checkContextSelection(pass *analysis.Pass, sel *ast.SelectorExpr, ctxIface *types.Interface) {
	if pass.TypesInfo == nil || sel.Sel == nil || sel.Sel.Name != "Value" {
		return
	}
	if s := pass.TypesInfo.Selections[sel]; s != nil {
		if vetutil.IsPkgSymbol(s.Obj(), "context", "Value") || implementsContextIface(s.Recv(), ctxIface) {
			pass.ReportRangef(sel.Sel, "noimplicit: 白名单包 core/internal/foundation/trace 之外禁止调用 ctx.Value")
		}
		return
	}
	if vetutil.IsPkgSymbol(pass.TypesInfo.Uses[sel.Sel], "context", "Value") {
		pass.ReportRangef(sel.Sel, "noimplicit: 白名单包 core/internal/foundation/trace 之外禁止引用 context.Context.Value")
	}
}

// checkNarrowValueIfaceDecl 在 trace 之外禁止声明暴露 Value(any) any 的非 context.Context 窄接口。
func checkNarrowValueIfaceDecl(pass *analysis.Pass, ts *ast.TypeSpec) {
	if pass.TypesInfo == nil || ts == nil || ts.Assign.IsValid() {
		return
	}
	if _, isIfaceAST := ts.Type.(*ast.InterfaceType); !isIfaceAST {
		return
	}
	if obj := pass.TypesInfo.Defs[ts.Name]; obj != nil && obj.Type() != nil {
		if iface, ok := types.Unalias(obj.Type()).Underlying().(*types.Interface); ok && isNarrowValueAnyIface(iface) {
			pass.ReportRangef(ts.Name, "noimplicit: 白名单包 core/internal/foundation/trace 之外禁止声明暴露 Value(any) any 的窄接口（除非显式嵌入 context.Context）")
		}
	}
}

// checkContextErasureAndInvokeSSA 基于 vetssa 封堵窄接口擦除、TypeAssert、IsInvoke 与泛型约束绕过（HIGH-3）。
func checkContextErasureAndInvokeSSA(pass *analysis.Pass, ctxIface *types.Interface) {
	s := vetssa.PackageSSA(pass)
	if s == nil {
		return
	}
	var diags []vetutil.Diag
	vetssa.ForEachFuncInst(vetssa.AllFuncs(s), func(fn *ssa.Function, inst ssa.Instruction) {
		checkContextSSAInst(pass, fn, inst, ctxIface, &diags)
	})
	checkContextGenericInstances(pass, ctxIface, &diags)
	vetutil.ReportSortedDedup(pass, diags, true)
}

func checkContextSSAInst(pass *analysis.Pass, fn *ssa.Function, inst ssa.Instruction, ctxIface *types.Interface, diags *[]vetutil.Diag) {
	const msg = "noimplicit: 白名单包 core/internal/foundation/trace 之外禁止将 context.Context 擦除或调用 Value(any) any 窄接口"
	if src, dst, ok := contextCastOperands(inst); ok {
		if implementsContextIface(src, ctxIface) && typeIsNarrowValueAnyIface(dst) {
			vetssa.AppendDiag(pass, diags, fn, inst, msg)
		}
		return
	}
	switch ins := inst.(type) {
	case *ssa.TypeAssert:
		if typeIsNarrowValueAnyIface(ins.AssertedType) {
			vetssa.AppendDiag(pass, diags, fn, ins, msg)
		}
	case ssa.CallInstruction:
		if cc := ins.Common(); cc != nil && cc.IsInvoke() && isValueAnyAnyMethod(cc.Method) && !implementsContextIface(cc.Value.Type(), ctxIface) {
			vetssa.AppendDiag(pass, diags, fn, ins, msg)
		}
	}
}

func contextCastOperands(inst ssa.Instruction) (types.Type, types.Type, bool) {
	switch ins := inst.(type) {
	case *ssa.MakeInterface:
		return ins.X.Type(), ins.Type(), true
	case *ssa.ChangeInterface:
		return ins.X.Type(), ins.Type(), true
	case *ssa.ChangeType:
		return ins.X.Type(), ins.Type(), true
	default:
		return nil, nil, false
	}
}

func checkContextGenericInstances(pass *analysis.Pass, ctxIface *types.Interface, diags *[]vetutil.Diag) {
	if pass.TypesInfo == nil || ctxIface == nil {
		return
	}
	for ident, inst := range pass.TypesInfo.Instances {
		tparams := genericTypeParamsOf(pass.TypesInfo.Uses[ident])
		if ident == nil || !ident.Pos().IsValid() || inst.TypeArgs == nil || tparams == nil {
			continue
		}
		for i := range min(tparams.Len(), inst.TypeArgs.Len()) {
			if typeIsNarrowValueAnyIface(tparams.At(i).Constraint()) && implementsContextIface(inst.TypeArgs.At(i), ctxIface) {
				*diags = append(*diags, vetutil.Diag{
					Pos: ident.Pos(), End: ident.End(),
					Msg: "noimplicit: 白名单包 core/internal/foundation/trace 之外禁止以 context.Context 实例化含 Value(any) any 约束的泛型",
				})
				break
			}
		}
	}
}

func genericTypeParamsOf(obj types.Object) *types.TypeParamList {
	switch o := obj.(type) {
	case *types.Func:
		if sig, ok := o.Type().(*types.Signature); ok {
			return sig.TypeParams()
		}
	case *types.TypeName:
		if named, ok := types.Unalias(o.Type()).(*types.Named); ok {
			return named.TypeParams()
		}
	}
	return nil
}

func typeIsNarrowValueAnyIface(t types.Type) bool {
	if t == nil {
		return false
	}
	u := types.Unalias(t)
	// 标准库 context.Context 自身合法，严禁误杀实现 context.Context 的结构体转为 context.Context。
	if named, ok := u.(*types.Named); ok && vetutil.IsPkgSymbol(named.Obj(), "context", "Context") {
		return false
	}
	iface, ok := u.Underlying().(*types.Interface)
	return ok && isNarrowValueAnyIface(iface)
}

func isNarrowValueAnyIface(iface *types.Interface) bool {
	if iface == nil || embedsContextContext(iface, make(map[*types.Interface]bool)) {
		return false
	}
	for i := range iface.NumMethods() {
		if isValueAnyAnyMethod(iface.Method(i)) {
			return true
		}
	}
	return false
}

func embedsContextContext(iface *types.Interface, seen map[*types.Interface]bool) bool {
	if iface == nil || seen[iface] {
		return false
	}
	seen[iface] = true
	for i := range iface.NumEmbeddeds() {
		emb := types.Unalias(iface.EmbeddedType(i))
		if named, ok := emb.(*types.Named); ok && vetutil.IsPkgSymbol(named.Obj(), "context", "Context") {
			return true
		}
		if sub, ok := emb.Underlying().(*types.Interface); ok && embedsContextContext(sub, seen) {
			return true
		}
	}
	return false
}

// isValueAnyAnyMethod 精确匹配 1 空接口入参 + 1 空接口返回值的 Value(any) any 签名，不误伤 0 参方法。
func isValueAnyAnyMethod(fn *types.Func) bool {
	if fn == nil || fn.Name() != "Value" {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	return ok && !sig.Variadic() && sig.Params().Len() == 1 && sig.Results().Len() == 1 &&
		isEmptyIfaceType(sig.Params().At(0).Type()) && isEmptyIfaceType(sig.Results().At(0).Type())
}

func isEmptyIfaceType(t types.Type) bool {
	if t == nil {
		return false
	}
	u := types.Unalias(t)
	if _, isTP := u.(*types.TypeParam); isTP {
		return false
	}
	iface, ok := u.Underlying().(*types.Interface)
	return ok && iface.Empty()
}

func implementsContextIface(t types.Type, ctxIface *types.Interface) bool {
	return t != nil && ctxIface != nil && (types.Implements(t, ctxIface) || types.Implements(types.NewPointer(t), ctxIface))
}

func findContextInterface(pass *analysis.Pass) *types.Interface {
	if pass.Pkg == nil {
		return nil
	}
	visited := make(map[*types.Package]bool)
	for queue := slices.Clone(pass.Pkg.Imports()); len(queue) > 0; {
		pkg := queue[0]
		queue = queue[1:]
		if pkg == nil || visited[pkg] {
			continue
		}
		visited[pkg] = true
		if pkg.Path() == "context" {
			if obj := pkg.Scope().Lookup("Context"); obj != nil {
				iface, _ := obj.Type().Underlying().(*types.Interface)
				return iface
			}
			return nil
		}
		queue = append(queue, pkg.Imports()...)
	}
	return nil
}

// containsAnonIface 递归检查类型表达式中是否内嵌匿名接口（含指针/容器/签名/结构体与泛型实参）。
func containsAnonIface(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.InterfaceType:
		return true
	case *ast.ParenExpr:
		return containsAnonIface(e.X)
	case *ast.StarExpr:
		return containsAnonIface(e.X)
	case *ast.ArrayType:
		return containsAnonIface(e.Elt)
	case *ast.Ellipsis:
		return containsAnonIface(e.Elt)
	case *ast.ChanType:
		return containsAnonIface(e.Value)
	case *ast.MapType:
		return containsAnonIface(e.Key) || containsAnonIface(e.Value)
	case *ast.FuncType:
		return fieldListHasAnonIface(e.Params) || fieldListHasAnonIface(e.Results)
	case *ast.StructType:
		return fieldListHasAnonIface(e.Fields)
	case *ast.IndexExpr:
		return containsAnonIface(e.X) || containsAnonIface(e.Index)
	case *ast.IndexListExpr:
		return containsAnonIface(e.X) || slices.ContainsFunc(e.Indices, containsAnonIface)
	}
	return false
}

func fieldListHasAnonIface(fl *ast.FieldList) bool {
	return fl != nil && slices.ContainsFunc(fl.List, func(f *ast.Field) bool { return containsAnonIface(f.Type) })
}
