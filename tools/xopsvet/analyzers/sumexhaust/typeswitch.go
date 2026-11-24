package sumexhaust

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

func checkTypeSwitch(pass *analysis.Pass, ts *ast.TypeSwitchStmt, localFailClosed map[types.Object]bool) {
	switchedExpr := extractSwitchedExpr(ts)
	if switchedExpr == nil {
		return
	}
	switchedType := pass.TypesInfo.TypeOf(switchedExpr)
	info := extractSealedInterface(pass.Pkg, switchedType)
	if info == nil {
		return
	}
	covered := make([]bool, len(info.variants))
	var defaultClause *ast.CaseClause
	for _, stmt := range ts.Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		if cc.List == nil {
			defaultClause = cc
			continue
		}
		matchCaseClause(pass, cc, info, covered)
	}
	if missing := formatMissingVariants(pass.Pkg, info.variants, covered); len(missing) > 0 {
		pass.ReportRangef(ts, "sumexhaust: 对封闭接口 %s 的 type switch 缺少变体: %s", formatInterfaceName(pass.Pkg, info.named, switchedType), strings.Join(missing, ", "))
	}
	if isSecurityDecisionSealed(pass, info, localFailClosed) {
		checkFailClosedDefault(pass, ts, info, switchedType, defaultClause)
	}
}

func extractSwitchedExpr(ts *ast.TypeSwitchStmt) ast.Expr {
	if ts == nil || ts.Body == nil {
		return nil
	}
	var rhs ast.Expr
	switch assign := ts.Assign.(type) {
	case *ast.ExprStmt:
		rhs = assign.X
	case *ast.AssignStmt:
		if len(assign.Rhs) == 1 {
			rhs = assign.Rhs[0]
		}
	}
	if ta, ok := ast.Unparen(rhs).(*ast.TypeAssertExpr); ok {
		return ta.X
	}
	return nil
}

func matchCaseClause(pass *analysis.Pass, cc *ast.CaseClause, info *sealedInfo, covered []bool) {
	for _, expr := range cc.List {
		ct := pass.TypesInfo.TypeOf(expr)
		if ct == nil {
			continue
		}
		ct = types.Unalias(ct)
		if basic, ok := ct.(*types.Basic); ok && basic.Kind() == types.UntypedNil {
			continue
		}
		if subIface, ok := ct.Underlying().(*types.Interface); ok {
			markSubInterfaceCovered(subIface, info, covered)
			continue
		}
		for i, v := range info.variants {
			if variantMatchesCaseType(ct, v) {
				covered[i] = true
			}
		}
	}
}

func markSubInterfaceCovered(subIface *types.Interface, info *sealedInfo, covered []bool) {
	// 禁止 case any / case interface{} / 任意超集或等价全覆盖接口绕过变体穷尽检查。
	if subIface.NumMethods() == 0 || types.Implements(info.iface, subIface) {
		return
	}
	var matched []int
	for i, v := range info.variants {
		if types.Implements(v, subIface) {
			matched = append(matched, i)
		}
	}
	if len(info.variants) > 0 && len(matched) == len(info.variants) {
		return
	}
	for _, idx := range matched {
		covered[idx] = true
	}
}

func variantMatchesCaseType(ct, v types.Type) bool {
	if types.Identical(ct, v) {
		return true
	}
	ctElem, ctIsPtr := unwrapPointerElem(ct)
	vElem, vIsPtr := unwrapPointerElem(v)
	vNamed, ok := isUninstantiatedGenericNamed(vElem)
	ctNamed, isNamed := ctElem.(*types.Named)
	return ctIsPtr == vIsPtr && ok && isNamed && ctNamed != nil && vNamed.Origin() != nil && ctNamed.Origin() == vNamed.Origin()
}

func unwrapPointerElem(t types.Type) (types.Type, bool) {
	u := types.Unalias(t)
	if ptr, ok := u.(*types.Pointer); ok {
		return types.Unalias(ptr.Elem()), true
	}
	return u, false
}

func shortQualifier(passPkg *types.Package) types.Qualifier {
	return func(p *types.Package) string {
		if p == nil || p == passPkg {
			return ""
		}
		return p.Name()
	}
}

func formatMissingVariants(passPkg *types.Package, variants []types.Type, covered []bool) []string {
	var missing []string
	qual := shortQualifier(passPkg)
	for i, v := range variants {
		if !covered[i] {
			missing = append(missing, types.TypeString(v, qual))
		}
	}
	return missing
}

func formatInterfaceName(passPkg *types.Package, named *types.Named, switchedType types.Type) string {
	if named != nil {
		return types.TypeString(named, shortQualifier(passPkg))
	}
	return types.TypeString(switchedType, shortQualifier(passPkg))
}
