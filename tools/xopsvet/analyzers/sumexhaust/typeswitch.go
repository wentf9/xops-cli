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
		pass.ReportRangef(
			ts,
			"sumexhaust: 对封闭接口 %s 的 type switch 缺少变体: %s",
			formatInterfaceName(pass.Pkg, info.named, switchedType),
			strings.Join(missing, ", "),
		)
	}

	if isSecurityDecisionSealed(pass, info, localFailClosed) {
		checkFailClosedDefault(pass, ts, info, switchedType, defaultClause)
	}
}

func extractSwitchedExpr(ts *ast.TypeSwitchStmt) ast.Expr {
	if ts == nil || ts.Body == nil {
		return nil
	}
	switch assign := ts.Assign.(type) {
	case *ast.ExprStmt:
		if ta, ok := ast.Unparen(assign.X).(*ast.TypeAssertExpr); ok {
			return ta.X
		}
	case *ast.AssignStmt:
		if len(assign.Rhs) == 1 {
			if ta, ok := ast.Unparen(assign.Rhs[0]).(*ast.TypeAssertExpr); ok {
				return ta.X
			}
		}
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
		markCaseTypeCovered(ct, info, covered)
	}
}

func markCaseTypeCovered(ct types.Type, info *sealedInfo, covered []bool) {
	if subIface, ok := asInterfaceType(ct); ok {
		markSubInterfaceCovered(subIface, info, covered)
		return
	}
	for i, v := range info.variants {
		if variantMatchesCaseType(ct, v) {
			covered[i] = true
		}
	}
}

func asInterfaceType(t types.Type) (*types.Interface, bool) {
	u := types.Unalias(t)
	if iface, ok := u.(*types.Interface); ok {
		return iface, true
	}
	if named, ok := u.(*types.Named); ok {
		iface, isIface := named.Underlying().(*types.Interface)
		return iface, isIface
	}
	return nil, false
}

func markSubInterfaceCovered(subIface *types.Interface, info *sealedInfo, covered []bool) {
	// 禁止 case any / case interface{} / 任意超集或等价接口（如 interface{ Tag() } 或 interface{ sealed*() }）绕过变体穷尽检查。
	if subIface.NumMethods() == 0 || types.Implements(info.iface, subIface) {
		return
	}
	var matched []int
	for i, v := range info.variants {
		if types.Implements(v, subIface) {
			matched = append(matched, i)
		}
	}
	// 当子接口恰好覆盖全部必填变体（含单变体封闭接口）时，视为等价全覆盖逃生口并拒绝计入覆盖。
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
	if ctIsPtr != vIsPtr {
		return false
	}
	vNamed, ok := isUninstantiatedGenericNamed(vElem)
	if !ok {
		return false
	}
	ctNamed, ok := ctElem.(*types.Named)
	if !ok || ctNamed == nil {
		return false
	}
	return vNamed.Origin() != nil && ctNamed.Origin() == vNamed.Origin()
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
	qual := shortQualifier(passPkg)
	if named != nil {
		return types.TypeString(named, qual)
	}
	return types.TypeString(switchedType, qual)
}
