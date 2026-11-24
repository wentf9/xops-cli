package digestcover

import (
	"go/ast"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

func isFieldCovered(passPkg *types.Package, f *types.Var, state *coverageState) bool {
	if state.covered[f] {
		return true
	}
	if !f.Embedded() {
		return false
	}
	embSt := unwrapEmbeddedStruct(f.Type())
	if embSt == nil || embSt.NumFields() == 0 {
		return false
	}
	return allEmbeddedFieldsPromoted(passPkg, embSt, state.promoted[f], make(map[*types.Struct]bool))
}

func unwrapEmbeddedStruct(t types.Type) *types.Struct {
	if embNamed, ok := vetutil.UnwrapNamedType(t); ok {
		embSt, _ := embNamed.Underlying().(*types.Struct)
		return embSt
	}
	u := types.Unalias(t)
	if ptr, isPtr := u.(*types.Pointer); isPtr {
		u = types.Unalias(ptr.Elem())
	}
	embSt, _ := u.(*types.Struct)
	return embSt
}

func allEmbeddedFieldsPromoted(
	passPkg *types.Package,
	embSt *types.Struct,
	hits map[*types.Var]bool,
	seen map[*types.Struct]bool,
) bool {
	if hits == nil || embSt == nil || seen[embSt] {
		return false
	}
	seen[embSt] = true
	for i := 0; i < embSt.NumFields(); i++ {
		if !isEmbeddedSubFieldCovered(passPkg, embSt.Field(i), hits, seen) {
			return false
		}
	}
	return true
}

func isEmbeddedSubFieldCovered(
	passPkg *types.Package,
	ef *types.Var,
	hits map[*types.Var]bool,
	seen map[*types.Struct]bool,
) bool {
	if ef.Name() == "_" {
		return true
	}
	// 嵌入体含本包不可见的未导出字段时，仅靠提升字段无法覆盖全貌，必须显式访问嵌入体自身。
	if !ef.Exported() && ef.Pkg() != passPkg {
		return false
	}
	// 使用 Origin() 归一化泛型嵌入体字段对象，避免实例化字段指针差异引发误报。
	if hits[ef.Origin()] {
		return true
	}
	if !ef.Embedded() {
		return false
	}
	nested := unwrapEmbeddedStruct(ef.Type())
	if nested == nil || nested.NumFields() == 0 {
		return false
	}
	return allEmbeddedFieldsPromoted(passPkg, nested, hits, seen)
}

// collectFieldPathPrefixes 收集仅作为子字段选择前缀使用的嵌入体选择器（如 o.Middle.LeafA 中的 o.Middle），
// 防止仅访问嵌入体单个子字段时将整个嵌入体误判为已完全覆盖。
func collectFieldPathPrefixes(info *types.Info, body *ast.BlockStmt) map[*ast.SelectorExpr]bool {
	prefixes := make(map[*ast.SelectorExpr]bool)
	if info == nil || body == nil {
		return prefixes
	}
	ast.Inspect(body, func(n ast.Node) bool {
		outer, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		outerSel, ok := info.Selections[outer]
		if !ok || outerSel == nil || outerSel.Kind() != types.FieldVal {
			return true
		}
		base := unwrapBaseSelector(outer.X)
		if base == nil {
			return true
		}
		baseSel, ok := info.Selections[base]
		if !ok || baseSel == nil || baseSel.Kind() != types.FieldVal {
			return true
		}
		if baseVar, ok := baseSel.Obj().(*types.Var); ok && baseVar.Embedded() {
			prefixes[base] = true
		}
		return true
	})
	return prefixes
}

func unwrapBaseSelector(expr ast.Expr) *ast.SelectorExpr {
	cur := ast.Unparen(expr)
	for cur != nil {
		switch e := cur.(type) {
		case *ast.StarExpr:
			cur = ast.Unparen(e.X)
		case *ast.SelectorExpr:
			return e
		default:
			return nil
		}
	}
	return nil
}

// recordSelectorCoverage 记录选择器对字段或嵌入提升字段的读取覆盖；
// 若选择器仅作为子字段选择前缀（如 o.Middle.LeafA 中的 o.Middle），则跳过整字段覆盖而归因到具体叶子字段。
func recordSelectorCoverage(
	info *types.Info,
	selExpr *ast.SelectorExpr,
	aliases map[*types.Var]bool,
	fieldPrefixes map[*ast.SelectorExpr]bool,
	state *coverageState,
) {
	if fieldPrefixes[selExpr] {
		return
	}
	outerSel, ok := info.Selections[selExpr]
	if !ok || outerSel == nil {
		return
	}
	topSel, topIdx, ok := resolveSelectorChain(info, selExpr, aliases)
	if !ok {
		return
	}
	if topSel == selExpr {
		if len(topIdx) == 1 {
			recordDirectFieldHit(outerSel.Obj(), state)
			return
		}
		if len(topIdx) > 1 {
			recordPromotedFieldHit(topIdx[0], outerSel.Obj(), state)
		}
		return
	}
	if outerSel.Kind() != types.FieldVal || len(topIdx) == 0 {
		return
	}
	recordPromotedFieldHit(topIdx[0], outerSel.Obj(), state)
}

// resolveSelectorChain 沿嵌入体字段选择链向下追溯至接收者别名，返回顶层嵌入字段选择器及其索引路径。
func resolveSelectorChain(
	info *types.Info,
	selExpr *ast.SelectorExpr,
	aliases map[*types.Var]bool,
) (*ast.SelectorExpr, []int, bool) {
	if isAliasExpr(info, selExpr.X, aliases) {
		sel := info.Selections[selExpr]
		if sel == nil {
			return nil, nil, false
		}
		return selExpr, sel.Index(), true
	}
	cur := selExpr
	for {
		base := unwrapBaseSelector(cur.X)
		if base == nil {
			return nil, nil, false
		}
		baseSel, ok := info.Selections[base]
		if !ok || baseSel == nil || baseSel.Kind() != types.FieldVal {
			return nil, nil, false
		}
		baseVar, ok := baseSel.Obj().(*types.Var)
		if !ok || !baseVar.Embedded() {
			return nil, nil, false
		}
		if isAliasExpr(info, base.X, aliases) {
			return base, baseSel.Index(), true
		}
		cur = base
	}
}

func recordDirectFieldHit(obj types.Object, state *coverageState) {
	v, ok := obj.(*types.Var)
	if !ok {
		return
	}
	orig := v.Origin()
	if state.target.fieldSet[orig] {
		state.covered[orig] = true
	}
}

func recordPromotedFieldHit(topIdx int, obj types.Object, state *coverageState) {
	if topIdx >= state.target.stType.NumFields() {
		return
	}
	topField := state.target.stType.Field(topIdx)
	if !state.target.fieldSet[topField] {
		return
	}
	leafVar, ok := obj.(*types.Var)
	if !ok {
		return
	}
	if state.promoted[topField] == nil {
		state.promoted[topField] = make(map[*types.Var]bool)
	}
	state.promoted[topField][leafVar.Origin()] = true
}
