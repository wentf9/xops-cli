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
	return embSt != nil && embSt.NumFields() > 0 && allEmbeddedFieldsPromoted(passPkg, embSt, state.promoted[f], make(map[*types.Struct]bool))
}

func unwrapEmbeddedStruct(t types.Type) *types.Struct { return vetutil.UnwrapStructType(t) }

func allEmbeddedFieldsPromoted(passPkg *types.Package, embSt *types.Struct, hits map[*types.Var]bool, seen map[*types.Struct]bool) bool {
	if hits == nil || embSt == nil || seen[embSt] {
		return false
	}
	seen[embSt] = true
	for i := range embSt.NumFields() {
		if !isEmbeddedSubFieldCovered(passPkg, embSt.Field(i), hits, seen) {
			return false
		}
	}
	return true
}

func isEmbeddedSubFieldCovered(passPkg *types.Package, ef *types.Var, hits map[*types.Var]bool, seen map[*types.Struct]bool) bool {
	if ef.Name() == "_" {
		return true
	}
	// 嵌入体含本包不可见的未导出字段时，仅靠提升字段无法覆盖全貌，必须显式访问嵌入体自身。
	if !ef.Exported() && ef.Pkg() != passPkg {
		return false
	}
	if hits[ef.Origin()] {
		return true
	}
	if !ef.Embedded() {
		return false
	}
	nested := unwrapEmbeddedStruct(ef.Type())
	return nested != nil && nested.NumFields() > 0 && allEmbeddedFieldsPromoted(passPkg, nested, hits, seen)
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
		if !ok || !isFieldValSelection(info.Selections[outer]) {
			return true
		}
		if base := unwrapStarParenSelector(outer.X); base != nil {
			if baseSel := info.Selections[base]; isFieldValSelection(baseSel) {
				if baseVar, ok := baseSel.Obj().(*types.Var); ok && baseVar.Embedded() {
					prefixes[base] = true
				}
			}
		}
		return true
	})
	return prefixes
}

func isFieldValSelection(sel *types.Selection) bool {
	return sel != nil && sel.Kind() == types.FieldVal
}

// recordSelectorCoverage 记录选择器对字段或嵌入提升字段的读取覆盖；跳过子字段前缀选择器。
func recordSelectorCoverage(info *types.Info, selExpr *ast.SelectorExpr, aliases map[*types.Var]bool, fieldPrefixes map[*ast.SelectorExpr]bool, state *coverageState) {
	if fieldPrefixes[selExpr] {
		return
	}
	outerSel := info.Selections[selExpr]
	topSel, topIdx, ok := resolveSelectorChain(info, selExpr, aliases)
	if outerSel == nil || !ok || len(topIdx) == 0 {
		return
	}
	if topSel == selExpr && len(topIdx) == 1 {
		if v, ok := outerSel.Obj().(*types.Var); ok && state.target.fieldSet[v.Origin()] {
			state.covered[v.Origin()] = true
		}
		return
	}
	if topSel != selExpr && outerSel.Kind() != types.FieldVal {
		return
	}
	recordPromotedFieldHit(topIdx[0], outerSel.Obj(), state)
}

// resolveSelectorChain 沿嵌入体字段选择链向下追溯至接收者别名，返回顶层嵌入字段选择器及其索引路径。
func resolveSelectorChain(info *types.Info, selExpr *ast.SelectorExpr, aliases map[*types.Var]bool) (*ast.SelectorExpr, []int, bool) {
	if isAliasExpr(info, selExpr.X, aliases) {
		if sel := info.Selections[selExpr]; sel != nil {
			return selExpr, sel.Index(), true
		}
		return nil, nil, false
	}
	for cur := selExpr; ; {
		base := unwrapStarParenSelector(cur.X)
		if base == nil {
			return nil, nil, false
		}
		baseSel := info.Selections[base]
		if !isFieldValSelection(baseSel) {
			return nil, nil, false
		}
		if baseVar, ok := baseSel.Obj().(*types.Var); !ok || !baseVar.Embedded() {
			return nil, nil, false
		}
		if isAliasExpr(info, base.X, aliases) {
			return base, baseSel.Index(), true
		}
		cur = base
	}
}

func recordPromotedFieldHit(topIdx int, obj types.Object, state *coverageState) {
	if topIdx >= state.target.stType.NumFields() {
		return
	}
	topField := state.target.stType.Field(topIdx)
	leafVar, ok := obj.(*types.Var)
	if !ok || !state.target.fieldSet[topField] {
		return
	}
	if state.promoted[topField] == nil {
		state.promoted[topField] = make(map[*types.Var]bool)
	}
	state.promoted[topField][leafVar.Origin()] = true
}
