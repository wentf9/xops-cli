package vetssa

import (
	"go/token"
	"slices"

	"golang.org/x/tools/go/ssa"
)

// RootStorageValues 反向追溯底层存储根（供后向反染使用）：对 UnOp(*alloc) 同时返回栈槽 alloc 及其指向目标。
func RootStorageValues(v ssa.Value, traverseFields bool) []ssa.Value {
	var roots []ssa.Value
	collectRoots(v, traverseFields, false, make(map[ssa.Value]bool), &roots, nil)
	return roots
}

// WriteTargetRoots 严格解析写入实际修改的底层存储根（供 AllRootsOwnedInScope，修复 C1/M5）：
// 遇 UnOp(*alloc) 追溯存入 alloc 的全部指针/切片来源，存在未追踪取址或逃逸时 fail-closed 返回 false。
func WriteTargetRoots(v ssa.Value, traverseFields bool) ([]ssa.Value, bool) {
	var roots []ssa.Value
	ok := collectRoots(v, traverseFields, true, make(map[ssa.Value]bool), &roots, nil)
	return roots, ok && len(roots) > 0
}

// WriteTargetAndTraversedCells 在 WriteTargetRoots 严格解析的基础上，同步记录路径上全部被解引用的
// 中间存储单元（*ssa.Alloc、解析后的 *ssa.FreeVar 源单元、*ssa.Global、*ssa.Parameter、*ssa.FieldAddr），
// 供 P4-T1 校验所有途经容器与底层切片根均直接归属 kiFn，阻断外层切片变量重赋后再别名绕过。
func WriteTargetAndTraversedCells(v ssa.Value, traverseFields bool) ([]ssa.Value, []ssa.Value, bool) {
	var roots, cells []ssa.Value
	ok := collectRoots(v, traverseFields, true, make(map[ssa.Value]bool), &roots, &cells)
	return roots, cells, ok && len(roots) > 0
}

func appendUniqueValue(dst *[]ssa.Value, v ssa.Value) {
	if dst != nil && v != nil && !slices.Contains(*dst, v) {
		*dst = append(*dst, v)
	}
}

func collectRoots(v ssa.Value, traverseFields, strictWrite bool, seen map[ssa.Value]bool, roots, cells *[]ssa.Value) bool {
	if v == nil {
		return !strictWrite
	}
	if seen[v] {
		return true
	}
	seen[v] = true
	if next, ok := rootStorageStep(v, traverseFields); ok {
		return collectRoots(next, traverseFields, strictWrite, seen, roots, cells)
	}
	if u, ok := v.(*ssa.UnOp); ok && u.Op == token.MUL {
		return collectDerefRoots(u.X, traverseFields, strictWrite, seen, roots, cells)
	}
	if phi, ok := v.(*ssa.Phi); ok {
		return collectPhiRoots(phi, traverseFields, strictWrite, seen, roots, cells)
	}
	*roots = append(*roots, v)
	return true
}

func collectPhiRoots(phi *ssa.Phi, traverseFields, strictWrite bool, seen map[ssa.Value]bool, roots, cells *[]ssa.Value) bool {
	if strictWrite && len(phi.Edges) == 0 {
		return false
	}
	for _, e := range phi.Edges {
		if (!strictWrite || !IsNilConst(e)) && !collectRoots(e, traverseFields, strictWrite, seen, roots, cells) {
			return false
		}
	}
	return true
}

func collectDerefRoots(addr ssa.Value, traverseFields, strictWrite bool, seen map[ssa.Value]bool, roots, cells *[]ssa.Value) bool {
	if !strictWrite {
		return collectBackLoadRoots(addr, traverseFields, seen, roots)
	}
	switch a := addr.(type) {
	case *ssa.Global, *ssa.Parameter:
		appendUniqueValue(cells, a)
		*roots = append(*roots, a)
		return true
	case *ssa.Alloc:
		appendUniqueValue(cells, a)
		return traceCellWriteTargets(a, traverseFields, seen, roots, cells)
	case *ssa.FreeVar:
		return traceFreeVarDerefTargets(a, traverseFields, seen, roots, cells)
	case *ssa.FieldAddr:
		appendUniqueValue(cells, a)
		return traceFieldLoadWriteTargets(a, traverseFields, seen, roots, cells)
	default:
		return false
	}
}

func collectBackLoadRoots(addr ssa.Value, traverseFields bool, seen map[ssa.Value]bool, roots *[]ssa.Value) bool {
	switch a := addr.(type) {
	case *ssa.Alloc:
		*roots = append(*roots, a)
		collectDirectStoredRoots(a, traverseFields, seen, roots)
	case *ssa.Global, *ssa.FreeVar, *ssa.Parameter:
		*roots = append(*roots, a)
	case *ssa.FieldAddr:
		if traverseFields {
			collectRoots(a.X, true, false, seen, roots, nil)
		} else {
			*roots = append(*roots, a)
		}
	default:
		*roots = append(*roots, addr)
	}
	return true
}

func collectDirectStoredRoots(alloc *ssa.Alloc, traverseFields bool, seen map[ssa.Value]bool, roots *[]ssa.Value) {
	if alloc.Referrers() == nil {
		return
	}
	for _, ref := range *alloc.Referrers() {
		if st, ok := ref.(*ssa.Store); ok && st.Addr == alloc && !IsNilConst(st.Val) {
			collectRoots(st.Val, traverseFields, false, seen, roots, nil)
		}
	}
}

func traceFreeVarDerefTargets(fv *ssa.FreeVar, traverseFields bool, seen map[ssa.Value]bool, roots, cells *[]ssa.Value) bool {
	origins := TraceFreeVarOrigins(fv)
	if len(origins) == 0 {
		return false
	}
	for _, orig := range origins {
		appendUniqueValue(cells, orig)
		if alloc, ok := orig.(*ssa.Alloc); ok {
			if !traceCellWriteTargets(alloc, traverseFields, seen, roots, cells) {
				return false
			}
		} else if !collectRoots(orig, traverseFields, true, seen, roots, cells) {
			return false
		}
	}
	return true
}

const (
	cellVisiting uint8 = 1
	cellVerified uint8 = 2
)

// LoadedCellValues 返回局部栈槽 *ssa.Alloc 的全部已知非 nil 写入值（兼容任意深度只读闭包捕获；存在未追踪逃逸或任意内层写入返回 false）。
func LoadedCellValues(alloc *ssa.Alloc) ([]ssa.Value, bool) {
	state := map[ssa.Value]uint8{alloc: cellVisiting}
	vals, found, safe := scanCellStores(alloc, func(mc *ssa.MakeClosure) (bool, bool) {
		return false, isReadOnlyClosureCapture(mc, alloc, state)
	})
	return vals, safe && found
}

// isReadOnlyClosureCapture 递归核验捕获单元在嵌套闭包树中仅发生只读解引用；
// 若 MakeClosure 未在 Bindings 中命中 cell（如非捕获槽位引用）或任意层级出现 *ssa.Store（含写 nil）、
// 未知/逃逸引用或环路，一律严格 Fail-Closed 返回 false。
func isReadOnlyClosureCapture(mc *ssa.MakeClosure, cell ssa.Value, state map[ssa.Value]uint8) bool {
	fn, ok := mc.Fn.(*ssa.Function)
	if !ok || fn == nil {
		return false
	}
	matched := false
	for i, b := range mc.Bindings {
		if b != cell {
			continue
		}
		matched = true
		if i >= len(fn.FreeVars) || !isReadOnlyCell(fn.FreeVars[i], state) {
			return false
		}
	}
	return matched
}

func isReadOnlyCell(cell ssa.Value, state map[ssa.Value]uint8) bool {
	if cell == nil || cell.Referrers() == nil || state[cell] == cellVisiting {
		return false
	}
	if state[cell] == cellVerified {
		return true
	}
	state[cell] = cellVisiting
	for _, ref := range *cell.Referrers() {
		switch r := ref.(type) {
		case *ssa.UnOp:
			if r.Op != token.MUL {
				return false
			}
		case *ssa.DebugRef:
		case *ssa.MakeClosure:
			if !isReadOnlyClosureCapture(r, cell, state) {
				return false
			}
		default:
			return false
		}
	}
	state[cell] = cellVerified
	return true
}

// scanCellStores 检查存储单元 cell 的全部引用者是否仅含直接 Store、读解引用、DebugRef 及可选闭包回调（C1/C4）。
func scanCellStores(cell ssa.Value, onClosure func(*ssa.MakeClosure) (bool, bool)) ([]ssa.Value, bool, bool) {
	if cell == nil || cell.Referrers() == nil {
		return nil, false, false
	}
	var vals []ssa.Value
	foundAny := false
	for _, ref := range *cell.Referrers() {
		f, safe := checkSingleCellRef(cell, ref, onClosure, &vals)
		if !safe {
			return nil, false, false
		}
		foundAny = foundAny || f
	}
	return vals, foundAny, true
}

func checkSingleCellRef(cell ssa.Value, ref ssa.Instruction, onClosure func(*ssa.MakeClosure) (bool, bool), vals *[]ssa.Value) (bool, bool) {
	switch r := ref.(type) {
	case *ssa.Store:
		if r.Addr != cell || r.Val == cell {
			return false, false
		}
		if !IsNilConst(r.Val) {
			*vals = append(*vals, r.Val)
			return true, true
		}
		return false, true
	case *ssa.UnOp:
		return false, r.Op == token.MUL
	case *ssa.DebugRef:
		return false, true
	case *ssa.MakeClosure:
		if onClosure == nil {
			return false, false
		}
		return onClosure(r)
	default:
		return false, false
	}
}

// traceCellWriteTargets 严格追溯单元及其任意层嵌套闭包中的全部已知写入根；
// 仅当全部层级均无未知/逃逸引用且至少存在一处已知非 nil 写入时返回 true。
func traceCellWriteTargets(cell ssa.Value, traverseFields bool, seen map[ssa.Value]bool, roots, cells *[]ssa.Value) bool {
	found, safe := traceCellWriteTargetsRec(cell, traverseFields, seen, make(map[ssa.Value]uint8), roots, cells)
	return safe && found
}

// traceCellWriteTargetsRec 分离 found（本层或子闭包存在非 nil 写入）与 safe（全部层级无逃逸或非法引用），
// 允许 2 层及以上纯只读闭包捕获（found==false, safe==true），同时对任意层级改写收集根目标、对逃逸严格 Fail-Closed。
func traceCellWriteTargetsRec(cell ssa.Value, traverseFields bool, seen map[ssa.Value]bool, cellState map[ssa.Value]uint8, roots, cells *[]ssa.Value) (bool, bool) {
	if cell == nil || cellState[cell] == cellVisiting {
		return false, false
	}
	if cellState[cell] == cellVerified {
		return false, true
	}
	cellState[cell] = cellVisiting
	vals, found, safe := scanCellStores(cell, func(mc *ssa.MakeClosure) (bool, bool) {
		return traceClosureCellReferrer(mc, cell, traverseFields, seen, cellState, roots, cells)
	})
	if !safe {
		return false, false
	}
	if slices.ContainsFunc(vals, func(v ssa.Value) bool { return !collectRoots(v, traverseFields, true, seen, roots, cells) }) {
		return false, false
	}
	cellState[cell] = cellVerified
	return found, true
}

func traceClosureCellReferrer(mc *ssa.MakeClosure, cell ssa.Value, traverseFields bool, seen map[ssa.Value]bool, cellState map[ssa.Value]uint8, roots, cells *[]ssa.Value) (bool, bool) {
	fn, ok := mc.Fn.(*ssa.Function)
	if !ok || fn == nil {
		return false, false
	}
	found, matched := false, false
	for i, b := range mc.Bindings {
		if b != cell {
			continue
		}
		matched = true
		if i >= len(fn.FreeVars) {
			return false, false
		}
		f, safe := traceCellWriteTargetsRec(fn.FreeVars[i], traverseFields, seen, cellState, roots, cells)
		if !safe {
			return false, false
		}
		found = found || f
	}
	if !matched {
		return false, false
	}
	return found, true
}

func traceFieldLoadWriteTargets(fa *ssa.FieldAddr, traverseFields bool, seen map[ssa.Value]bool, roots, cells *[]ssa.Value) bool {
	alloc, ok := fa.X.(*ssa.Alloc)
	if !ok || alloc.Referrers() == nil {
		return false
	}
	found := false
	for _, ref := range *alloc.Referrers() {
		f, safe := traceFieldAllocRef(ref, fa.Field, traverseFields, seen, roots, cells)
		if !safe {
			return false
		}
		found = found || f
	}
	return found
}

func traceFieldAllocRef(ref ssa.Instruction, field int, traverseFields bool, seen map[ssa.Value]bool, roots, cells *[]ssa.Value) (bool, bool) {
	switch r := ref.(type) {
	case *ssa.FieldAddr:
		if r.Field != field {
			return false, true
		}
		vals, f, safe := scanCellStores(r, nil)
		if !safe {
			return false, false
		}
		return f, !slices.ContainsFunc(vals, func(v ssa.Value) bool { return !collectRoots(v, traverseFields, true, seen, roots, cells) })
	case *ssa.UnOp, *ssa.DebugRef:
		return false, true
	default:
		return false, false
	}
}
