package vetssa

import (
	"go/token"
	"slices"

	"golang.org/x/tools/go/ssa"
)

// RootStorageValues 反向追溯底层存储根（供后向反染使用）：对 UnOp(*alloc) 同时返回栈槽 alloc 及其指向目标。
func RootStorageValues(v ssa.Value, traverseFields bool) []ssa.Value {
	var roots []ssa.Value
	collectRoots(v, traverseFields, false, make(map[ssa.Value]bool), &roots)
	return roots
}

// WriteTargetRoots 严格解析写入实际修改的底层存储根（供 AllRootsOwnedInScope，修复 C1/M5）：
// 遇 UnOp(*alloc) 追溯存入 alloc 的全部指针/切片来源，存在未追踪取址或逃逸时 fail-closed 返回 false。
func WriteTargetRoots(v ssa.Value, traverseFields bool) ([]ssa.Value, bool) {
	var roots []ssa.Value
	ok := collectRoots(v, traverseFields, true, make(map[ssa.Value]bool), &roots)
	return roots, ok && len(roots) > 0
}

func collectRoots(v ssa.Value, traverseFields, strictWrite bool, seen map[ssa.Value]bool, roots *[]ssa.Value) bool {
	if v == nil {
		return !strictWrite
	}
	if seen[v] {
		return true
	}
	seen[v] = true
	if next, ok := rootStorageStep(v, traverseFields); ok {
		return collectRoots(next, traverseFields, strictWrite, seen, roots)
	}
	if u, ok := v.(*ssa.UnOp); ok && u.Op == token.MUL {
		return collectDerefRoots(u.X, traverseFields, strictWrite, seen, roots)
	}
	if phi, ok := v.(*ssa.Phi); ok {
		return collectPhiRoots(phi, traverseFields, strictWrite, seen, roots)
	}
	*roots = append(*roots, v)
	return true
}

func collectPhiRoots(phi *ssa.Phi, traverseFields, strictWrite bool, seen map[ssa.Value]bool, roots *[]ssa.Value) bool {
	if strictWrite && len(phi.Edges) == 0 {
		return false
	}
	for _, e := range phi.Edges {
		if (!strictWrite || !IsNilConst(e)) && !collectRoots(e, traverseFields, strictWrite, seen, roots) {
			return false
		}
	}
	return true
}

func collectDerefRoots(addr ssa.Value, traverseFields, strictWrite bool, seen map[ssa.Value]bool, roots *[]ssa.Value) bool {
	if !strictWrite {
		return collectBackLoadRoots(addr, traverseFields, seen, roots)
	}
	switch a := addr.(type) {
	case *ssa.Global, *ssa.Parameter:
		*roots = append(*roots, a)
		return true
	case *ssa.Alloc:
		return traceCellWriteTargets(a, traverseFields, seen, roots)
	case *ssa.FreeVar:
		return traceFreeVarDerefTargets(a, traverseFields, seen, roots)
	case *ssa.FieldAddr:
		return traceFieldLoadWriteTargets(a, traverseFields, seen, roots)
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
			collectRoots(a.X, true, false, seen, roots)
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
			collectRoots(st.Val, traverseFields, false, seen, roots)
		}
	}
}

func traceFreeVarDerefTargets(fv *ssa.FreeVar, traverseFields bool, seen map[ssa.Value]bool, roots *[]ssa.Value) bool {
	origins := TraceFreeVarOrigins(fv)
	if len(origins) == 0 {
		return false
	}
	for _, orig := range origins {
		if alloc, ok := orig.(*ssa.Alloc); ok {
			if !traceCellWriteTargets(alloc, traverseFields, seen, roots) {
				return false
			}
		} else if !collectRoots(orig, traverseFields, true, seen, roots) {
			return false
		}
	}
	return true
}

// LoadedCellValues 返回局部栈槽 *ssa.Alloc 的全部已知非 nil 写入值（兼容只读闭包捕获；存在未追踪逃逸或写入返回 false）。
func LoadedCellValues(alloc *ssa.Alloc) ([]ssa.Value, bool) {
	vals, found, safe := scanCellStores(alloc, func(mc *ssa.MakeClosure) (bool, bool) {
		return false, isReadOnlyClosureCapture(mc, alloc)
	})
	return vals, safe && found
}

func isReadOnlyClosureCapture(mc *ssa.MakeClosure, cell ssa.Value) bool {
	fn, ok := mc.Fn.(*ssa.Function)
	if !ok || fn == nil {
		return false
	}
	for i, b := range mc.Bindings {
		if b == cell {
			if i >= len(fn.FreeVars) {
				return false
			}
			_, hasStore, safe := scanCellStores(fn.FreeVars[i], nil)
			if !safe || hasStore {
				return false
			}
		}
	}
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

func traceCellWriteTargets(cell ssa.Value, traverseFields bool, seen map[ssa.Value]bool, roots *[]ssa.Value) bool {
	vals, found, safe := scanCellStores(cell, func(mc *ssa.MakeClosure) (bool, bool) {
		return traceClosureCellReferrer(mc, cell, traverseFields, seen, roots)
	})
	if !safe || !found {
		return false
	}
	return !slices.ContainsFunc(vals, func(v ssa.Value) bool { return !collectRoots(v, traverseFields, true, seen, roots) })
}

func traceClosureCellReferrer(mc *ssa.MakeClosure, cell ssa.Value, traverseFields bool, seen map[ssa.Value]bool, roots *[]ssa.Value) (bool, bool) {
	fn, ok := mc.Fn.(*ssa.Function)
	if !ok || fn == nil {
		return false, false
	}
	found := false
	for i, b := range mc.Bindings {
		if b != cell {
			continue
		}
		if i >= len(fn.FreeVars) {
			return false, false
		}
		fv := fn.FreeVars[i]
		if !seen[fv] {
			seen[fv] = true
			if traceCellWriteTargets(fv, traverseFields, seen, roots) {
				found = true
			} else if _, hasStore, safe := scanCellStores(fv, nil); !safe || hasStore {
				return false, false
			}
		}
	}
	return found, true
}

func traceFieldLoadWriteTargets(fa *ssa.FieldAddr, traverseFields bool, seen map[ssa.Value]bool, roots *[]ssa.Value) bool {
	alloc, ok := fa.X.(*ssa.Alloc)
	if !ok || alloc.Referrers() == nil {
		return false
	}
	found := false
	for _, ref := range *alloc.Referrers() {
		f, safe := traceFieldAllocRef(ref, fa.Field, traverseFields, seen, roots)
		if !safe {
			return false
		}
		found = found || f
	}
	return found
}

func traceFieldAllocRef(ref ssa.Instruction, field int, traverseFields bool, seen map[ssa.Value]bool, roots *[]ssa.Value) (bool, bool) {
	switch r := ref.(type) {
	case *ssa.FieldAddr:
		if r.Field != field {
			return false, true
		}
		vals, f, safe := scanCellStores(r, nil)
		if !safe {
			return false, false
		}
		return f, !slices.ContainsFunc(vals, func(v ssa.Value) bool { return !collectRoots(v, traverseFields, true, seen, roots) })
	case *ssa.UnOp, *ssa.DebugRef:
		return false, true
	default:
		return false, false
	}
}
