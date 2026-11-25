package secrettaint

import (
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// structFieldKey 唯一标识当前包内具名结构体的单个私有字段（供 LayerHostVault 私有 cipher.AEAD 字段写点全包校验）。
type structFieldKey struct {
	named *types.Named
	field int
}

// collectSafeVaultAEADFields 仅在 LayerHostVault（排除外置 _test）上执行全包 SSA 写点核验：
// 当且仅当当前包未导入 reflect、无 unsafe.Add/unsafe.Slice、无 uintptr->unsafe.Pointer、
// 无 unsafe.Pointer->非 uintptr 类型强转及含 cipher.AEAD 的异构类型转换，
// 且非泛型具名结构体的未导出 cipher.AEAD 字段存在至少一处非 nil 写入、全部写入均唯一源于标准库安全 AEAD 构造器、
// 无字段取址逃逸、无异构类型转换/unsafe 介入该结构体时，才允许在 cipher.AEAD.Seal 中作为受信任接收者使用。
func collectSafeVaultAEADFields(pkgInfo vetutil.PkgInfo, s *buildssa.SSA) map[structFieldKey]bool {
	if pkgInfo.IsExternalTest || pkgInfo.Layer != vetutil.LayerHostVault || s == nil || s.Pkg == nil || s.Pkg.Pkg == nil {
		return nil
	}
	if importsReflect(s.Pkg.Pkg) {
		return nil
	}
	allFuncs := vetssa.AllFuncs(s)
	if hasUnsafeVaultForge(s, allFuncs) {
		return nil
	}
	poisonedTypes := collectPoisonedLocalStructs(s.Pkg.Pkg, allFuncs)
	writes, poisonedFields := scanVaultAEADFieldWrites(s.Pkg.Pkg, allFuncs)
	safe := make(map[structFieldKey]bool)
	for key, vals := range writes {
		if poisonedTypes[key.named] || poisonedFields[key] || len(vals) == 0 {
			continue
		}
		if allValuesTraceToStdlibAEAD(s, vals) {
			safe[key] = true
		}
	}
	return safe
}

func importsReflect(pkg *types.Package) bool {
	return slices.ContainsFunc(pkg.Imports(), func(imp *types.Package) bool {
		return imp != nil && imp.Path() == "reflect"
	})
}

// hasUnsafeVaultForge 执行全包级 unsafe 内存伪造防线（放行 Windows CREDENTIALW 所需的 *T -> unsafe.Pointer -> uintptr）：
// 一旦检测到 unsafe.Add / unsafe.Slice、uintptr -> unsafe.Pointer、unsafe.Pointer -> 任意非 uintptr 类型重解释
// 或涉及 crypto/cipher.AEAD 的非等价类型转换，立即按 Fail-Closed 禁用全包私有 AEAD 字段信任。
func hasUnsafeVaultForge(s *buildssa.SSA, funcs []*ssa.Function) bool {
	forged := false
	vetssa.ForEachFuncInst(funcs, func(_ *ssa.Function, inst ssa.Instruction) {
		if forged {
			return
		}
		if isUnsafeForgeInst(s, inst) {
			forged = true
		}
	})
	return forged
}

func isUnsafeForgeInst(s *buildssa.SSA, inst ssa.Instruction) bool {
	if call, ok := inst.(ssa.CallInstruction); ok {
		rc := vetssa.ResolveCall(s, call)
		if rc.Builtin != nil && (rc.Builtin.Name() == "Add" || rc.Builtin.Name() == "Slice") {
			return true
		}
		return vetutil.IsPkgSymbol(rc.FuncObj, "unsafe", "Add", "Slice")
	}
	srcVal, dstT, ok := convertSrcDst(inst)
	if !ok || types.Identical(types.Unalias(srcVal.Type()), types.Unalias(dstT)) {
		return false
	}
	if isUnsafePointerForgeConvert(srcVal.Type(), dstT) {
		return true
	}
	return vetutil.TypeContainsNamed(srcVal.Type(), "crypto/cipher", "AEAD") ||
		vetutil.TypeContainsNamed(dstT, "crypto/cipher", "AEAD")
}

func isUnsafePointerForgeConvert(srcT, dstT types.Type) bool {
	return (isBasicKind(srcT, types.Uintptr) && isBasicKind(dstT, types.UnsafePointer)) ||
		(isBasicKind(srcT, types.UnsafePointer) && !isBasicKind(dstT, types.Uintptr))
}

func convertSrcDst(inst ssa.Instruction) (ssa.Value, types.Type, bool) {
	switch ins := inst.(type) {
	case *ssa.ChangeType:
		return ins.X, ins.Type(), true
	case *ssa.Convert:
		return ins.X, ins.Type(), true
	default:
		return nil, nil, false
	}
}

func isBasicKind(t types.Type, kind types.BasicKind) bool {
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && b.Kind() == kind
}

// collectPoisonedLocalStructs 扫描全包非等价类型转换与 unsafe.Pointer 转换，
// 沿 RootStorageValues(srcVal, true) 穿透多层字段、数组/切片元素、Phi 与局部槽，标记全部受波及的本地结构体。
func collectPoisonedLocalStructs(pkg *types.Package, funcs []*ssa.Function) map[*types.Named]bool {
	poisoned := make(map[*types.Named]bool)
	vetssa.ForEachFuncInst(funcs, func(_ *ssa.Function, inst ssa.Instruction) {
		srcVal, dstT, ok := convertSrcDst(inst)
		if !ok || types.Identical(types.Unalias(srcVal.Type()), types.Unalias(dstT)) {
			return
		}
		markLocalStructTypes(srcVal.Type(), pkg, poisoned, map[types.Type]bool{})
		markLocalStructTypes(dstT, pkg, poisoned, map[types.Type]bool{})
		for _, root := range vetssa.RootStorageValues(srcVal, true) {
			if root != nil {
				markLocalStructTypes(root.Type(), pkg, poisoned, map[types.Type]bool{})
			}
		}
	})
	return poisoned
}

func markLocalStructTypes(t types.Type, pkg *types.Package, out map[*types.Named]bool, seen map[types.Type]bool) {
	if t == nil || seen[t] {
		return
	}
	seen[t] = true
	switch u := types.Unalias(t).(type) {
	case *types.Named:
		if u.Obj() != nil && u.Obj().Pkg() == pkg {
			if _, isSt := u.Underlying().(*types.Struct); isSt {
				out[u.Origin()] = true
			}
		}
		markLocalStructTypes(u.Underlying(), pkg, out, seen)
	case *types.Pointer:
		markLocalStructTypes(u.Elem(), pkg, out, seen)
	case *types.Slice:
		markLocalStructTypes(u.Elem(), pkg, out, seen)
	case *types.Array:
		markLocalStructTypes(u.Elem(), pkg, out, seen)
	case *types.Struct:
		for i := range u.NumFields() {
			markLocalStructTypes(u.Field(i).Type(), pkg, out, seen)
		}
	}
}

func scanVaultAEADFieldWrites(pkg *types.Package, funcs []*ssa.Function) (map[structFieldKey][]ssa.Value, map[structFieldKey]bool) {
	writes := make(map[structFieldKey][]ssa.Value)
	poisoned := make(map[structFieldKey]bool)
	vetssa.ForEachFuncInst(funcs, func(_ *ssa.Function, inst ssa.Instruction) {
		fa, ok := inst.(*ssa.FieldAddr)
		if !ok {
			return
		}
		key, ok := candidateVaultAEADField(pkg, fa)
		if !ok {
			return
		}
		inspectAEADFieldAddrRefs(fa, key, writes, poisoned)
	})
	return writes, poisoned
}

func inspectAEADFieldAddrRefs(fa *ssa.FieldAddr, key structFieldKey, writes map[structFieldKey][]ssa.Value, poisoned map[structFieldKey]bool) {
	if fa.Referrers() == nil {
		poisoned[key] = true
		return
	}
	for _, ref := range *fa.Referrers() {
		switch r := ref.(type) {
		case *ssa.Store:
			if r.Addr != fa || r.Val == fa {
				poisoned[key] = true
				return
			}
			if !vetssa.IsNilConst(r.Val) {
				writes[key] = append(writes[key], r.Val)
			}
		case *ssa.UnOp:
			if r.Op != token.MUL {
				poisoned[key] = true
				return
			}
		case *ssa.DebugRef:
		default:
			poisoned[key] = true
			return
		}
	}
}

func candidateVaultAEADField(pkg *types.Package, fa *ssa.FieldAddr) (structFieldKey, bool) {
	if fa == nil || fa.X == nil {
		return structFieldKey{}, false
	}
	ptr, ok := types.Unalias(fa.X.Type()).(*types.Pointer)
	if !ok {
		return structFieldKey{}, false
	}
	return candidateVaultAEADStructField(pkg, ptr.Elem(), fa.Field)
}

func candidateVaultAEADStructField(pkg *types.Package, structType types.Type, fieldIdx int) (structFieldKey, bool) {
	named, ok := types.Unalias(structType).(*types.Named)
	if !ok || named == nil || named.Obj() == nil || named.Obj().Pkg() != pkg || named.TypeParams().Len() > 0 {
		return structFieldKey{}, false
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok || fieldIdx < 0 || fieldIdx >= st.NumFields() {
		return structFieldKey{}, false
	}
	f := st.Field(fieldIdx)
	if f.Exported() || f.Embedded() {
		return structFieldKey{}, false
	}
	fNamed, ok := types.Unalias(f.Type()).(*types.Named)
	if !ok || !vetutil.IsPkgSymbol(fNamed.Obj(), "crypto/cipher", "AEAD") {
		return structFieldKey{}, false
	}
	return structFieldKey{named: named.Origin(), field: fieldIdx}, true
}

func allValuesTraceToStdlibAEAD(s *buildssa.SSA, vals []ssa.Value) bool {
	return !slices.ContainsFunc(vals, func(v ssa.Value) bool {
		return !tracesOnlyToSafeAEAD(s, v, nil, map[ssa.Value]bool{}, map[*ssa.Function]bool{})
	})
}

func (ts *taintScope) isSafeAEADRecv(v ssa.Value) bool {
	return tracesOnlyToSafeAEAD(ts.eng.ssaInfo, v, ts.eng.safeVaultAEAD, map[ssa.Value]bool{}, map[*ssa.Function]bool{})
}

// tracesOnlyToSafeAEAD 沿 Extract/Call/Phi/FreeVar/Alloc/UnOp 及已核验的 LayerHostVault 私有结构体字段
// 追溯 AEAD 接收者或写入值是否全部源于标准库安全 AEAD 构造器（采用活路径栈 visiting 避免菱形 DAG 误杀）。
func tracesOnlyToSafeAEAD(s *buildssa.SSA, v ssa.Value, safeFields map[structFieldKey]bool, visiting map[ssa.Value]bool, seenFn map[*ssa.Function]bool) bool {
	v = vetssa.UnwrapInterface(v)
	if v == nil || visiting[v] {
		return false
	}
	visiting[v] = true
	defer delete(visiting, v)
	switch val := v.(type) {
	case *ssa.Extract:
		return traceAEADCallResult(s, val.Tuple, val.Index, safeFields, visiting, seenFn)
	case *ssa.Call:
		return traceAEADCallResult(s, val, 0, safeFields, visiting, seenFn)
	case *ssa.Phi:
		return allNonNilEdgesMatch(val.Edges, func(e ssa.Value) bool {
			return tracesOnlyToSafeAEAD(s, e, safeFields, visiting, seenFn)
		})
	case *ssa.FreeVar:
		origins := vetssa.TraceFreeVarOrigins(val)
		return len(origins) > 0 && !slices.ContainsFunc(origins, func(o ssa.Value) bool {
			return !tracesOnlyToSafeAEAD(s, o, safeFields, visiting, seenFn)
		})
	case *ssa.Alloc:
		vals, ok := collectCellStoreValues(val, map[ssa.Value]bool{})
		return ok && !slices.ContainsFunc(vals, func(sv ssa.Value) bool {
			return !tracesOnlyToSafeAEAD(s, sv, safeFields, visiting, seenFn)
		})
	case *ssa.UnOp:
		return val.Op == token.MUL && traceAEADDeref(s, val.X, safeFields, visiting, seenFn)
	case *ssa.Field:
		return isVerifiedAEADStructField(s, val.X.Type(), val.Field, safeFields)
	default:
		return false
	}
}

func traceAEADDeref(s *buildssa.SSA, addr ssa.Value, safeFields map[structFieldKey]bool, seen map[ssa.Value]bool, seenFn map[*ssa.Function]bool) bool {
	if fa, ok := addr.(*ssa.FieldAddr); ok {
		return len(safeFields) > 0 && s != nil && s.Pkg != nil && isVerifiedAEADFieldAddr(s.Pkg.Pkg, fa, safeFields)
	}
	return tracesOnlyToSafeAEAD(s, addr, safeFields, seen, seenFn)
}

func isVerifiedAEADFieldAddr(pkg *types.Package, fa *ssa.FieldAddr, safeFields map[structFieldKey]bool) bool {
	key, ok := candidateVaultAEADField(pkg, fa)
	return ok && safeFields[key]
}

func isVerifiedAEADStructField(s *buildssa.SSA, structType types.Type, fieldIdx int, safeFields map[structFieldKey]bool) bool {
	if len(safeFields) == 0 || s == nil || s.Pkg == nil {
		return false
	}
	key, ok := candidateVaultAEADStructField(s.Pkg.Pkg, structType, fieldIdx)
	return ok && safeFields[key]
}

func traceAEADCallResult(s *buildssa.SSA, callVal ssa.Value, retSlot int, safeFields map[structFieldKey]bool, seen map[ssa.Value]bool, seenFn map[*ssa.Function]bool) bool {
	call, ok := callVal.(*ssa.Call)
	if !ok {
		return false
	}
	if retSlot == 0 && isStdlibAEADCtorCall(s, call, seenFn) {
		return true
	}
	origFn := vetssa.UnwrapOriginFunc(call.Call.StaticCallee())
	if origFn == nil || !vetssa.IsSamePackageFunc(s, origFn) || len(origFn.Blocks) == 0 {
		return false
	}
	return samePkgReturnsMatch(origFn, retSlot, seenFn, func(rv ssa.Value) bool {
		return tracesOnlyToSafeAEAD(s, rv, safeFields, seen, seenFn)
	})
}

// samePkgReturnsMatch 递归核验同包函数指定返回值槽位的全部非 nil 返回路径均满足 pred（无环且至少存在一条非 nil 路径）。
func samePkgReturnsMatch(fn *ssa.Function, retSlot int, seenFn map[*ssa.Function]bool, pred func(ssa.Value) bool) bool {
	if fn == nil || seenFn[fn] {
		return false
	}
	seenFn[fn] = true
	defer delete(seenFn, fn)
	hasNonNil, valid := false, true
	vetssa.ForEachInst(fn, func(inst ssa.Instruction) {
		ret, ok := inst.(*ssa.Return)
		if !ok || !valid {
			return
		}
		if retSlot < 0 || retSlot >= len(ret.Results) {
			valid = false
			return
		}
		rv := ret.Results[retSlot]
		if vetssa.IsNilConst(rv) {
			return
		}
		if !pred(rv) {
			valid = false
			return
		}
		hasNonNil = true
	})
	return valid && hasNonNil
}

func allNonNilEdgesMatch(edges []ssa.Value, pred func(ssa.Value) bool) bool {
	hasNonNil := false
	for _, e := range edges {
		if vetssa.IsNilConst(e) {
			continue
		}
		if !pred(e) {
			return false
		}
		hasNonNil = true
	}
	return hasNonNil
}

// collectCellStoreValues 收集局部栈槽 Alloc（含安全闭包捕获写入）的全部已知非 nil 写入值；若存在任意未追踪逃逸或地址泄露则 Fail-Closed。
func collectCellStoreValues(cell ssa.Value, seen map[ssa.Value]bool) ([]ssa.Value, bool) {
	vals, safe := scanCellStoresRecursive(cell, seen)
	return vals, safe && len(vals) > 0
}

func scanCellStoresRecursive(cell ssa.Value, seen map[ssa.Value]bool) ([]ssa.Value, bool) {
	if cell == nil || cell.Referrers() == nil || seen[cell] {
		return nil, false
	}
	seen[cell] = true
	var vals []ssa.Value
	for _, ref := range *cell.Referrers() {
		more, safe := inspectCellStoreRef(cell, ref, seen)
		if !safe {
			return nil, false
		}
		vals = append(vals, more...)
	}
	return vals, true
}

func inspectCellStoreRef(cell ssa.Value, ref ssa.Instruction, seen map[ssa.Value]bool) ([]ssa.Value, bool) {
	switch r := ref.(type) {
	case *ssa.Store:
		if r.Addr != cell || r.Val == cell {
			return nil, false
		}
		if vetssa.IsNilConst(r.Val) {
			return nil, true
		}
		return []ssa.Value{r.Val}, true
	case *ssa.UnOp:
		return nil, r.Op == token.MUL
	case *ssa.DebugRef:
		return nil, true
	case *ssa.MakeClosure:
		return inspectClosureCellStores(r, cell, seen)
	default:
		return nil, false
	}
}

func inspectClosureCellStores(mc *ssa.MakeClosure, cell ssa.Value, seen map[ssa.Value]bool) ([]ssa.Value, bool) {
	fn, ok := mc.Fn.(*ssa.Function)
	if !ok || fn == nil {
		return nil, false
	}
	var vals []ssa.Value
	for i, b := range mc.Bindings {
		if b != cell {
			continue
		}
		if i >= len(fn.FreeVars) {
			return nil, false
		}
		more, safe := scanCellStoresRecursive(fn.FreeVars[i], seen)
		if !safe {
			return nil, false
		}
		vals = append(vals, more...)
	}
	return vals, true
}
