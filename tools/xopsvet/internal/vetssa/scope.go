package vetssa

import (
	"go/token"
	"go/types"
	"slices"

	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// ScopeRange 表示借用/明文污点值的合法生存期源码区间 [Start, End]；
// SecretOnly 仅当值严格源自 (*secret.SecretBox).Use 或 //xops:secretuse 回调形参时为 true，
// 多来源合并时同时收紧区间并对 SecretOnly 取逻辑与交集，阻断非机密借用混入 P4-T1 窄钩子。
type ScopeRange struct {
	Start, End token.Pos
	SecretOnly bool
}

const (
	emptyScopeStart token.Pos = 2
	emptyScopeEnd   token.Pos = 1
)

// Valid 判断作用域区间是否有效且非空。
func (s ScopeRange) Valid() bool { return s.Start.IsValid() && s.End.IsValid() && s.Start <= s.End }

func isUnsetScope(s ScopeRange) bool { return !s.Start.IsValid() || !s.End.IsValid() }
func isEmptyScope(s ScopeRange) bool { return s.Start.IsValid() && s.End.IsValid() && s.Start > s.End }

// TightenScope 返回两个作用域区间的最紧交集（有限高交半格 meet 运算）：
// 未设置零值为单位元，两区间无交集时归一化为吸收底元，杜绝不相交区间在不动点迭代中震荡，并对 SecretOnly 取逻辑与。
func TightenScope(a, b ScopeRange) ScopeRange {
	if isUnsetScope(a) {
		return b
	}
	if isUnsetScope(b) {
		return a
	}
	if isEmptyScope(a) || isEmptyScope(b) {
		return ScopeRange{Start: emptyScopeStart, End: emptyScopeEnd}
	}
	start, end := max(a.Start, b.Start), min(a.End, b.End)
	if start > end {
		return ScopeRange{Start: emptyScopeStart, End: emptyScopeEnd}
	}
	return ScopeRange{Start: start, End: end, SecretOnly: a.SecretOnly && b.SecretOnly}
}

// ScopeRangeOfFunc 安全提取 SSA 函数的合法生存期源码区间（兼容 FuncDecl / FuncLit / RangeStmt）。
func ScopeRangeOfFunc(fn *ssa.Function) ScopeRange {
	s, e, ok := FuncSyntaxRange(fn)
	if !ok {
		return ScopeRange{}
	}
	return ScopeRange{Start: s, End: e}
}

// UnaryFlowOperand 提取单操作数流传播指令的源 SSA 值（含 SliceToArrayPointer 与一元位/算术运算，C3）。
func UnaryFlowOperand(inst ssa.Instruction, includeRecvArrow bool) (ssa.Value, bool) {
	switch ins := inst.(type) {
	case *ssa.UnOp:
		return ins.X, ins.Op == token.MUL || ins.Op == token.XOR || ins.Op == token.SUB || ins.Op == token.NOT || (includeRecvArrow && ins.Op == token.ARROW)
	case *ssa.Slice:
		return ins.X, true
	case *ssa.SliceToArrayPointer:
		return ins.X, true
	case *ssa.Index:
		return ins.X, true
	case *ssa.IndexAddr:
		return ins.X, true
	case *ssa.Field:
		return ins.X, true
	case *ssa.FieldAddr:
		return ins.X, true
	case *ssa.Lookup:
		return ins.X, true
	case *ssa.Range:
		return ins.X, true
	case *ssa.Next:
		return ins.Iter, true
	case *ssa.Extract:
		return ins.Tuple, true
	case *ssa.Convert:
		return ins.X, true
	case *ssa.MultiConvert:
		return ins.X, true
	case *ssa.ChangeType:
		return ins.X, true
	case *ssa.MakeInterface:
		return ins.X, true
	case *ssa.ChangeInterface:
		return ins.X, true
	case *ssa.TypeAssert:
		return ins.X, true
	default:
		return nil, false
	}
}

// MarkValueScope 在值映射表中标记或收紧 v 的作用域，返回映射是否发生变化。
func MarkValueScope(m map[ssa.Value]ScopeRange, v ssa.Value, sc ScopeRange) bool {
	if v == nil {
		return false
	}
	if prev, ok := m[v]; ok {
		if next := TightenScope(prev, sc); next != prev {
			m[v] = next
			return true
		}
		return false
	}
	m[v] = sc
	return true
}

// CombinedScope 合并一组 SSA 值中所有已标记项的最紧作用域。
func CombinedScope(m map[ssa.Value]ScopeRange, vals ...ssa.Value) (ScopeRange, bool) {
	var sc ScopeRange
	found := false
	for _, v := range vals {
		if vsc, ok := m[v]; ok {
			sc, found = TightenScope(sc, vsc), true
		}
	}
	return sc, found
}

// CollectCaptured 将外层受控值映射沿 MakeClosure.Bindings 投影到内层闭包的 FreeVars 上。
func CollectCaptured(mc *ssa.MakeClosure, target *ssa.Function, outer map[ssa.Value]ScopeRange) map[ssa.Value]ScopeRange {
	if len(outer) == 0 || mc == nil || target == nil {
		return nil
	}
	out := make(map[ssa.Value]ScopeRange)
	for i, b := range mc.Bindings {
		if i < len(target.FreeVars) {
			if sc, ok := outer[b]; ok {
				out[target.FreeVars[i]] = sc
			}
		}
	}
	return out
}

// MarkRootsBackward 沿底层存储链反向标记局部根分配对象，并回传至直接父闭包的绑定槽位（C5）。
func MarkRootsBackward(dst ssa.Value, sc ScopeRange, local, outerShared map[ssa.Value]ScopeRange) bool {
	changed := false
	for _, root := range RootStorageValues(dst, true) {
		if _, isGlobal := root.(*ssa.Global); isGlobal {
			continue
		}
		changed = MarkValueScope(local, root, sc) || changed
		if fv, ok := root.(*ssa.FreeVar); ok && outerShared != nil {
			markImmediateFreeVarBindings(fv, sc, outerShared)
		}
	}
	return changed
}

// FlushFreeVarsToOuter 将当前闭包中已标记的 FreeVar 逐层回冲至直接父闭包，闭合 2 层以上嵌套同步闭包回写（C5）。
func FlushFreeVarsToOuter(fn *ssa.Function, local, outerShared map[ssa.Value]ScopeRange) {
	if fn == nil || outerShared == nil {
		return
	}
	for _, fv := range fn.FreeVars {
		if sc, ok := local[fv]; ok {
			markImmediateFreeVarBindings(fv, sc, outerShared)
		}
	}
}

func markImmediateFreeVarBindings(fv *ssa.FreeVar, sc ScopeRange, outerShared map[ssa.Value]ScopeRange) {
	fn := fv.Parent()
	if fn == nil || fn.Parent() == nil {
		return
	}
	if fvIdx := slices.Index(fn.FreeVars, fv); fvIdx >= 0 {
		ForEachInst(fn.Parent(), func(inst ssa.Instruction) {
			if mc, ok := inst.(*ssa.MakeClosure); ok && mc.Fn == fn && fvIdx < len(mc.Bindings) {
				MarkRootsBackward(mc.Bindings[fvIdx], sc, outerShared, nil)
			}
		})
	}
}

// PropagateBuiltinCopyAppend 统一处理内置 copy 与 append 的 SSA 传播（修复 C2 必反染非 nil 切片）。
func PropagateBuiltinCopyAppend(call *ssa.Call, rc ResolvedCall, local, outerShared map[ssa.Value]ScopeRange) bool {
	if rc.Builtin == nil {
		return false
	}
	switch rc.Builtin.Name() {
	case "copy":
		if len(rc.UserArgs) >= 2 {
			if sc, ok := local[rc.UserArgs[1]]; ok {
				return MarkRootsBackward(rc.UserArgs[0], sc, local, outerShared)
			}
		}
	case "append":
		if sc, ok := CombinedScope(local, rc.UserArgs...); ok {
			changed := MarkValueScope(local, call, sc)
			if len(rc.UserArgs) > 0 && !IsNilConst(rc.UserArgs[0]) {
				changed = MarkRootsBackward(rc.UserArgs[0], sc, local, outerShared) || changed
			}
			return changed
		}
	}
	return false
}

// SeedAllParamIndices 返回函数全部形参索引集合，供同步迭代器回调参数入种使用。
func SeedAllParamIndices(fn *ssa.Function) map[int]bool {
	seeds := make(map[int]bool, len(fn.Params))
	for i := range fn.Params {
		seeds[i] = true
	}
	return seeds
}

// CheckStdlibYieldClosure 统一判定 range-over-func yield 闭包是否来自标准库同步迭代器（H8/ST-6/LL-4）。
func CheckStdlibYieldClosure(s *buildssa.SSA, parentFn, yieldFn *ssa.Function, parentScope ScopeRange, parentTaint map[ssa.Value]ScopeRange) (ssa.CallInstruction, map[int]bool, ScopeRange, bool) {
	callInst, _, rc := FindYieldCall(s, parentFn, yieldFn)
	if callInst == nil || rc.Common == nil {
		return nil, nil, ScopeRange{}, false
	}
	iterCalls, allStd := ResolveStdlibIterCalls(s, rc.Common.Value)
	if !allStd {
		return callInst, nil, ScopeRange{}, false
	}
	yieldScope, hasSeed := parentScope, false
	for _, ic := range iterCalls {
		if iterSc, ok := parentTaint[ic]; ok {
			yieldScope, hasSeed = TightenScope(yieldScope, iterSc), true
		} else if argSc, ok := CombinedScope(parentTaint, ResolveCall(s, ic).UserArgs...); ok {
			yieldScope, hasSeed = TightenScope(yieldScope, argSc), true
		}
	}
	if hasSeed {
		return callInst, SeedAllParamIndices(yieldFn), yieldScope, true
	}
	return callInst, nil, yieldScope, true
}

// IsIterSeqSignature 判断类型是否为 iter.Seq / iter.Seq2 形态（func(yield func(...) bool)）。
func IsIterSeqSignature(t types.Type) bool {
	if t == nil {
		return false
	}
	sig, ok := types.Unalias(t).Underlying().(*types.Signature)
	if !ok || sig.Params() == nil || sig.Params().Len() != 1 || (sig.Results() != nil && sig.Results().Len() != 0) {
		return false
	}
	ySig, ok := types.Unalias(sig.Params().At(0).Type()).Underlying().(*types.Signature)
	if !ok || ySig.Results() == nil || ySig.Results().Len() != 1 {
		return false
	}
	b, ok := types.Unalias(ySig.Results().At(0).Type()).Underlying().(*types.Basic)
	return ok && b.Kind() == types.Bool
}

// IterCallbackTarget 描述直接调用 iter.Seq(cb) 解析出的单个回调函数目标（支持捕获闭包与零捕获函数）。
type IterCallbackTarget struct {
	Fn *ssa.Function
	MC *ssa.MakeClosure
}

// ResolveDirectStdlibIterCallback 统一解析直接调用标准库 iter.Seq(cb) 的所有回调目标（供 secrettaint/linearlease 共享）。
func ResolveDirectStdlibIterCallback(s *buildssa.SSA, rc ResolvedCall, scoped map[ssa.Value]ScopeRange) ([]IterCallbackTarget, ScopeRange, bool) {
	if rc.Common == nil || rc.Common.IsInvoke() || len(rc.UserArgs) != 1 || !IsIterSeqSignature(rc.Common.Value.Type()) {
		return nil, ScopeRange{}, false
	}
	iterSc, ok := scoped[rc.Common.Value]
	if !ok {
		return nil, ScopeRange{}, false
	}
	if _, allStd := ResolveStdlibIterCalls(s, rc.Common.Value); !allStd {
		return nil, ScopeRange{}, false
	}
	targets, allKnown := ResolveFuncValues(rc.UserArgs[0])
	if !allKnown || len(targets) == 0 {
		return nil, ScopeRange{}, false
	}
	out := make([]IterCallbackTarget, 0, len(targets))
	for _, tgt := range targets {
		item, ok := iterCallbackTargetFromValue(tgt)
		if !ok {
			return nil, ScopeRange{}, false
		}
		out = append(out, item)
	}
	return out, iterSc, true
}

func iterCallbackTargetFromValue(tgt ssa.Value) (IterCallbackTarget, bool) {
	switch t := tgt.(type) {
	case *ssa.MakeClosure:
		fn, ok := t.Fn.(*ssa.Function)
		return IterCallbackTarget{Fn: fn, MC: t}, ok && fn != nil && len(fn.Blocks) > 0 && !IsBoundWrapper(fn)
	case *ssa.Function:
		return IterCallbackTarget{Fn: t}, len(t.Blocks) > 0 && !IsBoundWrapper(t)
	default:
		return IterCallbackTarget{}, false
	}
}

// ResolveStdlibIterCalls 追溯 iter.Seq 值的全部来源调用，全分支皆标准库同步迭代器时返回 true。
func ResolveStdlibIterCalls(s *buildssa.SSA, v ssa.Value) ([]*ssa.Call, bool) {
	var calls []*ssa.Call
	ok := collectStdlibIterCalls(s, v, make(map[ssa.Value]bool), &calls)
	return calls, ok && len(calls) > 0
}

func collectStdlibIterCalls(s *buildssa.SSA, v ssa.Value, seen map[ssa.Value]bool, out *[]*ssa.Call) bool {
	if v == nil {
		return false
	}
	if seen[v] {
		return true
	}
	seen[v] = true
	if inner, ok := unwrapFuncWrapper(v); ok {
		return collectStdlibIterCalls(s, inner, seen, out)
	}
	switch val := v.(type) {
	case *ssa.Call:
		if !IsStdlibSyncIter(ResolveCall(s, val).FuncObj) {
			return false
		}
		*out = append(*out, val)
		return true
	case *ssa.Phi:
		return len(val.Edges) > 0 && !slices.ContainsFunc(val.Edges, func(e ssa.Value) bool {
			return !IsNilConst(e) && !collectStdlibIterCalls(s, e, seen, out)
		})
	case *ssa.UnOp:
		alloc, ok := val.X.(*ssa.Alloc)
		if val.Op != token.MUL || !ok {
			return false
		}
		vals, found, safe := scanCellStores(alloc, nil)
		return safe && found && !slices.ContainsFunc(vals, func(sv ssa.Value) bool { return !collectStdlibIterCalls(s, sv, seen, out) })
	default:
		return false
	}
}

// AllRootsOwnedInScope 校验写入目标 addr 对应的全部真实底层存储根均属于合法作用域 sc 且不含 callerParams（C1/M5）。
func AllRootsOwnedInScope(addr ssa.Value, sc ScopeRange, callerParams map[ssa.Value]bool) bool {
	roots, allKnown := WriteTargetRoots(addr, true)
	if !allKnown || len(roots) == 0 {
		return false
	}
	return !slices.ContainsFunc(roots, func(root ssa.Value) bool {
		return root == nil || callerParams[root] || !isRootOwned(root, sc)
	})
}

func isRootOwned(root ssa.Value, sc ScopeRange) bool {
	if fv, ok := root.(*ssa.FreeVar); ok {
		origins := TraceFreeVarOrigins(fv)
		return len(origins) > 0 && !slices.ContainsFunc(origins, func(o ssa.Value) bool { return !IsValueOwnedInScope(o, sc.Start, sc.End) })
	}
	return IsValueOwnedInScope(root, sc.Start, sc.End)
}

// IsAllowedSliceWriteDst 判断切片写入目标是否为全新局部切片或当前作用域拥有的局部存储。
func IsAllowedSliceWriteDst(dst ssa.Value, sc ScopeRange, callerParams map[ssa.Value]bool) bool {
	return IsFreshLocalSlice(dst) || AllRootsOwnedInScope(dst, sc, callerParams)
}

// ExtractVarargsElements 提取 go/ssa 为可变参数调用打包的局部数组元素（Comment == "varargs"）。
func ExtractVarargsElements(arg ssa.Value) []ssa.Value {
	sl, ok := arg.(*ssa.Slice)
	if !ok {
		return nil
	}
	alloc, ok := sl.X.(*ssa.Alloc)
	if !ok || alloc.Comment != "varargs" || alloc.Referrers() == nil {
		return nil
	}
	var elems []ssa.Value
	for _, ref := range *alloc.Referrers() {
		if ia, ok := ref.(*ssa.IndexAddr); ok && ia.Referrers() != nil {
			for _, stRef := range *ia.Referrers() {
				if st, ok := stRef.(*ssa.Store); ok && st.Addr == ia {
					elems = append(elems, st.Val)
				}
			}
		}
	}
	return elems
}

// IsVarargsSliceStore 判断写入目标地址是否为编译器为可变参数调用生成的临时 varargs 数组槽位。
func IsVarargsSliceStore(addr ssa.Value) bool {
	ia, ok := addr.(*ssa.IndexAddr)
	if !ok {
		return false
	}
	alloc, ok := ia.X.(*ssa.Alloc)
	return ok && alloc.Comment == "varargs"
}

// IsBoundMethodVal 判断闭包值是否为方法值绑定包装器（recv.Method）。
func IsBoundMethodVal(mc *ssa.MakeClosure) bool {
	if mc == nil {
		return false
	}
	fn, ok := mc.Fn.(*ssa.Function)
	return ok && IsBoundWrapper(fn)
}

// IsNilConst 判断 SSA 值是否为类型化 nil 常量。
func IsNilConst(v ssa.Value) bool { c, ok := v.(*ssa.Const); return ok && c.IsNil() }

// UnwrapDirectParam 剥离同构/类型转换并提取底层 *ssa.Parameter（供回调透传豁免复用）。
func UnwrapDirectParam(v ssa.Value) *ssa.Parameter {
	for {
		switch val := v.(type) {
		case *ssa.Parameter:
			return val
		case *ssa.ChangeType:
			v = val.X
		case *ssa.Convert:
			v = val.X
		default:
			return nil
		}
	}
}

// UnwrapInterface 剥离 SSA 值外层的接口装箱与同构类型转换指令。
func UnwrapInterface(v ssa.Value) ssa.Value {
	for {
		switch val := v.(type) {
		case *ssa.MakeInterface:
			v = val.X
		case *ssa.ChangeInterface:
			v = val.X
		case *ssa.ChangeType:
			v = val.X
		default:
			return v
		}
	}
}
