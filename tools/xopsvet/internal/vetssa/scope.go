package vetssa

import (
	"go/token"

	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// ScopeRange 表示借用/明文污点值的合法生存期源码区间 [Start, End]，多来源合并始终收紧至交集。
type ScopeRange struct{ Start, End token.Pos }

// Valid 判断作用域区间是否有效。
func (s ScopeRange) Valid() bool { return s.Start.IsValid() && s.End.IsValid() }

// TightenScope 返回两个作用域区间的最紧交集区间。
func TightenScope(a, b ScopeRange) ScopeRange {
	if !a.Valid() {
		return b
	}
	if !b.Valid() {
		return a
	}
	return ScopeRange{Start: max(a.Start, b.Start), End: min(a.End, b.End)}
}

// ScopeRangeOfFunc 安全提取 SSA 函数的合法生存期源码区间（兼容 FuncDecl / FuncLit / RangeStmt）。
func ScopeRangeOfFunc(fn *ssa.Function) ScopeRange {
	s, e, ok := FuncSyntaxRange(fn)
	if !ok {
		return ScopeRange{}
	}
	return ScopeRange{Start: s, End: e}
}

// UnaryFlowOperand 提取单操作数流传播指令的源 SSA 值（统一服务 osboundary / secretbox / secrettaint / linearlease）。
func UnaryFlowOperand(inst ssa.Instruction, includeRecvArrow bool) (ssa.Value, bool) {
	switch ins := inst.(type) {
	case *ssa.UnOp:
		return ins.X, ins.Op == token.MUL || (includeRecvArrow && ins.Op == token.ARROW)
	case *ssa.Slice:
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

// MarkRootsBackward 沿底层存储链反向标记局部根分配对象（HIGH-1 陷阱 4），不反染 *ssa.Global。
func MarkRootsBackward(dst ssa.Value, sc ScopeRange, local, outerShared map[ssa.Value]ScopeRange) bool {
	changed := false
	for _, root := range RootStorageValues(dst, true) {
		if _, isGlobal := root.(*ssa.Global); isGlobal {
			continue
		}
		changed = MarkValueScope(local, root, sc) || changed
		if fv, ok := root.(*ssa.FreeVar); ok && outerShared != nil {
			for _, orig := range TraceFreeVarOrigins(fv) {
				if _, isGlobal := orig.(*ssa.Global); !isGlobal {
					MarkValueScope(outerShared, orig, sc)
				}
			}
		}
	}
	return changed
}

// PropagateBuiltinCopyAppend 统一处理内置 copy 与 append 的 SSA 前向/后向污点与借用传播。
func PropagateBuiltinCopyAppend(call *ssa.Call, rc ResolvedCall, local, outerShared map[ssa.Value]ScopeRange) bool {
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
			if len(rc.UserArgs) > 0 && !IsFreshLocalSlice(rc.UserArgs[0]) && !IsNilConst(rc.UserArgs[0]) {
				changed = MarkRootsBackward(rc.UserArgs[0], sc, local, outerShared) || changed
			}
			return changed
		}
	}
	return false
}

// CheckStdlibYieldClosure 统一判定 range-over-func yield 闭包是否来自标准库同步迭代器（HIGH-1 陷阱 3）。
func CheckStdlibYieldClosure(
	s *buildssa.SSA, parentFn, yieldFn *ssa.Function, parentScope ScopeRange, parentTaint map[ssa.Value]ScopeRange,
) (ssa.CallInstruction, map[int]bool, ScopeRange, bool) {
	callInst, _, rc := FindYieldCall(s, parentFn, yieldFn)
	if callInst == nil || rc.Common == nil {
		return nil, nil, ScopeRange{}, true
	}
	iterCall, isCall := rc.Common.Value.(*ssa.Call)
	if !isCall || !IsStdlibSyncIter(ResolveCall(s, iterCall).FuncObj) {
		return callInst, nil, ScopeRange{}, false
	}
	yieldScope := parentScope
	var seeds map[int]bool
	if iterSc, ok := parentTaint[iterCall]; ok {
		yieldScope = TightenScope(yieldScope, iterSc)
		seeds = make(map[int]bool, len(yieldFn.Params))
		for i := range yieldFn.Params {
			seeds[i] = true
		}
	}
	return callInst, seeds, yieldScope, true
}

// AllRootsOwnedInScope 校验写入目标 addr 对应的全部根存储对象均属于合法作用域 sc 且不含 callerParams（C4）。
func AllRootsOwnedInScope(addr ssa.Value, sc ScopeRange, callerParams map[ssa.Value]bool) bool {
	roots := RootStorageValues(addr, true)
	if len(roots) == 0 {
		return false
	}
	for _, root := range roots {
		if root == nil || callerParams[root] || !isRootOwned(root, sc) {
			return false
		}
	}
	return true
}

func isRootOwned(root ssa.Value, sc ScopeRange) bool {
	if fv, ok := root.(*ssa.FreeVar); ok {
		origins := TraceFreeVarOrigins(fv)
		if len(origins) == 0 {
			return false
		}
		for _, orig := range origins {
			if !IsValueOwnedInScope(orig, sc.Start, sc.End) {
				return false
			}
		}
		return true
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
func IsNilConst(v ssa.Value) bool {
	c, ok := v.(*ssa.Const)
	return ok && c.IsNil()
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
