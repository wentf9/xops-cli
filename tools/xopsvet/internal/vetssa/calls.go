package vetssa

import (
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// CallKind 标识经 CallSiteResolver 归一化后的 SSA 调用形态。
type CallKind uint8

const (
	CallStaticPkg CallKind = iota
	CallMethodVal
	CallMethodThunk
	CallMethodBound
	CallInvoke
	CallBuiltin
	CallDynamic
)

// ResolvedCall 保存经统一解包与接收者槽位归一后的调用站点元数据（UserArgs 严格对齐声明签名 Params）。
type ResolvedCall struct {
	Kind     CallKind
	Inst     ssa.CallInstruction
	Common   *ssa.CallCommon
	FuncObj  *types.Func
	TargetFn *ssa.Function
	Builtin  *ssa.Builtin
	Closure  *ssa.MakeClosure
	Recv     ssa.Value
	UserArgs []ssa.Value
}

// ResolveCall 将任意 ssa.CallInstruction 归一化为统一 ResolvedCall，
// 消解泛型包装器（Pkg == nil）、接口 IsInvoke()、$thunk 方法表达式与 $bound 方法值接收者偏移。
func ResolveCall(s *buildssa.SSA, inst ssa.CallInstruction) ResolvedCall {
	rc := ResolvedCall{Inst: inst}
	if inst == nil || inst.Common() == nil {
		return rc
	}
	cc := inst.Common()
	rc.Common = cc
	if cc.IsInvoke() {
		rc.Kind, rc.Recv, rc.UserArgs = CallInvoke, cc.Value, cc.Args
		if cc.Method != nil {
			rc.FuncObj = cc.Method.Origin()
		}
		return rc
	}
	if b, ok := cc.Value.(*ssa.Builtin); ok {
		rc.Kind, rc.Builtin, rc.UserArgs = CallBuiltin, b, cc.Args
		return rc
	}
	if callee := cc.StaticCallee(); callee != nil {
		return resolveStaticCallee(s, rc, cc, callee)
	}
	rc.Kind, rc.UserArgs = CallDynamic, cc.Args
	return rc
}

func resolveStaticCallee(s *buildssa.SSA, rc ResolvedCall, cc *ssa.CallCommon, callee *ssa.Function) ResolvedCall {
	rc.Closure, _ = cc.Value.(*ssa.MakeClosure)
	if IsBoundWrapper(callee) {
		rc.Kind, rc.FuncObj, rc.UserArgs = CallMethodBound, OriginFuncObj(callee), cc.Args
		rc.TargetFn = LookupPackageFunc(s, rc.FuncObj)
		if rc.Closure != nil && len(rc.Closure.Bindings) > 0 {
			rc.Recv = rc.Closure.Bindings[0]
		}
		return rc
	}
	if IsThunkWrapper(callee) {
		rc.Kind, rc.FuncObj = CallMethodThunk, OriginFuncObj(callee)
		rc.TargetFn = LookupPackageFunc(s, rc.FuncObj)
		if len(cc.Args) > 0 {
			rc.Recv, rc.UserArgs = cc.Args[0], cc.Args[1:]
		}
		return rc
	}
	origFn := UnwrapOriginFunc(callee)
	rc.FuncObj = OriginFuncObj(origFn)
	if strings.HasPrefix(origFn.Synthetic, "wrapper for ") {
		rc.TargetFn = LookupPackageFunc(s, rc.FuncObj)
	} else if IsSamePackageFunc(s, origFn) {
		rc.TargetFn = origFn
	}
	if callee.Signature != nil && callee.Signature.Recv() != nil {
		rc.Kind = CallMethodVal
		if len(cc.Args) > 0 {
			rc.Recv, rc.UserArgs = cc.Args[0], cc.Args[1:]
		}
		return rc
	}
	rc.Kind, rc.UserArgs = CallStaticPkg, cc.Args
	return rc
}

// ResolveFuncValues 逆向追踪任意 SSA 函数值（支持 MakeClosure/Function/Phi/Alloc+Store/Interface/TypeAssert），
// 若存在任意无法静态确定的路径则 allKnown 返回 false（供 secrettaint/linearlease 执行 Fail-Closed）。
func ResolveFuncValues(v ssa.Value) (funcs []ssa.Value, allKnown bool) {
	if v == nil {
		return nil, false
	}
	ok := collectFuncValues(v, make(map[ssa.Value]bool), &funcs)
	return funcs, ok && len(funcs) > 0
}

func collectFuncValues(v ssa.Value, seen map[ssa.Value]bool, out *[]ssa.Value) bool {
	if v == nil {
		return false
	}
	if seen[v] {
		return true
	}
	seen[v] = true
	if inner, ok := unwrapFuncWrapper(v); ok {
		return collectFuncValues(inner, seen, out)
	}
	switch val := v.(type) {
	case *ssa.Function, *ssa.MakeClosure:
		*out = append(*out, val)
		return true
	case *ssa.Phi:
		return collectPhiFuncValues(val, seen, out)
	case *ssa.UnOp:
		return val.Op.String() == "*" && collectLoadedFuncValues(val.X, seen, out)
	default:
		return false
	}
}

func unwrapFuncWrapper(v ssa.Value) (ssa.Value, bool) {
	switch val := v.(type) {
	case *ssa.ChangeType:
		return val.X, true
	case *ssa.Convert:
		return val.X, true
	case *ssa.MultiConvert:
		return val.X, true
	case *ssa.MakeInterface:
		return val.X, true
	case *ssa.ChangeInterface:
		return val.X, true
	case *ssa.TypeAssert:
		return val.X, true
	case *ssa.Extract:
		if ta, ok := val.Tuple.(*ssa.TypeAssert); ok && val.Index == 0 {
			return ta.X, true
		}
	}
	return nil, false
}

func collectPhiFuncValues(phi *ssa.Phi, seen map[ssa.Value]bool, out *[]ssa.Value) bool {
	found := false
	for _, edge := range phi.Edges {
		if IsNilConst(edge) {
			continue
		}
		if !collectFuncValues(edge, seen, out) {
			return false
		}
		found = true
	}
	return found
}

// collectLoadedFuncValues 解析栈槽 Alloc 中的函数值，若存在任何非直接 Store/读/DebugRef 引用者则 fail-closed（修复 C4）。
func collectLoadedFuncValues(addr ssa.Value, seen map[ssa.Value]bool, out *[]ssa.Value) bool {
	alloc, ok := addr.(*ssa.Alloc)
	if !ok {
		return false
	}
	vals, found, safe := scanCellStores(alloc, nil)
	if !safe || !found {
		return false
	}
	for _, v := range vals {
		if !collectFuncValues(v, seen, out) {
			return false
		}
	}
	return true
}
