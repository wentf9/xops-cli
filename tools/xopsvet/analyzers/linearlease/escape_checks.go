package linearlease

import (
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"golang.org/x/tools/go/ssa"
)

func (ls *leaseScope) report(inst ssa.Instruction, msg string) {
	vetssa.AppendDiag(ls.eng.pass, &ls.eng.diags, ls.fn, inst, msg)
}

func (ls *leaseScope) checkInst(inst ssa.Instruction) {
	switch ins := inst.(type) {
	case ssa.CallInstruction:
		ls.checkCallInst(ins)
	case *ssa.Store:
		ls.checkStore(ins)
	case *ssa.MapUpdate:
		if _, ok := vetssa.CombinedScope(ls.borrowed, ins.Key, ins.Value); ok {
			ls.report(ins, "linearlease: 禁止将 //xops:borrowed 借用变量存入复合字面量")
		}
	case *ssa.Send:
		if _, ok := ls.borrowed[ins.X]; ok {
			ls.report(ins, "linearlease: 禁止将 //xops:borrowed 借用变量发送至 channel")
		}
	case *ssa.Panic:
		if _, ok := ls.borrowed[ins.X]; ok {
			ls.report(ins, "linearlease: 禁止将 //xops:borrowed 借用变量传入 panic")
		}
	case *ssa.Return:
		for _, r := range ins.Results {
			if _, ok := ls.borrowed[r]; ok && !ls.isNamedResultLoad(r) {
				ls.report(ins, "linearlease: 禁止通过 return 返回 //xops:borrowed 借用变量")
				return
			}
		}
	}
}

func (ls *leaseScope) isNamedResultLoad(v ssa.Value) bool {
	u, ok := v.(*ssa.UnOp)
	if !ok || u.Op != token.MUL {
		return false
	}
	a, isAlloc := u.X.(*ssa.Alloc)
	return isAlloc && ls.namedResAllocs[a]
}

func (ls *leaseScope) checkStore(ins *ssa.Store) {
	sc, ok := ls.borrowed[ins.Val]
	if !ok || vetssa.IsVarargsSliceStore(ins.Addr) || isBoundMethodValue(ins.Val) {
		return
	}
	if call, isCall := ins.Val.(*ssa.Call); isCall && ls.reportedAppends[call] {
		return
	}
	if fa, isField := ins.Addr.(*ssa.FieldAddr); isField {
		if a, ok := fa.X.(*ssa.Alloc); ok && a.Comment == "complit" {
			ls.report(ins, "linearlease: 禁止将 //xops:borrowed 借用变量存入复合字面量")
		} else {
			ls.report(ins, "linearlease: 禁止将 //xops:borrowed 借用变量写入结构体字段")
		}
		return
	}
	if isCompositeSliceStore(ins.Addr) {
		ls.report(ins, "linearlease: 禁止将 //xops:borrowed 借用变量存入复合字面量")
	} else if ls.storesToNamedResult(ins.Addr) || !vetssa.AllRootsOwnedInScope(ins.Addr, sc, ls.callerParams) {
		ls.report(ins, "linearlease: 禁止将 //xops:borrowed 借用变量逃逸至外层变量或具名返回值")
	}
}

// storesToNamedResult 检查写入地址是否命中本层或任意外层祖先函数的具名返回值槽位（LL-2）。
func (ls *leaseScope) storesToNamedResult(addr ssa.Value) bool {
	return slices.ContainsFunc(vetssa.RootStorageValues(addr, true), func(root ssa.Value) bool {
		if a, ok := root.(*ssa.Alloc); ok && ls.namedResAllocs[a] {
			return true
		}
		if fv, ok := root.(*ssa.FreeVar); ok {
			return slices.ContainsFunc(vetssa.TraceFreeVarOrigins(fv), func(orig ssa.Value) bool {
				a, isAlloc := orig.(*ssa.Alloc)
				return isAlloc && ls.namedResAllocs[a]
			})
		}
		return false
	})
}

func (ls *leaseScope) checkMakeClosure(mc *ssa.MakeClosure) {
	target, ok := mc.Fn.(*ssa.Function)
	if !ok || target == nil {
		return
	}
	if vetssa.IsBoundWrapper(target) {
		if _, ok := vetssa.CombinedScope(ls.borrowed, mc.Bindings...); ok && !isDirectSyncCallOnly(mc) {
			ls.report(mc, "linearlease: 禁止将 //xops:borrowed 接收者的未调用方法值转存或逃逸")
		}
		return
	}
	if vetssa.IsYieldFunc(target) {
		ls.checkYieldClosure(mc, target)
	}
}

func (ls *leaseScope) checkYieldClosure(mc *ssa.MakeClosure, target *ssa.Function) {
	captured := vetssa.CollectCaptured(mc, target, ls.borrowed)
	callInst, seeds, yScope, isStd := vetssa.CheckStdlibYieldClosure(ls.eng.ssaInfo, ls.fn, target, ls.ownScope, ls.borrowed)
	if !isStd {
		iterBorrowed := callInst != nil && callInst.Common() != nil && ls.borrowed[callInst.Common().Value].Valid()
		if len(captured) > 0 || iterBorrowed {
			reportInst := ssa.Instruction(mc)
			if callInst != nil {
				reportInst = callInst
			}
			ls.report(reportInst, "linearlease: 禁止在非标准库自定义迭代器中捕获 //xops:borrowed 借用变量")
		}
		return
	}
	if len(seeds) > 0 || len(captured) > 0 {
		ls.eng.auditFunc(target, seeds, captured, yScope, ls.depth+1, ls.borrowed, ls.namedResAllocs, callInst)
	}
}

func (ls *leaseScope) checkCallInst(callInst ssa.CallInstruction) {
	if goInst, isGo := callInst.(*ssa.Go); isGo {
		rc := vetssa.ResolveCall(ls.eng.ssaInfo, goInst)
		_, argBorrowed := vetssa.CombinedScope(ls.borrowed, rc.UserArgs...)
		_, recvBorrowed := ls.borrowed[rc.Recv]
		if _, fnBorrowed := ls.borrowed[goInst.Call.Value]; fnBorrowed || argBorrowed || recvBorrowed {
			ls.report(goInst, "linearlease: 禁止在 go 语句中调用捕获了 //xops:borrowed 变量的闭包")
		}
		return
	}
	rc := vetssa.ResolveCall(ls.eng.ssaInfo, callInst)
	if rc.Kind == vetssa.CallBuiltin && rc.Builtin != nil {
		ls.checkBuiltinCall(callInst, rc)
		return
	}
	if rc.Common != nil && !rc.Common.IsInvoke() && !ls.auditedIterCalls[callInst] &&
		ls.borrowed[rc.Common.Value].Valid() && vetssa.IsIterSeqSignature(rc.Common.Value.Type()) {
		ls.report(callInst, "linearlease: 禁止对非标准库或未知来源的借用迭代器执行回调调用")
		return
	}
	spec := resolveSSACallLeaseSpec(ls.eng.pass, ls.eng.facts, ls.eng.secretFacts, rc)
	isLocalCallee := ls.isAuditableLocalClosureCallee(rc)
	for _, arg := range rc.UserArgs {
		ls.checkSingleClosureArg(callInst, arg, spec.syncClosure, isLocalCallee)
	}
}

func (ls *leaseScope) checkBuiltinCall(callInst ssa.CallInstruction, rc vetssa.ResolvedCall) {
	switch rc.Builtin.Name() {
	case "copy":
		ls.checkCopyBuiltin(callInst, rc)
	case "append":
		ls.checkAppendBuiltin(callInst, rc)
	}
}

func (ls *leaseScope) checkCopyBuiltin(callInst ssa.CallInstruction, rc vetssa.ResolvedCall) {
	if len(rc.UserArgs) < 2 {
		return
	}
	sc, ok := ls.borrowed[rc.UserArgs[1]]
	if !ok || vetssa.IsAllowedSliceWriteDst(rc.UserArgs[0], sc, ls.callerParams) {
		return
	}
	if isDirectOuterSliceLoad(rc.UserArgs[0]) {
		ls.report(callInst, "linearlease: 禁止通过 copy 将 //xops:borrowed 借用变量逃逸至外层切片")
		return
	}
	ls.report(callInst, "linearlease: 禁止通过 copy 将 //xops:borrowed 借用变量写入非新建局部切片目标")
}

func (ls *leaseScope) checkAppendBuiltin(callInst ssa.CallInstruction, rc vetssa.ResolvedCall) {
	if len(rc.UserArgs) < 2 {
		return
	}
	if _, elemBorrowed := vetssa.CombinedScope(ls.borrowed, rc.UserArgs[1:]...); elemBorrowed {
		if call, ok := callInst.(*ssa.Call); ok {
			ls.reportedAppends[call] = true
		}
		ls.report(callInst, "linearlease: 禁止通过 append 将 //xops:borrowed 借用变量存入切片")
	}
}

func (ls *leaseScope) auditDirectIterCall(callInst ssa.CallInstruction, rc vetssa.ResolvedCall) bool {
	targets, iterSc, ok := vetssa.ResolveDirectStdlibIterCallback(ls.eng.ssaInfo, rc, ls.borrowed)
	if !ok {
		return false
	}
	for _, tgt := range targets {
		ls.eng.auditFunc(tgt.Fn, vetssa.SeedAllParamIndices(tgt.Fn), vetssa.CollectCaptured(tgt.MC, tgt.Fn, ls.borrowed), iterSc, ls.depth+1, ls.borrowed, ls.namedResAllocs, callInst)
	}
	return true
}

func (ls *leaseScope) auditInvokedLocalClosure(callInst ssa.CallInstruction, rc vetssa.ResolvedCall) {
	targets, _ := vetssa.ResolveFuncValues(rc.Common.Value)
	for _, tgt := range targets {
		ls.auditInvokedTarget(callInst, rc, tgt)
	}
}

func (ls *leaseScope) auditInvokedTarget(callInst ssa.CallInstruction, rc vetssa.ResolvedCall, tgt ssa.Value) {
	switch t := tgt.(type) {
	case *ssa.MakeClosure:
		fn, ok := t.Fn.(*ssa.Function)
		if !ok || fn == nil || vetssa.IsBoundWrapper(fn) || vetssa.IsYieldFunc(fn) {
			return
		}
		seeds, captured := vetssa.CollectCallSeeds(rc, ls.borrowed, len(fn.Params), nil), vetssa.CollectCaptured(t, fn, ls.borrowed)
		if len(seeds) > 0 || len(captured) > 0 {
			ls.eng.auditFunc(fn, seeds, captured, ls.ownScope, ls.depth+1, ls.borrowed, ls.namedResAllocs, callInst)
		}
	case *ssa.Function:
		if t.Parent() != nil && !vetssa.IsBoundWrapper(t) && !vetssa.IsYieldFunc(t) {
			if seeds := vetssa.CollectCallSeeds(rc, ls.borrowed, len(t.Params), nil); len(seeds) > 0 {
				ls.eng.auditFunc(t, seeds, nil, ls.ownScope, ls.depth+1, ls.borrowed, ls.namedResAllocs, callInst)
			}
		}
	}
}

func (ls *leaseScope) auditSyncClosureArgRec(callInst ssa.CallInstruction, arg ssa.Value) {
	if varElems := vetssa.ExtractVarargsElements(arg); len(varElems) > 0 {
		for _, elem := range varElems {
			ls.auditSyncClosureArgRec(callInst, elem)
		}
		return
	}
	if !ls.isBorrowedFuncValue(arg) || isSpecialClosureArg(arg) {
		return
	}
	targets, _ := vetssa.ResolveFuncValues(arg)
	for _, tgt := range targets {
		ls.auditSingleSyncClosureTarget(callInst, tgt)
	}
}

func (ls *leaseScope) auditSingleSyncClosureTarget(callInst ssa.CallInstruction, tgt ssa.Value) {
	mc, ok := tgt.(*ssa.MakeClosure)
	if !ok {
		return
	}
	fn, ok := mc.Fn.(*ssa.Function)
	if ok && fn != nil && !vetssa.IsYieldFunc(fn) && !vetssa.IsBoundWrapper(fn) {
		if captured := vetssa.CollectCaptured(mc, fn, ls.borrowed); len(captured) > 0 {
			ls.eng.auditFunc(fn, nil, captured, ls.ownScope, ls.depth+1, ls.borrowed, ls.namedResAllocs, callInst)
		}
	}
}

func (ls *leaseScope) checkSingleClosureArg(callInst ssa.CallInstruction, arg ssa.Value, isSync, isLocalCallee bool) {
	if varElems := vetssa.ExtractVarargsElements(arg); len(varElems) > 0 {
		for _, elem := range varElems {
			ls.checkSingleClosureArg(callInst, elem, isSync, isLocalCallee)
		}
		return
	}
	if !ls.isBorrowedFuncValue(arg) || isSpecialClosureArg(arg) {
		return
	}
	if isSync || isLocalCallee {
		if _, allKnown := vetssa.ResolveFuncValues(arg); !allKnown {
			ls.report(callInst, "linearlease: 禁止将捕获了 //xops:borrowed 变量的无法解析闭包传入同步调用")
		}
		return
	}
	if _, isDirectMC := arg.(*ssa.MakeClosure); isDirectMC {
		ls.report(callInst, "linearlease: 禁止在非同步子闭包中捕获 //xops:borrowed 借用变量")
	} else {
		ls.report(callInst, "linearlease: 禁止将捕获了 //xops:borrowed 变量的闭包传入非同步调用")
	}
}

func (ls *leaseScope) auditSamePkgBorrowedHelperCall(callInst ssa.CallInstruction, rc vetssa.ResolvedCall) {
	if rc.TargetFn == nil || len(rc.TargetFn.Blocks) == 0 || vetssa.IsBoundWrapper(rc.TargetFn) {
		return
	}
	if seeds := vetssa.CollectCallSeeds(rc, ls.borrowed, len(rc.TargetFn.Params), func(v ssa.Value) bool { return !ls.isBorrowedFuncValue(v) }); len(seeds) > 0 {
		ls.eng.auditFunc(rc.TargetFn, seeds, nil, vetssa.ScopeRangeOfFunc(rc.TargetFn), ls.depth+1, nil, nil, callInst)
	}
}

func (ls *leaseScope) isAuditableLocalClosureCallee(rc vetssa.ResolvedCall) bool {
	if rc.Common == nil || rc.Common.IsInvoke() {
		return false
	}
	targets, allKnown := vetssa.ResolveFuncValues(rc.Common.Value)
	return allKnown && len(targets) > 0 && !slices.ContainsFunc(targets, func(t ssa.Value) bool { return !isLocalAnonClosureTarget(t) })
}

func isLocalAnonClosureTarget(t ssa.Value) bool {
	switch fnVal := t.(type) {
	case *ssa.MakeClosure:
		fn, ok := fnVal.Fn.(*ssa.Function)
		return ok && fn != nil && len(fn.Blocks) > 0 && !vetssa.IsBoundWrapper(fn)
	case *ssa.Function:
		return fnVal.Parent() != nil && len(fnVal.Blocks) > 0 && !vetssa.IsBoundWrapper(fnVal)
	default:
		return false
	}
}

func isBoundMethodValue(v ssa.Value) bool {
	targets, allKnown := vetssa.ResolveFuncValues(v)
	return allKnown && len(targets) > 0 && !slices.ContainsFunc(targets, func(t ssa.Value) bool {
		mc, ok := t.(*ssa.MakeClosure)
		return !ok || !vetssa.IsBoundMethodVal(mc)
	})
}

func isSpecialClosureArg(arg ssa.Value) bool {
	targets, allKnown := vetssa.ResolveFuncValues(arg)
	return allKnown && len(targets) > 0 && !slices.ContainsFunc(targets, func(t ssa.Value) bool {
		mc, ok := t.(*ssa.MakeClosure)
		if !ok {
			return true
		}
		fn, isFn := mc.Fn.(*ssa.Function)
		return !vetssa.IsBoundMethodVal(mc) && (!isFn || !vetssa.IsYieldFunc(fn))
	})
}

func (ls *leaseScope) isBorrowedFuncValue(v ssa.Value) bool {
	if _, ok := ls.borrowed[v]; !ok {
		return false
	}
	_, isSig := types.Unalias(v.Type()).Underlying().(*types.Signature)
	return isSig
}

func isDirectOuterSliceLoad(dst ssa.Value) bool {
	if _, isParam := dst.(*ssa.Parameter); isParam {
		return true
	}
	if u, ok := dst.(*ssa.UnOp); ok && u.Op == token.MUL {
		switch u.X.(type) {
		case *ssa.Global, *ssa.FreeVar, *ssa.Parameter:
			return true
		}
	}
	return false
}

func isDirectSyncCallOnly(mc *ssa.MakeClosure) bool {
	if mc.Referrers() == nil || len(*mc.Referrers()) == 0 {
		return false
	}
	for _, ref := range *mc.Referrers() {
		callInst, isCall := ref.(ssa.CallInstruction)
		_, isGo := callInst.(*ssa.Go)
		if !isCall || isGo || callInst.Common() == nil || callInst.Common().Value != mc {
			return false
		}
	}
	return true
}

func isCompositeSliceStore(addr ssa.Value) bool {
	ia, ok := addr.(*ssa.IndexAddr)
	if !ok {
		return false
	}
	alloc, ok := ia.X.(*ssa.Alloc)
	return ok && (alloc.Comment == "slicelit" || alloc.Comment == "complit")
}

func indicesToMap(indices []int, offset int) map[int]bool {
	out := make(map[int]bool, len(indices))
	for _, idx := range indices {
		out[idx+offset] = true
	}
	return out
}
