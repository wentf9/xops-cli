package secrettaint

import (
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/ssa"
)

func (ts *taintScope) report(inst ssa.Instruction, msg string) {
	vetssa.AppendDiag(ts.eng.pass, &ts.eng.diags, ts.fn, inst, msg)
}

func (ts *taintScope) checkInst(inst ssa.Instruction) {
	switch ins := inst.(type) {
	case *ssa.Store:
		ts.checkStore(ins)
	case *ssa.MapUpdate:
		if _, ok := vetssa.CombinedScope(ts.tainted, ins.Key, ins.Value); ok {
			ts.report(ins, "secrettaint: 禁止将明文机密存入结构体或非字节切片容器字面量")
		}
	case *ssa.Send:
		if _, ok := ts.tainted[ins.X]; ok {
			ts.report(ins, "secrettaint: 禁止将明文机密发送至 channel")
		}
	case *ssa.Panic:
		if _, ok := ts.tainted[ins.X]; ok {
			ts.report(ins, "secrettaint: 禁止将明文机密传入 panic")
		}
	case *ssa.Return:
		ts.checkReturn(ins)
	case *ssa.Go:
		rc := vetssa.ResolveCall(ts.eng.ssaInfo, ins)
		_, argT := ts.callInputScope(rc)
		mc, isMC := ins.Call.Value.(*ssa.MakeClosure)
		_, capT := false, false
		if isMC {
			_, capT = vetssa.CombinedScope(ts.tainted, mc.Bindings...)
		}
		if argT || capT {
			ts.report(ins, "secrettaint: 禁止将明文机密传入并发 goroutine")
		}
	case ssa.CallInstruction:
		ts.checkCallInst(ins)
	}
}

func (ts *taintScope) checkReturn(ins *ssa.Return) {
	if ts.depth != 0 {
		return
	}
	if ts.kiFn == ts.fn && vetssa.IsDialKIAnswersReturn(ts.eng.pkgInfo, ts.fn, ins) {
		if _, errT := ts.tainted[ins.Results[1]]; errT {
			ts.report(ins, "secrettaint: 禁止通过 return 返回明文机密")
		}
		return
	}
	if _, ok := vetssa.CombinedScope(ts.tainted, ins.Results...); ok {
		ts.report(ins, "secrettaint: 禁止通过 return 返回明文机密")
	}
}

func (ts *taintScope) checkStore(ins *ssa.Store) {
	sc, ok := ts.tainted[ins.Val]
	if !ok || vetssa.IsVarargsSliceStore(ins.Addr) {
		return
	}
	if fa, isField := ins.Addr.(*ssa.FieldAddr); isField {
		if !ts.isAllowedVaultNarrowFieldStore(ins, fa) || !vetssa.AllRootsOwnedInScope(fa, sc, ts.callerParams) {
			ts.report(ins, "secrettaint: 禁止将明文机密存入结构体或非字节切片容器字面量")
		}
		return
	}
	if ts.checkDialKIAnswersStore(ins) {
		return
	}
	if isNonByteContainerStore(ins.Addr) {
		ts.report(ins, "secrettaint: 禁止将明文机密存入结构体或非字节切片容器字面量")
	} else if !vetssa.AllRootsOwnedInScope(ins.Addr, sc, ts.callerParams) {
		ts.report(ins, "secrettaint: 禁止将明文机密逃逸至外层变量、字段或非本作用域存储")
	}
}

func (ts *taintScope) checkMakeClosure(mc *ssa.MakeClosure) {
	target, ok := mc.Fn.(*ssa.Function)
	if !ok || target == nil {
		return
	}
	captured := vetssa.CollectCaptured(mc, target, ts.tainted)
	if vetssa.IsYieldFunc(target) {
		ts.checkYieldClosure(mc, target, captured)
		return
	}
	if len(captured) == 0 {
		return
	}
	if ts.allClosureReferrersMatch(mc, ts.isSyncClosureCallSite) {
		if !ts.allClosureReferrersMatch(mc, ts.isSecretUseCallSite) {
			if retMask := ts.eng.auditFunc(target, nil, captured, ts.ownScope, ts.depth+1, ts.tainted, mc, ts.kiFn); retMask != 0 {
				ts.report(mc, "secrettaint: 禁止在同步闭包回调中通过 return 返回明文机密")
				ts.propagateDirectIIFEReturns(mc, retMask)
			}
		}
		return
	}
	ts.report(mc, "secrettaint: 禁止在内层闭包中捕获明文机密变量")
}

// propagateDirectIIFEReturns 将捕获明文后通过 return 返回值的本地立即执行闭包（IIFE）结果按槽位回染，
// 配合 checkMakeClosure 的 Fail-Closed 报错构成双重纵深拦截。
func (ts *taintScope) propagateDirectIIFEReturns(mc *ssa.MakeClosure, retMask uint64) {
	if mc.Referrers() == nil || retMask == 0 {
		return
	}
	capSc, ok := vetssa.CombinedScope(ts.tainted, mc.Bindings...)
	if !ok {
		return
	}
	for _, ref := range *mc.Referrers() {
		callInst, isCall := ref.(ssa.CallInstruction)
		if !isCall {
			continue
		}
		if rc := vetssa.ResolveCall(ts.eng.ssaInfo, callInst); rc.Common != nil && rc.Common.Value == mc {
			ts.markCallReturns(callInst, retMask, capSc)
		}
	}
}

func (ts *taintScope) checkYieldClosure(mc *ssa.MakeClosure, target *ssa.Function, captured map[ssa.Value]vetssa.ScopeRange) {
	callInst, seeds, yScope, isStd := vetssa.CheckStdlibYieldClosure(ts.eng.ssaInfo, ts.fn, target, ts.ownScope, ts.tainted)
	if !isStd {
		iterT := callInst != nil && callInst.Common() != nil && ts.isTainted(callInst.Common().Value)
		if len(captured) > 0 || iterT {
			rep := ssa.Instruction(mc)
			if callInst != nil {
				rep = callInst
			}
			ts.report(rep, "secrettaint: 禁止在非标准库自定义迭代器中捕获明文机密变量")
		}
		return
	}
	if len(seeds) > 0 || len(captured) > 0 {
		if retMask := ts.eng.auditFunc(target, seeds, captured, yScope, ts.depth+1, ts.tainted, callInst, ts.kiFn); retMask != 0 {
			ts.report(mc, "secrettaint: 禁止在同步闭包回调中通过 return 返回明文机密")
		}
	}
}

func (ts *taintScope) allClosureReferrersMatch(mc *ssa.MakeClosure, pred func(ssa.CallInstruction, *ssa.MakeClosure) bool) bool {
	if mc.Referrers() == nil || len(*mc.Referrers()) == 0 {
		return false
	}
	for _, ref := range *mc.Referrers() {
		if callInst, isCall := ref.(ssa.CallInstruction); !isCall || !pred(callInst, mc) {
			return false
		}
	}
	return true
}

// isSyncClosureCallSite 判定闭包引用点是否为受控同步执行站点：
// 对已登记公共汇点（SinkError/SinkLog/SinkSerialize/SinkEventAudit）恒返 false 实现纵深互斥，
// 并对 //xops:secretuse 具名回调参数按精确槽位匹配，杜绝非机密回调槽位借道逃逸。
func (ts *taintScope) isSyncClosureCallSite(callInst ssa.CallInstruction, mc *ssa.MakeClosure) bool {
	if _, isGo := callInst.(*ssa.Go); isGo {
		return false
	}
	rc := vetssa.ResolveCall(ts.eng.ssaInfo, callInst)
	if rc.Common != nil && rc.Common.Value == mc {
		return true
	}
	if rc.FuncObj == nil || secretfact.ClassifyCommonSink(rc.FuncObj) != secretfact.SinkNone {
		return false
	}
	if vetssa.IsRuntimeSecretDo(rc.FuncObj) {
		return true
	}
	return ts.eng.facts != nil && (ts.eng.facts.IsSyncClosureObject(rc.FuncObj) || ts.isSecretUseCallSite(callInst, mc))
}

func (ts *taintScope) isSecretUseCallSite(callInst ssa.CallInstruction, mc *ssa.MakeClosure) bool {
	rc := vetssa.ResolveCall(ts.eng.ssaInfo, callInst)
	if rc.FuncObj == nil || ts.eng.facts == nil {
		return false
	}
	sig, _ := rc.FuncObj.Type().Underlying().(*types.Signature)
	for i, arg := range rc.UserArgs {
		if arg == mc {
			if _, ok := secretCallbackSlot(ts.eng.facts, rc.FuncObj, sig, i, arg.Type()); ok {
				return true
			}
		}
	}
	return false
}

func (ts *taintScope) checkCallInst(callInst ssa.CallInstruction) {
	rc := vetssa.ResolveCall(ts.eng.ssaInfo, callInst)
	if rc.Kind == vetssa.CallBuiltin && rc.Builtin != nil {
		ts.checkBuiltinCall(callInst, rc)
		return
	}
	if sc, ok := ts.writeToDstCallTaint(rc); ok {
		ts.checkWriteToDstCall(callInst, rc, sc)
		return
	}
	if isIOCopyFunc(rc.FuncObj) {
		if isIOCopyBufferFunc(rc.FuncObj) && len(rc.UserArgs) >= 3 {
			if bufSc, ok := ts.tainted[rc.UserArgs[2]]; ok && !ts.isOwnedLocalBufferWriter(rc.UserArgs[0], bufSc) {
				ts.report(callInst, "secrettaint: 禁止通过 io.CopyBuffer 将明文机密写入外层缓冲或写入器")
			}
		}
		return
	}
	if inSc, ok := ts.callInputScope(rc); ok {
		if ts.allTaintedArgsCoveredBySecretUse(rc) {
			return
		}
		ts.checkTaintedNonWriteCall(callInst, rc, inSc)
	}
}

func (ts *taintScope) checkBuiltinCall(callInst ssa.CallInstruction, rc vetssa.ResolvedCall) {
	switch rc.Builtin.Name() {
	case "copy":
		if len(rc.UserArgs) >= 2 {
			if sc, ok := ts.tainted[rc.UserArgs[1]]; ok && !vetssa.IsAllowedSliceWriteDst(rc.UserArgs[0], sc, ts.callerParams) {
				ts.report(callInst, "secrettaint: 禁止通过 copy 将明文机密写入外层变量或字段")
			}
		}
	case "append":
		if sc, ok := vetssa.CombinedScope(ts.tainted, rc.UserArgs...); ok && len(rc.UserArgs) > 0 &&
			!vetssa.IsAllowedSliceWriteDst(rc.UserArgs[0], sc, ts.callerParams) && !vetssa.IsNilConst(rc.UserArgs[0]) {
			ts.report(callInst, "secrettaint: 禁止通过 append 将明文机密写入外层变量或字段")
		}
	}
}

func (ts *taintScope) checkWriteToDstCall(callInst ssa.CallInstruction, rc vetssa.ResolvedCall, sc vetssa.ScopeRange) {
	if isIOCopyFunc(rc.FuncObj) {
		if len(rc.UserArgs) >= 1 && !ts.isOwnedLocalBufferWriter(rc.UserArgs[0], sc) {
			ts.report(callInst, "secrettaint: 禁止通过 io.Copy 将明文机密写入外层缓冲或写入器")
		} else if isIOCopyBufferFunc(rc.FuncObj) && len(rc.UserArgs) >= 3 && !vetssa.IsNilConst(rc.UserArgs[2]) &&
			!vetssa.IsAllowedSliceWriteDst(rc.UserArgs[2], sc, ts.callerParams) {
			ts.report(callInst, "secrettaint: 禁止通过 io.CopyBuffer 将明文机密写入外层缓冲或切片")
		}
		return
	}
	for _, dst := range writeToDstTargets(rc) {
		if !vetssa.AllRootsOwnedInScope(dst, sc, ts.callerParams) {
			ts.report(callInst, writeToDstErrorMsg(rc.FuncObj))
			return
		}
	}
}

func (ts *taintScope) checkTaintedNonWriteCall(callInst ssa.CallInstruction, rc vetssa.ResolvedCall, inSc vetssa.ScopeRange) {
	if ts.auditedCalls[callInst] {
		return
	}
	if isAppendToDstFunc(rc.FuncObj) {
		ts.checkAppendToDstCall(callInst, rc, inSc)
		return
	}
	if isFmtSprintFunc(rc.FuncObj) {
		if !ts.allFmtArgsSafe(rc.UserArgs) {
			ts.report(callInst, "secrettaint: 禁止将自定义 Stringer/GoStringer 明文值传入 fmt 格式化函数")
		}
		return
	}
	if isSafePredicate(rc.FuncObj) || isTaintPreservingTransform(rc.FuncObj) || vetssa.IsStdlibSyncIter(rc.FuncObj) ||
		ts.isExactCryptoSanitizer(rc, inSc) || ts.isAllowedNarrowConsumerCall(callInst, rc, inSc) {
		return
	}
	if isBufferOrReaderWriteToFunc(rc.FuncObj) {
		ts.report(callInst, "secrettaint: 禁止通过 WriteTo 导出明文缓冲或读取器内容")
	} else if kind := secretfact.ClassifyCommonSink(rc.FuncObj); kind != secretfact.SinkNone {
		ts.report(callInst, "secrettaint: 禁止将明文机密及其衍生值传入"+kind.Label()+"汇点")
	} else {
		ts.report(callInst, "secrettaint: 禁止将明文机密传入未经授权的外部调用或未知汇点")
	}
}

func (ts *taintScope) checkAppendToDstCall(callInst ssa.CallInstruction, rc vetssa.ResolvedCall, inSc vetssa.ScopeRange) {
	if isFmtAppendFunc(rc.FuncObj) && len(rc.UserArgs) > 1 && !ts.allFmtArgsSafe(rc.UserArgs[1:]) {
		ts.report(callInst, "secrettaint: 禁止将自定义 Stringer/GoStringer 明文值传入 fmt 格式化函数")
		return
	}
	if len(rc.UserArgs) > 0 && !vetssa.IsAllowedSliceWriteDst(rc.UserArgs[0], inSc, ts.callerParams) && !vetssa.IsNilConst(rc.UserArgs[0]) {
		fnLabel := rc.FuncObj.Name()
		if rc.FuncObj.Pkg() != nil {
			fnLabel = rc.FuncObj.Pkg().Name() + "." + fnLabel
		}
		ts.report(callInst, "secrettaint: 禁止通过 "+fnLabel+" 将明文机密写入外层变量或字段")
	}
}

func (ts *taintScope) auditSamePackageCallee(callInst ssa.CallInstruction, rc vetssa.ResolvedCall) (uint64, bool) {
	if rc.TargetFn != nil && len(rc.TargetFn.Blocks) > 0 {
		return ts.eng.auditFunc(rc.TargetFn, vetssa.CollectCallSeeds(rc, ts.tainted, 0, nil), nil, vetssa.ScopeRangeOfFunc(rc.TargetFn), ts.depth+1, nil, callInst, ts.kiFn), true
	}
	if rc.Kind != vetssa.CallDynamic || rc.Common == nil {
		return 0, false
	}
	targets, allKnown := vetssa.ResolveFuncValues(rc.Common.Value)
	if !allKnown || len(targets) == 0 {
		return 0, false
	}
	var merged uint64
	seeds := vetssa.CollectCallSeeds(rc, ts.tainted, 0, nil)
	for _, tgt := range targets {
		mask, ok := ts.auditDynamicTarget(callInst, tgt, seeds)
		if !ok {
			return 0, false
		}
		merged |= mask
	}
	return merged, true
}

func (ts *taintScope) auditDynamicTarget(callInst ssa.CallInstruction, tgt ssa.Value, seeds map[int]bool) (uint64, bool) {
	switch t := tgt.(type) {
	case *ssa.MakeClosure:
		if fn, ok := t.Fn.(*ssa.Function); ok && fn != nil && len(fn.Blocks) > 0 {
			return ts.eng.auditFunc(fn, seeds, vetssa.CollectCaptured(t, fn, ts.tainted), ts.ownScope, ts.depth+1, ts.tainted, callInst, ts.kiFn), true
		}
	case *ssa.Function:
		if origFn := vetssa.UnwrapOriginFunc(t); vetssa.IsSamePackageFunc(ts.eng.ssaInfo, origFn) && len(origFn.Blocks) > 0 {
			return ts.eng.auditFunc(origFn, seeds, nil, vetssa.ScopeRangeOfFunc(origFn), ts.depth+1, nil, callInst, ts.kiFn), true
		}
	}
	return 0, false
}

func (ts *taintScope) isOwnedLocalBufferWriter(dst ssa.Value, sc vetssa.ScopeRange) bool {
	u := vetssa.UnwrapInterface(dst)
	named, ok := vetutil.UnwrapNamedType(u.Type())
	return ok && (vetutil.IsPkgSymbol(named.Obj(), "bytes", "Buffer") || vetutil.IsPkgSymbol(named.Obj(), "strings", "Builder")) &&
		vetssa.AllRootsOwnedInScope(u, sc, ts.callerParams)
}

func isNonByteContainerStore(addr ssa.Value) bool {
	ia, ok := addr.(*ssa.IndexAddr)
	if !ok {
		return false
	}
	ptr, ok := types.Unalias(ia.Type()).(*types.Pointer)
	if !ok {
		return false
	}
	b, ok := types.Unalias(ptr.Elem()).Underlying().(*types.Basic)
	return !ok || (b.Kind() != types.Byte && b.Kind() != types.Uint8 && b.Kind() != types.Rune)
}

func writeToDstErrorMsg(obj *types.Func) string {
	if obj == nil {
		return "secrettaint: 禁止将明文机密写入外层变量或字段"
	}
	switch obj.Name() {
	case "ReadFrom":
		return "secrettaint: 禁止通过 ReadFrom 将明文机密写入外层缓冲"
	case "Read", "ReadAt":
		return "secrettaint: 禁止通过 Read 将明文机密写入外层变量或字段"
	default:
		return "secrettaint: 禁止通过 " + obj.Name() + " 将明文机密写入外层变量或字段"
	}
}
