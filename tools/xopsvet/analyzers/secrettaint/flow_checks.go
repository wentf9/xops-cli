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
	case *ssa.Return:
		if _, ok := vetssa.CombinedScope(ts.tainted, ins.Results...); ok && ts.depth == 0 && !isDialKeyboardInteractiveAnswersReturn(ts.eng.pkgInfo, ts.fn, ins) {
			ts.report(ins, "secrettaint: 禁止通过 return 返回明文机密")
		}
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

func (ts *taintScope) checkStore(ins *ssa.Store) {
	sc, ok := ts.tainted[ins.Val]
	if !ok || vetssa.IsVarargsSliceStore(ins.Addr) {
		return
	}
	if fa, isField := ins.Addr.(*ssa.FieldAddr); isField {
		if !isVaultNarrowCredentialFieldStore(ts.eng.pkgInfo, fa) {
			ts.report(ins, "secrettaint: 禁止将明文机密存入结构体或非字节切片容器字面量")
		}
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
		callInst, seeds, yScope, isStd := vetssa.CheckStdlibYieldClosure(ts.eng.ssaInfo, ts.fn, target, ts.ownScope, ts.tainted)
		if !isStd {
			if len(captured) > 0 {
				ts.report(callInst, "secrettaint: 禁止在非标准库自定义迭代器中捕获明文机密变量")
			}
		} else if len(seeds) > 0 || len(captured) > 0 {
			ts.eng.auditFunc(target, seeds, captured, yScope, ts.depth+1, ts.tainted)
		}
		return
	}
	if len(captured) == 0 {
		return
	}
	if ts.allClosureReferrersMatch(mc, ts.isSyncClosureCallSite) {
		if !ts.allClosureReferrersMatch(mc, ts.isSecretUseCallSite) {
			ts.eng.auditFunc(target, nil, captured, ts.ownScope, ts.depth+1, ts.tainted)
		}
		return
	}
	ts.report(mc, "secrettaint: 禁止在内层闭包中捕获明文机密变量")
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

func (ts *taintScope) isSyncClosureCallSite(callInst ssa.CallInstruction, mc *ssa.MakeClosure) bool {
	if _, isGo := callInst.(*ssa.Go); isGo {
		return false
	}
	rc := vetssa.ResolveCall(ts.eng.ssaInfo, callInst)
	return (rc.Common != nil && rc.Common.Value == mc) ||
		(rc.FuncObj != nil && (vetssa.IsRuntimeSecretDo(rc.FuncObj) || ts.eng.syncFuncs[rc.FuncObj] ||
			(ts.eng.facts != nil && (ts.eng.facts.IsSecretUseObject(rc.FuncObj) || ts.eng.facts.HasSecretUseCallbackParam(rc.FuncObj)))))
}

func (ts *taintScope) isSecretUseCallSite(callInst ssa.CallInstruction, _ *ssa.MakeClosure) bool {
	rc := vetssa.ResolveCall(ts.eng.ssaInfo, callInst)
	return rc.FuncObj != nil && ts.eng.facts != nil && ts.eng.facts.IsSecretUseObject(rc.FuncObj)
}

func (ts *taintScope) checkCallInst(callInst ssa.CallInstruction) {
	rc := vetssa.ResolveCall(ts.eng.ssaInfo, callInst)
	if ts.eng.facts != nil && rc.FuncObj != nil && ts.eng.facts.IsSecretUseObject(rc.FuncObj) {
		return
	}
	if rc.Kind == vetssa.CallBuiltin && rc.Builtin != nil {
		ts.checkBuiltinCall(callInst, rc)
		return
	}
	if sc, ok := ts.writeToDstCallTaint(rc); ok {
		ts.checkWriteToDstCall(callInst, rc, sc)
		return
	}
	if isIOCopyFunc(rc.FuncObj) {
		return
	}
	if inSc, ok := ts.callInputScope(rc); ok {
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
	if isFmtAppendFunc(rc.FuncObj) {
		if len(rc.UserArgs) > 0 && !vetssa.IsAllowedSliceWriteDst(rc.UserArgs[0], inSc, ts.callerParams) && !vetssa.IsNilConst(rc.UserArgs[0]) {
			ts.report(callInst, "secrettaint: 禁止通过 fmt.Append 将明文机密写入外层变量或字段")
		}
		return
	}
	if isSafePredicate(rc.FuncObj) || isTaintPreservingTransform(rc.FuncObj) || isExactCryptoSanitizer(rc) ||
		isAllowedNarrowConsumerCall(ts.eng.pkgInfo, rc) || ts.auditSamePackageCallee(rc) {
		return
	}
	if isBufferOrReaderWriteToFunc(rc.FuncObj) {
		ts.report(callInst, "secrettaint: 禁止通过 WriteTo 导出明文缓冲或读取器内容")
	} else if kind := secretfact.ClassifyCommonSink(rc.FuncObj); kind != secretfact.SinkNone {
		ts.report(callInst, "secrettaint: 禁止将明文机密及其衍生值传入"+kind.Label()+"汇点")
	} else {
		// CRIT-4A 核心防线：默认 Fail-Closed 拦截一切未知外部调用、任意 io.Writer/接口方法与动态函数字段。
		ts.report(callInst, "secrettaint: 禁止将明文机密传入未经授权的外部调用或未知汇点")
	}
}

func (ts *taintScope) auditSamePackageCallee(rc vetssa.ResolvedCall) bool {
	if rc.TargetFn != nil && len(rc.TargetFn.Blocks) > 0 {
		ts.eng.auditFunc(rc.TargetFn, vetssa.CollectCallSeeds(rc, ts.tainted, 0, nil), nil, vetssa.ScopeRangeOfFunc(rc.TargetFn), ts.depth+1, nil)
		return true
	}
	if rc.Kind != vetssa.CallDynamic || rc.Common == nil {
		return false
	}
	targets, allKnown := vetssa.ResolveFuncValues(rc.Common.Value)
	if !allKnown || len(targets) == 0 {
		return false
	}
	for _, tgt := range targets {
		if !ts.auditResolvedDynamicCallee(tgt, rc) {
			return false
		}
	}
	return true
}

func (ts *taintScope) auditResolvedDynamicCallee(tgt ssa.Value, rc vetssa.ResolvedCall) bool {
	seeds := vetssa.CollectCallSeeds(rc, ts.tainted, 0, nil)
	switch t := tgt.(type) {
	case *ssa.MakeClosure:
		fn, ok := t.Fn.(*ssa.Function)
		if !ok || fn == nil || len(fn.Blocks) == 0 {
			return false
		}
		ts.eng.auditFunc(fn, seeds, vetssa.CollectCaptured(t, fn, ts.tainted), ts.ownScope, ts.depth+1, ts.tainted)
		return true
	case *ssa.Function:
		origFn := vetssa.UnwrapOriginFunc(t)
		if !vetssa.IsSamePackageFunc(ts.eng.ssaInfo, origFn) || len(origFn.Blocks) == 0 {
			return false
		}
		ts.eng.auditFunc(origFn, seeds, nil, vetssa.ScopeRangeOfFunc(origFn), ts.depth+1, nil)
		return true
	default:
		return false
	}
}

func (ts *taintScope) isOwnedLocalBufferWriter(dst ssa.Value, sc vetssa.ScopeRange) bool {
	unwrapped := vetssa.UnwrapInterface(dst)
	named, ok := vetutil.UnwrapNamedType(unwrapped.Type())
	return ok && named != nil &&
		(vetutil.IsPkgSymbol(named.Obj(), "bytes", "Buffer") || vetutil.IsPkgSymbol(named.Obj(), "strings", "Builder")) &&
		vetssa.AllRootsOwnedInScope(unwrapped, sc, ts.callerParams)
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
