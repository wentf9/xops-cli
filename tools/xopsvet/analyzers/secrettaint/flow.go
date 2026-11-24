package secrettaint

import (
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

const maxAuditDepth = 8

type taintEngine struct {
	pass           *analysis.Pass
	ssaInfo        *buildssa.SSA
	pkgInfo        vetutil.PkgInfo
	facts          *secretfact.Result
	tracker        *vetssa.AuditTracker
	kiClosures     map[*ssa.Function]bool
	kiTaintedRoots map[*ssa.Function][]ssa.Value
	diags          []vetutil.Diag
}

type taintScope struct {
	eng          *taintEngine
	fn           *ssa.Function
	depth        int
	ownScope     vetssa.ScopeRange
	tainted      map[ssa.Value]vetssa.ScopeRange
	callerParams map[ssa.Value]bool
	outerShared  map[ssa.Value]vetssa.ScopeRange
	kiFn         *ssa.Function
	auditedCalls map[ssa.CallInstruction]bool
}

// auditFunc 在单个 SSA 函数或闭包体上执行 Rule 2 明文污点迭代收敛传播、多级回写与全量 Fail-Closed 检查，
// 并返回染毒返回值槽位掩码（ST-2），供调用方按槽位精确回染而不误伤 error 槽位。
func (e *taintEngine) auditFunc(fn *ssa.Function, seedParams map[int]bool, captured map[ssa.Value]vetssa.ScopeRange, ownScope vetssa.ScopeRange, depth int, outerShared map[ssa.Value]vetssa.ScopeRange, siteInst ssa.Instruction, kiFn *ssa.Function) uint64 {
	key, leave, status := e.tracker.Enter(fn, seedParams, captured, depth, maxAuditDepth)
	switch status {
	case vetssa.EnterSkip:
		return e.tracker.ReturnMask(key)
	case vetssa.EnterDepthExceeded:
		vetssa.ReportDepthExceeded(e.pass, &e.diags, fn, siteInst, "secrettaint: 嵌套审计深度超过上限，按 Fail-Closed 拦截潜在明文逃逸")
		return ^uint64(0)
	}
	defer leave()
	tainted, callerParams := vetssa.SeedScopeParams(fn, seedParams, captured, ownScope)
	return e.runScopeAudit(key, fn, tainted, callerParams, ownScope, depth, outerShared, kiFn)
}

func (e *taintEngine) runScopeAudit(key vetssa.AuditKey, fn *ssa.Function, tainted map[ssa.Value]vetssa.ScopeRange, callerParams map[ssa.Value]bool, ownScope vetssa.ScopeRange, depth int, outerShared map[ssa.Value]vetssa.ScopeRange, kiFn *ssa.Function) uint64 {
	ts := &taintScope{
		eng: e, fn: fn, depth: depth, ownScope: ownScope,
		tainted: tainted, callerParams: callerParams, outerShared: outerShared,
		kiFn: kiFn, auditedCalls: map[ssa.CallInstruction]bool{},
	}
	vetssa.RunScopedFixpoint(fn, ts.tainted, outerShared, ts.propagateInst, ts.auditNestedInst)
	retMask := ts.computeReturnMask()
	if key.Fn != nil {
		e.tracker.RecordReturnMask(key, retMask)
	}
	vetssa.ForEachInst(fn, ts.checkInst)
	return retMask
}

func (ts *taintScope) computeReturnMask() uint64 {
	var mask uint64
	vetssa.ForEachInst(ts.fn, func(inst ssa.Instruction) {
		if ret, ok := inst.(*ssa.Return); ok {
			for i, r := range ret.Results {
				if i < 64 && ts.tainted[r].Valid() {
					mask |= 1 << uint(i)
				}
			}
		}
	})
	return mask
}

func (ts *taintScope) propagateInst(inst ssa.Instruction) bool {
	if op, ok := vetssa.UnaryFlowOperand(inst, false); ok {
		sc, tainted := ts.tainted[op]
		val, isVal := inst.(ssa.Value)
		return tainted && isVal && vetssa.MarkValueScope(ts.tainted, val, sc)
	}
	switch ins := inst.(type) {
	case *ssa.BinOp:
		sc, ok := vetssa.CombinedScope(ts.tainted, ins.X, ins.Y)
		return isTaintPropagatingBinOp(ins.Op) && ok && vetssa.MarkValueScope(ts.tainted, ins, sc)
	case *ssa.Phi:
		sc, ok := vetssa.CombinedScope(ts.tainted, ins.Edges...)
		return ok && vetssa.MarkValueScope(ts.tainted, ins, sc)
	case *ssa.Store:
		sc, ok := ts.tainted[ins.Val]
		return ok && vetssa.MarkRootsBackward(ins.Addr, sc, ts.tainted, ts.outerShared)
	case *ssa.MapUpdate:
		sc, ok := vetssa.CombinedScope(ts.tainted, ins.Key, ins.Value)
		return ok && vetssa.MarkRootsBackward(ins.Map, sc, ts.tainted, ts.outerShared)
	case *ssa.Call:
		return ts.propagateCall(ins)
	default:
		return false
	}
}

func isTaintPropagatingBinOp(op token.Token) bool {
	return op != token.EQL && op != token.NEQ && op != token.LSS && op != token.LEQ && op != token.GTR && op != token.GEQ
}

func (ts *taintScope) propagateCall(call *ssa.Call) bool {
	rc := vetssa.ResolveCall(ts.eng.ssaInfo, call)
	if rc.Kind == vetssa.CallBuiltin && rc.Builtin != nil {
		return vetssa.PropagateBuiltinCopyAppend(call, rc, ts.tainted, ts.outerShared)
	}
	if sc, ok := ts.writeToDstCallTaint(rc); ok {
		return ts.propagateWriteToDst(rc, sc)
	}
	inSc, hasTaint := ts.callInputScope(rc)
	if !hasTaint {
		return false
	}
	if isAppendToDstFunc(rc.FuncObj) {
		changed := vetssa.MarkValueScope(ts.tainted, call, inSc)
		if len(rc.UserArgs) > 0 && !vetssa.IsNilConst(rc.UserArgs[0]) {
			changed = vetssa.MarkRootsBackward(rc.UserArgs[0], inSc, ts.tainted, ts.outerShared) || changed
		}
		return changed
	}
	if isTaintPreservingTransform(rc.FuncObj) || isFmtSprintFunc(rc.FuncObj) || vetssa.IsStdlibSyncIter(rc.FuncObj) {
		return vetssa.MarkValueScope(ts.tainted, call, inSc)
	}
	return false
}

func (ts *taintScope) propagateWriteToDst(rc vetssa.ResolvedCall, sc vetssa.ScopeRange) bool {
	changed := false
	for _, dst := range writeToDstTargets(rc) {
		changed = vetssa.MarkRootsBackward(dst, sc, ts.tainted, ts.outerShared) || changed
	}
	if isIOCopyBufferFunc(rc.FuncObj) && len(rc.UserArgs) >= 3 && !vetssa.IsNilConst(rc.UserArgs[2]) {
		changed = vetssa.MarkRootsBackward(rc.UserArgs[2], sc, ts.tainted, ts.outerShared) || changed
	}
	return changed
}

func (ts *taintScope) callInputScope(rc vetssa.ResolvedCall) (vetssa.ScopeRange, bool) {
	vals := rc.UserArgs
	if rc.Recv != nil {
		vals = append(append([]ssa.Value(nil), vals...), rc.Recv)
	}
	if rc.Common != nil && !rc.Common.IsInvoke() && rc.Common.Value != nil {
		vals = append(append([]ssa.Value(nil), vals...), rc.Common.Value)
	}
	return vetssa.CombinedScope(ts.tainted, vals...)
}

func (ts *taintScope) auditNestedInst(inst ssa.Instruction) {
	switch ins := inst.(type) {
	case *ssa.MakeClosure:
		ts.checkMakeClosure(ins)
	case ssa.CallInstruction:
		if _, isGo := ins.(*ssa.Go); !isGo {
			ts.auditNestedCall(ins)
		}
	}
}

func (ts *taintScope) auditNestedCall(ins ssa.CallInstruction) {
	rc := vetssa.ResolveCall(ts.eng.ssaInfo, ins)
	if ts.auditNestedSecretEntry(ins, rc) || isHandledNonHelperCall(rc) {
		return
	}
	if _, isWrite := ts.writeToDstCallTaint(rc); isWrite {
		return
	}
	inSc, ok := ts.callInputScope(rc)
	if !ok {
		return
	}
	if targets, iterSc, ok := vetssa.ResolveDirectStdlibIterCallback(ts.eng.ssaInfo, rc, ts.tainted); ok {
		for _, tgt := range targets {
			ts.eng.auditFunc(tgt.Fn, vetssa.SeedAllParamIndices(tgt.Fn), vetssa.CollectCaptured(tgt.MC, tgt.Fn, ts.tainted), iterSc, ts.depth+1, ts.tainted, ins, ts.kiFn)
		}
		ts.auditedCalls[ins] = true
		return
	}
	if retMask, audited := ts.auditSamePackageCallee(ins, rc); audited {
		ts.auditedCalls[ins] = true
		ts.markCallReturns(ins, retMask, inSc)
	}
}

func (ts *taintScope) auditNestedSecretEntry(ins ssa.CallInstruction, rc vetssa.ResolvedCall) bool {
	if ts.eng.facts == nil || rc.FuncObj == nil {
		return false
	}
	isSecretObj := ts.eng.facts.IsSecretUseObject(rc.FuncObj)
	if !isSecretObj && !ts.eng.facts.HasSecretUseCallbackParam(rc.FuncObj) {
		return false
	}
	sig, _ := rc.FuncObj.Type().Underlying().(*types.Signature)
	for i, arg := range rc.UserArgs {
		if isSecretCallbackArgSlot(ts.eng.facts, sig, isSecretObj, i, arg.Type()) {
			ts.eng.auditCallbackArg(ts.fn, ins, arg, ts.tainted, ts.tainted, ts.kiFn)
		}
	}
	return true
}

func isHandledNonHelperCall(rc vetssa.ResolvedCall) bool {
	return rc.Kind == vetssa.CallBuiltin || isAppendToDstFunc(rc.FuncObj) || isFmtSprintFunc(rc.FuncObj) ||
		isSafePredicate(rc.FuncObj) || isTaintPreservingTransform(rc.FuncObj) || isIOCopyFunc(rc.FuncObj)
}

func (ts *taintScope) markCallReturns(callInst ssa.CallInstruction, retMask uint64, sc vetssa.ScopeRange) {
	call, ok := callInst.(*ssa.Call)
	if retMask == 0 || !ok {
		return
	}
	if tup, isTuple := call.Type().(*types.Tuple); isTuple && tup.Len() > 1 {
		if call.Referrers() != nil {
			for _, ref := range *call.Referrers() {
				if ext, isExt := ref.(*ssa.Extract); isExt && ext.Index < 64 && (retMask&(1<<uint(ext.Index))) != 0 {
					vetssa.MarkValueScope(ts.tainted, ext, sc)
				}
			}
		}
		return
	}
	if retMask&1 != 0 {
		vetssa.MarkValueScope(ts.tainted, call, sc)
	}
}
