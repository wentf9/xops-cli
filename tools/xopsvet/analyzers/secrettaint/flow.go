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
	safeVaultAEAD  map[structFieldKey]bool
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
	key, leave, status := e.tracker.Enter(fn, seedParams, nil, captured, depth, maxAuditDepth)
	switch status {
	case vetssa.EnterSkip:
		return e.tracker.ReturnMask(key)
	case vetssa.EnterDepthExceeded:
		vetssa.ReportDepthExceeded(e.pass, &e.diags, fn, siteInst, "secrettaint: 嵌套审计深度超过上限，按 Fail-Closed 拦截潜在明文逃逸")
		return ^uint64(0)
	}
	defer leave()
	tainted, callerParams := vetssa.SeedScopeParams(fn, seedParams, nil, captured, ownScope)
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

func (ts *taintScope) isTainted(v ssa.Value) bool {
	_, ok := ts.tainted[v]
	return ok
}

func (ts *taintScope) computeReturnMask() uint64 {
	var mask uint64
	vetssa.ForEachInst(ts.fn, func(inst ssa.Instruction) {
		if ret, ok := inst.(*ssa.Return); ok {
			for i, r := range ret.Results {
				if i < 64 && ts.isTainted(r) {
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
		if !ok {
			return false
		}
		// P4-T1 挑战闭包内合法写入局部 answers[i] = string(plain) 时，将反向标记作用域提升为 kiScope
		// （而非内层 box.Use 子区间），避免双分支 WithSecret/PromptSecret 交叉回冲将 answers 收紧为空区间。
		if _, kiScope, allowed := vetssa.IsDialKIAnswersStore(ts.eng.pkgInfo, ts.kiFn, ins); allowed {
			return vetssa.MarkRootsBackward(ins.Addr, kiScope, ts.tainted, ts.outerShared)
		}
		return vetssa.MarkRootsBackward(ins.Addr, sc, ts.tainted, ts.outerShared)
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
		changed := ts.markTransformReturn(call, rc.FuncObj, inSc)
		if len(rc.UserArgs) > 0 && !vetssa.IsNilConst(rc.UserArgs[0]) {
			changed = vetssa.MarkRootsBackward(rc.UserArgs[0], inSc, ts.tainted, ts.outerShared) || changed
		}
		return changed
	}
	if isTaintPreservingTransform(rc.FuncObj) || isFmtSprintFunc(rc.FuncObj) || vetssa.IsStdlibSyncIter(rc.FuncObj) {
		return ts.markTransformReturn(call, rc.FuncObj, inSc)
	}
	return false
}

func (ts *taintScope) markTransformReturn(call *ssa.Call, fn *types.Func, sc vetssa.ScopeRange) bool {
	if taintsOnlyFirstResult(fn) {
		return ts.markCallReturns(call, 1, sc)
	}
	return vetssa.MarkValueScope(ts.tainted, call, sc)
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
	ts.auditNestedSecretEntry(ins, rc)
	if isHandledNonHelperCall(rc) {
		return
	}
	if _, isWrite := ts.writeToDstCallTaint(rc); isWrite {
		return
	}
	inSc, ok := ts.callInputScope(rc)
	if !ok || ts.allTaintedArgsCoveredBySecretUse(rc) {
		return
	}
	if targets, iterSc, ok := vetssa.ResolveDirectStdlibIterCallback(ts.eng.ssaInfo, rc, ts.tainted); ok {
		for _, tgt := range targets {
			if retMask := ts.eng.auditFunc(tgt.Fn, vetssa.SeedAllParamIndices(tgt.Fn), vetssa.CollectCaptured(tgt.MC, tgt.Fn, ts.tainted), iterSc, ts.depth+1, ts.tainted, ins, ts.kiFn); retMask != 0 {
				ts.report(ins, "secrettaint: 禁止在同步闭包回调中通过 return 返回明文机密")
			}
		}
		ts.auditedCalls[ins] = true
		return
	}
	if retMask, audited := ts.auditSamePackageCallee(ins, rc); audited {
		ts.auditedCalls[ins] = true
		ts.markCallReturns(ins, retMask, inSc)
	}
}

func (ts *taintScope) auditNestedSecretEntry(ins ssa.CallInstruction, rc vetssa.ResolvedCall) {
	if ts.eng.facts == nil || rc.FuncObj == nil {
		return
	}
	if !ts.eng.facts.IsSecretUseObject(rc.FuncObj) && !ts.eng.facts.HasSecretUseCallbackParam(rc.FuncObj) {
		return
	}
	sig, _ := rc.FuncObj.Type().Underlying().(*types.Signature)
	for i, arg := range rc.UserArgs {
		if explicit, ok := secretCallbackSlot(ts.eng.facts, rc.FuncObj, sig, i, arg.Type()); ok {
			ts.eng.auditCallbackArg(ts.fn, ins, arg, explicit, ts.tainted, ts.tainted, ts.kiFn)
		}
	}
}

// allTaintedArgsCoveredBySecretUse 逐槽核验调用中全部已染毒接收者/实参是否均被合法 //xops:secretuse 契约覆盖：
// 接收者或动态函数值染毒一律返回 false；每个已染毒实参须命中 secretCallbackSlot 或 CoversDirectSecretSlot，
// 防止仅带回调或部分形参标注的 //xops:secretuse 函数放行未审计非机密槽位的明文入参。
func (ts *taintScope) allTaintedArgsCoveredBySecretUse(rc vetssa.ResolvedCall) bool {
	if ts.eng.facts == nil || rc.FuncObj == nil {
		return false
	}
	if rc.Recv != nil && ts.isTainted(rc.Recv) {
		return false
	}
	if rc.Common != nil && !rc.Common.IsInvoke() && rc.Common.Value != nil && ts.isTainted(rc.Common.Value) {
		return false
	}
	sig, _ := rc.FuncObj.Type().Underlying().(*types.Signature)
	for i, arg := range rc.UserArgs {
		if !ts.isTainted(arg) {
			continue
		}
		if _, isCB := secretCallbackSlot(ts.eng.facts, rc.FuncObj, sig, i, arg.Type()); isCB {
			continue
		}
		if !ts.eng.facts.CoversDirectSecretSlot(rc.FuncObj, sig, i) {
			return false
		}
	}
	return true
}

func isHandledNonHelperCall(rc vetssa.ResolvedCall) bool {
	return rc.Kind == vetssa.CallBuiltin || isAppendToDstFunc(rc.FuncObj) || isFmtSprintFunc(rc.FuncObj) ||
		isSafePredicate(rc.FuncObj) || isTaintPreservingTransform(rc.FuncObj) || isIOCopyFunc(rc.FuncObj)
}

func (ts *taintScope) markCallReturns(callInst ssa.CallInstruction, retMask uint64, sc vetssa.ScopeRange) bool {
	call, ok := callInst.(*ssa.Call)
	if retMask == 0 || !ok {
		return false
	}
	if tup, isTuple := call.Type().(*types.Tuple); isTuple && tup.Len() > 1 {
		return ts.markTupleReturns(call, retMask, sc)
	}
	return retMask&1 != 0 && vetssa.MarkValueScope(ts.tainted, call, sc)
}

func (ts *taintScope) markTupleReturns(call *ssa.Call, retMask uint64, sc vetssa.ScopeRange) bool {
	if call.Referrers() == nil {
		return false
	}
	changed := false
	for _, ref := range *call.Referrers() {
		ext, ok := ref.(*ssa.Extract)
		if ok && ext.Index < 64 && (retMask&(1<<uint(ext.Index))) != 0 {
			changed = vetssa.MarkValueScope(ts.tainted, ext, sc) || changed
		}
	}
	return changed
}
