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
	pass      *analysis.Pass
	ssaInfo   *buildssa.SSA
	pkgInfo   vetutil.PkgInfo
	facts     *secretfact.Result
	syncFuncs map[*types.Func]bool
	tracker   *vetssa.AuditTracker
	diags     []vetutil.Diag
}

type taintScope struct {
	eng          *taintEngine
	fn           *ssa.Function
	depth        int
	ownScope     vetssa.ScopeRange
	tainted      map[ssa.Value]vetssa.ScopeRange
	callerParams map[ssa.Value]bool
	outerShared  map[ssa.Value]vetssa.ScopeRange
}

// auditFunc 在单个 SSA 函数或闭包体上执行 Rule 2 明文污点不动点传播与全量 Fail-Closed 检查。
func (e *taintEngine) auditFunc(fn *ssa.Function, seedParams map[int]bool, captured map[ssa.Value]vetssa.ScopeRange, ownScope vetssa.ScopeRange, depth int, outerShared map[ssa.Value]vetssa.ScopeRange) {
	leave, ok := e.tracker.Enter(fn, seedParams, captured, depth, maxAuditDepth)
	if !ok {
		return
	}
	defer leave()

	tainted, callerParams := vetssa.SeedScopeParams(fn, seedParams, captured, ownScope)
	ts := &taintScope{eng: e, fn: fn, depth: depth, ownScope: ownScope, tainted: tainted, callerParams: callerParams, outerShared: outerShared}
	vetssa.RunFixpoint(fn, ts.propagateInst)
	before := len(ts.tainted)
	vetssa.ForEachInst(fn, ts.auditNestedInst)
	if len(ts.tainted) > before {
		vetssa.RunFixpoint(fn, ts.propagateInst)
	}
	vetssa.ForEachInst(fn, ts.checkInst)
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
		return ins.Op == token.ADD && ok && vetssa.MarkValueScope(ts.tainted, ins, sc)
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

func (ts *taintScope) propagateCall(call *ssa.Call) bool {
	rc := vetssa.ResolveCall(ts.eng.ssaInfo, call)
	if rc.Kind == vetssa.CallBuiltin && rc.Builtin != nil {
		return vetssa.PropagateBuiltinCopyAppend(call, rc, ts.tainted, ts.outerShared)
	}
	if sc, ok := ts.writeToDstCallTaint(rc); ok {
		return ts.propagateWriteToDst(rc, sc)
	}
	inSc, hasTaint := ts.callInputScope(rc)
	if !hasTaint || (!isTaintPreservingTransform(rc.FuncObj) && !isFmtAppendFunc(rc.FuncObj)) {
		return false
	}
	changed := vetssa.MarkValueScope(ts.tainted, call, inSc)
	if isFmtAppendFunc(rc.FuncObj) && len(rc.UserArgs) > 0 && !vetssa.IsFreshLocalSlice(rc.UserArgs[0]) && !vetssa.IsNilConst(rc.UserArgs[0]) {
		changed = vetssa.MarkRootsBackward(rc.UserArgs[0], inSc, ts.tainted, ts.outerShared) || changed
	}
	return changed
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
	sc, ok := vetssa.CombinedScope(ts.tainted, rc.UserArgs...)
	if rc.Recv != nil {
		if rsc, rok := ts.tainted[rc.Recv]; rok {
			return vetssa.TightenScope(sc, rsc), true
		}
	}
	return sc, ok
}

// auditNestedInst 先于最终检查遍历嵌套同步闭包，使内层回写外层局部变量的污点参与二次传播。
func (ts *taintScope) auditNestedInst(inst ssa.Instruction) {
	switch ins := inst.(type) {
	case *ssa.MakeClosure:
		ts.checkMakeClosure(ins)
	case ssa.CallInstruction:
		rc := vetssa.ResolveCall(ts.eng.ssaInfo, ins)
		if ts.eng.facts == nil || rc.FuncObj == nil || !ts.eng.facts.IsSecretUseObject(rc.FuncObj) {
			return
		}
		sig, _ := rc.FuncObj.Type().Underlying().(*types.Signature)
		for i, arg := range rc.UserArgs {
			if isSecretCallbackArgSlot(ts.eng.facts, sig, true, i, arg.Type()) {
				ts.eng.auditCallbackArg(ts.fn, ins, arg, ts.tainted, ts.tainted)
			}
		}
	}
}
