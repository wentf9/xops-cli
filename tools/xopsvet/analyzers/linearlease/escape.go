package linearlease

import (
	"go/ast"
	"go/token"
	"go/types"
	"maps"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

const maxLeaseAuditDepth = 8

type leaseEngine struct {
	pass        *analysis.Pass
	ssaInfo     *buildssa.SSA
	facts       *factIndex
	secretFacts *secretfact.Result
	tracker     *vetssa.AuditTracker
	diags       []vetutil.Diag
}

type leaseScope struct {
	eng              *leaseEngine
	fn               *ssa.Function
	depth            int
	ownScope         vetssa.ScopeRange
	borrowed         map[ssa.Value]vetssa.ScopeRange
	callerParams     map[ssa.Value]bool
	outerShared      map[ssa.Value]vetssa.ScopeRange
	reportedAppends  map[*ssa.Call]bool
	namedResAllocs   map[*ssa.Alloc]bool
	auditedIterCalls map[ssa.CallInstruction]bool
}

// analyzePackageLeases 在全包 SSA 上扫描全部 //xops:borrowed 入口并执行零逃逸分析。
func analyzePackageLeases(pass *analysis.Pass, s *buildssa.SSA, facts *factIndex, secretFacts *secretfact.Result) {
	if s == nil {
		return
	}
	eng := &leaseEngine{pass: pass, ssaInfo: s, facts: facts, secretFacts: secretFacts, tracker: vetssa.NewAuditTracker()}
	for _, fn := range vetssa.AllFuncs(s) {
		eng.auditDirectEntryFunc(fn)
		vetssa.ForEachInst(fn, func(inst ssa.Instruction) { eng.scanInstForBorrowedCall(fn, inst) })
	}
	vetutil.ReportSortedDedup(pass, eng.diags, false)
}

func (e *leaseEngine) auditDirectEntryFunc(fn *ssa.Function) {
	if len(fn.Blocks) == 0 {
		return
	}
	if indices := e.facts.directParams[vetssa.OriginFuncObj(fn)]; len(indices) > 0 {
		e.auditFunc(fn, indicesToMap(indices, vetssa.HasRecvParam(fn)), nil, vetssa.ScopeRangeOfFunc(fn), 0, nil, nil, nil)
	}
	if lit, ok := fn.Syntax().(*ast.FuncLit); ok && lit != nil && lit.Type != nil {
		if indices := collectExplicitParamIndices(e.pass.Fset, e.facts.commentsFor(e.pass.Fset, lit.Pos()), lit.Type.Params, vetutil.DirectiveBorrowed); len(indices) > 0 {
			e.auditFunc(fn, indicesToMap(indices, 0), nil, vetssa.ScopeRangeOfFunc(fn), 0, nil, nil, nil)
		}
	}
}

func (e *leaseEngine) scanInstForBorrowedCall(callerFn *ssa.Function, inst ssa.Instruction) {
	switch ins := inst.(type) {
	case ssa.CallInstruction:
		e.scanCallBorrowedCallbacks(callerFn, ins, nil, nil, nil)
	case *ssa.ChangeType:
		if direct := e.namedFuncDirectBorrowed(ins.Type()); len(direct) > 0 {
			e.auditCallbackTargets(callerFn, ins, ins.X, direct, nil, nil, nil)
		}
	}
}

func (e *leaseEngine) scanCallBorrowedCallbacks(callerFn *ssa.Function, callInst ssa.CallInstruction, outerBorrowed, outerShared map[ssa.Value]vetssa.ScopeRange, ancNamedRes map[*ssa.Alloc]bool) {
	rc := vetssa.ResolveCall(e.ssaInfo, callInst)
	spec := resolveSSACallLeaseSpec(e.pass, e.facts, e.secretFacts, rc)
	for argIdx, innerIndices := range spec.callbackBorrowed {
		if argIdx >= len(rc.UserArgs) || len(innerIndices) == 0 {
			continue
		}
		arg := rc.UserArgs[argIdx]
		if varElems := vetssa.ExtractVarargsElements(arg); len(varElems) > 0 {
			for _, elem := range varElems {
				e.auditCallbackTargets(callerFn, callInst, elem, innerIndices, outerBorrowed, outerShared, ancNamedRes)
			}
		} else {
			e.auditCallbackTargets(callerFn, callInst, arg, innerIndices, outerBorrowed, outerShared, ancNamedRes)
		}
	}
}

func (e *leaseEngine) auditCallbackTargets(callerFn *ssa.Function, siteInst ssa.Instruction, cbVal ssa.Value, innerIndices []int, outerBorrowed, outerShared map[ssa.Value]vetssa.ScopeRange, ancNamedRes map[*ssa.Alloc]bool) {
	if vetssa.IsNilConst(cbVal) || e.isDirectBorrowedFuncParam(cbVal) {
		return
	}
	targets, allKnown := vetssa.ResolveFuncValues(cbVal)
	for _, tgt := range targets {
		switch t := tgt.(type) {
		case *ssa.MakeClosure:
			if fn, ok := t.Fn.(*ssa.Function); ok && fn != nil && len(fn.Blocks) > 0 {
				e.auditFunc(fn, indicesToMap(innerIndices, 0), vetssa.CollectCaptured(t, fn, outerBorrowed), vetssa.ScopeRangeOfFunc(fn), 0, outerShared, ancNamedRes, siteInst)
			}
		case *ssa.Function:
			if origFn := vetssa.UnwrapOriginFunc(t); vetssa.IsSamePackageFunc(e.ssaInfo, origFn) && len(origFn.Blocks) > 0 {
				e.auditFunc(origFn, indicesToMap(innerIndices, vetssa.HasRecvParam(origFn)), nil, vetssa.ScopeRangeOfFunc(origFn), 0, nil, nil, siteInst)
			}
		}
	}
	if !allKnown {
		vetssa.AppendDiag(e.pass, &e.diags, callerFn, siteInst, "linearlease: 禁止将无法静态验证的未知函数或回调传入 //xops:borrowed 高阶函数")
	}
}

func (e *leaseEngine) isDirectBorrowedFuncParam(v ssa.Value) bool {
	p := vetssa.UnwrapDirectParam(v)
	return p != nil && len(e.namedFuncDirectBorrowed(p.Type())) > 0
}

func (e *leaseEngine) namedFuncDirectBorrowed(t types.Type) []int {
	if t == nil {
		return nil
	}
	if named, ok := types.Unalias(t).(*types.Named); ok && named != nil && named.Origin() != nil && named.Origin().Obj() != nil {
		if tf, found := lookupBorrowedFact(e.pass, e.facts.typeFacts, named.Origin().Obj()); found {
			return tf.DirectBorrowed
		}
	}
	return nil
}

func (e *leaseEngine) auditFunc(fn *ssa.Function, seedParams map[int]bool, captured map[ssa.Value]vetssa.ScopeRange, ownScope vetssa.ScopeRange, depth int, outerShared map[ssa.Value]vetssa.ScopeRange, ancNamedRes map[*ssa.Alloc]bool, siteInst ssa.Instruction) {
	_, leave, status := e.tracker.Enter(fn, seedParams, captured, depth, maxLeaseAuditDepth)
	switch status {
	case vetssa.EnterSkip:
		return
	case vetssa.EnterDepthExceeded:
		vetssa.ReportDepthExceeded(e.pass, &e.diags, fn, siteInst, "linearlease: 嵌套审计深度超过上限，按 Fail-Closed 拦截潜在借用逃逸")
		return
	}
	defer leave()

	borrowed, callerParams := vetssa.SeedScopeParams(fn, seedParams, captured, ownScope)
	namedRes := collectNamedResultAllocs(fn)
	maps.Copy(namedRes, ancNamedRes)
	ls := &leaseScope{
		eng: e, fn: fn, depth: depth, ownScope: ownScope,
		borrowed: borrowed, callerParams: callerParams, outerShared: outerShared,
		reportedAppends: map[*ssa.Call]bool{}, namedResAllocs: namedRes, auditedIterCalls: map[ssa.CallInstruction]bool{},
	}
	vetssa.RunScopedFixpoint(fn, ls.borrowed, outerShared, ls.propagateInst, ls.auditNestedInst)
	vetssa.ForEachInst(fn, ls.checkInst)
}

func collectNamedResultAllocs(fn *ssa.Function) map[*ssa.Alloc]bool {
	out := make(map[*ssa.Alloc]bool)
	if fn == nil || fn.Signature == nil || fn.Signature.Results() == nil {
		return out
	}
	resPos := make(map[token.Pos]bool)
	for i := range fn.Signature.Results().Len() {
		if r := fn.Signature.Results().At(i); r.Name() != "" && r.Pos().IsValid() {
			resPos[r.Pos()] = true
		}
	}
	if len(resPos) > 0 {
		vetssa.ForEachInst(fn, func(inst ssa.Instruction) {
			if a, ok := inst.(*ssa.Alloc); ok && resPos[a.Pos()] {
				out[a] = true
			}
		})
	}
	return out
}

func (ls *leaseScope) propagateInst(inst ssa.Instruction) bool {
	if op, ok := vetssa.UnaryFlowOperand(inst, true); ok {
		sc, borrowed := ls.borrowed[op]
		val, isVal := inst.(ssa.Value)
		return borrowed && isVal && vetssa.MarkValueScope(ls.borrowed, val, sc)
	}
	switch ins := inst.(type) {
	case *ssa.Phi:
		sc, ok := vetssa.CombinedScope(ls.borrowed, ins.Edges...)
		return ok && vetssa.MarkValueScope(ls.borrowed, ins, sc)
	case *ssa.Store:
		sc, ok := ls.borrowed[ins.Val]
		return ok && vetssa.MarkRootsBackward(ins.Addr, sc, ls.borrowed, ls.outerShared)
	case *ssa.MapUpdate:
		sc, ok := vetssa.CombinedScope(ls.borrowed, ins.Key, ins.Value)
		return ok && vetssa.MarkRootsBackward(ins.Map, sc, ls.borrowed, ls.outerShared)
	case *ssa.MakeClosure:
		sc, ok := vetssa.CombinedScope(ls.borrowed, ins.Bindings...)
		return ok && vetssa.MarkValueScope(ls.borrowed, ins, sc)
	case *ssa.Call:
		return ls.propagateCall(ins)
	}
	return false
}

func (ls *leaseScope) propagateCall(call *ssa.Call) bool {
	rc := vetssa.ResolveCall(ls.eng.ssaInfo, call)
	if rc.Kind == vetssa.CallBuiltin && rc.Builtin != nil {
		return vetssa.PropagateBuiltinCopyAppend(call, rc, ls.borrowed, ls.outerShared)
	}
	if vetssa.IsStdlibSyncIter(rc.FuncObj) {
		sc, ok := vetssa.CombinedScope(ls.borrowed, rc.UserArgs...)
		return ok && vetssa.MarkValueScope(ls.borrowed, call, sc)
	}
	return false
}

// auditNestedInst 在收敛阶段审计内层同步闭包、IIFE、直接 iter.Seq 与同包辅助调用（LL-1 / LL-4）。
func (ls *leaseScope) auditNestedInst(inst ssa.Instruction) {
	switch ins := inst.(type) {
	case *ssa.MakeClosure:
		ls.checkMakeClosure(ins)
	case ssa.CallInstruction:
		if _, isGo := ins.(*ssa.Go); isGo {
			return
		}
		ls.auditNestedCall(ins)
	}
}

func (ls *leaseScope) auditNestedCall(callInst ssa.CallInstruction) {
	ls.eng.scanCallBorrowedCallbacks(ls.fn, callInst, ls.borrowed, ls.borrowed, ls.namedResAllocs)
	rc := vetssa.ResolveCall(ls.eng.ssaInfo, callInst)
	if rc.Kind == vetssa.CallBuiltin {
		return
	}
	if rc.Common != nil && !rc.Common.IsInvoke() {
		if ls.auditDirectIterCall(callInst, rc) {
			ls.auditedIterCalls[callInst] = true
			return
		}
		ls.auditInvokedLocalClosure(callInst, rc)
	}
	spec := resolveSSACallLeaseSpec(ls.eng.pass, ls.eng.facts, ls.eng.secretFacts, rc)
	if spec.syncClosure || ls.isAuditableLocalClosureCallee(rc) {
		for _, arg := range rc.UserArgs {
			ls.auditSyncClosureArgRec(callInst, arg)
		}
	}
	ls.auditSamePkgBorrowedHelperCall(callInst, rc)
}
