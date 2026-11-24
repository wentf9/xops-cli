package linearlease

import (
	"go/ast"
	"go/token"
	"go/types"

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
	eng             *leaseEngine
	fn              *ssa.Function
	depth           int
	ownScope        vetssa.ScopeRange
	borrowed        map[ssa.Value]vetssa.ScopeRange
	callerParams    map[ssa.Value]bool
	outerShared     map[ssa.Value]vetssa.ScopeRange
	closureVals     map[ssa.Value]*ssa.MakeClosure
	reportedAppends map[*ssa.Call]bool
	namedResAllocs  map[*ssa.Alloc]bool
}

// analyzePackageLeases 在全包 SSA 上扫描全部 //xops:borrowed 入口并执行零逃逸分析。
func analyzePackageLeases(pass *analysis.Pass, s *buildssa.SSA, facts *factIndex, secretFacts *secretfact.Result) {
	if s == nil {
		return
	}
	eng := &leaseEngine{pass: pass, ssaInfo: s, facts: facts, secretFacts: secretFacts, tracker: vetssa.NewAuditTracker()}
	for _, fn := range vetssa.AllFuncs(s) {
		eng.auditDirectEntryFunc(fn)
		vetssa.ForEachInst(fn, eng.scanInstForBorrowedCall)
	}
	vetutil.ReportSortedDedup(pass, eng.diags, false)
}

func (e *leaseEngine) auditDirectEntryFunc(fn *ssa.Function) {
	if len(fn.Blocks) == 0 {
		return
	}
	if indices := e.facts.directParams[vetssa.OriginFuncObj(fn)]; len(indices) > 0 {
		e.auditFunc(fn, indicesToMap(indices, vetssa.HasRecvParam(fn)), nil, vetssa.ScopeRangeOfFunc(fn), 0, nil)
	}
	if lit, ok := fn.Syntax().(*ast.FuncLit); ok && lit != nil && lit.Type != nil {
		if indices := collectExplicitParamIndices(e.pass.Fset, e.facts.commentsFor(e.pass.Fset, lit.Pos()), lit.Type.Params, vetutil.DirectiveBorrowed); len(indices) > 0 {
			e.auditFunc(fn, indicesToMap(indices, 0), nil, vetssa.ScopeRangeOfFunc(fn), 0, nil)
		}
	}
}

func (e *leaseEngine) scanInstForBorrowedCall(inst ssa.Instruction) {
	switch ins := inst.(type) {
	case ssa.CallInstruction:
		e.scanCallBorrowedCallbacks(ins, nil, nil)
	case *ssa.ChangeType:
		if direct := e.namedFuncDirectBorrowed(ins.Type()); len(direct) > 0 {
			e.auditCallbackTargets(ins.X, direct, nil, nil)
		}
	}
}

func (e *leaseEngine) scanCallBorrowedCallbacks(callInst ssa.CallInstruction, outerBorrowed, outerShared map[ssa.Value]vetssa.ScopeRange) {
	rc := vetssa.ResolveCall(e.ssaInfo, callInst)
	spec := resolveSSACallLeaseSpec(e.pass, e.facts, e.secretFacts, rc)
	for argIdx, innerIndices := range spec.callbackBorrowed {
		if argIdx >= len(rc.UserArgs) || len(innerIndices) == 0 {
			continue
		}
		arg := rc.UserArgs[argIdx]
		if varElems := vetssa.ExtractVarargsElements(arg); len(varElems) > 0 {
			for _, elem := range varElems {
				e.auditCallbackTargets(elem, innerIndices, outerBorrowed, outerShared)
			}
		} else {
			e.auditCallbackTargets(arg, innerIndices, outerBorrowed, outerShared)
		}
	}
}

func (e *leaseEngine) auditCallbackTargets(cbVal ssa.Value, innerIndices []int, outerBorrowed, outerShared map[ssa.Value]vetssa.ScopeRange) {
	targets, _ := vetssa.ResolveFuncValues(cbVal)
	for _, tgt := range targets {
		switch t := tgt.(type) {
		case *ssa.MakeClosure:
			if fn, ok := t.Fn.(*ssa.Function); ok && fn != nil && len(fn.Blocks) > 0 {
				e.auditFunc(fn, indicesToMap(innerIndices, 0), vetssa.CollectCaptured(t, fn, outerBorrowed), vetssa.ScopeRangeOfFunc(fn), 0, outerShared)
			}
		case *ssa.Function:
			if origFn := vetssa.UnwrapOriginFunc(t); vetssa.IsSamePackageFunc(e.ssaInfo, origFn) && len(origFn.Blocks) > 0 {
				e.auditFunc(origFn, indicesToMap(innerIndices, vetssa.HasRecvParam(origFn)), nil, vetssa.ScopeRangeOfFunc(origFn), 0, nil)
			}
		}
	}
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

func (e *leaseEngine) auditFunc(fn *ssa.Function, seedParams map[int]bool, captured map[ssa.Value]vetssa.ScopeRange, ownScope vetssa.ScopeRange, depth int, outerShared map[ssa.Value]vetssa.ScopeRange) {
	leave, ok := e.tracker.Enter(fn, seedParams, captured, depth, maxLeaseAuditDepth)
	if !ok {
		return
	}
	defer leave()

	borrowed, callerParams := vetssa.SeedScopeParams(fn, seedParams, captured, ownScope)
	ls := &leaseScope{
		eng: e, fn: fn, depth: depth, ownScope: ownScope,
		borrowed: borrowed, callerParams: callerParams, outerShared: outerShared,
		closureVals: make(map[ssa.Value]*ssa.MakeClosure), reportedAppends: make(map[*ssa.Call]bool),
		namedResAllocs: collectNamedResultAllocs(fn),
	}
	vetssa.RunFixpoint(fn, ls.propagateInst)
	before := len(ls.borrowed)
	vetssa.ForEachInst(fn, ls.auditNestedInst)
	if len(ls.borrowed) > before {
		vetssa.RunFixpoint(fn, ls.propagateInst)
	}
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
		if !borrowed || !isVal {
			return false
		}
		if mc := ls.closureVals[op]; mc != nil {
			ls.closureVals[val] = mc
		}
		return vetssa.MarkValueScope(ls.borrowed, val, sc)
	}
	switch ins := inst.(type) {
	case *ssa.Phi:
		return ls.propagatePhi(ins)
	case *ssa.Store:
		return ls.propagateStore(ins)
	case *ssa.MapUpdate:
		sc, ok := vetssa.CombinedScope(ls.borrowed, ins.Key, ins.Value)
		return ok && vetssa.MarkRootsBackward(ins.Map, sc, ls.borrowed, ls.outerShared)
	case *ssa.MakeClosure:
		sc, ok := vetssa.CombinedScope(ls.borrowed, ins.Bindings...)
		if !ok {
			return false
		}
		ls.closureVals[ins] = ins
		return vetssa.MarkValueScope(ls.borrowed, ins, sc)
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

func (ls *leaseScope) propagatePhi(phi *ssa.Phi) bool {
	sc, ok := vetssa.CombinedScope(ls.borrowed, phi.Edges...)
	if !ok {
		return false
	}
	for _, e := range phi.Edges {
		if mc := ls.closureVals[e]; mc != nil {
			ls.closureVals[phi] = mc
		}
	}
	return vetssa.MarkValueScope(ls.borrowed, phi, sc)
}

func (ls *leaseScope) propagateStore(ins *ssa.Store) bool {
	sc, ok := ls.borrowed[ins.Val]
	if !ok {
		return false
	}
	changed := vetssa.MarkRootsBackward(ins.Addr, sc, ls.borrowed, ls.outerShared)
	if mc := ls.closureVals[ins.Val]; mc != nil {
		for _, root := range vetssa.RootStorageValues(ins.Addr, true) {
			if _, isGlobal := root.(*ssa.Global); !isGlobal {
				ls.closureVals[root] = mc
			}
		}
	}
	return changed
}

func (ls *leaseScope) auditNestedInst(inst ssa.Instruction) {
	switch ins := inst.(type) {
	case *ssa.MakeClosure:
		ls.checkMakeClosure(ins)
	case ssa.CallInstruction:
		ls.eng.scanCallBorrowedCallbacks(ins, ls.borrowed, ls.borrowed)
	}
}
