// Package secrettaint 实现 XOps v2 明文机密（Rule 2）SSA 污点流静态分析器。
//
// 本分析器与 secretbox（Rule 1 + Rule 3）正交拆分，依托 internal/secretfact 与 internal/vetssa
// 强制执行回调准入门禁、跨包同步闭包（//xops:syncclosure）与 runtime/secret.Do 协同审计、
// 返回值槽位回染（ReturnMask）、出参全面 Fail-Closed、精确符号级密码学消费表及 Phase 4 窄消费器钩子。
package secrettaint

import (
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ssa"
)

const sshCryptoPkgPath = "golang.org/x/crypto/ssh"

// NewAnalyzer 创建并返回 secrettaint Rule 2 明文机密污点分析器实例。
func NewAnalyzer(sf *analysis.Analyzer) *analysis.Analyzer {
	if sf == nil {
		sf = secretfact.NewAnalyzer()
	}
	return &analysis.Analyzer{
		Name:     "secrettaint",
		Doc:      "检查 SecretBox.Use 与 //xops:secretuse 明文污点流零逃逸、回调准入及密码学消费安全边界",
		Requires: []*analysis.Analyzer{inspect.Analyzer, buildssa.Analyzer, sf},
		Run:      func(pass *analysis.Pass) (any, error) { return run(pass, sf) },
	}
}

func run(pass *analysis.Pass, sf *analysis.Analyzer) (any, error) {
	s := vetssa.PackageSSA(pass)
	if vetutil.IsSyntheticTestMain(pass) || pass.TypesInfo == nil || s == nil {
		return nil, nil
	}
	facts, _ := pass.ResultOf[sf].(*secretfact.Result)
	pkgInfo := vetutil.ClassifyPass(pass)
	eng := &taintEngine{
		pass: pass, ssaInfo: s, pkgInfo: pkgInfo, facts: facts,
		tracker: vetssa.NewAuditTracker(), kiClosures: collectDialKIClosures(pkgInfo, s),
		kiTaintedRoots: map[*ssa.Function][]ssa.Value{},
	}
	for _, fn := range vetssa.AllFuncs(s) {
		eng.auditDirectSecretUseFunc(fn)
		vetssa.ForEachInst(fn, func(inst ssa.Instruction) { eng.scanInstForSecretEntry(fn, inst) })
	}
	for kiFn, roots := range eng.kiTaintedRoots {
		eng.auditDialKIFunc(kiFn, roots)
	}
	vetutil.ReportSortedDedup(pass, eng.diags, false)
	return nil, nil
}

func (e *taintEngine) auditDirectSecretUseFunc(fn *ssa.Function) {
	obj := vetssa.OriginFuncObj(fn)
	if len(fn.Blocks) == 0 || e.facts == nil || obj == nil || !e.facts.HasFuncFact(obj) || secretfact.IsSecretBoxUseMethod(obj) {
		return
	}
	if seeds := secretPlainParamIndices(fn); len(seeds) > 0 {
		e.auditFunc(fn, seeds, nil, vetssa.ScopeRangeOfFunc(fn), 0, nil, nil, e.enclosingKIFunc(fn))
	}
}

// scanInstForSecretEntry 扫描 SecretBox.Use / //xops:secretuse 调用点与具名回调类型写入站点。
func (e *taintEngine) scanInstForSecretEntry(fn *ssa.Function, inst ssa.Instruction) {
	if e.facts == nil {
		return
	}
	kiFn := e.enclosingKIFunc(fn)
	switch ins := inst.(type) {
	case ssa.CallInstruction:
		e.scanCallSecretEntry(fn, ins, kiFn)
	case *ssa.ChangeType:
		if e.facts.IsSecretUseNamedFuncType(ins.Type()) {
			e.auditCallbackArg(fn, ins, ins.X, nil, nil, kiFn)
		}
	case *ssa.Store:
		if ptr, ok := types.Unalias(ins.Addr.Type()).(*types.Pointer); ok && e.facts.IsSecretUseNamedFuncType(ptr.Elem()) {
			e.auditCallbackArg(fn, ins, ins.Val, nil, nil, kiFn)
		}
	case *ssa.MapUpdate:
		if m, ok := types.Unalias(ins.Map.Type()).Underlying().(*types.Map); ok && e.facts.IsSecretUseNamedFuncType(m.Elem()) {
			e.auditCallbackArg(fn, ins, ins.Value, nil, nil, kiFn)
		}
	case *ssa.Return:
		e.scanReturnSecretCB(fn, ins, kiFn)
	}
}

func (e *taintEngine) scanReturnSecretCB(fn *ssa.Function, ret *ssa.Return, kiFn *ssa.Function) {
	if fn.Signature == nil || fn.Signature.Results() == nil {
		return
	}
	results := fn.Signature.Results()
	for i, r := range ret.Results {
		if i < results.Len() && !vetssa.IsNilConst(r) && e.facts.IsSecretUseNamedFuncType(results.At(i).Type()) {
			e.auditCallbackArg(fn, ret, r, nil, nil, kiFn)
		}
	}
}

func (e *taintEngine) scanCallSecretEntry(fn *ssa.Function, callInst ssa.CallInstruction, kiFn *ssa.Function) {
	rc := vetssa.ResolveCall(e.ssaInfo, callInst)
	if rc.FuncObj == nil {
		return
	}
	isSecretObj := e.facts.IsSecretUseObject(rc.FuncObj)
	if !isSecretObj && !e.facts.HasSecretUseCallbackParam(rc.FuncObj) {
		return
	}
	sig, _ := rc.FuncObj.Type().Underlying().(*types.Signature)
	for i, arg := range rc.UserArgs {
		if isSecretCallbackArgSlot(e.facts, sig, isSecretObj, i, arg.Type()) {
			e.auditCallbackArg(fn, callInst, arg, nil, nil, kiFn)
		}
	}
}

func isSecretCallbackArgSlot(facts *secretfact.Result, sig *types.Signature, isSecretObj bool, argIdx int, argType types.Type) bool {
	if sig != nil && facts.IsSecretUseNamedFuncType(vetutil.ParamTypeAt(sig.Params(), sig.Variadic(), argIdx)) {
		return true
	}
	cbSig, ok := types.Unalias(argType).Underlying().(*types.Signature)
	if !isSecretObj || !ok || cbSig.Params() == nil {
		return false
	}
	for i := range cbSig.Params().Len() {
		if isPlainSecretParamType(cbSig.Params().At(i).Type()) {
			return true
		}
	}
	return false
}

// auditCallbackArg 执行回调准入门禁并透传外层污点与 P4-T1 KI 上下文。
func (e *taintEngine) auditCallbackArg(callerFn *ssa.Function, siteInst ssa.Instruction, cbVal ssa.Value, outerTaint, outerShared map[ssa.Value]vetssa.ScopeRange, kiFn *ssa.Function) {
	if p := vetssa.UnwrapDirectParam(cbVal); p != nil && e.facts != nil && e.facts.IsSecretUseNamedFuncType(p.Type()) {
		return
	}
	targets, allKnown := vetssa.ResolveFuncValues(cbVal)
	for _, tgt := range targets {
		e.auditResolvedCallbackTarget(callerFn, siteInst, tgt, outerTaint, outerShared, kiFn)
	}
	if !allKnown {
		vetssa.AppendDiag(e.pass, &e.diags, callerFn, siteInst, "secrettaint: 禁止将无法静态验证的未知函数或回调传入 SecretBox.Use / //xops:secretuse")
	}
}

func (e *taintEngine) auditResolvedCallbackTarget(callerFn *ssa.Function, siteInst ssa.Instruction, target ssa.Value, outerTaint, outerShared map[ssa.Value]vetssa.ScopeRange, kiFn *ssa.Function) {
	switch t := target.(type) {
	case *ssa.MakeClosure:
		fn, ok := t.Fn.(*ssa.Function)
		if !ok || fn == nil {
			return
		}
		if vetssa.IsBoundWrapper(fn) {
			e.auditBoundMethodCallback(callerFn, siteInst, fn, kiFn)
		} else {
			e.auditFunc(fn, secretPlainParamIndices(fn), vetssa.CollectCaptured(t, fn, outerTaint), vetssa.ScopeRangeOfFunc(fn), 0, outerShared, siteInst, kiFn)
		}
	case *ssa.Function:
		origFn := vetssa.UnwrapOriginFunc(t)
		if vetssa.IsSamePackageFunc(e.ssaInfo, origFn) && len(origFn.Blocks) > 0 {
			e.auditFunc(origFn, secretPlainParamIndices(origFn), nil, vetssa.ScopeRangeOfFunc(origFn), 0, nil, siteInst, kiFn)
		} else if e.facts == nil || !e.facts.HasFuncFact(vetssa.OriginFuncObj(origFn)) {
			vetssa.AppendDiag(e.pass, &e.diags, callerFn, siteInst, "secrettaint: 禁止将未标注 //xops:secretuse 的跨包函数传入 SecretBox.Use")
		}
	}
}

func (e *taintEngine) auditBoundMethodCallback(callerFn *ssa.Function, siteInst ssa.Instruction, boundFn, kiFn *ssa.Function) {
	origObj := vetssa.OriginFuncObj(boundFn)
	if origObj == nil {
		vetssa.AppendDiag(e.pass, &e.diags, callerFn, siteInst, "secrettaint: 禁止将无法静态验证的未知函数或回调传入 SecretBox.Use / //xops:secretuse")
		return
	}
	if mFn := vetssa.LookupPackageFunc(e.ssaInfo, origObj); mFn != nil && len(mFn.Blocks) > 0 {
		e.auditFunc(mFn, secretPlainParamIndices(mFn), nil, vetssa.ScopeRangeOfFunc(mFn), 0, nil, siteInst, kiFn)
	} else if e.facts == nil || !e.facts.HasFuncFact(origObj) {
		vetssa.AppendDiag(e.pass, &e.diags, callerFn, siteInst, "secrettaint: 禁止将未标注 //xops:secretuse 的接口方法或无体函数传入 SecretBox.Use")
	}
}

func secretPlainParamIndices(fn *ssa.Function) map[int]bool {
	seeds := make(map[int]bool)
	for i := vetssa.HasRecvParam(fn); i < len(fn.Params); i++ {
		if isPlainSecretParamType(fn.Params[i].Type()) {
			seeds[i] = true
		}
	}
	return seeds
}

func isPlainSecretParamType(t types.Type) bool {
	if t == nil {
		return false
	}
	u := types.Unalias(t).Underlying()
	if sl, ok := u.(*types.Slice); ok {
		b, ok := types.Unalias(sl.Elem()).Underlying().(*types.Basic)
		return ok && (b.Kind() == types.Byte || b.Kind() == types.Uint8)
	}
	b, ok := u.(*types.Basic)
	return ok && b.Info()&types.IsString != 0
}
