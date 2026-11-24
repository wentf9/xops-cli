// Package secrettaint 实现 XOps v2 明文机密（Rule 2）SSA 污点流静态分析器。
//
// 本分析器与 secretbox（Rule 1 + Rule 3）正交拆分，依托 internal/secretfact 与 internal/vetssa
// 强制执行回调准入门禁（H3c + CRIT-4C）、嵌套同步闭包与 runtime/secret.Do 协同审计（CRIT-4D）、
// 出参全面 Fail-Closed 与精确符号级密码学表（CRIT-4A/B + B2a）以及 Phase 4 窄消费器钩子（B2b）。
package secrettaint

import (
	"go/ast"
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
	eng := &taintEngine{
		pass: pass, ssaInfo: s, pkgInfo: vetutil.ClassifyPackage(pass.Pkg.Path()),
		facts: facts, syncFuncs: collectLocalSyncClosureFuncs(pass), tracker: vetssa.NewAuditTracker(),
	}
	for _, fn := range vetssa.AllFuncs(s) {
		eng.auditDirectSecretUseFunc(fn)
		vetssa.ForEachInst(fn, func(inst ssa.Instruction) { eng.scanInstForSecretEntry(fn, inst) })
	}
	vetutil.ReportSortedDedup(pass, eng.diags, false)
	return nil, nil
}

func collectLocalSyncClosureFuncs(pass *analysis.Pass) map[*types.Func]bool {
	out := make(map[*types.Func]bool)
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.FuncDecl)(nil), (*ast.InterfaceType)(nil)}, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Name != nil && vetutil.FuncDeclHasDirective(node, vetutil.DirectiveSyncClosure) {
				recordDefFunc(pass, node.Name, out)
			}
		case *ast.InterfaceType:
			collectInterfaceSyncClosure(pass, node, out)
		}
	})
	return out
}

func collectInterfaceSyncClosure(pass *analysis.Pass, iface *ast.InterfaceType, out map[*types.Func]bool) {
	if iface.Methods == nil {
		return
	}
	for _, m := range iface.Methods.List {
		if len(m.Names) > 0 && vetutil.FieldHasDirective(m, vetutil.DirectiveSyncClosure) {
			recordDefFunc(pass, m.Names[0], out)
		}
	}
}

func recordDefFunc(pass *analysis.Pass, id *ast.Ident, out map[*types.Func]bool) {
	if fnObj, ok := pass.TypesInfo.Defs[id].(*types.Func); ok && fnObj != nil {
		out[fnObj.Origin()] = true
	}
}

func (e *taintEngine) auditDirectSecretUseFunc(fn *ssa.Function) {
	obj := vetssa.OriginFuncObj(fn)
	if len(fn.Blocks) == 0 || e.facts == nil || obj == nil || !e.facts.HasFuncFact(obj) || secretfact.IsSecretBoxUseMethod(obj) {
		return
	}
	if seeds := secretPlainParamIndices(fn); len(seeds) > 0 {
		e.auditFunc(fn, seeds, nil, vetssa.ScopeRangeOfFunc(fn), 0, nil)
	}
}

// scanInstForSecretEntry 扫描 SecretBox.Use / //xops:secretuse 调用点与具名回调类型写入站点（CRIT-4C）。
func (e *taintEngine) scanInstForSecretEntry(fn *ssa.Function, inst ssa.Instruction) {
	if e.facts == nil {
		return
	}
	switch ins := inst.(type) {
	case ssa.CallInstruction:
		e.scanCallSecretEntry(fn, ins)
	case *ssa.ChangeType:
		if e.facts.IsSecretUseNamedFuncType(ins.Type()) {
			e.auditCallbackArg(fn, ins, ins.X, nil, nil)
		}
	case *ssa.Store:
		if ptr, ok := types.Unalias(ins.Addr.Type()).(*types.Pointer); ok && e.facts.IsSecretUseNamedFuncType(ptr.Elem()) {
			e.auditCallbackArg(fn, ins, ins.Val, nil, nil)
		}
	case *ssa.MapUpdate:
		if m, ok := types.Unalias(ins.Map.Type()).Underlying().(*types.Map); ok && e.facts.IsSecretUseNamedFuncType(m.Elem()) {
			e.auditCallbackArg(fn, ins, ins.Value, nil, nil)
		}
	case *ssa.Return:
		e.scanReturnSecretCB(fn, ins)
	}
}

func (e *taintEngine) scanReturnSecretCB(fn *ssa.Function, ret *ssa.Return) {
	if fn.Signature == nil || fn.Signature.Results() == nil {
		return
	}
	results := fn.Signature.Results()
	for i, r := range ret.Results {
		if i < results.Len() && !vetssa.IsNilConst(r) && e.facts.IsSecretUseNamedFuncType(results.At(i).Type()) {
			e.auditCallbackArg(fn, ret, r, nil, nil)
		}
	}
}

func (e *taintEngine) scanCallSecretEntry(fn *ssa.Function, callInst ssa.CallInstruction) {
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
			e.auditCallbackArg(fn, callInst, arg, nil, nil)
		}
	}
}

func isSecretCallbackArgSlot(facts *secretfact.Result, sig *types.Signature, isSecretObj bool, argIdx int, argType types.Type) bool {
	if sig != nil && sig.Params() != nil && argIdx < sig.Params().Len() && facts.IsSecretUseNamedFuncType(sig.Params().At(argIdx).Type()) {
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

// auditCallbackArg 执行回调准入门禁（H3c + CRIT-4C）。
func (e *taintEngine) auditCallbackArg(callerFn *ssa.Function, siteInst ssa.Instruction, cbVal ssa.Value, outerTaint, outerShared map[ssa.Value]vetssa.ScopeRange) {
	if isDirectSecretUseParam(e.facts, cbVal) {
		return
	}
	targets, allKnown := vetssa.ResolveFuncValues(cbVal)
	for _, tgt := range targets {
		e.auditResolvedCallbackTarget(callerFn, siteInst, tgt, outerTaint, outerShared)
	}
	if !allKnown {
		vetssa.AppendDiag(e.pass, &e.diags, callerFn, siteInst, "secrettaint: 禁止将无法静态验证的未知函数或回调传入 SecretBox.Use / //xops:secretuse")
	}
}

func (e *taintEngine) auditResolvedCallbackTarget(callerFn *ssa.Function, siteInst ssa.Instruction, target ssa.Value, outerTaint, outerShared map[ssa.Value]vetssa.ScopeRange) {
	switch t := target.(type) {
	case *ssa.MakeClosure:
		fn, ok := t.Fn.(*ssa.Function)
		if !ok || fn == nil {
			return
		}
		if vetssa.IsBoundWrapper(fn) {
			e.auditBoundMethodCallback(callerFn, siteInst, fn)
		} else {
			e.auditFunc(fn, secretPlainParamIndices(fn), vetssa.CollectCaptured(t, fn, outerTaint), vetssa.ScopeRangeOfFunc(fn), 0, outerShared)
		}
	case *ssa.Function:
		origFn := vetssa.UnwrapOriginFunc(t)
		if vetssa.IsSamePackageFunc(e.ssaInfo, origFn) && len(origFn.Blocks) > 0 {
			e.auditFunc(origFn, secretPlainParamIndices(origFn), nil, vetssa.ScopeRangeOfFunc(origFn), 0, nil)
		} else if e.facts == nil || !e.facts.HasFuncFact(vetssa.OriginFuncObj(origFn)) {
			vetssa.AppendDiag(e.pass, &e.diags, callerFn, siteInst, "secrettaint: 禁止将未标注 //xops:secretuse 的跨包函数传入 SecretBox.Use")
		}
	}
}

func (e *taintEngine) auditBoundMethodCallback(callerFn *ssa.Function, siteInst ssa.Instruction, boundFn *ssa.Function) {
	origObj := vetssa.OriginFuncObj(boundFn)
	if origObj == nil {
		vetssa.AppendDiag(e.pass, &e.diags, callerFn, siteInst, "secrettaint: 禁止将无法静态验证的未知函数或回调传入 SecretBox.Use / //xops:secretuse")
		return
	}
	if mFn := vetssa.LookupPackageFunc(e.ssaInfo, origObj); mFn != nil && len(mFn.Blocks) > 0 {
		// $bound 接收者 Params[0] 不作种子，由 auditFunc 锁定为不可写 CallerParam。
		e.auditFunc(mFn, secretPlainParamIndices(mFn), nil, vetssa.ScopeRangeOfFunc(mFn), 0, nil)
	} else if e.facts == nil || !e.facts.HasFuncFact(origObj) {
		vetssa.AppendDiag(e.pass, &e.diags, callerFn, siteInst, "secrettaint: 禁止将未标注 //xops:secretuse 的接口方法或无体函数传入 SecretBox.Use")
	}
}

func isDirectSecretUseParam(facts *secretfact.Result, v ssa.Value) bool {
	if facts == nil {
		return false
	}
	for {
		switch val := v.(type) {
		case *ssa.Parameter:
			return facts.IsSecretUseNamedFuncType(val.Type())
		case *ssa.ChangeType:
			v = val.X
		case *ssa.Convert:
			v = val.X
		default:
			return false
		}
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
