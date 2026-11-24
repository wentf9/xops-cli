package secrettaint

import (
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

const (
	dialPkgPath  = vetutil.ModulePrefix + "/core/internal/sshnet/dial"
	vaultPkgPath = vetutil.ModulePrefix + "/internal/host/vault"
)

// 本文件实现 Phase 4 受控窄消费器模式钩子（B-4 / ST-7 / ST-10）：
//   1. P4-T1（core/internal/sshnet/dial）：仅放行唯一流向 ssh.KeyboardInteractive 的挑战闭包内，
//      通过 box.Use 写入局部 answers []string 并在槽 0 返回（槽 1 error 禁染毒，闭包体全量复审）；
//   2. P4-T4（internal/host/vault）：Windows CREDENTIALW 本作用域局部结构体写入 + LazyProc.Call。

func collectDialKIClosures(pkgInfo vetutil.PkgInfo, s *buildssa.SSA) map[*ssa.Function]bool {
	out := make(map[*ssa.Function]bool)
	if pkgInfo.IsExternalTest || pkgInfo.BasePath != dialPkgPath || s == nil {
		return out
	}
	vetssa.ForEachFuncInst(vetssa.AllFuncs(s), func(_ *ssa.Function, inst ssa.Instruction) {
		call, ok := inst.(ssa.CallInstruction)
		if !ok {
			return
		}
		rc := vetssa.ResolveCall(s, call)
		if vetutil.IsPkgSymbol(rc.FuncObj, sshCryptoPkgPath, "KeyboardInteractive") && len(rc.UserArgs) >= 1 {
			if fn := extractExclusiveKIClosure(rc.UserArgs[0], call); fn != nil && hasKIChallengeSignature(fn.Signature) {
				out[fn] = true
			}
		}
	})
	return out
}

func extractExclusiveKIClosure(arg ssa.Value, kiCall ssa.CallInstruction) *ssa.Function {
	expectedRef := ssa.Instruction(kiCall)
	if ct, ok := arg.(*ssa.ChangeType); ok {
		if ct.Referrers() == nil || len(*ct.Referrers()) != 1 || (*ct.Referrers())[0] != expectedRef {
			return nil
		}
		arg, expectedRef = ct.X, ct
	}
	if mc, ok := arg.(*ssa.MakeClosure); ok {
		if fn, isFn := mc.Fn.(*ssa.Function); isFn && fn != nil && mc.Referrers() != nil && len(*mc.Referrers()) == 1 && (*mc.Referrers())[0] == expectedRef {
			return fn
		}
		return nil
	}
	fn, _ := arg.(*ssa.Function)
	return fn
}

func (e *taintEngine) enclosingKIFunc(fn *ssa.Function) *ssa.Function {
	for cur := fn; cur != nil; cur = cur.Parent() {
		if e.kiClosures[cur] {
			return cur
		}
	}
	return nil
}

// checkDialKIAnswersStore 放行 P4-T1 挑战闭包内 box.Use 向局部 answers []string 写入并登记根切片复审。
func (ts *taintScope) checkDialKIAnswersStore(ins *ssa.Store) bool {
	if ts.kiFn == nil || ts.eng.pkgInfo.IsExternalTest || ts.eng.pkgInfo.BasePath != dialPkgPath {
		return false
	}
	ia, ok := ins.Addr.(*ssa.IndexAddr)
	if !ok || !isSliceOfBasic(ia.X.Type(), types.IsString) {
		return false
	}
	kiScope := vetssa.ScopeRangeOfFunc(ts.kiFn)
	if !vetssa.AllRootsOwnedInScope(ia.X, kiScope, nil) {
		return false
	}
	kiRoots := collectKIAnswersAuditRoots(ia.X, kiScope)
	if len(kiRoots) == 0 {
		return false
	}
	for _, r := range kiRoots {
		if !slices.Contains(ts.eng.kiTaintedRoots[ts.kiFn], r) {
			ts.eng.kiTaintedRoots[ts.kiFn] = append(ts.eng.kiTaintedRoots[ts.kiFn], r)
		}
	}
	return true
}

func collectKIAnswersAuditRoots(sliceVal ssa.Value, kiScope vetssa.ScopeRange) []ssa.Value {
	var out []ssa.Value
	addOwned := func(v ssa.Value) {
		if v != nil && vetssa.IsValueOwnedInScope(v, kiScope.Start, kiScope.End) && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	wRoots, _ := vetssa.WriteTargetRoots(sliceVal, false)
	for _, r := range append(wRoots, vetssa.RootStorageValues(sliceVal, false)...) {
		if fv, isFV := r.(*ssa.FreeVar); isFV {
			for _, orig := range vetssa.TraceFreeVarOrigins(fv) {
				addOwned(orig)
			}
			continue
		}
		addOwned(r)
	}
	return out
}

func (e *taintEngine) auditDialKIFunc(kiFn *ssa.Function, roots []ssa.Value) {
	kiScope := vetssa.ScopeRangeOfFunc(kiFn)
	tainted := make(map[ssa.Value]vetssa.ScopeRange, len(roots))
	for _, r := range roots {
		tainted[r] = kiScope
	}
	_, callerParams := vetssa.SeedScopeParams(kiFn, nil, nil, kiScope)
	e.runScopeAudit(vetssa.AuditKey{}, kiFn, tainted, callerParams, kiScope, 0, nil, kiFn)
}

func hasKIChallengeSignature(sig *types.Signature) bool {
	if sig == nil || sig.Results() == nil || sig.Params() == nil || sig.Results().Len() != 2 || sig.Params().Len() != 4 {
		return false
	}
	return isSliceOfBasic(sig.Results().At(0).Type(), types.IsString) && vetutil.IsErrorInterfaceType(sig.Results().At(1).Type()) &&
		isBasicInfo(sig.Params().At(0).Type(), types.IsString) && isBasicInfo(sig.Params().At(1).Type(), types.IsString) &&
		isSliceOfBasic(sig.Params().At(2).Type(), types.IsString) && isSliceOfBasic(sig.Params().At(3).Type(), types.IsBoolean)
}

func isDialKeyboardInteractiveAnswersReturn(pkgInfo vetutil.PkgInfo, fn *ssa.Function, ret *ssa.Return) bool {
	return !pkgInfo.IsExternalTest && pkgInfo.BasePath == dialPkgPath && fn != nil && len(ret.Results) == 2 && hasKIChallengeSignature(fn.Signature)
}

func isVaultNarrowCredentialFieldStore(pkgInfo vetutil.PkgInfo, fa *ssa.FieldAddr) bool {
	if pkgInfo.IsExternalTest || pkgInfo.BasePath != vaultPkgPath || fa == nil {
		return false
	}
	named, ok := vetutil.UnwrapNamedType(fa.X.Type())
	return ok && named != nil && named.Obj() != nil && (named.Obj().Name() == "credentialW" || named.Obj().Name() == "CREDENTIALW")
}

func isAllowedNarrowConsumerCall(pkgInfo vetutil.PkgInfo, rc vetssa.ResolvedCall) bool {
	if pkgInfo.IsExternalTest || pkgInfo.BasePath != vaultPkgPath || rc.FuncObj == nil || rc.FuncObj.Name() != "Call" {
		return false
	}
	pkgPath := vetutil.ObjectPkgPath(rc.FuncObj)
	named, ok := secretfact.RecvNamedType(rc.FuncObj)
	return (pkgPath == "syscall" || pkgPath == "golang.org/x/sys/windows") &&
		ok && named.Obj() != nil && (named.Obj().Name() == "LazyProc" || named.Obj().Name() == "Proc")
}

func isBasicInfo(t types.Type, info types.BasicInfo) bool {
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && b.Info()&info != 0
}

func isSliceOfBasic(t types.Type, info types.BasicInfo) bool {
	sl, ok := types.Unalias(t).(*types.Slice)
	return ok && isBasicInfo(sl.Elem(), info)
}
