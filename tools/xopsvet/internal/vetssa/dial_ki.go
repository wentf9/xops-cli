package vetssa

import (
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

const (
	// DialPkgPath 是 core/internal/sshnet/dial 规范包路径（P4-T1 挑战闭包窄钩子唯一适用包）。
	DialPkgPath = vetutil.ModulePrefix + "/core/internal/sshnet/dial"

	sshCryptoPkgPath = "golang.org/x/crypto/ssh"
)

// IsDialProdOrWhitebox 判断当前包是否为 core/internal/sshnet/dial（排除外置 _test 包与子包）。
func IsDialProdOrWhitebox(pkgInfo vetutil.PkgInfo) bool {
	return !pkgInfo.IsExternalTest && pkgInfo.BasePath == DialPkgPath
}

// CollectDialKIClosures 在 core/internal/sshnet/dial 中收集唯一流向 ssh.KeyboardInteractive
// 且签名严格匹配四参两返（(string, string, []string, []bool) ([]string, error)）的局部挑战闭包集合，
// 供 secrettaint 与 linearlease 对称复用（P4-T1 受控窄模式）。
func CollectDialKIClosures(pkgInfo vetutil.PkgInfo, s *buildssa.SSA) map[*ssa.Function]bool {
	out := make(map[*ssa.Function]bool)
	if !IsDialProdOrWhitebox(pkgInfo) || s == nil {
		return out
	}
	ForEachFuncInst(AllFuncs(s), func(_ *ssa.Function, inst ssa.Instruction) {
		call, ok := inst.(ssa.CallInstruction)
		if !ok {
			return
		}
		rc := ResolveCall(s, call)
		if vetutil.IsPkgSymbol(rc.FuncObj, sshCryptoPkgPath, "KeyboardInteractive") && len(rc.UserArgs) >= 1 {
			if fn := extractExclusiveKIClosure(rc.UserArgs[0], call); fn != nil && HasKIChallengeSignature(fn.Signature) {
				out[fn] = true
			}
		}
	})
	return out
}

// extractExclusiveKIClosure 严格核验传入 ssh.KeyboardInteractive 的回调必须是内联局部匿名闭包
// （fn.Parent() != nil 且非 $bound 方法值包装器），且闭包函数与 MakeClosure/ChangeType 链路
// 均仅有唯一流向该调用的非调试引用；拒绝一切包级具名函数、同时直接调用或转存至外部变量的非独占闭包。
func extractExclusiveKIClosure(arg ssa.Value, kiCall ssa.CallInstruction) *ssa.Function {
	expectedRef := ssa.Instruction(kiCall)
	for {
		ct, ok := arg.(*ssa.ChangeType)
		if !ok {
			break
		}
		if !hasSingleNonDebugRef(ct, expectedRef) {
			return nil
		}
		arg, expectedRef = ct.X, ct
	}
	if mc, ok := arg.(*ssa.MakeClosure); ok {
		fn, isFn := mc.Fn.(*ssa.Function)
		if isFn && fn != nil && fn.Parent() != nil && !IsBoundWrapper(fn) &&
			hasSingleNonDebugRef(fn, mc) && hasSingleNonDebugRef(mc, expectedRef) {
			return fn
		}
		return nil
	}
	if fn, ok := arg.(*ssa.Function); ok && fn != nil && fn.Parent() != nil && !IsBoundWrapper(fn) && hasSingleNonDebugRef(fn, expectedRef) {
		return fn
	}
	return nil
}

func hasSingleNonDebugRef(v ssa.Value, expected ssa.Instruction) bool {
	if v == nil || v.Referrers() == nil {
		return false
	}
	count := 0
	for _, ref := range *v.Referrers() {
		if _, isDbg := ref.(*ssa.DebugRef); isDbg {
			continue
		}
		if ref != expected {
			return false
		}
		count++
	}
	return count == 1
}

// EnclosingKIFunc 沿词法嵌套父链查找包含 fn 的 P4-T1 挑战闭包（含 fn 自身）。
func EnclosingKIFunc(fn *ssa.Function, kiClosures map[*ssa.Function]bool) *ssa.Function {
	if len(kiClosures) == 0 {
		return nil
	}
	for cur := fn; cur != nil; cur = cur.Parent() {
		if kiClosures[cur] {
			return cur
		}
	}
	return nil
}

// HasKIChallengeSignature 严格校验无接收者、非可变参函数签名与 ssh.KeyboardInteractiveChallenge 完全一致：
// (string, string, []string, []bool) ([]string, error)。
func HasKIChallengeSignature(sig *types.Signature) bool {
	if sig == nil || sig.Recv() != nil || sig.Variadic() || sig.Results() == nil || sig.Params() == nil ||
		sig.Results().Len() != 2 || sig.Params().Len() != 4 {
		return false
	}
	return IsExactStringSlice(sig.Results().At(0).Type()) && vetutil.IsErrorInterfaceType(sig.Results().At(1).Type()) &&
		IsExactBasicString(sig.Params().At(0).Type()) && IsExactBasicString(sig.Params().At(1).Type()) &&
		IsExactStringSlice(sig.Params().At(2).Type()) && isExactBoolSlice(sig.Params().At(3).Type())
}

// IsDialKIAnswersReturn 判定返回指令是否位于 core/internal/sshnet/dial 的合法 P4-T1 挑战闭包内
// （供 secrettaint 与 linearlease 对称放行槽 0 返回局部 answers []string，同时严查槽 1 error）。
func IsDialKIAnswersReturn(pkgInfo vetutil.PkgInfo, fn *ssa.Function, ret *ssa.Return) bool {
	return IsDialProdOrWhitebox(pkgInfo) && fn != nil && ret != nil && len(ret.Results) == 2 && HasKIChallengeSignature(fn.Signature)
}

// IsPlainSecretParamType 判断参数类型底层是否为明文机密常见载体（[]byte / []uint8 / string），
// 委托 vetutil 单一事实源供 secrettaint 与 linearlease 共享。
func IsPlainSecretParamType(t types.Type) bool { return vetutil.IsPlainSecretParamType(t) }

// IsExactBasicString 判断类型是否为精确内置 string（解别名后非自定义命名类型，阻断自定义 error/Stringer 伪装）。
func IsExactBasicString(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := types.Unalias(t).(*types.Basic)
	return ok && b.Kind() == types.String
}

// IsExactStringSlice 判断类型是否为精确内置 []string 切片类型。
func IsExactStringSlice(t types.Type) bool {
	if t == nil {
		return false
	}
	sl, ok := types.Unalias(t).(*types.Slice)
	return ok && IsExactBasicString(sl.Elem())
}

func isExactBoolSlice(t types.Type) bool {
	if t == nil {
		return false
	}
	sl, ok := types.Unalias(t).(*types.Slice)
	if !ok {
		return false
	}
	b, ok := types.Unalias(sl.Elem()).(*types.Basic)
	return ok && b.Kind() == types.Bool
}

// IsDialKIAnswersStore 判定存储指令是否满足 P4-T1 挑战闭包窄模式全部 Fail-Closed 条件，
// 并直接返回供 kiFn 复审入种的完整 kiFn 直属根集合（保证准入判定与复审入种 100% 同源）：
//  1. 位于 core/internal/sshnet/dial（排除外置 _test）且处于唯一流向 ssh.KeyboardInteractive 的 kiFn 内；
//  2. 写入值为精确内置 string（不可变字符串拷贝，绝不放行 []byte 别名或借用指针/结构体）；
//  3. 写入目标为 *ssa.IndexAddr 指向精确 []string 切片，且全部写目标根与途经存储单元均直接归属 kiFn。
func IsDialKIAnswersStore(pkgInfo vetutil.PkgInfo, kiFn *ssa.Function, ins *ssa.Store) ([]ssa.Value, ScopeRange, bool) {
	if kiFn == nil || ins == nil || !IsDialProdOrWhitebox(pkgInfo) {
		return nil, ScopeRange{}, false
	}
	if ins.Val == nil || !IsExactBasicString(ins.Val.Type()) {
		return nil, ScopeRange{}, false
	}
	ia, ok := ins.Addr.(*ssa.IndexAddr)
	if !ok || !IsExactStringSlice(ia.X.Type()) {
		return nil, ScopeRange{}, false
	}
	kiScope := ScopeRangeOfFunc(kiFn)
	auditRoots, ok := CollectKIAnswersAuditRoots(ia.X, kiFn, kiScope)
	if !ok {
		return nil, ScopeRange{}, false
	}
	return auditRoots, kiScope, true
}

// CollectKIAnswersAuditRoots 以严格 traverseFields=true 收集切片写入目标根与全部途经存储单元，
// 强制要求每一个写目标根、途经存储单元及直接存储根均直接归属于 kiFn（Parent() == kiFn 且位置落入 kiScope）：
//   - 阻断内层嵌套闭包（WithSecret/PromptSecret/IIFE/混合 Phi）自建局部 []string 绕过；
//   - 阻断外层切片变量在 kiFn 内重赋 make 后再经局部变量别名（outer = make(...); answers := outer）绕过；
//   - 确保 kiFn 内结构体局部数组切片（holder.buf[:]）同步将 holder 与 answers 入种复审，杜绝经结构体字段外泄。
func CollectKIAnswersAuditRoots(sliceVal ssa.Value, kiFn *ssa.Function, kiScope ScopeRange) ([]ssa.Value, bool) {
	if sliceVal == nil || kiFn == nil || !kiScope.Valid() {
		return nil, false
	}
	roots, cells, ok := WriteTargetAndTraversedCells(sliceVal, true)
	if !ok || len(roots) == 0 {
		return nil, false
	}
	var auditRoots []ssa.Value
	if !collectDirectKIOwnedValues(roots, kiFn, kiScope, &auditRoots) ||
		!collectDirectKIOwnedValues(cells, kiFn, kiScope, &auditRoots) ||
		!collectDirectKIOwnedValues(RootStorageValues(sliceVal, true), kiFn, kiScope, &auditRoots) {
		return nil, false
	}
	return auditRoots, len(auditRoots) > 0
}

func collectDirectKIOwnedValues(vals []ssa.Value, kiFn *ssa.Function, kiScope ScopeRange, out *[]ssa.Value) bool {
	for _, v := range vals {
		if fv, isFV := v.(*ssa.FreeVar); isFV {
			origins := TraceFreeVarOrigins(fv)
			if len(origins) == 0 {
				return false
			}
			for _, orig := range origins {
				if !isDirectlyOwnedByFunc(orig, kiFn, kiScope) {
					return false
				}
				appendUniqueValue(out, orig)
			}
			continue
		}
		if !isDirectlyOwnedByFunc(v, kiFn, kiScope) {
			return false
		}
		appendUniqueValue(out, v)
	}
	return true
}

// isDirectlyOwnedByFunc 校验 SSA 分配节点直接隶属于 owner 函数（Parent() == owner）且源码位置落入 ownerScope。
func isDirectlyOwnedByFunc(v ssa.Value, owner *ssa.Function, ownerScope ScopeRange) bool {
	if v == nil || owner == nil || !ownerScope.Valid() {
		return false
	}
	switch r := v.(type) {
	case *ssa.Alloc:
		return r.Parent() == owner && r.Pos().IsValid() && r.Pos() >= ownerScope.Start && r.Pos() <= ownerScope.End
	case *ssa.MakeSlice:
		return r.Parent() == owner && r.Pos().IsValid() && r.Pos() >= ownerScope.Start && r.Pos() <= ownerScope.End
	default:
		return false
	}
}
