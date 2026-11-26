package secrettaint

import (
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

const portsPkgPath = vetutil.ModulePrefix + "/core/ports"

// 本文件实现 Phase 4 受控窄消费器模式钩子（B-4 / ST-7 / ST-10 / Phase2-Readiness）：
//   1. P4-T1（core/internal/sshnet/dial）：仅放行唯一流向 ssh.KeyboardInteractive 的挑战闭包内，
//      通过 box.Use 写入局部 answers []string 并在槽 0 返回（槽 1 error 禁染毒，闭包体全量复审）；
//   2. P4-T1（core/internal/sshnet/priv）：仅在 LayerCoreSSHNetPriv 内按严格正向白名单放行向已验证的 SSH
//      会话/通道写入器（(*ssh.Session).StdinPipe、(ports.RemoteSession).StdinPipe、(*ssh.Client).OpenChannel、
//      (ssh.Conn).OpenChannel、(ssh.NewChannel).Accept 及显式 ssh.Channel 形参）写入提权明文字节（拒绝通用
//      io.Writer/io.WriteCloser 形参、自定义接口 StdinPipe、io.Pipe/*io.PipeWriter、结构体字段、全局变量与一切未授权外部写入器）；
//   3. P4-T4（LayerHostVault，含 internal/host/vault/wincred 子包隔离）：Windows CREDENTIALW 本作用域局部结构体写入 + LazyProc.Call。

// checkDialKIAnswersStore 放行 P4-T1 挑战闭包内 box.Use 向局部 answers []string 写入并登记 kiFn 直属根集合复审。
func (ts *taintScope) checkDialKIAnswersStore(ins *ssa.Store) bool {
	kiRoots, _, ok := vetssa.IsDialKIAnswersStore(ts.eng.pkgInfo, ts.kiFn, ins)
	if !ok {
		return false
	}
	for _, r := range kiRoots {
		if !slices.Contains(ts.eng.kiTaintedRoots[ts.kiFn], r) {
			ts.eng.kiTaintedRoots[ts.kiFn] = append(ts.eng.kiTaintedRoots[ts.kiFn], r)
		}
	}
	return true
}

func (e *taintEngine) auditDialKIFunc(kiFn *ssa.Function, roots []ssa.Value) {
	kiScope := vetssa.ScopeRangeOfFunc(kiFn)
	tainted := make(map[ssa.Value]vetssa.ScopeRange, len(roots))
	for _, r := range roots {
		tainted[r] = kiScope
	}
	_, callerParams := vetssa.SeedScopeParams(kiFn, nil, nil, nil, kiScope)
	e.runScopeAudit(vetssa.AuditKey{}, kiFn, tainted, callerParams, kiScope, 0, nil, kiFn)
}

func (ts *taintScope) isAllowedNarrowConsumerCall(callInst ssa.CallInstruction, rc vetssa.ResolvedCall, inSc vetssa.ScopeRange) bool {
	if ts.isAllowedVaultNarrowCall(callInst, rc, inSc) {
		return true
	}
	return ts.isAllowedPrivEscalationWrite(rc)
}

// isAllowedPrivEscalationWrite 仅在 LayerCoreSSHNetPriv 生产/白盒包内按严格正向来源白名单放行向远端 SSH 会话/通道写入提权明文字节；
// 强制要求接收者未染毒、调用目标为 (ssh.Channel|io.Writer|io.WriteCloser).Write，且接收者全部溯源至合法 SSH 通道/StdinPipe。
func (ts *taintScope) isAllowedPrivEscalationWrite(rc vetssa.ResolvedCall) bool {
	if ts.eng.pkgInfo.IsExternalTest || ts.eng.pkgInfo.Layer != vetutil.LayerCoreSSHNetPriv {
		return false
	}
	if rc.FuncObj == nil || rc.Recv == nil || len(rc.UserArgs) != 1 || ts.isTainted(rc.Recv) {
		return false
	}
	if !isAllowedPrivWriteMethod(rc.FuncObj) {
		return false
	}
	return tracesOnlyToSafePrivWriter(ts.eng.ssaInfo, rc.Recv, map[ssa.Value]bool{}, map[*ssa.Function]bool{})
}

func isAllowedPrivWriteMethod(fn *types.Func) bool {
	if fn == nil || fn.Name() != "Write" {
		return false
	}
	named, ok := secretfact.RecvNamedType(fn)
	return ok && (vetutil.IsPkgSymbol(named.Obj(), sshCryptoPkgPath, "Channel") ||
		vetutil.IsPkgSymbol(named.Obj(), "io", "Writer", "WriteCloser"))
}

// tracesOnlyToSafePrivWriter 实施严格正向 Fail-Closed 溯源：仅放行 (*ssh.Session).StdinPipe、
// (ports.RemoteSession).StdinPipe、(*ssh.Client).OpenChannel、(ssh.Conn).OpenChannel、(ssh.NewChannel).Accept
// 槽 0 及静态类型为 ssh.Channel 的形参，沿同包辅助返回、Phi、FreeVar、Alloc/UnOp(MUL) 闭环传播，
// 拒绝通用 io.Writer/io.WriteCloser 形参、自定义接口 StdinPipe、io.Pipe 与一切结构体字段/全局/未授权构造器。
func tracesOnlyToSafePrivWriter(s *buildssa.SSA, v ssa.Value, visiting map[ssa.Value]bool, seenFn map[*ssa.Function]bool) bool {
	v = vetssa.UnwrapInterface(v)
	if v == nil || visiting[v] {
		return false
	}
	visiting[v] = true
	defer delete(visiting, v)
	switch val := v.(type) {
	case *ssa.Parameter:
		return isSSHChannelType(val.Type())
	case *ssa.Extract:
		return tracePrivWriterCall(s, val.Tuple, val.Index, visiting, seenFn)
	case *ssa.Call:
		return tracePrivWriterCall(s, val, 0, visiting, seenFn)
	case *ssa.Phi:
		return allNonNilEdgesMatch(val.Edges, func(e ssa.Value) bool { return tracesOnlyToSafePrivWriter(s, e, visiting, seenFn) })
	case *ssa.FreeVar:
		origins := vetssa.TraceFreeVarOrigins(val)
		return len(origins) > 0 && !slices.ContainsFunc(origins, func(o ssa.Value) bool { return !tracesOnlyToSafePrivWriter(s, o, visiting, seenFn) })
	case *ssa.Alloc:
		vals, ok := collectCellStoreValues(val, map[ssa.Value]bool{})
		return ok && !slices.ContainsFunc(vals, func(sv ssa.Value) bool { return !tracesOnlyToSafePrivWriter(s, sv, visiting, seenFn) })
	case *ssa.UnOp:
		return val.Op == token.MUL && tracesOnlyToSafePrivWriter(s, val.X, visiting, seenFn)
	default:
		return false
	}
}

func tracePrivWriterCall(s *buildssa.SSA, callVal ssa.Value, retSlot int, visiting map[ssa.Value]bool, seenFn map[*ssa.Function]bool) bool {
	call, ok := callVal.(*ssa.Call)
	if !ok {
		return false
	}
	rc := vetssa.ResolveCall(s, call)
	if retSlot == 0 && isAllowedSSHPrivWriterCtor(rc.FuncObj) {
		return true
	}
	if rc.TargetFn != nil && len(rc.TargetFn.Blocks) > 0 {
		return samePkgReturnsMatch(rc.TargetFn, retSlot, seenFn, func(rv ssa.Value) bool {
			return tracesOnlyToSafePrivWriter(s, rv, visiting, seenFn)
		})
	}
	return false
}

func isAllowedSSHPrivWriterCtor(fn *types.Func) bool {
	named, ok := secretfact.RecvNamedType(fn)
	if !ok || fn == nil {
		return false
	}
	switch fn.Name() {
	case "StdinPipe":
		return vetutil.IsPkgSymbol(named.Obj(), sshCryptoPkgPath, "Session") ||
			vetutil.IsPkgSymbol(named.Obj(), portsPkgPath, "RemoteSession")
	case "OpenChannel":
		return vetutil.IsPkgSymbol(named.Obj(), sshCryptoPkgPath, "Client", "Conn")
	case "Accept":
		return vetutil.IsPkgSymbol(named.Obj(), sshCryptoPkgPath, "NewChannel")
	default:
		return false
	}
}

func isSSHChannelType(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && vetutil.IsPkgSymbol(named.Obj(), sshCryptoPkgPath, "Channel")
}
