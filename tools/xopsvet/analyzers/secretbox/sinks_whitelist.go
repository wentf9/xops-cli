package secretbox

import (
	"go/ast"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

const (
	whitelistViolationMsg = "secretbox: 禁止在白名单（core/domain/secret、internal/host/vault、core/internal/sshnet/dial、core/internal/sshnet/priv、core/internal/sim）外调用或引用 SecretBox.Use / //xops:secretuse"
	restrictedStoreMsg    = "secretbox: 禁止将 secret.SecretBox 存入 Event/Audit/Plan/Error/序列化结构体字段"
)

// checkSSASinksAndRestrictedStores 在全包 SSA 上追踪 SecretBox 值流，拦截高危汇点与受限容器写入，
// 并返回已由精确汇点诊断接管的单引用 MakeInterface 集合以消除同行重复噪声。
func checkSSASinksAndRestrictedStores(pass *analysis.Pass, s *buildssa.SSA, pkgInfo vetutil.PkgInfo, restricted map[*types.TypeName]bool) map[*ssa.MakeInterface]bool {
	handledMI := make(map[*ssa.MakeInterface]bool)
	if s == nil {
		return handledMI
	}
	funcs := vetssa.AllFuncs(s)
	tainted := collectSSABoxValues(s, funcs)
	var diags []vetutil.Diag
	vetssa.ForEachFuncInst(funcs, func(fn *ssa.Function, inst ssa.Instruction) {
		switch ins := inst.(type) {
		case ssa.CallInstruction:
			checkBoxCallSink(pass, s, pkgInfo, fn, ins, tainted, handledMI, &diags)
		case *ssa.Store:
			if tainted[ins.Val] && addrTargetsRestrictedType(ins.Addr, restricted) {
				vetssa.AppendDiag(pass, &diags, fn, ins, restrictedStoreMsg)
				markSingleRefMIHandled(ins.Val, ins, handledMI)
			}
		case *ssa.MapUpdate:
			if (tainted[ins.Key] || tainted[ins.Value]) && isRestrictedNamedType(ins.Map.Type(), restricted) {
				vetssa.AppendDiag(pass, &diags, fn, ins, restrictedStoreMsg)
				markSingleRefMIHandled(ins.Key, ins, handledMI)
				markSingleRefMIHandled(ins.Value, ins, handledMI)
			}
		}
	})
	vetutil.ReportSortedDedup(pass, diags, false)
	return handledMI
}

func collectSSABoxValues(s *buildssa.SSA, funcs []*ssa.Function) map[ssa.Value]bool {
	tainted := make(map[ssa.Value]bool)
	vetssa.SeedTypedValues(funcs, isSecretBoxValueType, func(v ssa.Value) bool { tainted[v] = true; return true })
	for {
		changed := false
		vetssa.ForEachFuncInst(funcs, func(_ *ssa.Function, inst ssa.Instruction) {
			if propagateBoxInst(s, inst, tainted) {
				changed = true
			}
		})
		if !changed {
			return tainted
		}
	}
}

func propagateBoxInst(s *buildssa.SSA, inst ssa.Instruction, tainted map[ssa.Value]bool) bool {
	if op, ok := vetssa.UnaryFlowOperand(inst, false); ok {
		val, isVal := inst.(ssa.Value)
		if isVal && tainted[op] && !tainted[val] {
			tainted[val] = true
			return true
		}
		return false
	}
	switch ins := inst.(type) {
	case *ssa.Phi:
		if !tainted[ins] && slices.ContainsFunc(ins.Edges, func(e ssa.Value) bool { return tainted[e] }) {
			tainted[ins] = true
			return true
		}
	case *ssa.Store:
		return tainted[ins.Val] && markBoxRoots(ins.Addr, tainted)
	case *ssa.MapUpdate:
		return (tainted[ins.Key] || tainted[ins.Value]) && markBoxRoots(ins.Map, tainted)
	case *ssa.MakeClosure:
		return vetssa.PropagateClosureFreeVars(ins, tainted)
	case *ssa.Call:
		return propagateBoxIIFE(s, ins, tainted)
	}
	return false
}

func markBoxRoots(addr ssa.Value, tainted map[ssa.Value]bool) bool {
	changed := false
	for _, root := range vetssa.RootStorageValues(addr, true) {
		if !tainted[root] {
			tainted[root], changed = true, true
		}
	}
	return changed
}

func propagateBoxIIFE(s *buildssa.SSA, call *ssa.Call, tainted map[ssa.Value]bool) bool {
	rc := vetssa.ResolveCall(s, call)
	if rc.Closure == nil || rc.TargetFn == nil {
		return false
	}
	changed := false
	for i, arg := range rc.UserArgs {
		if i < len(rc.TargetFn.Params) && tainted[arg] && !tainted[rc.TargetFn.Params[i]] {
			tainted[rc.TargetFn.Params[i]], changed = true, true
		}
	}
	if !tainted[call] && funcReturnsBoxValue(rc.TargetFn, tainted) {
		tainted[call], changed = true, true
	}
	return changed
}

func funcReturnsBoxValue(fn *ssa.Function, tainted map[ssa.Value]bool) bool {
	found := false
	vetssa.ForEachInst(fn, func(inst ssa.Instruction) {
		if ret, ok := inst.(*ssa.Return); ok && slices.ContainsFunc(ret.Results, func(r ssa.Value) bool { return tainted[r] }) {
			found = true
		}
	})
	return found
}

func checkBoxCallSink(pass *analysis.Pass, s *buildssa.SSA, pkgInfo vetutil.PkgInfo, fn *ssa.Function, callInst ssa.CallInstruction, tainted map[ssa.Value]bool, handledMI map[*ssa.MakeInterface]bool, diags *[]vetutil.Diag) {
	rc := vetssa.ResolveCall(s, callInst)
	kind := secretfact.ClassifyCommonSink(rc.FuncObj)
	if vetutil.IsPkgSymbol(rc.FuncObj, "fmt", "Sprint", "Sprintf", "Sprintln") {
		kind = secretfact.SinkError
	}
	if kind == secretfact.SinkNone {
		return
	}
	for _, arg := range rc.UserArgs {
		if !tainted[arg] || isAllowedJSONv2SecretTestCall(pass, pkgInfo, fn, callInst, rc, arg) {
			continue
		}
		vetssa.AppendDiag(pass, diags, fn, callInst, "secretbox: 禁止将 secret.SecretBox 传入"+kind.Label()+"汇点")
		markSingleRefMIHandled(arg, callInst, handledMI)
		for _, elem := range vetssa.ExtractVarargsElements(arg) {
			if mi, ok := elem.(*ssa.MakeInterface); ok {
				handledMI[mi] = true
			}
		}
		return
	}
}

func addrTargetsRestrictedType(addr ssa.Value, restricted map[*types.TypeName]bool) bool {
	if isRestrictedNamedType(addr.Type(), restricted) {
		return true
	}
	return slices.ContainsFunc(vetssa.RootStorageValues(addr, true), func(root ssa.Value) bool {
		return isRestrictedNamedType(root.Type(), restricted) || rootRefersRestrictedType(root, restricted)
	})
}

func rootRefersRestrictedType(root ssa.Value, restricted map[*types.TypeName]bool) bool {
	if root.Referrers() == nil {
		return false
	}
	for _, ref := range *root.Referrers() {
		switch r := ref.(type) {
		case *ssa.Slice:
			if isRestrictedNamedType(r.Type(), restricted) {
				return true
			}
		case *ssa.ChangeType:
			if isRestrictedNamedType(r.Type(), restricted) {
				return true
			}
		}
	}
	return false
}

func markSingleRefMIHandled(v ssa.Value, owner ssa.Instruction, handledMI map[*ssa.MakeInterface]bool) {
	if mi, ok := v.(*ssa.MakeInterface); ok && mi.Referrers() != nil && len(*mi.Referrers()) == 1 && (*mi.Referrers())[0] == owner {
		handledMI[mi] = true
	}
}

// checkSecretUseWhitelist 强制规则 3：仅 5 个明文消费白名单包（不含外置 _test）可调用或引用 SecretBox.Use / //xops:secretuse。
func checkSecretUseWhitelist(pass *analysis.Pass, s *buildssa.SSA, pkgInfo vetutil.PkgInfo, facts *secretfact.Result) {
	if vetutil.AllowSecretPlaintext(pkgInfo) || facts == nil {
		return
	}
	var diags []vetutil.Diag
	selIdents := make(map[*ast.Ident]bool)
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.CallExpr)(nil), (*ast.SelectorExpr)(nil), (*ast.Ident)(nil)}, func(n ast.Node) {
		checkWhitelistNode(pass, facts, n, selIdents, &diags)
	})
	if s != nil {
		vetssa.ForEachFuncInst(vetssa.AllFuncs(s), func(fn *ssa.Function, inst ssa.Instruction) {
			if callInst, ok := inst.(ssa.CallInstruction); ok {
				rc := vetssa.ResolveCall(s, callInst)
				if rc.FuncObj != nil && (facts.IsSecretUseObject(rc.FuncObj) || facts.HasSecretUseCallbackParam(rc.FuncObj)) {
					vetssa.AppendDiag(pass, &diags, fn, callInst, whitelistViolationMsg)
				}
			}
		})
	}
	vetutil.ReportSortedDedup(pass, diags, true)
}

func checkWhitelistNode(pass *analysis.Pass, facts *secretfact.Result, n ast.Node, selIdents map[*ast.Ident]bool, diags *[]vetutil.Diag) {
	switch node := n.(type) {
	case *ast.CallExpr:
		obj := vetutil.ResolveCalledObject(pass.TypesInfo, node)
		if isWhitelistRestrictedObj(facts, obj) {
			*diags = append(*diags, vetutil.Diag{Pos: node.Fun.Pos(), End: node.Fun.End(), Msg: whitelistViolationMsg})
		}
	case *ast.SelectorExpr:
		selIdents[node.Sel] = true
		obj := pass.TypesInfo.Uses[node.Sel]
		if sel := pass.TypesInfo.Selections[node]; sel != nil {
			obj = sel.Obj()
		}
		if isWhitelistRestrictedObj(facts, obj) {
			*diags = append(*diags, vetutil.Diag{Pos: node.Pos(), End: node.End(), Msg: whitelistViolationMsg})
		}
	case *ast.Ident:
		if !selIdents[node] && isWhitelistRestrictedObj(facts, pass.TypesInfo.Uses[node]) {
			*diags = append(*diags, vetutil.Diag{Pos: node.Pos(), End: node.End(), Msg: whitelistViolationMsg})
		}
	}
}

func isWhitelistRestrictedObj(facts *secretfact.Result, obj types.Object) bool {
	return facts.IsSecretUseObject(obj) || facts.HasSecretUseCallbackParam(obj)
}
