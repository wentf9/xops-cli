package archbound

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

type diagAdder func(pos, end token.Pos, msg string)

// checkOSFSNetSymbols 在 core/osfs 层实施四道 fail-closed 的标准库 net 符号防线（RFC v2.3.3 §2.3）。
func checkOSFSNetSymbols(pass *analysis.Pass) {
	if pass.TypesInfo == nil {
		return
	}
	var diags []vetutil.Diag
	addDiag := func(pos, end token.Pos, msg string) {
		if pos.IsValid() {
			diags = append(diags, vetutil.Diag{Pos: pos, End: end, Msg: msg})
		}
	}
	checkOSFSNetUses(pass.TypesInfo, collectDirectNetCalls(pass), addDiag)
	checkOSFSNetASTNodes(pass, addDiag)
	checkOSFSNetSelections(pass, addDiag)
	diags = append(diags, vetssa.CheckNoErasure(pass, vetssa.PackageSSA(pass), vetssa.ErasureConfig{
		MatchType:      containsErasableRestrictedNet,
		CheckInstances: true,
		Message:        "archbound: core/osfs 禁止将 net.Dialer/net.ListenConfig 经接口或泛型实参擦除",
	})...)
	vetutil.ReportSortedDedup(pass, diags, true)
}

func collectDirectNetCalls(pass *analysis.Pass) map[*ast.Ident]*ast.CallExpr {
	directCalls := make(map[*ast.Ident]*ast.CallExpr)
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return
		}
		switch fun := ast.Unparen(call.Fun).(type) {
		case *ast.Ident:
			directCalls[fun] = call
		case *ast.SelectorExpr:
			if sel := pass.TypesInfo.Selections[fun]; sel == nil || sel.Kind() == types.MethodVal {
				directCalls[fun.Sel] = call
			}
		}
	})
	return directCalls
}

func checkOSFSNetUses(info *types.Info, directCalls map[*ast.Ident]*ast.CallExpr, addDiag diagAdder) {
	for ident, obj := range info.Uses {
		if ident == nil || !ident.Pos().IsValid() || obj == nil {
			continue
		}
		if isNetPkgScopeObject(obj) && !isAllowedOSFSNetPkgSymbol(obj.Name()) {
			addDiag(ident.Pos(), ident.End(), "archbound: core/osfs 仅允许 18 项本地 AF_UNIX net 符号，禁止使用 net."+obj.Name())
			continue
		}
		if rule, ok := controlledNetCallRule(obj); ok {
			checkControlledNetCall(info, ident, obj.Name(), rule, directCalls, addDiag)
		}
	}
}

func checkControlledNetCall(info *types.Info, ident *ast.Ident, fnName string, rule controlledNetRule, directCalls map[*ast.Ident]*ast.CallExpr, addDiag diagAdder) {
	call, ok := directCalls[ident]
	if !ok {
		addDiag(ident.Pos(), ident.End(), "archbound: core/osfs 禁止将 net."+fnName+" 用作函数值、方法值或方法表达式，仅允许直接调用并传入 unix* 常量网络")
		return
	}
	if call.Ellipsis.IsValid() || len(call.Args) <= rule.argIdx {
		addDiag(call.Pos(), call.End(), "archbound: core/osfs 调用 net."+fnName+" 的 network 参数必须为对应编译期常量 unix/unixpacket/unixgram")
		return
	}
	if tv, ok := info.Types[call.Args[rule.argIdx]]; !ok || tv.Value == nil || tv.Value.Kind() != constant.String || !slices.Contains(rule.networks, constant.StringVal(tv.Value)) {
		addDiag(call.Pos(), call.End(), "archbound: core/osfs 调用 net."+fnName+" 的 network 参数必须为对应编译期常量 unix/unixpacket/unixgram")
	}
}

func checkOSFSNetASTNodes(pass *analysis.Pass, addDiag diagAdder) {
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.TypeSpec)(nil), (*ast.StructType)(nil), (*ast.CompositeLit)(nil)}, func(n ast.Node) {
		switch node := n.(type) {
		case *ast.TypeSpec:
			checkClonedNetStructTypeSpec(pass.TypesInfo, node, addDiag)
		case *ast.StructType:
			checkEmbeddedRestrictedNetStruct(pass.TypesInfo, node, addDiag)
		case *ast.CompositeLit:
			if name, ok := netNamedTypeName(pass.TypesInfo.TypeOf(node)); ok && (name == "Dialer" || name == "ListenConfig") {
				checkRestrictedNetCompositeLit(node, name, addDiag)
			}
		}
	})
}

func checkClonedNetStructTypeSpec(info *types.Info, ts *ast.TypeSpec, addDiag diagAdder) {
	if ts == nil || ts.Assign.IsValid() {
		return
	}
	obj := info.Defs[ts.Name]
	if obj == nil || obj.Type() == nil {
		return
	}
	st, ok := types.Unalias(obj.Type()).Underlying().(*types.Struct)
	if !ok {
		return
	}
	for i := range st.NumFields() {
		if f := st.Field(i); f.Pkg() != nil && f.Pkg().Path() == "net" {
			addDiag(ts.Pos(), ts.End(), "archbound: core/osfs 禁止通过定义类型同构克隆 net 包结构体 "+ts.Name.Name)
			return
		}
	}
}

func checkEmbeddedRestrictedNetStruct(info *types.Info, st *ast.StructType, addDiag diagAdder) {
	if st == nil || st.Fields == nil {
		return
	}
	for _, f := range st.Fields.List {
		if len(f.Names) == 0 {
			if name, ok := netNamedTypeName(info.TypeOf(f.Type)); ok && (name == "Dialer" || name == "ListenConfig") {
				addDiag(f.Type.Pos(), f.Type.End(), "archbound: core/osfs 禁止在命名或匿名结构体中嵌入 net."+name)
			}
		}
	}
}

func checkRestrictedNetCompositeLit(lit *ast.CompositeLit, typeName string, addDiag diagAdder) {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			addDiag(elt.Pos(), elt.End(), "archbound: core/osfs 禁止使用无键位置字面量初始化 net."+typeName)
			continue
		}
		if id, ok := ast.Unparen(kv.Key).(*ast.Ident); !ok || !isAllowedOSFSNetField(typeName, id.Name) {
			addDiag(kv.Key.Pos(), kv.Key.End(), "archbound: core/osfs 禁止在 net."+typeName+" 字面量中初始化受禁字段")
		}
	}
}

func checkOSFSNetSelections(pass *analysis.Pass, addDiag diagAdder) {
	for selExpr, sel := range pass.TypesInfo.Selections {
		if selExpr == nil || sel == nil || sel.Obj() == nil {
			continue
		}
		if checkOSFSNetSelectionMember(selExpr, sel, addDiag) && vetutil.TypeContainsLocalPred(sel.Type(), pass.Pkg, isBannedNetNamedType) {
			addDiag(selExpr.Sel.Pos(), selExpr.Sel.End(), "archbound: core/osfs 禁止引用包含受禁 net 类型的成员 "+sel.Obj().Name())
		}
	}
}

func checkOSFSNetSelectionMember(selExpr *ast.SelectorExpr, sel *types.Selection, addDiag diagAdder) bool {
	switch member := sel.Obj().(type) {
	case *types.Func:
		if member.Pkg() != nil && member.Pkg().Path() == "net" {
			return checkOSFSNetFuncSelection(selExpr, sel, member, addDiag)
		}
	case *types.Var:
		if member.IsField() && member.Pkg() != nil && member.Pkg().Path() == "net" {
			owner, _ := walkSelectionOwner(sel)
			if ownerName, ok := netNamedTypeName(owner); !ok || !isAllowedOSFSNetField(ownerName, member.Name()) {
				addDiag(selExpr.Sel.Pos(), selExpr.Sel.End(), "archbound: core/osfs 禁止访问受禁 net 结构体字段 "+member.Name())
				return false
			}
		}
	}
	return true
}

func checkOSFSNetFuncSelection(selExpr *ast.SelectorExpr, sel *types.Selection, fn *types.Func, addDiag diagAdder) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return true
	}
	recvName, ok := resolveExportedNetMethodOwner(sel, sig.Recv().Type())
	if !ok {
		if _, isIface := types.Unalias(sig.Recv().Type()).(*types.Interface); isIface {
			return true
		}
		addDiag(selExpr.Sel.Pos(), selExpr.Sel.End(), "archbound: core/osfs 禁止调用非白名单 net 接收者方法 "+fn.Name())
		return false
	}
	if !isAllowedOSFSNetMethod(recvName, fn.Name()) {
		addDiag(selExpr.Sel.Pos(), selExpr.Sel.End(), "archbound: core/osfs 禁止调用 net."+recvName+"."+fn.Name())
		return false
	}
	return true
}

func resolveExportedNetMethodOwner(sel *types.Selection, recvType types.Type) (string, bool) {
	name, exported, isNet := netTypeIdentity(recvType)
	if !isNet {
		return "", false
	}
	if exported {
		return name, true
	}
	_, lastExported := walkSelectionOwner(sel)
	return lastExported, lastExported != ""
}

// walkSelectionOwner 沿 Selection.Index() 追溯直接字段归属类型与最近一层导出 net 嵌入宿主类型。
func walkSelectionOwner(sel *types.Selection) (direct types.Type, lastExported string) {
	if sel == nil {
		return nil, ""
	}
	cur := sel.Recv()
	if name, exported, isNet := netTypeIdentity(cur); isNet && exported {
		lastExported = name
	}
	idxPath := sel.Index()
	for i := range len(idxPath) - 1 {
		st := unwrapStructType(cur)
		if st == nil || idxPath[i] < 0 || idxPath[i] >= st.NumFields() {
			return nil, lastExported
		}
		cur = st.Field(idxPath[i]).Type()
		if name, exported, isNet := netTypeIdentity(cur); isNet && exported {
			lastExported = name
		}
	}
	return cur, lastExported
}
