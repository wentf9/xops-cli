package archbound

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

type diagAdder func(pos, end token.Pos, msg string)

// checkOSFSNetSymbols 在 core/osfs 层实施三道 fail-closed 的标准库 net 符号防线，
// 仅放行本地 AF_UNIX SocketSlot 与探活所需的最小能力面，物理封堵 TCP/UDP/IP/DNS 网络逃逸：
//  1. 防线 1：对 net 包级作用域符号实施 22 项严格白名单；
//  2. 防线 2：对 7 个受控通用 network 符号实施直接调用绑定（封死函数值/方法值/MethodExpr/点导入绕过）
//     并按符号精确映射 network 参数位，要求实参为编译期常量 unix/unixpacket/unixgram；
//  3. 防线 3：按成员直接归属类型校验方法接收者与结构体字段（穿透嵌入包装结构体），
//     并校验省略类型复合字面量（如 []net.Dialer{{...}}）与成员类型中不得包含受禁 net 类型。
func checkOSFSNetSymbols(pass *analysis.Pass) {
	if pass.TypesInfo == nil {
		return
	}
	var diags []symDiag
	addDiag := func(pos, end token.Pos, msg string) {
		if pos.IsValid() {
			diags = append(diags, symDiag{pos: pos, end: end, msg: msg})
		}
	}
	directCalls := collectDirectNetCalls(pass)
	checkOSFSNetUses(pass.TypesInfo, directCalls, addDiag)
	checkOSFSNetSelections(pass, addDiag)
	checkOSFSNetCompositeLits(pass, addDiag)
	reportDedupedLineDiags(pass, diags)
}

// collectDirectNetCalls 收集所有作为 CallExpr.Fun 直接调用的目标标识符。
// 对 SelectorExpr 仅在 Selections == nil（包级函数）或 MethodVal（绑定接收者方法调用）时记录 sel.Sel，
// 物理排除 MethodExpr（如 (*net.Dialer).Dial）导致的参数位偏移绕过。
func collectDirectNetCalls(pass *analysis.Pass) map[*ast.Ident]*ast.CallExpr {
	directCalls := make(map[*ast.Ident]*ast.CallExpr)
	ins := vetutil.InspectorOf(pass)
	ins.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
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
			addDiag(ident.Pos(), ident.End(), "archbound: core/osfs 仅允许本地 AF_UNIX 相关 net 符号，禁止使用 net."+obj.Name())
			continue
		}
		if argIdx, controlled := controlledNetArgIndex(obj); controlled {
			checkControlledNetCall(info, ident, obj.Name(), argIdx, directCalls, addDiag)
		}
	}
}

func checkControlledNetCall(
	info *types.Info,
	ident *ast.Ident,
	fnName string,
	argIdx int,
	directCalls map[*ast.Ident]*ast.CallExpr,
	addDiag diagAdder,
) {
	call, ok := directCalls[ident]
	if !ok {
		addDiag(ident.Pos(), ident.End(),
			"archbound: core/osfs 禁止将 net."+fnName+" 用作函数值、方法值或方法表达式，仅允许直接调用并传入 unix* 常量网络")
		return
	}
	if !isUnixNetworkConstArg(info, call, argIdx) {
		addDiag(call.Pos(), call.End(),
			"archbound: core/osfs 调用 net."+fnName+" 的 network 参数必须为编译期常量 unix/unixpacket/unixgram")
	}
}

func isUnixNetworkConstArg(info *types.Info, call *ast.CallExpr, argIdx int) bool {
	if call == nil || call.Ellipsis.IsValid() || len(call.Args) <= argIdx {
		return false
	}
	tv, ok := info.Types[call.Args[argIdx]]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	netw := constant.StringVal(tv.Value)
	return netw == "unix" || netw == "unixpacket" || netw == "unixgram"
}

func checkOSFSNetSelections(pass *analysis.Pass, addDiag diagAdder) {
	for selExpr, sel := range pass.TypesInfo.Selections {
		if selExpr == nil || sel == nil || sel.Obj() == nil {
			continue
		}
		if !checkOSFSNetSelectionMember(selExpr, sel, addDiag) {
			continue
		}
		if typeContainsBannedOSFSNetType(pass.Pkg, sel.Obj().Type(), make(map[types.Type]bool)) {
			addDiag(selExpr.Sel.Pos(), selExpr.Sel.End(),
				"archbound: core/osfs 禁止引用包含受禁 net 类型的成员 "+sel.Obj().Name())
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
			return checkOSFSNetFieldSelection(selExpr, sel, member, addDiag)
		}
	}
	return true
}

func checkOSFSNetFuncSelection(selExpr *ast.SelectorExpr, sel *types.Selection, fn *types.Func, addDiag diagAdder) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return true
	}
	recvType := sig.Recv().Type()
	recvName, ok := resolveExportedNetMethodOwner(sel, recvType)
	if !ok {
		if _, isIface := types.Unalias(recvType).(*types.Interface); isIface {
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

// resolveExportedNetMethodOwner 解析 net 方法的导出接收者类型名：
// 当方法直接定义在导出 net 类型上（如 *net.Dialer、*net.UnixListener）时直接返回该类型名；
// 当方法继承自标准库未导出嵌入结构体（如 *net.UnixConn / *net.TCPConn 共同嵌入的 net.conn）时，
// 沿 sel.Index() 定位进入未导出结构体前的最后一个导出 net 类型，放行 UnixConn.Close/Read/Write
// 同时继续拦截 TCPConn/UDPConn/IPConn 上的同名方法。
func resolveExportedNetMethodOwner(sel *types.Selection, recvType types.Type) (string, bool) {
	if name, exported, isNet := netTypeIdentity(recvType); isNet {
		if exported {
			return name, true
		}
		return resolveLastExportedNetOwner(sel)
	}
	return "", false
}

func resolveLastExportedNetOwner(sel *types.Selection) (string, bool) {
	if sel == nil {
		return "", false
	}
	cur := sel.Recv()
	var lastExported string
	if name, exported, isNet := netTypeIdentity(cur); isNet && exported {
		lastExported = name
	}
	idxPath := sel.Index()
	for i := 0; i < len(idxPath)-1; i++ {
		st := unwrapStructType(cur)
		if st == nil || idxPath[i] < 0 || idxPath[i] >= st.NumFields() {
			break
		}
		cur = st.Field(idxPath[i]).Type()
		if name, exported, isNet := netTypeIdentity(cur); isNet && exported {
			lastExported = name
		}
	}
	return lastExported, lastExported != ""
}

func checkOSFSNetFieldSelection(selExpr *ast.SelectorExpr, sel *types.Selection, field *types.Var, addDiag diagAdder) bool {
	ownerName, ok := netNamedTypeName(resolveDirectFieldOwnerType(sel))
	if !ok || !isAllowedOSFSNetField(ownerName, field.Name()) {
		addDiag(selExpr.Sel.Pos(), selExpr.Sel.End(), "archbound: core/osfs 禁止访问受禁 net 结构体字段 "+field.Name())
		return false
	}
	return true
}

// resolveDirectFieldOwnerType 沿 sel.Index() 逐层步进至字段的直接宿主结构体类型，
// 防止通过嵌入结构体（如 type wrapDialer struct { net.Dialer }）绕过 net.Dialer/ListenConfig 字段白名单。
func resolveDirectFieldOwnerType(sel *types.Selection) types.Type {
	if sel == nil {
		return nil
	}
	cur := sel.Recv()
	idxPath := sel.Index()
	for i := 0; i < len(idxPath)-1; i++ {
		st := unwrapStructType(cur)
		if st == nil || idxPath[i] < 0 || idxPath[i] >= st.NumFields() {
			return nil
		}
		cur = st.Field(idxPath[i]).Type()
	}
	return cur
}

func unwrapStructType(t types.Type) *types.Struct {
	if t == nil {
		return nil
	}
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	st, _ := t.Underlying().(*types.Struct)
	return st
}

// checkOSFSNetCompositeLits 基于 TypesInfo.TypeOf(lit) 校验 net.Dialer 与 net.ListenConfig 复合字面量，
// 同时覆盖显式类型字面量与省略类型元素字面量（如 []net.Dialer{{DualStack: true}}）。
func checkOSFSNetCompositeLits(pass *analysis.Pass, addDiag diagAdder) {
	ins := vetutil.InspectorOf(pass)
	ins.Preorder([]ast.Node{(*ast.CompositeLit)(nil)}, func(n ast.Node) {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return
		}
		typeName, ok := netNamedTypeName(pass.TypesInfo.TypeOf(lit))
		if ok && (typeName == "Dialer" || typeName == "ListenConfig") {
			checkRestrictedNetCompositeLit(lit, typeName, addDiag)
		}
	})
}

func checkRestrictedNetCompositeLit(lit *ast.CompositeLit, typeName string, addDiag diagAdder) {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			addDiag(elt.Pos(), elt.End(), "archbound: core/osfs 禁止使用无键位置字面量初始化 net."+typeName)
			continue
		}
		id, ok := ast.Unparen(kv.Key).(*ast.Ident)
		if !ok || !isAllowedOSFSNetField(typeName, id.Name) {
			addDiag(kv.Key.Pos(), kv.Key.End(), "archbound: core/osfs 禁止在 net."+typeName+" 字面量中初始化受禁字段")
		}
	}
}

func isNetPkgScopeObject(obj types.Object) bool {
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "net" && obj.Parent() == obj.Pkg().Scope()
}

// isAllowedOSFSNetPkgSymbol 定义 core/osfs 允许引用的 22 个 net 包级符号（fail-closed）：
// 4 个 Unix 专用函数、3 个 fd 适配器、3 个受防线 2 管控的通用函数、
// 3 个 Unix 具名类型、2 个受防线 2/3 管控的配置/拨号器、5 个核心接口与 2 个错误符号。
func isAllowedOSFSNetPkgSymbol(name string) bool {
	switch name {
	case "ListenUnix", "ListenUnixgram", "DialUnix", "ResolveUnixAddr",
		"FileListener", "FileConn", "FilePacketConn",
		"Listen", "ListenPacket", "DialTimeout",
		"UnixAddr", "UnixConn", "UnixListener",
		"ListenConfig", "Dialer",
		"Listener", "Conn", "PacketConn", "Addr", "Error",
		"OpError", "ErrClosed":
		return true
	default:
		return false
	}
}

func isAllowedOSFSNetType(name string) bool {
	switch name {
	case "UnixAddr", "UnixConn", "UnixListener",
		"ListenConfig", "Dialer",
		"Listener", "Conn", "PacketConn", "Addr", "Error",
		"OpError":
		return true
	default:
		return false
	}
}

// isAllowedOSFSNetMethod 定义防线 3 允许的 net 方法接收者白名单：
// Dialer 与 ListenConfig 仅开放最小本地 AF_UNIX 方法子集，其余已放行的本地套接字/错误与接口接收者全量放行。
func isAllowedOSFSNetMethod(recvName, methodName string) bool {
	switch recvName {
	case "Dialer":
		return methodName == "DialUnix" || methodName == "DialContext" || methodName == "Dial"
	case "ListenConfig":
		return methodName == "Listen" || methodName == "ListenPacket"
	case "UnixListener", "UnixConn", "UnixAddr", "OpError",
		"Listener", "Conn", "PacketConn", "Addr", "Error":
		return true
	default:
		return false
	}
}

func isAllowedOSFSNetField(ownerName, fieldName string) bool {
	switch ownerName {
	case "Dialer":
		return fieldName == "Timeout" || fieldName == "Deadline" ||
			fieldName == "LocalAddr" || fieldName == "Control" || fieldName == "ControlContext"
	case "ListenConfig":
		return fieldName == "Control"
	case "UnixAddr", "OpError":
		return true
	default:
		return false
	}
}

// controlledNetArgIndex 返回 7 个受控通用 network 符号的 network 形参位置索引：
// net.Listen/ListenPacket/DialTimeout 与 (*net.Dialer).Dial 为 0；
// (*net.ListenConfig).Listen/ListenPacket 与 (*net.Dialer).DialContext 为 1。
func controlledNetArgIndex(obj types.Object) (int, bool) {
	fn, ok := obj.(*types.Func)
	if !ok || fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "net" {
		return 0, false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return 0, false
	}
	if sig.Recv() == nil {
		switch fn.Name() {
		case "Listen", "ListenPacket", "DialTimeout":
			return 0, true
		}
		return 0, false
	}
	recvName, ok := netNamedTypeName(sig.Recv().Type())
	if !ok {
		return 0, false
	}
	return controlledMethodNetArgIndex(recvName, fn.Name())
}

func controlledMethodNetArgIndex(recvName, name string) (int, bool) {
	switch recvName {
	case "Dialer":
		if name == "Dial" {
			return 0, true
		}
		if name == "DialContext" {
			return 1, true
		}
	case "ListenConfig":
		if name == "Listen" || name == "ListenPacket" {
			return 1, true
		}
	}
	return 0, false
}

func netTypeIdentity(t types.Type) (name string, exported bool, isNet bool) {
	named, ok := vetutil.UnwrapNamedType(t)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != "net" {
		return "", false, false
	}
	return named.Obj().Name(), named.Obj().Exported(), true
}

func netNamedTypeName(t types.Type) (string, bool) {
	name, _, isNet := netTypeIdentity(t)
	return name, isNet
}

// typeContainsBannedOSFSNetType 检查类型树中是否出现不在白名单内的 net 命名类型
// （如 *net.Resolver、net.KeepAliveConfig、*net.TCPConn、*net.UDPConn、*net.IPConn）。
// 遇到已放行的 net 命名类型（如 net.Dialer）立即停止下钻，避免对其内部受控字段产生误报。
func typeContainsBannedOSFSNetType(localPkg *types.Package, t types.Type, seen map[types.Type]bool) bool {
	if t == nil {
		return false
	}
	t = types.Unalias(t)
	if named, ok := t.(*types.Named); ok {
		return namedContainsBannedOSFSNetType(localPkg, named, seen)
	}
	return compositeContainsBannedOSFSNetType(localPkg, t, seen)
}

func namedContainsBannedOSFSNetType(localPkg *types.Package, named *types.Named, seen map[types.Type]bool) bool {
	if obj := named.Obj(); obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "net" {
		return !isAllowedOSFSNetType(obj.Name())
	}
	if seen[named] {
		return false
	}
	seen[named] = true
	if typeArgs := named.TypeArgs(); typeArgs != nil {
		for i := 0; i < typeArgs.Len(); i++ {
			if typeContainsBannedOSFSNetType(localPkg, typeArgs.At(i), seen) {
				return true
			}
		}
	}
	if named.Obj() != nil && named.Obj().Pkg() != localPkg {
		return false
	}
	return typeContainsBannedOSFSNetType(localPkg, named.Underlying(), seen)
}

func compositeContainsBannedOSFSNetType(localPkg *types.Package, t types.Type, seen map[types.Type]bool) bool {
	switch v := t.(type) {
	case *types.Pointer:
		return typeContainsBannedOSFSNetType(localPkg, v.Elem(), seen)
	case *types.Slice:
		return typeContainsBannedOSFSNetType(localPkg, v.Elem(), seen)
	case *types.Array:
		return typeContainsBannedOSFSNetType(localPkg, v.Elem(), seen)
	case *types.Chan:
		return typeContainsBannedOSFSNetType(localPkg, v.Elem(), seen)
	case *types.Map:
		return typeContainsBannedOSFSNetType(localPkg, v.Key(), seen) ||
			typeContainsBannedOSFSNetType(localPkg, v.Elem(), seen)
	case *types.Signature:
		return tupleContainsBannedOSFSNetType(localPkg, v.Params(), seen) ||
			tupleContainsBannedOSFSNetType(localPkg, v.Results(), seen)
	case *types.Struct:
		return structContainsBannedOSFSNetType(localPkg, v, seen)
	default:
		return false
	}
}

func tupleContainsBannedOSFSNetType(localPkg *types.Package, tup *types.Tuple, seen map[types.Type]bool) bool {
	if tup == nil {
		return false
	}
	for i := 0; i < tup.Len(); i++ {
		if typeContainsBannedOSFSNetType(localPkg, tup.At(i).Type(), seen) {
			return true
		}
	}
	return false
}

func structContainsBannedOSFSNetType(localPkg *types.Package, st *types.Struct, seen map[types.Type]bool) bool {
	if seen[st] {
		return false
	}
	seen[st] = true
	for i := 0; i < st.NumFields(); i++ {
		if typeContainsBannedOSFSNetType(localPkg, st.Field(i).Type(), seen) {
			return true
		}
	}
	return false
}
