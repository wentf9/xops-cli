package archbound

import (
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

type controlledNetRule struct {
	argIdx   int
	networks []string
}

// isAllowedOSFSNetPkgSymbol 定义 core/osfs 唯一允许引用的 18 个 net 包级符号（fail-closed）。
func isAllowedOSFSNetPkgSymbol(name string) bool {
	return slices.Contains([]string{
		"ListenUnix", "ListenUnixgram", "ResolveUnixAddr",
		"FileListener", "FileConn", "FilePacketConn",
		"UnixAddr", "UnixConn", "UnixListener",
		"ListenConfig", "Dialer",
		"Listener", "Conn", "PacketConn", "Addr", "Error",
		"OpError", "ErrClosed",
	}, name)
}

func isAllowedOSFSNetType(name string) bool {
	return slices.Contains([]string{
		"UnixAddr", "UnixConn", "UnixListener", "ListenConfig", "Dialer",
		"Listener", "Conn", "PacketConn", "Addr", "Error", "OpError",
	}, name)
}

func isAllowedOSFSNetMethod(recvName, methodName string) bool {
	if recvName == "Dialer" {
		return methodName == "DialUnix"
	}
	if recvName == "ListenConfig" {
		return methodName == "Listen" || methodName == "ListenPacket"
	}
	return slices.Contains([]string{"UnixListener", "UnixConn", "UnixAddr", "OpError", "Listener", "Conn", "PacketConn", "Addr", "Error"}, recvName)
}

func isAllowedOSFSNetField(ownerName, fieldName string) bool {
	if ownerName == "Dialer" {
		return slices.Contains([]string{"Timeout", "Deadline", "LocalAddr", "Control", "ControlContext"}, fieldName)
	}
	return (ownerName == "ListenConfig" && fieldName == "Control") || ownerName == "UnixAddr" || ownerName == "OpError"
}

func controlledNetCallRule(obj types.Object) (controlledNetRule, bool) {
	fn, ok := obj.(*types.Func)
	if !ok || fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "net" {
		return controlledNetRule{}, false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return controlledNetRule{}, false
	}
	allUnix := []string{"unix", "unixpacket", "unixgram"}
	if sig.Recv() == nil {
		switch fn.Name() {
		case "ListenUnix":
			return controlledNetRule{argIdx: 0, networks: []string{"unix", "unixpacket"}}, true
		case "ListenUnixgram":
			return controlledNetRule{argIdx: 0, networks: []string{"unixgram"}}, true
		case "ResolveUnixAddr":
			return controlledNetRule{argIdx: 0, networks: allUnix}, true
		}
		return controlledNetRule{}, false
	}
	if recvName, ok := netNamedTypeName(sig.Recv().Type()); ok &&
		((recvName == "Dialer" && fn.Name() == "DialUnix") ||
			(recvName == "ListenConfig" && (fn.Name() == "Listen" || fn.Name() == "ListenPacket"))) {
		return controlledNetRule{argIdx: 1, networks: allUnix}, true
	}
	return controlledNetRule{}, false
}

// containsErasableRestrictedNet 封禁直接/容器/匿名结构体/导出或嵌入字段形式的 net.Dialer/ListenConfig 擦除，
// 同时放行仅以未导出具名字段持有的具名结构体（如 LocalFS）实现 ports.ScopedRootFS（修复 B-2）。
func containsErasableRestrictedNet(t types.Type) bool {
	return vetutil.ContainsExportedValueType(t, func(n *types.Named) bool {
		return vetutil.IsPkgSymbol(n.Obj(), "net", "Dialer", "ListenConfig")
	})
}

func isBannedNetNamedType(n *types.Named) bool {
	obj := n.Obj()
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "net" && !isAllowedOSFSNetType(obj.Name())
}

func isNetPkgScopeObject(obj types.Object) bool {
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == "net" && obj.Parent() == obj.Pkg().Scope()
}

func netTypeIdentity(t types.Type) (name string, exported, isNet bool) {
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

func unwrapStructType(t types.Type) *types.Struct { return vetutil.UnwrapStructType(t) }
