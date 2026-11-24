package osboundary

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
)

// checkOSSymbols 检查物理封锁于 core/osfs 与 internal/host/sys 的底层系统原语，
// 覆盖直接符号引用、os.Root 方法选择及 Unix Domain Socket 常量网络监听调用。
func checkOSSymbols(pass *analysis.Pass, pkgInfo vetutil.PkgInfo) {
	if pass.TypesInfo == nil {
		return
	}
	allowOSFS := vetutil.AllowOSFSPrimitives(pkgInfo)
	allowSys := vetutil.AllowSysExecEnv(pkgInfo)
	if allowOSFS && allowSys {
		return
	}
	reported := make(map[token.Pos]bool)
	ins := vetutil.InspectorOf(pass)
	nodeFilter := []ast.Node{
		(*ast.SelectorExpr)(nil),
		(*ast.Ident)(nil),
		(*ast.CallExpr)(nil),
	}
	ins.Preorder(nodeFilter, func(n ast.Node) {
		checkOSSymbolNode(pass, n, allowOSFS, allowSys, reported)
	})
}

func checkOSSymbolNode(pass *analysis.Pass, n ast.Node, allowOSFS, allowSys bool, reported map[token.Pos]bool) {
	switch node := n.(type) {
	case *ast.SelectorExpr:
		checkSelectorSymbol(pass, node, allowOSFS, allowSys, reported)
	case *ast.Ident:
		if obj := pass.TypesInfo.Uses[node]; obj != nil {
			reportBannedObject(pass, node, obj, allowOSFS, allowSys, reported)
		}
	case *ast.CallExpr:
		if !allowOSFS && isUnixNetListenCall(pass.TypesInfo, node) {
			reportPos(pass, node, reported, "osboundary: 白名单包 core/osfs 之外禁止直接创建 Unix Domain Socket 监听")
		}
	}
}

func checkSelectorSymbol(pass *analysis.Pass, sel *ast.SelectorExpr, allowOSFS, allowSys bool, reported map[token.Pos]bool) {
	if s, ok := pass.TypesInfo.Selections[sel]; ok && s != nil {
		if !allowOSFS && isOSRootType(s.Recv()) {
			reportPos(pass, sel.Sel, reported, "osboundary: 白名单包 core/osfs 之外禁止调用 os.Root 方法")
		}
		return
	}
	if obj := pass.TypesInfo.Uses[sel.Sel]; obj != nil {
		reportBannedObject(pass, sel.Sel, obj, allowOSFS, allowSys, reported)
	}
}

func reportBannedObject(pass *analysis.Pass, node ast.Node, obj types.Object, allowOSFS, allowSys bool, reported map[token.Pos]bool) {
	pkgPath := vetutil.ObjectPkgPath(obj)
	if pkgPath == "" {
		return
	}
	name := obj.Name()
	if !allowOSFS && isOSFSBannedSymbol(pkgPath, name) {
		reportPos(pass, node, reported, "osboundary: 白名单包 core/osfs 之外禁止直接调用裸 OS 文件/锁/ACL/Socket API ("+pkgPath+"."+name+")")
		return
	}
	if !allowSys && isSysBannedSymbol(pkgPath, name) {
		reportPos(pass, node, reported, "osboundary: 白名单包 internal/host/sys 之外禁止直接调用环境变量或进程执行 API ("+pkgPath+"."+name+")")
	}
}

// reportPos 按 AST 节点起始位置去重，避免同一符号在 Ident 与 SelectorExpr 阶段重复告警。
func reportPos(pass *analysis.Pass, node ast.Node, reported map[token.Pos]bool, msg string) {
	pos := node.Pos()
	if !pos.IsValid() || reported[pos] {
		return
	}
	reported[pos] = true
	pass.ReportRangef(node, "%s", msg)
}

func isOSFSBannedSymbol(pkgPath, name string) bool {
	switch pkgPath {
	case "os":
		return isOSFileOrRootSymbol(name)
	case "io/ioutil":
		return isIOUtilFileSymbol(name)
	case "syscall":
		return isSyscallFileSymbol(name)
	case "golang.org/x/sys/unix":
		return isUnixFileSymbol(name)
	case "golang.org/x/sys/windows":
		return isWindowsFileOrACLSymbol(name)
	case "net":
		return name == "ListenUnix" || name == "ListenUnixgram"
	default:
		return false
	}
}

func isOSFileOrRootSymbol(name string) bool {
	switch name {
	case "Open", "OpenFile", "Create", "CreateTemp", "OpenInRoot",
		"ReadFile", "WriteFile", "ReadDir",
		"Mkdir", "MkdirAll", "MkdirTemp",
		"Remove", "RemoveAll", "Rename",
		"Link", "Symlink", "Readlink",
		"Stat", "Lstat", "Chmod", "Chown", "Lchown", "Chtimes", "Truncate",
		"NewFile", "OpenRoot", "DirFS", "CopyFS", "Chdir", "Getwd", "Root":
		return true
	default:
		return false
	}
}

func isIOUtilFileSymbol(name string) bool {
	switch name {
	case "ReadFile", "WriteFile", "ReadDir", "TempFile", "TempDir":
		return true
	default:
		return false
	}
}

func isSyscallFileSymbol(name string) bool {
	switch name {
	case "Flock", "FcntlFlock", "Open", "Openat", "Creat",
		"Unlink", "Unlinkat", "Rmdir", "Rename", "Renameat",
		"Mkdir", "Mkdirat", "Symlink", "Symlinkat", "Link", "Linkat",
		"Readlink", "Stat", "Lstat", "Fstat",
		"Chmod", "Fchmod", "Chown", "Fchown", "Lchown", "Truncate", "Ftruncate":
		return true
	default:
		return false
	}
}

func isUnixFileSymbol(name string) bool {
	switch name {
	case "Flock", "FcntlFlock", "Open", "Openat", "Openat2",
		"Unlink", "Unlinkat", "Rename", "Renameat", "Renameat2",
		"Mkdir", "Mkdirat", "Symlink", "Symlinkat", "Link", "Linkat",
		"Readlink", "Readlinkat", "Stat", "Lstat", "Fstat", "Fstatat",
		"Chmod", "Fchmod", "Fchmodat", "Chown", "Fchown", "Fchownat", "Lchown",
		"GetsockoptUcred", "GetsockoptXucred":
		return true
	default:
		return false
	}
}

func isWindowsFileOrACLSymbol(name string) bool {
	switch name {
	case "CreateFile", "LockFileEx", "UnlockFileEx",
		"MoveFileEx", "DeleteFile", "RemoveDirectory", "CreateDirectory",
		"SetFileInformationByHandle", "GetFileInformationByHandle",
		"GetFileInformationByHandleEx", "GetFinalPathNameByHandle",
		"GetNamedSecurityInfo", "SetNamedSecurityInfo",
		"GetSecurityInfo", "SetSecurityInfo", "SetEntriesInAcl",
		"SecurityDescriptor", "ACL", "ExplicitAccess":
		return true
	default:
		return false
	}
}

func isSysBannedSymbol(pkgPath, name string) bool {
	switch pkgPath {
	case "os":
		switch name {
		case "Getenv", "LookupEnv", "Setenv", "Unsetenv", "Clearenv", "Environ", "ExpandEnv", "StartProcess":
			return true
		}
	case "os/exec":
		switch name {
		case "Command", "CommandContext", "LookPath", "Cmd":
			return true
		}
	case "syscall":
		switch name {
		case "Getenv", "Setenv", "Unsetenv", "Clearenv", "Environ", "ForkExec", "StartProcess", "Exec":
			return true
		}
	}
	return false
}

func isOSRootType(t types.Type) bool {
	return vetutil.TypeContainsNamed(t, "os", "Root")
}

// isUnixNetListenCall 拦截直接针对 unix/unixpacket/unixgram 的 net.Listen/ListenPacket
// 以及 (*net.ListenConfig).Listen/ListenPacket 调用（network 位于第 2 个参数）。
func isUnixNetListenCall(info *types.Info, call *ast.CallExpr) bool {
	obj := vetutil.ResolveCalledObject(info, call)
	if !vetutil.IsPkgSymbol(obj, "net", "Listen", "ListenPacket") {
		return false
	}
	argIdx := 0
	if isListenConfigMethod(obj) {
		argIdx = 1
	}
	if len(call.Args) <= argIdx {
		return false
	}
	tv, ok := info.Types[call.Args[argIdx]]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return false
	}
	netw := constant.StringVal(tv.Value)
	return netw == "unix" || netw == "unixpacket" || netw == "unixgram"
}

func isListenConfigMethod(obj types.Object) bool {
	fn, ok := obj.(*types.Func)
	if !ok || fn == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	return vetutil.TypeContainsNamed(sig.Recv().Type(), "net", "ListenConfig")
}
