package osboundary

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

// checkOSSymbols 在生产源码中检查封锁于 core/osfs 与 internal/host/sys 的底层系统原语，
// 覆盖 AST 符号引用、os.Root 方法选择及 SSA 级 Unix Domain Socket 常量网络监听调用；
// 测试文件与 core/ports/tck 豁免此检查（pkg.init 按解析后指令位置精确判测试）。
func checkOSSymbols(pass *analysis.Pass, s *buildssa.SSA, pkgInfo vetutil.PkgInfo) {
	if pass.TypesInfo == nil || pkgInfo.IsExternalTest || pkgInfo.Layer == vetutil.LayerCorePortsTCK {
		return
	}
	allowOSFS, allowSys := vetutil.AllowOSFSPrimitives(pkgInfo), vetutil.AllowSysExecEnv(pkgInfo)
	if allowOSFS && allowSys {
		return
	}
	reported := make(map[token.Pos]bool)
	vetutil.InspectorOf(pass).Preorder([]ast.Node{(*ast.SelectorExpr)(nil), (*ast.Ident)(nil)}, func(n ast.Node) {
		if !vetutil.IsPosInTestFile(pass, n.Pos()) {
			checkOSSymbolNode(pass, n, allowOSFS, allowSys, reported)
		}
	})
	if !allowOSFS && s != nil {
		checkSSAUnixNetListen(pass, s, reported)
	}
}

func checkOSSymbolNode(pass *analysis.Pass, n ast.Node, allowOSFS, allowSys bool, reported map[token.Pos]bool) {
	switch node := n.(type) {
	case *ast.SelectorExpr:
		if sel := pass.TypesInfo.Selections[node]; sel != nil {
			if !allowOSFS && vetutil.TypeContainsNamed(sel.Recv(), "os", "Root") {
				reportPos(pass, node.Sel, reported, "osboundary: 白名单包 core/osfs 之外禁止调用 os.Root 方法")
			}
			return
		}
		if obj := pass.TypesInfo.Uses[node.Sel]; obj != nil {
			reportBannedObject(pass, node.Sel, obj, allowOSFS, allowSys, reported)
		}
	case *ast.Ident:
		if obj := pass.TypesInfo.Uses[node]; obj != nil {
			reportBannedObject(pass, node, obj, allowOSFS, allowSys, reported)
		}
	}
}

func reportBannedObject(pass *analysis.Pass, node ast.Node, obj types.Object, allowOSFS, allowSys bool, reported map[token.Pos]bool) {
	pkgPath, name := vetutil.ObjectPkgPath(obj), obj.Name()
	if pkgPath == "" {
		return
	}
	if !allowOSFS && isOSFSBannedSymbol(pkgPath, name) {
		reportPos(pass, node, reported, "osboundary: 白名单包 core/osfs 之外禁止直接调用裸 OS 文件/锁/ACL/Socket API ("+pkgPath+"."+name+")")
	} else if !allowSys && isSysBannedSymbol(pkgPath, name) {
		reportPos(pass, node, reported, "osboundary: 白名单包 internal/host/sys 之外禁止直接调用环境变量或进程执行 API ("+pkgPath+"."+name+")")
	}
}

func reportPos(pass *analysis.Pass, node ast.Node, reported map[token.Pos]bool, msg string) {
	if pos := node.Pos(); pos.IsValid() && !reported[pos] {
		reported[pos] = true
		pass.ReportRangef(node, "%s", msg)
	}
}

// checkSSAUnixNetListen 基于 vetssa 拦截针对 unix* 的 net.Listen/ListenPacket 与 (*net.ListenConfig).Listen/ListenPacket，
// 统一覆盖 $bound/$thunk、Phi 函数值、Phi 网络常量与窄接口擦除调用（H5）。
func checkSSAUnixNetListen(pass *analysis.Pass, s *buildssa.SSA, reported map[token.Pos]bool) {
	var diags []vetutil.Diag
	vetssa.ForEachFuncInst(vetssa.AllFuncs(s), func(fn *ssa.Function, inst ssa.Instruction) {
		callInst, ok := inst.(ssa.CallInstruction)
		if !ok || vetssa.IsInstInTestFile(pass, fn, callInst) || !isUnixNetListenCall(s, callInst) {
			return
		}
		if pos := vetssa.ResolvePos(pass, fn, callInst); pos.IsValid() && !reported[pos] {
			reported[pos] = true
			diags = append(diags, vetutil.Diag{Pos: pos, End: pos, Msg: "osboundary: 白名单包 core/osfs 之外禁止直接创建 Unix Domain Socket 监听"})
		}
	})
	vetutil.ReportSortedDedup(pass, diags, true)
}

func isUnixNetListenCall(s *buildssa.SSA, callInst ssa.CallInstruction) bool {
	rc := vetssa.ResolveCall(s, callInst)
	if isUnixNetListenResolved(rc) {
		return true
	}
	cc := callInst.Common()
	if cc == nil {
		return false
	}
	if cc.IsInvoke() {
		return isUnixNetListenInvoke(cc)
	}
	targets, _ := vetssa.ResolveFuncValues(cc.Value)
	for _, tgt := range targets {
		fnObj := targetFuncObj(tgt)
		if fnObj == nil {
			continue
		}
		if argIdx, ok := unixListenNetworkArgIdx(fnObj, cc.Args); ok && hasUnixNetworkConst(cc.Args[argIdx]) {
			return true
		}
	}
	return false
}

func isUnixNetListenInvoke(cc *ssa.CallCommon) bool {
	if cc.Method == nil || (cc.Method.Name() != "Listen" && cc.Method.Name() != "ListenPacket") || len(cc.Args) < 2 {
		return false
	}
	unwrapped := vetssa.UnwrapInterface(cc.Value)
	return vetutil.ContainsValueNamed(unwrapped.Type(), "net", "ListenConfig") && hasUnixNetworkConst(cc.Args[1])
}

func targetFuncObj(tgt ssa.Value) *types.Func {
	switch v := tgt.(type) {
	case *ssa.Function:
		return vetssa.OriginFuncObj(v)
	case *ssa.MakeClosure:
		if fn, ok := v.Fn.(*ssa.Function); ok {
			return vetssa.OriginFuncObj(fn)
		}
	}
	return nil
}

func isUnixNetListenResolved(rc vetssa.ResolvedCall) bool {
	argIdx, ok := unixListenNetworkArgIdx(rc.FuncObj, rc.UserArgs)
	return ok && hasUnixNetworkConst(rc.UserArgs[argIdx])
}

func unixListenNetworkArgIdx(fnObj *types.Func, args []ssa.Value) (int, bool) {
	if !vetutil.IsPkgSymbol(fnObj, "net", "Listen", "ListenPacket") {
		return 0, false
	}
	argIdx := 0
	if sig, ok := fnObj.Type().(*types.Signature); ok && sig.Recv() != nil && vetutil.ContainsValueNamed(sig.Recv().Type(), "net", "ListenConfig") {
		argIdx = 1
	}
	return argIdx, len(args) > argIdx
}

func hasUnixNetworkConst(v ssa.Value) bool {
	return hasUnixNetworkConstSeen(v, make(map[ssa.Value]bool))
}

func hasUnixNetworkConstSeen(v ssa.Value, seen map[ssa.Value]bool) bool {
	if v == nil || seen[v] {
		return false
	}
	seen[v] = true
	switch val := v.(type) {
	case *ssa.Const:
		if val.Value == nil || val.Value.Kind() != constant.String {
			return false
		}
		netw := constant.StringVal(val.Value)
		return netw == "unix" || netw == "unixpacket" || netw == "unixgram"
	case *ssa.ChangeType:
		return hasUnixNetworkConstSeen(val.X, seen)
	case *ssa.Convert:
		return hasUnixNetworkConstSeen(val.X, seen)
	case *ssa.Phi:
		return slices.ContainsFunc(val.Edges, func(e ssa.Value) bool { return hasUnixNetworkConstSeen(e, seen) })
	default:
		return false
	}
}

func isOSFSBannedSymbol(pkgPath, name string) bool {
	switch pkgPath {
	case "os":
		return slices.Contains([]string{
			"Open", "OpenFile", "Create", "CreateTemp", "OpenInRoot", "ReadFile", "WriteFile", "ReadDir",
			"Mkdir", "MkdirAll", "MkdirTemp", "Remove", "RemoveAll", "Rename", "Link", "Symlink", "Readlink",
			"Stat", "Lstat", "Chmod", "Chown", "Lchown", "Chtimes", "Truncate", "NewFile", "OpenRoot",
			"DirFS", "CopyFS", "Chdir", "Getwd", "Root",
		}, name)
	case "io/ioutil":
		return slices.Contains([]string{"ReadFile", "WriteFile", "ReadDir", "TempFile", "TempDir"}, name)
	case "syscall":
		return slices.Contains([]string{
			"Flock", "FcntlFlock", "Open", "Openat", "Creat", "Unlink", "Unlinkat", "Rmdir", "Rename",
			"Renameat", "Mkdir", "Mkdirat", "Symlink", "Symlinkat", "Link", "Linkat", "Readlink", "Stat",
			"Lstat", "Fstat", "Chmod", "Fchmod", "Chown", "Fchown", "Lchown", "Truncate", "Ftruncate",
		}, name)
	case "golang.org/x/sys/unix":
		return slices.Contains([]string{
			"Flock", "FcntlFlock", "Open", "Openat", "Openat2", "Unlink", "Unlinkat", "Rename", "Renameat",
			"Renameat2", "Mkdir", "Mkdirat", "Symlink", "Symlinkat", "Link", "Linkat", "Readlink", "Readlinkat",
			"Stat", "Lstat", "Fstat", "Fstatat", "Chmod", "Fchmod", "Fchmodat", "Chown", "Fchown", "Fchownat",
			"Lchown", "GetsockoptUcred", "GetsockoptXucred",
		}, name)
	case "golang.org/x/sys/windows":
		return slices.Contains([]string{
			"CreateFile", "LockFileEx", "UnlockFileEx", "MoveFileEx", "DeleteFile", "RemoveDirectory",
			"CreateDirectory", "SetFileInformationByHandle", "GetFileInformationByHandle",
			"GetFileInformationByHandleEx", "GetFinalPathNameByHandle", "GetNamedSecurityInfo",
			"SetNamedSecurityInfo", "GetSecurityInfo", "SetSecurityInfo", "SetEntriesInAcl",
			"SecurityDescriptor", "ACL", "ExplicitAccess",
		}, name)
	case "net":
		return name == "ListenUnix" || name == "ListenUnixgram"
	default:
		return false
	}
}

func isSysBannedSymbol(pkgPath, name string) bool {
	switch pkgPath {
	case "os":
		return slices.Contains([]string{"Getenv", "LookupEnv", "Setenv", "Unsetenv", "Clearenv", "Environ", "ExpandEnv", "StartProcess"}, name)
	case "os/exec":
		return slices.Contains([]string{"Command", "CommandContext", "LookPath", "Cmd"}, name)
	case "syscall":
		return slices.Contains([]string{"Getenv", "Setenv", "Unsetenv", "Clearenv", "Environ", "ForkExec", "StartProcess", "Exec", "CreateProcess"}, name)
	case "golang.org/x/sys/unix":
		return slices.Contains([]string{"Exec", "Getenv", "Setenv", "Unsetenv", "Clearenv", "Environ"}, name)
	case "golang.org/x/sys/windows":
		return slices.Contains([]string{
			"CreateProcess", "CreateProcessAsUser", "GetEnvironmentVariable",
			"SetEnvironmentVariable", "GetEnvironmentStrings", "ExpandEnvironmentStrings",
		}, name)
	default:
		return false
	}
}
