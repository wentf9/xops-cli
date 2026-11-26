package secrettaint

import (
	"go/constant"
	"go/token"
	"go/types"
	"slices"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/analysis/passes/buildssa"
	"golang.org/x/tools/go/ssa"
)

const (
	vaultPkgPath          = vetutil.ModulePrefix + "/internal/host/vault"
	vaultWinCredPkgPath   = vetutil.ModulePrefix + "/internal/host/vault/wincred"
	vaultKeychainPkgPath  = vetutil.ModulePrefix + "/internal/host/vault/keychain"
	vaultSecretSvcPkgPath = vetutil.ModulePrefix + "/internal/host/vault/secretservice"
	vaultHelperPkgPath    = vetutil.ModulePrefix + "/internal/host/vault/helper"
	puregoPkgPath         = "github.com/ebitengine/purego"
	dbusPkgPath           = "github.com/godbus/dbus/v5"
	dbusCreateItemMethod  = "org.freedesktop.Secret.Collection.CreateItem"
	dbusSetSecretMethod   = "org.freedesktop.Secret.Item.SetSecret"
)

// 本文件实现 P4-T4 四个子包级受控窄消费器钩子（非外置测试生产文件专用，0 //nolint:）：
//   1. vault/wincred（含 Phase 0 夹具 vault）：局部 credentialW/CREDENTIALW 字段写入 + LazyProc/Proc.Call；
//   2. vault/keychain：github.com/ebitengine/purego.SyscallN（强制 arg 0 fn uintptr 未染毒）；
//   3. vault/secretservice：DH AES-128-CBC（NewCBCEncrypter + BlockMode.CryptBlocks）与 plain 回退
//      （局部 dbusSecret.Value 写入 + dbus.BusObject/Object.{CallWithContext,Call} 精确常量方法）；
//   4. vault/helper：(ports.ProcessPort).Run(ctx, spec, stdin)（recv/ctx/spec 未染毒，仅允许 arg 2 stdin 染毒）。

func (ts *taintScope) isProdVaultSubpkg(inst ssa.Instruction, allowedPaths ...string) bool {
	if ts.eng.pkgInfo.IsExternalTest || ts.eng.pkgInfo.Layer != vetutil.LayerHostVault {
		return false
	}
	if vetssa.IsInstInTestFile(ts.eng.pass, ts.fn, inst) {
		return false
	}
	return slices.Contains(allowedPaths, ts.eng.pkgInfo.BasePath)
}

func (ts *taintScope) isAllowedVaultNarrowFieldStore(ins *ssa.Store, fa *ssa.FieldAddr) bool {
	if fa == nil || fa.X == nil {
		return false
	}
	named, ok := vetutil.UnwrapNamedType(fa.X.Type())
	if !ok || named == nil || named.Obj() == nil {
		return false
	}
	name := named.Obj().Name()
	if (name == "credentialW" || name == "CREDENTIALW") && ts.isProdVaultSubpkg(ins, vaultWinCredPkgPath, vaultPkgPath) {
		return true
	}
	if name == "dbusSecret" && ts.isProdVaultSubpkg(ins, vaultSecretSvcPkgPath) {
		st, ok := named.Underlying().(*types.Struct)
		return ok && fa.Field >= 0 && fa.Field < st.NumFields() && st.Field(fa.Field).Name() == "Value"
	}
	return false
}

func (ts *taintScope) isAllowedVaultNarrowCall(callInst ssa.CallInstruction, rc vetssa.ResolvedCall, inSc vetssa.ScopeRange) bool {
	switch {
	case ts.isAllowedVaultProcCall(callInst, rc):
		return true
	case ts.isAllowedKeychainPuregoCall(callInst, rc):
		return true
	case ts.isAllowedSecretServiceNarrowCall(callInst, rc, inSc):
		return true
	case ts.isAllowedVaultHelperProcessRun(callInst, rc):
		return true
	default:
		return false
	}
}

func (ts *taintScope) isAllowedVaultProcCall(callInst ssa.CallInstruction, rc vetssa.ResolvedCall) bool {
	if !ts.isProdVaultSubpkg(callInst, vaultWinCredPkgPath, vaultPkgPath) || rc.FuncObj == nil || rc.FuncObj.Name() != "Call" {
		return false
	}
	if rc.Recv != nil && ts.isTainted(rc.Recv) {
		return false
	}
	pkgPath := vetutil.ObjectPkgPath(rc.FuncObj)
	named, ok := secretfact.RecvNamedType(rc.FuncObj)
	return (pkgPath == "syscall" || pkgPath == "golang.org/x/sys/windows") &&
		ok && named.Obj() != nil && (named.Obj().Name() == "LazyProc" || named.Obj().Name() == "Proc")
}

func (ts *taintScope) isAllowedKeychainPuregoCall(callInst ssa.CallInstruction, rc vetssa.ResolvedCall) bool {
	if !ts.isProdVaultSubpkg(callInst, vaultKeychainPkgPath) {
		return false
	}
	return vetutil.IsPkgSymbol(rc.FuncObj, puregoPkgPath, "SyscallN") &&
		len(rc.UserArgs) >= 1 && !ts.isTainted(rc.UserArgs[0])
}

func (ts *taintScope) isAllowedVaultHelperProcessRun(callInst ssa.CallInstruction, rc vetssa.ResolvedCall) bool {
	if !ts.isProdVaultSubpkg(callInst, vaultHelperPkgPath) || rc.FuncObj == nil || rc.FuncObj.Name() != "Run" {
		return false
	}
	if rc.Recv == nil || ts.isTainted(rc.Recv) || len(rc.UserArgs) != 3 {
		return false
	}
	named, ok := secretfact.RecvNamedType(rc.FuncObj)
	if !ok || !vetutil.IsPkgSymbol(named.Obj(), portsPkgPath, "ProcessPort") {
		return false
	}
	return !ts.isTainted(rc.UserArgs[0]) && !ts.isTainted(rc.UserArgs[1])
}

func (ts *taintScope) isAllowedSecretServiceNarrowCall(callInst ssa.CallInstruction, rc vetssa.ResolvedCall, inSc vetssa.ScopeRange) bool {
	if !ts.isProdVaultSubpkg(callInst, vaultSecretSvcPkgPath) || rc.FuncObj == nil {
		return false
	}
	if vetutil.IsPkgSymbol(rc.FuncObj, "crypto/cipher", "NewCBCEncrypter") {
		return len(rc.UserArgs) == 2 &&
			tracesOnlyToAESBlock(ts.eng.ssaInfo, rc.UserArgs[0], map[ssa.Value]bool{}, map[*ssa.Function]bool{}) &&
			!ts.isTainted(rc.UserArgs[1])
	}
	if ts.isAllowedSecretServiceCryptBlocks(rc, inSc) {
		return true
	}
	return ts.isAllowedSecretServiceDBusCall(rc)
}

func (ts *taintScope) isAllowedSecretServiceCryptBlocks(rc vetssa.ResolvedCall, inSc vetssa.ScopeRange) bool {
	if rc.FuncObj.Name() != "CryptBlocks" || rc.Recv == nil || ts.isTainted(rc.Recv) || len(rc.UserArgs) != 2 {
		return false
	}
	named, ok := secretfact.RecvNamedType(rc.FuncObj)
	if !ok || !vetutil.IsPkgSymbol(named.Obj(), "crypto/cipher", "BlockMode") {
		return false
	}
	dst, src := rc.UserArgs[0], rc.UserArgs[1]
	if ts.isTainted(dst) || !vetssa.IsAllowedSliceWriteDst(dst, inSc, ts.callerParams) || slicesShareRoot(dst, src) {
		return false
	}
	return tracesOnlyToStdlibCBCEncrypter(ts.eng.ssaInfo, rc.Recv, map[ssa.Value]bool{}, map[*ssa.Function]bool{})
}

func slicesShareRoot(a, b ssa.Value) bool {
	if a == b {
		return true
	}
	rootsA := vetssa.RootStorageValues(a, false)
	rootsB := vetssa.RootStorageValues(b, false)
	for _, ra := range rootsA {
		if slices.Contains(rootsB, ra) {
			return true
		}
	}
	return false
}

func tracesOnlyToStdlibCBCEncrypter(s *buildssa.SSA, v ssa.Value, visiting map[ssa.Value]bool, seenFn map[*ssa.Function]bool) bool {
	v = vetssa.UnwrapInterface(v)
	if v == nil || visiting[v] {
		return false
	}
	visiting[v] = true
	defer delete(visiting, v)
	switch val := v.(type) {
	case *ssa.Extract:
		return traceCBCEncrypterCall(s, val.Tuple, val.Index, visiting, seenFn)
	case *ssa.Call:
		return traceCBCEncrypterCall(s, val, 0, visiting, seenFn)
	case *ssa.Phi:
		return allNonNilEdgesMatch(val.Edges, func(e ssa.Value) bool { return tracesOnlyToStdlibCBCEncrypter(s, e, visiting, seenFn) })
	case *ssa.FreeVar:
		origins := vetssa.TraceFreeVarOrigins(val)
		return len(origins) > 0 && !slices.ContainsFunc(origins, func(o ssa.Value) bool { return !tracesOnlyToStdlibCBCEncrypter(s, o, visiting, seenFn) })
	case *ssa.Alloc:
		vals, ok := collectCellStoreValues(val, map[ssa.Value]bool{})
		return ok && !slices.ContainsFunc(vals, func(sv ssa.Value) bool { return !tracesOnlyToStdlibCBCEncrypter(s, sv, visiting, seenFn) })
	case *ssa.UnOp:
		return val.Op == token.MUL && tracesOnlyToStdlibCBCEncrypter(s, val.X, visiting, seenFn)
	default:
		return false
	}
}

func traceCBCEncrypterCall(s *buildssa.SSA, callVal ssa.Value, retSlot int, visiting map[ssa.Value]bool, seenFn map[*ssa.Function]bool) bool {
	call, ok := callVal.(*ssa.Call)
	if !ok {
		return false
	}
	callee := call.Call.StaticCallee()
	if retSlot == 0 && vetutil.IsPkgSymbol(vetssa.OriginFuncObj(callee), "crypto/cipher", "NewCBCEncrypter") {
		return len(call.Call.Args) == 2 && tracesOnlyToAESBlock(s, call.Call.Args[0], map[ssa.Value]bool{}, seenFn)
	}
	origFn := vetssa.UnwrapOriginFunc(callee)
	if origFn == nil || !vetssa.IsSamePackageFunc(s, origFn) || len(origFn.Blocks) == 0 {
		return false
	}
	return samePkgReturnsMatch(origFn, retSlot, seenFn, func(rv ssa.Value) bool {
		return tracesOnlyToStdlibCBCEncrypter(s, rv, visiting, seenFn)
	})
}

func (ts *taintScope) isAllowedSecretServiceDBusCall(rc vetssa.ResolvedCall) bool {
	if rc.Recv == nil || ts.isTainted(rc.Recv) {
		return false
	}
	named, ok := secretfact.RecvNamedType(rc.FuncObj)
	if !ok || !vetutil.IsPkgSymbol(named.Obj(), dbusPkgPath, "BusObject", "Object") {
		return false
	}
	var methodIdx, flagsIdx, varargsIdx int
	switch rc.FuncObj.Name() {
	case "CallWithContext":
		if len(rc.UserArgs) < 4 || ts.isTainted(rc.UserArgs[0]) {
			return false
		}
		methodIdx, flagsIdx, varargsIdx = 1, 2, 3
	case "Call":
		if len(rc.UserArgs) < 3 {
			return false
		}
		methodIdx, flagsIdx, varargsIdx = 0, 1, 2
	default:
		return false
	}
	if ts.isTainted(rc.UserArgs[methodIdx]) || ts.isTainted(rc.UserArgs[flagsIdx]) || !isAllowedSecretServiceDBusMethod(rc.UserArgs[methodIdx]) {
		return false
	}
	return ts.allTaintedDBusArgsAreSecretStruct(rc.UserArgs[varargsIdx:])
}

func isAllowedSecretServiceDBusMethod(v ssa.Value) bool {
	for v != nil {
		switch val := v.(type) {
		case *ssa.Const:
			if val.Value == nil || val.Value.Kind() != constant.String {
				return false
			}
			m := constant.StringVal(val.Value)
			return m == dbusCreateItemMethod || m == dbusSetSecretMethod
		case *ssa.ChangeType:
			v = val.X
		case *ssa.Convert:
			v = val.X
		default:
			return false
		}
	}
	return false
}

func (ts *taintScope) allTaintedDBusArgsAreSecretStruct(args []ssa.Value) bool {
	for _, arg := range args {
		if elems := vetssa.ExtractVarargsElements(arg); len(elems) > 0 {
			if !ts.allTaintedDBusArgsAreSecretStruct(elems) {
				return false
			}
			continue
		}
		if !ts.isTainted(arg) {
			continue
		}
		if !isDBusSecretStructValue(arg) {
			return false
		}
	}
	return true
}

func isDBusSecretStructValue(v ssa.Value) bool {
	u := vetssa.UnwrapInterface(v)
	if u == nil {
		return false
	}
	named, ok := vetutil.UnwrapNamedType(u.Type())
	return ok && named != nil && named.Obj() != nil && named.Obj().Name() == "dbusSecret"
}
