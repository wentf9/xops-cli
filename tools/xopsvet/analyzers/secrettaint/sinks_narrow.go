package secrettaint

import (
	"go/types"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/secretfact"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetssa"
	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
	"golang.org/x/tools/go/ssa"
)

const (
	dialPkgPath  = vetutil.ModulePrefix + "/core/internal/sshnet/dial"
	vaultPkgPath = vetutil.ModulePrefix + "/internal/host/vault"
)

// 本文件实现 Phase 4 受控窄消费器模式钩子（v2.3.3 B2b），
// 在保持 0 //nolint: 与默认 Fail-Closed 的前提下，为两类跨平台真实 OS/SSH 窄边界预留精确结构化契约：
//   1. P4-T1（core/internal/sshnet/dial）：ssh.KeyboardInteractiveChallenge 回调的局部 answers []string 返回槽位；
//   2. P4-T4（internal/host/vault）：Windows CREDENTIALW 单函数零逃逸局部结构体指针 + LazyProc.Call。

// isDialKeyboardInteractiveAnswersReturn 在 core/internal/sshnet/dial 包中精确放行
// 签名为 ssh.KeyboardInteractiveChallenge（返回 ([]string, error)）的闭包返回局部 answers 切片。
func isDialKeyboardInteractiveAnswersReturn(pkgInfo vetutil.PkgInfo, fn *ssa.Function, ret *ssa.Return) bool {
	if pkgInfo.IsExternalTest || pkgInfo.BasePath != dialPkgPath || fn == nil || fn.Signature == nil {
		return false
	}
	results, params := fn.Signature.Results(), fn.Signature.Params()
	if results == nil || results.Len() != 2 || len(ret.Results) != 2 || params == nil || params.Len() != 4 {
		return false
	}
	return isSliceOfBasic(results.At(0).Type(), types.IsString) &&
		vetutil.IsErrorInterfaceType(results.At(1).Type()) &&
		isBasicInfo(params.At(0).Type(), types.IsString) &&
		isBasicInfo(params.At(1).Type(), types.IsString) &&
		isSliceOfBasic(params.At(2).Type(), types.IsString) &&
		isSliceOfBasic(params.At(3).Type(), types.IsBoolean)
}

// isVaultNarrowCredentialFieldStore 在 internal/host/vault 包中放行单函数局部栈上 Windows
// CREDENTIALW 结构体（仅限该具名类型）写入明文字段，以便立即经 LazyProc.Call 传入系统凭据库并在同函数内清零。
func isVaultNarrowCredentialFieldStore(pkgInfo vetutil.PkgInfo, fa *ssa.FieldAddr) bool {
	if pkgInfo.IsExternalTest || pkgInfo.BasePath != vaultPkgPath || fa == nil {
		return false
	}
	named, ok := vetutil.UnwrapNamedType(fa.X.Type())
	return ok && named != nil && named.Obj() != nil && (named.Obj().Name() == "credentialW" || named.Obj().Name() == "CREDENTIALW")
}

// isAllowedNarrowConsumerCall 检查 Phase 4 预留的 internal/host/vault Windows LazyProc.Call 窄消费边界。
func isAllowedNarrowConsumerCall(pkgInfo vetutil.PkgInfo, rc vetssa.ResolvedCall) bool {
	if pkgInfo.IsExternalTest || pkgInfo.BasePath != vaultPkgPath || rc.FuncObj == nil || rc.FuncObj.Name() != "Call" {
		return false
	}
	pkgPath := vetutil.ObjectPkgPath(rc.FuncObj)
	if pkgPath != "syscall" && pkgPath != "golang.org/x/sys/windows" {
		return false
	}
	named, ok := secretfact.RecvNamedType(rc.FuncObj)
	return ok && named.Obj() != nil && (named.Obj().Name() == "LazyProc" || named.Obj().Name() == "Proc")
}

func isBasicInfo(t types.Type, info types.BasicInfo) bool {
	b, ok := types.Unalias(t).Underlying().(*types.Basic)
	return ok && b.Info()&info != 0
}

func isSliceOfBasic(t types.Type, info types.BasicInfo) bool {
	sl, ok := types.Unalias(t).(*types.Slice)
	return ok && isBasicInfo(sl.Elem(), info)
}
