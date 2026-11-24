package vetutil

import (
	"strings"

	"golang.org/x/tools/go/analysis"
)

// ModulePrefix 定义 XOps v2 仓库根模块路径前缀。
const ModulePrefix = "github.com/wentf9/xops-cli"

// Layer 表示包在 XOps v2 三模块六边形架构中的所属层级。
type Layer uint8

const (
	LayerUnknown Layer = iota
	LayerCoreDomain
	LayerCorePorts
	LayerCorePortsTCK
	LayerCoreEvents
	LayerCoreOSFS
	LayerCoreConc
	LayerCoreEngine
	LayerCoreFoundationActor
	LayerCoreFoundationTrace
	LayerCoreFoundationOther
	LayerCorePool
	LayerCoreGate
	LayerCoreUsecase
	LayerCoreMCPRuntime
	LayerCoreSSHNetDial
	LayerCoreSSHNetPriv
	LayerCoreSSHNetOther
	LayerCoreSim
	LayerCoreOther
	LayerHostSys
	LayerHostVault
	LayerHostOther
	LayerEntry
	LayerCmdXops
	LayerToolsXopsvet
)

// PkgInfo 保存归一化后的包路径与架构层级元数据。
type PkgInfo struct {
	RawPath        string // 原始导入或包路径
	BasePath       string // 剥离 _test 与驱动后缀后的规范路径
	Layer          Layer  // 所属架构层级
	IsExternalTest bool   // 是否为外置 *_test 包
	IsXops         bool   // 是否属于 github.com/wentf9/xops-cli 仓库
}

type layerPrefixRule struct {
	prefix string
	layer  Layer
}

// IsSyntheticTestMain 判断 pass 是否为 go test / go vet 生成的合成 .test 入口包。
func IsSyntheticTestMain(pass *analysis.Pass) bool {
	return pass != nil && pass.Pkg != nil && strings.HasSuffix(pass.Pkg.Path(), ".test") && pass.Pkg.Name() == "main"
}

// NormalizePkgPath 归一化包路径：截断驱动附加的 " [...]" 后缀，并识别外置 _test 包。
func NormalizePkgPath(pkgPath string) (base string, isExtTest bool) {
	p, _, _ := strings.Cut(pkgPath, " [")
	if trimmed, ok := strings.CutSuffix(p, "_test"); ok {
		return trimmed, true
	}
	return p, false
}

// ClassifyPackage 将任意 Go 导入路径或包路径分类为 XOps v2 架构层级。
func ClassifyPackage(pkgPath string) PkgInfo {
	base, isExtTest := NormalizePkgPath(pkgPath)
	return classifyWithExt(pkgPath, base, isExtTest)
}

// ClassifyPass 结合编译单元文件集合分类当前分析包：仅当所有源码均为 *_test.go 时才认定为外置 _test 包，
// 防止名为 *_test 的普通生产子目录绕过架构与安全护栏（H5）。
func ClassifyPass(pass *analysis.Pass) PkgInfo {
	if pass == nil || pass.Pkg == nil {
		return PkgInfo{}
	}
	info := ClassifyPackage(pass.Pkg.Path())
	if !info.IsExternalTest || len(pass.Files) == 0 {
		return info
	}
	for _, f := range pass.Files {
		if !IsTestFile(pass, f) {
			raw, _, _ := strings.Cut(pass.Pkg.Path(), " [")
			return classifyWithExt(pass.Pkg.Path(), raw, false)
		}
	}
	return info
}

func classifyWithExt(rawPath, base string, isExtTest bool) PkgInfo {
	if base != ModulePrefix && !strings.HasPrefix(base, ModulePrefix+"/") {
		return PkgInfo{RawPath: rawPath, BasePath: base, Layer: LayerUnknown, IsExternalTest: isExtTest}
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(base, ModulePrefix), "/")
	return PkgInfo{RawPath: rawPath, BasePath: base, Layer: classifyRelPath(rel), IsExternalTest: isExtTest, IsXops: true}
}

func classifyRelPath(rel string) Layer {
	rules := []layerPrefixRule{
		{"core/internal/foundation/actor", LayerCoreFoundationActor},
		{"core/internal/foundation/trace", LayerCoreFoundationTrace},
		{"core/internal/foundation", LayerCoreFoundationOther},
		{"core/internal/pool", LayerCorePool},
		{"core/internal/gate", LayerCoreGate},
		{"core/internal/usecase", LayerCoreUsecase},
		{"core/internal/mcpruntime", LayerCoreMCPRuntime},
		{"core/internal/sshnet/dial", LayerCoreSSHNetDial},
		{"core/internal/sshnet/priv", LayerCoreSSHNetPriv},
		{"core/internal/sshnet", LayerCoreSSHNetOther},
		{"core/internal/sim", LayerCoreSim},
		{"core/domain", LayerCoreDomain},
		{"core/ports/tck", LayerCorePortsTCK},
		{"core/ports", LayerCorePorts},
		{"core/events", LayerCoreEvents},
		{"core/osfs", LayerCoreOSFS},
		{"core/conc", LayerCoreConc},
		{"core/engine", LayerCoreEngine},
		{"core", LayerCoreOther},
		{"internal/host/sys", LayerHostSys},
		{"internal/host/vault", LayerHostVault},
		{"internal/host", LayerHostOther},
		{"internal/entry", LayerEntry},
		{"cmd/xops", LayerCmdXops},
		{"tools/xopsvet", LayerToolsXopsvet},
	}
	for _, r := range rules {
		if matchPkgPrefix(rel, r.prefix) {
			return r.layer
		}
	}
	return LayerUnknown
}

func matchPkgPrefix(rel, prefix string) bool {
	return rel == prefix || strings.HasPrefix(rel, prefix+"/")
}

// IsStdlibImport 判断导入路径是否属于 Go 标准库包（首段不含 '.' 且非 "C"）。
func IsStdlibImport(impPath string) bool {
	if impPath == "" || impPath == "C" {
		return false
	}
	head, _, _ := strings.Cut(impPath, "/")
	return !strings.Contains(head, ".")
}

// IsCoreLayer 判断给定层级是否位于 core/ 模块内部。
func IsCoreLayer(layer Layer) bool { return layer >= LayerCoreDomain && layer <= LayerCoreOther }

// AllowContextValue 判断包是否位于 context.WithValue / ctx.Value 白名单内（仅 foundation/trace）。
func AllowContextValue(info PkgInfo) bool {
	return !info.IsExternalTest && info.Layer == LayerCoreFoundationTrace
}

// AllowOSFSPrimitives 判断包是否位于裸 OS 文件/锁/ACL/os.Root/SocketSlot 白名单内（仅 core/osfs）。
func AllowOSFSPrimitives(info PkgInfo) bool {
	return !info.IsExternalTest && info.Layer == LayerCoreOSFS
}

// AllowSysExecEnv 判断包是否位于环境变量与外部进程执行白名单内（仅 internal/host/sys）。
func AllowSysExecEnv(info PkgInfo) bool { return !info.IsExternalTest && info.Layer == LayerHostSys }

// AllowBareGo 判断包是否位于裸 go 语句白名单内（全仓唯一：core/conc，不含外置 _test）。
func AllowBareGo(info PkgInfo) bool { return !info.IsExternalTest && info.Layer == LayerCoreConc }

// AllowSecretPlaintext 判断包是否位于 5 个明文机密 []byte 消费白名单包集合内（不含外置 _test）。
func AllowSecretPlaintext(info PkgInfo) bool {
	if info.IsExternalTest {
		return false
	}
	return info.Layer == LayerHostVault || info.Layer == LayerCoreSSHNetDial || info.Layer == LayerCoreSSHNetPriv ||
		info.Layer == LayerCoreSim || (info.Layer == LayerCoreDomain && matchPkgPrefix(info.BasePath, ModulePrefix+"/core/domain/secret"))
}

// AllowNolint 判断包层级是否位于 8 个生产特权白名单包集合内（外置 _test 禁止；单文件白盒测试由 AllowNolintInFile 进一步封禁）。
func AllowNolint(info PkgInfo) bool {
	if info.IsExternalTest {
		return false
	}
	return (AllowSecretPlaintext(info) && info.Layer != LayerCoreSim) ||
		info.Layer == LayerCoreOSFS || info.Layer == LayerCoreConc ||
		info.Layer == LayerCoreFoundationTrace || info.Layer == LayerHostSys
}
