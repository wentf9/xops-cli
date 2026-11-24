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
	// LayerUnknown 表示仓库外第三方包、标准库或未识别根路径。
	LayerUnknown Layer = iota
	// LayerCoreDomain 表示 core/domain/** 纯数学领域核。
	LayerCoreDomain
	// LayerCorePorts 表示 core/ports 出站端口契约层。
	LayerCorePorts
	// LayerCorePortsTCK 表示 core/ports/tck 通用契约测试套件层。
	LayerCorePortsTCK
	// LayerCoreEvents 表示 core/events 作用域事件流层。
	LayerCoreEvents
	// LayerCoreOSFS 表示 core/osfs 三平台句柄安全本地文件系统原语层。
	LayerCoreOSFS
	// LayerCoreEngine 表示 core/engine 核心门面与唯一内部装配点。
	LayerCoreEngine
	// LayerCoreFoundationConc 表示 core/internal/foundation/conc 结构化并发白名单包。
	LayerCoreFoundationConc
	// LayerCoreFoundationTrace 表示 core/internal/foundation/trace 上下文追踪白名单包。
	LayerCoreFoundationTrace
	// LayerCoreFoundationOther 表示 core/internal/foundation 下其余基础子包。
	LayerCoreFoundationOther
	// LayerCorePool 表示 core/internal/pool 双通道连接池包。
	LayerCorePool
	// LayerCoreGate 表示 core/internal/gate 能力门控包。
	LayerCoreGate
	// LayerCoreUsecase 表示 core/internal/usecase/** 用例服务层。
	LayerCoreUsecase
	// LayerCoreMCPRuntime 表示 core/internal/mcpruntime MCP 运行时层。
	LayerCoreMCPRuntime
	// LayerCoreSSHNetDial 表示 core/internal/sshnet/dial SSH 拨号白名单包。
	LayerCoreSSHNetDial
	// LayerCoreSSHNetOther 表示 core/internal/sshnet 下其余传输子包。
	LayerCoreSSHNetOther
	// LayerCoreSim 表示 core/internal/sim 确定性仿真器层。
	LayerCoreSim
	// LayerCoreOther 表示 core/ 下未纳入架构清单的未知路径（fail-closed）。
	LayerCoreOther
	// LayerHostSys 表示 internal/host/sys 系统环境与进程执行白名单包。
	LayerHostSys
	// LayerHostVault 表示 internal/host/vault 机密保管白名单包。
	LayerHostVault
	// LayerHostOther 表示 internal/host 下其余本机适配器包。
	LayerHostOther
	// LayerEntry 表示 internal/entry/** 入站驱动适配器层。
	LayerEntry
	// LayerCmdXops 表示 cmd/xops 唯一外部组合根。
	LayerCmdXops
	// LayerToolsXopsvet 表示 tools/xopsvet/** 静态分析器工具模块。
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

// IsSyntheticTestMain 判断 pass 是否为 go test / go vet 生成的合成 .test 入口包。
// 合成测试入口包包含自动生成的 _testmain.go，会引入 os、reflect 等测试驱动依赖，
// 应当由架构依赖检查跳过以避免误报。
func IsSyntheticTestMain(pass *analysis.Pass) bool {
	if pass == nil || pass.Pkg == nil {
		return false
	}
	return strings.HasSuffix(pass.Pkg.Path(), ".test") && pass.Pkg.Name() == "main"
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
	if base != ModulePrefix && !strings.HasPrefix(base, ModulePrefix+"/") {
		return PkgInfo{
			RawPath:        pkgPath,
			BasePath:       base,
			Layer:          LayerUnknown,
			IsExternalTest: isExtTest,
			IsXops:         false,
		}
	}
	rel := strings.TrimPrefix(base, ModulePrefix)
	rel = strings.TrimPrefix(rel, "/")
	return PkgInfo{
		RawPath:        pkgPath,
		BasePath:       base,
		Layer:          classifyRelPath(rel),
		IsExternalTest: isExtTest,
		IsXops:         true,
	}
}

func classifyRelPath(rel string) Layer {
	if rel == "core" || strings.HasPrefix(rel, "core/") {
		return classifyCoreRel(rel)
	}
	switch {
	case matchPkgPrefix(rel, "internal/host/sys"):
		return LayerHostSys
	case matchPkgPrefix(rel, "internal/host/vault"):
		return LayerHostVault
	case matchPkgPrefix(rel, "internal/host"):
		return LayerHostOther
	case matchPkgPrefix(rel, "internal/entry"):
		return LayerEntry
	case matchPkgPrefix(rel, "cmd/xops"):
		return LayerCmdXops
	case matchPkgPrefix(rel, "tools/xopsvet"):
		return LayerToolsXopsvet
	default:
		return LayerUnknown
	}
}

func classifyCoreRel(rel string) Layer {
	if strings.HasPrefix(rel, "core/internal/") || rel == "core/internal" {
		return classifyCoreInternalRel(rel)
	}
	switch {
	case matchPkgPrefix(rel, "core/domain"):
		return LayerCoreDomain
	case matchPkgPrefix(rel, "core/ports/tck"):
		return LayerCorePortsTCK
	case matchPkgPrefix(rel, "core/ports"):
		return LayerCorePorts
	case matchPkgPrefix(rel, "core/events"):
		return LayerCoreEvents
	case matchPkgPrefix(rel, "core/osfs"):
		return LayerCoreOSFS
	case matchPkgPrefix(rel, "core/engine"):
		return LayerCoreEngine
	default:
		return LayerCoreOther
	}
}

func classifyCoreInternalRel(rel string) Layer {
	switch {
	case matchPkgPrefix(rel, "core/internal/foundation/conc"):
		return LayerCoreFoundationConc
	case matchPkgPrefix(rel, "core/internal/foundation/trace"):
		return LayerCoreFoundationTrace
	case matchPkgPrefix(rel, "core/internal/foundation"):
		return LayerCoreFoundationOther
	case matchPkgPrefix(rel, "core/internal/pool"):
		return LayerCorePool
	case matchPkgPrefix(rel, "core/internal/gate"):
		return LayerCoreGate
	case matchPkgPrefix(rel, "core/internal/usecase"):
		return LayerCoreUsecase
	case matchPkgPrefix(rel, "core/internal/mcpruntime"):
		return LayerCoreMCPRuntime
	case matchPkgPrefix(rel, "core/internal/sshnet/dial"):
		return LayerCoreSSHNetDial
	case matchPkgPrefix(rel, "core/internal/sshnet"):
		return LayerCoreSSHNetOther
	case matchPkgPrefix(rel, "core/internal/sim"):
		return LayerCoreSim
	default:
		return LayerCoreOther
	}
}

func matchPkgPrefix(rel, prefix string) bool {
	return rel == prefix || strings.HasPrefix(rel, prefix+"/")
}

// IsStdlibImport 判断导入路径是否属于 Go 标准库包。
// 按 Go 工具链约定，首段路径不含 '.' 且非 "C" 的导入路径视为标准库。
func IsStdlibImport(impPath string) bool {
	if impPath == "" || impPath == "C" {
		return false
	}
	head, _, _ := strings.Cut(impPath, "/")
	return !strings.Contains(head, ".")
}

// IsCoreLayer 判断给定层级是否位于 core/ 模块内部。
func IsCoreLayer(layer Layer) bool {
	return layer >= LayerCoreDomain && layer <= LayerCoreOther
}

// AllowContextValue 判断包是否位于 context.WithValue / ctx.Value 白名单内。
func AllowContextValue(info PkgInfo) bool {
	return !info.IsExternalTest && info.Layer == LayerCoreFoundationTrace
}

// AllowOSFSPrimitives 判断包是否位于裸 OS 文件/锁/ACL/os.Root/SocketSlot 白名单内。
func AllowOSFSPrimitives(info PkgInfo) bool {
	return !info.IsExternalTest && info.Layer == LayerCoreOSFS
}

// AllowSysExecEnv 判断包是否位于环境变量与外部进程执行白名单内。
func AllowSysExecEnv(info PkgInfo) bool {
	return !info.IsExternalTest && info.Layer == LayerHostSys
}

// AllowNolint 判断包是否位于 AGENTS.md §3 规定的行内 //nolint: 特权白名单包集合内。
func AllowNolint(info PkgInfo) bool {
	if info.IsExternalTest {
		return false
	}
	switch info.Layer {
	case LayerCoreOSFS,
		LayerCoreFoundationConc,
		LayerCoreFoundationTrace,
		LayerHostSys,
		LayerHostVault,
		LayerCoreSSHNetDial:
		return true
	case LayerCoreDomain:
		return matchBaseSubpkg(info.BasePath, ModulePrefix+"/core/domain/secret")
	default:
		return false
	}
}

func matchBaseSubpkg(basePath, prefix string) bool {
	return basePath == prefix || strings.HasPrefix(basePath, prefix+"/")
}
