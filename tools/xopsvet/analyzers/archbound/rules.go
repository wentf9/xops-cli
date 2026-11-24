package archbound

import (
	"fmt"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

// checkImportAllowed 按单个文件是否为测试源码分别核验导入路径：
// 测试文件额外放行 testing、外置 *_test 对被测主包的反向导入，以及授权层的 sim/tck，
// 但同包生产代码与测试文件仍受所属层级（如 core/domain/** 禁 os/sync/reflect）约束。
func checkImportAllowed(src vetutil.PkgInfo, isTest bool, impPath string) (string, bool) {
	if impPath == "C" {
		return "禁止导入 cgo 伪包 \"C\"", false
	}
	if isTest && isCommonTestImportAllowed(src, impPath) {
		return "", true
	}
	if vetutil.IsStdlibImport(impPath) {
		return checkStdlibImport(src, impPath)
	}
	dst := vetutil.ClassifyPackage(impPath)
	if !dst.IsXops {
		return checkExternalImport(src, impPath)
	}
	return checkInternalImport(src, dst, impPath)
}

// isCommonTestImportAllowed 放行测试专用依赖，严格区分领域层/未知层与其他层：
//   - 全仓测试放行 testing / testing/* 以及外置 *_test 对被测主包的反向导入；
//   - 非 domain 且非 LayerCoreOther 的测试额外放行 core/conc 与 go.uber.org/goleak；
//   - core/internal/sim 仅放行给 core/ 内非 domain/conc/other 层的测试；
//   - core/ports/tck 仅放行给已登记的适配器层测试。
func isCommonTestImportAllowed(src vetutil.PkgInfo, impPath string) bool {
	if impPath == "testing" || strings.HasPrefix(impPath, "testing/") {
		return true
	}
	if src.IsExternalTest && impPath == src.BasePath {
		return true
	}
	if src.Layer != vetutil.LayerCoreDomain && src.Layer != vetutil.LayerCoreOther {
		if impPath == vetutil.ModulePrefix+"/core/conc" || impPath == "go.uber.org/goleak" {
			return true
		}
	}
	if impPath == vetutil.ModulePrefix+"/core/internal/sim" {
		return vetutil.IsCoreLayer(src.Layer) &&
			src.Layer != vetutil.LayerCoreDomain &&
			src.Layer != vetutil.LayerCoreConc &&
			src.Layer != vetutil.LayerCoreOther
	}
	return isAdapterForTCK(src.Layer) && impPath == vetutil.ModulePrefix+"/core/ports/tck"
}

func isAdapterForTCK(layer vetutil.Layer) bool {
	if isSSHNetLayer(layer) {
		return true
	}
	switch layer {
	case vetutil.LayerCoreOSFS,
		vetutil.LayerCoreSim,
		vetutil.LayerHostSys,
		vetutil.LayerHostVault,
		vetutil.LayerHostOther:
		return true
	default:
		return false
	}
}

func checkStdlibImport(src vetutil.PkgInfo, impPath string) (string, bool) {
	switch src.Layer {
	case vetutil.LayerCoreDomain:
		if !isDomainAllowedStdlib(src.BasePath, impPath) {
			return fmt.Sprintf("core/domain/** 禁止导入非白名单标准库 %q", impPath), false
		}
		return "", true
	case vetutil.LayerCorePorts:
		return checkPortsStdlib(impPath, false)
	case vetutil.LayerCorePortsTCK:
		return checkPortsStdlib(impPath, true)
	case vetutil.LayerCoreEvents:
		if isEventsBannedStdlib(impPath) {
			return fmt.Sprintf("core/events 禁止导入系统/网络标准库 %q", impPath), false
		}
		return "", true
	case vetutil.LayerCoreOSFS:
		if strings.HasPrefix(impPath, "net/") || impPath == "os/exec" {
			return fmt.Sprintf("core/osfs 禁止导入网络子包或进程执行标准库 %q", impPath), false
		}
		return "", true
	case vetutil.LayerCoreConc, vetutil.LayerCoreFoundationActor:
		if isConcOrActorBannedStdlib(impPath) {
			return fmt.Sprintf("core/conc 与 core/internal/foundation/actor 禁止导入 I/O、反射或随机标准库 %q", impPath), false
		}
		return "", true
	case vetutil.LayerCoreFoundationTrace, vetutil.LayerCoreFoundationOther:
		if impPath == "os/exec" || impPath == "net/http" {
			return fmt.Sprintf("core/internal/foundation/** 禁止导入 %q", impPath), false
		}
		return "", true
	case vetutil.LayerCoreOther:
		return fmt.Sprintf("未知 core/ 包路径 %q，未在 RFC §2.1/§2.3 授权包清单内", src.BasePath), false
	default:
		return "", true
	}
}

func checkPortsStdlib(impPath string, allowTesting bool) (string, bool) {
	if impPath == "os/exec" || impPath == "syscall" || impPath == "unsafe" {
		return fmt.Sprintf("core/ports 禁止导入底层系统标准库 %q", impPath), false
	}
	if !allowTesting && (impPath == "testing" || strings.HasPrefix(impPath, "testing/")) {
		return fmt.Sprintf("core/ports 生产代码禁止导入 %q", impPath), false
	}
	return "", true
}

func isEventsBannedStdlib(impPath string) bool {
	return impPath == "os" ||
		strings.HasPrefix(impPath, "os/") ||
		impPath == "net" ||
		strings.HasPrefix(impPath, "net/") ||
		impPath == "syscall" ||
		impPath == "unsafe"
}

// isConcOrActorBannedStdlib 强制 core/conc 与 core/internal/foundation/actor 维持纯内存非 I/O 不变量，
// 放行 runtime/debug、time、sync、sync/atomic 等纯并发/调度标准库，禁止系统 I/O、网络、反射与随机源。
func isConcOrActorBannedStdlib(impPath string) bool {
	return isEventsBannedStdlib(impPath) ||
		impPath == "reflect" ||
		impPath == "math/rand" ||
		strings.HasPrefix(impPath, "math/rand/")
}

// isDomainAllowedStdlib 精确匹配 RFC v2.3.2 §2.3 为 core/domain/** 划定的 29 个纯函数标准库白名单，
// 并按子包隔离授予专属例外：core/domain/option 额外放行 crypto/sha1（OpenSSH %C 哈希），
// core/domain/secret 额外放行 runtime/secret（goexperiment.runtimesecret 擦除钩子）。
func isDomainAllowedStdlib(basePath, impPath string) bool {
	if impPath == "crypto/sha1" {
		return matchBasePrefix(basePath, vetutil.ModulePrefix+"/core/domain/option")
	}
	if impPath == "runtime/secret" {
		return matchBasePrefix(basePath, vetutil.ModulePrefix+"/core/domain/secret")
	}
	switch impPath {
	case "bytes",
		"cmp",
		"crypto/sha256",
		"crypto/subtle",
		"encoding",
		"encoding/base64",
		"encoding/binary",
		"encoding/hex",
		"encoding/json/jsontext",
		"encoding/json/v2",
		"errors",
		"fmt",
		"hash",
		"io",
		"iter",
		"maps",
		"math",
		"math/bits",
		"net/netip",
		"path",
		"regexp",
		"slices",
		"sort",
		"strconv",
		"strings",
		"time",
		"unicode",
		"unicode/utf8",
		"unicode/utf16":
		return true
	default:
		return false
	}
}

func matchBasePrefix(basePath, prefix string) bool {
	return basePath == prefix || strings.HasPrefix(basePath, prefix+"/")
}

func checkExternalImport(src vetutil.PkgInfo, impPath string) (string, bool) {
	switch src.Layer {
	case vetutil.LayerCoreDomain:
		if impPath == "golang.org/x/text/unicode/norm" {
			return "", true
		}
		return fmt.Sprintf("当前架构层禁止导入外部第三方包 %q", impPath), false
	case vetutil.LayerCorePortsTCK:
		if impPath == "go.uber.org/goleak" {
			return "", true
		}
		return fmt.Sprintf("当前架构层禁止导入外部第三方包 %q", impPath), false
	case vetutil.LayerCorePorts,
		vetutil.LayerCoreEvents,
		vetutil.LayerCoreConc,
		vetutil.LayerCoreFoundationActor,
		vetutil.LayerCoreFoundationTrace,
		vetutil.LayerCoreFoundationOther,
		vetutil.LayerCorePool,
		vetutil.LayerCoreGate,
		vetutil.LayerCoreUsecase,
		vetutil.LayerCoreSim,
		vetutil.LayerCoreOther:
		return fmt.Sprintf("当前架构层禁止导入外部第三方包 %q", impPath), false
	default:
		return "", true
	}
}

func checkInternalImport(src, dst vetutil.PkgInfo, impPath string) (string, bool) {
	if isInternalLayerAllowed(src.Layer, dst.Layer) {
		return "", true
	}
	if src.Layer == vetutil.LayerCoreOther {
		return fmt.Sprintf("未知 core/ 包路径 %q，未在 RFC §2.1/§2.3 授权包清单内", src.BasePath), false
	}
	return fmt.Sprintf("架构边界违规：当前层禁止导入 %q", impPath), false
}

// isInternalLayerAllowed 按 ADR-001 / RFC v2.3.2 §2.3 单向依赖矩阵裁决仓内包间导入合法性，
// 未登记的新增包或 LayerUnknown 一律走 fail-closed 拒绝分支。
func isInternalLayerAllowed(src, dst vetutil.Layer) bool {
	if dst == vetutil.LayerUnknown {
		return false
	}
	if isCoreBasicLayerAllowed(src, dst) {
		return true
	}
	return isCoreRuntimeOrRootLayerAllowed(src, dst)
}

func isCoreBasicLayerAllowed(src, dst vetutil.Layer) bool {
	switch src {
	case vetutil.LayerCoreDomain:
		return dst == vetutil.LayerCoreDomain
	case vetutil.LayerCorePorts:
		return dst == vetutil.LayerCoreDomain || dst == vetutil.LayerCorePorts
	case vetutil.LayerCorePortsTCK:
		return dst == vetutil.LayerCoreDomain || dst == vetutil.LayerCorePorts || dst == vetutil.LayerCorePortsTCK || dst == vetutil.LayerCoreConc
	case vetutil.LayerCoreEvents:
		return dst == vetutil.LayerCoreDomain || dst == vetutil.LayerCoreEvents
	case vetutil.LayerCoreOSFS:
		return dst == vetutil.LayerCoreDomain || dst == vetutil.LayerCorePorts || dst == vetutil.LayerCoreOSFS
	case vetutil.LayerCoreConc:
		return dst == vetutil.LayerCoreConc
	case vetutil.LayerCoreFoundationActor, vetutil.LayerCoreFoundationTrace, vetutil.LayerCoreFoundationOther:
		return dst == vetutil.LayerCoreDomain || isFoundationLayer(dst)
	default:
		return false
	}
}

func isCoreRuntimeOrRootLayerAllowed(src, dst vetutil.Layer) bool {
	if isSSHNetLayer(src) {
		return isCommonCoreBase(dst) || dst == vetutil.LayerCoreOSFS || isSSHNetLayer(dst)
	}
	switch src {
	case vetutil.LayerCorePool:
		return isCommonCoreBase(dst) || dst == vetutil.LayerCorePool
	case vetutil.LayerCoreGate:
		return isCommonCoreBase(dst) || dst == vetutil.LayerCoreGate
	case vetutil.LayerCoreUsecase:
		return isCommonCoreBase(dst) || dst == vetutil.LayerCorePool || dst == vetutil.LayerCoreGate || dst == vetutil.LayerCoreUsecase
	case vetutil.LayerCoreMCPRuntime:
		return isCommonCoreBase(dst) || dst == vetutil.LayerCoreGate || dst == vetutil.LayerCoreUsecase || dst == vetutil.LayerCoreMCPRuntime
	case vetutil.LayerCoreSim:
		return isCommonCoreBase(dst) || dst == vetutil.LayerCoreSim
	case vetutil.LayerCoreEngine:
		// 生产核心门面禁止引入测试契约夹具（tck）与确定性仿真器（sim），保证 0 生产二进制可达。
		return vetutil.IsCoreLayer(dst) &&
			dst != vetutil.LayerCoreOther &&
			dst != vetutil.LayerCorePortsTCK &&
			dst != vetutil.LayerCoreSim
	default:
		return isHostOrEntryLayerAllowed(src, dst)
	}
}

func isHostOrEntryLayerAllowed(src, dst vetutil.Layer) bool {
	switch src {
	case vetutil.LayerHostSys, vetutil.LayerHostVault, vetutil.LayerHostOther:
		return dst == vetutil.LayerCoreDomain ||
			dst == vetutil.LayerCorePorts ||
			dst == vetutil.LayerCoreOSFS ||
			dst == vetutil.LayerCoreConc ||
			isHostLayer(dst)
	case vetutil.LayerEntry:
		return dst == vetutil.LayerCoreDomain ||
			dst == vetutil.LayerCoreEvents ||
			dst == vetutil.LayerCoreConc ||
			dst == vetutil.LayerCoreEngine ||
			dst == vetutil.LayerEntry
	case vetutil.LayerCmdXops:
		return dst == vetutil.LayerCoreDomain ||
			dst == vetutil.LayerCorePorts ||
			dst == vetutil.LayerCoreEvents ||
			dst == vetutil.LayerCoreOSFS ||
			dst == vetutil.LayerCoreConc ||
			dst == vetutil.LayerCoreEngine ||
			isHostLayer(dst) ||
			dst == vetutil.LayerEntry ||
			dst == vetutil.LayerCmdXops
	case vetutil.LayerToolsXopsvet:
		return dst == vetutil.LayerToolsXopsvet
	default:
		return false
	}
}

func isCommonCoreBase(dst vetutil.Layer) bool {
	return dst == vetutil.LayerCoreDomain ||
		dst == vetutil.LayerCorePorts ||
		dst == vetutil.LayerCoreEvents ||
		dst == vetutil.LayerCoreConc ||
		isFoundationLayer(dst)
}

func isFoundationLayer(dst vetutil.Layer) bool {
	return dst == vetutil.LayerCoreFoundationActor ||
		dst == vetutil.LayerCoreFoundationTrace ||
		dst == vetutil.LayerCoreFoundationOther
}

func isSSHNetLayer(layer vetutil.Layer) bool {
	return layer == vetutil.LayerCoreSSHNetDial ||
		layer == vetutil.LayerCoreSSHNetPriv ||
		layer == vetutil.LayerCoreSSHNetOther
}

func isHostLayer(dst vetutil.Layer) bool {
	return dst == vetutil.LayerHostSys || dst == vetutil.LayerHostVault || dst == vetutil.LayerHostOther
}
