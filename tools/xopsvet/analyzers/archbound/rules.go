package archbound

import (
	"fmt"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/tools/xopsvet/internal/vetutil"
)

// checkImportAllowed 按单个文件是否为测试源码分别核验导入路径：
// 测试文件额外放行 testing、外置 *_test 对被测主包的反向导入，以及授权层的 sim/tck，
// 但同包生产代码与测试文件仍受所属层级（如 core/domain/**、conc/actor/trace 纯非 I/O）约束。
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

func isCommonTestImportAllowed(src vetutil.PkgInfo, impPath string) bool {
	if isUnregisteredCoreLayer(src.Layer) {
		return false
	}
	if impPath == "testing" || strings.HasPrefix(impPath, "testing/") || (src.IsExternalTest && impPath == src.BasePath) {
		return true
	}
	if src.Layer != vetutil.LayerCoreDomain && !isUnregisteredCoreLayer(src.Layer) &&
		(impPath == vetutil.ModulePrefix+"/core/conc" || impPath == "go.uber.org/goleak") {
		return true
	}
	if impPath == vetutil.ModulePrefix+"/core/internal/sim" {
		return vetutil.IsCoreLayer(src.Layer) && src.Layer != vetutil.LayerCoreDomain &&
			src.Layer != vetutil.LayerCoreConc && !isUnregisteredCoreLayer(src.Layer)
	}
	return (isSSHNetLayer(src.Layer) || isHostLayer(src.Layer) || src.Layer == vetutil.LayerCoreOSFS || src.Layer == vetutil.LayerCoreSim) &&
		impPath == vetutil.ModulePrefix+"/core/ports/tck"
}

func isUnregisteredCoreLayer(layer vetutil.Layer) bool {
	return layer == vetutil.LayerCoreOther || layer == vetutil.LayerCoreFoundationOther
}

func checkStdlibImport(src vetutil.PkgInfo, impPath string) (string, bool) {
	switch src.Layer {
	case vetutil.LayerCoreDomain:
		if !isDomainAllowedStdlib(src.BasePath, impPath) {
			return fmt.Sprintf("core/domain/** 禁止导入非白名单标准库 %q", impPath), false
		}
	case vetutil.LayerCorePorts, vetutil.LayerCorePortsTCK:
		return checkPortsStdlibImport(src.Layer, impPath)
	case vetutil.LayerCoreEvents:
		if isEventsBannedStdlib(impPath) {
			return fmt.Sprintf("core/events 禁止导入系统/网络标准库 %q", impPath), false
		}
	case vetutil.LayerCoreOSFS:
		if strings.HasPrefix(impPath, "net/") || impPath == "os/exec" {
			return fmt.Sprintf("core/osfs 禁止导入网络子包或进程执行标准库 %q", impPath), false
		}
		if slices.Contains([]string{"crypto/tls", "log/syslog", "reflect"}, impPath) {
			return fmt.Sprintf("core/osfs 禁止导入 TLS、系统日志或反射标准库 %q", impPath), false
		}
	case vetutil.LayerCoreConc, vetutil.LayerCoreFoundationActor, vetutil.LayerCoreFoundationTrace:
		if isPureMemoryStdlibBanned(impPath) {
			return fmt.Sprintf("core/conc 与 core/internal/foundation/{actor,trace} 禁止导入非纯内存 I/O、反射或随机标准库 %q", impPath), false
		}
	case vetutil.LayerCoreOther:
		return fmt.Sprintf("未知 core/ 包路径 %q，未在 RFC §2.1/§2.3 授权包清单内", src.BasePath), false
	case vetutil.LayerCoreFoundationOther:
		return fmt.Sprintf("未登记 core/internal/foundation 子包 %q，未在 RFC §2.1/§2.3 授权包清单内", src.BasePath), false
	}
	return "", true
}

func checkPortsStdlibImport(layer vetutil.Layer, impPath string) (string, bool) {
	if slices.Contains([]string{"os/exec", "syscall", "unsafe"}, impPath) {
		return fmt.Sprintf("core/ports 禁止导入底层系统标准库 %q", impPath), false
	}
	if layer == vetutil.LayerCorePorts && (impPath == "testing" || strings.HasPrefix(impPath, "testing/")) {
		return fmt.Sprintf("core/ports 生产代码禁止导入 %q", impPath), false
	}
	return "", true
}

func isEventsBannedStdlib(impPath string) bool {
	return impPath == "os" || strings.HasPrefix(impPath, "os/") ||
		impPath == "net" || strings.HasPrefix(impPath, "net/") ||
		impPath == "crypto/tls" || impPath == "syscall" || impPath == "unsafe"
}

// isPureMemoryStdlibBanned 强制 core/conc、foundation/actor 与 foundation/trace 维持纯内存非 I/O 不变量。
func isPureMemoryStdlibBanned(impPath string) bool {
	return isEventsBannedStdlib(impPath) || strings.HasPrefix(impPath, "math/rand/") ||
		slices.Contains([]string{"reflect", "math/rand", "crypto/rand", "path/filepath", "io/ioutil", "log", "log/syslog", "flag", "mime", "plugin", "embed"}, impPath)
}

// isDomainAllowedStdlib 精确匹配 RFC v2.3.3 §2.3 的 29 个纯函数标准库白名单及 option/secret 子包独占例外。
func isDomainAllowedStdlib(basePath, impPath string) bool {
	if impPath == "crypto/sha1" {
		return matchBasePrefix(basePath, vetutil.ModulePrefix+"/core/domain/option")
	}
	if impPath == "runtime/secret" {
		return matchBasePrefix(basePath, vetutil.ModulePrefix+"/core/domain/secret")
	}
	return slices.Contains([]string{
		"bytes", "cmp", "crypto/sha256", "crypto/subtle", "encoding", "encoding/base64",
		"encoding/binary", "encoding/hex", "encoding/json/jsontext", "encoding/json/v2",
		"errors", "fmt", "hash", "io", "iter", "maps", "math", "math/bits", "net/netip",
		"path", "regexp", "slices", "sort", "strconv", "strings", "time", "unicode", "unicode/utf8", "unicode/utf16",
	}, impPath)
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
	case vetutil.LayerCorePortsTCK:
		if impPath == "go.uber.org/goleak" {
			return "", true
		}
	case vetutil.LayerCoreOSFS:
		if impPath == "golang.org/x/sys/unix" || impPath == "golang.org/x/sys/windows" {
			return "", true
		}
	case vetutil.LayerCorePorts, vetutil.LayerCoreEvents, vetutil.LayerCoreConc,
		vetutil.LayerCoreFoundationActor, vetutil.LayerCoreFoundationTrace, vetutil.LayerCoreFoundationOther,
		vetutil.LayerCorePool, vetutil.LayerCoreGate, vetutil.LayerCoreUsecase, vetutil.LayerCoreSim, vetutil.LayerCoreOther:
	default:
		return "", true
	}
	return fmt.Sprintf("当前架构层禁止导入外部第三方包 %q", impPath), false
}

func checkInternalImport(src, dst vetutil.PkgInfo, impPath string) (string, bool) {
	if isInternalLayerAllowed(src.Layer, dst.Layer) {
		return "", true
	}
	if src.Layer == vetutil.LayerCoreOther {
		return fmt.Sprintf("未知 core/ 包路径 %q，未在 RFC §2.1/§2.3 授权包清单内", src.BasePath), false
	}
	if src.Layer == vetutil.LayerCoreFoundationOther {
		return fmt.Sprintf("未登记 core/internal/foundation 子包 %q，未在 RFC §2.1/§2.3 授权包清单内", src.BasePath), false
	}
	return fmt.Sprintf("架构边界违规：当前层禁止导入 %q", impPath), false
}

// isInternalLayerAllowed 按 ADR-001 / RFC v2.3.3 §2.3 单向依赖矩阵裁决仓内包间导入合法性。
func isInternalLayerAllowed(src, dst vetutil.Layer) bool {
	if dst == vetutil.LayerUnknown || isUnregisteredCoreLayer(dst) {
		return false
	}
	return isCoreBasicLayerAllowed(src, dst) || isCoreRuntimeOrRootLayerAllowed(src, dst)
}

func isCoreBasicLayerAllowed(src, dst vetutil.Layer) bool {
	switch src {
	case vetutil.LayerCoreDomain, vetutil.LayerCoreConc:
		return dst == src
	case vetutil.LayerCorePorts, vetutil.LayerCoreEvents, vetutil.LayerCoreFoundationTrace:
		return dst == vetutil.LayerCoreDomain || dst == src
	case vetutil.LayerCorePortsTCK:
		return slices.Contains([]vetutil.Layer{vetutil.LayerCoreDomain, vetutil.LayerCorePorts, vetutil.LayerCorePortsTCK, vetutil.LayerCoreConc}, dst)
	case vetutil.LayerCoreOSFS:
		return dst == vetutil.LayerCoreDomain || dst == vetutil.LayerCorePorts || dst == vetutil.LayerCoreOSFS
	case vetutil.LayerCoreFoundationActor:
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
	case vetutil.LayerCorePool, vetutil.LayerCoreGate, vetutil.LayerCoreSim:
		return isCommonCoreBase(dst) || dst == src
	case vetutil.LayerCoreUsecase:
		return isCommonCoreBase(dst) || slices.Contains([]vetutil.Layer{vetutil.LayerCorePool, vetutil.LayerCoreGate, vetutil.LayerCoreUsecase}, dst)
	case vetutil.LayerCoreMCPRuntime:
		return isCommonCoreBase(dst) || slices.Contains([]vetutil.Layer{vetutil.LayerCoreGate, vetutil.LayerCoreUsecase, vetutil.LayerCoreMCPRuntime}, dst)
	case vetutil.LayerCoreEngine:
		// 生产核心门面禁止引入 tck、sim 及任何未登记 core/foundation 层。
		return vetutil.IsCoreLayer(dst) && !isUnregisteredCoreLayer(dst) && dst != vetutil.LayerCorePortsTCK && dst != vetutil.LayerCoreSim
	default:
		return isHostOrEntryLayerAllowed(src, dst)
	}
}

func isHostOrEntryLayerAllowed(src, dst vetutil.Layer) bool {
	switch src {
	case vetutil.LayerHostSys, vetutil.LayerHostVault, vetutil.LayerHostOther:
		return isHostLayer(dst) || slices.Contains([]vetutil.Layer{vetutil.LayerCoreDomain, vetutil.LayerCorePorts, vetutil.LayerCoreOSFS, vetutil.LayerCoreConc}, dst)
	case vetutil.LayerEntry:
		return slices.Contains([]vetutil.Layer{vetutil.LayerCoreDomain, vetutil.LayerCoreEvents, vetutil.LayerCoreConc, vetutil.LayerCoreEngine, vetutil.LayerEntry}, dst)
	case vetutil.LayerCmdXops:
		return isHostLayer(dst) || slices.Contains([]vetutil.Layer{
			vetutil.LayerCoreDomain, vetutil.LayerCorePorts, vetutil.LayerCoreEvents,
			vetutil.LayerCoreOSFS, vetutil.LayerCoreConc, vetutil.LayerCoreEngine, vetutil.LayerEntry, vetutil.LayerCmdXops,
		}, dst)
	case vetutil.LayerToolsXopsvet:
		return dst == vetutil.LayerToolsXopsvet
	default:
		return false
	}
}

func isCommonCoreBase(dst vetutil.Layer) bool {
	return isFoundationLayer(dst) || slices.Contains([]vetutil.Layer{vetutil.LayerCoreDomain, vetutil.LayerCorePorts, vetutil.LayerCoreEvents, vetutil.LayerCoreConc}, dst)
}

func isFoundationLayer(dst vetutil.Layer) bool {
	return dst == vetutil.LayerCoreFoundationActor || dst == vetutil.LayerCoreFoundationTrace
}

func isSSHNetLayer(layer vetutil.Layer) bool {
	return layer == vetutil.LayerCoreSSHNetDial || layer == vetutil.LayerCoreSSHNetPriv || layer == vetutil.LayerCoreSSHNetOther
}

func isHostLayer(dst vetutil.Layer) bool {
	return dst == vetutil.LayerHostSys || dst == vetutil.LayerHostVault || dst == vetutil.LayerHostOther
}
