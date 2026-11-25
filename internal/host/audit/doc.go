// Package audit 实现 XOps v2 本地 Fail-Closed JSONL 审计日志与 O(1) 跨进程崩溃对账适配器
// （ports.AuditSink 与 ports.AuditReconciler，ADR-008 / RFC §3.4 / Plan §4 #4 & #5）。
//
// 核心工程与安全不变量：
//   - 所有文件 I/O、内核文件锁与安全删锁严格经由 ports.ScopedRootFS + core/osfs 完成，
//     全包零裸 os.* 绕过、零裸 go 语句（锁持有协程受 core/conc.Nursery 监督）、零 //nolint:；
//   - ~/.xops/run/<ProcessInstanceID>.lock 严格遵循只追加协议：StageOperation 追加 "+<opID>\n"，
//     UnstageOperation 追加 "-<opID>\n"，仅在内存活跃操作集合归零时调用 Truncate(0) 并紧跟
//     Seek(0, io.SeekStart) + Sync()，防止 O_RDWR 句柄在旧偏移处产生稀疏 NUL 空洞；
//   - 启动期 O(1) 零扫描快路径：无死亡进程 .lock 时完全不打开、不扫描 audit.jsonl；
//   - 崩溃慢路径经非阻塞独占 TryLock 认领死亡锁、按 +/- 差集与 audit.jsonl 核验未闭合操作后，
//     在短生命周期跨进程旁路锁 audit.jsonl.lock 下补写 AbortedByCrash（json/v2 Deterministic(true)），
//     并经 osfs.RemoveLockedFileSafely 执行三平台（含 Windows）安全删锁。
package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/ports"
)

const (
	defaultAuditFileName     = "audit.jsonl"
	defaultRunDirName        = "run"
	auditFilePerm            = fs.FileMode(0o600)
	runDirPerm               = fs.FileMode(0o700)
	defaultMaxAuditReadBytes = int64(64 << 20)  // 崩溃慢路径单次读取 audit.jsonl 默认上限 64 MiB
	maxAllowedAuditReadBytes = int64(256 << 20) // audit.jsonl 读取硬上限 256 MiB
	defaultMaxLockReadBytes  = int64(4 << 20)   // 单个死亡 .lock 文件读取默认上限 4 MiB
	maxAllowedLockReadBytes  = int64(32 << 20)  // 单个 .lock 文件读取硬上限 32 MiB
)

// 本包导出的规范化哨兵错误，供调用方与诊断层精确识别审计日志损坏故障。
var (
	// ErrCorruptAuditLog 表示审计 JSONL 文件包含无法反序列化或校验失败的损坏记录。
	ErrCorruptAuditLog = errors.New("audit: 审计日志记录损坏或格式非法")
)

// SinkSpec 是构造 FileSink（ports.AuditSink）的显式入参规格。
type SinkSpec struct {
	// ScopedFS 为必选沙箱文件系统端口（生产使用 osfs.NewScopedRootFS()）。
	ScopedFS ports.ScopedRootFS
	// RootDir 为必选本地根目录（通常为 ~/.xops）。
	// 须满足 INV-A4 私有目录契约：尚未存在时由 EnsureRoot(0o700) 以 Owner-Only DACL 安全创建，
	// 已存在时须具备仅当前所有者可访问权限（如 Windows 受保护 Owner-Only DACL）。
	RootDir pathalg.LocalDir
	// ProcessID 为当前 Engine 实例的唯一进程标识（映射 run/<ProcessID>.lock）。
	ProcessID ports.ProcessInstanceID
	// AuditFile 可选覆盖审计日志相对路径（默认 "audit.jsonl"）。
	AuditFile algebraic.Option[pathalg.LocalRootedDest]
	// RunDir 可选覆盖活跃锁目录相对路径（默认 "run"）。
	RunDir algebraic.Option[pathalg.LocalRootedDest]
}

// ReconcilerSpec 是构造 FileReconciler（ports.AuditReconciler）的显式入参规格。
type ReconcilerSpec struct {
	// ScopedFS 为必选沙箱文件系统端口。
	ScopedFS ports.ScopedRootFS
	// RootDir 为必选本地根目录（通常为 ~/.xops，须与对应 FileSink 指向同一私有根目录）。
	RootDir pathalg.LocalDir
	// AuditFile 可选覆盖审计日志相对路径（默认 "audit.jsonl"）。
	AuditFile algebraic.Option[pathalg.LocalRootedDest]
	// RunDir 可选覆盖活跃锁目录相对路径（默认 "run"）。
	RunDir algebraic.Option[pathalg.LocalRootedDest]
	// MaxAuditBytes 限制崩溃慢路径读取 audit.jsonl 的字节上限（0 使用默认 64 MiB，负数失败关闭）。
	MaxAuditBytes int64
	// MaxLockBytes 限制单次读取死亡 .lock 文件的字节上限（0 使用默认 4 MiB，负数失败关闭）。
	MaxLockBytes int64
}

func zeroVal[T any]() (z T) { return z }

func resolveAuditPaths(auditOpt, runOpt algebraic.Option[pathalg.LocalRootedDest]) (auditDest, runDest pathalg.LocalRootedDest, err error) {
	if a, ok := auditOpt.Get(); ok {
		if !a.IsValid() {
			return zeroVal[pathalg.LocalRootedDest](), zeroVal[pathalg.LocalRootedDest](), fmt.Errorf("%w: AuditFile 路径无效", ports.ErrInvalidArgument)
		}
		auditDest = a
	} else {
		auditDest, err = pathalg.ParseLocalRootedDest(defaultAuditFileName)
		if err != nil {
			return zeroVal[pathalg.LocalRootedDest](), zeroVal[pathalg.LocalRootedDest](), err
		}
	}
	if r, ok := runOpt.Get(); ok {
		if !r.IsValid() {
			return zeroVal[pathalg.LocalRootedDest](), zeroVal[pathalg.LocalRootedDest](), fmt.Errorf("%w: RunDir 路径无效", ports.ErrInvalidArgument)
		}
		runDest = r
	} else {
		runDest, err = pathalg.ParseLocalRootedDest(defaultRunDirName)
		if err != nil {
			return zeroVal[pathalg.LocalRootedDest](), zeroVal[pathalg.LocalRootedDest](), err
		}
	}
	return auditDest, runDest, nil
}

// replayLockLog 按只追加 +/- 协议重放死亡进程的 .lock 日志内容，返回按 OperationID 升序排列的未闭合操作集合。
// 若遇 SIGKILL 造成尾行截断或空行，安全忽略不完整片段（未闭合的 +opID 仍需慢路径核对 audit.jsonl）。
func replayLockLog(raw []byte) []security.OperationID {
	active := make(map[security.OperationID]struct{})
	for line := range bytes.SplitSeq(raw, []byte{'\n'}) {
		s := strings.TrimSpace(strings.TrimSuffix(string(line), "\r"))
		if len(s) < 2 {
			continue
		}
		prefix, body := s[0], s[1:]
		if prefix != '+' && prefix != '-' {
			continue
		}
		opID, err := security.ParseOperationID(body)
		if err != nil {
			continue
		}
		if prefix == '+' {
			active[opID] = struct{}{}
		} else {
			delete(active, opID)
		}
	}
	if len(active) == 0 {
		return nil
	}
	ops := slices.Collect(maps.Keys(active))
	slices.SortFunc(ops, security.OperationID.Compare)
	return ops
}
