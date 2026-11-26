// Package transfer 实现 XOps v2 全量文件传输与远端文件用例服务（ADR-007 / ADR-008 / ADR-009 / ADR-016 / Plan P3-T3）。
//
// 核心交付范围与安全不变量：
//   - 并行分片 SCP（SCPUpload / SCPDownload）：受 core/conc.Nursery 监督，支持断点续传、NoClobber、Lstat 悬空软链校验、
//     单次容器展开（INV-B4）、软链策略 (b) 全图与碰撞校验（INV-B2）及 Chtimes 时间戳保留；显式隔离 OperatorReadFS
//     （缺席 Fail-Closed）与 ScopedRootFS，SFTP / 原子文件 / 下载 / MCP 流式路径零 OperatorReadFS 依赖；
//   - SFTP 工作区：列目录、创建目录、权限/时间修改、stat/lstat/realpath/readlink，严格隔离 Remove（文件/软链）与 RemoveDir（空目录）；
//   - 远端原子操作（ReadFile / WriteFile / PatchFile / Stat / RenameFile）：消费 RemoteWriteSpec / RemoteRenameSpec 与 FSTAT 锚定防 Lost Update；
//   - MCP HTTP 10 GiB 流式传输与双代崩溃恢复：由 TransferFSM / JournalStore / RecoverTransferFromDualJournal 驱动，
//     长会话经 pool.RegisterLeaseHandleWith 托管，全路径 gate.WithAuthorized 包裹 pool.WithLease。
package transfer

import (
	"errors"
	"io/fs"
	"time"
)

const (
	defaultChunkSize         int64       = 1 << 20
	minChunkSize             int64       = 4 << 10
	defaultConcurrency                   = 4
	maxConcurrency                       = 16
	defaultMaxReadBytes      int64       = 16 << 20
	maxAtomicReadBytes       int64       = 64 << 20
	defaultMaxRecursiveFiles             = 10000
	maxRecursiveFilesLimit               = 100000
	maxRemoteCanonicalDepth              = 128
	defaultRemoteFilePerm    fs.FileMode = 0o644
	defaultLocalStagePerm    fs.FileMode = 0o600
	defaultDirPerm           fs.FileMode = 0o755
	terminalEventEmitTimeout             = 50 * time.Millisecond
)

// 本包导出的不可变哨兵错误，供 core/engine、mcpruntime 与测试经 errors.Is 精确区分故障类别。
var (
	ErrNilContext              = errors.New("usecase/transfer: context 不能为 nil")
	ErrInvalidConfig           = errors.New("usecase/transfer: 无效的 ServiceConfig 配置")
	ErrServiceNotInitialized   = errors.New("usecase/transfer: Service 未初始化")
	ErrInvalidRequest          = errors.New("usecase/transfer: 无效的传输请求")
	ErrOperatorReadUnavailable = errors.New("usecase/transfer: 未配置 OperatorReadFS，拒绝读取操作员本地路径")
	ErrScopedFSUnavailable     = errors.New("usecase/transfer: 未配置 ScopedRootFS")
	ErrJournalStoreUnavailable = errors.New("usecase/transfer: 未配置 JournalStore")
	ErrPatchConflict           = errors.New("usecase/transfer: 远端文件补丁应用冲突")
	ErrPatchNoMatch            = errors.New("usecase/transfer: 补丁目标文本未找到匹配项")
	ErrPatchAmbiguous          = errors.New("usecase/transfer: 补丁目标文本存在多处歧义匹配")
	ErrUncertainCommit         = errors.New("usecase/transfer: 传输处于 TransferUncertainCommit，严禁重试或清理")
	ErrCorruptJournal          = errors.New("usecase/transfer: 传输 Journal 损坏或违反恢复不变量")
	ErrTransferNotFound        = errors.New("usecase/transfer: 传输任务不存在")
	ErrTransferHandleMismatch  = errors.New("usecase/transfer: 传输托管句柄与目标任务不匹配")
	ErrSymlinkPolicyDenied     = errors.New("usecase/transfer: 符号链接被安全策略拒绝")
	ErrRemoteObjectUnsupported = errors.New("usecase/transfer: 远端对象类型不受支持")
	ErrDigestMismatch          = errors.New("usecase/transfer: SHA-256 摘要校验不匹配")
)

func zeroVal[T any]() (z T) { return z }
func pickIf[T any](cond bool, yes, no T) T {
	if cond {
		return yes
	}
	return no
}
func isValidRFC3339Time(t time.Time) bool {
	return !t.IsZero() && t.UTC().Year() >= 1 && t.UTC().Year() <= 9999
}
func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
