// Package transfer 实现 XOps v2 全量文件传输与远端文件用例服务（ADR-007 / ADR-008 / ADR-009 / ADR-016 / Plan P3-T3）。
//
// 核心交付范围与安全不变量：
//   - 并行分片 SCP（SCPUpload / SCPDownload）：受 core/conc.Nursery 监督，支持断点续传防稀疏空洞/换源校验、
//     NoClobber、Lstat 悬空软链校验、单次容器展开（INV-B4）、软链策略 (b) 全图与碰撞校验（INV-B2）及 Chtimes 时间戳保留；
//     显式隔离 OperatorReadFS（缺席 Fail-Closed）与 ScopedRootFS，SFTP / 原子文件 / 下载 / MCP 流式路径零 OperatorReadFS 依赖；
//   - SFTP 工作区：列目录、创建目录、权限/时间修改、stat/lstat/realpath/readlink，严格隔离 Remove（文件/软链）与 RemoveDir（空目录）；
//   - 远端原子操作（ReadFile / WriteFile / PatchFile / Stat / RenameFile）：消费 RemoteWriteSpec / RemoteRenameSpec 与 FSTAT 锚定防 Lost Update；
//   - MCP HTTP 10 GiB 流式传输与双代崩溃恢复：由 TransferFSM / JournalStore / RecoverTransferFromDualJournal 驱动，
//     长会话经 pool.RegisterLeaseHandleWith 托管，全路径 gate.WithAuthorized 包裹 pool.WithLease，严守三条恢复铁律与 INV-E5。
package transfer

import (
	"io/fs"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
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
	ErrNilContext              = domi18n.Sentinel(domi18n.KeyUCTransferNilContext)
	ErrInvalidConfig           = domi18n.Sentinel(domi18n.KeyUCTransferInvalidCfg)
	ErrServiceNotInitialized   = domi18n.Sentinel(domi18n.KeyUCTransferNotInit)
	ErrInvalidRequest          = domi18n.Sentinel(domi18n.KeyUCTransferInvalidReq)
	ErrOperatorReadUnavailable = domi18n.Sentinel(domi18n.KeyUCTransferOpReadUnav)
	ErrScopedFSUnavailable     = domi18n.Sentinel(domi18n.KeyUCTransferScopedUnav)
	ErrJournalStoreUnavailable = domi18n.Sentinel(domi18n.KeyUCTransferJournalUnav)
	ErrPatchConflict           = domi18n.Sentinel(domi18n.KeyUCTransferPatchConf)
	ErrPatchNoMatch            = domi18n.Sentinel(domi18n.KeyUCTransferPatchNoHit)
	ErrPatchAmbiguous          = domi18n.Sentinel(domi18n.KeyUCTransferPatchAmbig)
	ErrUncertainCommit         = domi18n.Sentinel(domi18n.KeyUCTransferUncertain)
	ErrCorruptJournal          = domi18n.Sentinel(domi18n.KeyUCTransferCorruptJrn)
	ErrTransferNotFound        = domi18n.Sentinel(domi18n.KeyUCTransferNotFound)
	ErrTransferHandleMismatch  = domi18n.Sentinel(domi18n.KeyUCTransferHandleDiff)
	ErrSymlinkPolicyDenied     = domi18n.Sentinel(domi18n.KeyUCTransferSymlinkDeny)
	ErrRemoteObjectUnsupported = domi18n.Sentinel(domi18n.KeyUCTransferRemoteUnsup)
	ErrDigestMismatch          = domi18n.Sentinel(domi18n.KeyUCTransferDigestDiff)
)

// ServiceConfig 定义 transfer.Service 的出站依赖与限流；MCP 路径物理上不注入 OperatorReadFS。
type ServiceConfig struct {
	Gate                                  gate.Authorizer      // 必填：能力门控授权器（ADR-008）
	Pool                                  *pool.Pool           // 必填：双通道纯内存 Actor 连接池（ADR-009）
	Clock                                 ports.Clock          // 必填：确定性时钟端口
	Entropy                               ports.Entropy        // 必填：显式熵源端口
	ScopedFS                              ports.ScopedRootFS   // 可选：沙箱本地文件系统端口
	OperatorReadFS                        ports.OperatorReadFS // 可选：操作员只读本地源端口（MCP 物理留 nil）
	Journals                              ports.JournalStore   // 可选：双代分片传输 WAL 端口
	SystemBus                             *events.SystemBus    // 可选：非阻塞诊断总线
	DefaultChunkSize, DefaultMaxReadBytes int64                // 可选：默认分片（1 MiB）/ 原子读上限（16 MiB）
	DefaultConcurrency                    int                  // 可选：并行 SCP 默认并发度（0 默认 4）
}

// CallBase 聚合受权请求共享的连接计划、节点标识、风险等级、审批凭据与隔离事件流。
type CallBase struct {
	Plan            plan.SealedConnectionPlan
	NodeID          string
	Risk            algebraic.Option[security.RiskLevel]
	Approval        algebraic.Option[gate.ApprovalSubmission]
	OperationStream *events.OperationStream
}

// TransferSessionOptions 聚合流式传输启动与恢复共享的本地/远端绑定、覆写护栏、权限与时间戳选项。
type TransferSessionOptions struct {
	LocalRoot                algebraic.Option[pathalg.LocalDir]
	RemoteSource             algebraic.Option[pathalg.RemotePath]
	NoClobber, PreserveTimes bool
	ExpectedAnchor           algebraic.Option[ports.RemoteFileAnchor]
	Perm                     algebraic.Option[fs.FileMode]
	ModTime                  algebraic.Option[time.Time]
}

// LocalUploadSourceKind 标识 SCP 上传本地源的双模态类别；零值 LocalUploadSourceInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type LocalUploadSourceKind uint8

const (
	LocalUploadSourceInvalid  LocalUploadSourceKind = iota // 未初始化零值（失败关闭）
	LocalUploadSourceOperator                              // 经 OperatorReadFS 读取的操作员本地源
	LocalUploadSourceScoped                                // 经 ScopedRootFS 读取的沙箱本地源（零 OperatorReadFS 依赖）
)

// IsValid / String 返回上传源模态合法性与文本名称。
func (k LocalUploadSourceKind) IsValid() bool {
	return k == LocalUploadSourceOperator || k == LocalUploadSourceScoped
}
func (k LocalUploadSourceKind) String() string {
	return pickIf(k == LocalUploadSourceOperator, "operator", pickIf(k == LocalUploadSourceScoped, "scoped", "invalid"))
}

// LocalUploadSource 封装 SCP 双模态不可变本地上传源规格；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type LocalUploadSource struct {
	kind          LocalUploadSourceKind
	operatorPath  pathalg.LocalSourcePath
	symlinkPolicy pathalg.SymlinkPolicy
	scopedRoot    pathalg.LocalDir
	scopedPath    pathalg.LocalRootedDest
	valid         bool
}

// NewOperatorUploadSource / NewScopedUploadSource 构造双模态不可变上传源规格（Scoped 零 OperatorReadFS 依赖）。
func NewOperatorUploadSource(src pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy) (LocalUploadSource, error) {
	ok := src.IsValid() && policy.IsValid()
	return pickIf(ok, LocalUploadSource{kind: LocalUploadSourceOperator, operatorPath: src, symlinkPolicy: policy, valid: true}, LocalUploadSource{}), pickIf[error](ok, nil, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "OperatorUploadSource")))
}
func NewScopedUploadSource(rootDir pathalg.LocalDir, rel pathalg.LocalRootedDest) (LocalUploadSource, error) {
	ok := rootDir.IsValid() && rel.IsValid()
	return pickIf(ok, LocalUploadSource{kind: LocalUploadSourceScoped, scopedRoot: rootDir, scopedPath: rel, valid: true}, LocalUploadSource{}), pickIf[error](ok, nil, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "ScopedUploadSource")))
}
func (s LocalUploadSource) IsValid() bool {
	return s.valid && pickIf(s.kind == LocalUploadSourceOperator, s.operatorPath.IsValid() && s.symlinkPolicy.IsValid(), s.kind == LocalUploadSourceScoped && s.scopedRoot.IsValid() && s.scopedPath.IsValid())
}
func (s LocalUploadSource) IsZero() bool { return !s.IsValid() }
func (s LocalUploadSource) Kind() LocalUploadSourceKind {
	return pickIf(s.IsValid(), s.kind, LocalUploadSourceInvalid)
}
func (s LocalUploadSource) BaseName() string {
	return pickIf(!s.IsValid(), "", pickIf(s.kind == LocalUploadSourceOperator, s.operatorPath.Base(), s.scopedPath.Base()))
}

// TextEdit 表示单条不可变远端原子补丁替换规则；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type TextEdit struct {
	oldText, newText  string
	replaceAll, valid bool
}

// NewTextEdit 校验旧文本非空后构造不可变 TextEdit。
func NewTextEdit(oldText, newText string, replaceAll bool) (TextEdit, error) {
	return pickIf(oldText != "", TextEdit{oldText: oldText, newText: newText, replaceAll: replaceAll, valid: true}, TextEdit{}), pickIf[error](oldText != "", nil, domi18n.EF(ErrInvalidRequest, domi18n.KeyCommonFieldEmpty, domi18n.Str("field", "TextEdit.OldText")))
}
func (e TextEdit) IsValid() bool    { return e.valid && e.oldText != "" }
func (e TextEdit) OldText() string  { return pickIf(e.IsValid(), e.oldText, "") }
func (e TextEdit) NewText() string  { return pickIf(e.IsValid(), e.newText, "") }
func (e TextEdit) ReplaceAll() bool { return e.IsValid() && e.replaceAll }

// SCPUploadRequest / SCPUploadResult / SCPDownloadRequest / SCPDownloadResult 描述并行分片 SCP DTO。
type (
	SCPUploadRequest struct {
		CallBase
		Source                                                                   LocalUploadSource
		RemoteDest                                                               pathalg.RemotePath
		Recursive, ExpandIntoDir, NoClobber, Resume, PreserveMode, PreserveTimes bool
		SymlinkPolicy                                                            pathalg.SymlinkPolicy
		Perm                                                                     algebraic.Option[fs.FileMode]
		ModTime                                                                  algebraic.Option[time.Time]
		ChunkSize                                                                int64
		Concurrency, MaxFiles                                                    int
		MaxTotalBytes                                                            uint64
		ExpectedDigest                                                           algebraic.Option[security.Digest]
	}
	SCPUploadResult struct {
		RemotePath                                        pathalg.RemotePath
		FilesUploaded, DirsCreated                        int
		BytesTransferred, ResumedBytes, ChunksTransferred int64
		Digest                                            security.Digest
		ModTimePreserved                                  bool
	}
	SCPDownloadRequest struct {
		CallBase
		RemoteSource                                pathalg.RemotePath
		LocalRoot                                   pathalg.LocalDir
		LocalDest                                   pathalg.LocalRootedDest
		Recursive, NoClobber, Resume, PreserveTimes bool
		SymlinkPolicy                               pathalg.SymlinkPolicy
		ChunkSize                                   int64
		Concurrency, MaxFiles                       int
		MaxTotalBytes                               uint64
		ExpectedDigest                              algebraic.Option[security.Digest]
	}
	SCPDownloadResult struct {
		LocalDest                                         pathalg.LocalRootedDest
		FilesDownloaded, DirsCreated, SymlinksCreated     int
		BytesTransferred, ResumedBytes, ChunksTransferred int64
		Digest                                            algebraic.Option[security.Digest]
		ModTimePreserved                                  bool
	}
)

// RemotePathRequest 及 SFTP 工作区、远端原子文件与 10 GiB 流式恢复请求与响应 DTO。
type (
	RemotePathRequest struct {
		CallBase
		Path pathalg.RemotePath
	}
	ListDirRequest   = RemotePathRequest
	RealPathRequest  = RemotePathRequest
	ReadLinkRequest  = RemotePathRequest
	RemoveRequest    = RemotePathRequest
	RemoveDirRequest = RemotePathRequest
	ListDirResult    struct {
		Path    pathalg.RemotePath
		Entries []ports.RemoteDirEntry
	}
	StatRequest struct {
		CallBase
		Path           pathalg.RemotePath
		FollowSymlinks bool
	}
	MkdirAllRequest struct {
		CallBase
		Path pathalg.RemotePath
		Perm algebraic.Option[fs.FileMode]
	}
	ChmodRequest struct {
		CallBase
		Path pathalg.RemotePath
		Perm fs.FileMode
	}
	ChtimesRequest struct {
		CallBase
		Path         pathalg.RemotePath
		Atime, Mtime time.Time
	}
	ReadFileRequest struct {
		CallBase
		Path     pathalg.RemotePath
		MaxBytes int64
	}
	ReadFileResult struct {
		Stat    ports.RemoteFileStat
		Content []byte
		Digest  security.Digest
	}
	WriteFileRequest struct {
		CallBase
		Path                     pathalg.RemotePath
		Content                  []byte
		Perm                     algebraic.Option[fs.FileMode]
		NoClobber, CreateParents bool
		ExpectedAnchor           algebraic.Option[ports.RemoteFileAnchor]
	}
	WriteFileResult struct {
		Stat         ports.RemoteFileStat
		BytesWritten int64
		Digest       security.Digest
	}
	PatchFileRequest struct {
		CallBase
		Path           pathalg.RemotePath
		Edits          []TextEdit
		ExpectedAnchor algebraic.Option[ports.RemoteFileAnchor]
		ExpectedDigest algebraic.Option[security.Digest]
		MaxBytes       int64
	}
	PatchFileResult struct {
		BeforeStat, AfterStat     ports.RemoteFileStat
		BeforeDigest, AfterDigest security.Digest
		Replacements              int
		BytesWritten              int64
	}
	RenameFileRequest struct {
		CallBase
		OldPath, NewPath pathalg.RemotePath
		NoClobber        bool
		ExpectedAnchor   algebraic.Option[ports.RemoteFileAnchor]
	}
	StartTransferRequest struct {
		CallBase
		TransferSessionOptions
		TransferID             algebraic.Option[security.OperationID]
		Dest                   fsm.TransferDest
		TotalBytes, Generation uint64
		ExpectedDigest         algebraic.Option[security.Digest]
		JournalVersion         fsm.JournalVersion
	}
	TransferHandleInfo struct {
		TransferID security.OperationID
		Handle     plan.ManagedHandle[plan.KindTransfer]
		Meta       fsm.TransferMeta
		State      fsm.TransferState
	}
	WriteTransferChunkRequest struct {
		CallBase
		Handle plan.ManagedHandle[plan.KindTransfer]
		Offset uint64
		Data   []byte
	}
	WriteTransferChunkResult struct {
		TransferID             security.OperationID
		NextOffset, TotalBytes uint64
		ChunkDigest            security.Digest
		StateKind              fsm.TransferStateKind
	}
	PullTransferChunkRequest struct {
		CallBase
		Handle        plan.ManagedHandle[plan.KindTransfer]
		MaxChunkBytes uint64
	}
	PullTransferChunkResult struct {
		TransferID                                  security.OperationID
		Offset, BytesPulled, NextOffset, TotalBytes uint64
		ChunkDigest                                 security.Digest
		StateKind                                   fsm.TransferStateKind
	}
	CommitTransferRequest struct {
		CallBase
		Handle plan.ManagedHandle[plan.KindTransfer]
	}
	CommitTransferResult struct {
		TransferID   security.OperationID
		State        fsm.TransferState
		ActualDigest algebraic.Option[security.Digest]
		Generation   uint64
	}
	AbortTransferRequest struct {
		CallBase
		Handle plan.ManagedHandle[plan.KindTransfer]
		Reason string
	}
	InspectTransferRequest struct {
		CallBase
		TransferID security.OperationID
		Handle     algebraic.Option[plan.ManagedHandle[plan.KindTransfer]]
	}
	TransferStatusSnapshot struct {
		TransferID             security.OperationID
		LiveHandle, IsTerminal bool
		Meta                   fsm.TransferMeta
		StateKind              fsm.TransferStateKind
		Offset, ChunkCount     uint64
	}
	RecoverTransferRequest struct {
		CallBase
		TransferID        security.OperationID
		PruneSuperseded   bool
		LocalRootForClean algebraic.Option[pathalg.LocalDir]
	}
	TransferRecoveryResult struct {
		TransferID        security.OperationID
		State             fsm.TransferState
		SelectedGen       uint64
		PrunedGenerations []uint64
		UncertainCommit   bool
		Effects           []fsm.TransferEffect
	}
	ResumeTransferRequest struct {
		CallBase
		TransferSessionOptions
		TransferID   security.OperationID
		StartNextGen bool
	}
	RecoverAllRequest           struct{ PruneSuperseded bool }
	RecoverAllAuthorizedRequest struct {
		PruneSuperseded bool
		Risk            algebraic.Option[security.RiskLevel]
		Approval        algebraic.Option[gate.ApprovalSubmission]
		OperationStream *events.OperationStream
	}
	TransferRecoveryEntry struct {
		TransferID security.OperationID
		Result     TransferRecoveryResult
		Err        error
	}
	RecoverAllResult struct{ Entries []TransferRecoveryEntry }
)
