// Package clikit 提供 internal/entry/cli 各命令族子包共享的极薄命令行底座
// （退出码映射、具名引擎能力窄接口、作用域引擎会话、规范 JSON/v2 编码与 OpenSSH 选项解析）。
//
// 核心架构与安全不变量：
//   - 仅依赖 core/{domain,events,engine,conc} 与 Go 标准库，严禁导入 internal/host/**、core/osfs 或 core/ports；
//   - 全包 0 init()、0 可变包级 var、0 裸 go 语句、0 os.Exit、0 行内 //nolint:；
//   - 所有 JSON 序列化 DTO 严禁裸用 time.Duration（统一使用 algebraic.Duration），严禁携带 *secret.SecretBox；
//   - 所有运行期回调（子入口、宿主只读文件、审计查询、工作目录解析）在为 nil 时严格失败关闭。
package clikit

import (
	"context"
	"io"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
)

// SentinelError 表示编译期不可变的字符串哨兵错误类型，保证跨包重导出时严格保持错误标识同一性且零可变包级状态。
type SentinelError string

// Error 实现标准 error 接口。
func (e SentinelError) Error() string { return string(e) }

// 规范进程退出码常量，全 CLI 入口统一消费。
const (
	// ExitOK 表示命令成功退出。
	ExitOK = 0
	// ExitGeneral 表示通用运行期错误、诊断不健康或资源关闭阶段故障。
	ExitGeneral = 1
	// ExitUsage 表示命令行子命令或选项参数语法错误。
	ExitUsage = 2
	// ExitSSHError 对齐 OpenSSH ssh(1) 约定，表示 SSH 建连、认证、启动前拒绝或未知终态故障。
	ExitSSHError = 255
	// ExitSignalBase 为 POSIX 信号终止退出码基址（128 + signal）。
	ExitSignalBase = 128
)

// 本包导出的不可变哨兵错误，供根 cli 包、命令子包与单测精确判定错误类别。
const (
	// ErrInvalidConfig 表示构造 CLI App 时缺少必填依赖或配置项非法。
	ErrInvalidConfig SentinelError = "cli: 无效的 AppConfig 配置"
	// ErrAppNotInitialized 表示在 nil 或未初始化零值 App 上调用运行方法。
	ErrAppNotInitialized SentinelError = "cli: App 未初始化"
	// ErrUsage 表示命令行子命令或选项参数语法非法。
	ErrUsage SentinelError = "cli: 命令行参数无效"
	// ErrNotConfigured 表示所请求的子入口或宿主只读钩子尚未由组合根注入。
	ErrNotConfigured SentinelError = "cli: 宿主未注入该能力回调"
	// ErrUnsupportedRunner 表示注入的 EngineHandle.Runner 未实现当前子命令所需引擎能力接口。
	ErrUnsupportedRunner SentinelError = "cli: 当前 Engine Runner 不支持该命令能力"
)

// SessionRunner 定义 CLI 最小核心会话执行与停机契约（保持 Wave 1 cmd/xops 100% 兼容）。
type SessionRunner interface {
	RunSSH(ctx context.Context, req engine.RunSSHRequest) (execution.ExecutionOutcome, error)
	Close(ctx context.Context) error
}

// SSHClient 聚合 ssh / exec / tunnel / mux 所需的引擎会话与转发控制能力。
type SSHClient interface {
	SessionRunner
	ResolveTarget(ctx context.Context, req engine.ResolveTargetRequest) (engine.ResolvedTarget, error)
	Exec(ctx context.Context, req engine.ExecRequest) (execution.ExecutionOutcome, error)
	ExecPrivileged(ctx context.Context, req engine.PrivilegeExecRequest) (execution.ExecutionOutcome, error)
	ProbeShell(ctx context.Context, req engine.ProbeShellRequest) (engine.ShellProbeResult, error)
	StartForward(ctx context.Context, req engine.StartForwardRequest) (engine.ForwardInfo, error)
	InspectForward(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) (engine.ForwardStatus, error)
	StopForward(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) error
	StartControlMaster(ctx context.Context, req engine.ControlMasterRequest) (engine.ControlMasterInfo, error)
	InspectControlMaster(ctx context.Context, handle plan.ManagedHandle[plan.KindMux]) (engine.ControlMasterStatus, error)
	StopControlMaster(ctx context.Context, handle plan.ManagedHandle[plan.KindMux]) error
	ProbeMux(ctx context.Context, req engine.MuxControlRequest) (engine.MuxControlResponse, error)
	ControlMux(ctx context.Context, req engine.MuxControlRequest) (engine.MuxControlResponse, error)
	RunMuxProxy(ctx context.Context, req engine.MuxControlRequest, stdin io.ReadCloser, stdout io.Writer) error
}

// AutomationClient 聚合批量命令执行与声明式 Playbook 编排能力。
type AutomationClient interface {
	SessionRunner
	ResolveTarget(ctx context.Context, req engine.ResolveTargetRequest) (engine.ResolvedTarget, error)
	NewOperationStream(ctx context.Context, buffer int) (*events.OperationStream, error)
	BatchExec(ctx context.Context, req engine.BatchExecRequest) (engine.BatchExecReport, error)
	RunPlaybook(ctx context.Context, req engine.PlaybookRequest) (engine.PlaybookRunResult, error)
}

// TransferClient 聚合 SCP 并行传输、远端 SFTP 文件操作与传输恢复能力。
type TransferClient interface {
	SessionRunner
	SCPUpload(ctx context.Context, req engine.SCPUploadRequest) (engine.SCPUploadResult, error)
	SCPDownload(ctx context.Context, req engine.SCPDownloadRequest) (engine.SCPDownloadResult, error)
	ReadRemoteFile(ctx context.Context, req engine.RemoteFileReadRequest) (engine.ReadFileResult, error)
	WriteRemoteFile(ctx context.Context, req engine.RemoteFileWriteRequest) (engine.WriteFileResult, error)
	PatchRemoteFile(ctx context.Context, req engine.RemoteFilePatchRequest) (engine.PatchFileResult, error)
	StatRemoteFile(ctx context.Context, req engine.RemoteStatRequest) (engine.RemoteFileStat, error)
	RenameRemoteFile(ctx context.Context, req engine.RemoteRenameRequest) error
	ListRemoteDir(ctx context.Context, req engine.RemotePathOpRequest) (engine.ListDirResult, error)
	MkdirRemoteAll(ctx context.Context, req engine.RemotePathOpRequest) error
	RemoveRemoteFile(ctx context.Context, req engine.RemotePathOpRequest) error
	RemoveRemoteDir(ctx context.Context, req engine.RemotePathOpRequest) error
	ChmodRemote(ctx context.Context, req engine.RemotePathOpRequest) error
	ChtimesRemote(ctx context.Context, req engine.RemotePathOpRequest) error
	RealPathRemote(ctx context.Context, req engine.RemotePathOpRequest) (pathalgRemotePath, error)
	ReadLinkRemote(ctx context.Context, req engine.RemotePathOpRequest) (string, error)
	RecoverTransfer(ctx context.Context, req engine.RecoverTransferRequest) (engine.TransferRecoveryResult, error)
	RecoverAllTransfers(ctx context.Context, req engine.RecoverAllTransfersRequest) (engine.RecoverAllResult, error)
	InspectTransfer(ctx context.Context, req engine.InspectTransferRequest) (engine.TransferStatusSnapshot, error)
}

// InventoryClient 聚合资产 CRUD、DAG 校验、凭据引用检查、导入与诊断能力。
type InventoryClient interface {
	SessionRunner
	ResolveTarget(ctx context.Context, req engine.ResolveTargetRequest) (engine.ResolvedTarget, error)
	GetInventorySnapshot(ctx context.Context, req engine.InventoryQueryRequest) (engine.InventorySnapshot, error)
	GetHost(ctx context.Context, id inventory.HostID, req engine.InventoryQueryRequest) (inventory.Host, engine.Revision, error)
	GetIdentity(ctx context.Context, id inventory.IdentityID, req engine.InventoryQueryRequest) (inventory.Identity, engine.Revision, error)
	GetNode(ctx context.Context, id inventory.NodeID, req engine.InventoryQueryRequest) (inventory.Node, engine.Revision, error)
	ListHosts(ctx context.Context, req engine.InventoryQueryRequest) ([]inventory.Host, engine.Revision, error)
	ListIdentities(ctx context.Context, req engine.InventoryQueryRequest) ([]inventory.Identity, engine.Revision, error)
	ListNodes(ctx context.Context, req engine.InventoryQueryRequest) ([]inventory.Node, engine.Revision, error)
	CreateHost(ctx context.Context, req engine.HostMutationRequest) (engine.MutationResult, error)
	UpdateHost(ctx context.Context, req engine.HostMutationRequest) (engine.MutationResult, error)
	DeleteHost(ctx context.Context, req engine.DeleteAssetRequest) (engine.MutationResult, error)
	CreateIdentity(ctx context.Context, req engine.IdentityMutationRequest) (engine.MutationResult, error)
	UpdateIdentity(ctx context.Context, req engine.IdentityMutationRequest) (engine.MutationResult, error)
	DeleteIdentity(ctx context.Context, req engine.DeleteAssetRequest) (engine.MutationResult, error)
	CreateNode(ctx context.Context, req engine.NodeMutationRequest) (engine.MutationResult, error)
	UpdateNode(ctx context.Context, req engine.NodeMutationRequest) (engine.MutationResult, error)
	DeleteNode(ctx context.Context, req engine.DeleteAssetRequest) (engine.MutationResult, error)
	ValidateDAG(ctx context.Context, req engine.InventoryQueryRequest) (inventory.DAGReport, error)
	CheckSecretReferences(ctx context.Context, req engine.SecretRefCheckRequest) ([]inventory.SecretReference, error)
	InventoryDoctor(ctx context.Context, req engine.InventoryDoctorRequest) (engine.InventoryDoctorRep, error)
	SupportedImportFormats() []string
	PlanImport(ctx context.Context, req engine.ImportRequest) (engine.ImportPreview, error)
	ApplyImport(ctx context.Context, req engine.ImportRequest) (engine.ImportResult, error)
	EnrollEncryptedPrivateKeyIdentity(ctx context.Context, req engine.EnrollEncryptedPrivateKeyRequest) (engine.EnrollEncryptedPrivateKeyResult, error)
}

// VaultClient 聚合凭据库生命周期控制、健康诊断、引用查询与安全回收能力。
type VaultClient interface {
	SessionRunner
	VaultStatus(ctx context.Context, req engine.VaultOpRequest) (engine.VaultStatus, error)
	VaultInitInteractive(ctx context.Context, req engine.InteractiveVaultOpRequest) error
	VaultUnlockInteractive(ctx context.Context, req engine.InteractiveVaultOpRequest) error
	VaultLock(ctx context.Context, req engine.VaultOpRequest) error
	VaultDoctor(ctx context.Context, req engine.VaultDoctorRequest) (engine.CredentialDoctorRep, error)
	FindSecretReferences(ctx context.Context, req engine.FindSecretReferencesRequest) ([]inventory.SecretReference, error)
	DeleteSecret(ctx context.Context, req engine.DeleteSecretRequest) error
	GCUnreferencedSecrets(ctx context.Context, req engine.GCUnreferencedRequest) (engine.GCUnreferencedResult, error)
}

// ReconcileClient 聚合启动期 O(1) 跨进程审计崩溃对账能力。
type ReconcileClient interface {
	SessionRunner
	ReconcileCrashedAudits(ctx context.Context) (engine.ReconcileReport, error)
}

// 编译期契约断言：确保 *engine.Engine 原生实现全部 CLI 能力窄接口。
var (
	_ SessionRunner    = (*engine.Engine)(nil)
	_ SSHClient        = (*engine.Engine)(nil)
	_ AutomationClient = (*engine.Engine)(nil)
	_ TransferClient   = (*engine.Engine)(nil)
	_ InventoryClient  = (*engine.Engine)(nil)
	_ VaultClient      = (*engine.Engine)(nil)
	_ ReconcileClient  = (*engine.Engine)(nil)
)
