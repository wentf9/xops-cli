package engine

import (
	"errors"
	"io"
	"io/fs"
	"slices"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/mcpruntime"
	"github.com/wentf9/xops-cli/core/internal/pool"
	ucauto "github.com/wentf9/xops-cli/core/internal/usecase/automation"
	uccred "github.com/wentf9/xops-cli/core/internal/usecase/credential"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	ucobs "github.com/wentf9/xops-cli/core/internal/usecase/observability"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

// 公开核心值类型、规格、枚举、嵌套返回子类型及零拷贝请求别名：
// 使受 archbound 约束的 internal/entry/** 与外部宿主仅导入 core/{domain,events,conc,engine} 即可零阻塞消费全量强类型契约。
type (
	Revision                = ports.Revision
	DurabilityOutcome       = ports.DurabilityOutcome
	InventorySnapshot       = ports.InventorySnapshot
	CrashReconcileReport    = ports.CrashReconcileReport
	ReconcileReport         = ports.CrashReconcileReport
	VaultState              = ports.VaultState
	VaultStatus             = ports.VaultStatus
	ForwardSpec             = ports.ForwardSpec
	ForwardDirection        = ports.ForwardDirection
	ForwardEndpointKind     = ports.ForwardEndpointKind
	TUNSpec                 = ports.TUNSpec
	TUNMode                 = ports.TUNMode
	MuxControlAction        = ports.MuxControlAction
	MuxControlResponse      = ports.MuxControlResponse
	PrivilegeMethod         = ports.PrivilegeMethod
	PrivilegeRequestSpec    = ports.PrivilegeRequestSpec
	PrivilegeRequest        = ports.PrivilegeRequest
	ShellProbeResult        = ports.ShellProbeResult
	TerminalSize            = ports.TerminalSize
	RemoteFileType          = ports.RemoteFileType
	RemoteFileStat          = ports.RemoteFileStat
	RemoteFileAnchor        = ports.RemoteFileAnchor
	RemoteDirEntry          = ports.RemoteDirEntry
	SecretPromptRequestSpec = ports.SecretPromptRequestSpec
	SecretPromptRequest     = ports.SecretPromptRequest
	ApprovalSubmission      = gate.ApprovalSubmission
	HandleStatus            = pool.HandleStatus

	ResolvedTarget                   = ucinv.ResolvedTarget
	InventoryQueryRequest            = ucinv.QueryRequest
	HostMutationRequest              = ucinv.HostMutationRequest
	IdentityMutationRequest          = ucinv.IdentityMutationRequest
	NodeMutationRequest              = ucinv.NodeMutationRequest
	InventoryDoctorRequest           = ucinv.DoctorRequest
	SecretRefCheckRequest            = ucinv.SecretRefCheckRequest
	PendingEnrollmentRequest         = ucinv.PendingEnrollmentRequest
	EnrollEncryptedPrivateKeyRequest = ucinv.EnrollEncryptedPrivateKeyRequest
	MutationResult                   = ucinv.MutationResult
	ImportPreview                    = ucinv.ImportPreview
	ImportResult                     = ucinv.ImportResult
	InventoryDoctorRep               = ucinv.DoctorReport
	PendingProbeFunc                 = ucinv.PendingProbeFunc
	PendingEnrollmentResult          = ucinv.PendingEnrollmentResult
	PendingEnrollmentLease           = ucinv.PendingEnrollmentLease
	EnrollEncryptedPrivateKeyResult  = ucinv.EnrollEncryptedPrivateKeyResult

	VaultOpRequest                 = uccred.VaultControlRequest
	InteractiveVaultOpRequest      = uccred.InteractiveVaultControlRequest
	VaultDoctorRequest             = uccred.DoctorRequest
	FindSecretReferencesRequest    = uccred.FindReferencesRequest
	WithSecretRequest              = uccred.WithSecretRequest
	DeleteSecretRequest            = uccred.DeleteSecretRequest
	GCUnreferencedRequest          = uccred.GCUnreferencedRequest
	RotateSecretRequest            = uccred.RotateSecretRequest
	InteractiveRotateSecretRequest = uccred.InteractiveRotateSecretRequest
	VaultSagaRequest               = uccred.VaultSagaRequest
	InteractiveVaultSagaRequest    = uccred.InteractiveVaultSagaRequest
	DoctorSeverity                 = uccred.DoctorSeverity
	DoctorFinding                  = uccred.DoctorFinding
	CredentialDoctorRep            = uccred.DoctorReport
	RetainedSecret                 = uccred.RetainedSecret
	GCUnreferencedResult           = uccred.GCUnreferencedResult
	SagaResult                     = uccred.SagaResult
	GraphMutator                   = uccred.GraphMutator
	OldSecretRefsResolver          = uccred.OldSecretRefsResolver
	NewSecretVerifier              = uccred.NewSecretVerifier

	PTYReadRequest             = ucsess.PTYReadRequest
	PTYReadResult              = ucsess.PTYReadResult
	PTYStatus                  = ucsess.PTYStatus
	ForwardInfo                = ucsess.ForwardInfo
	ForwardStatus              = ucsess.ForwardStatus
	ControlMasterInfo          = ucsess.ControlMasterInfo
	ControlMasterStatus        = ucsess.ControlMasterStatus
	TextEdit                   = uctrans.TextEdit
	LocalUploadSourceKind      = uctrans.LocalUploadSourceKind
	LocalUploadSource          = uctrans.LocalUploadSource
	TransferSessionOptions     = uctrans.TransferSessionOptions
	RecoverAllTransfersRequest = uctrans.RecoverAllAuthorizedRequest
	SCPUploadResult            = uctrans.SCPUploadResult
	SCPDownloadResult          = uctrans.SCPDownloadResult
	ReadFileResult             = uctrans.ReadFileResult
	WriteFileResult            = uctrans.WriteFileResult
	PatchFileResult            = uctrans.PatchFileResult
	ListDirResult              = uctrans.ListDirResult
	TransferHandleInfo         = uctrans.TransferHandleInfo
	WriteTransferChunkRes      = uctrans.WriteTransferChunkResult
	PullTransferChunkResult    = uctrans.PullTransferChunkResult
	CommitTransferResult       = uctrans.CommitTransferResult
	TransferRecoveryResult     = uctrans.TransferRecoveryResult
	TransferRecoveryEntry      = uctrans.TransferRecoveryEntry
	RecoverAllResult           = uctrans.RecoverAllResult
	TransferStatusSnapshot     = uctrans.TransferStatusSnapshot
	NodeStreamFactory          = ucauto.NodeStreamFactory
	BatchNodeResult            = ucauto.BatchNodeResult
	BatchExecReport            = ucauto.BatchExecReport
	PlaybookRunResult          = ucauto.PlaybookRunResult
	DiskMetric                 = ucobs.DiskMetric
	ProcessMetric              = ucobs.ProcessMetric
	HostMetricsFrame           = ucobs.HostMetricsFrame
	GUIActionKind              = ucobs.GUIActionKind
	GUISessionKind             = ucobs.GUISessionKind
	ScrollDirection            = ucobs.ScrollDirection
	GUIActionSpec              = ucobs.GUIActionSpec
	GUIArtifactDest            = ucobs.GUIArtifactDest
	GUISessionSpec             = ucobs.GUISessionSpec
	ProcessedScreenshot        = ucobs.ProcessedScreenshot
	LogTargetKind              = ucobs.LogTargetKind
	LogTarget                  = ucobs.LogTarget
	ProcessSortBy              = ucobs.ProcessSortBy
	ProjectionConfig           = ucobs.ProjectionConfig
	OperationView              = ucobs.OperationView
	MetricPoint                = ucobs.MetricPoint
	LogEntry                   = ucobs.LogEntry
	DiagnosticRecord           = ucobs.DiagnosticRecord
	PoolRecord                 = ucobs.PoolRecord
	ProjectionSnapshot         = ucobs.ProjectionSnapshot
	MetricsStreamResult        = ucobs.MetricsStreamResult
	LogStreamResult            = ucobs.LogStreamResult
	GUIExecResult              = ucobs.GUIExecResult
	GUISessionInfo             = ucobs.GUISessionInfo
	GUISessionStatus           = ucobs.GUISessionStatus
	TransferRecSummary         = mcpruntime.TransferRecoverySummary
	MCPStartupReport           = mcpruntime.StartupReport
)

// 公开端口与用例枚举常量别名（零 core/ports 与 core/internal 导入即可穷尽 switch）。
const (
	VaultStateInvalid       = ports.VaultStateInvalid
	VaultStateUninitialized = ports.VaultStateUninitialized
	VaultStateLocked        = ports.VaultStateLocked
	VaultStateUnlocked      = ports.VaultStateUnlocked

	PrivilegeMethodInvalid = ports.PrivilegeMethodInvalid
	PrivilegeMethodSudo    = ports.PrivilegeMethodSudo
	PrivilegeMethodSu      = ports.PrivilegeMethodSu
	PrivilegeMethodDoas    = ports.PrivilegeMethodDoas

	ForwardDirectionInvalid = ports.ForwardDirectionInvalid
	ForwardLocal            = ports.ForwardLocal
	ForwardRemote           = ports.ForwardRemote
	ForwardDynamic          = ports.ForwardDynamic
	ForwardTUN              = ports.ForwardTUN
	ForwardEndpointInvalid  = ports.ForwardEndpointInvalid
	ForwardEndpointTCP      = ports.ForwardEndpointTCP
	ForwardEndpointUnix     = ports.ForwardEndpointUnix
	TUNModeInvalid          = ports.TUNModeInvalid
	TUNModePointToPoint     = ports.TUNModePointToPoint
	TUNModeEthernet         = ports.TUNModeEthernet
	TUNUnitAny              = ports.TUNUnitAny

	MuxActionInvalid = ports.MuxActionInvalid
	MuxActionCheck   = ports.MuxActionCheck
	MuxActionForward = ports.MuxActionForward
	MuxActionCancel  = ports.MuxActionCancel
	MuxActionExit    = ports.MuxActionExit
	MuxActionStop    = ports.MuxActionStop
	MuxActionProxy   = ports.MuxActionProxy

	RemoteFileTypeInvalid = ports.RemoteFileTypeInvalid
	RemoteFileRegular     = ports.RemoteFileRegular
	RemoteFileDir         = ports.RemoteFileDir
	RemoteFileSymlink     = ports.RemoteFileSymlink
	RemoteFileOther       = ports.RemoteFileOther

	DoctorSeverityInvalid = uccred.DoctorSeverityInvalid
	DoctorSeverityInfo    = uccred.DoctorSeverityInfo
	DoctorSeverityWarn    = uccred.DoctorSeverityWarn
	DoctorSeverityError   = uccred.DoctorSeverityError

	LocalUploadSourceInvalid  = uctrans.LocalUploadSourceInvalid
	LocalUploadSourceOperator = uctrans.LocalUploadSourceOperator
	LocalUploadSourceScoped   = uctrans.LocalUploadSourceScoped

	LogTargetInvalid       = ucobs.LogTargetInvalid
	LogTargetFile          = ucobs.LogTargetFile
	LogTargetDocker        = ucobs.LogTargetDocker
	ProcessSortInvalid     = ucobs.ProcessSortInvalid
	ProcessSortCPU         = ucobs.ProcessSortCPU
	ProcessSortMem         = ucobs.ProcessSortMem
	GUIActionInvalid       = ucobs.GUIActionInvalid
	GUIActionScreenshot    = ucobs.GUIActionScreenshot
	GUIActionClick         = ucobs.GUIActionClick
	GUIActionDoubleClick   = ucobs.GUIActionDoubleClick
	GUIActionRightClick    = ucobs.GUIActionRightClick
	GUIActionMove          = ucobs.GUIActionMove
	GUIActionDrag          = ucobs.GUIActionDrag
	GUIActionScroll        = ucobs.GUIActionScroll
	GUIActionType          = ucobs.GUIActionType
	GUIActionKey           = ucobs.GUIActionKey
	ScrollDirectionInvalid = ucobs.ScrollDirectionInvalid
	ScrollUp               = ucobs.ScrollUp
	ScrollDown             = ucobs.ScrollDown
	ScrollLeft             = ucobs.ScrollLeft
	ScrollRight            = ucobs.ScrollRight
	GUISessionInvalid      = ucobs.GUISessionInvalid
	GUISessionX11          = ucobs.GUISessionX11
	GUISessionVNC          = ucobs.GUISessionVNC
)

// 不透明值类型公开构造器与解析器薄转发函数（严禁 var NewX = ... 以满足 xopsvet/noimplicit）。
func NewSecretPromptRequest(s SecretPromptRequestSpec) (SecretPromptRequest, error) {
	return mapRes(ports.NewSecretPromptRequest(s))
}
func ParseVaultState(raw string) (VaultState, error) { return mapRes(ports.ParseVaultState(raw)) }
func NewPrivilegeRequest(s PrivilegeRequestSpec) (PrivilegeRequest, error) {
	return mapRes(ports.NewPrivilegeRequest(s))
}
func ParsePrivilegeMethod(s string) (PrivilegeMethod, error) {
	return mapRes(ports.ParsePrivilegeMethod(s))
}
func NewForwardSpec(d ForwardDirection, b, t string) (ForwardSpec, error) {
	return mapRes(ports.NewForwardSpec(d, b, t))
}
func NewTypedForwardSpec(d ForwardDirection, bk ForwardEndpointKind, b string, tk ForwardEndpointKind, t string) (ForwardSpec, error) {
	return mapRes(ports.NewTypedForwardSpec(d, bk, b, tk, t))
}
func NewForwardTUNSpec(tun TUNSpec) (ForwardSpec, error) { return mapRes(ports.NewForwardTUNSpec(tun)) }
func NewTUNSpec(m TUNMode, l, r uint32) (TUNSpec, error) { return mapRes(ports.NewTUNSpec(m, l, r)) }
func ParseForwardDirection(s string) (ForwardDirection, error) {
	return mapRes(ports.ParseForwardDirection(s))
}
func ParseForwardEndpointKind(s string) (ForwardEndpointKind, error) {
	return mapRes(ports.ParseForwardEndpointKind(s))
}
func ParseTUNMode(raw string) (TUNMode, error) { return mapRes(ports.ParseTUNMode(raw)) }
func ParseMuxControlAction(s string) (MuxControlAction, error) {
	return mapRes(ports.ParseMuxControlAction(s))
}
func ParseRevision(raw string) (Revision, error)        { return mapRes(ports.ParseRevision(raw)) }
func NewTerminalSize(c, r uint16) (TerminalSize, error) { return mapRes(ports.NewTerminalSize(c, r)) }
func NewRemoteFileAnchor(t RemoteFileType, h bool, d, i uint64) (RemoteFileAnchor, error) {
	return mapRes(ports.NewRemoteFileAnchor(t, h, d, i))
}
func ParseRemoteFileType(s string) (RemoteFileType, error) {
	return mapRes(ports.ParseRemoteFileType(s))
}
func ParseDoctorSeverity(s string) (DoctorSeverity, error) {
	return mapRes(uccred.ParseDoctorSeverity(s))
}
func NewTextEdit(o, n string, all bool) (TextEdit, error) {
	return mapRes(uctrans.NewTextEdit(o, n, all))
}
func NewOperatorUploadSource(s pathalg.LocalSourcePath, p pathalg.SymlinkPolicy) (LocalUploadSource, error) {
	return mapRes(uctrans.NewOperatorUploadSource(s, p))
}
func NewScopedUploadSource(r pathalg.LocalDir, d pathalg.LocalRootedDest) (LocalUploadSource, error) {
	return mapRes(uctrans.NewScopedUploadSource(r, d))
}
func ParseLogTargetKind(s string) (LogTargetKind, error) { return mapRes(ucobs.ParseLogTargetKind(s)) }
func ParseGUIActionKind(s string) (GUIActionKind, error) { return mapRes(ucobs.ParseGUIActionKind(s)) }
func ParseGUISessionKind(s string) (GUISessionKind, error) {
	return mapRes(ucobs.ParseGUISessionKind(s))
}
func ParseScrollDirection(s string) (ScrollDirection, error) {
	return mapRes(ucobs.ParseScrollDirection(s))
}
func ParseProcessSortBy(s string) (ProcessSortBy, error) { return mapRes(ucobs.ParseProcessSortBy(s)) }
func NewFileLogTarget(p pathalg.RemotePath) (LogTarget, error) {
	return mapRes(ucobs.NewFileLogTarget(p))
}
func NewDockerLogTarget(c string) (LogTarget, error) { return mapRes(ucobs.NewDockerLogTarget(c)) }

// NewApprovalSubmission 校验用户审批判定、信封 SHA-256 摘要与可选完整信封，构造公开 ApprovalSubmission。
func NewApprovalSubmission(verdict security.Verdict, envelopeDigest security.Digest, envelope algebraic.Option[security.ApprovalEnvelope], comment string) (ApprovalSubmission, error) {
	resp, err := ports.NewApprovalDecisionResponse(verdict, envelopeDigest, comment)
	if err != nil {
		return zeroVal[ApprovalSubmission](), mapEngineError(err)
	}
	return mapRes(gate.NewApprovalSubmission(gate.ApprovalSubmissionSpec{Envelope: envelope, Response: resp}))
}

// ApprovalChallenge 封装护栏签发的两步审批挑战信封与摘要，供 CLI/TUI/外部宿主处理结构化审批。
//
//xops:opaque
//xops:failclosed
type ApprovalChallenge struct {
	envelope  security.ApprovalEnvelope
	digest    security.Digest
	escalated bool
	reason    string
	valid     bool
}

// ExtractApprovalChallenge 从任意 Engine 返回的 error 链中提取结构化两步审批挑战。
func ExtractApprovalChallenge(err error) (ApprovalChallenge, bool) {
	if ch, ok := errors.AsType[*gate.ApprovalChallengeError](err); ok && ch != nil && ch.IsValid() {
		return ApprovalChallenge{envelope: ch.Envelope(), digest: ch.EnvelopeDigest(), escalated: ch.Escalated(), reason: ch.Reason(), valid: true}, true
	}
	return ApprovalChallenge{}, false
}
func (c ApprovalChallenge) IsValid() bool {
	return c.valid && c.envelope.IsValid() && c.digest.IsValid()
}
func (c ApprovalChallenge) Envelope() security.ApprovalEnvelope { return c.envelope }
func (c ApprovalChallenge) EnvelopeDigest() security.Digest     { return c.digest }
func (c ApprovalChallenge) Escalated() bool                     { return c.valid && c.escalated }
func (c ApprovalChallenge) Reason() string                      { return c.reason }

// 公共入参复用结构体及面向目标解析/跨用例门面扩展的公开请求 DTO（零明文、零裸 time.Duration）。
type (
	RemoteCall struct {
		TargetInput
		CallOptions
	}
	TargetInput struct {
		Target     ResolvedTarget
		TargetSpec string
		CLIOptions option.OptionLayer
	}
	CallOptions struct {
		Risk            algebraic.Option[security.RiskLevel]
		Approval        algebraic.Option[ApprovalSubmission]
		OperationStream *events.OperationStream
	}
	DeleteAssetRequest struct {
		CallOptions
		ID, ScopeSummary                                string
		ExpectedRevision                                algebraic.Option[Revision]
		DeleteUnusedSecrets, RequireSecretsUnreferenced bool
		ExtraPending                                    []inventory.PendingSecretRef
	}
	ImportRequest struct {
		CallOptions
		Format, SourceName, ScopeSummary string
		Reader                           io.Reader
		Bundle                           algebraic.Option[inventory.ImportBundle]
		ExpectedRevision                 algebraic.Option[Revision]
		DryRun                           bool
	}
	ProbePendingEnrollmentRequest struct {
		CallOptions
		CLIOptions option.OptionLayer
	}
	PrivilegeExecRequest struct {
		RemoteCall
		Privilege             PrivilegeRequest
		PasswordRef           algebraic.Option[secret.Ref]
		PromptPassword        bool
		Paths, RecursivePaths []string
		Stdin                 io.Reader
		Stdout, Stderr        io.Writer
		RequestTTY            RequestTTYMode
		Term                  string
	}
	ProbeShellRequest struct {
		RemoteCall
		Timeout algebraic.Option[algebraic.Duration]
	}
	OpenPTYRequest struct {
		RemoteCall
		Term           string
		Size           algebraic.Option[TerminalSize]
		MaxBufferBytes int
	}
	StartForwardRequest struct {
		RemoteCall
		Spec ForwardSpec
	}
	ControlMasterRequest struct{ RemoteCall }
	MuxControlRequest    struct {
		RemoteCall
		SocketPath algebraic.Option[pathalg.LocalSourcePath]
		Action     MuxControlAction
		Forward    algebraic.Option[ForwardSpec]
	}
	SCPUploadRequest struct {
		RemoteCall
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
	SCPDownloadRequest struct {
		RemoteCall
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
	RemoteFileReadRequest struct {
		RemoteCall
		Path     pathalg.RemotePath
		MaxBytes int64
	}
	RemoteFileWriteRequest struct {
		RemoteCall
		Path                     pathalg.RemotePath
		Content                  []byte
		Perm                     algebraic.Option[fs.FileMode]
		NoClobber, CreateParents bool
		ExpectedAnchor           algebraic.Option[RemoteFileAnchor]
	}
	RemoteFilePatchRequest struct {
		RemoteCall
		Path           pathalg.RemotePath
		Edits          []TextEdit
		ExpectedAnchor algebraic.Option[RemoteFileAnchor]
		ExpectedDigest algebraic.Option[security.Digest]
		MaxBytes       int64
	}
	RemoteStatRequest struct {
		RemoteCall
		Path           pathalg.RemotePath
		FollowSymlinks bool
	}
	RemoteRenameRequest struct {
		RemoteCall
		OldPath, NewPath pathalg.RemotePath
		NoClobber        bool
		ExpectedAnchor   algebraic.Option[RemoteFileAnchor]
	}
	RemotePathOpRequest struct {
		RemoteCall
		Path         pathalg.RemotePath
		Perm         algebraic.Option[fs.FileMode]
		Atime, Mtime time.Time
	}
	StartTransferRequest struct {
		RemoteCall
		TransferSessionOptions
		TransferID     algebraic.Option[security.OperationID]
		Dest           fsm.TransferDest
		TotalBytes     uint64
		ExpectedDigest algebraic.Option[security.Digest]
	}
	WriteTransferChunkRequest struct {
		RemoteCall
		Handle plan.ManagedHandle[plan.KindTransfer]
		Offset uint64
		Data   []byte
	}
	PullTransferChunkRequest struct {
		RemoteCall
		Handle        plan.ManagedHandle[plan.KindTransfer]
		MaxChunkBytes uint64
	}
	TransferHandleOpRequest struct {
		RemoteCall
		Handle plan.ManagedHandle[plan.KindTransfer]
		Reason string
	}
	ResumeTransferRequest struct {
		RemoteCall
		TransferSessionOptions
		TransferID   security.OperationID
		StartNextGen bool
	}
	RecoverTransferRequest struct {
		RemoteCall
		TransferID        security.OperationID
		PruneSuperseded   bool
		LocalRootForClean algebraic.Option[pathalg.LocalDir]
	}
	InspectTransferRequest struct {
		RemoteCall
		TransferID security.OperationID
		Handle     algebraic.Option[plan.ManagedHandle[plan.KindTransfer]]
	}
	BatchExecRequest struct {
		CallOptions
		Targets           []ResolvedTarget
		Selector          algebraic.Option[playbook.TargetSelector]
		CLIOptions        option.OptionLayer
		ExcludeNodes      []inventory.NodeID
		ExcludeTags       []inventory.Tag
		Command           execution.CommandPlan
		Concurrency       int
		MaxOutputBytes    uint64
		OutputDir         algebraic.Option[pathalg.LocalDir]
		FailFast          bool
		NodeStreams       map[inventory.NodeID]*events.OperationStream
		NodeStreamFactory NodeStreamFactory
	}
	PlaybookRequest struct {
		CallOptions
		Playbook          playbook.Playbook
		Targets           []ResolvedTarget
		CLIOptions        option.OptionLayer
		DefaultProfile    algebraic.Option[execution.LaunchProfile]
		ScopedSourceRoot  algebraic.Option[pathalg.LocalDir]
		Concurrency       int
		Timeout           algebraic.Option[algebraic.Duration]
		ExtraVars         map[string]string
		NodeStreams       map[inventory.NodeID]*events.OperationStream
		NodeStreamFactory NodeStreamFactory
	}
	MetricsStreamRequest struct {
		RemoteCall
		Profile                  algebraic.Option[execution.LaunchProfile]
		Interval, Timeout        algebraic.Option[algebraic.Duration]
		MaxSamples, TopProcesses int
		SortBy                   algebraic.Option[ProcessSortBy]
		OnFrame                  func(HostMetricsFrame)
	}
	LogStreamRequest struct {
		RemoteCall
		Profile   algebraic.Option[execution.LaunchProfile]
		Target    LogTarget
		TailLines int
		Follow    bool
		MaxBytes  uint64
		Timeout   algebraic.Option[algebraic.Duration]
		Output    io.Writer
	}
	GUIExecRequest struct {
		RemoteCall
		Profile  algebraic.Option[execution.LaunchProfile]
		Spec     GUIActionSpec
		Artifact algebraic.Option[GUIArtifactDest]
		Timeout  algebraic.Option[algebraic.Duration]
	}
	OpenGUISessionRequest struct {
		RemoteCall
		Spec GUISessionSpec
	}
	// MCPConfig 定义从 Engine 派生 MCPServer 时的安全传输与沙箱参数（物理零 OperatorReadFS）。
	MCPConfig struct {
		ServerName, ServerVersion, Instructions                                                      string
		TransferRoot, ArtifactRoot                                                                   algebraic.Option[pathalg.LocalDir]
		MaxMessageBytes, HTTPChunkSize                                                               int64
		MaxTrackedHandles, MaxHTTPSessions                                                           int
		AllowNonLoopbackHTTP, PruneSupersededJournals, FailOnCorruptJournal, AllowOptionalReconciler bool
		HTTPAllowedOrigins, HTTPAllowedHosts                                                         []string
		HTTPReadHeaderTimeout, HTTPShutdownTimeout                                                   algebraic.Option[algebraic.Duration]
	}
)

// 本包导出的不可变规范哨兵错误，供组合根与受 archbound 约束的 internal/entry/** 通过 errors.Is 精确区分运行期故障类别。
var (
	ErrNilContext               = domi18n.Sentinel(domi18n.KeyEngineNilContext)
	ErrInvalidConfig            = domi18n.Sentinel(domi18n.KeyEngineInvalidConfig)
	ErrEngineNotInitialized     = domi18n.Sentinel(domi18n.KeyEngineNotInitialized)
	ErrEngineClosed             = domi18n.Sentinel(domi18n.KeyEngineClosed)
	ErrEngineHalted             = domi18n.Sentinel(domi18n.KeyEngineHalted)
	ErrInvalidRequest           = domi18n.Sentinel(domi18n.KeyEngineInvalidRequest)
	ErrInvalidProfile           = domi18n.Sentinel(domi18n.KeyEngineInvalidProfile)
	ErrInvalidFallback          = domi18n.Sentinel(domi18n.KeyEngineInvalidFallback)
	ErrInvalidRequestTTY        = domi18n.Sentinel(domi18n.KeyEngineInvalidReqTTY)
	ErrReconcilerUnavailable    = domi18n.Sentinel(domi18n.KeyEngineReconcilerUnav)
	ErrVaultUnavailable         = domi18n.Sentinel(domi18n.KeyEngineVaultUnavail)
	ErrMCPServerNotInitialized  = domi18n.Sentinel(domi18n.KeyEngineMCPNotInit)
	ErrProjectionNotInitialized = domi18n.Sentinel(domi18n.KeyEngineProjNotInit)
	ErrApprovalRequired         = domi18n.Sentinel(domi18n.KeyEngineApprovalReq)
	ErrApprovalRejected         = domi18n.Sentinel(domi18n.KeyEngineApprovalReject)
	ErrAuthorizationDenied      = domi18n.Sentinel(domi18n.KeyEngineAuthDenied)
	ErrScopeEscalated           = domi18n.Sentinel(domi18n.KeyEngineScopeEscalated)
	ErrNotFound                 = domi18n.Sentinel(domi18n.KeyEngineNotFound)
	ErrAlreadyExists            = domi18n.Sentinel(domi18n.KeyEngineAlreadyExists)
	ErrRevisionConflict         = domi18n.Sentinel(domi18n.KeyEngineRevisionConf)
	ErrStillReferenced          = domi18n.Sentinel(domi18n.KeyEngineStillReferenced)
	ErrImportConflict           = domi18n.Sentinel(domi18n.KeyEngineImportConflict)
	ErrUncertainDurability      = domi18n.Sentinel(domi18n.KeyEngineUncertainDur)
	ErrOutcomeUnknown           = domi18n.Sentinel(domi18n.KeyEngineOutcomeUnknown)
	ErrVaultLocked              = domi18n.Sentinel(domi18n.KeyEngineVaultLocked)
	ErrSecretNotFound           = domi18n.Sentinel(domi18n.KeyEngineSecretNotFound)
	ErrAuthFailed               = domi18n.Sentinel(domi18n.KeyEngineAuthFailed)
	ErrHostKeyUnknown           = domi18n.Sentinel(domi18n.KeyEngineHostKeyUnknown)
	ErrHostKeyMismatch          = domi18n.Sentinel(domi18n.KeyEngineHostKeyMismatch)
	ErrHostKeyRevoked           = domi18n.Sentinel(domi18n.KeyEngineHostKeyRevoked)
	ErrDialFailed               = domi18n.Sentinel(domi18n.KeyEngineDialFailed)
	ErrControlMasterDisabled    = domi18n.Sentinel(domi18n.KeyEngineMuxDisabled)
	ErrMuxUnavailable           = domi18n.Sentinel(domi18n.KeyEngineMuxUnavailable)
	ErrHandleNotFound           = domi18n.Sentinel(domi18n.KeyEngineHandleNotFound)
	ErrHandleRevoked            = domi18n.Sentinel(domi18n.KeyEngineHandleRevoked)
	ErrInteractionUnavailable   = domi18n.Sentinel(domi18n.KeyEngineInteractUnav)
	ErrInteractionCanceled      = domi18n.Sentinel(domi18n.KeyEngineInteractCancel)
	ErrRemoteAnchorMismatch     = domi18n.Sentinel(domi18n.KeyEngineAnchorMismatch)
	ErrRemoteIsDir              = domi18n.Sentinel(domi18n.KeyEngineRemoteIsDir)
	ErrNotRegularFile           = domi18n.Sentinel(domi18n.KeyEngineNotRegularFile)
	ErrPatchConflict            = domi18n.Sentinel(domi18n.KeyEnginePatchConflict)
	ErrDigestMismatch           = domi18n.Sentinel(domi18n.KeyEngineDigestMismatch)
	ErrSymlinkRejected          = domi18n.Sentinel(domi18n.KeyEngineSymlinkReject)
	ErrCorruptData              = domi18n.Sentinel(domi18n.KeyEngineCorruptData)
	ErrLimitExceeded            = domi18n.Sentinel(domi18n.KeyEngineLimitExceeded)
	ErrUnsupported              = domi18n.Sentinel(domi18n.KeyEngineUnsupported)
)

func zeroVal[T any]() (z T)                   { return z }
func mapRes[T any](v T, err error) (T, error) { return v, mapEngineError(err) }

// ReferenceConflict 封装因仍被其他资产反向引用或 5 位置/Pending 凭据占用而拒绝删除的只读结构化冲突详情（零明文）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type ReferenceConflict struct {
	assetKind, subject string
	assetRefs          []inventory.AssetReference
	secretRefs         []inventory.SecretReference
	valid              bool
}

// ExtractReferenceConflict 从任意 Engine 返回的 error 链中提取资产反向引用或 5 位置/Pending 凭据引用冲突详情。
func ExtractReferenceConflict(err error) (ReferenceConflict, bool) {
	if ae, ok := errors.AsType[*ucinv.AssetReferencedError](err); ok && ae.IsValid() {
		return ReferenceConflict{assetKind: ae.AssetKind(), subject: ae.AssetID(), assetRefs: ae.References(), valid: true}, true
	}
	if se, ok := errors.AsType[*ucinv.SecretReferencedError](err); ok && se.IsValid() {
		return ReferenceConflict{assetKind: "secret", subject: se.Subject(), secretRefs: se.References(), valid: true}, true
	}
	if ce, ok := errors.AsType[*uccred.SecretReferencedError](err); ok && ce.IsValid() {
		return ReferenceConflict{assetKind: "secret", subject: ce.Ref().String(), secretRefs: ce.References(), valid: true}, true
	}
	return ReferenceConflict{}, false
}

// IsValid / IsZero / AssetKind / Subject / AssetReferences / SecretReferences 提供结构化引用冲突只读访问器。
func (c ReferenceConflict) IsValid() bool {
	return c.valid && c.subject != "" && (len(c.assetRefs) > 0 || len(c.secretRefs) > 0)
}
func (c ReferenceConflict) IsZero() bool      { return !c.IsValid() }
func (c ReferenceConflict) AssetKind() string { return validOrZero(c.IsValid(), c.assetKind) }
func (c ReferenceConflict) Subject() string   { return validOrZero(c.IsValid(), c.subject) }
func (c ReferenceConflict) AssetReferences() []inventory.AssetReference {
	return validOrZero(c.IsValid(), slices.Clone(c.assetRefs))
}
func (c ReferenceConflict) SecretReferences() []inventory.SecretReference {
	return validOrZero(c.IsValid(), slices.Clone(c.secretRefs))
}

type engineErrRule struct{ src, pub error }

func engineErrorRules() []engineErrRule {
	return []engineErrRule{
		{gate.ErrGateHalted, ErrEngineHalted}, {pool.ErrGateHalted, ErrEngineHalted}, {ports.ErrAuditHalted, ErrEngineHalted},
		{gate.ErrReconcilerUnavailable, ErrReconcilerUnavailable},
		{gate.ErrApprovalRequired, ErrApprovalRequired}, {gate.ErrApprovalRejected, ErrApprovalRejected},
		{gate.ErrAuthorizationDenied, ErrAuthorizationDenied}, {ports.ErrPermissionDenied, ErrAuthorizationDenied},
		{gate.ErrScopeEscalated, ErrScopeEscalated}, {ucsess.ErrEscalationScopeChanged, ErrScopeEscalated},
		{ports.ErrVaultLocked, ErrVaultLocked}, {ports.ErrSecretNotFound, ErrSecretNotFound},
		{ucinv.ErrVaultUnavailable, ErrVaultUnavailable}, {uccred.ErrVaultControlUnavailable, ErrVaultUnavailable},
		{ports.ErrRevisionConflict, ErrRevisionConflict}, {ucinv.ErrImportConflict, ErrImportConflict},
		{ucinv.ErrAssetStillReferenced, ErrStillReferenced}, {ucinv.ErrSecretStillReferenced, ErrStillReferenced}, {uccred.ErrSecretStillReferenced, ErrStillReferenced},
		{ucinv.ErrUncertainDurability, ErrUncertainDurability}, {uccred.ErrUncertainDurability, ErrUncertainDurability}, {ucauto.ErrUncertainDurability, ErrUncertainDurability},
		{ucinv.ErrCommitOutcomeUnknown, ErrOutcomeUnknown}, {ucinv.ErrEnrollmentUncertain, ErrOutcomeUnknown}, {uccred.ErrSagaUncertain, ErrOutcomeUnknown},
		{uctrans.ErrUncertainCommit, ErrOutcomeUnknown}, {ucauto.ErrUncertainOutcome, ErrOutcomeUnknown}, {ucobs.ErrUncertainOutcome, ErrOutcomeUnknown},
		{ports.ErrNotFound, ErrNotFound}, {ucinv.ErrAssetNotFound, ErrNotFound}, {uctrans.ErrTransferNotFound, ErrNotFound},
		{ports.ErrAlreadyExists, ErrAlreadyExists}, {ucinv.ErrAssetAlreadyExists, ErrAlreadyExists},
		{ports.ErrAuthFailed, ErrAuthFailed}, {ports.ErrHostKeyUnknown, ErrHostKeyUnknown}, {ports.ErrHostKeyMismatch, ErrHostKeyMismatch},
		{ports.ErrHostKeyRevoked, ErrHostKeyRevoked}, {ports.ErrDialFailed, ErrDialFailed},
		{ports.ErrRemoteAnchorMismatch, ErrRemoteAnchorMismatch}, {ports.ErrRemoteIsDir, ErrRemoteIsDir}, {ports.ErrNotRegularFile, ErrNotRegularFile},
		{uctrans.ErrPatchConflict, ErrPatchConflict}, {uctrans.ErrDigestMismatch, ErrDigestMismatch},
		{ports.ErrSymlinkRejected, ErrSymlinkRejected}, {uctrans.ErrSymlinkPolicyDenied, ErrSymlinkRejected}, {ucauto.ErrSymlinkPolicyDenied, ErrSymlinkRejected}, {ucobs.ErrSymlinkPolicyDenied, ErrSymlinkRejected},
		{ucsess.ErrControlMasterDisabled, ErrControlMasterDisabled}, {ports.ErrMuxUnavailable, ErrMuxUnavailable}, {ucsess.ErrMuxMasterUnavailable, ErrMuxUnavailable},
		{pool.ErrHandleNotFound, ErrHandleNotFound}, {pool.ErrHandleRevoked, ErrHandleRevoked}, {pool.ErrLeaseRevoked, ErrHandleRevoked},
		{ports.ErrInteractionUnavailable, ErrInteractionUnavailable}, {ucinv.ErrInteractionUnavailable, ErrInteractionUnavailable}, {uccred.ErrInteractionUnavailable, ErrInteractionUnavailable},
		{ports.ErrInteractionCanceled, ErrInteractionCanceled},
		{ports.ErrCorruptData, ErrCorruptData}, {uctrans.ErrCorruptJournal, ErrCorruptData}, {ports.ErrLimitExceeded, ErrLimitExceeded},
		{ports.ErrUnsupported, ErrUnsupported}, {ucsess.ErrPortUnavailable, ErrUnsupported}, {uctrans.ErrOperatorReadUnavailable, ErrUnsupported},
		{uctrans.ErrScopedFSUnavailable, ErrUnsupported}, {uctrans.ErrJournalStoreUnavailable, ErrUnsupported}, {ucauto.ErrOperatorReadUnavailable, ErrUnsupported},
		{ucauto.ErrScopedFSUnavailable, ErrUnsupported}, {ucobs.ErrScopedFSUnavailable, ErrUnsupported}, {ucobs.ErrForwarderUnavailable, ErrUnsupported},
		{ports.ErrInvalidArgument, ErrInvalidRequest}, {ports.ErrInvalidRevision, ErrInvalidRequest}, {ports.ErrInvalidTTYSize, ErrInvalidRequest},
		{ucinv.ErrInvalidRequest, ErrInvalidRequest}, {ucinv.ErrInvalidTarget, ErrInvalidRequest}, {uccred.ErrInvalidRequest, ErrInvalidRequest},
		{ucsess.ErrInvalidRequest, ErrInvalidRequest}, {uctrans.ErrInvalidRequest, ErrInvalidRequest}, {ucauto.ErrInvalidRequest, ErrInvalidRequest},
		{ucobs.ErrInvalidRequest, ErrInvalidRequest}, {ucobs.ErrInvalidGUIInput, ErrInvalidRequest}, {ucobs.ErrInvalidLogTarget, ErrInvalidRequest},
	}
}

type engineErrGroup struct {
	pub  error
	srcs []error
}

func addEngineErrGroup(groups []engineErrGroup, pub, src error) []engineErrGroup {
	for i := range groups {
		if errors.Is(groups[i].pub, pub) {
			if !slices.ContainsFunc(groups[i].srcs, func(s error) bool { return errors.Is(s, src) && errors.Is(src, s) }) {
				groups[i].srcs = append(groups[i].srcs, src)
			}
			return groups
		}
	}
	return append(groups, engineErrGroup{pub: pub, srcs: []error{src}})
}

// mapEngineError 按目标门面哨兵分组收集全部命中的底层源哨兵（保首次命中序），
// 并逆序经 domi18n.WrapSentinel 封装以完整保留错误链与结构化无损折叠渲染。
func mapEngineError(err error) error {
	if err == nil {
		return nil
	}
	var groups []engineErrGroup
	if _, isCh := errors.AsType[*gate.ApprovalChallengeError](err); isCh && !errors.Is(err, ErrApprovalRequired) {
		groups = addEngineErrGroup(groups, ErrApprovalRequired, gate.ErrApprovalRequired)
	}
	for _, r := range engineErrorRules() {
		if errors.Is(err, r.src) && !errors.Is(err, r.pub) {
			groups = addEngineErrGroup(groups, r.pub, r.src)
		}
	}
	out := err
	for i := len(groups) - 1; i >= 0; i-- {
		out = domi18n.WrapSentinel(groups[i].pub, out, groups[i].srcs...)
	}
	return out
}
