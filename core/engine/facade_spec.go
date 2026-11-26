package engine

import (
	"errors"
	"io"
	"io/fs"
	"time"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
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
	ucauto "github.com/wentf9/xops-cli/core/internal/usecase/automation"
	uccred "github.com/wentf9/xops-cli/core/internal/usecase/credential"
	ucinv "github.com/wentf9/xops-cli/core/internal/usecase/inventory"
	ucobs "github.com/wentf9/xops-cli/core/internal/usecase/observability"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
	"github.com/wentf9/xops-cli/core/ports"
)

// 公开核心值类型别名：使 internal/entry/** 与外部宿主仅导入 core/engine 即可消费全量强类型契约而无需导入 core/ports 或 core/internal。
type (
	Revision            = ports.Revision
	DurabilityOutcome   = ports.DurabilityOutcome
	InventorySnapshot   = ports.InventorySnapshot
	VaultStatus         = ports.VaultStatus
	ForwardSpec         = ports.ForwardSpec
	ForwardDirection    = ports.ForwardDirection
	ForwardEndpointKind = ports.ForwardEndpointKind
	TUNSpec             = ports.TUNSpec
	TUNMode             = ports.TUNMode
	MuxControlAction    = ports.MuxControlAction
	MuxControlResponse  = ports.MuxControlResponse
	PrivilegeMethod     = ports.PrivilegeMethod
	PrivilegeRequest    = ports.PrivilegeRequest
	ShellProbeResult    = ports.ShellProbeResult
	TerminalSize        = ports.TerminalSize
	RemoteFileStat      = ports.RemoteFileStat
	RemoteFileAnchor    = ports.RemoteFileAnchor
	RemoteDirEntry      = ports.RemoteDirEntry
	SecretPromptRequest = ports.SecretPromptRequest

	MutationResult                  = ucinv.MutationResult
	ImportPreview                   = ucinv.ImportPreview
	ImportResult                    = ucinv.ImportResult
	InventoryDoctorRep              = ucinv.DoctorReport
	PendingProbeFunc                = ucinv.PendingProbeFunc
	PendingEnrollmentResult         = ucinv.PendingEnrollmentResult
	PendingEnrollmentLease          = ucinv.PendingEnrollmentLease
	EnrollEncryptedPrivateKeyResult = ucinv.EnrollEncryptedPrivateKeyResult
	DoctorFinding                   = uccred.DoctorFinding
	CredentialDoctorRep             = uccred.DoctorReport
	GCUnreferencedResult            = uccred.GCUnreferencedResult
	SagaResult                      = uccred.SagaResult
	GraphMutator                    = uccred.GraphMutator
	OldSecretRefsResolver           = uccred.OldSecretRefsResolver
	NewSecretVerifier               = uccred.NewSecretVerifier
	PTYReadResult                   = ucsess.PTYReadResult
	PTYStatus                       = ucsess.PTYStatus
	ForwardInfo                     = ucsess.ForwardInfo
	ForwardStatus                   = ucsess.ForwardStatus
	ControlMasterInfo               = ucsess.ControlMasterInfo
	ControlMasterStatus             = ucsess.ControlMasterStatus
	TextEdit                        = uctrans.TextEdit
	LocalUploadSource               = uctrans.LocalUploadSource
	SCPUploadResult                 = uctrans.SCPUploadResult
	SCPDownloadResult               = uctrans.SCPDownloadResult
	ReadFileResult                  = uctrans.ReadFileResult
	WriteFileResult                 = uctrans.WriteFileResult
	PatchFileResult                 = uctrans.PatchFileResult
	ListDirResult                   = uctrans.ListDirResult
	TransferHandleInfo              = uctrans.TransferHandleInfo
	WriteTransferChunkRes           = uctrans.WriteTransferChunkResult
	PullTransferChunkResult         = uctrans.PullTransferChunkResult
	CommitTransferResult            = uctrans.CommitTransferResult
	TransferRecoveryResult          = uctrans.TransferRecoveryResult
	RecoverAllResult                = uctrans.RecoverAllResult
	TransferStatusSnapshot          = uctrans.TransferStatusSnapshot
	BatchExecReport                 = ucauto.BatchExecReport
	PlaybookRunResult               = ucauto.PlaybookRunResult
	HostMetricsFrame                = ucobs.HostMetricsFrame
	GUIActionSpec                   = ucobs.GUIActionSpec
	GUIArtifactDest                 = ucobs.GUIArtifactDest
	GUISessionSpec                  = ucobs.GUISessionSpec
	LogTarget                       = ucobs.LogTarget
	ProcessSortBy                   = ucobs.ProcessSortBy
	ProjectionConfig                = ucobs.ProjectionConfig
	ProjectionSnapshot              = ucobs.ProjectionSnapshot
	MetricsStreamResult             = ucobs.MetricsStreamResult
	LogStreamResult                 = ucobs.LogStreamResult
	GUIExecResult                   = ucobs.GUIExecResult
	GUISessionInfo                  = ucobs.GUISessionInfo
	GUISessionStatus                = ucobs.GUISessionStatus
	TransferRecSummary              = mcpruntime.TransferRecoverySummary
	MCPStartupReport                = mcpruntime.StartupReport
)

// ApprovalSubmission 封装两步审批流程中由入站适配器回传的不可变审批提交对象（零 core/internal/gate 泄漏）。
//
//xops:opaque
//xops:failclosed
type ApprovalSubmission struct {
	inner gate.ApprovalSubmission
	valid bool
}

// NewApprovalSubmission 校验用户审批判定、信封 SHA-256 摘要与可选完整信封，构造公开 ApprovalSubmission。
func NewApprovalSubmission(verdict security.Verdict, envelopeDigest security.Digest, envelope algebraic.Option[security.ApprovalEnvelope], comment string) (ApprovalSubmission, error) {
	resp, err := ports.NewApprovalDecisionResponse(verdict, envelopeDigest, comment)
	if err != nil {
		return ApprovalSubmission{}, err
	}
	sub, err := gate.NewApprovalSubmission(gate.ApprovalSubmissionSpec{Envelope: envelope, Response: resp})
	if err != nil {
		return ApprovalSubmission{}, err
	}
	return ApprovalSubmission{inner: sub, valid: true}, nil
}

// IsValid / IsZero 报告 ApprovalSubmission 有效性。
func (a ApprovalSubmission) IsValid() bool { return a.valid && a.inner.IsValid() }
func (a ApprovalSubmission) IsZero() bool  { return !a.IsValid() }

func toGateApproval(opt algebraic.Option[ApprovalSubmission]) algebraic.Option[gate.ApprovalSubmission] {
	if sub, ok := opt.Get(); ok && sub.IsValid() {
		return algebraic.Some(sub.inner)
	}
	return algebraic.None[gate.ApprovalSubmission]()
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
	ch, ok := errors.AsType[*gate.ApprovalChallengeError](err)
	if !ok || ch == nil || !ch.IsValid() {
		return ApprovalChallenge{}, false
	}
	return ApprovalChallenge{envelope: ch.Envelope(), digest: ch.EnvelopeDigest(), escalated: ch.Escalated(), reason: ch.Reason(), valid: true}, true
}

func (c ApprovalChallenge) IsValid() bool {
	return c.valid && c.envelope.IsValid() && c.digest.IsValid()
}
func (c ApprovalChallenge) Envelope() security.ApprovalEnvelope { return c.envelope }
func (c ApprovalChallenge) EnvelopeDigest() security.Digest     { return c.digest }
func (c ApprovalChallenge) Escalated() bool                     { return c.valid && c.escalated }
func (c ApprovalChallenge) Reason() string                      { return c.reason }

// 公共入参复用结构体：RemoteCall / TargetInput / CallOptions / TransferSessionOptions。
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
	TransferSessionOptions struct {
		LocalRoot                algebraic.Option[pathalg.LocalDir]
		RemoteSource             algebraic.Option[pathalg.RemotePath]
		NoClobber, PreserveTimes bool
		ExpectedAnchor           algebraic.Option[RemoteFileAnchor]
		Perm                     algebraic.Option[fs.FileMode]
	}
)

// Inventory 与 Credential 公开门面请求类型（零明文字段）。
type (
	InventoryQueryRequest struct{ CallOptions }
	HostMutationRequest   struct {
		CallOptions
		Host             inventory.Host
		ExpectedRevision algebraic.Option[Revision]
		ScopeSummary     string
	}
	IdentityMutationRequest struct {
		CallOptions
		Identity                 inventory.Identity
		ExpectedRevision         algebraic.Option[Revision]
		GCUnreferencedOldSecrets bool
		ScopeSummary             string
	}
	NodeMutationRequest struct {
		CallOptions
		Node                     inventory.Node
		ExpectedRevision         algebraic.Option[Revision]
		GCUnreferencedOldSecrets bool
		ScopeSummary             string
	}
	DeleteAssetRequest struct {
		CallOptions
		ID, ScopeSummary                                string
		ExpectedRevision                                algebraic.Option[Revision]
		DeleteUnusedSecrets, RequireSecretsUnreferenced bool
	}
	InventoryDoctorRequest struct {
		CallOptions
		CheckVaultSecrets, CheckPrivateKeys bool
	}
	ImportRequest struct {
		CallOptions
		Format, SourceName, ScopeSummary string
		Reader                           io.Reader
		Bundle                           algebraic.Option[inventory.ImportBundle]
		ExpectedRevision                 algebraic.Option[Revision]
		DryRun                           bool
	}
	VaultOpRequest struct {
		CallOptions
		ScopeSummary string
	}
	WithSecretRequest struct {
		CallOptions
		Ref                  secret.Ref
		NodeID, ScopeSummary string
	}
	DeleteSecretRequest struct {
		CallOptions
		Ref          secret.Ref
		ScopeSummary string
	}
	GCUnreferencedRequest struct {
		CallOptions
		Candidates   []secret.Ref
		ScopeSummary string
	}
	RotateSecretRequest struct {
		CallOptions
		OldRef, NewRef            secret.Ref
		TargetStore, ScopeSummary string
		ExpectedRevision          algebraic.Option[Revision]
	}
	PendingEnrollmentRequest struct {
		CallOptions
		Host             algebraic.Option[inventory.Host]
		Identity         algebraic.Option[inventory.Identity]
		Node             inventory.Node
		PinnedRefs       []secret.Ref
		ExtraPending     []inventory.PendingSecretRef
		ExpectedRevision algebraic.Option[Revision]
		TTL              algebraic.Duration
		ScopeSummary     string
	}
	EnrollEncryptedPrivateKeyRequest struct {
		CallOptions
		IdentityID                             inventory.IdentityID
		User                                   option.Username
		KeyPath                                inventory.KeyPathSpec
		CertPaths                              []inventory.CertPathSpec
		Description, TargetStore, ScopeSummary string
		Tags                                   []inventory.Tag
		NewRef                                 secret.Ref
		ExpectedFingerprint                    algebraic.Option[inventory.KeyFingerprint]
		ReplaceExisting                        bool
		ExpectedRevision                       algebraic.Option[Revision]
		Prompt                                 SecretPromptRequest
		ExtraPending                           []inventory.PendingSecretRef
	}
	InteractiveVaultOpRequest struct {
		CallOptions
		Prompt        SecretPromptRequest
		ConfirmPrompt algebraic.Option[SecretPromptRequest]
		ScopeSummary  string
	}
	VaultSagaRequest struct {
		CallOptions
		NewRef                                    secret.Ref
		TargetStore, Action, NodeID, ScopeSummary string
		OldRef                                    algebraic.Option[secret.Ref]
		ResolveOldRefs                            OldSecretRefsResolver
		ExpectedRevision                          algebraic.Option[Revision]
		ExpectedCASVersion                        uint64
		VerifyNewRef                              NewSecretVerifier
		MutateGraph                               GraphMutator
		ExtraPending                              []inventory.PendingSecretRef
	}
	InteractiveVaultSagaRequest struct {
		Prompt SecretPromptRequest
		Saga   VaultSagaRequest
	}
	InteractiveRotateSecretRequest struct {
		Prompt SecretPromptRequest
		Rotate RotateSecretRequest
	}
)

// Session 与 Transfer 公开门面请求类型。
type (
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
	PTYReadRequest struct {
		Handle   plan.ManagedHandle[plan.KindPTY]
		MaxBytes int
		Wait     bool
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
		Source                                                        LocalUploadSource
		RemoteDest                                                    pathalg.RemotePath
		ExpandIntoDir, NoClobber, Resume, PreserveMode, PreserveTimes bool
		Perm                                                          algebraic.Option[fs.FileMode]
		ModTime                                                       algebraic.Option[time.Time]
		ChunkSize                                                     int64
		Concurrency                                                   int
		ExpectedDigest                                                algebraic.Option[security.Digest]
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
)

// Automation、Observability 与 MCP 运行时公开门面请求/配置类型（零裸 time.Duration）。
type (
	BatchExecRequest struct {
		CallOptions
		Targets        []ResolvedTarget
		Selector       algebraic.Option[playbook.TargetSelector]
		CLIOptions     option.OptionLayer
		ExcludeNodes   []inventory.NodeID
		ExcludeTags    []inventory.Tag
		Command        execution.CommandPlan
		Concurrency    int
		MaxOutputBytes uint64
		OutputDir      algebraic.Option[pathalg.LocalDir]
		FailFast       bool
	}
	PlaybookRequest struct {
		CallOptions
		Playbook         playbook.Playbook
		Targets          []ResolvedTarget
		CLIOptions       option.OptionLayer
		ScopedSourceRoot algebraic.Option[pathalg.LocalDir]
		Concurrency      int
		Timeout          algebraic.Option[algebraic.Duration]
		ExtraVars        map[string]string
	}
	MetricsStreamRequest struct {
		RemoteCall
		Interval, Timeout        algebraic.Option[algebraic.Duration]
		MaxSamples, TopProcesses int
		SortBy                   algebraic.Option[ProcessSortBy]
		OnFrame                  func(HostMetricsFrame)
	}
	LogStreamRequest struct {
		RemoteCall
		Target    LogTarget
		TailLines int
		Follow    bool
		MaxBytes  uint64
		Timeout   algebraic.Option[algebraic.Duration]
		Output    io.Writer
	}
	GUIExecRequest struct {
		RemoteCall
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
