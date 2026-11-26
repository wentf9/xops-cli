package engine_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/core/conc"
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/playbook"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
)

// 本文件模拟 Phase 5 受 archbound 严格约束的 internal/entry/** 依赖边界：
// 仅允许导入 stdlib 与 core/{domain/...,events,conc,engine}（物理 0 core/ports、0 core/internal/**、0 core/osfs），
// 在编译期与运行期实证全部不透明构造器、解析器、枚举常量、嵌套返回子类型、语义哨兵与 Engine 入口签名完整可用。

type entryEngineContract interface {
	ResolveTarget(context.Context, engine.ResolveTargetRequest) (engine.ResolvedTarget, error)
	ResolvePendingEnrollmentTarget(context.Context, *engine.PendingEnrollmentLease, option.OptionLayer) (engine.ResolvedTarget, error)
	ProbePendingEnrollmentTarget(context.Context, *engine.PendingEnrollmentLease, engine.ProbePendingEnrollmentRequest) (inventory.KeyFingerprint, error)
	CheckSecretReferences(context.Context, engine.SecretRefCheckRequest) ([]inventory.SecretReference, error)
	FindSecretReferences(context.Context, engine.FindSecretReferencesRequest) ([]inventory.SecretReference, error)
	CanSuspendProcessGroup() (security.Verdict, error)
	RecoverAllTransfers(context.Context, engine.RecoverAllTransfersRequest) (engine.RecoverAllResult, error)
	NewProjection(context.Context, engine.ProjectionConfig) (*engine.Projection, error)
	NewMCPServer(engine.MCPConfig) (*engine.MCPServer, error)
	BatchExec(context.Context, engine.BatchExecRequest) (engine.BatchExecReport, error)
	RunPlaybook(context.Context, engine.PlaybookRequest) (engine.PlaybookRunResult, error)
	SCPUpload(context.Context, engine.SCPUploadRequest) (engine.SCPUploadResult, error)
	SCPDownload(context.Context, engine.SCPDownloadRequest) (engine.SCPDownloadResult, error)
	Exec(context.Context, engine.ExecRequest) (execution.ExecutionOutcome, error)
	ExecPrivileged(context.Context, engine.PrivilegeExecRequest) (execution.ExecutionOutcome, error)
	StartForward(context.Context, engine.StartForwardRequest) (engine.ForwardInfo, error)
	StartControlMaster(context.Context, engine.ControlMasterRequest) (engine.ControlMasterInfo, error)
	ControlMux(context.Context, engine.MuxControlRequest) (engine.MuxControlResponse, error)
	InspectPTY(context.Context, plan.ManagedHandle[plan.KindPTY]) (engine.PTYStatus, error)
	StartTransfer(context.Context, engine.StartTransferRequest) (engine.TransferHandleInfo, error)
	StreamMetrics(context.Context, engine.MetricsStreamRequest) (engine.MetricsStreamResult, error)
	StreamLogs(context.Context, engine.LogStreamRequest) (engine.LogStreamResult, error)
	ExecuteGUI(context.Context, engine.GUIExecRequest) (engine.GUIExecResult, error)
	OpenGUISession(context.Context, engine.OpenGUISessionRequest) (engine.GUISessionInfo, error)
	RotateSecret(context.Context, engine.RotateSecretRequest, *secret.SecretBox) (engine.SagaResult, error)
	WithPendingEnrollment(context.Context, engine.PendingEnrollmentRequest, func(context.Context, *engine.PendingEnrollmentLease) error) (engine.PendingEnrollmentResult, error)
}

var _ entryEngineContract = (*engine.Engine)(nil)

func requireEntryValid[T interface{ IsValid() bool }](t *testing.T, label string, fn func() (T, error)) T {
	t.Helper()
	v, err := fn()
	if err != nil || !v.IsValid() {
		t.Fatalf("%s 失败: val=%+v err=%v", label, v, err)
	}
	return v
}

func requireEntryEq[T comparable](t *testing.T, label string, got T, err error, want T) {
	t.Helper()
	if err != nil || got != want {
		t.Fatalf("%s 失配: got=%v want=%v err=%v", label, got, want, err)
	}
}

func TestEntryContract_PureEngineConstructorsAndEnums(t *testing.T) {
	_ = conc.NewCtxMutex()
	var _ *events.OperationStream

	assertEntryCoreAuthAndTerminalConstructors(t)
	assertEntryPolicyAndAnchorConstructors(t)
	assertEntryForwardAndMuxConstructors(t)
	assertEntryTransferConstructors(t)
	assertEntryObsAndGUIConstructors(t)
	assertEntryCoreEnumSwitches(t)
	assertEntryObsAndGUISwitches(t)
}

func assertEntryCoreAuthAndTerminalConstructors(t *testing.T) {
	t.Helper()
	requireEntryValid(t, "NewSecretPromptRequest", func() (engine.SecretPromptRequest, error) {
		return engine.NewSecretPromptRequest(engine.SecretPromptRequestSpec{Title: "Unlock", Prompt: "Passphrase", Subject: "vault"})
	})
	if _, err := engine.NewSecretPromptRequest(engine.SecretPromptRequestSpec{}); !errors.Is(err, engine.ErrInvalidRequest) {
		t.Fatalf("非法 SecretPromptRequest 期望 ErrInvalidRequest，实际=%v", err)
	}
	vs, err := engine.ParseVaultState("unlocked")
	requireEntryEq(t, "ParseVaultState", vs, err, engine.VaultStateUnlocked)
	pm, err := engine.ParsePrivilegeMethod("sudo")
	requireEntryEq(t, "ParsePrivilegeMethod", pm, err, engine.PrivilegeMethodSudo)
	cmd := requireEntryValid(t, "NewCommandPlan", func() (execution.CommandPlan, error) {
		return execution.NewCommandPlan(execution.CommandPlanSpec{Kind: execution.PlanKindCommand, Profile: execution.DefaultServerLaunchProfile(), Command: "id"})
	})
	requireEntryValid(t, "NewPrivilegeRequest", func() (engine.PrivilegeRequest, error) {
		return engine.NewPrivilegeRequest(engine.PrivilegeRequestSpec{Method: pm, Command: cmd})
	})
	requireEntryValid(t, "ParseRevision", func() (engine.Revision, error) { return engine.ParseRevision("rev-001") })
	requireEntryValid(t, "NewTerminalSize", func() (engine.TerminalSize, error) { return engine.NewTerminalSize(120, 40) })
	if _, err := engine.NewTerminalSize(0, 0); !errors.Is(err, engine.ErrInvalidRequest) {
		t.Fatalf("零尺寸 TerminalSize 期望 ErrInvalidRequest，实际=%v", err)
	}
}

func assertEntryPolicyAndAnchorConstructors(t *testing.T) {
	t.Helper()
	rft, err := engine.ParseRemoteFileType("regular")
	requireEntryEq(t, "ParseRemoteFileType", rft, err, engine.RemoteFileRegular)
	requireEntryValid(t, "NewRemoteFileAnchor", func() (engine.RemoteFileAnchor, error) { return engine.NewRemoteFileAnchor(rft, true, 1, 42) })
	sev, err := engine.ParseDoctorSeverity("warn")
	requireEntryEq(t, "ParseDoctorSeverity", sev, err, engine.DoctorSeverityWarn)
	dig := security.DigestBytes([]byte("envelope"))
	requireEntryValid(t, "NewApprovalSubmission", func() (engine.ApprovalSubmission, error) {
		return engine.NewApprovalSubmission(security.VerdictAllow, dig, algebraic.None[security.ApprovalEnvelope](), "ok")
	})
	p, err := engine.ParsePolicyProfile("strict_agent")
	requireEntryEq(t, "ParsePolicyProfile", p, err, engine.PolicyProfileStrictAgent)
	fb, err := engine.ParseNoElicitFallback("challenge")
	requireEntryEq(t, "ParseNoElicitFallback", fb, err, engine.NoElicitFallbackChallenge)
	tty, err := engine.ParseRequestTTYMode("force")
	requireEntryEq(t, "ParseRequestTTYMode", tty, err, engine.RequestTTYForce)
}

func assertEntryForwardAndMuxConstructors(t *testing.T) {
	t.Helper()
	dir, err := engine.ParseForwardDirection("local")
	requireEntryEq(t, "ParseForwardDirection", dir, err, engine.ForwardLocal)
	ek, err := engine.ParseForwardEndpointKind("tcp")
	requireEntryEq(t, "ParseForwardEndpointKind", ek, err, engine.ForwardEndpointTCP)
	requireEntryValid(t, "NewForwardSpec", func() (engine.ForwardSpec, error) {
		return engine.NewForwardSpec(dir, "127.0.0.1:8080", "127.0.0.1:80")
	})
	requireEntryValid(t, "NewTypedForwardSpec", func() (engine.ForwardSpec, error) {
		return engine.NewTypedForwardSpec(dir, ek, "127.0.0.1:8081", ek, "127.0.0.1:80")
	})
	tm, err := engine.ParseTUNMode("point_to_point")
	requireEntryEq(t, "ParseTUNMode", tm, err, engine.TUNModePointToPoint)
	tun := requireEntryValid(t, "NewTUNSpec", func() (engine.TUNSpec, error) { return engine.NewTUNSpec(tm, engine.TUNUnitAny, 0) })
	requireEntryValid(t, "NewForwardTUNSpec", func() (engine.ForwardSpec, error) { return engine.NewForwardTUNSpec(tun) })
	act, err := engine.ParseMuxControlAction("check")
	requireEntryEq(t, "ParseMuxControlAction", act, err, engine.MuxActionCheck)
}

func assertEntryTransferConstructors(t *testing.T) {
	t.Helper()
	requireEntryValid(t, "NewTextEdit", func() (engine.TextEdit, error) { return engine.NewTextEdit("old", "new", false) })
	opPath := requireEntryValid(t, "ParseLocalSourcePath", func() (pathalg.LocalSourcePath, error) { return pathalg.ParseLocalSourcePath("/tmp/source.bin") })
	opSrc := requireEntryValid(t, "NewOperatorUploadSource", func() (engine.LocalUploadSource, error) {
		return engine.NewOperatorUploadSource(opPath, pathalg.SymlinkReject)
	})
	requireEntryEq(t, "opSrc.Kind", opSrc.Kind(), nil, engine.LocalUploadSourceOperator)
	rootDir := requireEntryValid(t, "ParseLocalDir", func() (pathalg.LocalDir, error) { return pathalg.ParseLocalDir("/tmp") })
	relDest := requireEntryValid(t, "ParseLocalRootedDest", func() (pathalg.LocalRootedDest, error) { return pathalg.ParseLocalRootedDest("sub/file.txt") })
	scSrc := requireEntryValid(t, "NewScopedUploadSource", func() (engine.LocalUploadSource, error) {
		return engine.NewScopedUploadSource(rootDir, relDest)
	})
	requireEntryEq(t, "scSrc.Kind", scSrc.Kind(), nil, engine.LocalUploadSourceScoped)
}

func assertEntryObsAndGUIConstructors(t *testing.T) {
	t.Helper()
	lk, err := engine.ParseLogTargetKind("file")
	requireEntryEq(t, "ParseLogTargetKind", lk, err, engine.LogTargetFile)
	rp := requireEntryValid(t, "ParseRemotePath", func() (pathalg.RemotePath, error) { return pathalg.ParseRemotePath("/var/log/app.log") })
	requireEntryValid(t, "NewFileLogTarget", func() (engine.LogTarget, error) { return engine.NewFileLogTarget(rp) })
	requireEntryValid(t, "NewDockerLogTarget", func() (engine.LogTarget, error) { return engine.NewDockerLogTarget("nginx") })
	ga, err := engine.ParseGUIActionKind("click")
	requireEntryEq(t, "ParseGUIActionKind", ga, err, engine.GUIActionClick)
	gs, err := engine.ParseGUISessionKind("vnc")
	requireEntryEq(t, "ParseGUISessionKind", gs, err, engine.GUISessionVNC)
	sd, err := engine.ParseScrollDirection("down")
	requireEntryEq(t, "ParseScrollDirection", sd, err, engine.ScrollDown)
	ps, err := engine.ParseProcessSortBy("cpu")
	requireEntryEq(t, "ParseProcessSortBy", ps, err, engine.ProcessSortCPU)
}

func assertEnumSet[T comparable](t *testing.T, label string, vals ...T) {
	t.Helper()
	seen := make(map[T]bool, len(vals))
	for _, v := range vals {
		if seen[v] {
			t.Fatalf("%s 含重复枚举值: %v", label, v)
		}
		seen[v] = true
	}
}

func assertEntryCoreEnumSwitches(t *testing.T) {
	t.Helper()
	assertEnumSet(t, "VaultState", engine.VaultStateInvalid, engine.VaultStateUninitialized, engine.VaultStateLocked, engine.VaultStateUnlocked)
	assertEnumSet(t, "PrivilegeMethod", engine.PrivilegeMethodInvalid, engine.PrivilegeMethodSudo, engine.PrivilegeMethodSu, engine.PrivilegeMethodDoas)
	assertEnumSet(t, "ForwardDirection", engine.ForwardDirectionInvalid, engine.ForwardLocal, engine.ForwardRemote, engine.ForwardDynamic, engine.ForwardTUN)
	assertEnumSet(t, "ForwardEndpointKind", engine.ForwardEndpointInvalid, engine.ForwardEndpointTCP, engine.ForwardEndpointUnix)
	assertEnumSet(t, "TUNMode", engine.TUNModeInvalid, engine.TUNModePointToPoint, engine.TUNModeEthernet)
	assertEnumSet(t, "MuxControlAction", engine.MuxActionInvalid, engine.MuxActionCheck, engine.MuxActionForward, engine.MuxActionCancel, engine.MuxActionExit, engine.MuxActionStop, engine.MuxActionProxy)
	assertEnumSet(t, "RemoteFileType", engine.RemoteFileTypeInvalid, engine.RemoteFileRegular, engine.RemoteFileDir, engine.RemoteFileSymlink, engine.RemoteFileOther)
	assertEnumSet(t, "DoctorSeverity", engine.DoctorSeverityInvalid, engine.DoctorSeverityInfo, engine.DoctorSeverityWarn, engine.DoctorSeverityError)
	assertEnumSet(t, "LocalUploadSourceKind", engine.LocalUploadSourceInvalid, engine.LocalUploadSourceOperator, engine.LocalUploadSourceScoped)
}

func assertEntryObsAndGUISwitches(t *testing.T) {
	t.Helper()
	assertEnumSet(t, "LogTargetKind", engine.LogTargetInvalid, engine.LogTargetFile, engine.LogTargetDocker)
	assertEnumSet(t, "ProcessSortBy", engine.ProcessSortInvalid, engine.ProcessSortCPU, engine.ProcessSortMem)
	assertEnumSet(t, "GUIActionKind", engine.GUIActionInvalid, engine.GUIActionScreenshot, engine.GUIActionClick, engine.GUIActionDoubleClick, engine.GUIActionRightClick, engine.GUIActionMove, engine.GUIActionDrag, engine.GUIActionScroll, engine.GUIActionType, engine.GUIActionKey)
	assertEnumSet(t, "ScrollDirection", engine.ScrollDirectionInvalid, engine.ScrollUp, engine.ScrollDown, engine.ScrollLeft, engine.ScrollRight)
	assertEnumSet(t, "GUISessionKind", engine.GUISessionInvalid, engine.GUISessionX11, engine.GUISessionVNC)
}

func TestEntryContract_ReturnSubtypesSentinelsAndEntrySignatures(t *testing.T) {
	// 显式声明全部公开返回子类型与嵌套字段类型，确保 entry 包在 0 ports/internal 导入下可编译。
	var (
		_ engine.Revision
		_ engine.DurabilityOutcome
		_ engine.InventorySnapshot
		_ engine.CrashReconcileReport
		_ engine.ReconcileReport
		_ engine.VaultStatus
		_ engine.ShellProbeResult
		_ engine.RemoteFileStat
		_ engine.RemoteDirEntry
		_ engine.MuxControlResponse
		_ engine.HandleStatus
		_ engine.ResolvedTarget
		_ engine.MutationResult
		_ engine.ImportPreview
		_ engine.ImportResult
		_ engine.InventoryDoctorRep
		_ engine.CredentialDoctorRep
		_ engine.DoctorFinding
		_ engine.RetainedSecret
		_ engine.GCUnreferencedResult
		_ engine.SagaResult
		_ engine.PendingEnrollmentResult
		_ engine.EnrollEncryptedPrivateKeyResult
		_ engine.PTYReadRequest
		_ engine.PTYReadResult
		_ engine.PTYStatus
		_ engine.ForwardInfo
		_ engine.ForwardStatus
		_ engine.ControlMasterInfo
		_ engine.ControlMasterStatus
		_ engine.TransferSessionOptions
		_ engine.SCPUploadResult
		_ engine.SCPDownloadResult
		_ engine.ReadFileResult
		_ engine.WriteFileResult
		_ engine.PatchFileResult
		_ engine.ListDirResult
		_ engine.TransferHandleInfo
		_ engine.WriteTransferChunkRes
		_ engine.PullTransferChunkResult
		_ engine.CommitTransferResult
		_ engine.TransferRecoveryResult
		_ engine.TransferRecoveryEntry
		_ engine.RecoverAllResult
		_ engine.TransferStatusSnapshot
		_ engine.NodeStreamFactory
		_ engine.BatchNodeResult
		_ engine.BatchExecReport
		_ engine.PlaybookRunResult
		_ engine.DiskMetric
		_ engine.ProcessMetric
		_ engine.HostMetricsFrame
		_ engine.ProcessedScreenshot
		_ engine.OperationView
		_ engine.MetricPoint
		_ engine.LogEntry
		_ engine.DiagnosticRecord
		_ engine.PoolRecord
		_ engine.ProjectionSnapshot
		_ engine.MetricsStreamResult
		_ engine.LogStreamResult
		_ engine.GUIExecResult
		_ engine.GUISessionInfo
		_ engine.GUISessionStatus
		_ engine.TransferRecSummary
		_ engine.MCPStartupReport
		_ engine.ApprovalChallenge
		_ engine.ReferenceConflict
		_ engine.HaltInfo
		_ netaddr.Endpoint
		_ fsm.TransferStateKind
		_ playbook.Playbook
		_ time.Time
	)

	sentinels := []error{
		engine.ErrNilContext, engine.ErrInvalidConfig, engine.ErrEngineNotInitialized, engine.ErrEngineClosed, engine.ErrEngineHalted,
		engine.ErrInvalidRequest, engine.ErrInvalidProfile, engine.ErrInvalidFallback, engine.ErrInvalidRequestTTY,
		engine.ErrReconcilerUnavailable, engine.ErrVaultUnavailable, engine.ErrMCPServerNotInitialized, engine.ErrProjectionNotInitialized,
		engine.ErrApprovalRequired, engine.ErrApprovalRejected, engine.ErrAuthorizationDenied, engine.ErrScopeEscalated,
		engine.ErrNotFound, engine.ErrAlreadyExists, engine.ErrRevisionConflict, engine.ErrStillReferenced, engine.ErrImportConflict,
		engine.ErrUncertainDurability, engine.ErrOutcomeUnknown, engine.ErrVaultLocked, engine.ErrSecretNotFound, engine.ErrAuthFailed,
		engine.ErrHostKeyUnknown, engine.ErrHostKeyMismatch, engine.ErrHostKeyRevoked, engine.ErrDialFailed,
		engine.ErrControlMasterDisabled, engine.ErrMuxUnavailable, engine.ErrHandleNotFound, engine.ErrHandleRevoked,
		engine.ErrInteractionUnavailable, engine.ErrInteractionCanceled, engine.ErrRemoteAnchorMismatch, engine.ErrRemoteIsDir,
		engine.ErrNotRegularFile, engine.ErrPatchConflict, engine.ErrDigestMismatch, engine.ErrSymlinkRejected,
		engine.ErrCorruptData, engine.ErrLimitExceeded, engine.ErrUnsupported,
	}
	assertEnumSet(t, "engine.Err*", sentinels...)
	if ch, ok := engine.ExtractApprovalChallenge(nil); ok || ch.IsValid() {
		t.Fatalf("ExtractApprovalChallenge(nil) 必须失败关闭")
	}
	if rc, ok := engine.ExtractReferenceConflict(nil); ok || rc.IsValid() {
		t.Fatalf("ExtractReferenceConflict(nil) 必须失败关闭")
	}
}
