package cli_test

import (
	"bytes"
	"context"
	jsonv2 "encoding/json/v2"
	"io"
	"sync"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/secret"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/engine"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/internal/entry/cli"
	"github.com/wentf9/xops-cli/internal/entry/cli/clikit"
)

// fakeFullEngine 在进程内实现全部 7 个 clikit 引擎能力窄接口，供全命令面端到端路由与 JSON/v2 单测使用。
type fakeFullEngine struct {
	mu sync.Mutex

	runSSHFn      func(context.Context, engine.RunSSHRequest) (execution.ExecutionOutcome, error)
	execFn        func(context.Context, engine.ExecRequest) (execution.ExecutionOutcome, error)
	execPrivFn    func(context.Context, engine.PrivilegeExecRequest) (execution.ExecutionOutcome, error)
	batchExecFn   func(context.Context, engine.BatchExecRequest) (engine.BatchExecReport, error)
	runPlaybookFn func(context.Context, engine.PlaybookRequest) (engine.PlaybookRunResult, error)
	scpUploadFn   func(context.Context, engine.SCPUploadRequest) (engine.SCPUploadResult, error)
	scpDownloadFn func(context.Context, engine.SCPDownloadRequest) (engine.SCPDownloadResult, error)
	invDoctorFn   func(context.Context, engine.InventoryDoctorRequest) (engine.InventoryDoctorRep, error)
	vaultDoctorFn func(context.Context, engine.VaultDoctorRequest) (engine.CredentialDoctorRep, error)
	probeMuxFn    func(context.Context, engine.MuxControlRequest) (engine.MuxControlResponse, error)
	deleteHostFn  func(context.Context, engine.DeleteAssetRequest) (engine.MutationResult, error)
	reconcileFn   func(context.Context) (engine.ReconcileReport, error)
	closeFn       func(context.Context) error
	importFormats []string

	calls              []string
	lastSSHReq         engine.RunSSHRequest
	lastExecReq        engine.ExecRequest
	lastPrivReq        engine.PrivilegeExecRequest
	lastBatchReq       engine.BatchExecRequest
	lastPlaybookReq    engine.PlaybookRequest
	lastFwdReqs        []engine.StartForwardRequest
	lastMasterReq      engine.ControlMasterRequest
	lastMuxReq         engine.MuxControlRequest
	lastUploadReq      engine.SCPUploadRequest
	lastDownloadReq    engine.SCPDownloadRequest
	lastImportReq      engine.ImportRequest
	lastHostMut        engine.HostMutationRequest
	lastIdentMut       engine.IdentityMutationRequest
	lastNodeMut        engine.NodeMutationRequest
	lastDeleteReq      engine.DeleteAssetRequest
	lastWriteReq       engine.RemoteFileWriteRequest
	lastPatchReq       engine.RemoteFilePatchRequest
	lastEnrollReq      engine.EnrollEncryptedPrivateKeyRequest
	lastRenameReq      engine.RemoteRenameRequest
	lastChmodReq       engine.RemotePathOpRequest
	lastRecoverReq     engine.RecoverTransferRequest
	lastVaultInitReq   engine.InteractiveVaultOpRequest
	lastVaultUnlockReq engine.InteractiveVaultOpRequest
	lastVaultSaga      engine.InteractiveVaultSagaRequest
	lastRotateReq      engine.InteractiveRotateSecretRequest
	vaultSagaFn        func(context.Context, engine.InteractiveVaultSagaRequest) (engine.SagaResult, error)
	rotateSecretFn     func(context.Context, engine.InteractiveRotateSecretRequest) (engine.SagaResult, error)
}

var (
	_ clikit.SSHClient        = (*fakeFullEngine)(nil)
	_ clikit.AutomationClient = (*fakeFullEngine)(nil)
	_ clikit.TransferClient   = (*fakeFullEngine)(nil)
	_ clikit.InventoryClient  = (*fakeFullEngine)(nil)
	_ clikit.VaultClient      = (*fakeFullEngine)(nil)
	_ clikit.ReconcileClient  = (*fakeFullEngine)(nil)
)

func (f *fakeFullEngine) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
}

func (f *fakeFullEngine) hasCall(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if c == name {
			return true
		}
	}
	return false
}

func (f *fakeFullEngine) Close(ctx context.Context) error {
	f.record("Close")
	if f.closeFn != nil {
		return f.closeFn(ctx)
	}
	return nil
}

func (f *fakeFullEngine) RunSSH(ctx context.Context, req engine.RunSSHRequest) (execution.ExecutionOutcome, error) {
	f.record("RunSSH")
	f.lastSSHReq = req
	if f.runSSHFn != nil {
		return f.runSSHFn(ctx, req)
	}
	if req.Stdout != nil {
		_, _ = io.WriteString(req.Stdout, "ssh-ok\n")
	}
	out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	return out, nil
}

func (f *fakeFullEngine) ResolveTarget(_ context.Context, _ engine.ResolveTargetRequest) (res engine.ResolvedTarget, err error) {
	f.record("ResolveTarget")
	return res, nil
}

func (f *fakeFullEngine) Exec(ctx context.Context, req engine.ExecRequest) (execution.ExecutionOutcome, error) {
	f.record("Exec")
	f.lastExecReq = req
	if f.execFn != nil {
		return f.execFn(ctx, req)
	}
	if req.Stdout != nil {
		_, _ = io.WriteString(req.Stdout, "exec-out\n")
	}
	out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	return out, nil
}

func (f *fakeFullEngine) ExecPrivileged(ctx context.Context, req engine.PrivilegeExecRequest) (execution.ExecutionOutcome, error) {
	f.record("ExecPrivileged")
	f.lastPrivReq = req
	if f.execPrivFn != nil {
		return f.execPrivFn(ctx, req)
	}
	out, _ := execution.NewOutcomeCompleted(execution.NewExitCode(0), false)
	return out, nil
}

func (f *fakeFullEngine) ProbeShell(_ context.Context, _ engine.ProbeShellRequest) (res engine.ShellProbeResult, err error) {
	f.record("ProbeShell")
	return res, nil
}

func (f *fakeFullEngine) StartForward(_ context.Context, req engine.StartForwardRequest) (info engine.ForwardInfo, err error) {
	f.record("StartForward")
	f.mu.Lock()
	f.lastFwdReqs = append(f.lastFwdReqs, req)
	f.mu.Unlock()
	return info, nil
}

func (f *fakeFullEngine) InspectForward(_ context.Context, _ plan.ManagedHandle[plan.KindTunnel]) (st engine.ForwardStatus, err error) {
	f.record("InspectForward")
	return st, nil
}

func (f *fakeFullEngine) StopForward(_ context.Context, _ plan.ManagedHandle[plan.KindTunnel]) error {
	f.record("StopForward")
	return nil
}

func (f *fakeFullEngine) StartControlMaster(_ context.Context, req engine.ControlMasterRequest) (info engine.ControlMasterInfo, err error) {
	f.record("StartControlMaster")
	f.lastMasterReq = req
	return info, nil
}

func (f *fakeFullEngine) InspectControlMaster(_ context.Context, _ plan.ManagedHandle[plan.KindMux]) (st engine.ControlMasterStatus, err error) {
	f.record("InspectControlMaster")
	return st, nil
}

func (f *fakeFullEngine) StopControlMaster(_ context.Context, _ plan.ManagedHandle[plan.KindMux]) error {
	f.record("StopControlMaster")
	return nil
}

func (f *fakeFullEngine) ProbeMux(ctx context.Context, req engine.MuxControlRequest) (engine.MuxControlResponse, error) {
	f.record("ProbeMux")
	f.lastMuxReq = req
	if f.probeMuxFn != nil {
		return f.probeMuxFn(ctx, req)
	}
	return mustDecodeJSON[engine.MuxControlResponse](`{"alive":true,"master_pid":4242,"detail":"running"}`), nil
}

func (f *fakeFullEngine) ControlMux(_ context.Context, req engine.MuxControlRequest) (engine.MuxControlResponse, error) {
	f.record("ControlMux")
	f.lastMuxReq = req
	return mustDecodeJSON[engine.MuxControlResponse](`{"alive":true,"master_pid":4242,"detail":"applied"}`), nil
}

func (f *fakeFullEngine) RunMuxProxy(_ context.Context, req engine.MuxControlRequest, _ io.ReadCloser, out io.Writer) error {
	f.record("RunMuxProxy")
	f.lastMuxReq = req
	_, _ = io.WriteString(out, "proxy-stream")
	return nil
}

func (f *fakeFullEngine) NewOperationStream(_ context.Context, buffer int) (*events.OperationStream, error) {
	f.record("NewOperationStream")
	tr, _ := security.ParseTraceID("0123456789abcdef0123456789abcdef")
	op, _ := security.ParseOperationID("fedcba9876543210")
	return events.NewOperationStream(events.OperationStreamConfig{
		TraceID:         tr,
		OperationID:     op,
		OperationBuffer: buffer,
	})
}

func (f *fakeFullEngine) BatchExec(ctx context.Context, req engine.BatchExecRequest) (rep engine.BatchExecReport, err error) {
	f.record("BatchExec")
	f.lastBatchReq = req
	if f.batchExecFn != nil {
		return f.batchExecFn(ctx, req)
	}
	return rep, nil
}

func (f *fakeFullEngine) RunPlaybook(ctx context.Context, req engine.PlaybookRequest) (res engine.PlaybookRunResult, err error) {
	f.record("RunPlaybook")
	f.lastPlaybookReq = req
	if f.runPlaybookFn != nil {
		return f.runPlaybookFn(ctx, req)
	}
	return res, nil
}

func (f *fakeFullEngine) SCPUpload(ctx context.Context, req engine.SCPUploadRequest) (engine.SCPUploadResult, error) {
	f.record("SCPUpload")
	f.lastUploadReq = req
	// 严格对齐 core/internal/usecase/transfer/scp_upload.go 真实不变量：递归上传必须使用 ScopedRootFS 且 SymlinkReject。
	if req.Recursive && (req.Source.Kind() != engine.LocalUploadSourceScoped || req.SymlinkPolicy != pathalg.SymlinkReject) {
		return engine.SCPUploadResult{}, engine.ErrInvalidRequest
	}
	if f.scpUploadFn != nil {
		return f.scpUploadFn(ctx, req)
	}
	return engine.SCPUploadResult{RemotePath: req.RemoteDest, FilesUploaded: 1, BytesTransferred: 128, ChunksTransferred: 1}, nil
}

func (f *fakeFullEngine) SCPDownload(ctx context.Context, req engine.SCPDownloadRequest) (engine.SCPDownloadResult, error) {
	f.record("SCPDownload")
	f.lastDownloadReq = req
	// 严格对齐 core/internal/usecase/transfer/scp_download.go 真实不变量：下载严禁 SymlinkFollowOperatorSource。
	if req.SymlinkPolicy == pathalg.SymlinkFollowOperatorSource {
		return engine.SCPDownloadResult{}, engine.ErrInvalidRequest
	}
	if f.scpDownloadFn != nil {
		return f.scpDownloadFn(ctx, req)
	}
	return engine.SCPDownloadResult{LocalDest: req.LocalDest, FilesDownloaded: 1, BytesTransferred: 64, ChunksTransferred: 1}, nil
}

func (f *fakeFullEngine) ReadRemoteFile(_ context.Context, _ engine.RemoteFileReadRequest) (engine.ReadFileResult, error) {
	f.record("ReadRemoteFile")
	data := []byte("hello-remote\n")
	st := mustDecodeJSON[engine.RemoteFileStat](`{"path":"/etc/hosts","size":13,"mode":420,"anchor":{"file_type":"regular"}}`)
	return engine.ReadFileResult{Stat: st, Digest: security.DigestBytes(data), Content: data}, nil
}

func (f *fakeFullEngine) WriteRemoteFile(_ context.Context, req engine.RemoteFileWriteRequest) (engine.WriteFileResult, error) {
	f.record("WriteRemoteFile")
	f.lastWriteReq = req
	st := mustDecodeJSON[engine.RemoteFileStat](`{"path":"/tmp/a.txt","size":10,"mode":416,"anchor":{"file_type":"regular"}}`)
	return engine.WriteFileResult{Stat: st, BytesWritten: int64(len(req.Content)), Digest: security.DigestBytes(req.Content)}, nil
}

func (f *fakeFullEngine) PatchRemoteFile(_ context.Context, req engine.RemoteFilePatchRequest) (engine.PatchFileResult, error) {
	f.record("PatchRemoteFile")
	f.lastPatchReq = req
	return engine.PatchFileResult{
		Replacements: 1,
		BytesWritten: 32,
		BeforeDigest: security.DigestBytes([]byte("foo")),
		AfterDigest:  security.DigestBytes([]byte("bar")),
	}, nil
}

func (f *fakeFullEngine) StatRemoteFile(_ context.Context, _ engine.RemoteStatRequest) (engine.RemoteFileStat, error) {
	f.record("StatRemoteFile")
	return mustDecodeJSON[engine.RemoteFileStat](`{"path":"/etc/hosts","size":99,"mode":420,"anchor":{"file_type":"regular"}}`), nil
}

func (f *fakeFullEngine) RenameRemoteFile(_ context.Context, req engine.RemoteRenameRequest) error {
	f.record("RenameRemoteFile")
	f.lastRenameReq = req
	return nil
}

func (f *fakeFullEngine) ListRemoteDir(_ context.Context, req engine.RemotePathOpRequest) (engine.ListDirResult, error) {
	f.record("ListRemoteDir")
	entry := mustDecodeJSON[engine.RemoteDirEntry](`{"name":"app.conf","file_type":"regular","size":42,"mode":420}`)
	return engine.ListDirResult{Path: req.Path, Entries: []engine.RemoteDirEntry{entry}}, nil
}

func (f *fakeFullEngine) MkdirRemoteAll(_ context.Context, _ engine.RemotePathOpRequest) error {
	f.record("MkdirRemoteAll")
	return nil
}

func (f *fakeFullEngine) RemoveRemoteFile(_ context.Context, _ engine.RemotePathOpRequest) error {
	f.record("RemoveRemoteFile")
	return nil
}

func (f *fakeFullEngine) RemoveRemoteDir(_ context.Context, _ engine.RemotePathOpRequest) error {
	f.record("RemoveRemoteDir")
	return nil
}

func (f *fakeFullEngine) ChmodRemote(_ context.Context, req engine.RemotePathOpRequest) error {
	f.record("ChmodRemote")
	f.lastChmodReq = req
	return nil
}

func (f *fakeFullEngine) ChtimesRemote(_ context.Context, _ engine.RemotePathOpRequest) error {
	f.record("ChtimesRemote")
	return nil
}

func (f *fakeFullEngine) RealPathRemote(_ context.Context, req engine.RemotePathOpRequest) (pathalg.RemotePath, error) {
	f.record("RealPathRemote")
	return req.Path, nil
}

func (f *fakeFullEngine) ReadLinkRemote(_ context.Context, _ engine.RemotePathOpRequest) (string, error) {
	f.record("ReadLinkRemote")
	return "/opt/target", nil
}

func (f *fakeFullEngine) RecoverTransfer(_ context.Context, req engine.RecoverTransferRequest) (engine.TransferRecoveryResult, error) {
	f.record("RecoverTransfer")
	f.lastRecoverReq = req
	return engine.TransferRecoveryResult{TransferID: req.TransferID, SelectedGen: 1}, nil
}

func (f *fakeFullEngine) RecoverAllTransfers(_ context.Context, _ engine.RecoverAllTransfersRequest) (engine.RecoverAllResult, error) {
	f.record("RecoverAllTransfers")
	return engine.RecoverAllResult{}, nil
}

func (f *fakeFullEngine) InspectTransfer(_ context.Context, _ engine.InspectTransferRequest) (engine.TransferStatusSnapshot, error) {
	f.record("InspectTransfer")
	return engine.TransferStatusSnapshot{}, nil
}

func (f *fakeFullEngine) GetInventorySnapshot(_ context.Context, _ engine.InventoryQueryRequest) (snap engine.InventorySnapshot, err error) {
	f.record("GetInventorySnapshot")
	return snap, nil
}

func (f *fakeFullEngine) GetHost(_ context.Context, _ inventory.HostID, _ engine.InventoryQueryRequest) (inventory.Host, engine.Revision, error) {
	f.record("GetHost")
	h, _, _ := sampleAssets()
	rev, _ := engine.ParseRevision("rev-1")
	return h, rev, nil
}

func (f *fakeFullEngine) GetIdentity(_ context.Context, _ inventory.IdentityID, _ engine.InventoryQueryRequest) (inventory.Identity, engine.Revision, error) {
	f.record("GetIdentity")
	_, id, _ := sampleAssets()
	rev, _ := engine.ParseRevision("rev-1")
	return id, rev, nil
}

func (f *fakeFullEngine) GetNode(_ context.Context, _ inventory.NodeID, _ engine.InventoryQueryRequest) (inventory.Node, engine.Revision, error) {
	f.record("GetNode")
	_, _, n := sampleAssets()
	rev, _ := engine.ParseRevision("rev-1")
	return n, rev, nil
}

func (f *fakeFullEngine) ListHosts(_ context.Context, _ engine.InventoryQueryRequest) ([]inventory.Host, engine.Revision, error) {
	f.record("ListHosts")
	h, _, _ := sampleAssets()
	rev, _ := engine.ParseRevision("rev-1")
	return []inventory.Host{h}, rev, nil
}

func (f *fakeFullEngine) ListIdentities(_ context.Context, _ engine.InventoryQueryRequest) ([]inventory.Identity, engine.Revision, error) {
	f.record("ListIdentities")
	_, id, _ := sampleAssets()
	rev, _ := engine.ParseRevision("rev-1")
	return []inventory.Identity{id}, rev, nil
}

func (f *fakeFullEngine) ListNodes(_ context.Context, _ engine.InventoryQueryRequest) ([]inventory.Node, engine.Revision, error) {
	f.record("ListNodes")
	_, _, n := sampleAssets()
	rev, _ := engine.ParseRevision("rev-1")
	return []inventory.Node{n}, rev, nil
}

func (f *fakeFullEngine) CreateHost(_ context.Context, req engine.HostMutationRequest) (res engine.MutationResult, err error) {
	f.record("CreateHost")
	f.lastHostMut = req
	return res, nil
}

func (f *fakeFullEngine) UpdateHost(_ context.Context, req engine.HostMutationRequest) (res engine.MutationResult, err error) {
	f.record("UpdateHost")
	f.lastHostMut = req
	return res, nil
}

func (f *fakeFullEngine) DeleteHost(ctx context.Context, req engine.DeleteAssetRequest) (res engine.MutationResult, err error) {
	f.record("DeleteHost")
	f.lastDeleteReq = req
	if f.deleteHostFn != nil {
		return f.deleteHostFn(ctx, req)
	}
	return res, nil
}

func (f *fakeFullEngine) CreateIdentity(_ context.Context, req engine.IdentityMutationRequest) (res engine.MutationResult, err error) {
	f.record("CreateIdentity")
	f.lastIdentMut = req
	return res, nil
}

func (f *fakeFullEngine) UpdateIdentity(_ context.Context, req engine.IdentityMutationRequest) (res engine.MutationResult, err error) {
	f.record("UpdateIdentity")
	f.lastIdentMut = req
	return res, nil
}

func (f *fakeFullEngine) DeleteIdentity(_ context.Context, req engine.DeleteAssetRequest) (res engine.MutationResult, err error) {
	f.record("DeleteIdentity")
	f.lastDeleteReq = req
	return res, nil
}

func (f *fakeFullEngine) CreateNode(_ context.Context, req engine.NodeMutationRequest) (res engine.MutationResult, err error) {
	f.record("CreateNode")
	f.lastNodeMut = req
	return res, nil
}

func (f *fakeFullEngine) UpdateNode(_ context.Context, req engine.NodeMutationRequest) (res engine.MutationResult, err error) {
	f.record("UpdateNode")
	f.lastNodeMut = req
	return res, nil
}

func (f *fakeFullEngine) DeleteNode(_ context.Context, req engine.DeleteAssetRequest) (res engine.MutationResult, err error) {
	f.record("DeleteNode")
	f.lastDeleteReq = req
	return res, nil
}

func (f *fakeFullEngine) ValidateDAG(_ context.Context, _ engine.InventoryQueryRequest) (inventory.DAGReport, error) {
	f.record("ValidateDAG")
	return inventory.DAGReport{MaxObservedDepth: 1}, nil
}

func (f *fakeFullEngine) CheckSecretReferences(_ context.Context, req engine.SecretRefCheckRequest) ([]inventory.SecretReference, error) {
	f.record("CheckSecretReferences")
	ref := req.Ref
	if !ref.IsValid() {
		ref, _ = secret.ParseRef("vault/default")
	}
	return []inventory.SecretReference{{Location: inventory.SecretLocNodePrivilege, OwnerID: "id-1", Ref: ref}}, nil
}

func (f *fakeFullEngine) InventoryDoctor(ctx context.Context, req engine.InventoryDoctorRequest) (engine.InventoryDoctorRep, error) {
	f.record("InventoryDoctor")
	if f.invDoctorFn != nil {
		return f.invDoctorFn(ctx, req)
	}
	return engine.InventoryDoctorRep{Healthy: true, HostCount: 1, IdentityCount: 1, NodeCount: 1, DAGMaxDepth: 1}, nil
}

func (f *fakeFullEngine) SupportedImportFormats() []string {
	f.record("SupportedImportFormats")
	if f.importFormats != nil {
		return f.importFormats
	}
	return []string{"csv", "openssh"}
}

func (f *fakeFullEngine) PlanImport(_ context.Context, req engine.ImportRequest) (p engine.ImportPreview, err error) {
	f.record("PlanImport")
	f.lastImportReq = req
	return p, nil
}

func (f *fakeFullEngine) ApplyImport(_ context.Context, req engine.ImportRequest) (r engine.ImportResult, err error) {
	f.record("ApplyImport")
	f.lastImportReq = req
	return r, nil
}

func (f *fakeFullEngine) EnrollEncryptedPrivateKeyIdentity(_ context.Context, req engine.EnrollEncryptedPrivateKeyRequest) (r engine.EnrollEncryptedPrivateKeyResult, err error) {
	f.record("EnrollEncryptedPrivateKeyIdentity")
	f.lastEnrollReq = req
	return r, nil
}

func (f *fakeFullEngine) VaultStatus(_ context.Context, _ engine.VaultOpRequest) (engine.VaultStatus, error) {
	f.record("VaultStatus")
	return mustDecodeJSON[engine.VaultStatus](`{"state":"unlocked","known_stores":["offline"],"detail":"ready"}`), nil
}

func (f *fakeFullEngine) VaultInitInteractive(_ context.Context, req engine.InteractiveVaultOpRequest) error {
	f.record("VaultInitInteractive")
	f.lastVaultInitReq = req
	return nil
}

func (f *fakeFullEngine) VaultUnlockInteractive(_ context.Context, req engine.InteractiveVaultOpRequest) error {
	f.record("VaultUnlockInteractive")
	f.lastVaultUnlockReq = req
	return nil
}

func (f *fakeFullEngine) VaultLock(_ context.Context, _ engine.VaultOpRequest) error {
	f.record("VaultLock")
	return nil
}

func (f *fakeFullEngine) VaultDoctor(ctx context.Context, req engine.VaultDoctorRequest) (engine.CredentialDoctorRep, error) {
	f.record("VaultDoctor")
	if f.vaultDoctorFn != nil {
		return f.vaultDoctorFn(ctx, req)
	}
	return engine.CredentialDoctorRep{Healthy: true, ReferencedCount: 1, DistinctRefCount: 1}, nil
}

func (f *fakeFullEngine) FindSecretReferences(_ context.Context, req engine.FindSecretReferencesRequest) ([]inventory.SecretReference, error) {
	f.record("FindSecretReferences")
	return []inventory.SecretReference{{Location: inventory.SecretLocNodePrivilege, OwnerID: "id-1", Ref: req.Ref}}, nil
}

func (f *fakeFullEngine) DeleteSecret(_ context.Context, _ engine.DeleteSecretRequest) error {
	f.record("DeleteSecret")
	return nil
}

func (f *fakeFullEngine) GCUnreferencedSecrets(_ context.Context, req engine.GCUnreferencedRequest) (engine.GCUnreferencedResult, error) {
	f.record("GCUnreferencedSecrets")
	return engine.GCUnreferencedResult{Deleted: req.Candidates}, nil
}

func (f *fakeFullEngine) ExecuteVaultSagaInteractive(ctx context.Context, req engine.InteractiveVaultSagaRequest) (res engine.SagaResult, err error) {
	f.record("ExecuteVaultSagaInteractive")
	f.lastVaultSaga = req
	if req.Saga.MutateGraph == nil || (req.Saga.NewRef.IsValid() == (req.Saga.TargetStore != "")) {
		return res, engine.ErrInvalidRequest
	}
	if f.vaultSagaFn != nil {
		return f.vaultSagaFn(ctx, req)
	}
	return res, nil
}

func (f *fakeFullEngine) RotateSecretInteractive(ctx context.Context, req engine.InteractiveRotateSecretRequest) (res engine.SagaResult, err error) {
	f.record("RotateSecretInteractive")
	f.lastRotateReq = req
	if !req.Rotate.OldRef.IsValid() || (req.Rotate.NewRef.IsValid() == (req.Rotate.TargetStore != "")) {
		return res, engine.ErrInvalidRequest
	}
	if f.rotateSecretFn != nil {
		return f.rotateSecretFn(ctx, req)
	}
	return res, nil
}

func (f *fakeFullEngine) ReconcileCrashedAudits(ctx context.Context) (engine.ReconcileReport, error) {
	f.record("ReconcileCrashedAudits")
	if f.reconcileFn != nil {
		return f.reconcileFn(ctx)
	}
	return mustDecodeJSON[engine.ReconcileReport](`{"scanned_locks":2,"live_locks_skipped":1,"dead_locks_claimed":1}`), nil
}

func mustDecodeJSON[T any](raw string) T {
	var out T
	if err := jsonv2.Unmarshal([]byte(raw), &out); err != nil {
		panic("mustDecodeJSON failed: " + err.Error())
	}
	return out
}

func sampleAssets() (inventory.Host, inventory.Identity, inventory.Node) {
	hid, _ := inventory.ParseHostID("web-host")
	ep, _ := netaddr.ParseEndpoint("10.0.0.10:22")
	tagProd, _ := inventory.ParseTag("prod")
	h, _ := inventory.NewHost(inventory.HostSpec{ID: hid, Endpoint: ep, Tags: []inventory.Tag{tagProd}})
	iid, _ := inventory.ParseIdentityID("deploy-id")
	user, _ := option.ParseUsername("deploy")
	auth, _ := inventory.NewAuthAgent(algebraic.None[inventory.AgentSpec]())
	id, _ := inventory.NewIdentity(inventory.IdentitySpec{ID: iid, User: user, Auth: auth})
	nid, _ := inventory.ParseNodeID("web-1")
	n, _ := inventory.NewNode(inventory.NodeSpec{
		ID: nid, HostRef: hid, IdentityRef: iid, Tags: []inventory.Tag{tagProd}, Origin: inventory.NewOriginManaged(),
	})
	return h, id, n
}

type appHarness struct {
	app          *cli.App
	eng          *fakeFullEngine
	stdout       *bytes.Buffer
	stderr       *bytes.Buffer
	factoryCalls int
	lastInitOpts cli.EngineInitOptions
}

func newFullAppHarness(t interface {
	Helper()
	Fatalf(string, ...any)
}, cfgMut func(*cli.AppConfig), stdin io.Reader) *appHarness {
	t.Helper()
	eng := &fakeFullEngine{}
	var stdout, stderr bytes.Buffer
	h := &appHarness{eng: eng, stdout: &stdout, stderr: &stderr}
	cfg := cli.AppConfig{
		BuildInfo: cli.BuildInfo{
			Version: "v2.3.3", Commit: "deadbeef", BuildTime: "2026-11-27T00:00:00Z", GoVersion: "go1.27.0", Platform: "linux/amd64",
		},
		EngineFactory: func(_ context.Context, opts cli.EngineInitOptions) (cli.EngineHandle, error) {
			h.factoryCalls++
			h.lastInitOpts = opts
			return cli.EngineHandle{Runner: eng}, nil
		},
		Stdin:  stdin,
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if cfgMut != nil {
		cfgMut(&cfg)
	}
	app, err := cli.NewApp(cfg)
	if err != nil {
		t.Fatalf("NewApp 失败: %v", err)
	}
	h.app = app
	return h
}
