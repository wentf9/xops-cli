package engine

import (
	"context"
	"io"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
)

//xops:syncclosure
func runTransferOp[T any](
	e *Engine, ctx context.Context, target TargetInput, opts CallOptions, fn func(context.Context, uctrans.CallBase) (T, error),
) (T, error) {
	return runTargetOp(e, ctx, target, func(c context.Context, resolved ResolvedTarget) (T, error) {
		return fn(c, uctrans.CallBase{
			Plan: resolved.Plan(), NodeID: resolved.NodeID(),
			Risk: opts.Risk, Approval: toGateApproval(opts.Approval), OperationStream: opts.OperationStream,
		})
	})
}

//xops:syncclosure
func runTransferOpErr(e *Engine, ctx context.Context, target TargetInput, opts CallOptions, fn func(context.Context, uctrans.CallBase) error) error {
	_, err := runTransferOp(e, ctx, target, opts, func(c context.Context, base uctrans.CallBase) (struct{}, error) { return struct{}{}, fn(c, base) })
	return err
}

func toTransferSessionOpts(o TransferSessionOptions) uctrans.TransferSessionOptions {
	return uctrans.TransferSessionOptions{
		LocalRoot: o.LocalRoot, RemoteSource: o.RemoteSource, NoClobber: o.NoClobber,
		PreserveTimes: o.PreserveTimes, ExpectedAnchor: o.ExpectedAnchor, Perm: o.Perm,
	}
}

// ExecPrivileged 执行远端提权命令（sudo/su/doas），口令仅经 Vault/交互借用透传。
func (e *Engine) ExecPrivileged(ctx context.Context, req PrivilegeExecRequest) (execution.ExecutionOutcome, error) {
	return runOp(e, ctx, func(c context.Context) (execution.ExecutionOutcome, error) {
		ttyMode, err := req.RequestTTY.toSessionTTYMode()
		if err != nil {
			return notStartedOutcome(execution.StartPhaseValidate, "invalid_request_tty", err), err
		}
		resolved, err := e.resolveTargetRef(c, req.Target, req.TargetSpec, req.CLIOptions)
		if err != nil {
			return notStartedOutcome(execution.StartPhaseValidate, "resolve_target_failed", err), err
		}
		return e.session.ExecPrivileged(c, ucsess.PrivilegeExecRequest{
			Plan: resolved.Plan(), Privilege: req.Privilege, NodeID: resolved.NodeID(), Term: req.Term,
			PasswordRef: req.PasswordRef, PromptPassword: req.PromptPassword, Paths: req.Paths, RecursivePaths: req.RecursivePaths,
			Stdin: req.Stdin, Stdout: req.Stdout, Stderr: req.Stderr, RequestTTY: ttyMode,
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}

// ProbeShell 执行两阶段远端 Shell 方言与解释器探测。
func (e *Engine) ProbeShell(ctx context.Context, req ProbeShellRequest) (ShellProbeResult, error) {
	return runTargetOp(e, ctx, req.TargetInput, func(c context.Context, r ResolvedTarget) (ShellProbeResult, error) {
		return e.session.ProbeShell(c, ucsess.ProbeShellRequest{
			Plan: r.Plan(), NodeID: r.NodeID(), Timeout: req.Timeout,
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}

// OpenPTY / ReadPTY / WritePTY / ResizePTY / SignalPTY / InspectPTY / ClosePTY 管理跨请求持久 PTY 世代句柄。
func (e *Engine) OpenPTY(ctx context.Context, req OpenPTYRequest) (plan.ManagedHandle[plan.KindPTY], error) {
	return runTargetOp(e, ctx, req.TargetInput, func(c context.Context, r ResolvedTarget) (plan.ManagedHandle[plan.KindPTY], error) {
		return e.session.OpenPTY(c, ucsess.OpenPTYRequest{
			Plan: r.Plan(), NodeID: r.NodeID(), Term: req.Term, Size: req.Size, MaxBufferBytes: req.MaxBufferBytes,
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}
func (e *Engine) ReadPTY(ctx context.Context, req PTYReadRequest) (PTYReadResult, error) {
	return runOp(e, ctx, func(c context.Context) (PTYReadResult, error) {
		return e.session.ReadPTY(c, ucsess.PTYReadRequest{Handle: req.Handle, MaxBytes: req.MaxBytes, Wait: req.Wait})
	})
}
func (e *Engine) WritePTY(ctx context.Context, handle plan.ManagedHandle[plan.KindPTY], data []byte) (int, error) {
	return runOp(e, ctx, func(c context.Context) (int, error) { return e.session.WritePTY(c, handle, data) })
}
func (e *Engine) ResizePTY(ctx context.Context, handle plan.ManagedHandle[plan.KindPTY], size TerminalSize) error {
	return runOpErr(e, ctx, func(c context.Context) error { return e.session.ResizePTY(c, handle, size) })
}
func (e *Engine) SignalPTY(ctx context.Context, handle plan.ManagedHandle[plan.KindPTY], sig string) error {
	return runOpErr(e, ctx, func(c context.Context) error { return e.session.SignalPTY(c, handle, sig) })
}
func (e *Engine) InspectPTY(ctx context.Context, handle plan.ManagedHandle[plan.KindPTY]) (PTYStatus, error) {
	return runOp(e, ctx, func(c context.Context) (PTYStatus, error) { return e.session.InspectPTY(c, handle) })
}
func (e *Engine) ClosePTY(ctx context.Context, handle plan.ManagedHandle[plan.KindPTY]) error {
	return runOpErr(e, ctx, func(c context.Context) error { return e.session.ClosePTY(c, handle) })
}

// StartForward / InspectForward / StopForward 管理 -L/-R/-D/StreamLocal/TUN 隧道转发句柄。
func (e *Engine) StartForward(ctx context.Context, req StartForwardRequest) (ForwardInfo, error) {
	return runTargetOp(e, ctx, req.TargetInput, func(c context.Context, r ResolvedTarget) (ForwardInfo, error) {
		return e.session.StartForward(c, ucsess.StartForwardRequest{
			Plan: r.Plan(), Spec: req.Spec, NodeID: r.NodeID(),
			Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}
func (e *Engine) InspectForward(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) (ForwardStatus, error) {
	return runOp(e, ctx, func(c context.Context) (ForwardStatus, error) { return e.session.InspectForward(c, handle) })
}
func (e *Engine) StopForward(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) error {
	return runOpErr(e, ctx, func(c context.Context) error { return e.session.StopForward(c, handle) })
}

// StartControlMaster / InspectControlMaster / TouchControlMaster / StopControlMaster / ProbeMux / ControlMux / RunMuxProxy。
func (e *Engine) StartControlMaster(ctx context.Context, req ControlMasterRequest) (ControlMasterInfo, error) {
	return runTargetOp(e, ctx, req.TargetInput, func(c context.Context, r ResolvedTarget) (ControlMasterInfo, error) {
		return e.session.StartControlMaster(c, ucsess.ControlMasterRequest{
			Plan: r.Plan(), NodeID: r.NodeID(), Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
		})
	})
}
func (e *Engine) InspectControlMaster(ctx context.Context, handle plan.ManagedHandle[plan.KindMux]) (ControlMasterStatus, error) {
	return runOp(e, ctx, func(c context.Context) (ControlMasterStatus, error) { return e.session.InspectControlMaster(c, handle) })
}
func (e *Engine) TouchControlMaster(ctx context.Context, handle plan.ManagedHandle[plan.KindMux]) error {
	return runOpErr(e, ctx, func(c context.Context) error { return e.session.TouchControlMaster(c, handle) })
}
func (e *Engine) StopControlMaster(ctx context.Context, handle plan.ManagedHandle[plan.KindMux]) error {
	return runOpErr(e, ctx, func(c context.Context) error { return e.session.StopControlMaster(c, handle) })
}
func (e *Engine) ProbeMux(ctx context.Context, req MuxControlRequest) (MuxControlResponse, error) {
	return runTargetOp(e, ctx, req.TargetInput, func(c context.Context, r ResolvedTarget) (MuxControlResponse, error) {
		return e.session.ProbeMux(c, toMuxReq(r, req))
	})
}
func (e *Engine) ControlMux(ctx context.Context, req MuxControlRequest) (MuxControlResponse, error) {
	return runTargetOp(e, ctx, req.TargetInput, func(c context.Context, r ResolvedTarget) (MuxControlResponse, error) {
		return e.session.ControlMux(c, ucsess.MuxControlRequest{Target: toMuxReq(r, req), Action: req.Action, Forward: req.Forward})
	})
}
func (e *Engine) RunMuxProxy(ctx context.Context, req MuxControlRequest, stdin io.ReadCloser, stdout io.Writer) error {
	return runOpErr(e, ctx, func(c context.Context) error {
		r, err := e.resolveTargetRef(c, req.Target, req.TargetSpec, req.CLIOptions)
		if err != nil {
			return err
		}
		return e.session.RunMuxProxy(c, toMuxReq(r, req), stdin, stdout)
	})
}

func toMuxReq(r ResolvedTarget, req MuxControlRequest) ucsess.MuxRequest {
	return ucsess.MuxRequest{
		Plan: r.Plan(), NodeID: r.NodeID(), SocketPath: req.SocketPath,
		Risk: req.Risk, Approval: toGateApproval(req.Approval), OperationStream: req.OperationStream,
	}
}

// SCPUpload / SCPDownload 执行并行分片 SCP 传输（显式双模态本地 FS 隔离）。
func (e *Engine) SCPUpload(ctx context.Context, req SCPUploadRequest) (SCPUploadResult, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (SCPUploadResult, error) {
		return e.transfer.SCPUpload(c, uctrans.SCPUploadRequest{
			CallBase: base, Source: req.Source, RemoteDest: req.RemoteDest, ExpandIntoDir: req.ExpandIntoDir,
			NoClobber: req.NoClobber, Resume: req.Resume, PreserveMode: req.PreserveMode, PreserveTimes: req.PreserveTimes,
			Perm: req.Perm, ModTime: req.ModTime, ChunkSize: req.ChunkSize, Concurrency: req.Concurrency, ExpectedDigest: req.ExpectedDigest,
		})
	})
}
func (e *Engine) SCPDownload(ctx context.Context, req SCPDownloadRequest) (SCPDownloadResult, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (SCPDownloadResult, error) {
		return e.transfer.SCPDownload(c, uctrans.SCPDownloadRequest{
			CallBase: base, RemoteSource: req.RemoteSource, LocalRoot: req.LocalRoot, LocalDest: req.LocalDest,
			Recursive: req.Recursive, NoClobber: req.NoClobber, Resume: req.Resume, PreserveTimes: req.PreserveTimes,
			SymlinkPolicy: req.SymlinkPolicy, ChunkSize: req.ChunkSize, Concurrency: req.Concurrency,
			MaxFiles: req.MaxFiles, MaxTotalBytes: req.MaxTotalBytes, ExpectedDigest: req.ExpectedDigest,
		})
	})
}

// ReadRemoteFile / WriteRemoteFile / PatchRemoteFile / StatRemoteFile / RenameRemoteFile / ListRemoteDir / MkdirRemoteAll / RemoveRemoteFile / RemoveRemoteDir / ChmodRemote / ChtimesRemote / RealPathRemote / ReadLinkRemote。
func (e *Engine) ReadRemoteFile(ctx context.Context, req RemoteFileReadRequest) (ReadFileResult, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (ReadFileResult, error) {
		return e.transfer.ReadFile(c, uctrans.ReadFileRequest{CallBase: base, Path: req.Path, MaxBytes: req.MaxBytes})
	})
}
func (e *Engine) WriteRemoteFile(ctx context.Context, req RemoteFileWriteRequest) (WriteFileResult, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (WriteFileResult, error) {
		return e.transfer.WriteFile(c, uctrans.WriteFileRequest{CallBase: base, Path: req.Path, Content: req.Content, Perm: req.Perm, NoClobber: req.NoClobber, CreateParents: req.CreateParents, ExpectedAnchor: req.ExpectedAnchor})
	})
}
func (e *Engine) PatchRemoteFile(ctx context.Context, req RemoteFilePatchRequest) (PatchFileResult, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (PatchFileResult, error) {
		return e.transfer.PatchFile(c, uctrans.PatchFileRequest{CallBase: base, Path: req.Path, Edits: req.Edits, ExpectedAnchor: req.ExpectedAnchor, ExpectedDigest: req.ExpectedDigest, MaxBytes: req.MaxBytes})
	})
}
func (e *Engine) StatRemoteFile(ctx context.Context, req RemoteStatRequest) (RemoteFileStat, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (RemoteFileStat, error) {
		return e.transfer.Stat(c, uctrans.StatRequest{CallBase: base, Path: req.Path, FollowSymlinks: req.FollowSymlinks})
	})
}
func (e *Engine) RenameRemoteFile(ctx context.Context, req RemoteRenameRequest) error {
	return runTransferOpErr(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) error {
		return e.transfer.RenameFile(c, uctrans.RenameFileRequest{CallBase: base, OldPath: req.OldPath, NewPath: req.NewPath, NoClobber: req.NoClobber, ExpectedAnchor: req.ExpectedAnchor})
	})
}
func (e *Engine) ListRemoteDir(ctx context.Context, req RemotePathOpRequest) (ListDirResult, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (ListDirResult, error) {
		return e.transfer.ListDir(c, uctrans.ListDirRequest{CallBase: base, Path: req.Path})
	})
}
func (e *Engine) MkdirRemoteAll(ctx context.Context, req RemotePathOpRequest) error {
	return runTransferOpErr(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) error {
		return e.transfer.MkdirAll(c, uctrans.MkdirAllRequest{CallBase: base, Path: req.Path, Perm: req.Perm})
	})
}
func (e *Engine) RemoveRemoteFile(ctx context.Context, req RemotePathOpRequest) error {
	return runTransferOpErr(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) error {
		return e.transfer.Remove(c, uctrans.RemoveRequest{CallBase: base, Path: req.Path})
	})
}
func (e *Engine) RemoveRemoteDir(ctx context.Context, req RemotePathOpRequest) error {
	return runTransferOpErr(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) error {
		return e.transfer.RemoveDir(c, uctrans.RemoveDirRequest{CallBase: base, Path: req.Path})
	})
}
func (e *Engine) ChmodRemote(ctx context.Context, req RemotePathOpRequest) error {
	return runTransferOpErr(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) error {
		return e.transfer.Chmod(c, uctrans.ChmodRequest{CallBase: base, Path: req.Path, Perm: req.Perm.OrElse(0)})
	})
}
func (e *Engine) ChtimesRemote(ctx context.Context, req RemotePathOpRequest) error {
	return runTransferOpErr(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) error {
		return e.transfer.Chtimes(c, uctrans.ChtimesRequest{CallBase: base, Path: req.Path, Atime: req.Atime, Mtime: req.Mtime})
	})
}
func (e *Engine) RealPathRemote(ctx context.Context, req RemotePathOpRequest) (pathalg.RemotePath, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (pathalg.RemotePath, error) {
		return e.transfer.RealPath(c, uctrans.RealPathRequest{CallBase: base, Path: req.Path})
	})
}
func (e *Engine) ReadLinkRemote(ctx context.Context, req RemotePathOpRequest) (string, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (string, error) {
		return e.transfer.ReadLink(c, uctrans.ReadLinkRequest{CallBase: base, Path: req.Path})
	})
}

// StartTransfer / WriteTransferChunk / PullTransferChunk / CommitTransfer / AbortTransfer / ResumeTransfer / RecoverTransfer / RecoverAllTransfers / InspectTransfer。
func (e *Engine) StartTransfer(ctx context.Context, req StartTransferRequest) (TransferHandleInfo, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (TransferHandleInfo, error) {
		return e.transfer.StartTransfer(c, uctrans.StartTransferRequest{CallBase: base, TransferID: req.TransferID, Dest: req.Dest, TotalBytes: req.TotalBytes, ExpectedDigest: req.ExpectedDigest, TransferSessionOptions: toTransferSessionOpts(req.TransferSessionOptions)})
	})
}
func (e *Engine) WriteTransferChunk(ctx context.Context, req WriteTransferChunkRequest) (WriteTransferChunkRes, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (WriteTransferChunkRes, error) {
		return e.transfer.WriteTransferChunk(c, uctrans.WriteTransferChunkRequest{CallBase: base, Handle: req.Handle, Offset: req.Offset, Data: req.Data})
	})
}
func (e *Engine) PullTransferChunk(ctx context.Context, req PullTransferChunkRequest) (PullTransferChunkResult, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (PullTransferChunkResult, error) {
		return e.transfer.PullTransferChunk(c, uctrans.PullTransferChunkRequest{CallBase: base, Handle: req.Handle, MaxChunkBytes: req.MaxChunkBytes})
	})
}
func (e *Engine) CommitTransfer(ctx context.Context, req TransferHandleOpRequest) (CommitTransferResult, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (CommitTransferResult, error) {
		return e.transfer.CommitTransfer(c, uctrans.CommitTransferRequest{CallBase: base, Handle: req.Handle})
	})
}
func (e *Engine) AbortTransfer(ctx context.Context, req TransferHandleOpRequest) error {
	return runTransferOpErr(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) error {
		return e.transfer.AbortTransfer(c, uctrans.AbortTransferRequest{CallBase: base, Handle: req.Handle, Reason: req.Reason})
	})
}
func (e *Engine) ResumeTransfer(ctx context.Context, req ResumeTransferRequest) (TransferHandleInfo, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (TransferHandleInfo, error) {
		return e.transfer.ResumeTransfer(c, uctrans.ResumeTransferRequest{CallBase: base, TransferID: req.TransferID, StartNextGen: req.StartNextGen, TransferSessionOptions: toTransferSessionOpts(req.TransferSessionOptions)})
	})
}
func (e *Engine) RecoverTransfer(ctx context.Context, req RecoverTransferRequest) (TransferRecoveryResult, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (TransferRecoveryResult, error) {
		return e.transfer.RecoverTransfer(c, uctrans.RecoverTransferRequest{CallBase: base, TransferID: req.TransferID, PruneSuperseded: req.PruneSuperseded, LocalRootForClean: req.LocalRootForClean})
	})
}
func (e *Engine) RecoverAllTransfers(ctx context.Context, pruneSuperseded bool) (RecoverAllResult, error) {
	return runOp(e, ctx, func(c context.Context) (RecoverAllResult, error) {
		return e.transfer.RecoverAllTransfers(c, uctrans.RecoverAllRequest{PruneSuperseded: pruneSuperseded})
	})
}
func (e *Engine) InspectTransfer(ctx context.Context, req InspectTransferRequest) (TransferStatusSnapshot, error) {
	return runTransferOp(e, ctx, req.TargetInput, req.CallOptions, func(c context.Context, base uctrans.CallBase) (TransferStatusSnapshot, error) {
		return e.transfer.InspectTransfer(c, uctrans.InspectTransferRequest{CallBase: base, TransferID: req.TransferID, Handle: req.Handle})
	})
}

// NewTextEdit / NewOperatorUploadSource / NewScopedUploadSource 代理常用值构造器，便于 entry 层零 core/internal 引用。
func NewTextEdit(oldText, newText string, replaceAll bool) (TextEdit, error) {
	return uctrans.NewTextEdit(oldText, newText, replaceAll)
}
func NewOperatorUploadSource(src pathalg.LocalSourcePath, policy pathalg.SymlinkPolicy) (LocalUploadSource, error) {
	return uctrans.NewOperatorUploadSource(src, policy)
}
func NewScopedUploadSource(rootDir pathalg.LocalDir, rel pathalg.LocalRootedDest) (LocalUploadSource, error) {
	return uctrans.NewScopedUploadSource(rootDir, rel)
}
