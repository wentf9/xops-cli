package engine

import (
	"context"
	"io"

	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	ucsess "github.com/wentf9/xops-cli/core/internal/usecase/session"
	uctrans "github.com/wentf9/xops-cli/core/internal/usecase/transfer"
)

func callSess[A, R any](e *Engine, ctx context.Context, fn func(*ucsess.Service, context.Context, A) (R, error), arg A) (R, error) {
	return runOp(e, ctx, func(c context.Context) (R, error) { return fn(e.session, c, arg) })
}
func callSessErr[A any](e *Engine, ctx context.Context, fn func(*ucsess.Service, context.Context, A) error, arg A) error {
	return runOpErr(e, ctx, func(c context.Context) error { return fn(e.session, c, arg) })
}
func callBaseOf(r ResolvedTarget, o CallOptions) uctrans.CallBase {
	return uctrans.CallBase{Plan: r.Plan(), NodeID: r.NodeID(), Risk: o.Risk, Approval: o.Approval, OperationStream: o.OperationStream}
}

//xops:syncclosure
func runTrans[T any](e *Engine, ctx context.Context, rc RemoteCall, fn func(context.Context, uctrans.CallBase) (T, error)) (T, error) {
	return runTargetOp(e, ctx, rc, func(c context.Context, r ResolvedTarget) (T, error) { return fn(c, callBaseOf(r, rc.CallOptions)) })
}

//xops:syncclosure
func runTransErr(e *Engine, ctx context.Context, rc RemoteCall, fn func(context.Context, uctrans.CallBase) error) error {
	_, err := runTrans(e, ctx, rc, func(c context.Context, b uctrans.CallBase) (struct{}, error) { return struct{}{}, fn(c, b) })
	return err
}
func callTransPath[R any](e *Engine, ctx context.Context, req RemotePathOpRequest, fn func(*uctrans.Service, context.Context, uctrans.RemotePathRequest) (R, error)) (R, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (R, error) {
		return fn(e.transfer, c, uctrans.RemotePathRequest{CallBase: b, Path: req.Path})
	})
}
func callTransPathErr(e *Engine, ctx context.Context, req RemotePathOpRequest, fn func(*uctrans.Service, context.Context, uctrans.RemotePathRequest) error) error {
	_, err := callTransPath(e, ctx, req, func(s *uctrans.Service, c context.Context, a uctrans.RemotePathRequest) (struct{}, error) {
		return struct{}{}, fn(s, c, a)
	})
	return err
}

// CanSuspendProcessGroup 暴露本机 POSIX 孤儿进程组安全挂起判定（INV-E1，供 Phase 5 entry/cli 实现 ~^Z）；未初始化或已关闭恒失败关闭。
func (e *Engine) CanSuspendProcessGroup() (security.Verdict, error) {
	if e == nil || !e.initialized {
		return security.VerdictDeny, ErrEngineNotInitialized
	}
	if e.IsClosed() {
		return security.VerdictDeny, ErrEngineClosed
	}
	return mapRes(e.session.CanSuspendProcessGroup())
}

// ExecPrivileged 执行远端提权命令（sudo/su/doas），口令仅经 Vault/交互借用透传，全路径确保 OperationStream 确定性 EOF。
func (e *Engine) ExecPrivileged(ctx context.Context, req PrivilegeExecRequest) (execution.ExecutionOutcome, error) {
	return runOpStream(e, ctx, req.OperationStream, func(c context.Context) (execution.ExecutionOutcome, error) {
		ttyMode, err := req.RequestTTY.toSessionTTYMode()
		if err != nil {
			return notStartedOutcome(execution.StartPhaseValidate, "invalid_request_tty", err), err
		}
		resolved, err := e.resolveTargetRef(c, req.Target, req.TargetSpec, req.CLIOptions)
		if err != nil {
			err = mapEngineError(err)
			return notStartedOutcome(execution.StartPhaseValidate, "resolve_target_failed", err), err
		}
		return e.session.ExecPrivileged(c, ucsess.PrivilegeExecRequest{
			Plan: resolved.Plan(), Privilege: req.Privilege, NodeID: resolved.NodeID(), Term: req.Term,
			PasswordRef: req.PasswordRef, PromptPassword: req.PromptPassword, Paths: req.Paths, RecursivePaths: req.RecursivePaths,
			Stdin: req.Stdin, Stdout: req.Stdout, Stderr: req.Stderr, RequestTTY: ttyMode,
			Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream,
		})
	})
}

// ProbeShell / OpenPTY / ReadPTY / WritePTY / ResizePTY / SignalPTY / InspectPTY / ClosePTY。
func (e *Engine) ProbeShell(ctx context.Context, req ProbeShellRequest) (ShellProbeResult, error) {
	return runTargetOp(e, ctx, req.RemoteCall, func(c context.Context, r ResolvedTarget) (ShellProbeResult, error) {
		return e.session.ProbeShell(c, ucsess.ProbeShellRequest{Plan: r.Plan(), NodeID: r.NodeID(), Timeout: req.Timeout, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream})
	})
}
func (e *Engine) OpenPTY(ctx context.Context, req OpenPTYRequest) (plan.ManagedHandle[plan.KindPTY], error) {
	return runTargetOp(e, ctx, req.RemoteCall, func(c context.Context, r ResolvedTarget) (plan.ManagedHandle[plan.KindPTY], error) {
		return e.session.OpenPTY(c, ucsess.OpenPTYRequest{Plan: r.Plan(), NodeID: r.NodeID(), Term: req.Term, Size: req.Size, MaxBufferBytes: req.MaxBufferBytes, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream})
	})
}
func (e *Engine) ReadPTY(ctx context.Context, req PTYReadRequest) (PTYReadResult, error) {
	return callSess(e, ctx, (*ucsess.Service).ReadPTY, req)
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
	return callSess(e, ctx, (*ucsess.Service).InspectPTY, handle)
}
func (e *Engine) ClosePTY(ctx context.Context, handle plan.ManagedHandle[plan.KindPTY]) error {
	return callSessErr(e, ctx, (*ucsess.Service).ClosePTY, handle)
}

// StartForward / InspectForward / StopForward / StartControlMaster / InspectControlMaster / TouchControlMaster / StopControlMaster / ProbeMux / ControlMux / RunMuxProxy。
func (e *Engine) StartForward(ctx context.Context, req StartForwardRequest) (ForwardInfo, error) {
	return runTargetOp(e, ctx, req.RemoteCall, func(c context.Context, r ResolvedTarget) (ForwardInfo, error) {
		return e.session.StartForward(c, ucsess.StartForwardRequest{Plan: r.Plan(), Spec: req.Spec, NodeID: r.NodeID(), Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream})
	})
}
func (e *Engine) InspectForward(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) (ForwardStatus, error) {
	return callSess(e, ctx, (*ucsess.Service).InspectForward, handle)
}
func (e *Engine) StopForward(ctx context.Context, handle plan.ManagedHandle[plan.KindTunnel]) error {
	return callSessErr(e, ctx, (*ucsess.Service).StopForward, handle)
}
func (e *Engine) StartControlMaster(ctx context.Context, req ControlMasterRequest) (ControlMasterInfo, error) {
	return runTargetOp(e, ctx, req.RemoteCall, func(c context.Context, r ResolvedTarget) (ControlMasterInfo, error) {
		info, err := e.session.StartControlMaster(c, ucsess.ControlMasterRequest{Plan: r.Plan(), NodeID: r.NodeID(), Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream})
		if err == nil && !info.ReusedExisting() {
			if h, ok := info.Handle().Get(); ok && h.IsValid() {
				e.muxActivity.register(info.SocketPath().String(), h)
			}
		}
		return info, err
	})
}
func (e *Engine) InspectControlMaster(ctx context.Context, handle plan.ManagedHandle[plan.KindMux]) (ControlMasterStatus, error) {
	return callSess(e, ctx, (*ucsess.Service).InspectControlMaster, handle)
}
func (e *Engine) TouchControlMaster(ctx context.Context, handle plan.ManagedHandle[plan.KindMux]) error {
	return callSessErr(e, ctx, (*ucsess.Service).TouchControlMaster, handle)
}
func (e *Engine) StopControlMaster(ctx context.Context, handle plan.ManagedHandle[plan.KindMux]) error {
	e.muxActivity.unregisterHandle(handle)
	return callSessErr(e, ctx, (*ucsess.Service).StopControlMaster, handle)
}
func (e *Engine) ProbeMux(ctx context.Context, req MuxControlRequest) (MuxControlResponse, error) {
	return runTargetOp(e, ctx, req.RemoteCall, func(c context.Context, r ResolvedTarget) (MuxControlResponse, error) {
		return e.session.ProbeMux(c, toMuxReq(r, req))
	})
}
func (e *Engine) ControlMux(ctx context.Context, req MuxControlRequest) (MuxControlResponse, error) {
	return runTargetOp(e, ctx, req.RemoteCall, func(c context.Context, r ResolvedTarget) (MuxControlResponse, error) {
		return e.session.ControlMux(c, ucsess.MuxControlRequest{Target: toMuxReq(r, req), Action: req.Action, Forward: req.Forward})
	})
}
func (e *Engine) RunMuxProxy(ctx context.Context, req MuxControlRequest, stdin io.ReadCloser, stdout io.Writer) error {
	_, err := runTargetOp(e, ctx, req.RemoteCall, func(c context.Context, r ResolvedTarget) (struct{}, error) {
		return struct{}{}, e.session.RunMuxProxy(c, toMuxReq(r, req), stdin, stdout)
	})
	return err
}
func toMuxReq(r ResolvedTarget, req MuxControlRequest) ucsess.MuxRequest {
	return ucsess.MuxRequest{Plan: r.Plan(), NodeID: r.NodeID(), SocketPath: req.SocketPath, Risk: req.Risk, Approval: req.Approval, OperationStream: req.OperationStream}
}

// SCPUpload / SCPDownload 执行并行分片与 ScopedRootFS 递归目录 SCP 传输（显式双模态本地 FS 隔离）。
func (e *Engine) SCPUpload(ctx context.Context, req SCPUploadRequest) (SCPUploadResult, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (SCPUploadResult, error) {
		return e.transfer.SCPUpload(c, uctrans.SCPUploadRequest{
			CallBase: b, Source: req.Source, RemoteDest: req.RemoteDest, Recursive: req.Recursive, ExpandIntoDir: req.ExpandIntoDir,
			NoClobber: req.NoClobber, Resume: req.Resume, PreserveMode: req.PreserveMode, PreserveTimes: req.PreserveTimes,
			SymlinkPolicy: req.SymlinkPolicy, Perm: req.Perm, ModTime: req.ModTime, ChunkSize: req.ChunkSize,
			Concurrency: req.Concurrency, MaxFiles: req.MaxFiles, MaxTotalBytes: req.MaxTotalBytes, ExpectedDigest: req.ExpectedDigest,
		})
	})
}
func (e *Engine) SCPDownload(ctx context.Context, req SCPDownloadRequest) (SCPDownloadResult, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (SCPDownloadResult, error) {
		return e.transfer.SCPDownload(c, uctrans.SCPDownloadRequest{
			CallBase: b, RemoteSource: req.RemoteSource, LocalRoot: req.LocalRoot, LocalDest: req.LocalDest,
			Recursive: req.Recursive, NoClobber: req.NoClobber, Resume: req.Resume, PreserveTimes: req.PreserveTimes,
			SymlinkPolicy: req.SymlinkPolicy, ChunkSize: req.ChunkSize, Concurrency: req.Concurrency,
			MaxFiles: req.MaxFiles, MaxTotalBytes: req.MaxTotalBytes, ExpectedDigest: req.ExpectedDigest,
		})
	})
}

// ReadRemoteFile / WriteRemoteFile / PatchRemoteFile / StatRemoteFile / RenameRemoteFile / ListRemoteDir / MkdirRemoteAll / RemoveRemoteFile / RemoveRemoteDir / ChmodRemote / ChtimesRemote / RealPathRemote / ReadLinkRemote。
func (e *Engine) ReadRemoteFile(ctx context.Context, req RemoteFileReadRequest) (ReadFileResult, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (ReadFileResult, error) {
		return e.transfer.ReadFile(c, uctrans.ReadFileRequest{CallBase: b, Path: req.Path, MaxBytes: req.MaxBytes})
	})
}
func (e *Engine) WriteRemoteFile(ctx context.Context, req RemoteFileWriteRequest) (WriteFileResult, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (WriteFileResult, error) {
		return e.transfer.WriteFile(c, uctrans.WriteFileRequest{CallBase: b, Path: req.Path, Content: req.Content, Perm: req.Perm, NoClobber: req.NoClobber, CreateParents: req.CreateParents, ExpectedAnchor: req.ExpectedAnchor})
	})
}
func (e *Engine) PatchRemoteFile(ctx context.Context, req RemoteFilePatchRequest) (PatchFileResult, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (PatchFileResult, error) {
		return e.transfer.PatchFile(c, uctrans.PatchFileRequest{CallBase: b, Path: req.Path, Edits: req.Edits, ExpectedAnchor: req.ExpectedAnchor, ExpectedDigest: req.ExpectedDigest, MaxBytes: req.MaxBytes})
	})
}
func (e *Engine) StatRemoteFile(ctx context.Context, req RemoteStatRequest) (RemoteFileStat, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (RemoteFileStat, error) {
		return e.transfer.Stat(c, uctrans.StatRequest{CallBase: b, Path: req.Path, FollowSymlinks: req.FollowSymlinks})
	})
}
func (e *Engine) RenameRemoteFile(ctx context.Context, req RemoteRenameRequest) error {
	return runTransErr(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) error {
		return e.transfer.RenameFile(c, uctrans.RenameFileRequest{CallBase: b, OldPath: req.OldPath, NewPath: req.NewPath, NoClobber: req.NoClobber, ExpectedAnchor: req.ExpectedAnchor})
	})
}
func (e *Engine) ListRemoteDir(ctx context.Context, req RemotePathOpRequest) (ListDirResult, error) {
	return callTransPath(e, ctx, req, (*uctrans.Service).ListDir)
}
func (e *Engine) MkdirRemoteAll(ctx context.Context, req RemotePathOpRequest) error {
	return runTransErr(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) error {
		return e.transfer.MkdirAll(c, uctrans.MkdirAllRequest{CallBase: b, Path: req.Path, Perm: req.Perm})
	})
}
func (e *Engine) RemoveRemoteFile(ctx context.Context, req RemotePathOpRequest) error {
	return callTransPathErr(e, ctx, req, (*uctrans.Service).Remove)
}
func (e *Engine) RemoveRemoteDir(ctx context.Context, req RemotePathOpRequest) error {
	return callTransPathErr(e, ctx, req, (*uctrans.Service).RemoveDir)
}
func (e *Engine) ChmodRemote(ctx context.Context, req RemotePathOpRequest) error {
	return runTransErr(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) error {
		return e.transfer.Chmod(c, uctrans.ChmodRequest{CallBase: b, Path: req.Path, Perm: req.Perm.OrElse(0)})
	})
}
func (e *Engine) ChtimesRemote(ctx context.Context, req RemotePathOpRequest) error {
	return runTransErr(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) error {
		return e.transfer.Chtimes(c, uctrans.ChtimesRequest{CallBase: b, Path: req.Path, Atime: req.Atime, Mtime: req.Mtime})
	})
}
func (e *Engine) RealPathRemote(ctx context.Context, req RemotePathOpRequest) (pathalg.RemotePath, error) {
	return callTransPath(e, ctx, req, (*uctrans.Service).RealPath)
}
func (e *Engine) ReadLinkRemote(ctx context.Context, req RemotePathOpRequest) (string, error) {
	return callTransPath(e, ctx, req, (*uctrans.Service).ReadLink)
}

// StartTransfer / WriteTransferChunk / PullTransferChunk / CommitTransfer / AbortTransfer / ResumeTransfer / RecoverTransfer / RecoverAllTransfers / InspectTransfer。
func (e *Engine) StartTransfer(ctx context.Context, req StartTransferRequest) (TransferHandleInfo, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (TransferHandleInfo, error) {
		return e.transfer.StartTransfer(c, uctrans.StartTransferRequest{CallBase: b, TransferID: req.TransferID, Dest: req.Dest, TotalBytes: req.TotalBytes, ExpectedDigest: req.ExpectedDigest, TransferSessionOptions: req.TransferSessionOptions})
	})
}
func (e *Engine) WriteTransferChunk(ctx context.Context, req WriteTransferChunkRequest) (WriteTransferChunkRes, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (WriteTransferChunkRes, error) {
		return e.transfer.WriteTransferChunk(c, uctrans.WriteTransferChunkRequest{CallBase: b, Handle: req.Handle, Offset: req.Offset, Data: req.Data})
	})
}
func (e *Engine) PullTransferChunk(ctx context.Context, req PullTransferChunkRequest) (PullTransferChunkResult, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (PullTransferChunkResult, error) {
		return e.transfer.PullTransferChunk(c, uctrans.PullTransferChunkRequest{CallBase: b, Handle: req.Handle, MaxChunkBytes: req.MaxChunkBytes})
	})
}
func (e *Engine) CommitTransfer(ctx context.Context, req TransferHandleOpRequest) (CommitTransferResult, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (CommitTransferResult, error) {
		return e.transfer.CommitTransfer(c, uctrans.CommitTransferRequest{CallBase: b, Handle: req.Handle})
	})
}
func (e *Engine) AbortTransfer(ctx context.Context, req TransferHandleOpRequest) error {
	return runTransErr(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) error {
		return e.transfer.AbortTransfer(c, uctrans.AbortTransferRequest{CallBase: b, Handle: req.Handle, Reason: req.Reason})
	})
}
func (e *Engine) ResumeTransfer(ctx context.Context, req ResumeTransferRequest) (TransferHandleInfo, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (TransferHandleInfo, error) {
		return e.transfer.ResumeTransfer(c, uctrans.ResumeTransferRequest{CallBase: b, TransferID: req.TransferID, StartNextGen: req.StartNextGen, TransferSessionOptions: req.TransferSessionOptions})
	})
}
func (e *Engine) RecoverTransfer(ctx context.Context, req RecoverTransferRequest) (TransferRecoveryResult, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (TransferRecoveryResult, error) {
		return e.transfer.RecoverTransfer(c, uctrans.RecoverTransferRequest{CallBase: b, TransferID: req.TransferID, PruneSuperseded: req.PruneSuperseded, LocalRootForClean: req.LocalRootForClean})
	})
}
func (e *Engine) RecoverAllTransfers(ctx context.Context, req RecoverAllTransfersRequest) (RecoverAllResult, error) {
	return runOpStream(e, ctx, req.OperationStream, func(c context.Context) (RecoverAllResult, error) {
		return e.transfer.RecoverAllTransfersAuthorized(c, req)
	})
}
func (e *Engine) InspectTransfer(ctx context.Context, req InspectTransferRequest) (TransferStatusSnapshot, error) {
	return runTrans(e, ctx, req.RemoteCall, func(c context.Context, b uctrans.CallBase) (TransferStatusSnapshot, error) {
		return e.transfer.InspectTransfer(c, uctrans.InspectTransferRequest{CallBase: b, TransferID: req.TransferID, Handle: req.Handle})
	})
}
