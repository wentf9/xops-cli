package transfer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/plan"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/internal/pool"
	"github.com/wentf9/xops-cli/core/ports"
)

// StartTransfer 启动最高 10 GiB 可恢复流式传输（零 OperatorReadFS 依赖，适配物理隔离 MCP 路径）：
// 门控前保持 OperationBinding 100% 由显式入参确定（不提前抽熵破坏两步审批），受权后确定 TransferID 锁定 Generation=1、
// 原子校验互斥准入并登记托管句柄，审计后写失败自动回滚释放。
func (s *Service) StartTransfer(ctx context.Context, req StartTransferRequest) (TransferHandleInfo, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, perm, renameSpec, err := s.normalizeStartRequest(ctx, &req)
	if err != nil {
		return TransferHandleInfo{}, err
	}
	rpaths, extra := collectDestPaths(req.Dest, req.RemoteSource, nil, nil)
	params, summary := map[string]string{"direction": req.Dest.Direction().String(), "target": req.Dest.String()}, "transfer start "+req.Dest.String()
	if explicitID, ok := req.TransferID.Get(); ok {
		params["transfer_id"], summary = explicitID.String(), "transfer start "+explicitID.String()
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "transfer", action: "start", paths: rpaths, extraPaths: extra, params: params, defaultRisk: pickIf(req.Dest.Direction() == fsm.TransferDirectionUpload, security.RiskModerate, security.RiskSafe), summary: summary, canonicalize: len(rpaths) > 0}
	return s.runAuthorizedTransferRegister(ctx, spec, func(authCtx context.Context, auth gate.Authorized[security.CapTransfer], emitter *transferEmitter) (TransferHandleInfo, error) {
		tid := req.TransferID.OrElse(auth.OperationID())
		req.TransferID = algebraic.Some(tid)
		if _, live, lErr := s.lookupLiveHandle(authCtx, tid); lErr != nil || live {
			return TransferHandleInfo{}, pickIf[error](lErr != nil, lErr, fmt.Errorf("%w: 传输 %s 已存在活跃受管句柄", ports.ErrAlreadyExists, tid))
		}
		if _, lErr := s.journals.LoadGenerations(authCtx, tid); lErr == nil || !errors.Is(lErr, ports.ErrNotFound) {
			return TransferHandleInfo{}, pickIf[error](lErr == nil, fmt.Errorf("%w: 传输 %s 已存在于 JournalStore，禁止重复 StartTransfer", ports.ErrAlreadyExists, tid), lErr)
		}
		return s.registerStreamSession(authCtx, auth.Binding(), emitter, req, perm, renameSpec, nil, true)
	})
}
func collectDestPaths(dest fsm.TransferDest, remoteSrc algebraic.Option[pathalg.RemotePath], rpaths []pathalg.RemotePath, extra []string) ([]pathalg.RemotePath, []string) {
	if rp, ok := dest.Remote().Get(); ok {
		rpaths = append(rpaths, rp)
	}
	if rs, ok := remoteSrc.Get(); ok {
		rpaths = append(rpaths, rs)
	}
	if lp, ok := dest.Local().Get(); ok {
		extra = append(extra, lp.String())
	}
	return rpaths, extra
}

// runAuthorizedTransferRegister 统一包裹 StartTransfer/ResumeTransfer 的门控登记与 AuditPostWriteError 回滚释放。
//
//xops:syncclosure
func (s *Service) runAuthorizedTransferRegister(ctx context.Context, spec authOpSpec, fn func(context.Context, gate.Authorized[security.CapTransfer], *transferEmitter) (TransferHandleInfo, error)) (TransferHandleInfo, error) {
	var registered TransferHandleInfo
	info, err := runAuthorizedVal[security.CapTransfer](ctx, s, spec, func(authCtx context.Context, auth gate.Authorized[security.CapTransfer], emitter *transferEmitter) (TransferHandleInfo, error) {
		res, rErr := fn(authCtx, auth, emitter)
		if rErr == nil {
			registered = res
		}
		return res, rErr
	})
	if err != nil && registered.Handle.IsValid() {
		s.dropActiveHandle(registered.TransferID, registered.Handle, true)
	}
	return pickIf(err == nil, info, TransferHandleInfo{}), err
}
func (s *Service) normalizeStartRequest(ctx context.Context, req *StartTransferRequest) (hop plan.HopSpec, perm fs.FileMode, renameSpec ports.RemoteRenameSpec, err error) {
	if hop, err = s.validateBaseCall(ctx, req.CallBase); err != nil || s.journals == nil {
		return hop, 0, renameSpec, pickIf[error](err != nil, err, ErrJournalStoreUnavailable)
	}
	if id, ok := req.TransferID.Get(); !req.Dest.IsValid() || req.TotalBytes > fsm.MaxTransferBytes || req.Generation > 1 || (ok && !id.IsValid()) {
		return hop, 0, renameSpec, pickIf[error](req.TotalBytes > fsm.MaxTransferBytes, fmt.Errorf("%w: TotalBytes=%d 超限", fsm.ErrTransferSizeExceeded, req.TotalBytes), fmt.Errorf("%w: TransferDest/TransferID/Generation 无效", ErrInvalidRequest))
	}
	renameSpec, e1 := s.validateStartDirectionFields(*req)
	perm, e2 := resolvePerm(req.Perm, pickIf(req.Dest.Direction() == fsm.TransferDirectionUpload, defaultRemoteFilePerm, defaultLocalStagePerm))
	req.JournalVersion, req.Generation = pickIf(req.JournalVersion == fsm.JournalVersionInvalid, fsm.JournalVersionV2, req.JournalVersion), 1
	return hop, perm, renameSpec, firstErr(e1, e2, pickIf[error](req.JournalVersion.IsValid(), nil, fmt.Errorf("%w: JournalVersion 无效", ErrInvalidRequest)))
}
func (s *Service) validateStartDirectionFields(req StartTransferRequest) (renameSpec ports.RemoteRenameSpec, err error) {
	if err = validateOptionalUploadAttrs(req.ModTime, req.ExpectedDigest); err != nil {
		return renameSpec, err
	}
	if req.Dest.Direction() != fsm.TransferDirectionDownload {
		return ports.NewRemoteRenameSpec(ports.RemoteRenameSpecInput{ExpectedAnchor: req.ExpectedAnchor, NoClobber: req.NoClobber})
	}
	lr, okL := req.LocalRoot.Get()
	rs, okR := req.RemoteSource.Get()
	return renameSpec, pickIf[error](s.scopedFS == nil, ErrScopedFSUnavailable, pickIf[error](!okL || !lr.IsValid() || !okR || !rs.IsValid() || req.ExpectedAnchor.IsSome(), fmt.Errorf("%w: 下载传输须提供有效 LocalRoot/RemoteSource 且禁设 ExpectedAnchor", ErrInvalidRequest), nil))
}
func (s *Service) getActiveHandle(tid security.OperationID) (plan.ManagedHandle[plan.KindTransfer], bool) {
	s.handleMu.Lock()
	h, ok := s.activeHandles[tid]
	s.handleMu.Unlock()
	return h, ok
}
func (s *Service) dropActiveHandle(tid security.OperationID, h plan.ManagedHandle[plan.KindTransfer], release bool) {
	s.handleMu.Lock()
	if cur, ok := s.activeHandles[tid]; ok && cur.Equal(h) {
		delete(s.activeHandles, tid)
	}
	s.handleMu.Unlock()
	if release {
		_ = pool.ReleaseHandle[plan.KindTransfer](s.pool, h)
	}
}
func (s *Service) lookupLiveHandle(ctx context.Context, tid security.OperationID) (plan.ManagedHandle[plan.KindTransfer], bool, error) {
	h, ok := s.getActiveHandle(tid)
	if !ok {
		return zeroVal[plan.ManagedHandle[plan.KindTransfer]](), false, nil
	}
	err := pool.WithManagedHandle[plan.KindTransfer, *managedTransferSession](ctx, s.pool, h, func(context.Context, *managedTransferSession) error { return nil })
	if errors.Is(err, pool.ErrHandleNotFound) {
		s.dropActiveHandle(tid, h, false)
		return zeroVal[plan.ManagedHandle[plan.KindTransfer]](), false, nil
	}
	return pickIf(err == nil, h, zeroVal[plan.ManagedHandle[plan.KindTransfer]]()), err == nil, err
}
func (s *Service) registerStreamSession(ctx context.Context, binding security.OperationBinding, emitter *transferEmitter, req StartTransferRequest, perm fs.FileMode, renameSpec ports.RemoteRenameSpec, resumedState fsm.TransferState, freshStart bool) (info TransferHandleInfo, err error) {
	tid, _ := req.TransferID.Get()
	handleBinding, err := enrichHandleBinding(binding, tid, req.Dest)
	if err != nil {
		return TransferHandleInfo{}, err
	}
	var startEffs []fsm.TransferEffect
	var startEvs []fsm.TransferEvent
	if err = s.pool.WithLease(ctx, req.Plan, func(leaseCtx context.Context, lease *pool.Lease) (regErr error) {
		info.Handle, regErr = pool.RegisterLeaseHandleWith[plan.KindTransfer](s.pool, lease, handleBinding, func(revokeCtx context.Context, conn ports.TransportConn) (*managedTransferSession, error) {
			sess, effs, evs, bErr := s.buildManagedTransferSession(leaseCtx, revokeCtx, conn, req, perm, renameSpec, resumedState, freshStart, s.clock.Now().UTC().Round(0))
			if bErr == nil {
				info.TransferID, info.Meta, info.State, startEffs, startEvs = sess.meta.TransferID(), sess.meta, sess.state, effs, evs
			}
			return sess, bErr
		})
		return regErr
	}); err != nil {
		return TransferHandleInfo{}, err
	}
	// 在 s.handleMu 内原子占槽，杜绝并发 ResumeTransfer(StartNextGen=false) 覆盖活句柄造成孤儿钉选。
	s.handleMu.Lock()
	_, dup := s.activeHandles[info.TransferID]
	if !dup {
		s.activeHandles[info.TransferID] = info.Handle
	}
	s.handleMu.Unlock()
	if dup {
		_ = pool.ReleaseHandle[plan.KindTransfer](s.pool, info.Handle)
		return TransferHandleInfo{}, fmt.Errorf("%w: 传输 %s 已存在并发活跃句柄", ports.ErrAlreadyExists, info.TransferID)
	}
	if err = s.persistJournalEffects(ctx, startEffs); err != nil {
		s.dropActiveHandle(info.TransferID, info.Handle, true)
		return TransferHandleInfo{}, err
	}
	emitter.emitFSMTransitions(ctx, fsm.TransferKindInitialized, info.State, startEvs)
	return info, nil
}
func enrichHandleBinding(b security.OperationBinding, tid security.OperationID, dest fsm.TransferDest) (security.OperationBinding, error) {
	params := b.Parameters()
	if params == nil {
		params = map[string]string{}
	}
	params["transfer_id"], params["direction"], params["target"] = tid.String(), dest.Direction().String(), dest.String()
	return security.NewOperationBinding(security.OperationBindingSpec{Capability: b.Capability(), Tool: b.Tool(), Action: b.Action(), NodeID: b.NodeID(), NodeIDs: b.NodeIDs(), Endpoint: b.Endpoint(), CanonicalPaths: b.CanonicalPaths(), RecursivePaths: b.RecursivePaths(), CommandDigest: b.CommandDigest(), PlanDigest: b.PlanDigest(), Parameters: params})
}

// WriteTransferChunk 向活跃上传会话写入单个严格连续分片（<= 64 MiB），写前复核远端路径未发生软链漂移并同步推进 Journal。
func (s *Service) WriteTransferChunk(ctx context.Context, req WriteTransferChunkRequest) (WriteTransferChunkResult, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, err := s.validateHandleCall(ctx, req.CallBase, req.Handle)
	if err != nil || len(req.Data) == 0 || uint64(len(req.Data)) > fsm.MaxTransferChunkBytes {
		return WriteTransferChunkResult{}, pickIf[error](err != nil, err, fmt.Errorf("%w: 分片长度 %d 越界", fsm.ErrInvalidChunkOffset, len(req.Data)))
	}
	return runAuthorizedHandleVal(ctx, s, req.CallBase, hop, req.Handle, "write_chunk", security.RiskModerate, func(hCtx context.Context, _ gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter) (WriteTransferChunkResult, error) {
		stagePath, okS := sess.remoteStagePath.Get()
		finalPath, okF := sess.meta.Dest().Remote().Get()
		if sess.meta.Direction() != fsm.TransferDirectionUpload || !okS || !okF {
			return WriteTransferChunkResult{}, pickIf[error](sess.meta.Direction() != fsm.TransferDirectionUpload, fmt.Errorf("%w: 仅适用于上传", ErrTransferHandleMismatch), ErrInvalidRequest)
		}
		if dErr := verifyRemotePathAuthorized(hCtx, s.enforceStrictPaths(), sess.rfs, req.Handle.Binding(), finalPath); dErr != nil {
			return WriteTransferChunkResult{}, dErr
		}
		off, chunkDig, kind, aErr := s.applyChunkWithWriter(hCtx, sess, emitter, req.Offset, req.Data, "streaming", func() error {
			return sess.rfs.WriteChunk(hCtx, stagePath, int64(req.Offset), bytes.NewReader(req.Data), int64(len(req.Data)))
		})
		return pickIf(aErr == nil, WriteTransferChunkResult{TransferID: sess.meta.TransferID(), NextOffset: off, TotalBytes: sess.meta.TotalBytes(), ChunkDigest: chunkDig, StateKind: kind}, WriteTransferChunkResult{}), aErr
	})
}

// PullTransferChunk 从远端向本地 ScopedRootFS 暂存文件拉取下一个连续分片并推进 TransferFSM 与 Journal。
func (s *Service) PullTransferChunk(ctx context.Context, req PullTransferChunkRequest) (PullTransferChunkResult, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, err := s.validateHandleCall(ctx, req.CallBase, req.Handle)
	maxChunk := pickIf(req.MaxChunkBytes == 0, uint64(s.defaultChunkSize), req.MaxChunkBytes)
	if err != nil || s.scopedFS == nil || maxChunk == 0 || maxChunk > fsm.MaxTransferChunkBytes {
		return PullTransferChunkResult{}, firstErr(err, pickIf[error](s.scopedFS == nil, ErrScopedFSUnavailable, fmt.Errorf("%w: MaxChunkBytes 越界", ErrInvalidRequest)))
	}
	return runAuthorizedHandleVal(ctx, s, req.CallBase, hop, req.Handle, "pull_chunk", security.RiskSafe, func(hCtx context.Context, _ gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter) (PullTransferChunkResult, error) {
		return s.pullOneDownloadChunk(hCtx, sess, emitter, maxChunk, req.Handle.Binding())
	})
}
func (s *Service) pullOneDownloadChunk(ctx context.Context, sess *managedTransferSession, emitter *transferEmitter, maxChunk uint64, handleBinding security.OperationBinding) (PullTransferChunkResult, error) {
	streamSt, ok := sess.state.(*fsm.TransferStreaming)
	if sess.meta.Direction() != fsm.TransferDirectionDownload || !ok {
		return PullTransferChunkResult{}, pickIf(sess.meta.Direction() != fsm.TransferDirectionDownload, fmt.Errorf("%w: PullTransferChunk 仅适用于下载", ErrTransferHandleMismatch), fmt.Errorf("%w: 当前状态 %s 不能拉取分片", fsm.ErrIllegalTransition, sess.state.Kind()))
	}
	rs, okR := sess.opts.RemoteSource.Get()
	lr, okL := sess.opts.LocalRoot.Get()
	stageDest, okS := sess.localStageDest.Get()
	if !okR || !okL || !okS {
		return PullTransferChunkResult{}, ErrInvalidRequest
	}
	if err := verifyRemoteDownloadSource(ctx, s.enforceStrictPaths(), sess.rfs, handleBinding, rs, sess.sourceAnchor, int64(sess.meta.TotalBytes()), sess.sourceModTime); err != nil {
		return PullTransferChunkResult{}, err
	}
	offset, want := streamSt.Offset(), min(maxChunk, sess.meta.TotalBytes()-streamSt.Offset())
	data, err := readRemoteChunkExact(ctx, sess.rfs, rs, int64(offset), int64(want))
	if err != nil {
		return PullTransferChunkResult{}, err
	}
	off, chunkDig, kind, err := s.applyChunkWithWriter(ctx, sess, emitter, offset, data, "downloading", func() error {
		return s.scopedFS.WithRoot(lr, func(root ports.RootHandle) error {
			if e := ensureParentLocalDir(root, stageDest); e != nil {
				return e
			}
			_, wErr := root.WriteChunk(stageDest, int64(offset), bytes.NewReader(data), int64(len(data)), sanitizeLocalDownloadPerm(sess.effectivePerm))
			return wErr
		})
	})
	return pickIf(err == nil, PullTransferChunkResult{TransferID: sess.meta.TransferID(), Offset: offset, BytesPulled: want, NextOffset: off, TotalBytes: sess.meta.TotalBytes(), ChunkDigest: chunkDig, StateKind: kind}, PullTransferChunkResult{}), err
}

//xops:syncclosure
func (s *Service) applyChunkWithWriter(ctx context.Context, sess *managedTransferSession, emitter *transferEmitter, offset uint64, data []byte, stage string, writeData func() error) (uint64, security.Digest, fsm.TransferStateKind, error) {
	chunkDig, prevKind := security.DigestBytes(data), sess.state.Kind()
	chunkIn, err := fsm.TransferInputChunk(offset, uint64(len(data)), chunkDig)
	var nextSt fsm.TransferState
	var effs []fsm.TransferEffect
	var evs []fsm.TransferEvent
	if err == nil {
		nextSt, effs, evs, err = fsm.TransitionTransfer(sess.state, chunkIn)
	}
	if err == nil {
		err = writeData()
	}
	if err == nil {
		err = s.persistJournalEffects(ctx, effs)
	}
	if err != nil {
		return 0, zeroVal[security.Digest](), fsm.TransferKindInvalid, err
	}
	sess.state = nextSt
	if sess.hasher != nil {
		_, _ = sess.hasher.Write(data)
	}
	off, chunks := transferProgressOf(nextSt)
	emitter.emitFSMTransitions(ctx, prevKind, nextSt, evs)
	emitter.emitProgress(ctx, sess.meta.TransferID(), sess.meta.Direction(), off, sess.meta.TotalBytes(), chunks, sess.startedAt, stage)
	return off, chunkDig, nextSt.Kind(), nil
}
func (s *Service) advanceTransferFSM(ctx context.Context, sess *managedTransferSession, emitter *transferEmitter, in fsm.TransferInput, inErr error) (fsm.TransferState, bool, error) {
	if inErr != nil {
		return nil, false, inErr
	}
	prevKind := sess.state.Kind()
	nextSt, effs, evs, err := fsm.TransitionTransfer(sess.state, in)
	if err != nil {
		return nil, false, err
	}
	if err = s.persistJournalEffects(ctx, effs); err != nil {
		return nil, true, err
	}
	sess.state = nextSt
	emitter.emitFSMTransitions(ctx, prevKind, nextSt, evs)
	return nextSt, false, nil
}

// CommitTransfer 执行全量 SHA-256 核验、Journal(Verified+CommitStarted) 落盘与原子提交交接；
// 瞬态核验错误保留 Verifying 与暂存文件；Committed WAL 落盘失败确定性推进至 *fsm.TransferUncertainCommit 并上报 OutcomeUnknown。
func (s *Service) CommitTransfer(ctx context.Context, req CommitTransferRequest) (CommitTransferResult, error) {
	return runReleasableHandleVal(ctx, s, req.CallBase, req.Handle, "commit", func(hCtx context.Context, auth gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter) (CommitTransferResult, bool, error) {
		return s.driveCommitTransfer(hCtx, auth, sess, emitter, req.Handle.Binding())
	})
}

// AbortTransfer 主动中止 Streaming/Verifying 受管传输，落盘 Aborted、清理暂存并释放句柄；已进提交态严格拒绝。
func (s *Service) AbortTransfer(ctx context.Context, req AbortTransferRequest) error {
	_, err := runReleasableHandleVal(ctx, s, req.CallBase, req.Handle, "abort", func(hCtx context.Context, _ gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter) (struct{}, bool, error) {
		if _, jFail, aErr := s.advanceTransferFSM(hCtx, sess, emitter, fsm.TransferInputAbort(req.Reason), nil); aErr != nil {
			return struct{}{}, jFail, aErr
		}
		s.cleanupTransferStaging(hCtx, sess)
		return struct{}{}, true, nil
	})
	return err
}

//xops:syncclosure
func runReleasableHandleVal[T any](ctx context.Context, s *Service, base CallBase, handle plan.ManagedHandle[plan.KindTransfer], action string, fn func(context.Context, gate.Authorized[security.CapTransfer], *managedTransferSession, *transferEmitter) (T, bool, error)) (T, error) {
	defer closeStreamIfNonNil(base.OperationStream)
	hop, err := s.validateHandleCall(ctx, base, handle)
	if err != nil {
		return zeroVal[T](), err
	}
	var releaseSlot bool
	var transferID security.OperationID
	out, err := runAuthorizedHandleVal(ctx, s, base, hop, handle, action, security.RiskModerate, func(hCtx context.Context, auth gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter) (res T, fErr error) {
		transferID = sess.meta.TransferID()
		res, releaseSlot, fErr = fn(hCtx, auth, sess, emitter)
		return res, fErr
	})
	if releaseSlot {
		s.dropActiveHandle(transferID, handle, true)
	}
	return out, err
}
func (s *Service) driveCommitTransfer(ctx context.Context, auth gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter, handleBinding security.OperationBinding) (CommitTransferResult, bool, error) {
	if sess.state.Kind() != fsm.TransferKindVerifying {
		return CommitTransferResult{}, false, fmt.Errorf("%w: CommitTransfer 要求 Verifying 状态，当前=%s", fsm.ErrIllegalTransition, sess.state.Kind())
	}
	out := CommitTransferResult{TransferID: sess.meta.TransferID(), Generation: sess.meta.Generation()}
	actualDig, vErr := s.verifyStagedDigest(ctx, sess)
	if vErr != nil && !errors.Is(vErr, io.ErrUnexpectedEOF) && !errors.Is(vErr, ports.ErrNotRegularFile) && !errors.Is(vErr, ports.ErrNotFound) {
		return CommitTransferResult{}, false, vErr
	}
	verifyIn, inErr := fsm.TransferInputVerifyResult(vErr == nil, actualDig, fmtErr(vErr))
	nextSt, verifyJFail, err := s.advanceTransferFSM(ctx, sess, emitter, verifyIn, inErr)
	if err != nil {
		return CommitTransferResult{}, verifyJFail, err
	}
	if nextSt.Kind() == fsm.TransferKindAborted {
		s.cleanupTransferStaging(ctx, sess)
		out.State = nextSt
		return out, true, pickIf[error](vErr != nil, vErr, ErrDigestMismatch)
	}
	out.ActualDigest = algebraic.Some(actualDig)
	dur, reason, commitErr := s.commitByDirection(ctx, sess, handleBinding)
	comIn, inErr := fsm.TransferInputCommitResult(dur, reason)
	endSt, journalFailed, err := s.advanceTransferFSM(ctx, sess, emitter, comIn, inErr)
	if err != nil {
		if journalFailed {
			return transitionCommitWALFailure(ctx, auth, sess, emitter, out, dur, err)
		}
		return CommitTransferResult{}, false, err
	}
	return s.finalizeCommitState(ctx, auth, sess, out, endSt, reason, commitErr)
}
func transitionCommitWALFailure(ctx context.Context, auth gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter, out CommitTransferResult, dur fsm.DurabilityStatus, walErr error) (CommitTransferResult, bool, error) {
	if uncIn, err := fsm.TransferInputCommitResult(pickIf(dur == fsm.DurabilityCommitted, fsm.DurabilityAppliedNotDurable, fsm.DurabilityOutcomeUnknown), walErr.Error()); err == nil {
		if uncSt, _, uncEvs, tErr := fsm.TransitionTransfer(sess.state, uncIn); tErr == nil {
			sess.state, out.State = uncSt, uncSt
			emitter.emitFSMTransitions(ctx, fsm.TransferKindCommitting, uncSt, uncEvs)
		}
	}
	reportUnknownOutcome(auth, "journal_commit_append_failed", walErr.Error())
	return out, true, fmt.Errorf("%w: %w", ErrUncertainCommit, walErr)
}
func (s *Service) finalizeCommitState(ctx context.Context, auth gate.Authorized[security.CapTransfer], sess *managedTransferSession, out CommitTransferResult, endSt fsm.TransferState, reason string, commitErr error) (CommitTransferResult, bool, error) {
	out.State = endSt
	switch endSt.(type) {
	case *fsm.TransferCommitted:
		return out, true, nil
	case *fsm.TransferAborted:
		s.cleanupTransferStaging(ctx, sess)
		return out, true, commitErr
	case *fsm.TransferUncertainCommit:
		reportUnknownOutcome(auth, "transfer_uncertain_commit", reason)
		return out, true, fmt.Errorf("%w: %w", ErrUncertainCommit, commitErr)
	case *fsm.TransferInitialized, *fsm.TransferStreaming, *fsm.TransferVerifying, *fsm.TransferCommitting:
		return out, false, fsm.ErrInvalidState
	default:
		return out, false, fsm.ErrInvalidState
	}
}

// InspectTransfer 严守 INV-E5：先经 Gate 鉴权，再查询活跃受管句柄或持久化 Journal，返回纯值只读快照。
func (s *Service) InspectTransfer(ctx context.Context, req InspectTransferRequest) (TransferStatusSnapshot, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, err := s.validateBaseCall(ctx, req.CallBase)
	if h, ok := req.Handle.Get(); err != nil || !req.TransferID.IsValid() || (ok && !h.IsValid()) {
		return TransferStatusSnapshot{}, pickIf[error](err != nil, err, fmt.Errorf("%w: TransferID 或 Handle 无效", ErrInvalidRequest))
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "transfer", action: "inspect", params: map[string]string{"transfer_id": req.TransferID.String()}, defaultRisk: security.RiskSafe, summary: "transfer inspect " + req.TransferID.String()}
	return runAuthorizedVal[security.CapTransfer](ctx, s, spec, func(authCtx context.Context, _ gate.Authorized[security.CapTransfer], _ *transferEmitter) (TransferStatusSnapshot, error) {
		return s.inspectAuthorizedTransfer(authCtx, req)
	})
}
func (s *Service) inspectAuthorizedTransfer(ctx context.Context, req InspectTransferRequest) (TransferStatusSnapshot, error) {
	handle, hasHandle := req.Handle.Get()
	if !hasHandle {
		handle, hasHandle = s.getActiveHandle(req.TransferID)
	}
	if hasHandle {
		var snap TransferStatusSnapshot
		err := pool.WithManagedHandle[plan.KindTransfer, *managedTransferSession](ctx, s.pool, handle, func(hCtx context.Context, sess *managedTransferSession) error {
			return sess.mu.WithLock(hCtx, func() error {
				var ok bool
				snap, ok = sess.snapshotIfMatches(req.TransferID)
				return pickIf[error](ok, nil, ErrTransferHandleMismatch)
			})
		})
		if !errors.Is(err, pool.ErrHandleNotFound) || req.Handle.IsSome() {
			return snap, err
		}
		s.dropActiveHandle(req.TransferID, handle, false)
	}
	if s.journals == nil {
		return TransferStatusSnapshot{}, ErrTransferNotFound
	}
	rec, err := s.recoverFromStore(ctx, req.TransferID, false)
	if errors.Is(err, ports.ErrNotFound) || rec.State == nil || !rec.State.IsValid() {
		return TransferStatusSnapshot{}, pickIf[error](errors.Is(err, ports.ErrNotFound), ErrTransferNotFound, err)
	}
	off, chunks := transferProgressOf(rec.State)
	return TransferStatusSnapshot{TransferID: req.TransferID, IsTerminal: rec.State.IsTerminal(), Meta: fsm.TransferMetaOf(rec.State), StateKind: rec.State.Kind(), Offset: off, ChunkCount: chunks}, err
}
func (s *Service) validateHandleCall(ctx context.Context, base CallBase, handle plan.ManagedHandle[plan.KindTransfer]) (hop plan.HopSpec, err error) {
	if hop, err = s.validateBaseCall(ctx, base); err != nil || s.journals == nil || !handle.IsValid() || !handle.MatchesPlan(base.Plan.PlanDigest()) {
		return zeroVal[plan.HopSpec](), firstErr(err, pickIf[error](s.journals == nil, ErrJournalStoreUnavailable, pickIf[error](!handle.IsValid(), fmt.Errorf("%w: ManagedHandle 无效", ErrInvalidRequest), fmt.Errorf("%w: 托管句柄与连接计划不匹配", ErrTransferHandleMismatch))))
	}
	return hop, nil
}

//xops:syncclosure
func runAuthorizedHandleVal[T any](ctx context.Context, s *Service, base CallBase, hop plan.HopSpec, handle plan.ManagedHandle[plan.KindTransfer], action string, defaultRisk security.RiskLevel, fn func(context.Context, gate.Authorized[security.CapTransfer], *managedTransferSession, *transferEmitter) (T, error)) (T, error) {
	params, bParams := map[string]string{"handle_id": handle.ID().String()}, handle.Binding().Parameters()
	for _, k := range [...]string{"transfer_id", "direction", "target"} {
		if v := bParams[k]; v != "" {
			params[k] = v
		}
	}
	spec := authOpSpec{base: base, targetHop: hop, tool: "transfer", action: action, params: params, defaultRisk: defaultRisk, summary: "transfer " + action + " " + pickIf(params["transfer_id"] != "", params["transfer_id"], handle.ID().String())}
	return runAuthorizedVal[security.CapTransfer](ctx, s, spec, func(authCtx context.Context, auth gate.Authorized[security.CapTransfer], emitter *transferEmitter) (out T, err error) {
		err = pool.WithManagedHandle[plan.KindTransfer, *managedTransferSession](authCtx, s.pool, handle, func(hCtx context.Context, sess *managedTransferSession) error {
			return sess.mu.WithLock(hCtx, func() (fErr error) { out, fErr = fn(hCtx, auth, sess, emitter); return fErr })
		})
		return out, err
	})
}
func (s *Service) persistJournalEffects(ctx context.Context, effs []fsm.TransferEffect) error {
	for _, eff := range effs {
		if eff.Kind() == fsm.TransferEffectWriteJournal {
			if rec, ok := eff.Record().Get(); !ok || !rec.IsValid() {
				return fsm.ErrInvalidJournal
			} else if err := s.journals.Append(ctx, rec); err != nil {
				return err
			}
		}
	}
	return nil
}
func reportUnknownOutcome(auth gate.Authorized[security.CapTransfer], code, reason string) {
	if out, err := execution.NewOutcomeUnknown(execution.ExecPhaseTransportLost, code, reason); err == nil {
		_ = auth.ReportOutcome(out)
	}
}
