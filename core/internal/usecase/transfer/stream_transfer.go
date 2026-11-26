package transfer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
// 严格经 gate.WithAuthorized -> pool.WithLease -> pool.RegisterLeaseHandleWith[KindTransfer] 登记托管句柄，
// 由 fsm.TransferFSM 持久化初始 Init Journal（写盘失败自动释放句柄）。
func (s *Service) StartTransfer(ctx context.Context, req StartTransferRequest) (TransferHandleInfo, error) {
	return s.startOrResumeTransfer(ctx, req, nil, true)
}

func (s *Service) startOrResumeTransfer(ctx context.Context, req StartTransferRequest, resumedState fsm.TransferState, freshStart bool) (TransferHandleInfo, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, perm, renameSpec, err := s.normalizeStartRequest(ctx, &req)
	if err != nil {
		return TransferHandleInfo{}, err
	}
	tid, _ := req.TransferID.Get()
	rpaths, extra := collectTransferPaths(req)
	action := pickIf(freshStart, "start", "resume")
	spec := authOpSpec{
		base: req.CallBase, targetHop: hop, tool: "transfer", action: action, paths: rpaths, extraPaths: extra,
		params:      map[string]string{"transfer_id": tid.String(), "direction": req.Dest.Direction().String()},
		defaultRisk: pickIf(req.Dest.Direction() == fsm.TransferDirectionUpload, security.RiskModerate, security.RiskSafe),
		summary:     "transfer " + action + " " + tid.String(), canonicalize: len(rpaths) > 0,
	}
	return runAuthorizedVal[security.CapTransfer](ctx, s, spec, func(authCtx context.Context, auth gate.Authorized[security.CapTransfer], emitter *transferEmitter) (TransferHandleInfo, error) {
		return s.registerStreamSession(authCtx, auth.Binding(), emitter, req, perm, renameSpec, resumedState, freshStart)
	})
}
func collectTransferPaths(req StartTransferRequest) (rpaths []pathalg.RemotePath, extra []string) {
	if rp, ok := req.Dest.Remote().Get(); ok {
		rpaths = append(rpaths, rp)
	}
	if rs, ok := req.RemoteSource.Get(); ok {
		rpaths = append(rpaths, rs)
	}
	if lp, ok := req.Dest.Local().Get(); ok {
		extra = append(extra, lp.String())
	}
	return rpaths, extra
}
func (s *Service) normalizeStartRequest(ctx context.Context, req *StartTransferRequest) (hop plan.HopSpec, perm fs.FileMode, renameSpec ports.RemoteRenameSpec, err error) {
	if hop, err = s.validateBaseCall(ctx, req.CallBase); err != nil || s.journals == nil {
		return hop, 0, renameSpec, pickIf[error](err != nil, err, ErrJournalStoreUnavailable)
	}
	if !req.Dest.IsValid() || req.TotalBytes > fsm.MaxTransferBytes {
		return hop, 0, renameSpec, pickIf[error](req.TotalBytes > fsm.MaxTransferBytes, fmt.Errorf("%w: TotalBytes=%d 超限", fsm.ErrTransferSizeExceeded, req.TotalBytes), fmt.Errorf("%w: TransferDest 无效", ErrInvalidRequest))
	}
	renameSpec, e1 := s.validateStartDirectionFields(*req)
	perm, e2 := resolvePerm(req.Perm, pickIf(req.Dest.Direction() == fsm.TransferDirectionUpload, defaultRemoteFilePerm, defaultLocalStagePerm))
	if err = firstErr(e1, e2); err != nil {
		return hop, 0, renameSpec, err
	}
	if id, ok := req.TransferID.Get(); !ok {
		genID, gErr := security.NewOperationIDFrom(s.entropy)
		if gErr != nil {
			return hop, 0, renameSpec, gErr
		}
		req.TransferID = algebraic.Some(genID)
	} else if !id.IsValid() {
		return hop, 0, renameSpec, fmt.Errorf("%w: TransferID 无效", ErrInvalidRequest)
	}
	req.JournalVersion, req.Generation = pickIf(req.JournalVersion == fsm.JournalVersionInvalid, fsm.JournalVersionV2, req.JournalVersion), pickIf(req.Generation == 0, uint64(1), req.Generation)
	return hop, perm, renameSpec, pickIf[error](req.JournalVersion.IsValid(), nil, fmt.Errorf("%w: JournalVersion 无效", ErrInvalidRequest))
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
	switch {
	case s.scopedFS == nil:
		return renameSpec, ErrScopedFSUnavailable
	case !okL || !lr.IsValid() || !okR || !rs.IsValid():
		return renameSpec, fmt.Errorf("%w: 下载传输须提供有效 LocalRoot 与 RemoteSource", ErrInvalidRequest)
	case req.ExpectedAnchor.IsSome():
		return renameSpec, fmt.Errorf("%w: 下载传输不支持 ExpectedAnchor", ErrInvalidRequest)
	default:
		return renameSpec, nil
	}
}
func (s *Service) registerStreamSession(ctx context.Context, binding security.OperationBinding, emitter *transferEmitter, req StartTransferRequest, perm fs.FileMode, renameSpec ports.RemoteRenameSpec, resumedState fsm.TransferState, freshStart bool) (TransferHandleInfo, error) {
	var info TransferHandleInfo
	var startEffs []fsm.TransferEffect
	var startEvs []fsm.TransferEvent
	startedAt := s.clock.Now().UTC().Round(0)
	if err := s.pool.WithLease(ctx, req.Plan, func(_ context.Context, lease *pool.Lease) (regErr error) {
		info.Handle, regErr = pool.RegisterLeaseHandleWith[plan.KindTransfer](s.pool, lease, binding, func(revokeCtx context.Context, conn ports.TransportConn) (*managedTransferSession, error) {
			sess, effs, evs, bErr := s.buildManagedTransferSession(revokeCtx, conn, req, perm, renameSpec, resumedState, freshStart, startedAt)
			if bErr == nil {
				info.TransferID, info.Meta, info.State, startEffs, startEvs = sess.meta.TransferID(), sess.meta, sess.state, effs, evs
			}
			return sess, bErr
		})
		return regErr
	}); err != nil {
		return TransferHandleInfo{}, err
	}
	if err := s.persistJournalEffects(ctx, startEffs); err != nil {
		_ = pool.ReleaseHandle[plan.KindTransfer](s.pool, info.Handle)
		return TransferHandleInfo{}, err
	}
	emitter.emitFSMTransitions(ctx, fsm.TransferKindInitialized, info.State, startEvs)
	s.handleMu.Lock()
	s.activeHandles[info.TransferID] = info.Handle
	s.handleMu.Unlock()
	return info, nil
}

// WriteTransferChunk 向活跃上传会话写入单个严格连续分片（<= 64 MiB）并同步推进 TransferFSM 与 Journal。
func (s *Service) WriteTransferChunk(ctx context.Context, req WriteTransferChunkRequest) (WriteTransferChunkResult, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, err := s.validateHandleCall(ctx, req.CallBase, req.Handle)
	if err != nil {
		return WriteTransferChunkResult{}, err
	}
	if len(req.Data) == 0 || uint64(len(req.Data)) > fsm.MaxTransferChunkBytes {
		return WriteTransferChunkResult{}, fmt.Errorf("%w: 分片长度 %d 越界", fsm.ErrInvalidChunkOffset, len(req.Data))
	}
	return runAuthorizedHandleVal(ctx, s, req.CallBase, hop, req.Handle, "write_chunk", security.RiskModerate, func(hCtx context.Context, _ gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter) (WriteTransferChunkResult, error) {
		stagePath, ok := sess.remoteStagePath.Get()
		if sess.meta.Direction() != fsm.TransferDirectionUpload || !ok {
			return WriteTransferChunkResult{}, pickIf[error](sess.meta.Direction() != fsm.TransferDirectionUpload, fmt.Errorf("%w: 仅适用于上传", ErrTransferHandleMismatch), ErrInvalidRequest)
		}
		nextSt, chunkDig, aErr := s.applyChunkWithWriter(hCtx, sess, emitter, req.Offset, req.Data, "streaming", func() error {
			return sess.rfs.WriteChunk(hCtx, stagePath, int64(req.Offset), bytes.NewReader(req.Data), int64(len(req.Data)))
		})
		if aErr != nil {
			return WriteTransferChunkResult{}, aErr
		}
		off, _ := transferProgressOf(nextSt)
		return WriteTransferChunkResult{TransferID: sess.meta.TransferID(), NextOffset: off, TotalBytes: sess.meta.TotalBytes(), ChunkDigest: chunkDig, StateKind: nextSt.Kind()}, nil
	})
}

// PullTransferChunk 从远端向本地 ScopedRootFS 暂存文件拉取下一个连续分片并推进 TransferFSM 与 Journal。
func (s *Service) PullTransferChunk(ctx context.Context, req PullTransferChunkRequest) (PullTransferChunkResult, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, err := s.validateHandleCall(ctx, req.CallBase, req.Handle)
	if err != nil {
		return PullTransferChunkResult{}, err
	}
	maxChunk := pickIf(req.MaxChunkBytes == 0, uint64(s.defaultChunkSize), req.MaxChunkBytes)
	if s.scopedFS == nil || maxChunk == 0 || maxChunk > fsm.MaxTransferChunkBytes {
		return PullTransferChunkResult{}, pickIf[error](s.scopedFS == nil, ErrScopedFSUnavailable, fmt.Errorf("%w: MaxChunkBytes 越界", ErrInvalidRequest))
	}
	return runAuthorizedHandleVal(ctx, s, req.CallBase, hop, req.Handle, "pull_chunk", security.RiskSafe, func(hCtx context.Context, _ gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter) (PullTransferChunkResult, error) {
		return s.pullOneDownloadChunk(hCtx, sess, emitter, maxChunk)
	})
}

func (s *Service) pullOneDownloadChunk(ctx context.Context, sess *managedTransferSession, emitter *transferEmitter, maxChunk uint64) (PullTransferChunkResult, error) {
	if sess.meta.Direction() != fsm.TransferDirectionDownload {
		return PullTransferChunkResult{}, fmt.Errorf("%w: PullTransferChunk 仅适用于下载", ErrTransferHandleMismatch)
	}
	streamSt, ok := sess.state.(*fsm.TransferStreaming)
	if !ok {
		return PullTransferChunkResult{}, fmt.Errorf("%w: 当前状态 %s 不能拉取分片", fsm.ErrIllegalTransition, sess.state.Kind())
	}
	rs, okR := sess.remoteSource.Get()
	lr, okL := sess.localRoot.Get()
	stageDest, okS := sess.localStageDest.Get()
	if !okR || !okL || !okS {
		return PullTransferChunkResult{}, ErrInvalidRequest
	}
	offset, want := streamSt.Offset(), min(maxChunk, sess.meta.TotalBytes()-streamSt.Offset())
	data, err := readRemoteChunkExact(ctx, sess.rfs, rs, int64(offset), int64(want))
	if err != nil {
		return PullTransferChunkResult{}, err
	}
	nextSt, chunkDig, err := s.applyChunkWithWriter(ctx, sess, emitter, offset, data, "downloading", func() error {
		return s.scopedFS.WithRoot(lr, func(root ports.RootHandle) error {
			if err := ensureParentLocalDir(root, stageDest); err != nil {
				return err
			}
			_, wErr := root.WriteChunk(stageDest, int64(offset), bytes.NewReader(data), int64(len(data)), sanitizeLocalDownloadPerm(sess.perm))
			return wErr
		})
	})
	if err != nil {
		return PullTransferChunkResult{}, err
	}
	off, _ := transferProgressOf(nextSt)
	return PullTransferChunkResult{TransferID: sess.meta.TransferID(), Offset: offset, BytesPulled: want, NextOffset: off, TotalBytes: sess.meta.TotalBytes(), ChunkDigest: chunkDig, StateKind: nextSt.Kind()}, nil
}

//xops:syncclosure
func (s *Service) applyChunkWithWriter(ctx context.Context, sess *managedTransferSession, emitter *transferEmitter, offset uint64, data []byte, stage string, writeData func() error) (fsm.TransferState, security.Digest, error) {
	chunkDig := security.DigestBytes(data)
	chunkIn, err := fsm.TransferInputChunk(offset, uint64(len(data)), chunkDig)
	if err != nil {
		return nil, zeroVal[security.Digest](), err
	}
	prevKind := sess.state.Kind()
	nextSt, effs, evs, err := fsm.TransitionTransfer(sess.state, chunkIn)
	if err != nil {
		return nil, zeroVal[security.Digest](), err
	}
	if err = writeData(); err != nil {
		return nil, zeroVal[security.Digest](), err
	}
	if err = s.persistJournalEffects(ctx, effs); err != nil {
		return nil, zeroVal[security.Digest](), err
	}
	sess.state = nextSt
	if sess.hasher != nil {
		_, _ = sess.hasher.Write(data)
	}
	off, chunks := transferProgressOf(nextSt)
	emitter.emitFSMTransitions(ctx, prevKind, nextSt, evs)
	emitter.emitProgress(ctx, sess.meta.TransferID(), sess.meta.Direction(), off, sess.meta.TotalBytes(), chunks, sess.startedAt, stage)
	return nextSt, chunkDig, nil
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
	if err := s.persistJournalEffects(ctx, effs); err != nil {
		return nil, true, err
	}
	sess.state = nextSt
	emitter.emitFSMTransitions(ctx, prevKind, nextSt, evs)
	return nextSt, false, nil
}

// CommitTransfer 执行全量 SHA-256 核验、Journal(Verified+CommitStarted) 落盘与原子提交交接；
// 遇 Applied&&!Durable 或 OutcomeUnknown 停留 TransferUncertainCommit 零副作用并上报 OutcomeUnknown。
func (s *Service) CommitTransfer(ctx context.Context, req CommitTransferRequest) (CommitTransferResult, error) {
	return runReleasableHandleVal(ctx, s, req.CallBase, req.Handle, "commit", func(hCtx context.Context, auth gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter) (CommitTransferResult, bool, error) {
		return s.driveCommitTransfer(hCtx, auth, sess, emitter)
	})
}

// AbortTransfer 主动中止 Streaming/Verifying 受管传输，落盘 Aborted、清理暂存并释放句柄；已进提交态严格拒绝。
func (s *Service) AbortTransfer(ctx context.Context, req AbortTransferRequest) error {
	_, err := runReleasableHandleVal(ctx, s, req.CallBase, req.Handle, "abort", func(hCtx context.Context, _ gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter) (struct{}, bool, error) {
		if _, _, aErr := s.advanceTransferFSM(hCtx, sess, emitter, fsm.TransferInputAbort(req.Reason), nil); aErr != nil {
			return struct{}{}, false, aErr
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
	var transferID security.OperationID
	var releaseSlot bool
	out, err := runAuthorizedHandleVal(ctx, s, base, hop, handle, action, security.RiskModerate, func(hCtx context.Context, auth gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter) (res T, fErr error) {
		transferID = sess.meta.TransferID()
		res, releaseSlot, fErr = fn(hCtx, auth, sess, emitter)
		return res, fErr
	})
	if releaseSlot {
		s.handleMu.Lock()
		if cur, ok := s.activeHandles[transferID]; ok && cur.Equal(handle) {
			delete(s.activeHandles, transferID)
		}
		s.handleMu.Unlock()
		_ = pool.ReleaseHandle[plan.KindTransfer](s.pool, handle)
	}
	return out, err
}
func (s *Service) driveCommitTransfer(ctx context.Context, auth gate.Authorized[security.CapTransfer], sess *managedTransferSession, emitter *transferEmitter) (CommitTransferResult, bool, error) {
	if sess.state.Kind() != fsm.TransferKindVerifying {
		return CommitTransferResult{}, false, fmt.Errorf("%w: CommitTransfer 要求 Verifying 状态，当前=%s", fsm.ErrIllegalTransition, sess.state.Kind())
	}
	out := CommitTransferResult{TransferID: sess.meta.TransferID(), Generation: sess.meta.Generation()}
	actualDig, vErr := s.verifyStagedDigest(ctx, sess)
	verifyIn, inErr := fsm.TransferInputVerifyResult(vErr == nil, actualDig, fmtErr(vErr))
	nextSt, _, err := s.advanceTransferFSM(ctx, sess, emitter, verifyIn, inErr)
	if err != nil {
		return CommitTransferResult{}, false, err
	}
	if nextSt.Kind() == fsm.TransferKindAborted {
		s.cleanupTransferStaging(ctx, sess)
		out.State = nextSt
		return out, true, pickIf[error](vErr != nil, vErr, ErrDigestMismatch)
	}
	out.ActualDigest = algebraic.Some(actualDig)
	dur, reason, commitErr := s.executeAtomicTransferCommit(ctx, sess)
	comIn, inErr := fsm.TransferInputCommitResult(dur, reason)
	endSt, journalFailed, err := s.advanceTransferFSM(ctx, sess, emitter, comIn, inErr)
	if err != nil {
		if journalFailed {
			reportUnknownOutcome(auth, "journal_commit_append_failed", err.Error())
			out.State = sess.state
			return out, true, fmt.Errorf("%w: %w", ErrUncertainCommit, err)
		}
		return CommitTransferResult{}, false, err
	}
	return s.finalizeCommitState(ctx, auth, sess, out, endSt, reason, commitErr)
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
	if err != nil {
		return TransferStatusSnapshot{}, err
	}
	if h, ok := req.Handle.Get(); !req.TransferID.IsValid() || (ok && !h.IsValid()) {
		return TransferStatusSnapshot{}, fmt.Errorf("%w: TransferID 或 Handle 无效", ErrInvalidRequest)
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "transfer", action: "inspect", params: map[string]string{"transfer_id": req.TransferID.String()}, defaultRisk: security.RiskSafe, summary: "transfer inspect " + req.TransferID.String()}
	return runAuthorizedVal[security.CapTransfer](ctx, s, spec, func(authCtx context.Context, _ gate.Authorized[security.CapTransfer], _ *transferEmitter) (TransferStatusSnapshot, error) {
		return s.inspectAuthorizedTransfer(authCtx, req)
	})
}
func (s *Service) inspectAuthorizedTransfer(ctx context.Context, req InspectTransferRequest) (TransferStatusSnapshot, error) {
	handle, hasHandle := req.Handle.Get()
	if !hasHandle {
		s.handleMu.Lock()
		handle, hasHandle = s.activeHandles[req.TransferID]
		s.handleMu.Unlock()
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
		if err == nil || req.Handle.IsSome() || !errors.Is(err, pool.ErrHandleNotFound) {
			return snap, err
		}
	}
	if s.journals == nil {
		return TransferStatusSnapshot{}, ErrTransferNotFound
	}
	rec, err := s.recoverFromStore(ctx, req.TransferID, false)
	if errors.Is(err, ports.ErrNotFound) || rec.State == nil || !rec.State.IsValid() {
		return TransferStatusSnapshot{}, pickIf[error](errors.Is(err, ports.ErrNotFound), ErrTransferNotFound, err)
	}
	off, chunks := transferProgressOf(rec.State)
	return TransferStatusSnapshot{TransferID: req.TransferID, Meta: fsm.TransferMetaOf(rec.State), StateKind: rec.State.Kind(), IsTerminal: rec.State.IsTerminal(), Offset: off, ChunkCount: chunks}, err
}
func (s *Service) validateHandleCall(ctx context.Context, base CallBase, handle plan.ManagedHandle[plan.KindTransfer]) (hop plan.HopSpec, err error) {
	if hop, err = s.validateBaseCall(ctx, base); err != nil {
		return hop, err
	}
	switch {
	case s.journals == nil:
		return zeroVal[plan.HopSpec](), ErrJournalStoreUnavailable
	case !handle.IsValid():
		return zeroVal[plan.HopSpec](), fmt.Errorf("%w: ManagedHandle 无效", ErrInvalidRequest)
	case !handle.MatchesPlan(base.Plan.PlanDigest()):
		return zeroVal[plan.HopSpec](), fmt.Errorf("%w: 托管句柄与连接计划不匹配", ErrTransferHandleMismatch)
	}
	return hop, nil
}

//xops:syncclosure
func runAuthorizedHandleVal[T any](ctx context.Context, s *Service, base CallBase, hop plan.HopSpec, handle plan.ManagedHandle[plan.KindTransfer], action string, defaultRisk security.RiskLevel, fn func(context.Context, gate.Authorized[security.CapTransfer], *managedTransferSession, *transferEmitter) (T, error)) (T, error) {
	spec := authOpSpec{base: base, targetHop: hop, tool: "transfer", action: action, params: map[string]string{"handle_id": handle.ID().String()}, defaultRisk: defaultRisk, summary: "transfer " + action + " " + handle.ID().String()}
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
			rec, ok := eff.Record().Get()
			if !ok || !rec.IsValid() {
				return fsm.ErrInvalidJournal
			}
			if err := s.journals.Append(ctx, rec); err != nil {
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
