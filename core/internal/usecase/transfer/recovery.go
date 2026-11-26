package transfer

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
	"github.com/wentf9/xops-cli/core/events"
	"github.com/wentf9/xops-cli/core/internal/gate"
	"github.com/wentf9/xops-cli/core/ports"
)

// RecoverTransfer 经能力门控执行单任务双代 Journal 崩溃恢复（ADR-016 / Plan P3-T3），严守三条铁律：
//  1. 严禁从损坏高世代回退至更低世代；
//  2. 任意损坏世代 PartialRecords() 含 CommitStarted/Committed 或健康世代悬停于 CommitStarted 时，
//     必须停留 TransferUncertainCommit、上报 OutcomeUnknown 且严格 0 副作用（禁重试、禁覆写、禁删日志）；
//  3. 空前缀高世代损坏必须 Fail-Closed 返回 ErrCorruptJournal 且严格 0 副作用。
func (s *Service) RecoverTransfer(ctx context.Context, req RecoverTransferRequest) (TransferRecoveryResult, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, err := s.validateBaseCall(ctx, req.CallBase)
	if lr, ok := req.LocalRootForClean.Get(); err != nil || s.journals == nil || !req.TransferID.IsValid() || (ok && !lr.IsValid()) {
		return TransferRecoveryResult{}, firstErr(err, pickIf[error](s.journals == nil, ErrJournalStoreUnavailable, fmt.Errorf("%w: TransferID 或 LocalRootForClean 无效", ErrInvalidRequest)))
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "transfer", action: "recover", params: map[string]string{"transfer_id": req.TransferID.String()}, defaultRisk: security.RiskSafe, summary: "transfer recover " + req.TransferID.String()}
	return runAuthorizedVal[security.CapTransfer](ctx, s, spec, func(authCtx context.Context, auth gate.Authorized[security.CapTransfer], _ *transferEmitter) (TransferRecoveryResult, error) {
		out, recErr := s.recoverFromStore(authCtx, req.TransferID, req.PruneSuperseded)
		if out.UncertainCommit || errors.Is(recErr, ErrUncertainCommit) {
			reportUnknownOutcome(auth, "transfer_uncertain_commit", fmtErr(recErr))
		}
		if recErr == nil {
			s.cleanAbortedDownloadStage(out.State, req.LocalRootForClean)
		}
		return out, recErr
	})
}
func (s *Service) cleanAbortedDownloadStage(st fsm.TransferState, localRoot algebraic.Option[pathalg.LocalDir]) {
	if st != nil && st.Kind() == fsm.TransferKindAborted {
		if meta := fsm.TransferMetaOf(st); meta.Direction() == fsm.TransferDirectionDownload {
			if _, localStageOpt, err := computeStreamStagePaths(meta); err == nil {
				s.removeLocalBestEffort(localRoot, localStageOpt)
			}
		}
	}
}

// RecoverAllTransfers 启动期扫描 JournalStore.ListActive 并逐条安全恢复（Gate Halted 态严格拒绝，单条异常不阻断扫描）。
func (s *Service) RecoverAllTransfers(ctx context.Context, req RecoverAllRequest) (RecoverAllResult, error) {
	if err := firstErr(s.checkReadyCtx(ctx), pickIf[error](s.gate.IsHalted(), gate.ErrGateHalted, pickIf[error](s.journals == nil, ErrJournalStoreUnavailable, nil))); err != nil {
		return RecoverAllResult{}, err
	}
	ids, err := s.journals.ListActive(ctx)
	if err != nil {
		return RecoverAllResult{}, err
	}
	entries := make([]TransferRecoveryEntry, 0, len(ids))
	for _, id := range ids {
		res, rErr := s.recoverFromStore(ctx, id, req.PruneSuperseded)
		entries = append(entries, TransferRecoveryEntry{TransferID: id, Result: res, Err: rErr})
	}
	return RecoverAllResult{Entries: entries}, nil
}

// ResumeTransfer 严守 INV-E5：全流程收口进单一 gate.WithAuthorized[CapTransfer]（鉴权前零 JournalStore 读取与零诊断发射），
// 非 DirectOperator 经 Round-2 规范化持久化目标路径，遇 UncertainCommit 上报 OutcomeUnknown 且严格 0 副作用，
// 对活跃句柄实施互斥准入（同代拒绝双活接管，StartNextGen=true 先原子释放旧句柄再登记 gen+1），审计后写失败自动回滚。
func (s *Service) ResumeTransfer(ctx context.Context, req ResumeTransferRequest) (TransferHandleInfo, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, err := s.validateBaseCall(ctx, req.CallBase)
	rs, hasRS := req.RemoteSource.Get()
	if err != nil || s.journals == nil || !req.TransferID.IsValid() || (hasRS && !rs.IsValid()) {
		return TransferHandleInfo{}, firstErr(err, pickIf[error](s.journals == nil, ErrJournalStoreUnavailable, fmt.Errorf("%w: TransferID 或 RemoteSource 无效", ErrInvalidRequest)))
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "transfer", action: "resume", paths: pickIf(hasRS, []pathalg.RemotePath{rs}, nil), params: map[string]string{"transfer_id": req.TransferID.String(), "start_next_gen": strconv.FormatBool(req.StartNextGen)}, defaultRisk: security.RiskModerate, summary: "transfer resume " + req.TransferID.String()}
	if s.enforceStrictPaths() {
		spec.customCanon = s.makeResumeCanonicalizer(spec, pickIf(req.NodeID != "", req.NodeID, hop.NodeID()), req.TransferID)
	}
	return s.runAuthorizedTransferRegister(ctx, spec, func(authCtx context.Context, auth gate.Authorized[security.CapTransfer], emitter *transferEmitter) (TransferHandleInfo, error) {
		return s.resumeAuthorizedTransfer(authCtx, auth, emitter, req)
	})
}
func (s *Service) makeResumeCanonicalizer(spec authOpSpec, nodeID string, transferID security.OperationID) gate.CanonicalizeFunc {
	return func(ctx context.Context) (gate.CanonicalizeResult, error) {
		rpaths, extra := slices.Clone(spec.paths), slices.Clone(spec.extraPaths)
		snaps, err := s.journals.LoadGenerations(ctx, transferID)
		if err != nil && !errors.Is(err, ports.ErrNotFound) {
			return gate.CanonicalizeResult{}, err
		}
		if dest, ok := extractLatestJournalDest(snaps); ok {
			rpaths, extra = collectDestPaths(dest, algebraic.None[pathalg.RemotePath](), rpaths, extra)
		}
		return s.canonicalizeRemoteTargets(ctx, security.CapabilityKindOf[security.CapTransfer](), spec, nodeID, rpaths, nil, extra)
	}
}
func extractLatestJournalDest(snaps []ports.JournalGenerationSnapshot) (fsm.TransferDest, bool) {
	for i := len(snaps) - 1; i >= 0; i-- {
		if recs := pickIf(snaps[i].Corrupt(), snaps[i].PartialRecords(), snaps[i].Records()); len(recs) > 0 && recs[0].IsValid() && recs[0].Kind() == fsm.JournalRecordInit {
			if d, ok := recs[0].Dest().Get(); ok && d.IsValid() {
				return d, true
			}
		}
	}
	return zeroVal[fsm.TransferDest](), false
}
func (s *Service) resumeAuthorizedTransfer(ctx context.Context, auth gate.Authorized[security.CapTransfer], emitter *transferEmitter, req ResumeTransferRequest) (TransferHandleInfo, error) {
	rec, err := s.recoverFromStore(ctx, req.TransferID, false)
	if errors.Is(err, ports.ErrNotFound) {
		return TransferHandleInfo{}, ErrTransferNotFound
	}
	if rec.UncertainCommit || errors.Is(err, ErrUncertainCommit) {
		reportUnknownOutcome(auth, "transfer_uncertain_commit", fmtErr(err))
		return TransferHandleInfo{}, pickIf[error](err != nil, err, ErrUncertainCommit)
	}
	if err != nil || rec.State == nil || !rec.State.IsValid() {
		return TransferHandleInfo{}, pickIf[error](err != nil, err, fsm.ErrInvalidState)
	}
	if rec.State.IsTerminal() {
		return TransferHandleInfo{}, fmt.Errorf("%w: 传输 %s 已处于终态 %s", fsm.ErrIllegalTransition, req.TransferID, rec.State.Kind())
	}
	meta := fsm.TransferMetaOf(rec.State)
	startReq := StartTransferRequest{CallBase: req.CallBase, TransferSessionOptions: req.TransferSessionOptions, TransferID: algebraic.Some(meta.TransferID()), Dest: meta.Dest(), TotalBytes: meta.TotalBytes(), ExpectedDigest: meta.ExpectedDigest(), JournalVersion: meta.JournalVersion(), Generation: pickIf(req.StartNextGen, meta.Generation()+1, meta.Generation())}
	renameSpec, e1 := s.validateStartDirectionFields(startReq)
	perm, e2 := resolvePerm(startReq.Perm, pickIf(meta.Direction() == fsm.TransferDirectionUpload, defaultRemoteFilePerm, defaultLocalStagePerm))
	if err = firstErr(e1, e2); err != nil {
		return TransferHandleInfo{}, err
	}
	oldHandle, live, hErr := s.lookupLiveHandle(ctx, req.TransferID)
	if hErr != nil || (live && !req.StartNextGen) {
		return TransferHandleInfo{}, pickIf[error](hErr != nil, hErr, fmt.Errorf("%w: 传输 %s 同世代句柄仍活跃，禁止双活接管", ports.ErrAlreadyExists, req.TransferID))
	}
	if live {
		s.dropActiveHandle(req.TransferID, oldHandle, true)
	}
	return s.registerStreamSession(ctx, auth.Binding(), emitter, startReq, perm, renameSpec, pickIf[fsm.TransferState](req.StartNextGen, nil, rec.State), req.StartNextGen)
}
func (s *Service) recoverFromStore(ctx context.Context, transferID security.OperationID, pruneSuperseded bool) (TransferRecoveryResult, error) {
	snaps, err := s.journals.LoadGenerations(ctx, transferID)
	if err != nil {
		return TransferRecoveryResult{TransferID: transferID}, err
	}
	res, pruneList, recErr := recoverFromGenerationSnapshots(transferID, snaps)
	if recErr == nil && !res.UncertainCommit && pruneSuperseded {
		for _, g := range pruneList {
			if pErr := s.journals.PruneGeneration(ctx, transferID, g); pErr != nil && !errors.Is(pErr, ports.ErrNotFound) {
				return res, pErr
			}
			res.PrunedGenerations = append(res.PrunedGenerations, g)
		}
	}
	s.emitRecoveryDiag(transferID, res, recErr)
	return res, recErr
}
func (s *Service) emitRecoveryDiag(id security.OperationID, res TransferRecoveryResult, err error) {
	attrs := map[string]string{"selected_gen": strconv.FormatUint(res.SelectedGen, 10), "uncertain": strconv.FormatBool(res.UncertainCommit)}
	if err == nil && res.State != nil && res.State.IsValid() {
		attrs["state"] = res.State.Kind().String()
	}
	s.emitDiagnostic(algebraic.Some(id), pickIf(err != nil, events.SeverityError, events.SeverityInfo), pickIf(err != nil, "transfer_recovery_blocked", "transfer_recovered"), pickIf(err != nil, fmtErr(err), "transfer journal recovered"), attrs)
}

// recoverFromGenerationSnapshots 是纯函数双代/多代恢复裁决核心，严格强制全部三条崩溃恢复铁律。
func recoverFromGenerationSnapshots(transferID security.OperationID, snaps []ports.JournalGenerationSnapshot) (TransferRecoveryResult, []uint64, error) {
	if err := validateSnapshotOrdering(snaps); err != nil {
		return TransferRecoveryResult{TransferID: transferID}, nil, err
	}
	// 铁律 2（最高优先）：任意损坏世代含提交标记或健康世代悬停于 CommitStarted -> TransferUncertainCommit 零副作用。
	if res, err, matched := detectAnyCommitUncertainty(transferID, snaps); matched {
		return res, nil, err
	}
	// 铁律 1 & 3：高世代损坏（含空前缀损坏）严禁回退低世代，Fail-Closed 返回 ErrCorruptJournal。
	highest := snaps[len(snaps)-1]
	if highest.Corrupt() {
		msg := pickIf(len(highest.PartialRecords()) == 0, "空前缀损坏", "损坏")
		return TransferRecoveryResult{TransferID: transferID, SelectedGen: highest.Generation()}, nil, fmt.Errorf("%w: 高世代 gen=%d %s，严禁回退低世代: %w", ErrCorruptJournal, highest.Generation(), msg, highest.Err())
	}
	return recoverHealthyHighestWithLowers(transferID, snaps[:len(snaps)-1], highest)
}
func validateSnapshotOrdering(snaps []ports.JournalGenerationSnapshot) error {
	var prevGen uint64
	for _, snap := range snaps {
		if !snap.IsValid() || snap.Generation() <= prevGen {
			return fmt.Errorf("%w: 世代快照无效或未严格升序", ErrCorruptJournal)
		}
		prevGen = snap.Generation()
	}
	return pickIf[error](len(snaps) == 0, fmt.Errorf("%w: 空世代快照列表", ErrCorruptJournal), nil)
}
func detectAnyCommitUncertainty(transferID security.OperationID, snaps []ports.JournalGenerationSnapshot) (TransferRecoveryResult, error, bool) {
	for i := len(snaps) - 1; i >= 0; i-- {
		snap := snaps[i]
		if snap.Corrupt() {
			if slices.ContainsFunc(snap.PartialRecords(), func(r fsm.TransferJournalRecord) bool {
				return r.IsValid() && (r.Kind() == fsm.JournalRecordCommitStarted || r.Kind() == fsm.JournalRecordCommitted)
			}) {
				return TransferRecoveryResult{TransferID: transferID, State: buildUncertainStateFromPartial(snap.PartialRecords()), SelectedGen: snap.Generation(), UncertainCommit: true},
					fmt.Errorf("%w: 损坏世代 gen=%d 前缀含提交标记，严禁重试或删日志: %w", ErrUncertainCommit, snap.Generation(), snap.Err()), true
			}
			continue
		}
		if st, _, _, _ := fsm.RecoverTransferFromJournal(snap.Records()); st != nil && st.Kind() == fsm.TransferKindUncertainCommit {
			return TransferRecoveryResult{TransferID: transferID, State: st, SelectedGen: snap.Generation(), UncertainCommit: true},
				fmt.Errorf("%w: 世代 gen=%d 处于 UncertainCommit，严禁重试或删日志", ErrUncertainCommit, snap.Generation()), true
		}
	}
	return TransferRecoveryResult{}, nil, false
}
func buildUncertainStateFromPartial(partial []fsm.TransferJournalRecord) fsm.TransferState {
	cut := len(partial)
	if idx := slices.IndexFunc(partial, func(r fsm.TransferJournalRecord) bool { return r.Kind() == fsm.JournalRecordCommitStarted }); idx >= 0 {
		cut = idx + 1
	}
	st, _, _, _ := fsm.RecoverTransferFromJournal(partial[:cut])
	return pickIf(st != nil && st.Kind() == fsm.TransferKindUncertainCommit, st, nil)
}
func recoverHealthyHighestWithLowers(transferID security.OperationID, lowers []ports.JournalGenerationSnapshot, highest ports.JournalGenerationSnapshot) (TransferRecoveryResult, []uint64, error) {
	hiRecs := highest.Records()
	hiSt, hiEffs, _, hiErr := fsm.RecoverTransferFromJournal(hiRecs)
	if hiErr != nil || !fsm.TransferMetaOf(hiSt).TransferID().Equal(transferID) {
		return TransferRecoveryResult{TransferID: transferID, SelectedGen: highest.Generation()}, nil, fmt.Errorf("%w: 高世代 gen=%d 无效，严禁回退低世代: %w", ErrCorruptJournal, highest.Generation(), hiErr)
	}
	pruneList := make([]uint64, 0, len(lowers))
	hiMeta := fsm.TransferMetaOf(hiSt)
	for _, lo := range lowers {
		if lo.Corrupt() {
			if err := verifyCorruptLowerIdentity(lo.PartialRecords(), hiMeta); err != nil {
				return TransferRecoveryResult{TransferID: transferID, SelectedGen: highest.Generation()}, nil, err
			}
		} else if _, _, _, dErr := fsm.RecoverTransferFromDualJournal(lo.Records(), hiRecs); dErr != nil {
			return TransferRecoveryResult{TransferID: transferID, SelectedGen: highest.Generation()}, nil, fmt.Errorf("%w: %w", ErrCorruptJournal, dErr)
		}
		pruneList = append(pruneList, lo.Generation())
	}
	return TransferRecoveryResult{TransferID: transferID, State: hiSt, SelectedGen: highest.Generation(), Effects: hiEffs}, pruneList, nil
}
func verifyCorruptLowerIdentity(partial []fsm.TransferJournalRecord, hiMeta fsm.TransferMeta) error {
	if len(partial) == 0 || !partial[0].IsValid() || partial[0].Kind() != fsm.JournalRecordInit {
		return nil
	}
	first := partial[0]
	dest, okD := first.Dest().Get()
	hiExp, okH := hiMeta.ExpectedDigest().Get()
	loExp, okL := first.Digest().Get()
	bad := !okD || !first.TransferID().Equal(hiMeta.TransferID()) || !dest.Equal(hiMeta.Dest()) || first.TotalBytes() != hiMeta.TotalBytes() || okH != okL || (okH && !hiExp.Equal(loExp))
	return pickIf[error](bad, fmt.Errorf("%w: 损坏低世代 gen=%d 元数据与高世代不一致", ErrCorruptJournal, first.Generation()), nil)
}
