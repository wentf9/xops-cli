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
//  2. 任意损坏世代 PartialRecords() 含 CommitStarted/Committed（或健康世代悬停于 CommitStarted）时，
//     必须停留 TransferUncertainCommit 且严格 0 副作用（禁重试、禁覆写、禁 PruneGeneration、禁 Delete）；
//  3. 空前缀高世代损坏必须 Fail-Closed 返回 ErrCorruptJournal 且严格 0 副作用。
func (s *Service) RecoverTransfer(ctx context.Context, req RecoverTransferRequest) (TransferRecoveryResult, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, err := s.validateBaseCall(ctx, req.CallBase)
	if err != nil {
		return TransferRecoveryResult{}, err
	}
	if lr, ok := req.LocalRootForClean.Get(); s.journals == nil || !req.TransferID.IsValid() || (ok && !lr.IsValid()) {
		return TransferRecoveryResult{}, pickIf[error](s.journals == nil, ErrJournalStoreUnavailable, fmt.Errorf("%w: TransferID 或 LocalRootForClean 无效", ErrInvalidRequest))
	}
	spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "transfer", action: "recover", params: map[string]string{"transfer_id": req.TransferID.String()}, defaultRisk: security.RiskSafe, summary: "transfer recover " + req.TransferID.String()}
	return runAuthorizedVal[security.CapTransfer](ctx, s, spec, func(authCtx context.Context, _ gate.Authorized[security.CapTransfer], _ *transferEmitter) (TransferRecoveryResult, error) {
		out, recErr := s.recoverFromStore(authCtx, req.TransferID, req.PruneSuperseded)
		if recErr == nil && out.State != nil && out.State.Kind() == fsm.TransferKindAborted {
			s.cleanupRecoveredLocalStaging(out.State, req.LocalRootForClean)
		}
		return out, recErr
	})
}

// RecoverAllTransfers 启动期扫描 JournalStore.ListActive 并逐条安全恢复（Gate Halted 态严格拒绝，单条异常不阻断扫描）。
func (s *Service) RecoverAllTransfers(ctx context.Context, req RecoverAllRequest) (RecoverAllResult, error) {
	if err := s.checkReadyCtx(ctx); err != nil {
		return RecoverAllResult{}, err
	}
	if s.gate.IsHalted() || s.journals == nil {
		return RecoverAllResult{}, pickIf[error](s.gate.IsHalted(), gate.ErrGateHalted, ErrJournalStoreUnavailable)
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

// ResumeTransfer 按三条崩溃恢复铁律恢复目标传输并将可继续任务挂载至受管池句柄；
// Halted 态立即拒绝，不存在任务经 Gate 过闸防存在性探测（INV-E5），UncertainCommit 或高世代损坏严禁续传（0 副作用）。
func (s *Service) ResumeTransfer(ctx context.Context, req ResumeTransferRequest) (TransferHandleInfo, error) {
	defer closeStreamIfNonNil(req.OperationStream)
	hop, err := s.validateBaseCall(ctx, req.CallBase)
	if err != nil {
		return TransferHandleInfo{}, err
	}
	if s.gate.IsHalted() || s.journals == nil || !req.TransferID.IsValid() {
		return TransferHandleInfo{}, pickIf[error](s.gate.IsHalted(), gate.ErrGateHalted, pickIf[error](s.journals == nil, ErrJournalStoreUnavailable, fmt.Errorf("%w: TransferID 无效", ErrInvalidRequest)))
	}
	rec, err := s.recoverFromStore(ctx, req.TransferID, false)
	if errors.Is(err, ports.ErrNotFound) {
		spec := authOpSpec{base: req.CallBase, targetHop: hop, tool: "transfer", action: "resume", params: map[string]string{"transfer_id": req.TransferID.String()}, defaultRisk: security.RiskModerate, summary: "transfer resume " + req.TransferID.String()}
		return runAuthorizedVal[security.CapTransfer](ctx, s, spec, func(context.Context, gate.Authorized[security.CapTransfer], *transferEmitter) (TransferHandleInfo, error) {
			return TransferHandleInfo{}, ErrTransferNotFound
		})
	}
	if err != nil || rec.UncertainCommit || rec.State == nil || !rec.State.IsValid() {
		return TransferHandleInfo{}, pickIf[error](err != nil, err, ErrUncertainCommit)
	}
	if rec.State.IsTerminal() {
		return TransferHandleInfo{}, fmt.Errorf("%w: 传输 %s 已处于终态 %s", fsm.ErrIllegalTransition, req.TransferID, rec.State.Kind())
	}
	meta := fsm.TransferMetaOf(rec.State)
	startReq := StartTransferRequest{
		CallBase: req.CallBase, TransferSessionOptions: req.TransferSessionOptions,
		TransferID: algebraic.Some(meta.TransferID()), Dest: meta.Dest(), TotalBytes: meta.TotalBytes(),
		ExpectedDigest: meta.ExpectedDigest(), JournalVersion: meta.JournalVersion(),
		Generation: pickIf(req.StartNextGen, meta.Generation()+1, meta.Generation()),
	}
	return s.startOrResumeTransfer(ctx, startReq, pickIf[fsm.TransferState](req.StartNextGen, nil, rec.State), req.StartNextGen)
}

func (s *Service) recoverFromStore(ctx context.Context, transferID security.OperationID, pruneSuperseded bool) (TransferRecoveryResult, error) {
	snaps, err := s.journals.LoadGenerations(ctx, transferID)
	if err != nil {
		return TransferRecoveryResult{TransferID: transferID}, err
	}
	res, pruneList, recErr := recoverFromGenerationSnapshots(transferID, snaps)
	if recErr != nil || res.UncertainCommit {
		s.emitRecoveryDiag(transferID, res, recErr)
		return res, recErr
	}
	if pruneSuperseded {
		for _, g := range pruneList {
			if pErr := s.journals.PruneGeneration(ctx, transferID, g); pErr != nil && !errors.Is(pErr, ports.ErrNotFound) {
				return res, pErr
			}
			res.PrunedGenerations = append(res.PrunedGenerations, g)
		}
	}
	s.emitRecoveryDiag(transferID, res, nil)
	return res, nil
}
func (s *Service) cleanupRecoveredLocalStaging(st fsm.TransferState, rootOpt algebraic.Option[pathalg.LocalDir]) {
	if meta := fsm.TransferMetaOf(st); meta.Direction() == fsm.TransferDirectionDownload {
		if _, localStageOpt, err := computeStreamStagePaths(meta); err == nil {
			s.removeLocalBestEffort(rootOpt, localStageOpt)
		}
	}
}
func (s *Service) emitRecoveryDiag(id security.OperationID, res TransferRecoveryResult, err error) {
	attrs := map[string]string{"selected_gen": strconv.FormatUint(res.SelectedGen, 10), "uncertain": strconv.FormatBool(res.UncertainCommit)}
	if err != nil {
		s.emitDiagnostic(algebraic.Some(id), events.SeverityError, "transfer_recovery_blocked", err.Error(), attrs)
		return
	}
	if res.State != nil && res.State.IsValid() {
		attrs["state"] = res.State.Kind().String()
	}
	s.emitDiagnostic(algebraic.Some(id), events.SeverityInfo, "transfer_recovered", "transfer journal recovered", attrs)
}

// recoverFromGenerationSnapshots 是纯函数双代/多代恢复裁决核心，严格强制全部三条崩溃恢复铁律。
func recoverFromGenerationSnapshots(transferID security.OperationID, snaps []ports.JournalGenerationSnapshot) (TransferRecoveryResult, []uint64, error) {
	if err := validateSnapshotOrdering(snaps); err != nil {
		return TransferRecoveryResult{TransferID: transferID}, nil, err
	}
	// 铁律 2（最高优先）：任意损坏世代 PartialRecords() 含 CommitStarted 或 Committed -> TransferUncertainCommit 零副作用。
	if res, err, matched := detectCorruptCommitMarker(transferID, snaps); matched {
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
	if len(snaps) == 0 {
		return fmt.Errorf("%w: 空世代快照列表", ErrCorruptJournal)
	}
	var prevGen uint64
	for _, snap := range snaps {
		if !snap.IsValid() || snap.Generation() <= prevGen {
			return fmt.Errorf("%w: 世代快照无效或未严格升序", ErrCorruptJournal)
		}
		prevGen = snap.Generation()
	}
	return nil
}
func detectCorruptCommitMarker(transferID security.OperationID, snaps []ports.JournalGenerationSnapshot) (TransferRecoveryResult, error, bool) {
	for i := len(snaps) - 1; i >= 0; i-- {
		snap := snaps[i]
		if !snap.Corrupt() || !slices.ContainsFunc(snap.PartialRecords(), func(r fsm.TransferJournalRecord) bool {
			return r.IsValid() && (r.Kind() == fsm.JournalRecordCommitStarted || r.Kind() == fsm.JournalRecordCommitted)
		}) {
			continue
		}
		return TransferRecoveryResult{TransferID: transferID, State: buildUncertainStateFromPartial(snap.PartialRecords()), SelectedGen: snap.Generation(), UncertainCommit: true},
			fmt.Errorf("%w: 损坏世代 gen=%d 前缀含提交标记，严禁重试或删日志: %w", ErrUncertainCommit, snap.Generation(), snap.Err()), true
	}
	return TransferRecoveryResult{}, nil, false
}
func buildUncertainStateFromPartial(partial []fsm.TransferJournalRecord) fsm.TransferState {
	for i, r := range partial {
		if r.Kind() == fsm.JournalRecordCommitStarted {
			st, _, _, _ := fsm.RecoverTransferFromJournal(partial[:i+1])
			return pickIf(st != nil && st.Kind() == fsm.TransferKindUncertainCommit, st, nil)
		}
	}
	st, _, _, _ := fsm.RecoverTransferFromJournal(partial)
	return pickIf(st != nil && st.Kind() == fsm.TransferKindUncertainCommit, st, nil)
}
func recoverHealthyHighestWithLowers(transferID security.OperationID, lowers []ports.JournalGenerationSnapshot, highest ports.JournalGenerationSnapshot) (TransferRecoveryResult, []uint64, error) {
	hiRecs := highest.Records()
	hiSt, hiEffs, _, hiErr := fsm.RecoverTransferFromJournal(hiRecs)
	if hiSt != nil && hiSt.Kind() == fsm.TransferKindUncertainCommit {
		return TransferRecoveryResult{TransferID: transferID, State: hiSt, SelectedGen: highest.Generation(), UncertainCommit: true}, nil, fmt.Errorf("%w: gen=%d 处于 UncertainCommit", ErrUncertainCommit, highest.Generation())
	}
	if hiErr != nil || !fsm.TransferMetaOf(hiSt).TransferID().Equal(transferID) {
		return TransferRecoveryResult{TransferID: transferID, SelectedGen: highest.Generation()}, nil, fmt.Errorf("%w: 高世代 gen=%d 无效，严禁回退低世代: %w", ErrCorruptJournal, highest.Generation(), hiErr)
	}
	pruneList, uncRes, err := validateLowerGenerationsAgainstHigh(transferID, lowers, hiRecs, fsm.TransferMetaOf(hiSt), highest.Generation())
	if err != nil {
		return uncRes, nil, err
	}
	return TransferRecoveryResult{TransferID: transferID, State: hiSt, SelectedGen: highest.Generation(), Effects: hiEffs}, pruneList, nil
}
func validateLowerGenerationsAgainstHigh(transferID security.OperationID, lowers []ports.JournalGenerationSnapshot, hiRecs []fsm.TransferJournalRecord, hiMeta fsm.TransferMeta, hiGen uint64) ([]uint64, TransferRecoveryResult, error) {
	pruneList := make([]uint64, 0, len(lowers))
	for _, lo := range lowers {
		if lo.Corrupt() {
			if err := verifyCorruptLowerIdentity(lo.PartialRecords(), hiMeta); err != nil {
				return nil, TransferRecoveryResult{TransferID: transferID, SelectedGen: hiGen}, err
			}
			pruneList = append(pruneList, lo.Generation())
			continue
		}
		st, _, _, err := fsm.RecoverTransferFromDualJournal(lo.Records(), hiRecs)
		if st != nil && st.Kind() == fsm.TransferKindUncertainCommit {
			return nil, TransferRecoveryResult{TransferID: transferID, State: st, SelectedGen: lo.Generation(), UncertainCommit: true}, fmt.Errorf("%w: 低世代 gen=%d 处于 UncertainCommit", ErrUncertainCommit, lo.Generation())
		}
		if err != nil {
			return nil, TransferRecoveryResult{TransferID: transferID, SelectedGen: hiGen}, fmt.Errorf("%w: %w", ErrCorruptJournal, err)
		}
		pruneList = append(pruneList, lo.Generation())
	}
	return pruneList, TransferRecoveryResult{}, nil
}
func verifyCorruptLowerIdentity(partial []fsm.TransferJournalRecord, hiMeta fsm.TransferMeta) error {
	if len(partial) == 0 || !partial[0].IsValid() || partial[0].Kind() != fsm.JournalRecordInit {
		return nil
	}
	first := partial[0]
	dest, okD := first.Dest().Get()
	hiExp, okH := hiMeta.ExpectedDigest().Get()
	loExp, okL := first.Digest().Get()
	if !okD || !first.TransferID().Equal(hiMeta.TransferID()) || !dest.Equal(hiMeta.Dest()) || first.TotalBytes() != hiMeta.TotalBytes() || okH != okL || (okH && !hiExp.Equal(loExp)) {
		return fmt.Errorf("%w: 损坏低世代 gen=%d 元数据与高世代不一致", ErrCorruptJournal, first.Generation())
	}
	return nil
}
