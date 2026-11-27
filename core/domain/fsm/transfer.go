package fsm

import (
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// NewTransferState 校验传输元数据并构造 TransferFSM 初始状态 *TransferInitialized。
func NewTransferState(meta TransferMeta) (*TransferInitialized, error) {
	if !meta.IsValid() {
		return nil, ErrInvalidContext
	}
	return &TransferInitialized{tMix(meta, TransferKindInitialized, "")}, nil
}

// TransferInput 的显式校验构造器集（零值输入恒无效）。
func TransferInputStart() TransferInput { return TransferInput{kind: transferInStart, valid: true} }
func TransferInputChunk(offset, length uint64, chunkDigest security.Digest) (TransferInput, error) {
	if length == 0 || length > MaxTransferChunkBytes {
		return TransferInput{}, domi18n.EF(ErrInvalidChunkOffset, domi18n.KeyCommonFieldRange, domi18n.Str("field", "chunk_length"), domi18n.Uint64("value", length), domi18n.Int("min", 1), domi18n.Uint64("max", MaxTransferChunkBytes))
	}
	if !chunkDigest.IsValid() {
		return TransferInput{}, domi18n.EF(ErrInvalidInput, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "chunk_digest"))
	}
	return TransferInput{kind: transferInChunk, offset: offset, length: length, digest: chunkDigest, valid: true}, nil
}
func TransferInputVerifyResult(ok bool, actualDigest security.Digest, reason string) (TransferInput, error) {
	if ok && !actualDigest.IsValid() {
		return TransferInput{}, domi18n.EF(ErrInvalidInput, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "actual_digest"))
	}
	return TransferInput{kind: transferInVerifyResult, ok: ok, digest: actualDigest, reason: sanitizeReason(reason), valid: true}, nil
}
func TransferInputCommitResult(durability DurabilityStatus, reason string) (TransferInput, error) {
	if !durability.IsValid() {
		return TransferInput{}, domi18n.WrapSentinel(ErrInvalidInput, ErrInvalidDurability)
	}
	return TransferInput{kind: transferInCommitResult, durability: durability, reason: sanitizeReason(reason), valid: true}, nil
}
func TransferInputAbort(reason string) TransferInput {
	return TransferInput{kind: transferInAbort, reason: sanitizeReason(reason), valid: true}
}

// TransitionTransfer 执行 TransferFSM 纯 Mealy 状态转移：
//   - 严格守卫 10 GiB 总上限与单调连续分片偏移；
//   - 自动产出双版本（V1/V2）自校验 Journal 记录副作用；
//   - 原子交接遇 Applied && !Durable 或 OutcomeUnknown 立即进入 *TransferUncertainCommit（零重试零删目标）。
func TransitionTransfer(state TransferState, input TransferInput) (TransferState, []TransferEffect, []TransferEvent, error) {
	if state == nil || !state.IsValid() {
		return state, nil, nil, ErrInvalidState
	}
	if !input.IsValid() {
		return state, nil, nil, ErrInvalidInput
	}
	switch s := state.(type) {
	case *TransferInitialized:
		return stepTransferInitialized(s, input)
	case *TransferStreaming:
		return stepTransferStreaming(s, input)
	case *TransferVerifying:
		return stepTransferVerifying(s, input)
	case *TransferCommitting:
		return stepTransferCommitting(s, input)
	case *TransferCommitted, *TransferAborted, *TransferUncertainCommit:
		return state, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMTerminalState, domi18n.Str("state", s.Kind().String()))
	default:
		return state, nil, nil, ErrInvalidState
	}
}

func stepTransferInitialized(s *TransferInitialized, in TransferInput) (TransferState, []TransferEffect, []TransferEvent, error) {
	switch in.kind {
	case transferInStart:
		initRec, err := NewTransferJournalRecord(TransferJournalRecordSpec{s.meta.journalVersion, s.meta.generation, 1, JournalRecordInit, s.meta.transferID, algebraic.Some(s.meta.dest), 0, 0, s.meta.totalBytes, s.meta.expectedDigest, algebraic.None[security.Digest]()})
		if err != nil {
			return s, nil, nil, err
		}
		if s.meta.totalBytes == 0 {
			return &TransferVerifying{tProg(s.meta, TransferKindVerifying, 0, 0, 2, initRec.recordDigest)}, []TransferEffect{journalEffect(initRec), simpleTransferEffect(TransferEffectVerifyFullDigest)}, []TransferEvent{transferEvent(TransferEventStarted, 0, "empty_stream_verifying")}, nil
		}
		return &TransferStreaming{tProg(s.meta, TransferKindStreaming, 0, 0, 2, initRec.recordDigest)}, []TransferEffect{journalEffect(initRec)}, []TransferEvent{transferEvent(TransferEventStarted, 0, "streaming")}, nil
	case transferInAbort:
		return &TransferAborted{tMix(s.meta, TransferKindAborted, in.reason)}, []TransferEffect{simpleTransferEffect(TransferEffectCleanupStaging)}, []TransferEvent{transferEvent(TransferEventAborted, 0, in.reason)}, nil
	default:
		return s, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMExpectedInput, domi18n.Str("state", s.Kind().String()), domi18n.Str("expected", "Start/Abort"))
	}
}
func stepTransferStreaming(s *TransferStreaming, in TransferInput) (TransferState, []TransferEffect, []TransferEvent, error) {
	switch in.kind {
	case transferInChunk:
		return acceptTransferChunk(s, in)
	case transferInAbort:
		return abortTransferWithJournal(s, s.meta, s.offset, s.nextSeq, s.lastDigest, in.reason)
	default:
		return s, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMExpectedInput, domi18n.Str("state", s.Kind().String()), domi18n.Str("expected", "Chunk/Abort"))
	}
}
func acceptTransferChunk(s *TransferStreaming, in TransferInput) (TransferState, []TransferEffect, []TransferEvent, error) {
	if in.offset != s.offset {
		return s, nil, nil, domi18n.EF(ErrInvalidChunkOffset, domi18n.KeyCommonMismatch, domi18n.Str("field", "offset"), domi18n.Uint64("expected", s.offset), domi18n.Uint64("actual", in.offset))
	}
	if in.length > s.meta.totalBytes-s.offset {
		return s, nil, nil, domi18n.EF(ErrTransferSizeExceeded, domi18n.KeyFSMChunkRemainingExceeded, domi18n.Uint64("length", in.length), domi18n.Uint64("remaining", s.meta.totalBytes-s.offset))
	}
	rec, err := buildFollowRecord(s.meta, s.nextSeq, s.lastDigest, JournalRecordChunk, in.offset, in.length, algebraic.Some(in.digest))
	if err != nil {
		return s, nil, nil, err
	}
	nextOffset := s.offset + in.length
	if nextOffset == s.meta.totalBytes {
		return &TransferVerifying{tProg(s.meta, TransferKindVerifying, nextOffset, s.chunkCount+1, s.nextSeq+1, rec.recordDigest)}, []TransferEffect{journalEffect(rec), simpleTransferEffect(TransferEffectVerifyFullDigest)}, []TransferEvent{transferEvent(TransferEventChunkAccepted, nextOffset, "final_chunk"), transferEvent(TransferEventStreamCompleted, nextOffset, "verifying")}, nil
	}
	return &TransferStreaming{tProg(s.meta, TransferKindStreaming, nextOffset, s.chunkCount+1, s.nextSeq+1, rec.recordDigest)}, []TransferEffect{journalEffect(rec)}, []TransferEvent{transferEvent(TransferEventChunkAccepted, nextOffset, "chunk_ok")}, nil
}
func stepTransferVerifying(s *TransferVerifying, in TransferInput) (TransferState, []TransferEffect, []TransferEvent, error) {
	switch in.kind {
	case transferInVerifyResult:
		exp, hasExp := s.meta.expectedDigest.Get()
		if !in.ok || (hasExp && !exp.Equal(in.digest)) {
			return abortTransferWithJournal(s, s.meta, s.meta.totalBytes, s.nextSeq, s.lastDigest, pickIf(in.reason != "", in.reason, "full stream digest mismatch"))
		}
		verRec, err := buildFollowRecord(s.meta, s.nextSeq, s.lastDigest, JournalRecordVerified, 0, 0, algebraic.Some(in.digest))
		if err != nil {
			return s, nil, nil, err
		}
		commitRec, err := buildFollowRecord(s.meta, s.nextSeq+1, verRec.recordDigest, JournalRecordCommitStarted, 0, 0, algebraic.None[security.Digest]())
		if err != nil {
			return s, nil, nil, err
		}
		return &TransferCommitting{tProg(s.meta, TransferKindCommitting, s.meta.totalBytes, s.chunkCount, s.nextSeq+2, commitRec.recordDigest)}, []TransferEffect{journalEffect(verRec), journalEffect(commitRec), simpleTransferEffect(TransferEffectAtomicCommit)}, []TransferEvent{transferEvent(TransferEventDigestVerified, s.meta.totalBytes, in.digest.String()), transferEvent(TransferEventCommitStarted, s.meta.totalBytes, s.meta.dest.String())}, nil
	case transferInAbort:
		return abortTransferWithJournal(s, s.meta, s.meta.totalBytes, s.nextSeq, s.lastDigest, in.reason)
	default:
		return s, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMExpectedInput, domi18n.Str("state", s.Kind().String()), domi18n.Str("expected", "VerifyResult/Abort"))
	}
}
func stepTransferCommitting(s *TransferCommitting, in TransferInput) (TransferState, []TransferEffect, []TransferEvent, error) {
	if in.kind != transferInCommitResult {
		return s, nil, nil, domi18n.EF(ErrIllegalTransition, domi18n.KeyFSMExpectedInput, domi18n.Str("state", s.Kind().String()), domi18n.Str("expected", "CommitResult"))
	}
	switch in.durability {
	case DurabilityCommitted:
		rec, err := buildFollowRecord(s.meta, s.nextSeq, s.lastDigest, JournalRecordCommitted, 0, 0, algebraic.None[security.Digest]())
		if err != nil {
			return s, nil, nil, err
		}
		return &TransferCommitted{tMix(s.meta, TransferKindCommitted, "")}, []TransferEffect{journalEffect(rec)}, []TransferEvent{transferEvent(TransferEventCommitted, s.meta.totalBytes, s.meta.dest.String())}, nil
	case DurabilityNotApplied:
		return abortTransferWithJournal(s, s.meta, s.meta.totalBytes, s.nextSeq, s.lastDigest, pickIf(in.reason != "", in.reason, "commit_not_applied"))
	case DurabilityAppliedNotDurable, DurabilityOutcomeUnknown:
		// 原子提交处于 Applied && !Durable 或结果未知：严禁重试与删除，停机于 TransferUncertainCommit。
		reason := pickIf(in.reason != "", in.reason, in.durability.String())
		return &TransferUncertainCommit{tMix(s.meta, TransferKindUncertainCommit, reason)}, nil, []TransferEvent{transferEvent(TransferEventUncertainCommit, s.meta.totalBytes, reason)}, nil
	default:
		return s, nil, nil, ErrInvalidDurability
	}
}
func buildFollowRecord(m TransferMeta, seq uint64, lastDigest security.Digest, kind JournalRecordKind, offset, length uint64, dig algebraic.Option[security.Digest]) (TransferJournalRecord, error) {
	prev := pickIf(m.journalVersion == JournalVersionV2, algebraic.Some(lastDigest), algebraic.None[security.Digest]())
	return NewTransferJournalRecord(TransferJournalRecordSpec{m.journalVersion, m.generation, seq, kind, m.transferID, algebraic.None[TransferDest](), offset, length, m.totalBytes, dig, prev})
}
func abortTransferWithJournal(cur TransferState, meta TransferMeta, offset, nextSeq uint64, lastDigest security.Digest, reason string) (TransferState, []TransferEffect, []TransferEvent, error) {
	rec, err := buildFollowRecord(meta, nextSeq, lastDigest, JournalRecordAborted, 0, 0, algebraic.None[security.Digest]())
	if err != nil {
		return cur, nil, nil, err
	}
	clean := sanitizeReason(reason)
	return &TransferAborted{tMix(meta, TransferKindAborted, clean)}, []TransferEffect{journalEffect(rec), simpleTransferEffect(TransferEffectCleanupStaging)}, []TransferEvent{transferEvent(TransferEventAborted, offset, clean)}, nil
}

// RecoverTransferFromDualJournal 执行双代（active/staging）Journal 崩溃恢复：
//   - 双侧首条元数据均可解析时强制校验 (transferID, dest, totalBytes, expectedDigest) 一致且世代号严格互异；
//   - 任一代进入 TransferUncertainCommit 时最高优先停机返回（0 副作用）；
//   - 严禁低世代 Committed vs 高世代未提交脑裂，严禁从损坏的高世代回退至更低世代。
func RecoverTransferFromDualJournal(active, staging []TransferJournalRecord) (TransferState, []TransferEffect, []TransferEvent, error) {
	if len(active) == 0 || len(staging) == 0 {
		return RecoverTransferFromJournal(pickIf(len(active) > 0, active, staging))
	}
	mA, _, errHeadA := parseJournalInitMeta(active)
	mS, _, errHeadS := parseJournalInitMeta(staging)
	if errHeadA == nil && errHeadS == nil && (!sameTransferIdentity(mA, mS) || mA.generation == mS.generation) {
		return nil, nil, nil, domi18n.EF(ErrCorruptJournal, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "dual_journal_meta"))
	}
	stA, effA, evA, errA := RecoverTransferFromJournal(active)
	stS, effS, evS, errS := RecoverTransferFromJournal(staging)
	if stA != nil && stA.Kind() == TransferKindUncertainCommit {
		return stA, effA, evA, errA
	}
	if stS != nil && stS.Kind() == TransferKindUncertainCommit {
		return stS, effS, evS, errS
	}
	if errA == nil && errS == nil {
		return selectBothValidDualJournal(mA, stA, effA, evA, mS, stS, effS, evS)
	}
	return selectSingleValidDualJournal(errHeadA == nil, mA, stA, effA, evA, errA, mS, stS, effS, evS, errS)
}

func sameTransferIdentity(a, b TransferMeta) bool {
	return a.IsValid() && b.IsValid() && a.transferID.Equal(b.transferID) && a.dest.Equal(b.dest) &&
		a.totalBytes == b.totalBytes && equalOptionFunc(a.expectedDigest, b.expectedDigest, security.Digest.Equal)
}
func selectBothValidDualJournal(mA TransferMeta, stA TransferState, effA []TransferEffect, evA []TransferEvent, mS TransferMeta, stS TransferState, effS []TransferEffect, evS []TransferEvent) (TransferState, []TransferEffect, []TransferEvent, error) {
	loSt, hiSt, hiEff, hiEv := stA, stS, effS, evS
	if mA.generation > mS.generation {
		loSt, hiSt, hiEff, hiEv = stS, stA, effA, evA
	}
	if loSt.Kind() == TransferKindCommitted && hiSt.Kind() != TransferKindCommitted {
		return nil, nil, nil, domi18n.EF(ErrCorruptJournal, domi18n.KeyFSMJournalSplitBrain)
	}
	return hiSt, hiEff, hiEv, nil
}
func selectSingleValidDualJournal(hasHeadA bool, mA TransferMeta, stA TransferState, effA []TransferEffect, evA []TransferEvent, errA error, mS TransferMeta, stS TransferState, effS []TransferEffect, evS []TransferEvent, errS error) (TransferState, []TransferEffect, []TransferEvent, error) {
	if errA == nil {
		return stA, effA, evA, nil
	}
	if errS != nil {
		return nil, nil, nil, domi18n.WrapS(ErrCorruptJournal, errA, domi18n.KeyFSMJournalBothCorrupt)
	}
	if !hasHeadA || mS.generation <= mA.generation {
		return nil, nil, nil, domi18n.WrapS(ErrCorruptJournal, errA, domi18n.KeyFSMJournalRollbackForbidden)
	}
	return stS, effS, evS, nil
}
func journalEffect(r TransferJournalRecord) TransferEffect {
	return TransferEffect{TransferEffectWriteJournal, algebraic.Some(r), true}
}
func simpleTransferEffect(k TransferEffectKind) TransferEffect {
	return TransferEffect{kind: k, valid: true}
}
func transferEvent(k TransferEventKind, off uint64, d string) TransferEvent {
	return TransferEvent{k, off, sanitizeReason(d), true}
}
