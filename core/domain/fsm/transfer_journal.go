package fsm

import (
	"fmt"
	"io"
	"slices"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const transferJournalDomainTag = "xops.fsm.transfer_journal_record.v2"

// TransferJournalRecordSpec 与 TransferJournalRecord 表示双版本（V1/V2）双代自校验传输 Journal 记录：
// 经 //xops:canonicalhash 由 digestcover 校验全字段覆盖；V2 在 seq>1 时以 prevDigest 串联前驱哈希。
type (
	TransferJournalRecordSpec struct {
		Version    JournalVersion
		Generation uint64
		Seq        uint64
		Kind       JournalRecordKind
		TransferID security.OperationID
		Dest       algebraic.Option[TransferDest]
		Offset     uint64
		Length     uint64
		TotalBytes uint64
		Digest     algebraic.Option[security.Digest]
		PrevDigest algebraic.Option[security.Digest]
	}
	//xops:opaque
	//xops:failclosed
	//xops:canonicalhash
	TransferJournalRecord struct {
		version      JournalVersion
		generation   uint64
		seq          uint64
		kind         JournalRecordKind
		transferID   security.OperationID
		dest         algebraic.Option[TransferDest]
		offset       uint64
		length       uint64
		totalBytes   uint64
		digest       algebraic.Option[security.Digest]
		prevDigest   algebraic.Option[security.Digest]
		recordDigest security.Digest //xops:hash-exclude:由 WriteCanonical 派生的自校验记录摘要
		valid        bool
	}
)

// NewTransferJournalRecord 校验全部字段不变量并计算自校验摘要，构造 TransferJournalRecord。
func NewTransferJournalRecord(spec TransferJournalRecordSpec) (TransferJournalRecord, error) {
	if err := validateJournalRecordSpec(spec); err != nil {
		return TransferJournalRecord{}, err
	}
	rec := TransferJournalRecord{
		spec.Version, spec.Generation, spec.Seq, spec.Kind, spec.TransferID,
		spec.Dest, spec.Offset, spec.Length, spec.TotalBytes, spec.Digest, spec.PrevDigest, zeroVal[security.Digest](), true,
	}
	dig, err := digestCanonical(rec.WriteCanonical)
	if err != nil {
		return TransferJournalRecord{}, fmt.Errorf("%w: %w", ErrInvalidJournal, err)
	}
	rec.recordDigest = dig
	return rec, nil
}

func validateJournalRecordSpec(s TransferJournalRecordSpec) error {
	if !s.Version.IsValid() || s.Generation == 0 || s.Seq == 0 || !s.Kind.IsValid() || !s.TransferID.IsValid() {
		return fmt.Errorf("%w: version/generation/seq/kind/transfer_id 均须有效", ErrInvalidJournal)
	}
	if s.TotalBytes > MaxTransferBytes {
		return fmt.Errorf("%w: total_bytes=%d 超出 10 GiB 上限", ErrTransferSizeExceeded, s.TotalBytes)
	}
	p, hasPrev := s.PrevDigest.Get()
	if (hasPrev && !p.IsValid()) || (s.Version == JournalVersionV1 && hasPrev) || (s.Version == JournalVersionV2 && (s.Seq == 1) == hasPrev) {
		return fmt.Errorf("%w: prev_digest 与 Journal 版本/序号规则冲突", ErrInvalidJournal)
	}
	return validateJournalKindFields(s)
}
func validChunkSpan(s TransferJournalRecordSpec) bool {
	return s.Length > 0 && s.Length <= MaxTransferChunkBytes && s.Offset <= s.TotalBytes && s.Length <= s.TotalBytes-s.Offset
}
func validateJournalKindFields(s TransferJournalRecordSpec) error {
	dest, hasDest := s.Dest.Get()
	dig, hasDig := s.Digest.Get()
	if (hasDest && !dest.IsValid()) || (hasDig && !dig.IsValid()) {
		return fmt.Errorf("%w: dest 或 digest 零值无效", ErrInvalidJournal)
	}
	zeroSpan := s.Offset == 0 && s.Length == 0
	var ok bool
	switch s.Kind {
	case JournalRecordInit:
		ok = s.Seq == 1 && hasDest && zeroSpan
	case JournalRecordChunk:
		ok = s.Seq >= 2 && !hasDest && hasDig && validChunkSpan(s)
	case JournalRecordVerified:
		ok = s.Seq >= 2 && !hasDest && hasDig && zeroSpan
	case JournalRecordCommitStarted, JournalRecordCommitted, JournalRecordAborted:
		ok = s.Seq >= 2 && !hasDest && !hasDig && zeroSpan
	}
	if !ok {
		return fmt.Errorf("%w: %s 记录字段组合非法", ErrInvalidJournal, s.Kind)
	}
	return nil
}

func (r TransferJournalRecord) IsValid() bool {
	return r.valid && r.version.IsValid() && r.generation > 0 && r.seq > 0 && r.kind.IsValid() &&
		r.transferID.IsValid() && r.recordDigest.IsValid() && r.totalBytes <= MaxTransferBytes
}
func (r TransferJournalRecord) Version() JournalVersion                       { return r.version }
func (r TransferJournalRecord) Generation() uint64                            { return r.generation }
func (r TransferJournalRecord) Seq() uint64                                   { return r.seq }
func (r TransferJournalRecord) Kind() JournalRecordKind                       { return r.kind }
func (r TransferJournalRecord) TransferID() security.OperationID              { return r.transferID }
func (r TransferJournalRecord) Dest() algebraic.Option[TransferDest]          { return r.dest }
func (r TransferJournalRecord) Offset() uint64                                { return r.offset }
func (r TransferJournalRecord) Length() uint64                                { return r.length }
func (r TransferJournalRecord) TotalBytes() uint64                            { return r.totalBytes }
func (r TransferJournalRecord) Digest() algebraic.Option[security.Digest]     { return r.digest }
func (r TransferJournalRecord) PrevDigest() algebraic.Option[security.Digest] { return r.prevDigest }
func (r TransferJournalRecord) RecordDigest() security.Digest                 { return r.recordDigest }
func (r TransferJournalRecord) Equal(o TransferJournalRecord) bool {
	return r.IsValid() && o.IsValid() && r.version == o.version && r.generation == o.generation && r.seq == o.seq &&
		r.kind == o.kind && r.transferID.Equal(o.transferID) && r.recordDigest.Equal(o.recordDigest) &&
		r.offset == o.offset && r.length == o.length && r.totalBytes == o.totalBytes &&
		equalOptionFunc(r.dest, o.dest, TransferDest.Equal) && equalOptionFunc(r.digest, o.digest, security.Digest.Equal) &&
		equalOptionFunc(r.prevDigest, o.prevDigest, security.Digest.Equal)
}

// WriteCanonical 以零反射长度前缀方式写入 Journal 记录全部语义字段（含方向感知 TransferDest，受 digestcover 校验）。
func (r TransferJournalRecord) WriteCanonical(w io.Writer) error {
	if w == nil {
		return ErrNilWriter
	}
	if !r.valid || !r.version.IsValid() || r.generation == 0 || r.seq == 0 || !r.kind.IsValid() || !r.transferID.IsValid() {
		return ErrInvalidJournal
	}
	enc := &canonicalEncoder{w: w}
	enc.writeString(transferJournalDomainTag)
	enc.writeUint8(uint8(r.version))
	enc.writeUint64(r.generation)
	enc.writeUint64(r.seq)
	enc.writeUint8(uint8(r.kind))
	enc.writeString(r.transferID.String())
	d, hasD := r.dest.Get()
	enc.writeUint8(pickIf[uint8](hasD, 1, 0))
	if hasD {
		d.writeCanonical(enc)
	}
	enc.writeUint64(r.offset)
	enc.writeUint64(r.length)
	enc.writeUint64(r.totalBytes)
	writeOptDigest(enc, r.digest)
	writeOptDigest(enc, r.prevDigest)
	return enc.err
}
func writeOptDigest(enc *canonicalEncoder, opt algebraic.Option[security.Digest]) {
	d, ok := opt.Get()
	enc.writeUint8(pickIf[uint8](ok, 1, 0))
	if ok {
		if sum, valid := d.Bytes(); valid {
			enc.writeBytes(sum[:])
		} else {
			enc.err = ErrInvalidJournal
		}
	}
}

type recoveryAcc struct {
	meta           TransferMeta
	offset, chunks uint64
	lastSeq        uint64
	lastDigest     security.Digest
	verifiedDigest algebraic.Option[security.Digest]
	phase          JournalRecordKind
	commitSeen     bool
}

// RecoverTransferFromJournal 根据双版本（V1/V2）Journal 执行纯确定性崩溃恢复：
// 校验连续序号、V2 哈希链、单调偏移与 10 GiB 上限；支持重启后幂等复验（Verified -> Verified）及
// 明确回滚（CommitStarted -> Aborted）；CommitStarted 后崩溃或任意提交标记后损坏一律进入 *TransferUncertainCommit。
func RecoverTransferFromJournal(records []TransferJournalRecord) (TransferState, []TransferEffect, []TransferEvent, error) {
	meta, first, err := parseJournalInitMeta(records)
	if err != nil {
		return nil, nil, nil, err
	}
	acc := recoveryAcc{meta: meta, lastSeq: 1, lastDigest: first.recordDigest, phase: JournalRecordInit}
	for i := 1; i < len(records); i++ {
		if err := applyRecoveryRecord(&acc, records[i]); err != nil {
			acc.commitSeen = acc.commitSeen || hasCommitMarkerInTail(records[i:], acc.meta)
			return failClosedRecovery(acc, err)
		}
	}
	return finalizeRecoveryAcc(acc)
}
func parseJournalInitMeta(records []TransferJournalRecord) (TransferMeta, TransferJournalRecord, error) {
	if len(records) == 0 || len(records) > MaxJournalRecords {
		return TransferMeta{}, TransferJournalRecord{}, fmt.Errorf("%w: Journal 记录数 %d 非法", ErrCorruptJournal, len(records))
	}
	first := records[0]
	dest, okD := first.dest.Get()
	if !first.IsValid() || first.kind != JournalRecordInit || first.seq != 1 || !okD {
		return TransferMeta{}, TransferJournalRecord{}, fmt.Errorf("%w: 首条记录必须为有效的 seq=1 init 记录", ErrCorruptJournal)
	}
	meta, err := NewTransferMeta(TransferMetaSpec{first.transferID, dest, first.totalBytes, first.digest, first.version, first.generation})
	if err != nil {
		return TransferMeta{}, TransferJournalRecord{}, fmt.Errorf("%w: %w", ErrCorruptJournal, err)
	}
	return meta, first, nil
}
func hasCommitMarkerInTail(tail []TransferJournalRecord, meta TransferMeta) bool {
	return slices.ContainsFunc(tail, func(rec TransferJournalRecord) bool {
		return rec.IsValid() && rec.transferID.Equal(meta.transferID) && rec.generation == meta.generation &&
			(rec.kind == JournalRecordCommitStarted || rec.kind == JournalRecordCommitted)
	})
}
func applyRecoveryRecord(acc *recoveryAcc, rec TransferJournalRecord) error {
	if !rec.IsValid() || !rec.transferID.Equal(acc.meta.transferID) || rec.version != acc.meta.journalVersion ||
		rec.generation != acc.meta.generation || rec.totalBytes != acc.meta.totalBytes || rec.seq != acc.lastSeq+1 {
		return fmt.Errorf("%w: 记录归属、版本、世代、总大小或序号不连续", ErrCorruptJournal)
	}
	if prev, ok := rec.prevDigest.Get(); acc.meta.journalVersion == JournalVersionV2 && (!ok || !prev.Equal(acc.lastDigest)) {
		return fmt.Errorf("%w: V2 Journal 哈希链断裂", ErrCorruptJournal)
	}
	if err := advanceRecoveryPhase(acc, rec); err != nil {
		return err
	}
	acc.lastSeq, acc.lastDigest = rec.seq, rec.recordDigest
	return nil
}
func applyRecoveryChunk(acc *recoveryAcc, rec TransferJournalRecord) error {
	if (acc.phase != JournalRecordInit && acc.phase != JournalRecordChunk) || rec.offset != acc.offset || rec.length > acc.meta.totalBytes-acc.offset {
		return fmt.Errorf("%w: chunk 偏移不连续或超出总大小", ErrCorruptJournal)
	}
	acc.offset, acc.chunks, acc.phase = acc.offset+rec.length, acc.chunks+1, JournalRecordChunk
	return nil
}
func applyRecoveryVerified(acc *recoveryAcc, rec TransferJournalRecord) error {
	dig, ok := rec.digest.Get()
	exp, hasExp := acc.meta.expectedDigest.Get()
	canVerify := acc.phase == JournalRecordInit || acc.phase == JournalRecordChunk || acc.phase == JournalRecordVerified
	if !canVerify || acc.offset != acc.meta.totalBytes || !ok || (hasExp && !exp.Equal(dig)) {
		return fmt.Errorf("%w: verified 前置条件或摘要不匹配", ErrCorruptJournal)
	}
	if prev, hasPrev := acc.verifiedDigest.Get(); hasPrev && !prev.Equal(dig) {
		return fmt.Errorf("%w: 重复 verified 记录摘要不一致", ErrCorruptJournal)
	}
	acc.verifiedDigest, acc.phase = algebraic.Some(dig), JournalRecordVerified
	return nil
}
func advanceRecoveryPhase(acc *recoveryAcc, rec TransferJournalRecord) error {
	switch rec.kind {
	case JournalRecordChunk:
		return applyRecoveryChunk(acc, rec)
	case JournalRecordVerified:
		return applyRecoveryVerified(acc, rec)
	case JournalRecordCommitStarted:
		if acc.phase != JournalRecordVerified {
			return fmt.Errorf("%w: commit_started 必须紧随 verified", ErrCorruptJournal)
		}
		acc.commitSeen, acc.phase = true, JournalRecordCommitStarted
	case JournalRecordCommitted:
		if acc.phase != JournalRecordCommitStarted {
			return fmt.Errorf("%w: committed 必须紧随 commit_started", ErrCorruptJournal)
		}
		acc.phase = JournalRecordCommitted
	case JournalRecordAborted:
		if acc.phase == JournalRecordCommitted || acc.phase == JournalRecordAborted {
			return fmt.Errorf("%w: 终态 %s 后不得再出现 aborted", ErrCorruptJournal, acc.phase)
		}
		acc.phase = JournalRecordAborted
	default:
		return fmt.Errorf("%w: 非法记录阶段 %s", ErrCorruptJournal, rec.kind)
	}
	return nil
}
func failClosedRecovery(acc recoveryAcc, err error) (TransferState, []TransferEffect, []TransferEvent, error) {
	if acc.commitSeen {
		return &TransferUncertainCommit{tMix(acc.meta, TransferKindUncertainCommit, sanitizeReason(err.Error()))}, nil, []TransferEvent{transferEvent(TransferEventUncertainCommit, acc.offset, err.Error())}, err
	}
	return &TransferAborted{tMix(acc.meta, TransferKindAborted, sanitizeReason(err.Error()))}, []TransferEffect{simpleTransferEffect(TransferEffectCleanupStaging)}, []TransferEvent{transferEvent(TransferEventAborted, acc.offset, err.Error())}, err
}
func finalizeRecoveryAcc(acc recoveryAcc) (TransferState, []TransferEffect, []TransferEvent, error) {
	switch acc.phase {
	case JournalRecordInit, JournalRecordChunk:
		if acc.offset < acc.meta.totalBytes {
			return &TransferStreaming{tProg(acc.meta, TransferKindStreaming, acc.offset, acc.chunks, acc.lastSeq+1, acc.lastDigest)}, nil, []TransferEvent{transferEvent(TransferEventRecovered, acc.offset, "streaming")}, nil
		}
		return &TransferVerifying{tProg(acc.meta, TransferKindVerifying, acc.offset, acc.chunks, acc.lastSeq+1, acc.lastDigest)}, []TransferEffect{simpleTransferEffect(TransferEffectVerifyFullDigest)}, []TransferEvent{transferEvent(TransferEventRecovered, acc.offset, "verifying")}, nil
	case JournalRecordVerified:
		return &TransferVerifying{tProg(acc.meta, TransferKindVerifying, acc.offset, acc.chunks, acc.lastSeq+1, acc.lastDigest)}, []TransferEffect{simpleTransferEffect(TransferEffectVerifyFullDigest)}, []TransferEvent{transferEvent(TransferEventRecovered, acc.offset, "reverify_before_commit")}, nil
	case JournalRecordCommitStarted:
		return &TransferUncertainCommit{tMix(acc.meta, TransferKindUncertainCommit, "crashed after commit_started before committed")}, nil, []TransferEvent{transferEvent(TransferEventUncertainCommit, acc.offset, "crashed_mid_commit")}, nil
	case JournalRecordCommitted:
		return &TransferCommitted{tMix(acc.meta, TransferKindCommitted, "")}, nil, []TransferEvent{transferEvent(TransferEventRecovered, acc.offset, "committed")}, nil
	case JournalRecordAborted:
		return &TransferAborted{tMix(acc.meta, TransferKindAborted, "aborted_before_crash")}, []TransferEffect{simpleTransferEffect(TransferEffectCleanupStaging)}, []TransferEvent{transferEvent(TransferEventRecovered, acc.offset, "aborted")}, nil
	default:
		return nil, nil, nil, ErrCorruptJournal
	}
}
