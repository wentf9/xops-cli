package fsm

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
)

const transferJournalDomainTag = "xops.fsm.transfer_journal_record.v2"

// JournalRecordKind 标识单条传输 WAL/Journal 记录的生命周期类别；零值失败关闭。
//
//xops:opaque
//xops:failclosed
type JournalRecordKind uint8

const (
	JournalRecordInvalid JournalRecordKind = iota
	JournalRecordInit
	JournalRecordChunk
	JournalRecordVerified
	JournalRecordCommitStarted
	JournalRecordCommitted
	JournalRecordAborted
)

// ParseJournalRecordKind 严格解析规范小写 Journal 记录类别文本。
func ParseJournalRecordKind(raw string) (JournalRecordKind, error) {
	return parseEnumByName(raw, JournalRecordInit, JournalRecordAborted, JournalRecordInvalid, JournalRecordKind.String, ErrInvalidJournal)
}
func (k JournalRecordKind) IsValid() bool { return k >= JournalRecordInit && k <= JournalRecordAborted }
func (k JournalRecordKind) IsZero() bool  { return k == JournalRecordInvalid }
func (k JournalRecordKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "init", "chunk", "verified", "commit_started", "committed", "aborted")
}
func (k JournalRecordKind) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, k.IsValid(), k.String(), ErrInvalidJournal)
}
func (k JournalRecordKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }
func (k *JournalRecordKind) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(k, JournalRecordInvalid, text, ParseJournalRecordKind)
}

// TransferJournalRecordSpec 与 TransferJournalRecord 表示双版本（V1/V2）双代自校验传输 Journal 记录：
// 经 //xops:canonicalhash 由 digestcover 校验全字段覆盖；V2 在 seq>1 时以 prevDigest 串联前驱哈希。
type TransferJournalRecordSpec struct {
	Version    JournalVersion
	Generation uint64
	Seq        uint64
	Kind       JournalRecordKind
	TransferID security.OperationID
	Dest       algebraic.Option[pathalg.RemotePath]
	Offset     uint64
	Length     uint64
	TotalBytes uint64
	Digest     algebraic.Option[security.Digest]
	PrevDigest algebraic.Option[security.Digest]
}

//xops:opaque
//xops:failclosed
//xops:canonicalhash
type TransferJournalRecord struct {
	version      JournalVersion
	generation   uint64
	seq          uint64
	kind         JournalRecordKind
	transferID   security.OperationID
	dest         algebraic.Option[pathalg.RemotePath]
	offset       uint64
	length       uint64
	totalBytes   uint64
	digest       algebraic.Option[security.Digest]
	prevDigest   algebraic.Option[security.Digest]
	recordDigest security.Digest //xops:hash-exclude:由 WriteCanonical 派生的自校验记录摘要
	valid        bool
}

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
func isValidInitSpec(s TransferJournalRecordSpec, hasDest, hasDig bool) bool {
	return s.Seq == 1 && hasDest && hasDig && s.Offset == 0 && s.Length == 0
}
func isValidChunkSpec(s TransferJournalRecordSpec, hasDest, hasDig bool) bool {
	return s.Seq >= 2 && !hasDest && hasDig && s.Length > 0 && s.Length <= MaxTransferChunkBytes && s.Offset <= s.TotalBytes && s.Length <= s.TotalBytes-s.Offset
}
func isValidVerifiedSpec(s TransferJournalRecordSpec, hasDest, hasDig bool) bool {
	return s.Seq >= 2 && !hasDest && hasDig && s.Offset == 0 && s.Length == 0
}
func isValidMarkerSpec(s TransferJournalRecordSpec, hasDest, hasDig bool) bool {
	return s.Seq >= 2 && !hasDest && !hasDig && s.Offset == 0 && s.Length == 0
}
func validateJournalKindFields(s TransferJournalRecordSpec) error {
	dest, hasDest := s.Dest.Get()
	dig, hasDig := s.Digest.Get()
	if (hasDest && !dest.IsValid()) || (hasDig && !dig.IsValid()) {
		return fmt.Errorf("%w: dest 或 digest 零值无效", ErrInvalidJournal)
	}
	switch s.Kind {
	case JournalRecordInit:
		if !isValidInitSpec(s, hasDest, hasDig) {
			return fmt.Errorf("%w: init 记录必须为 seq=1 且携带 dest/expected_digest", ErrInvalidJournal)
		}
	case JournalRecordChunk:
		if !isValidChunkSpec(s, hasDest, hasDig) {
			return fmt.Errorf("%w: chunk 记录偏移、长度或摘要非法", ErrInvalidJournal)
		}
	case JournalRecordVerified:
		if !isValidVerifiedSpec(s, hasDest, hasDig) {
			return fmt.Errorf("%w: verified 记录必须携带校验摘要且 offset/length 为 0", ErrInvalidJournal)
		}
	case JournalRecordCommitStarted, JournalRecordCommitted, JournalRecordAborted:
		if !isValidMarkerSpec(s, hasDest, hasDig) {
			return fmt.Errorf("%w: 终态/提交标记记录字段组合非法", ErrInvalidJournal)
		}
	default:
		return ErrInvalidJournal
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
func (r TransferJournalRecord) Dest() algebraic.Option[pathalg.RemotePath]    { return r.dest }
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
		equalOptionFunc(r.dest, o.dest, pathalg.RemotePath.Equal) && equalOptionFunc(r.digest, o.digest, security.Digest.Equal) &&
		equalOptionFunc(r.prevDigest, o.prevDigest, security.Digest.Equal)
}

// WriteCanonical 以零反射长度前缀方式写入 Journal 记录全部语义字段（受 digestcover 校验）。
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
	p, hasP := r.dest.Get()
	enc.writeUint8(pickIf[uint8](hasP, 1, 0))
	if hasP {
		enc.writeString(p.String())
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
	if !ok {
		return
	}
	if sum, valid := d.Bytes(); valid {
		enc.writeBytes(sum[:])
	} else {
		enc.err = ErrInvalidJournal
	}
}

type transferJournalWire struct {
	Version      algebraic.Option[JournalVersion]       `json:"version"`
	Generation   algebraic.Option[uint64]               `json:"generation"`
	Seq          algebraic.Option[uint64]               `json:"seq"`
	Kind         algebraic.Option[JournalRecordKind]    `json:"kind"`
	TransferID   algebraic.Option[security.OperationID] `json:"transfer_id"`
	Dest         algebraic.Option[pathalg.RemotePath]   `json:"dest,omitzero"`
	Offset       uint64                                 `json:"offset,omitzero"`
	Length       uint64                                 `json:"length,omitzero"`
	TotalBytes   uint64                                 `json:"total_bytes,omitzero"`
	Digest       algebraic.Option[security.Digest]      `json:"digest,omitzero"`
	PrevDigest   algebraic.Option[security.Digest]      `json:"prev_digest,omitzero"`
	RecordDigest algebraic.Option[security.Digest]      `json:"record_digest"`
}

// MarshalJSONTo 与 UnmarshalJSONFrom 提供防篡改、拒收未知字段的确定性 json/v2 编解码。
func (r TransferJournalRecord) MarshalJSONTo(enc *jsontext.Encoder) error {
	if !r.IsValid() {
		return ErrInvalidJournal
	}
	return jsonv2.MarshalEncode(enc, transferJournalWire{
		algebraic.Some(r.version), algebraic.Some(r.generation), algebraic.Some(r.seq), algebraic.Some(r.kind),
		algebraic.Some(r.transferID), r.dest, r.offset, r.length, r.totalBytes, r.digest, r.prevDigest, algebraic.Some(r.recordDigest),
	})
}

func (r *TransferJournalRecord) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if r == nil || dec == nil {
		return ErrNilReceiver
	}
	*r = TransferJournalRecord{}
	if dec.PeekKind() == 'n' {
		_, err := dec.ReadToken()
		return pickIf(err != nil, err, fmt.Errorf("%w: JSON null 不是有效值", ErrCorruptJournal))
	}
	var w transferJournalWire
	if err := jsonv2.UnmarshalDecode(dec, &w, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	ver, okV := w.Version.Get()
	gen, okG := w.Generation.Get()
	seq, okS := w.Seq.Get()
	kind, okK := w.Kind.Get()
	tid, okT := w.TransferID.Get()
	rd, okRD := w.RecordDigest.Get()
	if !okV || !okG || !okS || !okK || !okT || !okRD {
		return fmt.Errorf("%w: 缺少必需的 Journal 字段", ErrCorruptJournal)
	}
	rec, err := NewTransferJournalRecord(TransferJournalRecordSpec{ver, gen, seq, kind, tid, w.Dest, w.Offset, w.Length, w.TotalBytes, w.Digest, w.PrevDigest})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCorruptJournal, err)
	}
	if !rd.Equal(rec.recordDigest) {
		return fmt.Errorf("%w: record_digest 校验失败", ErrCorruptJournal)
	}
	*r = rec
	return nil
}

type recoveryAcc struct {
	meta           TransferMeta
	offset, chunks uint64
	lastSeq        uint64
	lastDigest     security.Digest
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
			if !acc.commitSeen && hasCommitMarkerInTail(records[i:], acc.meta) {
				acc.commitSeen = true
			}
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
	dig, okH := first.digest.Get()
	if !first.IsValid() || first.kind != JournalRecordInit || first.seq != 1 || !okD || !okH {
		return TransferMeta{}, TransferJournalRecord{}, fmt.Errorf("%w: 首条记录必须为有效的 seq=1 init 记录", ErrCorruptJournal)
	}
	meta, err := NewTransferMeta(TransferMetaSpec{first.transferID, dest, first.totalBytes, dig, first.version, first.generation})
	if err != nil {
		return TransferMeta{}, TransferJournalRecord{}, fmt.Errorf("%w: %w", ErrCorruptJournal, err)
	}
	return meta, first, nil
}

func hasCommitMarkerInTail(tail []TransferJournalRecord, meta TransferMeta) bool {
	for _, rec := range tail {
		if rec.IsValid() && rec.transferID.Equal(meta.transferID) && rec.generation == meta.generation &&
			(rec.kind == JournalRecordCommitStarted || rec.kind == JournalRecordCommitted) {
			return true
		}
	}
	return false
}

func applyRecoveryRecord(acc *recoveryAcc, rec TransferJournalRecord) error {
	if !rec.IsValid() || !rec.transferID.Equal(acc.meta.transferID) || rec.version != acc.meta.journalVersion ||
		rec.generation != acc.meta.generation || rec.totalBytes != acc.meta.totalBytes || rec.seq != acc.lastSeq+1 {
		return fmt.Errorf("%w: 记录归属、版本、世代、总大小或序号不连续", ErrCorruptJournal)
	}
	if acc.meta.journalVersion == JournalVersionV2 {
		if prev, ok := rec.prevDigest.Get(); !ok || !prev.Equal(acc.lastDigest) {
			return fmt.Errorf("%w: V2 Journal 哈希链断裂", ErrCorruptJournal)
		}
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
	canVerify := acc.phase == JournalRecordInit || acc.phase == JournalRecordChunk || acc.phase == JournalRecordVerified
	if !canVerify || acc.offset != acc.meta.totalBytes || !ok || !acc.meta.expectedDigest.Equal(dig) {
		return fmt.Errorf("%w: verified 前置条件或摘要不匹配", ErrCorruptJournal)
	}
	acc.phase = JournalRecordVerified
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
		return &TransferUncertainCommit{sealedTransferMixin{acc.meta, true}, sanitizeReason(err.Error())}, nil, []TransferEvent{transferEvent(TransferEventUncertainCommit, acc.offset, err.Error())}, err
	}
	return &TransferAborted{sealedTransferMixin{acc.meta, true}, sanitizeReason(err.Error())}, []TransferEffect{simpleTransferEffect(TransferEffectCleanupStaging)}, []TransferEvent{transferEvent(TransferEventAborted, acc.offset, err.Error())}, err
}
func finalizeRecoveryAcc(acc recoveryAcc) (TransferState, []TransferEffect, []TransferEvent, error) {
	switch acc.phase {
	case JournalRecordInit, JournalRecordChunk:
		if acc.offset < acc.meta.totalBytes {
			return &TransferStreaming{sealedTransferMixin{acc.meta, true}, acc.offset, acc.chunks, acc.lastSeq + 1, acc.lastDigest}, nil, []TransferEvent{transferEvent(TransferEventRecovered, acc.offset, "streaming")}, nil
		}
		return &TransferVerifying{sealedTransferMixin{acc.meta, true}, acc.chunks, acc.lastSeq + 1, acc.lastDigest}, []TransferEffect{simpleTransferEffect(TransferEffectVerifyFullDigest)}, []TransferEvent{transferEvent(TransferEventRecovered, acc.offset, "verifying")}, nil
	case JournalRecordVerified:
		return &TransferVerifying{sealedTransferMixin{acc.meta, true}, acc.chunks, acc.lastSeq + 1, acc.lastDigest}, []TransferEffect{simpleTransferEffect(TransferEffectVerifyFullDigest)}, []TransferEvent{transferEvent(TransferEventRecovered, acc.offset, "reverify_before_commit")}, nil
	case JournalRecordCommitStarted:
		return &TransferUncertainCommit{sealedTransferMixin{acc.meta, true}, "crashed after commit_started before committed"}, nil, []TransferEvent{transferEvent(TransferEventUncertainCommit, acc.offset, "crashed_mid_commit")}, nil
	case JournalRecordCommitted:
		return &TransferCommitted{sealedTransferMixin{acc.meta, true}}, nil, []TransferEvent{transferEvent(TransferEventRecovered, acc.offset, "committed")}, nil
	case JournalRecordAborted:
		return &TransferAborted{sealedTransferMixin{acc.meta, true}, "aborted_before_crash"}, []TransferEffect{simpleTransferEffect(TransferEffectCleanupStaging)}, []TransferEvent{transferEvent(TransferEventRecovered, acc.offset, "aborted")}, nil
	default:
		return nil, nil, nil, ErrCorruptJournal
	}
}
