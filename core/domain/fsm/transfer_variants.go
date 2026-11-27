package fsm

import (
	"github.com/wentf9/xops-cli/core/domain/algebraic"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// TransferDirection、JournalVersion、JournalRecordKind、TransferStateKind、TransferEffectKind 与 TransferEventKind 为失败关闭枚举。
type (
	//xops:opaque
	//xops:failclosed
	TransferDirection uint8
	//xops:opaque
	//xops:failclosed
	JournalVersion uint8
	//xops:opaque
	//xops:failclosed
	JournalRecordKind uint8
	//xops:opaque
	//xops:failclosed
	TransferStateKind uint8
	//xops:opaque
	//xops:failclosed
	TransferEffectKind uint8
	//xops:opaque
	//xops:failclosed
	TransferEventKind uint8
)

const (
	TransferDirectionInvalid TransferDirection = iota
	TransferDirectionUpload
	TransferDirectionDownload
)
const (
	JournalVersionInvalid JournalVersion = iota
	JournalVersionV1
	JournalVersionV2
)
const (
	JournalRecordInvalid JournalRecordKind = iota
	JournalRecordInit
	JournalRecordChunk
	JournalRecordVerified
	JournalRecordCommitStarted
	JournalRecordCommitted
	JournalRecordAborted
)
const (
	TransferKindInvalid TransferStateKind = iota
	TransferKindInitialized
	TransferKindStreaming
	TransferKindVerifying
	TransferKindCommitting
	TransferKindCommitted
	TransferKindAborted
	TransferKindUncertainCommit
)
const (
	transferInInvalid uint8 = iota
	transferInStart
	transferInChunk
	transferInVerifyResult
	transferInCommitResult
	transferInAbort
)
const (
	TransferEffectInvalid TransferEffectKind = iota
	TransferEffectWriteJournal
	TransferEffectVerifyFullDigest
	TransferEffectAtomicCommit
	TransferEffectCleanupStaging
)
const (
	TransferEventInvalid TransferEventKind = iota
	TransferEventStarted
	TransferEventChunkAccepted
	TransferEventStreamCompleted
	TransferEventDigestVerified
	TransferEventCommitStarted
	TransferEventCommitted
	TransferEventAborted
	TransferEventUncertainCommit
	TransferEventRecovered
)

// TransferDest 表示方向感知的不可变传输目标：上传绑定远端 pathalg.RemotePath，下载绑定本机受限根目录目标 pathalg.LocalRootedDest；零值恒无效。
//
//xops:opaque
//xops:failclosed
type TransferDest struct {
	direction TransferDirection
	remote    pathalg.RemotePath
	local     pathalg.LocalRootedDest
	valid     bool
}

// NewUploadDest 与 NewDownloadDest 分别校验远端绝对路径与本机受限根目录相对目标，构造不可变 TransferDest。
func NewUploadDest(remote pathalg.RemotePath) (TransferDest, error) {
	if !remote.IsValid() {
		return TransferDest{}, domi18n.EF(ErrInvalidContext, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "remote_path"))
	}
	return TransferDest{direction: TransferDirectionUpload, remote: remote, valid: true}, nil
}
func NewDownloadDest(local pathalg.LocalRootedDest) (TransferDest, error) {
	if !local.IsValid() {
		return TransferDest{}, domi18n.EF(ErrInvalidContext, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "local_dest"))
	}
	return TransferDest{direction: TransferDirectionDownload, local: local, valid: true}, nil
}
func (d TransferDest) IsValid() bool {
	return d.valid && ((d.direction == TransferDirectionUpload && d.remote.IsValid() && d.local.IsZero()) ||
		(d.direction == TransferDirectionDownload && d.local.IsValid() && d.remote.IsZero()))
}
func (d TransferDest) IsZero() bool { return !d.IsValid() }
func (d TransferDest) Direction() TransferDirection {
	return pickIf(d.IsValid(), d.direction, TransferDirectionInvalid)
}
func (d TransferDest) Remote() algebraic.Option[pathalg.RemotePath] {
	return pickIf(d.IsValid() && d.direction == TransferDirectionUpload, algebraic.Some(d.remote), algebraic.None[pathalg.RemotePath]())
}
func (d TransferDest) Local() algebraic.Option[pathalg.LocalRootedDest] {
	return pickIf(d.IsValid() && d.direction == TransferDirectionDownload, algebraic.Some(d.local), algebraic.None[pathalg.LocalRootedDest]())
}
func (d TransferDest) String() string {
	return pickIf(d.IsValid(), d.direction.String()+":"+pickIf(d.direction == TransferDirectionUpload, d.remote.String(), d.local.String()), "")
}
func (d TransferDest) Equal(o TransferDest) bool {
	return d.IsValid() && o.IsValid() && d.direction == o.direction &&
		pickIf(d.direction == TransferDirectionUpload, d.remote.Equal(o.remote), d.local.Equal(o.local))
}
func (d TransferDest) writeCanonical(enc *canonicalEncoder) {
	if !d.IsValid() {
		enc.err = ErrInvalidJournal
		return
	}
	enc.writeUint8(uint8(d.direction))
	enc.writeString(pickIf(d.direction == TransferDirectionUpload, d.remote.String(), d.local.String()))
}

// TransferMetaSpec 与 TransferMeta 保存单次分片传输（上传或下载，最高 10 GiB，预期摘要可选）的不可变元数据；零值恒无效。
type (
	TransferMetaSpec struct {
		TransferID     security.OperationID
		Dest           TransferDest
		TotalBytes     uint64
		ExpectedDigest algebraic.Option[security.Digest]
		JournalVersion JournalVersion
		Generation     uint64
	}
	//xops:opaque
	//xops:failclosed
	TransferMeta struct {
		transferID     security.OperationID
		dest           TransferDest
		totalBytes     uint64
		expectedDigest algebraic.Option[security.Digest]
		journalVersion JournalVersion
		generation     uint64
		valid          bool
	}
)

// NewTransferMeta 校验传输标识、方向感知目标、总大小（<= 10 GiB）、可选预期摘要、Journal 版本与世代号（>= 1）。
func NewTransferMeta(spec TransferMetaSpec) (TransferMeta, error) {
	if spec.TotalBytes > MaxTransferBytes {
		return TransferMeta{}, domi18n.EF(ErrTransferSizeExceeded, domi18n.KeyCommonSizeLimit, domi18n.Str("kind", "total_bytes"), domi18n.Uint64("size", spec.TotalBytes), domi18n.Uint64("limit", MaxTransferBytes))
	}
	if d, ok := spec.ExpectedDigest.Get(); ok && !d.IsValid() {
		return TransferMeta{}, domi18n.EF(ErrInvalidContext, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "expected_digest"))
	}
	if !spec.TransferID.IsValid() || !spec.Dest.IsValid() || !spec.JournalVersion.IsValid() || spec.Generation == 0 {
		return TransferMeta{}, domi18n.EF(ErrInvalidContext, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "transfer_meta"))
	}
	return TransferMeta{spec.TransferID, spec.Dest, spec.TotalBytes, spec.ExpectedDigest, spec.JournalVersion, spec.Generation, true}, nil
}
func (m TransferMeta) IsValid() bool {
	d, hasD := m.expectedDigest.Get()
	return m.valid && m.transferID.IsValid() && m.dest.IsValid() && m.totalBytes <= MaxTransferBytes &&
		(!hasD || d.IsValid()) && m.journalVersion.IsValid() && m.generation > 0
}
func (m TransferMeta) TransferID() security.OperationID                  { return m.transferID }
func (m TransferMeta) Dest() TransferDest                                { return m.dest }
func (m TransferMeta) Direction() TransferDirection                      { return m.dest.Direction() }
func (m TransferMeta) TotalBytes() uint64                                { return pickIf(m.IsValid(), m.totalBytes, 0) }
func (m TransferMeta) ExpectedDigest() algebraic.Option[security.Digest] { return m.expectedDigest }
func (m TransferMeta) JournalVersion() JournalVersion                    { return m.journalVersion }
func (m TransferMeta) Generation() uint64                                { return pickIf(m.IsValid(), m.generation, 0) }

// TransferState 是 TransferFSM 的封闭状态代数和类型（RFC §3.6），由 xopsvet/sumexhaust 穷尽检查。
//
//xops:failclosed
type TransferState interface {
	sealedTransferState()
	rawMeta() TransferMeta
	rawKind() TransferStateKind
	rawReason() string
	rawProgress() (offset, chunks, nextSeq uint64)
	Kind() TransferStateKind
	IsValid() bool
	IsTerminal() bool
}

type sealedTransferMixin struct {
	meta       TransferMeta
	kind       TransferStateKind
	offset     uint64
	chunkCount uint64
	nextSeq    uint64
	lastDigest security.Digest
	reason     string
	valid      bool
}

func (*sealedTransferMixin) sealedTransferState()         {}
func (m *sealedTransferMixin) rawMeta() TransferMeta      { return m.meta }
func (m *sealedTransferMixin) rawKind() TransferStateKind { return m.kind }
func (m *sealedTransferMixin) rawReason() string          { return m.reason }
func (m *sealedTransferMixin) rawProgress() (uint64, uint64, uint64) {
	return m.offset, m.chunkCount, m.nextSeq
}
func tMix(m TransferMeta, k TransferStateKind, r string) sealedTransferMixin {
	return sealedTransferMixin{meta: m, kind: k, reason: r, valid: true}
}
func tProg(m TransferMeta, k TransferStateKind, off, chunks, seq uint64, dig security.Digest) sealedTransferMixin {
	return sealedTransferMixin{meta: m, kind: k, offset: off, chunkCount: chunks, nextSeq: seq, lastDigest: dig, valid: true}
}

// TransferState 的 7 个不可变封闭指针变体（内置正向 valid 门控，零值恒无效）；
// TransferUncertainCommit 表示原子交接遇 Applied && !Durable 或未知结果的零重试零删目标停机终态。
type (
	//xops:opaque
	//xops:failclosed
	TransferInitialized struct{ sealedTransferMixin }
	//xops:opaque
	//xops:failclosed
	TransferStreaming struct{ sealedTransferMixin }
	//xops:opaque
	//xops:failclosed
	TransferVerifying struct{ sealedTransferMixin }
	//xops:opaque
	//xops:failclosed
	TransferCommitting struct{ sealedTransferMixin }
	//xops:opaque
	//xops:failclosed
	TransferCommitted struct{ sealedTransferMixin }
	//xops:opaque
	//xops:failclosed
	TransferAborted struct{ sealedTransferMixin }
	//xops:opaque
	//xops:failclosed
	TransferUncertainCommit struct{ sealedTransferMixin }
)

func (m *sealedTransferMixin) okProg(minSeq uint64, checkOff bool) bool {
	return m.valid && m.meta.IsValid() && (!checkOff || m.offset <= m.meta.totalBytes) && m.nextSeq >= minSeq && m.lastDigest.IsValid()
}
func (s *TransferInitialized) IsValid() bool               { return s != nil && s.valid && s.meta.IsValid() }
func (s *TransferStreaming) IsValid() bool                 { return s != nil && s.okProg(2, true) }
func (s *TransferVerifying) IsValid() bool                 { return s != nil && s.okProg(2, false) }
func (s *TransferCommitting) IsValid() bool                { return s != nil && s.okProg(4, false) }
func (s *TransferCommitted) IsValid() bool                 { return s != nil && s.valid && s.meta.IsValid() }
func (s *TransferAborted) IsValid() bool                   { return s != nil && s.valid && s.meta.IsValid() }
func (s *TransferUncertainCommit) IsValid() bool           { return s != nil && s.valid && s.meta.IsValid() }
func (s *TransferInitialized) Kind() TransferStateKind     { return tKind(s) }
func (s *TransferStreaming) Kind() TransferStateKind       { return tKind(s) }
func (s *TransferVerifying) Kind() TransferStateKind       { return tKind(s) }
func (s *TransferCommitting) Kind() TransferStateKind      { return tKind(s) }
func (s *TransferCommitted) Kind() TransferStateKind       { return tKind(s) }
func (s *TransferAborted) Kind() TransferStateKind         { return tKind(s) }
func (s *TransferUncertainCommit) Kind() TransferStateKind { return tKind(s) }
func (*TransferInitialized) IsTerminal() bool              { return false }
func (*TransferStreaming) IsTerminal() bool                { return false }
func (*TransferVerifying) IsTerminal() bool                { return false }
func (*TransferCommitting) IsTerminal() bool               { return false }
func (s *TransferCommitted) IsTerminal() bool              { return s.IsValid() }
func (s *TransferAborted) IsTerminal() bool                { return s.IsValid() }
func (s *TransferUncertainCommit) IsTerminal() bool        { return s.IsValid() }
func (s *TransferStreaming) Offset() uint64                { return tNum(s, 0) }
func (s *TransferStreaming) ChunkCount() uint64            { return tNum(s, 1) }
func (s *TransferStreaming) NextSeq() uint64               { return tNum(s, 2) }
func (s *TransferVerifying) ChunkCount() uint64            { return tNum(s, 1) }
func (s *TransferVerifying) NextSeq() uint64               { return tNum(s, 2) }
func (s *TransferAborted) Reason() string                  { return tText(s) }
func (s *TransferUncertainCommit) Reason() string          { return tText(s) }
func tKind(s TransferState) TransferStateKind {
	if s != nil && s.IsValid() {
		return s.rawKind()
	}
	return TransferKindInvalid
}
func tText(s TransferState) string {
	if s != nil && s.IsValid() {
		return s.rawReason()
	}
	return ""
}
func tNum(s TransferState, idx int) uint64 {
	if s == nil || !s.IsValid() {
		return 0
	}
	off, chunks, seq := s.rawProgress()
	return [3]uint64{off, chunks, seq}[idx]
}

// TransferMetaOf 提取任意 TransferState 携带的不可变传输元数据；nil 或无效零值失败关闭返回零值。
func TransferMetaOf(state TransferState) TransferMeta {
	if state == nil || !state.IsValid() {
		return TransferMeta{}
	}
	return state.rawMeta()
}

// TransferInput、TransferEffect 与 TransferEvent 为 TransferFSM 的不透明值对象。
type (
	//xops:opaque
	//xops:failclosed
	TransferInput struct {
		kind       uint8
		offset     uint64
		length     uint64
		digest     security.Digest
		ok         bool
		durability DurabilityStatus
		reason     string
		valid      bool
	}
	//xops:opaque
	//xops:failclosed
	TransferEffect struct {
		kind   TransferEffectKind
		record algebraic.Option[TransferJournalRecord]
		valid  bool
	}
	//xops:opaque
	//xops:failclosed
	TransferEvent struct {
		kind   TransferEventKind
		offset uint64
		detail string
		valid  bool
	}
)

func (i TransferInput) IsValid() bool {
	return i.valid && i.kind >= transferInStart && i.kind <= transferInAbort
}
func (e TransferEffect) IsValid() bool                                   { return e.valid && e.kind.IsValid() }
func (e TransferEffect) Kind() TransferEffectKind                        { return e.kind }
func (e TransferEffect) Record() algebraic.Option[TransferJournalRecord] { return e.record }
func (e TransferEvent) IsValid() bool                                    { return e.valid && e.kind.IsValid() }
func (e TransferEvent) IsZero() bool                                     { return !e.IsValid() }
func (e TransferEvent) Kind() TransferEventKind                          { return e.kind }
func (e TransferEvent) Offset() uint64                                   { return e.offset }
func (e TransferEvent) Detail() string                                   { return e.detail }
func (e TransferEvent) Equal(o TransferEvent) bool {
	return e.IsValid() && o.IsValid() && e.kind == o.kind && e.offset == o.offset && e.detail == o.detail
}
