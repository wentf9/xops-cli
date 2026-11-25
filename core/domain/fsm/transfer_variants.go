package fsm

import (
	"fmt"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/pathalg"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// JournalVersion、TransferStateKind、TransferEffectKind 与 TransferEventKind 为失败关闭枚举。
type (
	//xops:opaque
	//xops:failclosed
	JournalVersion uint8
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
	JournalVersionInvalid JournalVersion = iota
	JournalVersionV1
	JournalVersionV2
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

// ParseJournalVersion 严格解析规范小写 Journal 版本（"v1" 或 "v2"）。
func ParseJournalVersion(raw string) (JournalVersion, error) {
	return parseEnumByName(raw, JournalVersionV1, JournalVersionV2, JournalVersionInvalid, JournalVersion.String, ErrInvalidJournal)
}
func (v JournalVersion) IsValid() bool  { return v == JournalVersionV1 || v == JournalVersionV2 }
func (v JournalVersion) IsZero() bool   { return v == JournalVersionInvalid }
func (v JournalVersion) String() string { return enumName(uint8(v), "invalid", "invalid", "v1", "v2") }
func (v JournalVersion) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, v.IsValid(), v.String(), ErrInvalidJournal)
}
func (v JournalVersion) MarshalText() ([]byte, error) { return v.AppendText(nil) }
func (v *JournalVersion) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(v, JournalVersionInvalid, text, ParseJournalVersion)
}

func (k TransferStateKind) IsValid() bool {
	return k >= TransferKindInitialized && k <= TransferKindUncertainCommit
}
func (k TransferEffectKind) IsValid() bool {
	return k >= TransferEffectWriteJournal && k <= TransferEffectCleanupStaging
}
func (k TransferEventKind) IsValid() bool {
	return k >= TransferEventStarted && k <= TransferEventRecovered
}
func (k TransferStateKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "initialized", "streaming", "verifying", "committing", "committed", "aborted", "uncertain_commit")
}
func (k TransferEffectKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "write_journal", "verify_full_digest", "atomic_commit", "cleanup_staging")
}
func (k TransferEventKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "started", "chunk_accepted", "stream_completed", "digest_verified", "commit_started", "committed", "aborted", "uncertain_commit", "recovered")
}

// TransferMetaSpec 与 TransferMeta 保存单次 MCP HTTP 分片传输（最高 10 GiB）的不可变元数据；零值恒无效。
type TransferMetaSpec struct {
	TransferID     security.OperationID
	Dest           pathalg.RemotePath
	TotalBytes     uint64
	ExpectedDigest security.Digest
	JournalVersion JournalVersion
	Generation     uint64
}

//xops:opaque
//xops:failclosed
type TransferMeta struct {
	transferID     security.OperationID
	dest           pathalg.RemotePath
	totalBytes     uint64
	expectedDigest security.Digest
	journalVersion JournalVersion
	generation     uint64
	valid          bool
}

// NewTransferMeta 校验传输标识、远端路径、总大小（<= 10 GiB）、预期全量摘要、Journal 版本与世代号（>= 1）。
func NewTransferMeta(spec TransferMetaSpec) (TransferMeta, error) {
	if spec.TotalBytes > MaxTransferBytes {
		return TransferMeta{}, fmt.Errorf("%w: total_bytes=%d 超出 10 GiB 上限 %d", ErrTransferSizeExceeded, spec.TotalBytes, MaxTransferBytes)
	}
	if !spec.TransferID.IsValid() || !spec.Dest.IsValid() || !spec.ExpectedDigest.IsValid() || !spec.JournalVersion.IsValid() || spec.Generation == 0 {
		return TransferMeta{}, fmt.Errorf("%w: transfer_id/dest/expected_digest/journal_version/generation(>=1) 均须有效", ErrInvalidContext)
	}
	return TransferMeta{spec.TransferID, spec.Dest, spec.TotalBytes, spec.ExpectedDigest, spec.JournalVersion, spec.Generation, true}, nil
}

func (m TransferMeta) IsValid() bool {
	return m.valid && m.transferID.IsValid() && m.dest.IsValid() && m.totalBytes <= MaxTransferBytes &&
		m.expectedDigest.IsValid() && m.journalVersion.IsValid() && m.generation > 0
}
func (m TransferMeta) TransferID() security.OperationID { return m.transferID }
func (m TransferMeta) Dest() pathalg.RemotePath         { return m.dest }
func (m TransferMeta) TotalBytes() uint64               { return pickIf(m.IsValid(), m.totalBytes, 0) }
func (m TransferMeta) ExpectedDigest() security.Digest  { return m.expectedDigest }
func (m TransferMeta) JournalVersion() JournalVersion   { return m.journalVersion }
func (m TransferMeta) Generation() uint64               { return pickIf(m.IsValid(), m.generation, 0) }

// TransferState 是 TransferFSM 的封闭状态代数和类型（RFC §3.6），由 xopsvet/sumexhaust 穷尽检查。
//
//xops:failclosed
type TransferState interface {
	sealedTransferState()
	rawMeta() TransferMeta
	Kind() TransferStateKind
	IsValid() bool
	IsTerminal() bool
}

type sealedTransferMixin struct {
	meta  TransferMeta
	valid bool
}

func (*sealedTransferMixin) sealedTransferState()    {}
func (m *sealedTransferMixin) rawMeta() TransferMeta { return m.meta }

// TransferState 的 7 个不可变封闭指针变体（内置正向 valid 门控，零值恒无效）；
// TransferUncertainCommit 表示原子交接遇 Applied && !Durable 或未知结果的零重试零删目标停机终态。
type (
	//xops:opaque
	//xops:failclosed
	TransferInitialized struct{ sealedTransferMixin }
	//xops:opaque
	//xops:failclosed
	TransferStreaming struct {
		sealedTransferMixin
		offset     uint64
		chunkCount uint64
		nextSeq    uint64
		lastDigest security.Digest
	}
	//xops:opaque
	//xops:failclosed
	TransferVerifying struct {
		sealedTransferMixin
		chunkCount uint64
		nextSeq    uint64
		lastDigest security.Digest
	}
	//xops:opaque
	//xops:failclosed
	TransferCommitting struct {
		sealedTransferMixin
		nextSeq    uint64
		lastDigest security.Digest
	}
	//xops:opaque
	//xops:failclosed
	TransferCommitted struct{ sealedTransferMixin }
	//xops:opaque
	//xops:failclosed
	TransferAborted struct {
		sealedTransferMixin
		reason string
	}
	//xops:opaque
	//xops:failclosed
	TransferUncertainCommit struct {
		sealedTransferMixin
		reason string
	}
)

func (s *TransferInitialized) IsValid() bool { return s != nil && s.valid && s.meta.IsValid() }
func (s *TransferStreaming) IsValid() bool {
	return s != nil && s.valid && s.meta.IsValid() && s.offset <= s.meta.totalBytes && s.nextSeq >= 2 && s.lastDigest.IsValid()
}
func (s *TransferVerifying) IsValid() bool {
	return s != nil && s.valid && s.meta.IsValid() && s.nextSeq >= 2 && s.lastDigest.IsValid()
}
func (s *TransferCommitting) IsValid() bool {
	return s != nil && s.valid && s.meta.IsValid() && s.nextSeq >= 4 && s.lastDigest.IsValid()
}
func (s *TransferCommitted) IsValid() bool       { return s != nil && s.valid && s.meta.IsValid() }
func (s *TransferAborted) IsValid() bool         { return s != nil && s.valid && s.meta.IsValid() }
func (s *TransferUncertainCommit) IsValid() bool { return s != nil && s.valid && s.meta.IsValid() }

func (s *TransferInitialized) Kind() TransferStateKind {
	return tk(s.IsValid(), TransferKindInitialized)
}
func (s *TransferStreaming) Kind() TransferStateKind  { return tk(s.IsValid(), TransferKindStreaming) }
func (s *TransferVerifying) Kind() TransferStateKind  { return tk(s.IsValid(), TransferKindVerifying) }
func (s *TransferCommitting) Kind() TransferStateKind { return tk(s.IsValid(), TransferKindCommitting) }
func (s *TransferCommitted) Kind() TransferStateKind  { return tk(s.IsValid(), TransferKindCommitted) }
func (s *TransferAborted) Kind() TransferStateKind    { return tk(s.IsValid(), TransferKindAborted) }
func (s *TransferUncertainCommit) Kind() TransferStateKind {
	return tk(s.IsValid(), TransferKindUncertainCommit)
}

func tk(ok bool, k TransferStateKind) TransferStateKind { return pickIf(ok, k, TransferKindInvalid) }

// TransferMetaOf 提取任意 TransferState 携带的不可变传输元数据；nil 或无效零值失败关闭返回零值。
func TransferMetaOf(state TransferState) TransferMeta {
	if state == nil || !state.IsValid() {
		return TransferMeta{}
	}
	return state.rawMeta()
}

func (*TransferInitialized) IsTerminal() bool       { return false }
func (*TransferStreaming) IsTerminal() bool         { return false }
func (*TransferVerifying) IsTerminal() bool         { return false }
func (*TransferCommitting) IsTerminal() bool        { return false }
func (s *TransferCommitted) IsTerminal() bool       { return s.IsValid() }
func (s *TransferAborted) IsTerminal() bool         { return s.IsValid() }
func (s *TransferUncertainCommit) IsTerminal() bool { return s.IsValid() }

func (s *TransferStreaming) Offset() uint64 {
	return pickLazy(s.IsValid(), func() uint64 { return s.offset })
}
func (s *TransferStreaming) ChunkCount() uint64 {
	return pickLazy(s.IsValid(), func() uint64 { return s.chunkCount })
}
func (s *TransferStreaming) NextSeq() uint64 {
	return pickLazy(s.IsValid(), func() uint64 { return s.nextSeq })
}
func (s *TransferVerifying) ChunkCount() uint64 {
	return pickLazy(s.IsValid(), func() uint64 { return s.chunkCount })
}
func (s *TransferVerifying) NextSeq() uint64 {
	return pickLazy(s.IsValid(), func() uint64 { return s.nextSeq })
}
func (s *TransferAborted) Reason() string {
	return pickLazy(s.IsValid(), func() string { return s.reason })
}
func (s *TransferUncertainCommit) Reason() string {
	return pickLazy(s.IsValid(), func() string { return s.reason })
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
func (e TransferEvent) Kind() TransferEventKind                          { return e.kind }
func (e TransferEvent) Offset() uint64                                   { return e.offset }
func (e TransferEvent) Detail() string                                   { return e.detail }
