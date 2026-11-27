package ports

import (
	"cmp"
	"context"
	"io"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// Revision 表示资产存储快照的不透明 CAS 版本令牌；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type Revision struct{ value string }

// ParseRevision 校验并构造不可变 CAS 版本令牌（1..128 位可打印非空白 ASCII）。
func ParseRevision(raw string) (Revision, error) {
	if !isValidASCIIToken(raw, maxPortTokenLen) {
		return Revision{}, domi18n.EF(ErrInvalidRevision, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "revision"), domi18n.BoundStr("value", raw))
	}
	return Revision{value: raw}, nil
}
func (r Revision) IsValid() bool          { return r.value != "" }
func (r Revision) IsZero() bool           { return r.value == "" }
func (r Revision) String() string         { return r.value }
func (r Revision) Equal(o Revision) bool  { return r.IsValid() && o.IsValid() && r.value == o.value }
func (r Revision) Compare(o Revision) int { return cmp.Compare(r.value, o.value) }
func (r Revision) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, r.IsValid(), r.value, ErrInvalidRevision)
}
func (r Revision) MarshalText() ([]byte, error) { return r.AppendText(nil) }
func (r *Revision) UnmarshalText(t []byte) error {
	return unmarshalTextWithReset(r, Revision{}, t, ParseRevision)
}

// InventorySnapshot 封装单次加载取得的不可变资产图快照与 CAS 版本令牌；零值恒无效。
//
//xops:opaque
//xops:failclosed
type InventorySnapshot struct {
	revision Revision
	graph    inventory.Graph
	valid    bool
}

// NewInventorySnapshot 校验版本令牌与资产图均有效后构造不可变 InventorySnapshot。
func NewInventorySnapshot(revision Revision, graph inventory.Graph) (InventorySnapshot, error) {
	if !revision.IsValid() {
		return InventorySnapshot{}, domi18n.EF(ErrInvalidRevision, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "revision"))
	}
	if !graph.IsValid() {
		return InventorySnapshot{}, domi18n.WrapSentinel(ErrInvalidArgument, inventory.ErrInvalidGraph)
	}
	return InventorySnapshot{revision: revision, graph: graph, valid: true}, nil
}
func (s InventorySnapshot) IsValid() bool {
	return s.valid && s.revision.IsValid() && s.graph.IsValid()
}
func (s InventorySnapshot) IsZero() bool           { return !s.IsValid() }
func (s InventorySnapshot) Revision() Revision     { return s.revision }
func (s InventorySnapshot) Graph() inventory.Graph { return s.graph }

// DurabilityOutcome 表示配置 CAS 提交后的结构化持久化结果（INV-F3）：
// 严分 Committed、NotApplied、AppliedNotDurable（Applied && !Durable）与 OutcomeUnknown。
//
//xops:opaque
//xops:failclosed
type DurabilityOutcome struct {
	status   fsm.DurabilityStatus
	revision algebraic.Option[Revision]
	detail   string
	valid    bool
}

// NewDurabilityCommitted 构造已生效且已落盘（Applied && Durable）的提交结果。
func NewDurabilityCommitted(revision Revision) (DurabilityOutcome, error) {
	if !revision.IsValid() {
		return DurabilityOutcome{}, domi18n.EF(ErrInvalidDurability, domi18n.KeyCommonFieldRequired, domi18n.Str("field", "revision"))
	}
	return DurabilityOutcome{status: fsm.DurabilityCommitted, revision: algebraic.Some(revision), valid: true}, nil
}

// NewDurabilityNotApplied 构造确认未生效（可安全补偿）的提交结果。
func NewDurabilityNotApplied(detail string) (DurabilityOutcome, error) {
	return newDurDetail(fsm.DurabilityNotApplied, algebraic.None[Revision](), detail, true)
}

// NewDurabilityAppliedNotDurable 构造已生效但未确认落盘（Applied && !Durable）的停机结果。
func NewDurabilityAppliedNotDurable(revision algebraic.Option[Revision], detail string) (DurabilityOutcome, error) {
	if rev, ok := revision.Get(); ok && !rev.IsValid() {
		return DurabilityOutcome{}, fieldErr(ErrInvalidDurability, "revision")
	}
	return newDurDetail(fsm.DurabilityAppliedNotDurable, revision, detail, false)
}

// NewDurabilityOutcomeUnknown 构造提交结果未知的失败关闭结果（严禁自动重试）。
func NewDurabilityOutcomeUnknown(detail string) (DurabilityOutcome, error) {
	return newDurDetail(fsm.DurabilityOutcomeUnknown, algebraic.None[Revision](), detail, false)
}
func newDurDetail(st fsm.DurabilityStatus, rev algebraic.Option[Revision], detail string, allowEmpty bool) (DurabilityOutcome, error) {
	clean, err := sanitizeBoundedText(detail, maxPortDetailBytes, allowEmpty, ErrInvalidDurability)
	return pickIf(err == nil, DurabilityOutcome{status: st, revision: rev, detail: clean, valid: true}, DurabilityOutcome{}), err
}
func (d DurabilityOutcome) IsValid() bool {
	rev, ok := d.revision.Get()
	switch d.status {
	case fsm.DurabilityCommitted:
		return d.valid && ok && rev.IsValid()
	case fsm.DurabilityAppliedNotDurable:
		return d.valid && d.detail != "" && (!ok || rev.IsValid())
	case fsm.DurabilityNotApplied, fsm.DurabilityOutcomeUnknown:
		return d.valid && !ok && (d.status == fsm.DurabilityNotApplied || d.detail != "")
	default:
		return false
	}
}
func (d DurabilityOutcome) IsZero() bool                         { return !d.IsValid() }
func (d DurabilityOutcome) Status() fsm.DurabilityStatus         { return orZero(d.IsValid(), d.status) }
func (d DurabilityOutcome) Applied() bool                        { return d.IsValid() && d.status.Applied() }
func (d DurabilityOutcome) Durable() bool                        { return d.IsValid() && d.status.Durable() }
func (d DurabilityOutcome) Revision() algebraic.Option[Revision] { return d.revision }
func (d DurabilityOutcome) Detail() string                       { return d.detail }
func (d DurabilityOutcome) Equal(o DurabilityOutcome) bool {
	return d.IsValid() && o.IsValid() && d.status == o.status && d.detail == o.detail && optEqualFunc(d.revision, o.revision, Revision.Equal)
}

// InventoryStore 定义本地资产配置的原子加载与 CAS 持久化出站端口（INV-F1 / INV-F3）。
type InventoryStore interface {
	Load(ctx context.Context) (InventorySnapshot, error)
	CommitCAS(ctx context.Context, expected Revision, next inventory.Graph) (DurabilityOutcome, error)
}

// JournalGenerationSnapshot 表示单个传输世代（如 active 或 staging）的只读 WAL 快照；
// 零值恒无效并失败关闭（Corrupt()==true）；某世代损坏时 Records() 恒返回 nil，同时经 PartialRecords() 保留损坏前有效前缀供上层识别 CommitStarted/UncertainCommit，严禁盲目丢弃损坏高世代回退低世代。
//
//xops:opaque
//xops:failclosed
type JournalGenerationSnapshot struct {
	generation uint64
	records    []fsm.TransferJournalRecord
	corrupt    bool
	err        error
	valid      bool
}

// NewJournalGenerationSnapshot 校验世代号与非空同代记录列表并构造健康世代快照。
func NewJournalGenerationSnapshot(generation uint64, records []fsm.TransferJournalRecord) (JournalGenerationSnapshot, error) {
	if generation == 0 || len(records) == 0 || slices.ContainsFunc(records, func(r fsm.TransferJournalRecord) bool { return !r.IsValid() || r.Generation() != generation }) {
		return JournalGenerationSnapshot{}, fieldErr(ErrInvalidArgument, "journal_generation_snapshot")
	}
	return JournalGenerationSnapshot{generation: generation, records: slices.Clone(records), valid: true}, nil
}

// NewCorruptJournalGenerationSnapshot 构造显式标记损坏的世代快照，并可选保留损坏点前已校验的同代前缀记录。
func NewCorruptJournalGenerationSnapshot(generation uint64, cause error, partialPrefix ...fsm.TransferJournalRecord) (JournalGenerationSnapshot, error) {
	if generation == 0 || cause == nil || slices.ContainsFunc(partialPrefix, func(r fsm.TransferJournalRecord) bool { return !r.IsValid() || r.Generation() != generation }) {
		return JournalGenerationSnapshot{}, fieldErr(ErrInvalidArgument, "corrupt_journal_generation_snapshot")
	}
	return JournalGenerationSnapshot{generation: generation, records: cloneSliceNilIfEmpty(partialPrefix), corrupt: true, err: cause, valid: true}, nil
}
func (s JournalGenerationSnapshot) IsValid() bool {
	return s.valid && s.generation > 0 && ((s.corrupt && s.err != nil) || (!s.corrupt && s.err == nil && len(s.records) > 0))
}
func (s JournalGenerationSnapshot) IsZero() bool       { return !s.IsValid() }
func (s JournalGenerationSnapshot) Generation() uint64 { return orZero(s.IsValid(), s.generation) }
func (s JournalGenerationSnapshot) Records() []fsm.TransferJournalRecord {
	return pickIf(s.IsValid() && !s.corrupt, slices.Clone(s.records), nil)
}

// PartialRecords 返回损坏世代在损坏点前已解码校验的前缀记录副本；健康、无效或头部即损坏的快照返回 nil。
func (s JournalGenerationSnapshot) PartialRecords() []fsm.TransferJournalRecord {
	return pickIf(s.IsValid() && s.corrupt && len(s.records) > 0, slices.Clone(s.records), nil)
}
func (s JournalGenerationSnapshot) Corrupt() bool { return !s.IsValid() || s.corrupt }
func (s JournalGenerationSnapshot) Err() error    { return pickIf(s.IsValid(), s.err, ErrCorruptData) }
func (s JournalGenerationSnapshot) Equal(o JournalGenerationSnapshot) bool {
	return s.IsValid() && o.IsValid() && s.generation == o.generation && s.corrupt == o.corrupt &&
		slices.EqualFunc(s.records, o.records, fsm.TransferJournalRecord.Equal) &&
		((s.err == nil && o.err == nil) || (s.err != nil && o.err != nil && s.err.Error() == o.err.Error()))
}

// JournalStore 定义可恢复分片文件传输（最高 10 GiB）双代（active/staging）WAL/Journal 持久化出站端口（P3-T3 <-> P4-T3）。
//   - Append 按 (TransferID, Generation) 分代追加；
//   - Load 按 (Generation 升序, Seq 升序) 确定性返回全部保留记录，任一代损坏则返回 ErrCorruptData；
//   - LoadGenerations 按 Generation 升序返回逐代隔离快照（损坏代 Corrupt()==true/Records()==nil，经 PartialRecords() 保留损坏前有效前缀）；严禁盲目丢弃损坏高世代回退低世代（前缀含 CommitStarted/Committed 须停于 TransferUncertainCommit，高世代空前缀须失败关闭）；
//   - PruneGeneration 仅移除指定 (transferID, generation)，若无剩余世代则 transferID 移出 ListActive。
type JournalStore interface {
	Append(ctx context.Context, record fsm.TransferJournalRecord) error
	Load(ctx context.Context, transferID security.OperationID) ([]fsm.TransferJournalRecord, error)
	LoadGenerations(ctx context.Context, transferID security.OperationID) ([]JournalGenerationSnapshot, error)
	PruneGeneration(ctx context.Context, transferID security.OperationID, generation uint64) error
	ListActive(ctx context.Context) ([]security.OperationID, error)
	Delete(ctx context.Context, transferID security.OperationID) error
}

// FormatImporter 定义配置导入层的格式无关扩展端口（ADR-006，如 openssh / csv，100% 零 v1 代码）。
type FormatImporter interface {
	Format() string
	Import(ctx context.Context, sourceName string, r io.Reader) (inventory.ImportBundle, error)
}

// OpenSSHVirtualHostSpec 是构造不可变 OpenSSHVirtualHost 的显式入参规格。
type OpenSSHVirtualHostSpec struct {
	Alias, SourceFile string
	Endpoint          algebraic.Option[netaddr.Endpoint]
	User              algebraic.Option[option.Username]
	Proxy             option.ProxyRoute
	Layer             option.OptionLayer
}

// OpenSSHVirtualHost 表示从只读 ~/.ssh/config 提取的不可变虚拟主机视图（ADR-004）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type OpenSSHVirtualHost struct {
	s     OpenSSHVirtualHostSpec
	valid bool
}

// NewOpenSSHVirtualHost 校验别名、来源路径、可选端点/用户名、代理路由与选项层并构造值对象。
func NewOpenSSHVirtualHost(spec OpenSSHVirtualHostSpec) (OpenSSHVirtualHost, error) {
	alias := strings.TrimSpace(spec.Alias)
	ep, hasEP := spec.Endpoint.Get()
	u, hasU := spec.User.Get()
	if !isValidASCIIToken(alias, maxPortTokenLen) || strings.EqualFold(alias, "none") || (hasEP && !ep.IsValid()) || (hasU && !u.IsValid()) {
		return OpenSSHVirtualHost{}, fieldErr(ErrInvalidArgument, "openssh_virtual_host")
	}
	src, e1 := sanitizeBoundedText(spec.SourceFile, maxPortDetailBytes, true, ErrInvalidArgument)
	if err := firstErr(e1, option.ValidateProxyRoute(spec.Proxy), spec.Layer.Validate()); err != nil {
		return OpenSSHVirtualHost{}, domi18n.WrapSentinel(ErrInvalidArgument, err)
	}
	proxy := pickIf[option.ProxyRoute](spec.Proxy != nil, spec.Proxy, option.NewProxyUnset())
	spec.Alias, spec.SourceFile = alias, src
	spec.Proxy, spec.Layer = option.ComposeProxyRoute(proxy, nil), spec.Layer.Compose(option.UnsetOptionLayer())
	return OpenSSHVirtualHost{s: spec, valid: true}, nil
}
func (h OpenSSHVirtualHost) IsValid() bool                                { return h.valid && h.s.Alias != "" }
func (h OpenSSHVirtualHost) IsZero() bool                                 { return !h.IsValid() }
func (h OpenSSHVirtualHost) Alias() string                                { return h.s.Alias }
func (h OpenSSHVirtualHost) SourceFile() string                           { return h.s.SourceFile }
func (h OpenSSHVirtualHost) Endpoint() algebraic.Option[netaddr.Endpoint] { return h.s.Endpoint }
func (h OpenSSHVirtualHost) User() algebraic.Option[option.Username]      { return h.s.User }
func (h OpenSSHVirtualHost) Proxy() option.ProxyRoute {
	return pickIf[option.ProxyRoute](h.IsValid(), option.ComposeProxyRoute(h.s.Proxy, nil), option.NewProxyUnset())
}
func (h OpenSSHVirtualHost) Layer() option.OptionLayer {
	return pickIf(h.IsValid(), h.s.Layer.Compose(option.UnsetOptionLayer()), option.UnsetOptionLayer())
}
func (h OpenSSHVirtualHost) JumpNode() (inventory.OpenSSHJumpNode, error) {
	if !h.IsValid() {
		return zeroVal[inventory.OpenSSHJumpNode](), ErrInvalidArgument
	}
	return inventory.NewOpenSSHJumpNode(h.s.Alias, h.s.Proxy)
}
func (h OpenSSHVirtualHost) Equal(o OpenSSHVirtualHost) bool {
	return h.IsValid() && o.IsValid() && h.s.Alias == o.s.Alias && h.s.SourceFile == o.s.SourceFile && optEqualFunc(h.s.Endpoint, o.s.Endpoint, netaddr.Endpoint.Equal) && optEqualFunc(h.s.User, o.s.User, option.Username.Equal) && option.EqualProxyRoute(h.s.Proxy, o.s.Proxy) && h.s.Layer.Equal(o.s.Layer)
}

// OpenSSHConfigSource 定义只读 ~/.ssh/config（含递归 Include）虚拟节点源与 Tier-4 选项折叠端口（ADR-004）。
type OpenSSHConfigSource interface {
	ListVirtualHosts(ctx context.Context) ([]OpenSSHVirtualHost, error)
	// ResolveTier4 针对显式原始主机 target 与可选规范化端点 endpoint 折叠返回单一 t4 OptionLayer；
	// endpoint 为 None 时支撑非 DNS 或通配符别名的初始展开，为 Some 时必须携带有效 Endpoint。
	ResolveTier4(ctx context.Context, target option.OriginalHostSpec, endpoint algebraic.Option[netaddr.Endpoint]) (option.OptionLayer, error)
}
