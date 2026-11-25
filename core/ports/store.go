package ports

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/fsm"
	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/security"
)

// Revision 表示资产存储快照的不透明 CAS 版本令牌（如内容哈希或单调世代号）；
// 零值恒无效并严格失败关闭，防止调用方误传零值绕过 CAS 并发冲突检查。
//
//xops:opaque
//xops:failclosed
type Revision struct{ value string }

// ParseRevision 校验并构造不可变 CAS 版本令牌（长度 1..128 的可打印非空白 ASCII）。
func ParseRevision(raw string) (Revision, error) {
	if !isValidASCIIToken(raw, maxPortTokenLen) {
		return Revision{}, fmt.Errorf("%w: %q", ErrInvalidRevision, raw)
	}
	return Revision{value: raw}, nil
}

// Revision 只读访问器、确定性全序与文本编解码方法（零值失败关闭）。
func (r Revision) IsValid() bool          { return r.value != "" }
func (r Revision) IsZero() bool           { return r.value == "" }
func (r Revision) String() string         { return r.value }
func (r Revision) Equal(o Revision) bool  { return r.IsValid() && o.IsValid() && r.value == o.value }
func (r Revision) Compare(o Revision) int { return cmp.Compare(r.value, o.value) }
func (r Revision) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, r.IsValid(), r.value, ErrInvalidRevision)
}
func (r Revision) MarshalText() ([]byte, error) { return r.AppendText(nil) }
func (r *Revision) UnmarshalText(text []byte) error {
	return unmarshalTextWithReset(r, Revision{}, text, ParseRevision)
}

// InventorySnapshot 封装单次加载取得的不可变资产图快照与其对应的 CAS 版本令牌；零值恒无效。
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
		return InventorySnapshot{}, fmt.Errorf("%w: 快照必须携带有效 Revision", ErrInvalidRevision)
	}
	if !graph.IsValid() {
		return InventorySnapshot{}, fmt.Errorf("%w: %w", ErrInvalidArgument, inventory.ErrInvalidGraph)
	}
	return InventorySnapshot{revision: revision, graph: graph, valid: true}, nil
}

// InventorySnapshot 只读访问器（零值失败关闭）。
func (s InventorySnapshot) IsValid() bool {
	return s.valid && s.revision.IsValid() && s.graph.IsValid()
}
func (s InventorySnapshot) IsZero() bool           { return !s.IsValid() }
func (s InventorySnapshot) Revision() Revision     { return s.revision }
func (s InventorySnapshot) Graph() inventory.Graph { return s.graph }

// DurabilityOutcome 表示配置 CAS 提交后的结构化持久化结果（INV-F3 / RFC §2.1）：
// 严格区分 Committed、NotApplied、AppliedNotDurable（Applied && !Durable，严禁重试或删凭据）与 OutcomeUnknown。
//
//xops:opaque
//xops:failclosed
type DurabilityOutcome struct {
	status   fsm.DurabilityStatus
	revision algebraic.Option[Revision]
	detail   string
	valid    bool
}

// NewDurabilityCommitted 构造确认已生效且已落盘（Applied && Durable）的提交结果，必须附带有效新 Revision。
func NewDurabilityCommitted(revision Revision) (DurabilityOutcome, error) {
	if !revision.IsValid() {
		return DurabilityOutcome{}, fmt.Errorf("%w: committed 结果必须携带有效新 Revision", ErrInvalidDurability)
	}
	return DurabilityOutcome{status: fsm.DurabilityCommitted, revision: algebraic.Some(revision), valid: true}, nil
}

// NewDurabilityNotApplied 构造确认未生效（可安全补偿）的提交结果。
func NewDurabilityNotApplied(detail string) (DurabilityOutcome, error) {
	clean, err := sanitizeBoundedText(detail, maxPortDetailBytes, true, ErrInvalidDurability)
	if err != nil {
		return DurabilityOutcome{}, err
	}
	return DurabilityOutcome{status: fsm.DurabilityNotApplied, detail: clean, valid: true}, nil
}

// NewDurabilityAppliedNotDurable 构造已生效但未确认落盘（Applied && !Durable）的停机结果；
// 调用方遇此状态必须进入 VaultSagaFSM.UncertainDurability，严禁自动重试或删除旧凭据。
func NewDurabilityAppliedNotDurable(revision algebraic.Option[Revision], detail string) (DurabilityOutcome, error) {
	if rev, ok := revision.Get(); ok && !rev.IsValid() {
		return DurabilityOutcome{}, fmt.Errorf("%w: 可选 Revision 无效", ErrInvalidDurability)
	}
	clean, err := sanitizeBoundedText(detail, maxPortDetailBytes, false, ErrInvalidDurability)
	if err != nil {
		return DurabilityOutcome{}, err
	}
	return DurabilityOutcome{status: fsm.DurabilityAppliedNotDurable, revision: revision, detail: clean, valid: true}, nil
}

// NewDurabilityOutcomeUnknown 构造提交结果未知的失败关闭结果（严禁自动重试）。
func NewDurabilityOutcomeUnknown(detail string) (DurabilityOutcome, error) {
	clean, err := sanitizeBoundedText(detail, maxPortDetailBytes, false, ErrInvalidDurability)
	if err != nil {
		return DurabilityOutcome{}, err
	}
	return DurabilityOutcome{status: fsm.DurabilityOutcomeUnknown, detail: clean, valid: true}, nil
}

// IsValid 报告 DurabilityOutcome 是否经构造器合法初始化并满足状态与版本一致性。
func (d DurabilityOutcome) IsValid() bool {
	if !d.valid || !d.status.IsValid() {
		return false
	}
	if d.status == fsm.DurabilityCommitted {
		rev, ok := d.revision.Get()
		return ok && rev.IsValid()
	}
	if d.status == fsm.DurabilityAppliedNotDurable {
		rev, ok := d.revision.Get()
		return d.detail != "" && (!ok || rev.IsValid())
	}
	return d.revision.IsNone() && (d.status == fsm.DurabilityNotApplied || d.detail != "")
}

// DurabilityOutcome 只读访问器与等价比对（无效零值永不相等）。
func (d DurabilityOutcome) IsZero() bool { return !d.IsValid() }
func (d DurabilityOutcome) Status() fsm.DurabilityStatus {
	return pickIf(d.IsValid(), d.status, fsm.DurabilityUnknown)
}
func (d DurabilityOutcome) Applied() bool                        { return d.IsValid() && d.status.Applied() }
func (d DurabilityOutcome) Durable() bool                        { return d.IsValid() && d.status.Durable() }
func (d DurabilityOutcome) Revision() algebraic.Option[Revision] { return d.revision }
func (d DurabilityOutcome) Detail() string                       { return d.detail }
func (d DurabilityOutcome) Equal(o DurabilityOutcome) bool {
	return d.IsValid() && o.IsValid() && d.status == o.status && d.detail == o.detail &&
		optEqualFunc(d.revision, o.revision, Revision.Equal)
}

// InventoryStore 定义本地资产配置的原子加载与 CAS 持久化出站端口（INV-F1 / INV-F3）。
// 实现方在 Load 与 CommitCAS 双端均须强制校验资产图全图不变量，并以旁路锁加原子替换落盘。
type InventoryStore interface {
	// Load 读取当前持久化配置并返回已校验的资产图快照与 CAS 版本令牌。
	Load(ctx context.Context) (InventorySnapshot, error)
	// CommitCAS 仅在当前存储版本严格等于 expected 时原子提交 next 资产图；
	// 版本不匹配返回 ErrRevisionConflict，持久化结果通过 DurabilityOutcome 精确汇报。
	CommitCAS(ctx context.Context, expected Revision, next inventory.Graph) (DurabilityOutcome, error)
}

// JournalStore 定义可恢复分片文件传输（最高 10 GiB）双版本 WAL/Journal 持久化出站端口。
type JournalStore interface {
	// Append 同步追加一条已校验的传输 Journal 记录并保证持久落盘。
	Append(ctx context.Context, record fsm.TransferJournalRecord) error
	// Load 按写入顺序加载指定 transferID 的全部 Journal 记录；不存在时返回 ErrNotFound。
	Load(ctx context.Context, transferID security.OperationID) ([]fsm.TransferJournalRecord, error)
	// ListActive 列举当前存在未清理 Journal 的全部传输操作标识（确定性排序）。
	ListActive(ctx context.Context) ([]security.OperationID, error)
	// Delete 清理已完成或已终止传输对应的 Journal；不存在时返回 ErrNotFound。
	Delete(ctx context.Context, transferID security.OperationID) error
}

// FormatImporter 定义配置导入层的格式无关扩展端口（ADR-006，如 openssh / csv，100% 零 v1 代码）。
type FormatImporter interface {
	// Format 返回导入器负责的规范小写格式标识（如 "openssh"、"csv"）。
	Format() string
	// Import 从输入流 r 解析外部配置并产出已校验、确定性排序的 inventory.ImportBundle。
	Import(ctx context.Context, sourceName string, r io.Reader) (inventory.ImportBundle, error)
}

// OpenSSHVirtualHostSpec 是构造不可变 OpenSSHVirtualHost 的显式入参规格。
type OpenSSHVirtualHostSpec struct {
	Alias      string
	SourceFile string
	Endpoint   algebraic.Option[netaddr.Endpoint]
	User       algebraic.Option[option.Username]
	Proxy      option.ProxyRoute
	Layer      option.OptionLayer
}

// OpenSSHVirtualHost 表示从只读 ~/.ssh/config 提取的不可变虚拟主机视图（ADR-004）；零值恒无效。
//
//xops:opaque
//xops:failclosed
type OpenSSHVirtualHost struct {
	alias      string
	sourceFile string
	endpoint   algebraic.Option[netaddr.Endpoint]
	user       algebraic.Option[option.Username]
	proxy      option.ProxyRoute
	layer      option.OptionLayer
	valid      bool
}

// NewOpenSSHVirtualHost 校验 OpenSSH 虚拟主机别名、来源路径、可选端点/用户名、代理路由与选项层并构造值对象。
func NewOpenSSHVirtualHost(spec OpenSSHVirtualHostSpec) (OpenSSHVirtualHost, error) {
	alias := strings.TrimSpace(spec.Alias)
	if !isValidASCIIToken(alias, maxPortTokenLen) || strings.EqualFold(alias, "none") {
		return OpenSSHVirtualHost{}, fmt.Errorf("%w: 非法 OpenSSH 别名 %q", ErrInvalidArgument, spec.Alias)
	}
	src, err := sanitizeBoundedText(spec.SourceFile, maxPortDetailBytes, true, ErrInvalidArgument)
	if err != nil {
		return OpenSSHVirtualHost{}, err
	}
	if err := validateOpenSSHVirtualHostFields(spec); err != nil {
		return OpenSSHVirtualHost{}, err
	}
	proxy := spec.Proxy
	if proxy == nil {
		proxy = option.NewProxyUnset()
	}
	return OpenSSHVirtualHost{
		alias: alias, sourceFile: src, endpoint: spec.Endpoint, user: spec.User,
		proxy: option.ComposeProxyRoute(proxy, nil), layer: spec.Layer.Compose(option.UnsetOptionLayer()), valid: true,
	}, nil
}

func validateOpenSSHVirtualHostFields(spec OpenSSHVirtualHostSpec) error {
	if ep, ok := spec.Endpoint.Get(); ok && !ep.IsValid() {
		return fmt.Errorf("%w: endpoint 无效", ErrInvalidArgument)
	}
	if u, ok := spec.User.Get(); ok && !u.IsValid() {
		return fmt.Errorf("%w: user 无效", ErrInvalidArgument)
	}
	if err := option.ValidateProxyRoute(spec.Proxy); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	if err := spec.Layer.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	return nil
}

// OpenSSHVirtualHost 只读访问器、DAG 顶点投影与严格等价比对。
func (h OpenSSHVirtualHost) IsValid() bool                                { return h.valid && h.alias != "" }
func (h OpenSSHVirtualHost) IsZero() bool                                 { return !h.IsValid() }
func (h OpenSSHVirtualHost) Alias() string                                { return h.alias }
func (h OpenSSHVirtualHost) SourceFile() string                           { return h.sourceFile }
func (h OpenSSHVirtualHost) Endpoint() algebraic.Option[netaddr.Endpoint] { return h.endpoint }
func (h OpenSSHVirtualHost) User() algebraic.Option[option.Username]      { return h.user }
func (h OpenSSHVirtualHost) Proxy() option.ProxyRoute {
	if !h.IsValid() {
		return option.NewProxyUnset()
	}
	return option.ComposeProxyRoute(h.proxy, nil)
}
func (h OpenSSHVirtualHost) Layer() option.OptionLayer {
	if !h.IsValid() {
		return option.UnsetOptionLayer()
	}
	return h.layer.Compose(option.UnsetOptionLayer())
}
func (h OpenSSHVirtualHost) JumpNode() (inventory.OpenSSHJumpNode, error) {
	if !h.IsValid() {
		return zeroVal[inventory.OpenSSHJumpNode](), ErrInvalidArgument
	}
	return inventory.NewOpenSSHJumpNode(h.alias, h.proxy)
}
func (h OpenSSHVirtualHost) Equal(o OpenSSHVirtualHost) bool {
	return h.IsValid() && o.IsValid() && h.alias == o.alias && h.sourceFile == o.sourceFile &&
		optEqualFunc(h.endpoint, o.endpoint, netaddr.Endpoint.Equal) &&
		optEqualFunc(h.user, o.user, option.Username.Equal) &&
		option.EqualProxyRoute(h.proxy, o.proxy) && h.layer.Equal(o.layer)
}

// OpenSSHConfigSource 定义只读 ~/.ssh/config（含递归 Include）虚拟节点源与 Tier-4 选项折叠端口（ADR-004）。
// 实现方必须将单份配置中全部命中的 Host/Match/Include 指令按遭遇序自上而下经 ApplyParsedOption 折叠为单一 t4 OptionLayer。
type OpenSSHConfigSource interface {
	// ListVirtualHosts 列举 ~/.ssh/config 中全部只读虚拟主机条目（用于目标解析与跨命名空间 DAG 校验）。
	ListVirtualHosts(ctx context.Context) ([]OpenSSHVirtualHost, error)
	// ResolveTier4 针对显式原始主机 target 与规范化端点 endpoint 折叠返回单一 t4 OptionLayer。
	ResolveTier4(ctx context.Context, target option.OriginalHostSpec, endpoint netaddr.Endpoint) (option.OptionLayer, error)
}
