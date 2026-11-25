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

// Revision 表示资产存储快照的不透明 CAS 版本令牌；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type Revision struct{ value string }

// ParseRevision 校验并构造不可变 CAS 版本令牌（1..128 位可打印非空白 ASCII）。
func ParseRevision(raw string) (Revision, error) {
	if !isValidASCIIToken(raw, maxPortTokenLen) {
		return Revision{}, fmt.Errorf("%w: %q", ErrInvalidRevision, raw)
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
		return InventorySnapshot{}, fmt.Errorf("%w: 快照必须携带有效 Revision", ErrInvalidRevision)
	}
	if !graph.IsValid() {
		return InventorySnapshot{}, fmt.Errorf("%w: %w", ErrInvalidArgument, inventory.ErrInvalidGraph)
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
		return DurabilityOutcome{}, fmt.Errorf("%w: committed 必须携带有效 Revision", ErrInvalidDurability)
	}
	return DurabilityOutcome{status: fsm.DurabilityCommitted, revision: algebraic.Some(revision), valid: true}, nil
}

// NewDurabilityNotApplied 构造确认未生效（可安全补偿）的提交结果。
func NewDurabilityNotApplied(detail string) (DurabilityOutcome, error) {
	clean, err := sanitizeBoundedText(detail, maxPortDetailBytes, true, ErrInvalidDurability)
	return DurabilityOutcome{status: fsm.DurabilityNotApplied, detail: clean, valid: err == nil}, err
}

// NewDurabilityAppliedNotDurable 构造已生效但未确认落盘（Applied && !Durable）的停机结果。
func NewDurabilityAppliedNotDurable(revision algebraic.Option[Revision], detail string) (DurabilityOutcome, error) {
	if rev, ok := revision.Get(); ok && !rev.IsValid() {
		return DurabilityOutcome{}, fmt.Errorf("%w: 可选 Revision 无效", ErrInvalidDurability)
	}
	clean, err := sanitizeBoundedText(detail, maxPortDetailBytes, false, ErrInvalidDurability)
	return DurabilityOutcome{status: fsm.DurabilityAppliedNotDurable, revision: revision, detail: clean, valid: err == nil}, err
}

// NewDurabilityOutcomeUnknown 构造提交结果未知的失败关闭结果（严禁自动重试）。
func NewDurabilityOutcomeUnknown(detail string) (DurabilityOutcome, error) {
	clean, err := sanitizeBoundedText(detail, maxPortDetailBytes, false, ErrInvalidDurability)
	return DurabilityOutcome{status: fsm.DurabilityOutcomeUnknown, detail: clean, valid: err == nil}, err
}
func (d DurabilityOutcome) IsValid() bool {
	if !d.valid || !d.status.IsValid() {
		return false
	}
	rev, ok := d.revision.Get()
	switch d.status {
	case fsm.DurabilityCommitted:
		return ok && rev.IsValid()
	case fsm.DurabilityAppliedNotDurable:
		return d.detail != "" && (!ok || rev.IsValid())
	default:
		return !ok && (d.status == fsm.DurabilityNotApplied || d.detail != "")
	}
}
func (d DurabilityOutcome) IsZero() bool { return !d.IsValid() }
func (d DurabilityOutcome) Status() fsm.DurabilityStatus {
	return pickIf(d.IsValid(), d.status, fsm.DurabilityUnknown)
}
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

// JournalStore 定义可恢复分片文件传输（最高 10 GiB）双版本 WAL/Journal 持久化出站端口。
type JournalStore interface {
	Append(ctx context.Context, record fsm.TransferJournalRecord) error
	Load(ctx context.Context, transferID security.OperationID) ([]fsm.TransferJournalRecord, error)
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
	alias, sourceFile string
	endpoint          algebraic.Option[netaddr.Endpoint]
	user              algebraic.Option[option.Username]
	proxy             option.ProxyRoute
	layer             option.OptionLayer
	valid             bool
}

// NewOpenSSHVirtualHost 校验别名、来源路径、可选端点/用户名、代理路由与选项层并构造值对象。
func NewOpenSSHVirtualHost(spec OpenSSHVirtualHostSpec) (OpenSSHVirtualHost, error) {
	alias := strings.TrimSpace(spec.Alias)
	if !isValidASCIIToken(alias, maxPortTokenLen) || strings.EqualFold(alias, "none") {
		return OpenSSHVirtualHost{}, fmt.Errorf("%w: 非法 OpenSSH 别名 %q", ErrInvalidArgument, spec.Alias)
	}
	src, e1 := sanitizeBoundedText(spec.SourceFile, maxPortDetailBytes, true, ErrInvalidArgument)
	if err := firstErr(e1, validateOpenSSHVirtualHostFields(spec)); err != nil {
		return OpenSSHVirtualHost{}, err
	}
	proxy := pickIf[option.ProxyRoute](spec.Proxy != nil, spec.Proxy, option.NewProxyUnset())
	return OpenSSHVirtualHost{
		alias: alias, sourceFile: src, endpoint: spec.Endpoint, user: spec.User,
		proxy: option.ComposeProxyRoute(proxy, nil), layer: spec.Layer.Compose(option.UnsetOptionLayer()), valid: true,
	}, nil
}

func validateOpenSSHVirtualHostFields(spec OpenSSHVirtualHostSpec) error {
	ep, hasEP := spec.Endpoint.Get()
	u, hasU := spec.User.Get()
	if (hasEP && !ep.IsValid()) || (hasU && !u.IsValid()) {
		return fmt.Errorf("%w: endpoint 或 user 无效", ErrInvalidArgument)
	}
	if err := firstErr(option.ValidateProxyRoute(spec.Proxy), spec.Layer.Validate()); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	return nil
}
func (h OpenSSHVirtualHost) IsValid() bool                                { return h.valid && h.alias != "" }
func (h OpenSSHVirtualHost) IsZero() bool                                 { return !h.IsValid() }
func (h OpenSSHVirtualHost) Alias() string                                { return h.alias }
func (h OpenSSHVirtualHost) SourceFile() string                           { return h.sourceFile }
func (h OpenSSHVirtualHost) Endpoint() algebraic.Option[netaddr.Endpoint] { return h.endpoint }
func (h OpenSSHVirtualHost) User() algebraic.Option[option.Username]      { return h.user }
func (h OpenSSHVirtualHost) Proxy() option.ProxyRoute {
	return pickIf[option.ProxyRoute](h.IsValid(), option.ComposeProxyRoute(h.proxy, nil), option.NewProxyUnset())
}
func (h OpenSSHVirtualHost) Layer() option.OptionLayer {
	return pickIf(h.IsValid(), h.layer.Compose(option.UnsetOptionLayer()), option.UnsetOptionLayer())
}
func (h OpenSSHVirtualHost) JumpNode() (inventory.OpenSSHJumpNode, error) {
	if !h.IsValid() {
		return zeroVal[inventory.OpenSSHJumpNode](), ErrInvalidArgument
	}
	return inventory.NewOpenSSHJumpNode(h.alias, h.proxy)
}
func (h OpenSSHVirtualHost) Equal(o OpenSSHVirtualHost) bool {
	return h.IsValid() && o.IsValid() && h.alias == o.alias && h.sourceFile == o.sourceFile &&
		optEqualFunc(h.endpoint, o.endpoint, netaddr.Endpoint.Equal) && optEqualFunc(h.user, o.user, option.Username.Equal) &&
		option.EqualProxyRoute(h.proxy, o.proxy) && h.layer.Equal(o.layer)
}

// OpenSSHConfigSource 定义只读 ~/.ssh/config（含递归 Include）虚拟节点源与 Tier-4 选项折叠端口（ADR-004）。
type OpenSSHConfigSource interface {
	ListVirtualHosts(ctx context.Context) ([]OpenSSHVirtualHost, error)
	// ResolveTier4 针对显式原始主机 target 与可选规范化端点 endpoint 折叠返回单一 t4 OptionLayer；
	// endpoint 为 None 时支撑非 DNS 或通配符别名的初始展开，为 Some 时必须携带有效 Endpoint。
	ResolveTier4(ctx context.Context, target option.OriginalHostSpec, endpoint algebraic.Option[netaddr.Endpoint]) (option.OptionLayer, error)
}
