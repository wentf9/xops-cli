package inventory

import (
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/algebraic"
	"github.com/wentf9/xops-cli/core/domain/execution"
	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/netaddr"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

// NodeOrigin 是节点来源分类的封闭代数和类型（RFC §3.6 / INV-D2）：
// *OriginManaged | *OriginOpenSSHVirtual | *OriginOpenSSHDerived | *OriginAdHoc。
//
//xops:failclosed
type NodeOrigin interface {
	sealedNodeOrigin()
	Kind() option.OriginKind
	AllowsFullOpenSSHConfig() bool
	IsValid() bool
}

// OriginManaged、OriginOpenSSHVirtual、OriginOpenSSHDerived 与 OriginAdHoc 为全部封闭来源变体（不可变）。
//
//xops:opaque
//xops:failclosed
type OriginManaged struct{ valid bool }

//xops:opaque
//xops:failclosed
type OriginOpenSSHVirtual struct {
	hostPattern, sourceFile string
	valid                   bool
}

//xops:opaque
//xops:failclosed
type OriginOpenSSHDerived struct {
	baseAlias, sourceFile string
	valid                 bool
}

//xops:opaque
//xops:failclosed
type OriginAdHoc struct {
	parentNode algebraic.Option[NodeID]
	valid      bool
}

// NewOriginManaged、NewOriginOpenSSHVirtual、NewOriginOpenSSHDerived 与 NewOriginAdHoc 构造节点来源。
func NewOriginManaged() *OriginManaged { return &OriginManaged{true} }
func NewOriginOpenSSHVirtual(hostPattern, sourceFile string) (*OriginOpenSSHVirtual, error) {
	pat, src, err := validateOpenSSHOriginMeta(hostPattern, sourceFile)
	return pickIf(err == nil, &OriginOpenSSHVirtual{pat, src, true}, nil), err
}
func NewOriginOpenSSHDerived(baseAlias, sourceFile string) (*OriginOpenSSHDerived, error) {
	alias, src, err := validateOpenSSHOriginMeta(baseAlias, sourceFile)
	return pickIf(err == nil, &OriginOpenSSHDerived{alias, src, true}, nil), err
}
func NewOriginAdHoc(parentNode algebraic.Option[NodeID]) (*OriginAdHoc, error) {
	if pid, ok := parentNode.Get(); ok && !pid.IsValid() {
		return nil, domi18n.EF(ErrInvalidNodeOrigin, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "parent_node"))
	}
	return &OriginAdHoc{parentNode, true}, nil
}
func validateOpenSSHOriginMeta(token, sourceFile string) (string, string, error) {
	t := strings.TrimSpace(token)
	if t == "" || len(t) > maxIDLen || hasSpaceOrForbidden(t) {
		return "", "", domi18n.EF(ErrInvalidNodeOrigin, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "openssh_origin"), domi18n.BoundStr("value", token))
	}
	src, err := sanitizeSingleLine(strings.TrimSpace(sourceFile), maxKeyPathBytes)
	if err != nil {
		return "", "", domi18n.WrapS(ErrInvalidNodeOrigin, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "source_file"))
	}
	return t, src, nil
}

func (*OriginManaged) sealedNodeOrigin()        {}
func (*OriginOpenSSHVirtual) sealedNodeOrigin() {}
func (*OriginOpenSSHDerived) sealedNodeOrigin() {}
func (*OriginAdHoc) sealedNodeOrigin()          {}

// 四类节点来源变体的零值与 nil 安全只读访问器。
func (o *OriginManaged) IsValid() bool               { return o != nil && o.valid }
func (o *OriginManaged) Kind() option.OriginKind     { return kindIf(o.IsValid(), option.OriginManaged) }
func (*OriginManaged) AllowsFullOpenSSHConfig() bool { return false }
func (o *OriginOpenSSHVirtual) IsValid() bool        { return o != nil && o.valid && o.hostPattern != "" }
func (o *OriginOpenSSHVirtual) Kind() option.OriginKind {
	return kindIf(o.IsValid(), option.OriginOpenSSHVirtual)
}
func (o *OriginOpenSSHVirtual) AllowsFullOpenSSHConfig() bool { return o.IsValid() }
func (o *OriginOpenSSHVirtual) HostPattern() string {
	return getValid(o, func(v *OriginOpenSSHVirtual) string { return v.hostPattern })
}
func (o *OriginOpenSSHVirtual) SourceFile() string {
	return getValid(o, func(v *OriginOpenSSHVirtual) string { return v.sourceFile })
}
func (o *OriginOpenSSHDerived) IsValid() bool { return o != nil && o.valid && o.baseAlias != "" }
func (o *OriginOpenSSHDerived) Kind() option.OriginKind {
	return kindIf(o.IsValid(), option.OriginOpenSSHDerived)
}
func (o *OriginOpenSSHDerived) AllowsFullOpenSSHConfig() bool { return o.IsValid() }
func (o *OriginOpenSSHDerived) BaseAlias() string {
	return getValid(o, func(v *OriginOpenSSHDerived) string { return v.baseAlias })
}
func (o *OriginOpenSSHDerived) SourceFile() string {
	return getValid(o, func(v *OriginOpenSSHDerived) string { return v.sourceFile })
}
func (o *OriginAdHoc) IsValid() bool               { return o != nil && o.valid }
func (o *OriginAdHoc) Kind() option.OriginKind     { return kindIf(o.IsValid(), option.OriginAdHoc) }
func (*OriginAdHoc) AllowsFullOpenSSHConfig() bool { return false }
func (o *OriginAdHoc) ParentNode() algebraic.Option[NodeID] {
	return getValid(o, func(v *OriginAdHoc) algebraic.Option[NodeID] { return v.parentNode })
}

// ToOptionOriginKind 穷尽地将 NodeOrigin 投影为 option.OriginKind；nil 或无效变体返回 option.OriginInvalid。
func ToOptionOriginKind(origin NodeOrigin) option.OriginKind {
	if origin == nil {
		return option.OriginInvalid
	}
	switch v := origin.(type) {
	case *OriginManaged, *OriginOpenSSHVirtual, *OriginOpenSSHDerived, *OriginAdHoc:
		return v.Kind()
	default:
		return option.OriginInvalid
	}
}

// EqualNodeOrigin 严格比对两个 NodeOrigin 是否均有效且完全一致（nil 或零值恒返回 false）。
func EqualNodeOrigin(a, b NodeOrigin) bool {
	if a == nil || b == nil || !a.IsValid() || !b.IsValid() {
		return false
	}
	switch va := a.(type) {
	case *OriginManaged:
		vb, ok := b.(*OriginManaged)
		return ok && vb.IsValid()
	case *OriginOpenSSHVirtual:
		vb, ok := b.(*OriginOpenSSHVirtual)
		return ok && vb.IsValid() && va.hostPattern == vb.hostPattern && va.sourceFile == vb.sourceFile
	case *OriginOpenSSHDerived:
		vb, ok := b.(*OriginOpenSSHDerived)
		return ok && vb.IsValid() && va.baseAlias == vb.baseAlias && va.sourceFile == vb.sourceFile
	case *OriginAdHoc:
		vb, ok := b.(*OriginAdHoc)
		return ok && vb.IsValid() && algebraic.EqualOption(va.parentNode, vb.parentNode)
	default:
		return false
	}
}

// HostSpec、IdentitySpec 与 NodeSpec 是构造不可变核心资产实体的显式入参规格。
type (
	HostSpec struct {
		ID          HostID
		Endpoint    netaddr.Endpoint
		Alias       algebraic.Option[Alias]
		Description string
		Tags        []Tag
	}
	IdentitySpec struct {
		ID          IdentityID
		User        option.Username
		Auth        AuthMethod
		Description string
		Tags        []Tag
	}
	NodeSpec struct {
		ID                   NodeID
		HostRef              HostID
		IdentityRef          IdentityID
		Aliases              []Alias
		Tags                 []Tag
		Proxy                option.ProxyRoute
		Execution            algebraic.Option[execution.LaunchProfile]
		Options              option.OptionLayer
		PrivilegePasswordRef algebraic.Option[secret.Ref]
		Origin               NodeOrigin
		Description          string
	}
)

// Host、Identity 与 Node 分别为资产图中的不可变主机端点、认证身份与目标节点实体；零值恒无效并失败关闭。
//
//xops:opaque
//xops:failclosed
type Host struct {
	id          HostID
	endpoint    netaddr.Endpoint
	alias       algebraic.Option[Alias]
	description string
	tags        []Tag
	valid       bool
}

//xops:opaque
//xops:failclosed
type Identity struct {
	id          IdentityID
	user        option.Username
	auth        AuthMethod
	description string
	tags        []Tag
	valid       bool
}

//xops:opaque
//xops:failclosed
type Node struct {
	id                   NodeID
	hostRef              HostID
	identityRef          IdentityID
	aliases              []Alias
	tags                 []Tag
	proxy                option.ProxyRoute
	execution            algebraic.Option[execution.LaunchProfile]
	options              option.OptionLayer
	privilegePasswordRef algebraic.Option[secret.Ref]
	origin               NodeOrigin
	description          string
	valid                bool
}

// NewHost 校验主机标识、端点、可选别名（不得与自身 HostID 同名）、描述与标签并构造不可变 Host。
func NewHost(spec HostSpec) (Host, error) {
	if !spec.ID.IsValid() || !spec.Endpoint.IsValid() {
		return Host{}, domi18n.EF(ErrInvalidHost, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "id/endpoint"))
	}
	if a, ok := spec.Alias.Get(); ok && (!a.IsValid() || a.String() == spec.ID.String()) {
		return Host{}, domi18n.EF(ErrInvalidHost, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "host.alias"))
	}
	desc, tags, err := sanitizeDescAndTags(spec.Description, spec.Tags, ErrInvalidHost)
	if err != nil {
		return Host{}, err
	}
	return Host{spec.ID, spec.Endpoint, spec.Alias, desc, tags, true}, nil
}

// NewIdentity 校验身份标识、用户名、不可变认证方式与标签并构造不可变 Identity。
func NewIdentity(spec IdentitySpec) (Identity, error) {
	if !spec.ID.IsValid() || !spec.User.IsValid() {
		return Identity{}, domi18n.EF(ErrInvalidIdentity, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "id/user"))
	}
	if err := validateAuthMethodDepth(spec.Auth, 1, make(map[*AuthComposite]bool)); err != nil {
		return Identity{}, domi18n.WrapSentinel(ErrInvalidIdentity, err)
	}
	desc, tags, err := sanitizeDescAndTags(spec.Description, spec.Tags, ErrInvalidIdentity)
	if err != nil {
		return Identity{}, err
	}
	return Identity{spec.ID, spec.User, spec.Auth, desc, tags, true}, nil
}

// NewNode 校验节点关联标识、别名/标签、代理路由、执行配置、选项层、提权凭据与来源，构造不可变 Node。
func NewNode(spec NodeSpec) (Node, error) {
	if err := validateNodeHeader(spec); err != nil {
		return Node{}, err
	}
	aliases, err := canonicalizeAliases(spec.Aliases, spec.ID)
	if err != nil {
		return Node{}, domi18n.WrapSentinel(ErrInvalidNode, err)
	}
	desc, tags, err := sanitizeDescAndTags(spec.Description, spec.Tags, ErrInvalidNode)
	if err != nil {
		return Node{}, err
	}
	proxy := pickIf(spec.Proxy != nil, spec.Proxy, option.ProxyRoute(option.NewProxyUnset()))
	return Node{
		spec.ID, spec.HostRef, spec.IdentityRef, aliases, tags,
		option.ComposeProxyRoute(proxy, nil), spec.Execution,
		spec.Options.Compose(option.UnsetOptionLayer()), spec.PrivilegePasswordRef, spec.Origin, desc, true,
	}, nil
}

func validateNodeHeader(spec NodeSpec) error {
	prof, hasProf := spec.Execution.Get()
	ref, hasRef := spec.PrivilegePasswordRef.Get()
	switch {
	case !spec.ID.IsValid() || !spec.HostRef.IsValid() || !spec.IdentityRef.IsValid():
		return domi18n.EF(ErrInvalidNode, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "id/host_ref/identity_ref"))
	case spec.Origin == nil || !spec.Origin.IsValid():
		return domi18n.WrapSentinel(ErrInvalidNode, ErrInvalidNodeOrigin)
	case option.ValidateProxyRoute(spec.Proxy) != nil || spec.Options.Validate() != nil || (hasProf && !prof.IsValid()) || (hasRef && !ref.IsValid()):
		return domi18n.EF(ErrInvalidNode, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "node_options"))
	}
	return nil
}

func sanitizeDescAndTags(rawDesc string, rawTags []Tag, baseErr error) (string, []Tag, error) {
	desc, err := sanitizeSingleLine(rawDesc, maxDescriptionBytes)
	if err != nil {
		return "", nil, domi18n.WrapS(baseErr, err, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "description"))
	}
	if len(rawTags) == 0 {
		return desc, nil, nil
	}
	if len(rawTags) > maxTagsOrAliases || slices.ContainsFunc(rawTags, Tag.IsZero) {
		return "", nil, domi18n.EF(baseErr, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "tags"))
	}
	tags := slices.Clone(rawTags)
	slices.SortFunc(tags, Tag.Compare)
	return desc, slices.CompactFunc(tags, Tag.Equal), nil
}

func canonicalizeAliases(raw []Alias, selfID NodeID) ([]Alias, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxTagsOrAliases || slices.ContainsFunc(raw, func(a Alias) bool { return !a.IsValid() || a.String() == selfID.String() }) {
		return nil, domi18n.E(domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "aliases"))
	}
	out := slices.Clone(raw)
	slices.SortFunc(out, Alias.Compare)
	return slices.CompactFunc(out, Alias.Equal), nil
}

// Host、Identity 与 Node 只读访问器与值等价判定。
func (h Host) IsValid() bool                  { return h.valid && h.id.IsValid() && h.endpoint.IsValid() }
func (h Host) IsZero() bool                   { return !h.IsValid() }
func (h Host) ID() HostID                     { return h.id }
func (h Host) Endpoint() netaddr.Endpoint     { return h.endpoint }
func (h Host) Alias() algebraic.Option[Alias] { return h.alias }
func (h Host) Description() string            { return h.description }
func (h Host) Tags() []Tag                    { return slices.Clone(h.tags) }
func (h Host) Equal(o Host) bool {
	return h.IsValid() && o.IsValid() && h.id.Equal(o.id) && h.endpoint.Equal(o.endpoint) &&
		algebraic.EqualOption(h.alias, o.alias) && h.description == o.description && slices.EqualFunc(h.tags, o.tags, Tag.Equal)
}
func (id Identity) IsValid() bool {
	return id.valid && id.id.IsValid() && id.user.IsValid() && id.auth != nil && id.auth.IsValid()
}
func (id Identity) IsZero() bool          { return !id.IsValid() }
func (id Identity) ID() IdentityID        { return id.id }
func (id Identity) User() option.Username { return id.user }
func (id Identity) Description() string   { return id.description }
func (id Identity) Tags() []Tag           { return slices.Clone(id.tags) }
func (id Identity) Auth() AuthMethod      { return pickIf(id.IsValid(), id.auth, nil) }
func (id Identity) Equal(o Identity) bool {
	return id.IsValid() && o.IsValid() && id.id.Equal(o.id) && id.user.Equal(o.user) &&
		EqualAuthMethod(id.auth, o.auth) && id.description == o.description && slices.EqualFunc(id.tags, o.tags, Tag.Equal)
}
func (n Node) IsValid() bool {
	return n.valid && n.id.IsValid() && n.hostRef.IsValid() && n.identityRef.IsValid() && n.origin != nil && n.origin.IsValid()
}
func (n Node) IsZero() bool                                         { return !n.IsValid() }
func (n Node) ID() NodeID                                           { return n.id }
func (n Node) HostRef() HostID                                      { return n.hostRef }
func (n Node) IdentityRef() IdentityID                              { return n.identityRef }
func (n Node) Aliases() []Alias                                     { return slices.Clone(n.aliases) }
func (n Node) Tags() []Tag                                          { return slices.Clone(n.tags) }
func (n Node) Execution() algebraic.Option[execution.LaunchProfile] { return n.execution }
func (n Node) Options() option.OptionLayer                          { return n.options.Compose(option.UnsetOptionLayer()) }
func (n Node) PrivilegePasswordRef() algebraic.Option[secret.Ref]   { return n.privilegePasswordRef }
func (n Node) Description() string                                  { return n.description }
func (n Node) Origin() NodeOrigin                                   { return pickIf(n.IsValid(), n.origin, nil) }
func (n Node) OriginKind() option.OriginKind {
	return pickIf(n.IsValid(), ToOptionOriginKind(n.origin), option.OriginInvalid)
}
func (n Node) Proxy() option.ProxyRoute {
	return pickIf(n.IsValid() && n.proxy != nil, option.ComposeProxyRoute(n.proxy, nil), option.ProxyRoute(option.NewProxyUnset()))
}
func (n Node) EffectiveProxy() option.ProxyRoute {
	return pickIf(n.IsValid(), option.ComposeProxyRoute(n.proxy, n.options.Proxy()), option.ProxyRoute(option.NewProxyDisabled()))
}
func (n Node) Equal(o Node) bool {
	return n.IsValid() && o.IsValid() && n.id.Equal(o.id) && n.hostRef.Equal(o.hostRef) && n.identityRef.Equal(o.identityRef) &&
		slices.EqualFunc(n.aliases, o.aliases, Alias.Equal) && slices.EqualFunc(n.tags, o.tags, Tag.Equal) &&
		option.EqualProxyRoute(n.proxy, o.proxy) && equalOptionFunc(n.execution, o.execution, execution.LaunchProfile.Equal) &&
		n.options.Equal(o.options) && equalOptionFunc(n.privilegePasswordRef, o.privilegePasswordRef, secret.Ref.Equal) &&
		EqualNodeOrigin(n.origin, o.origin) && n.description == o.description
}
