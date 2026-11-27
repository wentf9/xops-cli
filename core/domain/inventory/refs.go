package inventory

import (
	"cmp"
	"slices"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/option"
	"github.com/wentf9/xops-cli/core/domain/secret"
)

// AssetRefLocation 与 SecretRefLocation 分别标识资产图引用与 5 位置凭据引用类别（零值失败关闭）。
//
//xops:opaque
//xops:failclosed
type AssetRefLocation uint8

//xops:opaque
//xops:failclosed
type SecretRefLocation uint8

const (
	AssetRefLocationInvalid AssetRefLocation = iota // 无效资产引用位置（零值失败关闭）
	AssetRefNodeHost                                // Node.HostRef -> Host
	AssetRefNodeIdentity                            // Node.IdentityRef -> Identity
	AssetRefNodeProxyJump                           // Node.ProxyJump -> Node/Alias
)

const (
	SecretLocInvalid              SecretRefLocation = iota // 无效凭据引用位置（零值失败关闭）
	SecretLocAuthPassword                                  // 位置 1：Identity.Auth -> AuthPassword
	SecretLocPrivateKeyPassphrase                          // 位置 2：Identity.Auth -> AuthPrivateKey.PassphraseBinding
	SecretLocChallengeTOTP                                 // 位置 3：Identity.Auth -> KeyboardInteractive -> RuleTOTP
	SecretLocChallengeSecret                               // 位置 4：Identity.Auth -> KeyboardInteractive -> RuleSecretRef
	SecretLocNodePrivilege                                 // 位置 5：Node.PrivilegePasswordRef
	SecretLocPending                                       // 扩展位置：待确认会话 / 运行期覆盖引用
)

// ParseAssetRefLocation 与 ParseSecretRefLocation 严格解析规范小写引用位置文本。
func ParseAssetRefLocation(raw string) (AssetRefLocation, error) {
	return parseEnumByName(raw, AssetRefNodeHost, AssetRefNodeProxyJump, AssetRefLocationInvalid, AssetRefLocation.String, ErrInvalidGraph)
}
func ParseSecretRefLocation(raw string) (SecretRefLocation, error) {
	return parseEnumByName(raw, SecretLocAuthPassword, SecretLocPending, SecretLocInvalid, SecretRefLocation.String, ErrInvalidGraph)
}
func (l AssetRefLocation) IsValid() bool { return l >= AssetRefNodeHost && l <= AssetRefNodeProxyJump }
func (l AssetRefLocation) IsZero() bool  { return l == AssetRefLocationInvalid }
func (l AssetRefLocation) String() string {
	return enumName(uint8(l), "invalid", "invalid", "node_host", "node_identity", "node_proxy_jump")
}
func (l AssetRefLocation) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, l.IsValid(), l.String(), ErrInvalidGraph)
}
func (l AssetRefLocation) MarshalText() ([]byte, error) { return l.AppendText(nil) }
func (l *AssetRefLocation) UnmarshalText(b []byte) error {
	return unmarshalText(l, b, ParseAssetRefLocation)
}
func (l SecretRefLocation) IsValid() bool { return l >= SecretLocAuthPassword && l <= SecretLocPending }
func (l SecretRefLocation) IsZero() bool  { return l == SecretLocInvalid }
func (l SecretRefLocation) String() string {
	return enumName(uint8(l), "invalid", "invalid", "auth_password", "private_key_passphrase", "challenge_totp", "challenge_secret", "node_privilege", "pending")
}
func (l SecretRefLocation) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, l.IsValid(), l.String(), ErrInvalidGraph)
}
func (l SecretRefLocation) MarshalText() ([]byte, error) { return l.AppendText(nil) }
func (l *SecretRefLocation) UnmarshalText(b []byte) error {
	return unmarshalText(l, b, ParseSecretRefLocation)
}

// AssetReference、SecretReference、PendingSecretRef 与 GraphSpec 描述资产与凭据引用检查模型。
type (
	AssetReference struct {
		Location AssetRefLocation `json:"location"`
		FromNode NodeID           `json:"from_node"`
		Target   string           `json:"target"`
		ViaAlias string           `json:"via_alias,omitzero"`
	}
	SecretReference struct {
		Location SecretRefLocation `json:"location"`
		OwnerID  string            `json:"owner_id"`
		RuleName string            `json:"rule_name,omitzero"`
		Ref      secret.Ref        `json:"ref"`
	}
	PendingSecretRef struct {
		OwnerID string     `json:"owner_id"`
		Ref     secret.Ref `json:"ref"`
	}
	GraphSpec struct {
		Hosts        []Host
		Identities   []Identity
		Nodes        []Node
		OpenSSHNodes []OpenSSHJumpNode
		KnownStores  []string
		MaxJumpDepth int
	}
)

// Graph 表示经过完整全图不变量校验（INV-F1）的不可变资产配置图快照；零值恒无效。
//
//xops:opaque
//xops:failclosed
type Graph struct {
	hosts        []Host
	identities   []Identity
	nodes        []Node
	openSSHNodes []OpenSSHJumpNode
	knownStores  []string
	valid        bool
}

// EmptyGraph 返回合法的空资产图快照。
func EmptyGraph() Graph { return Graph{valid: true} }

// NewGraph 校验全图唯一性（含 Host.Alias 冲突）、引用完整性、跨命名空间 Tarjan DAG 与可选凭据存储表，构造不可变 Graph。
// 仅 spec.MaxJumpDepth == 0 时采用 DefaultMaxJumpDepth，负数严格失败关闭。
func NewGraph(spec GraphSpec) (Graph, error) {
	if spec.MaxJumpDepth < 0 {
		return Graph{}, domi18n.EF(ErrInvalidGraph, domi18n.KeyCommonFieldNegative, domi18n.Str("field", "max_jump_depth"))
	}
	hosts, hostSet, err := validateUniqueHosts(spec.Hosts)
	if err != nil {
		return Graph{}, err
	}
	idents, identSet, err := indexUnique(spec.Identities, Identity.IsValid, Identity.ID, IdentityID.Compare, ErrInvalidIdentity)
	if err != nil {
		return Graph{}, err
	}
	nodes, err := validateAndSortNodes(spec.Nodes, hostSet, identSet)
	if err != nil {
		return Graph{}, err
	}
	maxDepth := pickIf(spec.MaxJumpDepth == 0, DefaultMaxJumpDepth, spec.MaxJumpDepth)
	if _, err := ValidateProxyDAG(nodes, spec.OpenSSHNodes, maxDepth); err != nil {
		return Graph{}, err
	}
	stores, err := canonicalizeStores(spec.KnownStores)
	if err != nil {
		return Graph{}, err
	}
	g := Graph{hosts, idents, nodes, slices.Clone(spec.OpenSSHNodes), stores, true}
	if len(stores) > 0 {
		if err := g.ValidateSecretStores(stores); err != nil {
			return Graph{}, err
		}
	}
	return g, nil
}

// validateUniqueHosts 校验全部 Host 合法、HostID 唯一且 Host.Alias 不与任何 HostID 或其他 Host.Alias 碰撞（INV-D4）。
func validateUniqueHosts(raw []Host) ([]Host, map[HostID]bool, error) {
	hosts, hostSet, err := indexUnique(raw, Host.IsValid, Host.ID, HostID.Compare, ErrInvalidHost)
	if err != nil {
		return nil, nil, err
	}
	seenAlias := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		a, ok := h.alias.Get()
		if !ok {
			continue
		}
		s := a.String()
		if hostSet[HostID{assetIDToken{s}}] || seenAlias[s] {
			return nil, nil, domi18n.EF(ErrDuplicateAssetID, domi18n.KeyCommonDuplicateItem, domi18n.Str("kind", "host.alias"), domi18n.BoundStr("value", s))
		}
		seenAlias[s] = true
	}
	return hosts, hostSet, nil
}
func validateAndSortNodes(raw []Node, hosts map[HostID]bool, idents map[IdentityID]bool) ([]Node, error) {
	for i, n := range raw {
		if !n.IsValid() {
			return nil, domi18n.EF(ErrInvalidNode, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "nodes"), domi18n.Int("index", i))
		}
		if !hosts[n.hostRef] || !idents[n.identityRef] {
			return nil, domi18n.EF(ErrMissingAssetRef, domi18n.KeyInvNodeMissingAssetRef, domi18n.BoundStr("node", n.id.String()))
		}
	}
	out := slices.Clone(raw)
	slices.SortFunc(out, func(a, b Node) int { return a.id.Compare(b.id) })
	return out, nil
}
func canonicalizeStores(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if slices.ContainsFunc(raw, func(s string) bool { return s == "" || len(s) > maxIDLen || hasSpaceOrForbidden(s) }) {
		return nil, domi18n.EF(ErrInvalidGraph, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "known_stores"))
	}
	out := slices.Clone(raw)
	slices.Sort(out)
	return slices.Compact(out), nil
}

// Graph 只读访问器（全部返回防御性拷贝）。
func (g Graph) IsValid() bool                   { return g.valid }
func (g Graph) Hosts() []Host                   { return slices.Clone(g.hosts) }
func (g Graph) Identities() []Identity          { return slices.Clone(g.identities) }
func (g Graph) Nodes() []Node                   { return slices.Clone(g.nodes) }
func (g Graph) KnownStores() []string           { return slices.Clone(g.knownStores) }
func (g Graph) OpenSSHNodes() []OpenSSHJumpNode { return slices.Clone(g.openSSHNodes) }

// FindHostReferences、FindIdentityReferences 与 FindNodeReferences 执行纯资产图反向引用查询。
func (g Graph) FindHostReferences(id HostID) []AssetReference {
	return g.findDirectNodeRefs(id.IsValid(), AssetRefNodeHost, id.String(), func(n Node) bool { return n.hostRef.Equal(id) })
}
func (g Graph) FindIdentityReferences(id IdentityID) []AssetReference {
	return g.findDirectNodeRefs(id.IsValid(), AssetRefNodeIdentity, id.String(), func(n Node) bool { return n.identityRef.Equal(id) })
}
func (g Graph) findDirectNodeRefs(idValid bool, loc AssetRefLocation, target string, match func(Node) bool) []AssetReference {
	if !g.valid || !idValid {
		return nil
	}
	var out []AssetReference
	for _, n := range g.nodes {
		if match(n) {
			out = append(out, AssetReference{loc, n.id, target, ""})
		}
	}
	return out
}
func (g Graph) FindNodeReferences(id NodeID) []AssetReference {
	if !g.valid || !id.IsValid() {
		return nil
	}
	aliasSet := make(map[string]bool)
	if idx := slices.IndexFunc(g.nodes, func(n Node) bool { return n.id.Equal(id) }); idx >= 0 {
		for _, a := range g.nodes[idx].aliases {
			aliasSet[a.String()] = true
		}
	}
	var out []AssetReference
	for _, n := range g.nodes {
		appendNodeJumpRefs(n, id.String(), aliasSet, &out)
	}
	return out
}
func appendNodeJumpRefs(n Node, targetID string, aliasSet map[string]bool, out *[]AssetReference) {
	if jc, ok := n.EffectiveProxy().(*option.ProxyJumpChain); ok && jc.IsValid() {
		for _, hop := range jc.Hops().Slice() {
			if h := hop.Host(); h == targetID || aliasSet[h] {
				*out = append(*out, AssetReference{AssetRefNodeProxyJump, n.id, targetID, pickIf(h == targetID, "", h)})
			}
		}
	}
}

// AllSecretReferences、FindSecretReferences、FindStoreReferences 与 ValidateSecretStores 实现全图 5 位置凭据检查。
func (g Graph) AllSecretReferences(extraPending ...PendingSecretRef) []SecretReference {
	refs, ok := g.collectAllSecretReferences(extraPending...)
	return pickIf(ok, refs, nil)
}
func (g Graph) FindSecretReferences(target secret.Ref, extraPending ...PendingSecretRef) []SecretReference {
	refs, _ := g.filterSecretRefs(target.IsValid(), func(sr SecretReference) bool { return sr.Ref.Equal(target) }, extraPending...)
	return refs
}
func (g Graph) FindStoreReferences(storeID string, extraPending ...PendingSecretRef) []SecretReference {
	refs, _ := g.filterSecretRefs(storeID != "", func(sr SecretReference) bool { return sr.Ref.Store() == storeID }, extraPending...)
	return refs
}
func (g Graph) filterSecretRefs(cond bool, keep func(SecretReference) bool, extraPending ...PendingSecretRef) ([]SecretReference, bool) {
	all, ok := g.collectAllSecretReferences(extraPending...)
	if !cond || !ok {
		return nil, false
	}
	return slices.DeleteFunc(all, func(sr SecretReference) bool { return !keep(sr) }), true
}
func (g Graph) ValidateSecretStores(knownStores []string, extraPending ...PendingSecretRef) error {
	all, ok := g.collectAllSecretReferences(extraPending...)
	if !ok {
		return ErrInvalidGraph
	}
	for _, sr := range all {
		if !slices.Contains(knownStores, sr.Ref.Store()) {
			return domi18n.EF(ErrUnknownSecretStore, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "secret_store"), domi18n.BoundStr("value", sr.Ref.Store()))
		}
	}
	return nil
}

// CanDeleteHost、CanDeleteIdentity、CanDeleteNode 与 CanGCSecret 为安全删除与 Vault 回收提供失败关闭谓词。
func (g Graph) CanDeleteHost(id HostID) (bool, []AssetReference) {
	return canDeleteAsset(g.valid, id, g.FindHostReferences)
}
func (g Graph) CanDeleteIdentity(id IdentityID) (bool, []AssetReference) {
	return canDeleteAsset(g.valid, id, g.FindIdentityReferences)
}
func (g Graph) CanDeleteNode(id NodeID) (bool, []AssetReference) {
	return canDeleteAsset(g.valid, id, g.FindNodeReferences)
}
func canDeleteAsset[ID validatable](valid bool, id ID, find func(ID) []AssetReference) (bool, []AssetReference) {
	if !valid || !id.IsValid() {
		return false, nil
	}
	refs := find(id)
	return len(refs) == 0, refs
}
func (g Graph) CanGCSecret(ref secret.Ref, extraPending ...PendingSecretRef) (bool, []SecretReference) {
	refs, ok := g.filterSecretRefs(ref.IsValid(), func(sr SecretReference) bool { return sr.Ref.Equal(ref) }, extraPending...)
	return ok && len(refs) == 0, refs
}

func (g Graph) collectAllSecretReferences(extraPending ...PendingSecretRef) ([]SecretReference, bool) {
	if !g.valid {
		return nil, false
	}
	var out []SecretReference
	for _, id := range g.identities {
		if !collectAuthSecretRefs(id.id.String(), id.auth, &out) {
			return nil, false
		}
	}
	for _, n := range g.nodes {
		if ref, ok := n.privilegePasswordRef.Get(); ok && ref.IsValid() {
			out = append(out, SecretReference{SecretLocNodePrivilege, n.id.String(), "", ref})
		}
	}
	for _, p := range extraPending {
		if !p.Ref.IsValid() {
			return nil, false
		}
		out = append(out, SecretReference{SecretLocPending, p.OwnerID, "", p.Ref})
	}
	slices.SortFunc(out, func(a, b SecretReference) int {
		return cmp.Or(cmp.Compare(a.Location, b.Location), cmp.Compare(a.OwnerID, b.OwnerID), cmp.Compare(a.RuleName, b.RuleName), a.Ref.Compare(b.Ref))
	})
	return out, true
}
func collectAuthSecretRefs(ownerID string, auth AuthMethod, out *[]SecretReference) bool {
	if auth == nil || !auth.IsValid() {
		return false
	}
	switch v := auth.(type) {
	case *AuthPassword:
		*out = append(*out, SecretReference{SecretLocAuthPassword, ownerID, "", v.passwordRef})
		return true
	case *AuthPrivateKey:
		if pb, ok := v.passphrase.Get(); ok && pb.IsValid() {
			*out = append(*out, SecretReference{SecretLocPrivateKeyPassphrase, ownerID, "", pb.passphraseRef})
		}
		return true
	case *AuthAgent:
		return true
	case *AuthKeyboardInteractive:
		return allMatch(v.rules.Slice(), func(r ChallengeRule) bool { return collectChallengeSecretRefs(ownerID, r, out) })
	case *AuthComposite:
		return allMatch(v.methods.Slice(), func(sub AuthMethod) bool { return collectAuthSecretRefs(ownerID, sub, out) })
	default:
		return false
	}
}
func collectChallengeSecretRefs(ownerID string, r ChallengeRule, out *[]SecretReference) bool {
	if r == nil || !r.IsValid() {
		return false
	}
	switch v := r.(type) {
	case *RuleTOTP:
		*out = append(*out, SecretReference{SecretLocChallengeTOTP, ownerID, v.meta.name, v.totpSecretRef})
		return true
	case *RuleSecretRef:
		*out = append(*out, SecretReference{SecretLocChallengeSecret, ownerID, v.meta.name, v.secretRef})
		return true
	case *RuleCommand, *RuleLoginPassword:
		return true
	default:
		return false
	}
}
