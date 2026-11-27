package inventory

import (
	"cmp"
	"slices"
	"strings"

	domi18n "github.com/wentf9/xops-cli/core/domain/i18n"
	"github.com/wentf9/xops-cli/core/domain/option"
)

// NamespaceKind 标识跨命名空间 ProxyJump 资产图中的命名空间类别；零值 NamespaceInvalid 失败关闭。
//
//xops:opaque
//xops:failclosed
type NamespaceKind uint8

const (
	NamespaceInvalid NamespaceKind = iota // 无效命名空间（零值失败关闭）
	NamespaceManaged                      // XOps 托管配置节点命名空间
	NamespaceOpenSSH                      // ~/.ssh/config 只读虚拟节点命名空间
)

// ParseNamespaceKind 严格解析命名空间文本（"managed" 或 "openssh"）。
func ParseNamespaceKind(raw string) (NamespaceKind, error) {
	return parseEnumByName(raw, NamespaceManaged, NamespaceOpenSSH, NamespaceInvalid, NamespaceKind.String, ErrInvalidID)
}
func (k NamespaceKind) IsValid() bool { return k == NamespaceManaged || k == NamespaceOpenSSH }
func (k NamespaceKind) IsZero() bool  { return k == NamespaceInvalid }
func (k NamespaceKind) String() string {
	return enumName(uint8(k), "invalid", "invalid", "managed", "openssh")
}
func (k NamespaceKind) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, k.IsValid(), k.String(), ErrInvalidID)
}
func (k NamespaceKind) MarshalText() ([]byte, error) { return k.AppendText(nil) }
func (k *NamespaceKind) UnmarshalText(text []byte) error {
	return unmarshalText(k, text, ParseNamespaceKind)
}

// TargetKey 是跨命名空间代理图中的强类型节点顶点键（杜绝依赖 "openssh:" 字符串前缀猜测）。
//
//xops:opaque
//xops:failclosed
type TargetKey struct {
	ns   NamespaceKind
	name string
}

// NewTargetKey 校验命名空间与目标名称并构造不可变 TargetKey。
func NewTargetKey(ns NamespaceKind, name string) (TargetKey, error) {
	t := strings.TrimSpace(name)
	if !ns.IsValid() || t == "" || len(t) > maxIDLen || hasSpaceOrForbidden(t) || strings.EqualFold(t, "none") {
		return TargetKey{}, domi18n.EF(ErrInvalidID, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "target_key"), domi18n.BoundStr("value", ns.String()+":"+name))
	}
	if ns == NamespaceManaged {
		if _, err := ParseNodeID(t); err != nil {
			return TargetKey{}, err
		}
	}
	return TargetKey{ns, t}, nil
}

// ParseTargetKey 解析规范文本 "<namespace>:<name>"（如 "managed:web-01"、"openssh:prod_db"）为 TargetKey。
func ParseTargetKey(raw string) (TargetKey, error) {
	nsRaw, name, ok := strings.Cut(raw, ":")
	if !ok {
		return TargetKey{}, domi18n.EF(ErrInvalidID, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "target_key"), domi18n.BoundStr("value", raw))
	}
	ns, err := ParseNamespaceKind(nsRaw)
	if err != nil {
		return TargetKey{}, err
	}
	return NewTargetKey(ns, name)
}
func (k TargetKey) IsValid() bool            { return k.ns.IsValid() && k.name != "" }
func (k TargetKey) IsZero() bool             { return !k.IsValid() }
func (k TargetKey) Namespace() NamespaceKind { return k.ns }
func (k TargetKey) Name() string             { return k.name }
func (k TargetKey) String() string           { return pickIf(k.IsValid(), k.ns.String()+":"+k.name, "") }
func (k TargetKey) Equal(o TargetKey) bool {
	return k.IsValid() && o.IsValid() && k.ns == o.ns && k.name == o.name
}
func (k TargetKey) Compare(o TargetKey) int {
	return cmp.Or(cmp.Compare(k.ns, o.ns), cmp.Compare(k.name, o.name))
}
func (k TargetKey) AppendText(b []byte) ([]byte, error) {
	return appendValidText(b, k.IsValid(), k.String(), ErrInvalidID)
}
func (k TargetKey) MarshalText() ([]byte, error) { return k.AppendText(nil) }
func (k *TargetKey) UnmarshalText(text []byte) error {
	return unmarshalText(k, text, ParseTargetKey)
}

// OpenSSHJumpNode 表示来自 ~/.ssh/config 只读视图的代理跳板图顶点（供跨命名空间环路检测使用）。
//
//xops:opaque
//xops:failclosed
type OpenSSHJumpNode struct {
	alias string
	proxy option.ProxyRoute
	valid bool
}

// NewOpenSSHJumpNode 校验 OpenSSH Host 别名与 ProxyRoute 并构造 OpenSSHJumpNode。
func NewOpenSSHJumpNode(alias string, proxy option.ProxyRoute) (OpenSSHJumpNode, error) {
	t := strings.TrimSpace(alias)
	if t == "" || len(t) > maxIDLen || hasSpaceOrForbidden(t) || strings.EqualFold(t, "none") {
		return OpenSSHJumpNode{}, domi18n.EF(ErrInvalidID, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "openssh_alias"), domi18n.BoundStr("value", alias))
	}
	if err := option.ValidateProxyRoute(proxy); err != nil {
		return OpenSSHJumpNode{}, domi18n.WrapSentinel(ErrInvalidGraph, err)
	}
	proxy = pickIf(proxy != nil, proxy, option.ProxyRoute(option.NewProxyUnset()))
	return OpenSSHJumpNode{t, option.ComposeProxyRoute(proxy, nil), true}, nil
}
func (n OpenSSHJumpNode) IsValid() bool            { return n.valid && n.alias != "" }
func (n OpenSSHJumpNode) Alias() string            { return n.alias }
func (n OpenSSHJumpNode) Proxy() option.ProxyRoute { return option.ComposeProxyRoute(n.proxy, nil) }

// DAGCycle 与 DAGReport 分别表示 Tarjan SCC 检测到的强连通环路与跨命名空间 ProxyJump 校验报告。
type (
	DAGCycle struct {
		Nodes []TargetKey `json:"nodes"`
	}
	DAGReport struct {
		MaxObservedDepth int         `json:"max_observed_depth"`
		TopoOrder        []TargetKey `json:"topo_order,omitzero"`
		Cycles           []DAGCycle  `json:"cycles,omitzero"`
	}
	proxyGraph struct {
		vertices                             []TargetKey
		adj                                  map[TargetKey][]TargetKey
		managedByID, aliasToKey, openSSHKeys map[string]TargetKey
	}
)

// ValidateProxyDAG 对托管节点与 OpenSSH 虚拟节点集合执行确定性跨命名空间 ProxyJump 校验：
// 检测重复 ID/别名碰撞、缺失跳板、Tarjan SCC 自环/多跳环以及最大跳板深度限制。
func ValidateProxyDAG(nodes []Node, openSSH []OpenSSHJumpNode, maxDepth int) (DAGReport, error) {
	_, report, err := buildAndValidateProxyGraph(nodes, openSSH, maxDepth)
	return report, err
}

// ResolveJumpDAG 校验全图无环且深度合规后，按拓扑去重顺序解析 start 的上游到目标跳板链 [bastion..., start]（O(V+E)）。
func ResolveJumpDAG(nodes []Node, openSSH []OpenSSHJumpNode, start TargetKey, maxDepth int) ([]TargetKey, error) {
	if !start.IsValid() {
		return nil, domi18n.EF(ErrInvalidGraph, domi18n.KeyCommonFieldValueInvalid, domi18n.Str("field", "start"))
	}
	g, _, err := buildAndValidateProxyGraph(nodes, openSSH, maxDepth)
	if err != nil {
		return nil, err
	}
	if _, ok := g.adj[start]; !ok {
		return nil, domi18n.EF(ErrMissingProxyHop, domi18n.KeyCommonUnknownValue, domi18n.Str("kind", "target"), domi18n.BoundStr("value", start.String()))
	}
	var chain []TargetKey
	collectJumpChain(g, start, make(map[TargetKey]bool), &chain)
	return chain, nil
}

func buildAndValidateProxyGraph(nodes []Node, openSSH []OpenSSHJumpNode, maxDepth int) (*proxyGraph, DAGReport, error) {
	if maxDepth <= 0 {
		return nil, DAGReport{}, domi18n.EF(ErrInvalidGraph, domi18n.KeyCommonFieldPositive, domi18n.Str("field", "max_depth"))
	}
	g, err := buildProxyGraph(nodes, openSSH)
	if err != nil {
		return nil, DAGReport{}, err
	}
	if cycles := findTarjanCycles(g); len(cycles) > 0 {
		return nil, DAGReport{Cycles: cycles}, domi18n.EF(ErrProxyJumpCycle, domi18n.KeyInventoryCycleDetected, domi18n.Int("count", len(cycles)), domi18n.BoundStr("first", formatCycle(cycles[0])))
	}
	maxObs, err := computeMaxHopCount(g, maxDepth)
	if err != nil {
		return nil, DAGReport{}, err
	}
	return g, DAGReport{maxObs, collectTopoPostOrder(g), nil}, nil
}
func collectJumpChain(g *proxyGraph, cur TargetKey, emitted map[TargetKey]bool, out *[]TargetKey) {
	if emitted[cur] {
		return
	}
	for _, hop := range g.adj[cur] {
		collectJumpChain(g, hop, emitted, out)
	}
	emitted[cur] = true
	*out = append(*out, cur)
}
func buildProxyGraph(nodes []Node, openSSH []OpenSSHJumpNode) (*proxyGraph, error) {
	g := &proxyGraph{
		adj:         make(map[TargetKey][]TargetKey, len(nodes)+len(openSSH)),
		managedByID: make(map[string]TargetKey, len(nodes)),
		aliasToKey:  make(map[string]TargetKey, len(nodes)),
		openSSHKeys: make(map[string]TargetKey, len(openSSH)),
	}
	if err := registerVertices(g, nodes, openSSH); err != nil {
		return nil, err
	}
	if err := populateEdges(g, nodes, openSSH); err != nil {
		return nil, err
	}
	slices.SortFunc(g.vertices, TargetKey.Compare)
	return g, nil
}
func registerVertices(g *proxyGraph, nodes []Node, openSSH []OpenSSHJumpNode) error {
	for i, n := range nodes {
		if !n.IsValid() {
			return domi18n.EF(ErrInvalidNode, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "nodes"), domi18n.Int("index", i))
		}
		if err := g.addVertex(g.managedByID, NamespaceManaged, n.ID().String()); err != nil {
			return err
		}
	}
	if err := registerManagedAliases(g, nodes); err != nil {
		return err
	}
	for i, on := range openSSH {
		if !on.IsValid() {
			return domi18n.EF(ErrInvalidGraph, domi18n.KeyCommonIndexInvalid, domi18n.Str("field", "openssh_nodes"), domi18n.Int("index", i))
		}
		if err := g.addVertex(g.openSSHKeys, NamespaceOpenSSH, on.alias); err != nil {
			return err
		}
	}
	return nil
}
func (g *proxyGraph) addVertex(index map[string]TargetKey, ns NamespaceKind, name string) error {
	if _, dup := index[name]; dup {
		return domi18n.EF(ErrDuplicateAssetID, domi18n.KeyCommonDuplicateItem, domi18n.Str("kind", "target"), domi18n.BoundStr("value", name))
	}
	key := TargetKey{ns, name}
	index[name], g.adj[key] = key, nil
	g.vertices = append(g.vertices, key)
	return nil
}
func registerManagedAliases(g *proxyGraph, nodes []Node) error {
	for _, n := range nodes {
		key := g.managedByID[n.ID().String()]
		for _, a := range n.Aliases() {
			name := a.String()
			if _, col := g.managedByID[name]; col {
				return domi18n.EF(ErrDuplicateAssetID, domi18n.KeyInventoryAliasConflict, domi18n.BoundStr("alias", name), domi18n.BoundStr("first", name), domi18n.BoundStr("second", key.name))
			}
			if prev, dup := g.aliasToKey[name]; dup {
				return domi18n.EF(ErrDuplicateAssetID, domi18n.KeyInventoryAliasConflict, domi18n.BoundStr("alias", name), domi18n.BoundStr("first", prev.name), domi18n.BoundStr("second", key.name))
			}
			g.aliasToKey[name] = key
		}
	}
	return nil
}
func populateEdges(g *proxyGraph, nodes []Node, openSSH []OpenSSHJumpNode) error {
	setEdges := func(src TargetKey, route option.ProxyRoute) error {
		edges, err := resolveRouteHops(g, src, route)
		if err == nil {
			g.adj[src] = edges
		}
		return err
	}
	for _, n := range nodes {
		if err := setEdges(g.managedByID[n.ID().String()], n.EffectiveProxy()); err != nil {
			return err
		}
	}
	for _, on := range openSSH {
		if err := setEdges(g.openSSHKeys[on.alias], on.proxy); err != nil {
			return err
		}
	}
	return nil
}
func resolveRouteHops(g *proxyGraph, src TargetKey, route option.ProxyRoute) ([]TargetKey, error) {
	switch v := route.(type) {
	case nil, *option.ProxyUnset, *option.ProxyDisabled, *option.ProxyCommandSpec:
		return nil, nil
	case *option.ProxyJumpChain:
		if !v.IsValid() {
			return nil, domi18n.EF(ErrInvalidGraph, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "proxy_jump"), domi18n.BoundStr("value", src.String()))
		}
		return mapSliceErr(v.Hops().Slice(), func(h option.HopTarget) (TargetKey, error) {
			if dst, ok := g.lookupHop(h.Host(), src.ns); ok {
				return dst, nil
			}
			return TargetKey{}, domi18n.EF(ErrMissingProxyHop, domi18n.KeyInventoryHopUnknown, domi18n.BoundStr("node", src.String()), domi18n.BoundStr("hop", h.Host()))
		})
	default:
		return nil, domi18n.EF(ErrInvalidGraph, domi18n.KeyCommonFieldInvalid, domi18n.Str("field", "proxy_route"), domi18n.BoundStr("value", src.String()))
	}
}
func (g *proxyGraph) lookupHop(host string, fromNS NamespaceKind) (TargetKey, bool) {
	order := [3]map[string]TargetKey{g.managedByID, g.aliasToKey, g.openSSHKeys}
	if fromNS == NamespaceOpenSSH {
		order = [3]map[string]TargetKey{g.openSSHKeys, g.managedByID, g.aliasToKey}
	}
	for _, t := range order {
		if k, ok := t[host]; ok {
			return k, true
		}
	}
	return TargetKey{}, false
}

type tarjanState struct {
	g              *proxyGraph
	nextIdx        int
	index, lowlink map[TargetKey]int
	onStack        map[TargetKey]bool
	stack          []TargetKey
	cycles         []DAGCycle
}

func findTarjanCycles(g *proxyGraph) []DAGCycle {
	n := len(g.vertices)
	st := &tarjanState{g: g, index: make(map[TargetKey]int, n), lowlink: make(map[TargetKey]int, n), onStack: make(map[TargetKey]bool, n)}
	for _, v := range g.vertices {
		if _, visited := st.index[v]; !visited {
			st.strongConnect(v)
		}
	}
	slices.SortFunc(st.cycles, func(a, b DAGCycle) int { return slices.CompareFunc(a.Nodes, b.Nodes, TargetKey.Compare) })
	return st.cycles
}
func (st *tarjanState) strongConnect(v TargetKey) {
	st.nextIdx++
	st.index[v], st.lowlink[v], st.onStack[v] = st.nextIdx, st.nextIdx, true
	st.stack = append(st.stack, v)
	for _, w := range st.g.adj[v] {
		if _, visited := st.index[w]; !visited {
			st.strongConnect(w)
			st.lowlink[v] = min(st.lowlink[v], st.lowlink[w])
		} else if st.onStack[w] {
			st.lowlink[v] = min(st.lowlink[v], st.index[w])
		}
	}
	if st.lowlink[v] == st.index[v] {
		st.popComponent(v)
	}
}
func (st *tarjanState) popComponent(root TargetKey) {
	var comp []TargetKey
	for {
		w := st.stack[len(st.stack)-1]
		st.stack, st.onStack[w] = st.stack[:len(st.stack)-1], false
		comp = append(comp, w)
		if w == root {
			break
		}
	}
	if len(comp) > 1 || (len(comp) == 1 && slices.Contains(st.g.adj[root], root)) {
		slices.SortFunc(comp, TargetKey.Compare)
		st.cycles = append(st.cycles, DAGCycle{comp})
	}
}

// computeMaxHopCount 统计每个顶点在无环图中的精确去重上游跳数 |Ancestors(v)| == len(ResolveJumpDAG(v))-1，
// 覆盖逗号串联 ProxyJump b1,b2,...,bN 与菱形 DAG，并在超过 maxDepth 时即时短路。
func computeMaxHopCount(g *proxyGraph, maxDepth int) (int, error) {
	maxObs := 0
	for _, v := range g.vertices {
		seen := make(map[TargetKey]bool)
		if err := countAncestorsBounded(g, v, maxDepth, seen); err != nil {
			return 0, domi18n.EF(ErrProxyJumpDepthExceeded, domi18n.KeyCommonFieldMaxExceeded, domi18n.BoundStr("field", v.String()), domi18n.Int("value", len(seen)), domi18n.Int("max", maxDepth))
		}
		maxObs = max(maxObs, len(seen))
	}
	return maxObs, nil
}
func countAncestorsBounded(g *proxyGraph, cur TargetKey, maxDepth int, seen map[TargetKey]bool) error {
	for _, hop := range g.adj[cur] {
		if seen[hop] {
			continue
		}
		seen[hop] = true
		if len(seen) > maxDepth {
			return ErrProxyJumpDepthExceeded
		}
		if err := countAncestorsBounded(g, hop, maxDepth, seen); err != nil {
			return err
		}
	}
	return nil
}
func collectTopoPostOrder(g *proxyGraph) []TargetKey {
	emitted := make(map[TargetKey]bool, len(g.vertices))
	topo := make([]TargetKey, 0, len(g.vertices))
	for _, v := range g.vertices {
		collectJumpChain(g, v, emitted, &topo)
	}
	return topo
}
func formatCycle(c DAGCycle) string {
	parts := make([]string, len(c.Nodes))
	for i, k := range c.Nodes {
		parts[i] = k.String()
	}
	return strings.Join(parts, " -> ")
}
