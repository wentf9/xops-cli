package tui

import (
	"cmp"
	"slices"
	"strings"

	"github.com/wentf9/xops-cli/core/domain/inventory"
	"github.com/wentf9/xops-cli/core/engine"
)

// HostItem 是从 core/engine InventorySnapshot 投影出的不可变主机/节点行视图。
type HostItem struct {
	NodeID      string
	TargetSpec  string
	HostID      string
	Endpoint    string
	User        string
	Origin      string
	Aliases     []string
	Tags        []string
	Description string
}

// EffectiveTarget 返回面向 core/engine 目标解析的真实目标规格：
// 受管节点返回 NodeID，独立 Host 返回其可直连 Endpoint（缺失时回退 NodeID）。
func (h HostItem) EffectiveTarget() string {
	return pickStr(h.TargetSpec, h.NodeID)
}

// MatchesFilter 判定主机条目是否匹配不区分大小写的筛选关键词。
func (h HostItem) MatchesFilter(query string) bool {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return true
	}
	if strings.Contains(strings.ToLower(h.NodeID), q) ||
		strings.Contains(strings.ToLower(h.HostID), q) ||
		strings.Contains(strings.ToLower(h.Endpoint), q) ||
		strings.Contains(strings.ToLower(h.User), q) ||
		strings.Contains(strings.ToLower(h.Description), q) {
		return true
	}
	for _, a := range h.Aliases {
		if strings.Contains(strings.ToLower(a), q) {
			return true
		}
	}
	for _, t := range h.Tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	return false
}

// BuildHostItems 将核心资产图快照投影为确定性排序的主机/节点视图列表。
func BuildHostItems(snap engine.InventorySnapshot) []HostItem {
	if !snap.IsValid() {
		return nil
	}
	g := snap.Graph()
	return BuildHostItemsFromEntities(g.Hosts(), g.Identities(), g.Nodes())
}

// BuildHostItemsFromEntities 从资产实体切片构造确定性排序的主机/节点视图列表。
func BuildHostItemsFromEntities(hosts []inventory.Host, idents []inventory.Identity, nodes []inventory.Node) []HostItem {
	hostMap := make(map[string]inventory.Host, len(hosts))
	for _, h := range hosts {
		hostMap[h.ID().String()] = h
	}
	identMap := make(map[string]inventory.Identity, len(idents))
	for _, id := range idents {
		identMap[id.ID().String()] = id
	}
	items := make([]HostItem, 0, len(nodes)+len(hosts))
	referencedHosts := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		referencedHosts[n.HostRef().String()] = true
		items = append(items, hostItemFromNode(n, hostMap, identMap))
	}
	// 补充未被任何 Node 引用的独立 Host，确保资产面板完整可见。
	for _, h := range hosts {
		if referencedHosts[h.ID().String()] {
			continue
		}
		items = append(items, hostItemFromStandaloneHost(h))
	}
	slices.SortFunc(items, func(a, b HostItem) int {
		return cmp.Or(
			cmp.Compare(a.NodeID, b.NodeID),
			cmp.Compare(a.HostID, b.HostID),
			cmp.Compare(a.Endpoint, b.Endpoint),
		)
	})
	return items
}

func hostItemFromNode(n inventory.Node, hosts map[string]inventory.Host, idents map[string]inventory.Identity) HostItem {
	nodeID := n.ID().String()
	item := HostItem{
		NodeID:      nodeID,
		TargetSpec:  nodeID,
		HostID:      n.HostRef().String(),
		Origin:      n.OriginKind().String(),
		Description: n.Description(),
	}
	if h, ok := hosts[item.HostID]; ok {
		item.Endpoint = h.Endpoint().String()
	}
	if id, ok := idents[n.IdentityRef().String()]; ok {
		item.User = id.User().String()
	}
	for _, a := range n.Aliases() {
		item.Aliases = append(item.Aliases, a.String())
	}
	for _, t := range n.Tags() {
		item.Tags = append(item.Tags, t.String())
	}
	return item
}

func hostItemFromStandaloneHost(h inventory.Host) HostItem {
	ep := h.Endpoint().String()
	id := h.ID().String()
	item := HostItem{
		NodeID:      id,
		TargetSpec:  pickStr(ep, id),
		HostID:      id,
		Endpoint:    ep,
		Origin:      "host",
		Description: h.Description(),
	}
	if a, ok := h.Alias().Get(); ok {
		item.Aliases = []string{a.String()}
	}
	for _, t := range h.Tags() {
		item.Tags = append(item.Tags, t.String())
	}
	return item
}
