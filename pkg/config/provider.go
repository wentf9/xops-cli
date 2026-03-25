package config

import (
	"fmt"
	"slices"

	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

// Provider 提供了基础的配置查询和管理功能
type Provider struct {
	cfg         *Configuration
	lookupIndex *concurrent.Map[string, string]
}

// NewProvider 创建一个新的配置提供者实例
func NewProvider(cfg *Configuration) ConfigProvider {
	provider := Provider{
		cfg:         cfg,
		lookupIndex: concurrent.NewMap[string, string](concurrent.HashString),
	}
	provider.init()
	return provider
}

// Add 将主机及其所有标识符加入索引
func (cp Provider) add(nodeID string) {
	node, ok := cp.GetNode(nodeID)
	if !ok {
		return
	}
	identity, ok := cp.GetIdentity(nodeID)
	if !ok {
		return
	}
	host, ok := cp.GetHost(nodeID)
	if !ok {
		return
	}

	address := host.Address
	port := host.Port
	user := identity.User

	// 1. nodeID 映射
	cp.lookupIndex.Set(nodeID, nodeID)

	// 2. IP/地址 映射
	cp.lookupIndex.Set(address, nodeID)

	// 3. User@Address 映射
	if user != "" {
		cp.lookupIndex.Set(fmt.Sprintf("%s@%s", user, address), nodeID)
		cp.lookupIndex.Set(fmt.Sprintf("%s@%s:%d", user, address, port), nodeID)
	}

	// 4. 节点别名映射
	for _, a := range node.Alias {
		if a == "" {
			continue
		}
		cp.lookupIndex.Set(a, nodeID)
		if user != "" {
			cp.lookupIndex.Set(fmt.Sprintf("%s@%s", user, a), nodeID)
			cp.lookupIndex.Set(fmt.Sprintf("%s@%s:%d", user, a, port), nodeID)
		}
	}

	// 5. 主机别名映射
	for _, a := range host.Alias {
		if a == "" {
			continue
		}
		cp.lookupIndex.Set(a, nodeID)
		if user != "" {
			cp.lookupIndex.Set(fmt.Sprintf("%s@%s", user, a), nodeID)
			cp.lookupIndex.Set(fmt.Sprintf("%s@%s:%d", user, a, port), nodeID)
		}
	}
}

// Find 匹配用户输入
func (cp Provider) Find(input string) string {
	// 1. 直接匹配
	if nodeID, ok := cp.lookupIndex.Get(input); ok {
		return nodeID
	}
	return ""
}

// FindAlias 检查别名是否已存在，返回该别名所属的节点ID
// 如果别名不存在，返回空字符串
func (cp Provider) FindAlias(alias string) string {
	if alias == "" {
		return ""
	}
	return cp.Find(alias)
}

func (cp Provider) GetNode(nodeID string) (models.Node, bool) {
	return cp.cfg.Nodes.Get(nodeID)
}

func (cp Provider) GetHost(nodeID string) (models.Host, bool) {
	if node, ok := cp.cfg.Nodes.Get(nodeID); ok {
		return cp.cfg.Hosts.Get(node.HostRef)
	}
	return models.Host{}, false
}

func (cp Provider) GetIdentity(nodeID string) (models.Identity, bool) {
	if node, ok := cp.cfg.Nodes.Get(nodeID); ok {
		return cp.cfg.Identities.Get(node.IdentityRef)
	}
	return models.Identity{}, false
}

func (cp Provider) AddNode(nodeID string, node models.Node) {
	cp.cfg.Nodes.Set(nodeID, node)
	cp.add(nodeID)
}

func (cp Provider) AddHost(hostID string, host models.Host) {
	cp.cfg.Hosts.Set(hostID, host)
}

func (cp Provider) AddIdentity(identityID string, identity models.Identity) {
	cp.cfg.Identities.Set(identityID, identity)
}

func (cp Provider) DeleteNode(nodeID string) {
	node, ok := cp.cfg.Nodes.Get(nodeID)
	if !ok {
		return
	}

	hostRef := node.HostRef
	identityRef := node.IdentityRef

	// 1. 删除节点本身
	cp.cfg.Nodes.Remove(nodeID)

	// 2. 从索引中删除
	for _, key := range cp.lookupIndex.Keys() {
		if val, ok := cp.lookupIndex.Get(key); ok && val == nodeID {
			cp.lookupIndex.Remove(key)
		}
	}

	// 3. 检查 HostRef 和 IdentityRef 是否还在被其他节点引用
	hostUsed := false
	identityUsed := false
	for _, k := range cp.cfg.Nodes.Keys() {
		if n, ok := cp.cfg.Nodes.Get(k); ok {
			if n.HostRef == hostRef {
				hostUsed = true
			}
			if n.IdentityRef == identityRef {
				identityUsed = true
			}
		}
		if hostUsed && identityUsed {
			break
		}
	}

	// 如果不再被引用，则清理
	if !hostUsed && hostRef != "" {
		cp.cfg.Hosts.Remove(hostRef)
	}
	if !identityUsed && identityRef != "" {
		cp.cfg.Identities.Remove(identityRef)
	}
}

func (cp Provider) ListNodes() map[string]models.Node {
	nodes := make(map[string]models.Node)
	for _, k := range cp.cfg.Nodes.Keys() {
		if v, ok := cp.cfg.Nodes.Get(k); ok {
			nodes[k] = v
		}
	}
	return nodes
}

func (cp Provider) GetNodesByTag(tag string) map[string]models.Node {
	result := make(map[string]models.Node)
	for _, nodeID := range cp.cfg.Nodes.Keys() {
		node, _ := cp.cfg.Nodes.Get(nodeID)
		if slices.Contains(node.Tags, tag) {
			result[nodeID] = node
		}
	}
	return result
}

func (cp Provider) ListIdentities() map[string]models.Identity {
	identities := make(map[string]models.Identity)
	for _, k := range cp.cfg.Identities.Keys() {
		if v, ok := cp.cfg.Identities.Get(k); ok {
			identities[k] = v
		}
	}
	return identities
}

func (cp Provider) DeleteIdentity(name string) {
	cp.cfg.Identities.Remove(name)
}

func (cp Provider) init() {
	for _, nodeID := range cp.cfg.Nodes.Keys() {
		cp.add(nodeID)
	}
}

func (cp Provider) GetConfig() *Configuration {
	return cp.cfg
}
