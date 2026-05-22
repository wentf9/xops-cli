package config

import (
	"testing"

	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func newTestProvider() ConfigProvider {
	cfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Hosts.Set("host-web", models.Host{
		Address: "10.0.0.1",
		Port:    22,
		Alias:   []string{"web.example.com"},
	})
	cfg.Identities.Set("id-admin", models.Identity{
		User:     "admin",
		AuthType: "key",
	})
	cfg.Nodes.Set("web-server", models.Node{
		HostRef:     "host-web",
		IdentityRef: "id-admin",
		Alias:       []string{"ws1"},
		Tags:        []string{"production", "web"},
	})

	return NewProvider(cfg)
}

func TestFind_ByNodeId(t *testing.T) {
	p := newTestProvider()
	if got := p.Find("web-server"); got != "web-server" {
		t.Errorf("Find('web-server') = %q, want 'web-server'", got)
	}
}

func TestFind_ByAlias(t *testing.T) {
	p := newTestProvider()
	if got := p.Find("ws1"); got != "web-server" {
		t.Errorf("Find('ws1') = %q, want 'web-server'", got)
	}
}

func TestFind_ByUserHostPort(t *testing.T) {
	p := newTestProvider()

	// user@address:port
	if got := p.Find("admin@10.0.0.1:22"); got != "web-server" {
		t.Errorf("Find('admin@10.0.0.1:22') = %q, want 'web-server'", got)
	}

	// user@address (no port)
	if got := p.Find("admin@10.0.0.1"); got != "web-server" {
		t.Errorf("Find('admin@10.0.0.1') = %q, want 'web-server'", got)
	}

	// bare address
	if got := p.Find("10.0.0.1"); got != "web-server" {
		t.Errorf("Find('10.0.0.1') = %q, want 'web-server'", got)
	}

	// user@alias:port
	if got := p.Find("admin@web.example.com:22"); got != "web-server" {
		t.Errorf("Find('admin@web.example.com:22') = %q, want 'web-server'", got)
	}

	// user@alias (no port)
	if got := p.Find("admin@web.example.com"); got != "web-server" {
		t.Errorf("Find('admin@web.example.com') = %q, want 'web-server'", got)
	}
}

func TestFind_NotFound(t *testing.T) {
	p := newTestProvider()
	if got := p.Find("nonexistent"); got != "" {
		t.Errorf("Find('nonexistent') = %q, want empty", got)
	}
}

func TestAddNode_UpdatesIndex(t *testing.T) {
	cfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "1.2.3.4", Port: 22})
	cfg.Identities.Set("i1", models.Identity{User: "root", AuthType: "password"})
	p := NewProvider(cfg)

	p.AddNode("n1", models.Node{
		HostRef:     "h1",
		IdentityRef: "i1",
		Alias:       []string{"mynode"},
	})

	if got := p.Find("mynode"); got != "n1" {
		t.Errorf("Find('mynode') after AddNode = %q, want 'n1'", got)
	}
	if got := p.Find("root@1.2.3.4:22"); got != "n1" {
		t.Errorf("Find('root@1.2.3.4:22') after AddNode = %q, want 'n1'", got)
	}
}

func TestDeleteNode_CleansIndex(t *testing.T) {
	p := newTestProvider()

	// 确认存在
	if got := p.Find("ws1"); got != "web-server" {
		t.Fatalf("pre-check: Find('ws1') = %q, want 'web-server'", got)
	}

	p.DeleteNode("web-server")

	if got := p.Find("web-server"); got != "" {
		t.Errorf("Find('web-server') after delete = %q, want empty", got)
	}
	if got := p.Find("ws1"); got != "" {
		t.Errorf("Find('ws1') after delete = %q, want empty", got)
	}
}

func TestDeleteNode_CleansUnusedRefs(t *testing.T) {
	cfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "1.1.1.1"})
	cfg.Identities.Set("i1", models.Identity{User: "u1"})
	cfg.Nodes.Set("n1", models.Node{HostRef: "h1", IdentityRef: "i1"})
	cfg.Nodes.Set("n2", models.Node{HostRef: "h1", IdentityRef: "i1"}) // n2 也引用 h1, i1

	p := NewProvider(cfg)

	// 1. 删除 n1，应该保留 h1, i1 (因为还有 n2 引用)
	p.DeleteNode("n1")
	if _, ok := cfg.Hosts.Get("h1"); !ok {
		t.Error("expected h1 to be preserved as n2 still references it")
	}
	if _, ok := cfg.Identities.Get("i1"); !ok {
		t.Error("expected i1 to be preserved as n2 still references it")
	}

	// 2. 删除 n2，应该清理 h1, i1
	p.DeleteNode("n2")
	if _, ok := cfg.Hosts.Get("h1"); ok {
		t.Error("expected h1 to be cleaned as no more nodes reference it")
	}
	if _, ok := cfg.Identities.Get("i1"); ok {
		t.Error("expected i1 to be cleaned as no more nodes reference it")
	}
}

func TestGetNodesByTag(t *testing.T) {
	p := newTestProvider()

	nodes := p.GetNodesByTag("production")
	if len(nodes) != 1 {
		t.Fatalf("GetNodesByTag('production') returned %d nodes, want 1", len(nodes))
	}
	if _, ok := nodes["web-server"]; !ok {
		t.Error("expected 'web-server' in production nodes")
	}

	// 不匹配的 tag
	nodes = p.GetNodesByTag("staging")
	if len(nodes) != 0 {
		t.Errorf("GetNodesByTag('staging') returned %d nodes, want 0", len(nodes))
	}
}

func TestListNodes(t *testing.T) {
	p := newTestProvider()
	nodes := p.ListNodes()
	if len(nodes) != 1 {
		t.Errorf("ListNodes() returned %d, want 1", len(nodes))
	}
}

func TestListIdentities(t *testing.T) {
	p := newTestProvider()
	ids := p.ListIdentities()
	if len(ids) != 1 {
		t.Errorf("ListIdentities() returned %d, want 1", len(ids))
	}
}

func TestLocalNodeFiltering(t *testing.T) {
	cfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	// 1. 添加正常节点 (remote node)
	cfg.Hosts.Set("host-remote", models.Host{Address: "192.168.1.10", Port: 22})
	cfg.Identities.Set("id-remote", models.Identity{User: "remote-user", AuthType: "password"})
	cfg.Nodes.Set("remote-node", models.Node{
		HostRef:     "host-remote",
		IdentityRef: "id-remote",
		Tags:        []string{"web"},
	})

	// 2. 添加本地节点 (localhost node)
	cfg.Hosts.Set("host-local", models.Host{Address: "127.0.0.1", Port: 22})
	cfg.Identities.Set("id-local", models.Identity{User: "local-user", AuthType: "password"})
	cfg.Nodes.Set("local-node", models.Node{
		HostRef:     "host-local",
		IdentityRef: "id-local",
		Tags:        []string{"web"},
	})

	p := NewProvider(cfg)

	// 验证 ListNodes
	nodes := p.ListNodes()
	if len(nodes) != 1 {
		t.Errorf("ListNodes() returned %d nodes, want 1 (should exclude local node)", len(nodes))
	}
	if _, ok := nodes["remote-node"]; !ok {
		t.Error("expected remote-node to be in ListNodes()")
	}
	if _, ok := nodes["local-node"]; ok {
		t.Error("expected local-node to be excluded from ListNodes()")
	}

	// 验证 GetNodesByTag
	taggedNodes := p.GetNodesByTag("web")
	if len(taggedNodes) != 1 {
		t.Errorf("GetNodesByTag() returned %d nodes, want 1", len(taggedNodes))
	}
	if _, ok := taggedNodes["local-node"]; ok {
		t.Error("expected local-node to be excluded from GetNodesByTag()")
	}

	// 验证 Find 和 GetNode 依然保留单节点寻址能力
	if got := p.Find("local-node"); got != "local-node" {
		t.Errorf("Find('local-node') = %q, want 'local-node' (should preserve indexing)", got)
	}
	if _, ok := p.GetNode("local-node"); !ok {
		t.Error("GetNode('local-node') failed, should preserve point-to-point query")
	}
}
