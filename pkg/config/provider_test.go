package config

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

func TestProvider_ResolveRejectsMissingReferencedMaps(t *testing.T) {
	nodes := concurrent.NewMap[string, models.Node](concurrent.HashString)
	nodes.Set("node", models.Node{HostRef: "host", IdentityRef: "identity"})

	provider := NewProviderWithoutOpenSSH(&Configuration{Nodes: nodes})
	_, _, _, err := provider.Resolve("node")
	if !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("got %v, want ErrHostNotFound", err)
	}

	hosts := concurrent.NewMap[string, models.Host](concurrent.HashString)
	hosts.Set("host", models.Host{Address: "127.0.0.1", Port: 22})
	provider = NewProviderWithoutOpenSSH(&Configuration{Nodes: nodes, Hosts: hosts})
	_, _, _, err = provider.Resolve("node")
	if !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("got %v, want ErrIdentityNotFound", err)
	}
}

func TestProviderSnapshot_DefensiveCopy(t *testing.T) {
	p := newTestProvider()
	snapshot := p.Snapshot()
	node, _ := snapshot.Nodes.Get("web-server")
	host, _ := snapshot.Hosts.Get("host-web")
	node.Alias[0] = "mutated-node-alias"
	host.Alias[0] = "mutated-host-alias"
	snapshot.Nodes.Set("web-server", node)
	snapshot.Hosts.Set("host-web", host)

	resolvedNode, resolvedHost, _, err := p.Resolve("web-server")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resolvedNode.Alias[0] != "ws1" {
		t.Fatalf("node alias changed through snapshot: %q", resolvedNode.Alias[0])
	}
	if resolvedHost.Alias[0] != "web.example.com" {
		t.Fatalf("host alias changed through snapshot: %q", resolvedHost.Alias[0])
	}
}

func TestProviderResolveSelector_RejectsAmbiguousAddress(t *testing.T) {
	cfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	for _, nodeID := range []string{"root@host", "admin@host"} {
		cfg.Hosts.Set(nodeID, models.Host{Address: "192.0.2.10", Port: 22})
		cfg.Identities.Set(nodeID, models.Identity{User: nodeID[:len(nodeID)-5]})
		cfg.Nodes.Set(nodeID, models.Node{HostRef: nodeID, IdentityRef: nodeID})
	}
	p := NewProviderWithoutOpenSSH(cfg)
	if got := p.Find("192.0.2.10"); got != "" {
		t.Fatalf("Find() = %q, want no implicit selection", got)
	}
	_, err := p.ResolveSelector("192.0.2.10")
	var ambiguous *AmbiguousNodeError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("ResolveSelector() error = %v, want AmbiguousNodeError", err)
	}
	if !errors.Is(err, ErrAmbiguousNode) {
		t.Fatalf("ResolveSelector() error = %v, want ErrAmbiguousNode", err)
	}
	if len(ambiguous.Candidates) != 2 {
		t.Fatalf("ambiguous candidates = %v, want two", ambiguous.Candidates)
	}
}

func newTestProvider() *Provider {
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

	return NewProviderWithoutOpenSSH(cfg)
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

func TestProviderIndexesConfiguredNode(t *testing.T) {
	cfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "1.2.3.4", Port: 22})
	cfg.Identities.Set("i1", models.Identity{User: "root", AuthType: "password"})
	cfg.Nodes.Set("n1", models.Node{
		HostRef:     "h1",
		IdentityRef: "i1",
		Alias:       []string{"mynode"},
	})
	p := NewProviderWithoutOpenSSH(cfg)

	if got := p.Find("mynode"); got != "n1" {
		t.Errorf("Find('mynode') after AddNode = %q, want 'n1'", got)
	}
	if got := p.Find("root@1.2.3.4:22"); got != "n1" {
		t.Errorf("Find('root@1.2.3.4:22') after AddNode = %q, want 'n1'", got)
	}
}

func TestRepositoryDeleteNodeUpdatesProviderIndex(t *testing.T) {
	repository, err := NewRepositoryWithoutOpenSSH(newTestProvider().Snapshot(), &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	// 确认存在
	if got := repository.Find("ws1"); got != "web-server" {
		t.Fatalf("pre-check: Find('ws1') = %q, want 'web-server'", got)
	}

	if _, err := repository.DeleteNodeAtRefContext(t.Context(), repository.View().NodeRefs["web-server"]); err != nil {
		t.Fatalf("DeleteNodeAtRefContext() error = %v", err)
	}

	if got := repository.Find("web-server"); got != "" {
		t.Errorf("Find('web-server') after delete = %q, want empty", got)
	}
	if got := repository.Find("ws1"); got != "" {
		t.Errorf("Find('ws1') after delete = %q, want empty", got)
	}
}

func TestRepositoryDeleteNodeCleansUnusedRefs(t *testing.T) {
	cfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "1.1.1.1"})
	cfg.Identities.Set("i1", models.Identity{User: "u1"})
	cfg.Nodes.Set("n1", models.Node{HostRef: "h1", IdentityRef: "i1"})
	cfg.Nodes.Set("n2", models.Node{HostRef: "h1", IdentityRef: "i1"}) // n2 也引用 h1, i1

	repository, err := NewRepositoryWithoutOpenSSH(cfg, &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	// 1. 删除 n1，应该保留 h1, i1 (因为还有 n2 引用)
	if _, err := repository.DeleteNodeAtRefContext(t.Context(), repository.View().NodeRefs["n1"]); err != nil {
		t.Fatalf("DeleteNodeAtRefContext(n1) error = %v", err)
	}
	if _, ok := repository.Snapshot().Hosts.Get("h1"); !ok {
		t.Error("expected h1 to be preserved as n2 still references it")
	}
	if _, ok := repository.Snapshot().Identities.Get("i1"); !ok {
		t.Error("expected i1 to be preserved as n2 still references it")
	}

	// 2. 删除 n2，应该清理 h1, i1
	if _, err := repository.DeleteNodeAtRefContext(t.Context(), repository.View().NodeRefs["n2"]); err != nil {
		t.Fatalf("DeleteNodeAtRefContext(n2) error = %v", err)
	}
	if _, ok := repository.Snapshot().Hosts.Get("h1"); ok {
		t.Error("expected h1 to be cleaned as no more nodes reference it")
	}
	if _, ok := repository.Snapshot().Identities.Get("i1"); ok {
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

	p := NewProviderWithoutOpenSSH(cfg)

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

func TestRepositoryReplaceNodeClearsStaleIndex(t *testing.T) {
	cfg := &Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "1.2.3.4", Port: 22})
	cfg.Identities.Set("i1", models.Identity{User: "root", AuthType: "password"})
	// 1. 配置中存在带有旧别名的节点。
	node := models.Node{
		HostRef:     "h1",
		IdentityRef: "i1",
		Alias:       []string{"old-alias"},
	}
	cfg.Nodes.Set("n1", node)
	repository, err := NewRepositoryWithoutOpenSSH(cfg, &repositoryTestStore{result: PersistResult{Applied: true, Durable: true}})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	if got := repository.Find("old-alias"); got != "n1" {
		t.Fatalf("Find('old-alias') = %q, want 'n1'", got)
	}

	// 2. 更新节点，别名变更为 new-alias
	node.Alias = []string{"new-alias"}
	if err := repository.ReplaceNodeAtRefContext(t.Context(), repository.View().NodeRefs["n1"], "n1", node, models.Host{Address: "1.2.3.4", Port: 22}, models.Identity{User: "root", AuthType: "password"}); err != nil {
		t.Fatalf("ReplaceNodeAtRefContext() error = %v", err)
	}

	// 3. 验证新别名生效，旧别名失效
	if got := repository.Find("new-alias"); got != "n1" {
		t.Errorf("Find('new-alias') = %q, want 'n1'", got)
	}
	if got := repository.Find("old-alias"); got != "" {
		t.Errorf("Find('old-alias') = %q, want empty after updating node alias", got)
	}
}
