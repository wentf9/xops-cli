package ssh

import (
	"context"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
	"golang.org/x/crypto/ssh"
)

func TestConnector_FetchNodeConfig(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Nodes.Set("node-1", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
	})
	cfg.Hosts.Set("host-1", models.Host{
		Address: "10.0.0.1",
		Port:    22,
	})
	cfg.Identities.Set("id-1", models.Identity{
		User:     "admin",
		AuthType: "password",
	})

	provider := config.NewProvider(cfg)
	connector := NewConnector(provider)

	node, host, identity, err := connector.fetchNodeConfig("node-1")
	if err != nil {
		t.Fatalf("fetchNodeConfig failed: %v", err)
	}

	if node.HostRef != "host-1" || node.IdentityRef != "id-1" {
		t.Errorf("unexpected node config: %+v", node)
	}
	if host.Address != "10.0.0.1" || host.Port != 22 {
		t.Errorf("unexpected host config: %+v", host)
	}
	if identity.User != "admin" || identity.AuthType != "password" {
		t.Errorf("unexpected identity config: %+v", identity)
	}
}

func TestConnector_Connect_Cached(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}

	cfg.Nodes.Set("node-1", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
	})
	cfg.Hosts.Set("host-1", models.Host{
		Address: "10.0.0.1",
		Port:    22,
	})
	cfg.Identities.Set("id-1", models.Identity{
		User:     "admin",
		AuthType: "password",
	})

	provider := config.NewProvider(cfg)
	connector := NewConnector(provider)

	// 模拟已存在缓存连接
	dummyClient := &ssh.Client{}
	connector.clients.Set("node-1", dummyClient)

	ctx := context.Background()
	client, err := connector.Connect(ctx, "node-1")
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	// 验证在缓存命中时，能否正确通过修复后的 GetHost/GetIdentity 方法拿到对应的真实配置
	if client.host.Address != "10.0.0.1" {
		t.Errorf("expected host address '10.0.0.1', got %q", client.host.Address)
	}
	if client.identity.User != "admin" {
		t.Errorf("expected identity user 'admin', got %q", client.identity.User)
	}
}
