package adapter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

type adapterTestStore struct{}

func (adapterTestStore) Load() (*config.Configuration, error) { return nil, nil }

func (adapterTestStore) Save(*config.Configuration) error { return nil }

func TestSSHAdapter_NonInteractive(t *testing.T) {
	nodeMap := concurrent.NewMap[string, models.Node](concurrent.HashString)
	hostMap := concurrent.NewMap[string, models.Host](concurrent.HashString)
	identityMap := concurrent.NewMap[string, models.Identity](concurrent.HashString)

	hostMap.Set("host-1", models.Host{Address: "127.0.0.1", Port: 22})
	identityMap.Set("id-1", models.Identity{User: "root", AuthType: "password", Password: "pwd"})

	nodeMap.Set("node-su", models.Node{
		HostRef:     "host-1",
		IdentityRef: "id-1",
		SudoMode:    models.SudoModeSu,
	})

	cfg := &config.Configuration{
		Nodes:      nodeMap,
		Identities: identityMap,
		Hosts:      hostMap,
	}
	provider := config.NewProviderWithoutOpenSSH(cfg)

	// 创建非交互式 connector，验证默认策略返回 ErrInteractionRequired
	conn := NewConnector(provider)
	if conn == nil {
		t.Fatal("expected connector to be created, got nil")
	}
	defer func() { _ = conn.CloseAll() }()

	_, err := conn.Connect(context.Background(), "node-su")
	if err == nil {
		t.Fatal("expected interaction required error, got nil")
	}
	if !errors.Is(err, ssh.ErrInteractionRequired) {
		t.Fatalf("expected ssh.ErrInteractionRequired, got: %v", err)
	}
}

func TestSSHAdapterGetConfigOpenSSHVirtualNodeIsSessionLocal(t *testing.T) {
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(`
Host remote-app
    HostName 10.0.0.5
    User deploy
    Port 2200
`))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader() error = %v", err)
	}
	provider := config.NewProviderWithOpenSSHParser(&config.Configuration{}, parser)

	clientConfig, err := NewSSHAdapter(provider).GetConfig(config.OpenSSHNodePrefix + "remote-app")
	if err != nil {
		t.Fatalf("GetConfig() error = %v", err)
	}
	if clientConfig.Address != "10.0.0.5" || clientConfig.User != "deploy" {
		t.Fatalf("unexpected SSH client config: %+v", clientConfig)
	}
	if clientConfig.AuthUpdateToken != "" || clientConfig.SudoUpdateToken != "" {
		t.Fatalf("virtual OpenSSH node must not carry persistence tokens: %+v", clientConfig)
	}
}

func TestSSHAdapterRejectsEmptyPersistenceToken(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	cfg.Nodes.Set("persisted", models.Node{HostRef: "host", IdentityRef: "identity", SudoMode: models.SudoModeAuto})
	cfg.Hosts.Set("host", models.Host{Address: "192.0.2.1", Port: 22})
	cfg.Identities.Set("identity", models.Identity{User: "root"})
	repository, err := config.NewRepositoryWithoutOpenSSH(cfg, adapterTestStore{})
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH() error = %v", err)
	}

	adapter := NewSSHAdapter(repository)
	if err := adapter.UpdateSudo(t.Context(), "persisted", "", "sudo", ""); err == nil {
		t.Fatal("UpdateSudo() error = nil for empty persistence token")
	}
	node, ok := repository.GetNode("persisted")
	if !ok {
		t.Fatal("persisted node is missing")
	}
	if node.SudoMode != models.SudoModeAuto {
		t.Fatalf("empty token changed sudo mode to %q", node.SudoMode)
	}
}
