package adapter

import (
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/utils/concurrent"
)

type adapterTestStore struct{}

func (adapterTestStore) Load() (*config.Configuration, error) { return nil, nil }

func (adapterTestStore) Save(*config.Configuration) error { return nil }

func TestSSHAdapter_NonInteractive(t *testing.T) {
	// 创建一个空配置
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
	}
	provider := config.NewProviderWithoutOpenSSH(cfg)

	// 创建非交互式 adapter
	adp := NewNonInteractiveSSHAdapter(provider)

	// 验证 PromptPassword
	pwd, err := adp.PromptPassword("Enter password:")
	if err == nil {
		t.Error("expected error from PromptPassword in non-interactive mode, got nil")
	}
	if pwd != "" {
		t.Errorf("expected empty password, got %q", pwd)
	}

	// 验证 ConfirmHostKey
	confirmed, err := adp.ConfirmHostKey("127.0.0.1", "sha256-fingerprint")
	if err == nil {
		t.Error("expected error from ConfirmHostKey in non-interactive mode, got nil")
	}
	if confirmed {
		t.Error("expected confirmed to be false in non-interactive mode")
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
