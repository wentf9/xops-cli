package adapter

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/concurrent"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestSSHAdapter_LocalExecutionFence(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "key", KeyPath: "/tmp/id_node"})
	cfg.Nodes.Set("node1", models.Node{HostRef: "h1", IdentityRef: "id1"})

	provider := config.NewProviderWithoutOpenSSH(cfg)

	t.Run("default adapter disables local execution", func(t *testing.T) {
		adp := NewSSHAdapter(provider)
		if adp.localExecution {
			t.Fatalf("expected default SSHAdapter to have localExecution=false")
		}
		if _, err := adp.GetConfig("node1"); err != nil {
			t.Fatalf("GetConfig() without LocalExec options error = %v", err)
		}
	})

	t.Run("non-interactive adapter forces localExecution=false even if WithLocalExecution(true) passed", func(t *testing.T) {
		adp := NewNonInteractiveSSHAdapter(provider, WithLocalExecution(true))
		if adp.localExecution {
			t.Fatalf("expected NewNonInteractiveSSHAdapter to force localExecution=false")
		}
	})

	t.Run("foreground adapter with WithLocalExecution(true) enables local execution", func(t *testing.T) {
		adp := NewSSHAdapter(provider, WithLocalExecution(true))
		if !adp.localExecution {
			t.Fatalf("expected WithLocalExecution(true) to set localExecution=true")
		}
	})

	t.Run("ErrLocalExecutionDisabled sentinel is defined", func(t *testing.T) {
		if !errors.Is(ErrLocalExecutionDisabled, ErrLocalExecutionDisabled) {
			t.Fatalf("expected ErrLocalExecutionDisabled sentinel")
		}
	})
}

func TestSSHAdapter_MultiIdentityFilePriority(t *testing.T) {
	openSSHParser, err := config.NewOpenSSHParserFromReader(strings.NewReader(`
Host virtual-host
  HostName 10.1.1.10
  User vuser
  IdentityFile /tmp/tier4_first
  IdentityFile /tmp/tier4_second
`))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader failed: %v", err)
	}

	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "key", KeyPath: "/tmp/managed_key"})
	cfg.Nodes.Set("managed-node", models.Node{HostRef: "h1", IdentityRef: "id1", OpenSSHAlias: "virtual-host"})

	provider := config.NewProviderWithOpenSSHParser(cfg, openSSHParser)

	t.Run("managed node priority: CLI -i -> CLI -o IdentityFile -> managed node key (no Tier 4 IdentityFile)", func(t *testing.T) {
		ctrlOpts, err := ParseOptionStrings([]string{"IdentityFile=/tmp/cli_opt_key"})
		if err != nil {
			t.Fatalf("ParseOptionStrings failed: %v", err)
		}
		adp := NewSSHAdapter(provider,
			WithSessionAuthOverride("managed-node", SessionAuth{
				KeyPath:  "/tmp/cli_flag_1",
				KeyPaths: []string{"/tmp/cli_flag_1", "/tmp/cli_flag_2"},
			}),
			WithSessionControlOverride("managed-node", ctrlOpts),
		)
		clientCfg, err := adp.GetConfig("managed-node")
		if err != nil {
			t.Fatalf("GetConfig failed: %v", err)
		}
		want := []string{"/tmp/cli_flag_1", "/tmp/cli_flag_2", "/tmp/cli_opt_key", "/tmp/managed_key"}
		if !slices.Equal(clientCfg.KeyPaths, want) {
			t.Fatalf("KeyPaths = %v, want %v", clientCfg.KeyPaths, want)
		}
	})

	t.Run("openssh virtual node priority: CLI -i -> CLI -o IdentityFile -> Tier 4 IdentityFile", func(t *testing.T) {
		ctrlOpts, err := ParseOptionStrings([]string{"IdentityFile=/tmp/cli_opt_key"})
		if err != nil {
			t.Fatalf("ParseOptionStrings failed: %v", err)
		}
		adp := NewSSHAdapter(provider,
			WithSessionAuthOverride("openssh:virtual-host", SessionAuth{
				KeyPath:  "/tmp/cli_flag_1",
				KeyPaths: []string{"/tmp/cli_flag_1"},
			}),
			WithSessionControlOverride("openssh:virtual-host", ctrlOpts),
		)
		clientCfg, err := adp.GetConfig("openssh:virtual-host")
		if err != nil {
			t.Fatalf("GetConfig failed: %v", err)
		}
		want := []string{"/tmp/cli_flag_1", "/tmp/cli_opt_key", "/tmp/tier4_first", "/tmp/tier4_second"}
		if !slices.Equal(clientCfg.KeyPaths, want) {
			t.Fatalf("KeyPaths = %v, want %v", clientCfg.KeyPaths, want)
		}
	})
}

func TestSSHAdapter_HostNameOverrideIsolatedToTarget(t *testing.T) {
	cfg := &config.Configuration{
		Nodes:      concurrent.NewMap[string, models.Node](concurrent.HashString),
		Hosts:      concurrent.NewMap[string, models.Host](concurrent.HashString),
		Identities: concurrent.NewMap[string, models.Identity](concurrent.HashString),
	}
	cfg.Hosts.Set("hj", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Hosts.Set("ht", models.Host{Address: "10.0.0.2", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "password", Password: "secret"})
	cfg.Nodes.Set("jump", models.Node{HostRef: "hj", IdentityRef: "id1"})
	cfg.Nodes.Set("target", models.Node{HostRef: "ht", IdentityRef: "id1", ProxyJump: "jump"})

	provider := config.NewProviderWithoutOpenSSH(cfg)
	adp := NewSSHAdapter(provider,
		WithSessionAuthOverride("target", SessionAuth{HostName: "192.168.99.99"}),
	)

	targetCfg, err := adp.GetConfig("target")
	if err != nil {
		t.Fatalf("GetConfig(target) failed: %v", err)
	}
	if targetCfg.Address != "192.168.99.99" {
		t.Fatalf("target Address = %q, want 192.168.99.99", targetCfg.Address)
	}

	jumpCfg, err := adp.GetConfig("jump")
	if err != nil {
		t.Fatalf("GetConfig(jump) failed: %v", err)
	}
	if jumpCfg.Address != "10.0.0.1" {
		t.Fatalf("jump Address = %q, want 10.0.0.1 (must not inherit target HostName)", jumpCfg.Address)
	}
}
