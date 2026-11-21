package adapter

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestPass9_H1_UnpersistedUserOverrideOpenSSHNodePreservesTier4AndGuardrails(t *testing.T) {
	dir := t.TempDir()
	keyA := filepath.Join(dir, "id_a")
	keyB := filepath.Join(dir, "id_b")
	for _, p := range []string{keyA, keyB} {
		if err := os.WriteFile(p, []byte("dummy"), 0o600); err != nil {
			t.Fatalf("write key %s: %v", p, err)
		}
	}

	sshCfgPath := filepath.Join(dir, "ssh_config")
	sshCfg := strings.Join([]string{
		"Host role-a",
		"  HostName 10.0.0.5",
		"  Port 22",
		"  User reader",
		"  IdentityFile " + keyA,
		"",
		"Host role-b",
		"  HostName 10.0.0.5",
		"  Port 22",
		"  User writer",
		"  IdentityFile " + keyB,
		"  SetEnv APP_ROLE=b",
		"  SendEnv LC_ALL",
		"  ProxyCommand nc %h %p",
		"",
		"Host role-jump",
		"  HostName 10.0.0.6",
		"  Port 22",
		"  User writer",
		"  ProxyJump role-a",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	store := config.NewDefaultStore(filepath.Join(dir, "xops_config.yaml"), filepath.Join(dir, "xops.key"))
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	provider, err := config.WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}
	// Prepare ONLY role-b first so it gets a non-collided pending ID ("ops@10.0.0.5:22"), NOT openssh:...!
	if err := config.WithPendingNode(t.Context(), provider, config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "role-b", User: "ops", HasUser: true},
	}, func(leaseB config.PendingLease) error {
		resBID := leaseB.NodeID()
		if strings.HasPrefix(resBID, config.OpenSSHNodePrefix) {
			t.Fatalf("expected non-collided pending ID, got %q", resBID)
		}

		restrictedAdp := NewSSHAdapter(provider, WithLocalExecution(false))
		if _, err := restrictedAdp.GetConfig(resBID); !errors.Is(err, ErrLocalExecutionDisabled) {
			t.Fatalf("expected ErrLocalExecutionDisabled on unpersisted pending OpenSSH alias %q, got %v", resBID, err)
		}

		adp := NewSSHAdapter(provider, WithLocalExecution(true), WithSessionAndForwardOptions(true))
		cfgB, err := adp.GetConfig(resBID)
		if err != nil {
			t.Fatalf("GetConfig(%q): %v", resBID, err)
		}
		if cfgB.Options == nil {
			t.Fatal("expected non-nil cfgB.Options")
		}
		if got := cfgB.Options.ActiveProxyCommand(); got != "nc %h %p" {
			t.Errorf("ActiveProxyCommand = %q, want %q", got, "nc %h %p")
		}
		if !slices.Contains(cfgB.Options.SetEnvDirectives(), "APP_ROLE=b") {
			t.Errorf("SetEnvDirectives = %v, want APP_ROLE=b", cfgB.Options.SetEnvDirectives())
		}
		if !slices.Contains(cfgB.Options.SendEnvPatterns(), "LC_ALL") {
			t.Errorf("SendEnvPatterns = %v, want LC_ALL", cfgB.Options.SendEnvPatterns())
		}
		if !slices.Contains(cfgB.Options.IdentityFiles(), keyB) {
			t.Errorf("IdentityFiles = %v, want %s", cfgB.Options.IdentityFiles(), keyB)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode(role-b): %v", err)
	}

	// Collided/explicit openssh:role-jump allows Tier-3 global ProxyCommand to override Tier-4 ProxyJump.
	verifyTier3ProxyCommandOverridesTier4ProxyJump(t, dir, sshCfgPath)
}

func verifyTier3ProxyCommandOverridesTier4ProxyJump(t *testing.T, dir, sshCfgPath string) {
	t.Helper()
	cfg2 := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	if cfg2.SSHOptions == nil {
		cfg2.SSHOptions = &ssh.Options{}
	}
	if err := cfg2.SSHOptions.Set(ssh.OptionProxyCommand, "nc -x %h %p"); err != nil {
		t.Fatalf("SSHOptions.Set(ProxyCommand): %v", err)
	}
	repo2, err := config.NewRepositoryWithoutOpenSSH(cfg2, config.NewDefaultStore(
		filepath.Join(dir, "xops_config_2.yaml"),
		filepath.Join(dir, "xops_2.key"),
	))
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH #2: %v", err)
	}
	provider2, err := config.WithOpenSSHConfigOverride(repo2, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride #2: %v", err)
	}
	adp2 := NewSSHAdapter(provider2, WithLocalExecution(true))
	cfgJump, err := adp2.GetConfig(config.OpenSSHNodePrefix + "role-jump")
	if err != nil {
		t.Fatalf("GetConfig(openssh:role-jump): %v", err)
	}
	if cfgJump.ProxyJump != "" {
		t.Errorf("expected Tier-3 global ProxyCommand to override Tier-4 ProxyJump, got ProxyJump=%q", cfgJump.ProxyJump)
	}
	if got := cfgJump.Options.ActiveProxyCommand(); got != "nc -x %h %p" {
		t.Errorf("ActiveProxyCommand = %q, want %q", got, "nc -x %h %p")
	}
}
