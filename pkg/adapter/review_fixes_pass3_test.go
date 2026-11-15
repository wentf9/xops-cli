package adapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
)

func TestH6_DisambiguatedOpenSSHPendingNodePreservesOptionsAndIdentity(t *testing.T) {
	dir := t.TempDir()
	keyA := filepath.Join(dir, "id_a")
	keyB := filepath.Join(dir, "id_b")
	extraKey := filepath.Join(dir, "extra_key")
	for _, p := range []string{keyA, keyB, extraKey} {
		if err := os.WriteFile(p, []byte("dummy"), 0o600); err != nil {
			t.Fatalf("write key %s: %v", p, err)
		}
	}

	cmPathB := filepath.Join(dir, "cm-b-%C")
	sshCfgPath := filepath.Join(dir, "ssh_config")
	sshCfg := strings.Join([]string{
		"Host role-a",
		"  HostName 10.0.0.5",
		"  Port 22",
		"  User reader",
		"  IdentityFile " + keyA,
		"  Ciphers aes128-gcm@openssh.com",
		"  ProxyCommand nc -X connect %h %p",
		"Host role-b",
		"  HostName 10.0.0.5",
		"  Port 22",
		"  User writer",
		"  IdentityFile " + keyB,
		"  Ciphers chacha20-poly1305@openssh.com",
		"  HashKnownHosts yes",
		"  ControlMaster auto",
		"  ControlPath " + cmPathB,
		"  ProxyJump bastion.example.com",
	}, "\n") + "\n"
	if err := os.WriteFile(sshCfgPath, []byte(sshCfg), 0o600); err != nil {
		t.Fatalf("write ssh_config: %v", err)
	}

	globalOpts := &ssh.Options{}
	_ = globalOpts.Set(ssh.OptionProxyCommand, "global-proxy %h %p")
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.SSHOptions = globalOpts

	store := config.NewDefaultStore(filepath.Join(dir, "xops_config.yaml"), filepath.Join(dir, "xops.key"))
	repo, err := config.NewRepositoryWithoutOpenSSH(cfg, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	provider, err := config.WithOpenSSHConfigOverride(repo, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride: %v", err)
	}

	preparer := provider.(interface {
		PrepareNodeContext(context.Context, config.EnsureNodeOptions) (config.EnsureNodeResult, error)
	})
	resA, err := preparer.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "role-a", User: "ops", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(role-a): %v", err)
	}
	resB, err := preparer.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "role-b", User: "ops", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(role-b): %v", err)
	}
	if !strings.HasPrefix(resB.NodeID, config.OpenSSHNodePrefix) {
		t.Fatalf("expected disambiguated OpenSSH nodeID for role-b, got %q", resB.NodeID)
	}

	// Repository.ResolveConnection and PendingNodeExecution must treat disambiguated
	// openssh: nodes as session-ephemeral (UpdateRef == nil, PendingNodeExecution == false).
	underlying := config.NewProviderWithoutOpenSSH(nil)
	_ = underlying
	if snapB, snapErr := provider.ResolveConnection(resB.NodeID); snapErr != nil {
		t.Fatalf("ResolveConnection(role-b): %v", snapErr)
	} else if snapB.UpdateRef != nil {
		t.Fatalf("expected UpdateRef == nil for %q, got %+v", resB.NodeID, snapB.UpdateRef)
	}

	adp := NewSSHAdapter(provider,
		WithLocalExecution(true),
		WithSessionAuthOverride(resA.NodeID, SessionAuth{KeyPaths: []string{extraKey}}),
		WithSessionAuthOverride(resB.NodeID, SessionAuth{KeyPaths: []string{extraKey}}),
	)

	verifyDisambiguatedRoleB(t, adp, resB.NodeID, extraKey, keyB, cmPathB)

	// Without Tier-3 global ProxyCommand, collided role-b retains Tier-4 ProxyJump.
	cfgNoProxy := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	repoNoProxy, err := config.NewRepositoryWithoutOpenSSH(cfgNoProxy, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH(no-proxy): %v", err)
	}
	provNoProxy, err := config.WithOpenSSHConfigOverride(repoNoProxy, sshCfgPath)
	if err != nil {
		t.Fatalf("WithOpenSSHConfigOverride(no-proxy): %v", err)
	}
	prepNoProxy := provNoProxy.(interface {
		PrepareNodeContext(context.Context, config.EnsureNodeOptions) (config.EnsureNodeResult, error)
	})
	if _, err := prepNoProxy.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "role-a", User: "ops", HasUser: true},
	}); err != nil {
		t.Fatalf("PrepareNodeContext(role-a, no-proxy): %v", err)
	}
	resBNoProxy, err := prepNoProxy.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "role-b", User: "ops", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(role-b, no-proxy): %v", err)
	}
	adpNoProxy := NewSSHAdapter(provNoProxy, WithLocalExecution(true))
	cfgBNoProxy, err := adpNoProxy.GetConfig(resBNoProxy.NodeID)
	if err != nil {
		t.Fatalf("GetConfig(role-b, no-proxy): %v", err)
	}
	if cfgBNoProxy.ProxyJump != "openssh:bastion.example.com" {
		t.Fatalf("role-b (no Tier-3 ProxyCommand) ProxyJump = %q, want openssh:bastion.example.com", cfgBNoProxy.ProxyJump)
	}
}

func verifyDisambiguatedRoleB(t *testing.T, adp *SSHAdapter, nodeID, extraKey, keyB, cmPathB string) {
	t.Helper()
	cfgB, err := adp.GetConfig(nodeID)
	if err != nil {
		t.Fatalf("GetConfig(role-b): %v", err)
	}
	optsB, err := adp.ResolveSSHOptions(nodeID, SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveSSHOptions(role-b): %v", err)
	}
	if optsB == nil {
		t.Fatalf("expected non-nil ResolveSSHOptions for role-b")
	}
	if got := optsB.Get(ssh.OptionCiphers); got != "chacha20-poly1305@openssh.com" {
		t.Fatalf("role-b Ciphers = %q, want chacha20-poly1305@openssh.com", got)
	}
	if got := optsB.Get(ssh.OptionHashKnownHosts); got != "yes" {
		t.Fatalf("role-b HashKnownHosts = %q, want yes", got)
	}
	if got := optsB.Get(ssh.OptionProxyCommand); got != "global-proxy %h %p" {
		t.Fatalf("expected Tier-3 global ProxyCommand to override Tier-4 ProxyJump, got %q", got)
	}
	if cfgB.Options == nil || cfgB.Options.Get(ssh.OptionCiphers) != "chacha20-poly1305@openssh.com" {
		t.Fatalf("role-b cfgB.Options Ciphers = %v, want chacha20-poly1305@openssh.com", cfgB.Options)
	}
	if cfgB.ProxyJump != "" {
		t.Fatalf("expected Tier-3 global ProxyCommand to clear Tier-4 ProxyJump, got %q", cfgB.ProxyJump)
	}
	if len(cfgB.KeyPaths) != 2 || cfgB.KeyPaths[0] != extraKey || cfgB.KeyPaths[1] != keyB {
		t.Fatalf("role-b KeyPaths = %v, want [%s %s]", cfgB.KeyPaths, extraKey, keyB)
	}

	ctrlB, err := adp.GetControlConfig(nodeID)
	if err != nil {
		t.Fatalf("GetControlConfig(role-b): %v", err)
	}
	if ctrlB == nil || ctrlB.Master != "auto" || ctrlB.Path != cmPathB {
		t.Fatalf("role-b ControlConfig = %+v, want Master=auto Path=%q", ctrlB, cmPathB)
	}
}
