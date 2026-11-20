package adapter

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound3_P1_1_GetConfigAndResolveControlPreservePass1AndPercentN(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host short",
		"  User pass1-user",
		"  Port 2201",
		"  IdentityFile /tmp/r3-adp-pass1",
		"  ControlPath /tmp/r3-cm-%n-%h-%p",
		"",
		"Host *.corp.example.com",
		"  ConnectTimeout 11",
		"  ServerAliveInterval 19",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}
	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(nil, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser error = %v", err)
	}

	res, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector:     config.OpenSSHNodePrefix + "alice@short.corp.example.com:2222",
			OriginalHost: "short",
		},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext error = %v", err)
	}

	adp := NewSSHAdapter(repo)
	cfg, err := adp.GetConfig(res.NodeID)
	if err != nil {
		t.Fatalf("GetConfig error = %v", err)
	}
	if cfg.OriginalHost != "short" {
		t.Fatalf("OriginalHost = %q, want %q", cfg.OriginalHost, "short")
	}
	if cfg.User != "alice" || cfg.Port != 2222 {
		t.Fatalf("user/port = (%q, %d), want (alice, 2222)", cfg.User, cfg.Port)
	}
	if !strings.HasSuffix(cfg.KeyPath, "/tmp/r3-adp-pass1") {
		t.Fatalf("Pass-1 KeyPath lost: %q", cfg.KeyPath)
	}
	if got := cfg.Options.Get(ssh.OptionConnectTimeout); got != "11" {
		t.Fatalf("Pass-2 ConnectTimeout lost: %q", got)
	}

	ctrl, err := adp.ResolveControl(res.NodeID, SessionControlOptions{})
	if err != nil {
		t.Fatalf("ResolveControl error = %v", err)
	}
	expanded, err := adp.ExpandControlPath(res.NodeID, ctrl.Path)
	if err != nil {
		t.Fatalf("ExpandControlPath error = %v", err)
	}
	if !strings.HasSuffix(expanded, "/tmp/r3-cm-short-short.corp.example.com-2222") {
		t.Fatalf("ControlPath %%n expansion = %q", expanded)
	}
}

func TestRound3_P2_10_Tier4LookupWithOpenSSHAliasFallbackAndConcreteCanonical(t *testing.T) {
	t.Parallel()

	// Only CanonicalHost (short.corp.example.com) has a concrete Host block;
	// short is matched via Match host short + Host *.
	sshCfg := strings.Join([]string{
		"Match host short",
		"  ServerAliveInterval 15",
		"",
		"Host short.corp.example.com",
		"  HostName 10.90.0.10",
		"  ConnectTimeout 7",
		"",
		"Host other-same-ip",
		"  HostName 10.90.0.10",
		"  ConnectTimeout 99",
		"",
		"Host *",
		"  ServerAliveCountMax 4",
	}, "\n") + "\n"

	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader error = %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.90.0.10", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "password"})
	// Node has empty Node.OpenSSHAlias/CanonicalHost fields, relying on Provider lookup fallback.
	nodeID := "ops@10.90.0.10:22"
	cfg.Nodes.Set(nodeID, models.Node{HostRef: "h1", IdentityRef: "id1"})

	prov := config.NewProviderWithOpenSSHParser(cfg, parser)
	prov.SetNodeOpenSSHAlias(nodeID, "short")
	prov.SetNodeCanonicalHost(nodeID, "short.corp.example.com")

	adp := NewSSHAdapter(prov)
	clientCfg, err := adp.GetConfig(nodeID)
	if err != nil {
		t.Fatalf("GetConfig error = %v", err)
	}
	if got := clientCfg.Options.Get(ssh.OptionConnectTimeout); got != "7" {
		t.Fatalf("ConnectTimeout = %q, want 7 (concrete CanonicalHost without falling back to competing IP host)", got)
	}
	if got := clientCfg.Options.Get(ssh.OptionServerAliveInterval); got != "15" {
		t.Fatalf("ServerAliveInterval = %q, want 15 (Pass-1 Match host option preserved)", got)
	}
}

func TestRound3_P2_11_ParseOptionStringsWithJump(t *testing.T) {
	t.Parallel()

	// CLI -J none blocks subsequent -o ProxyJump=bastion so -o ProxyCommand remains active.
	opts, err := ParseOptionStringsWithJump([]string{"ProxyJump=bastion", "ProxyCommand=nc %h %p"}, "none")
	if err != nil {
		t.Fatalf("ParseOptionStringsWithJump error = %v", err)
	}
	if opts.Options == nil || opts.Options.Get(ssh.OptionProxyCommand) != "nc %h %p" {
		t.Fatalf("expected ProxyCommand preserved when CLI -J none blocks -o ProxyJump=bastion, got %+v", opts.Options)
	}

	// CLI -J bastion blocks subsequent -o ProxyCommand.
	optsBlocked, err := ParseOptionStringsWithJump([]string{"ProxyCommand=nc %h %p"}, "bastion")
	if err != nil {
		t.Fatalf("ParseOptionStringsWithJump error = %v", err)
	}
	if optsBlocked.Options != nil && optsBlocked.Options.Get(ssh.OptionProxyCommand) != "" {
		t.Fatalf("expected active CLI -J to suppress -o ProxyCommand, got %q", optsBlocked.Options.Get(ssh.OptionProxyCommand))
	}
}

func TestRound3_P3_7_ControlTargetContextNoneNormalizationAndDoubleNone(t *testing.T) {
	t.Parallel()

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.91.0.10", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "password"})
	cfg.Nodes.Set("node-none", models.Node{HostRef: "h1", IdentityRef: "id1", ProxyJump: "none"})
	cfg.Nodes.Set("node-jump", models.Node{HostRef: "h1", IdentityRef: "id1", ProxyJump: "saved-bastion"})

	prov := config.NewProviderWithoutOpenSSH(cfg)

	adpNone := NewSSHAdapter(prov)
	expandedNone, err := adpNone.ExpandControlPath("node-none", "/tmp/j-%j")
	if err != nil {
		t.Fatalf("ExpandControlPath(node-none) error = %v", err)
	}
	if expandedNone != "/tmp/j-" {
		t.Fatalf("ExpandControlPath(ProxyJump=none node) = %q, want /tmp/j-", expandedNone)
	}

	adpDoubleNone := NewSSHAdapter(prov, WithSessionAuthOverride("node-jump", SessionAuth{ProxyJump: "none,none"}))
	expandedDoubleNone, err := adpDoubleNone.ExpandControlPath("node-jump", "/tmp/j-%j")
	if err != nil {
		t.Fatalf("ExpandControlPath(none,none) error = %v", err)
	}
	if expandedDoubleNone != "/tmp/j-" {
		t.Fatalf("ExpandControlPath(ProxyJump=none,none override) = %q, want /tmp/j-", expandedDoubleNone)
	}
}
