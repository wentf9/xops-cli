package adapter

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestRound6_P2_4_SavedNodeWildcardPass2ExplicitIsolationAndSnapErrPrecedence(t *testing.T) {
	t.Parallel()

	sshCfg := strings.Join([]string{
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
		"",
		"Host *.corp.example.com",
		"  HostName 10.60.0.1",
		"  ConnectTimeout 19",
		"",
		"Host short-a",
		"  ServerAliveInterval 77",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.60.0.1", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops"})
	cfg.Nodes.Set("ops@10.60.0.1:22", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		Alias:       []string{"my-box"},
	})
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "c.yaml"), filepath.Join(t.TempDir(), "c.key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	// Seed shared side-map from Session 1 (short-a -> short-a.corp.example.com).
	repo.SetNodeOpenSSHOrigin("ops@10.60.0.1:22", config.OpenSSHOrigin{
		Alias:         "short-a",
		CanonicalHost: "short-a.corp.example.com",
	})

	// 1. Wildcard-only Pass-2 canonicalization (short-b has NO concrete Host block) must
	// resolve ConnectTimeout=19 & CanonicalHost=short-b.corp.example.com without being hijacked by short-a.
	adpWild := NewSSHAdapter(repo, WithSessionAuthOverride("ops@10.60.0.1:22", SessionAuth{
		OriginalHost:  "short-b",
		CanonicalHost: "short-b.corp.example.com",
	}))
	cfgWild, err := adpWild.GetConfig("ops@10.60.0.1:22")
	if err != nil {
		t.Fatalf("GetConfig(wildcard Pass-2): %v", err)
	}
	if cfgWild.CanonicalHost != "short-b.corp.example.com" || cfgWild.Options.Get(ssh.OptionConnectTimeout) != "19" {
		t.Fatalf("wildcard Pass-2 failed: canon=%q ConnectTimeout=%q", cfgWild.CanonicalHost, cfgWild.Options.Get(ssh.OptionConnectTimeout))
	}
	if got := cfgWild.Options.Get(ssh.OptionServerAliveInterval); got != "" {
		t.Fatalf("short-a side-map leaked ServerAliveInterval=%q into short-b session", got)
	}

	// 2. Session with explicit non-OpenSSH XOps alias ("my-box") must NOT fall back to shared short-a side-map.
	adpMyBox := NewSSHAdapter(repo, WithSessionAuthOverride("ops@10.60.0.1:22", SessionAuth{
		OriginalHost: "my-box",
	}))
	cfgMyBox, err := adpMyBox.GetConfig("ops@10.60.0.1:22")
	if err != nil {
		t.Fatalf("GetConfig(my-box): %v", err)
	}
	if cfgMyBox.CanonicalHost != "" || cfgMyBox.Options.Get(ssh.OptionServerAliveInterval) != "" {
		t.Fatalf("explicit my-box session polluted by shared side-map: canon=%q ServerAliveInterval=%q",
			cfgMyBox.CanonicalHost, cfgMyBox.Options.Get(ssh.OptionServerAliveInterval))
	}

	// 3. snapErr != nil (unsaved nodeName) prefers atomic Tier-1 origin over shared side-map without chimeras.
	repo.SetNodeOpenSSHOrigin("unsaved-node", config.OpenSSHOrigin{Alias: "old-alias", CanonicalHost: "old.corp"})
	adpUnsaved := NewSSHAdapter(repo, WithSessionAuthOverride("unsaved-node", SessionAuth{
		OriginalHost: "new-alias",
	}))
	gotAlias, gotCanon := adpUnsaved.resolveSessionOpenSSHMetadata(parser, "unsaved-node", config.ErrNodeNotFound, config.ConnectionSnapshot{}, SessionAuth{
		OriginalHost: "new-alias",
	})
	if gotAlias != "new-alias" || gotCanon != "" {
		t.Fatalf("snapErr != nil formed chimera or inverted precedence: (%q, %q), want (new-alias, \"\")", gotAlias, gotCanon)
	}
}

func TestRound6_P2_6_ProxyJumpCommaConsistencyBetweenControlAndGetConfig(t *testing.T) {
	t.Parallel()

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h1", models.Host{Address: "10.61.0.1", Port: 22})
	cfg.Hosts.Set("h2", models.Host{Address: "10.61.0.2", Port: 22})
	cfg.Identities.Set("id1", models.Identity{User: "ops"})
	cfg.Nodes.Set("comma-saved", models.Node{
		HostRef:     "h1",
		IdentityRef: "id1",
		ProxyJump:   " , ",
		SSHOptions:  ssh.MustOptions(ssh.OptionControlPath, "/tmp/cm-%j-%h"),
	})
	cfg.Nodes.Set("bastion-saved", models.Node{
		HostRef:     "h2",
		IdentityRef: "id1",
		ProxyJump:   "bastion",
		SSHOptions:  ssh.MustOptions(ssh.OptionControlPath, "/tmp/cm-%j-%h", ssh.OptionProxyCommand, "nc %h %p"),
	})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	// 1. Saved node with ProxyJump=" , " must expand %j as "" (not ",") matching GetConfig.
	adp := NewSSHAdapter(prov)
	gotCfg, err := adp.GetConfig("comma-saved")
	if err != nil {
		t.Fatalf("GetConfig(comma-saved): %v", err)
	}
	if gotCfg.ProxyJump != "" {
		t.Fatalf("GetConfig(comma-saved).ProxyJump = %q, want empty", gotCfg.ProxyJump)
	}
	ctrlPath, err := adp.ExpandControlPath("comma-saved", "/tmp/cm-%j-%h")
	if err != nil {
		t.Fatalf("ExpandControlPath(comma-saved): %v", err)
	}
	if ctrlPath != "/tmp/cm--10.61.0.1" {
		t.Fatalf("ExpandControlPath(comma-saved) = %q, want /tmp/cm--10.61.0.1 (JumpHost must be empty)", ctrlPath)
	}

	// 2. CLI SessionAuth{ProxyJump: " , "} disables lower-tier saved ProxyJump="bastion"
	// consistently across GetConfig and ExpandControlPath while preserving ProxyCommand.
	adpOverride := NewSSHAdapter(prov, WithLocalExecution(true), WithSessionAuthOverride("bastion-saved", SessionAuth{
		ProxyJump: " , ",
	}))
	gotOverride, err := adpOverride.GetConfig("bastion-saved")
	if err != nil {
		t.Fatalf("GetConfig(bastion-saved override): %v", err)
	}
	if gotOverride.ProxyJump != "" {
		t.Fatalf("GetConfig(bastion-saved override).ProxyJump = %q, want empty", gotOverride.ProxyJump)
	}
	if gotOverride.Options.ActiveProxyCommand() != "nc %h %p" {
		t.Fatalf("ProxyCommand = %q, want nc %%h %%p", gotOverride.Options.ActiveProxyCommand())
	}
	overrideCtrlPath, err := adpOverride.ExpandControlPath("bastion-saved", "/tmp/cm-%j-%h")
	if err != nil {
		t.Fatalf("ExpandControlPath(bastion-saved override): %v", err)
	}
	if overrideCtrlPath != "/tmp/cm--10.61.0.2" {
		t.Fatalf("ExpandControlPath(bastion-saved override) = %q, want /tmp/cm--10.61.0.2", overrideCtrlPath)
	}
}
