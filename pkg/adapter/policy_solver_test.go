package adapter

import (
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestSolveProxyPrecedencePureMatrix(t *testing.T) {
	mkProxyOpts := func(cmd string) *ssh.Options {
		o, err := ssh.NewOptions()
		if err != nil {
			t.Fatal(err)
		}
		if err := o.Set(ssh.OptionProxyCommand, cmd); err != nil {
			t.Fatal(err)
		}
		return o
	}

	t.Run("tier1_jump_masks_all_lower_proxycommands", func(t *testing.T) {
		assertTier1JumpMasksAllLower(t, mkProxyOpts)
	})

	t.Run("saved_node_jump_masks_tier3_and_tier4_while_tier1_cmd_overrides", func(t *testing.T) {
		assertSavedJumpMasksLowerAndTier1CmdOverrides(t, mkProxyOpts)
	})

	t.Run("unpersisted_openssh_jump_overridden_by_tier3_proxycommand", func(t *testing.T) {
		assertUnpersistedJumpOverriddenByTier3(t, mkProxyOpts)
	})

	t.Run("unpersisted_openssh_jump_masks_tier4_proxycommand", func(t *testing.T) {
		assertUnpersistedJumpMasksTier4(t, mkProxyOpts)
	})

	t.Run("tier1_jump_none_does_not_mask_lower_proxycommand", func(t *testing.T) {
		t3 := mkProxyOpts("global-cmd %h %p")
		snap := config.ConnectionSnapshot{
			Node:       models.Node{ProxyJump: "saved-jump"},
			Provenance: config.ProvenanceSavedManaged,
		}
		_, m3, _, higherCmdWins := solveProxyPrecedence(proxyDisabled, nil, snap, true, nil, t3, nil)
		if higherCmdWins {
			t.Fatal("tier1 ProxyJump=none must not claim higherCmdWins")
		}
		if got := m3.Get(ssh.OptionProxyCommand); got != "global-cmd %h %p" {
			t.Fatalf("expected tier1 -J none to preserve Tier-3 ProxyCommand, got %q", got)
		}
	})

	t.Run("tier1_proxycommand_none_shadows_tier3_active_command_over_tier4_jump", func(t *testing.T) {
		t3 := mkProxyOpts("global-cmd %h %p")
		snap := config.ConnectionSnapshot{
			Node:       models.Node{ProxyJump: "openssh:jump"},
			Provenance: config.ProvenanceOpenSSHVirtual,
		}
		_, _, _, higherCmdWins := solveProxyPrecedence(proxyUnset, mkProxyOpts("none"), snap, true, nil, t3, nil)
		if higherCmdWins {
			t.Fatal("tier1 ProxyCommand=none must stop higher-tier ProxyCommand search before tier3")
		}
	})
}

func assertTier1JumpMasksAllLower(t *testing.T, mkProxyOpts func(string) *ssh.Options) {
	t.Helper()
	t2 := mkProxyOpts("t2-cmd %h %p")
	t3 := mkProxyOpts("t3-cmd %h %p")
	t4 := mkProxyOpts("t4-cmd %h %p")
	snap := config.ConnectionSnapshot{
		Node:       models.Node{ProxyJump: "saved-jump"},
		Provenance: config.ProvenanceSavedManaged,
	}
	m2, m3, m4, higherCmdWins := solveProxyPrecedence(proxyActive, mkProxyOpts("t1-cmd %h %p"), snap, true, t2, t3, t4)
	if higherCmdWins {
		t.Fatal("tier1 active ProxyJump must not allow higherTierProxyCommandWins")
	}
	if m2.Get(ssh.OptionProxyCommand) != "" || m3.Get(ssh.OptionProxyCommand) != "" || m4.Get(ssh.OptionProxyCommand) != "" {
		t.Fatalf("expected all lower ProxyCommand masked, got m2=%q m3=%q m4=%q",
			m2.Get(ssh.OptionProxyCommand), m3.Get(ssh.OptionProxyCommand), m4.Get(ssh.OptionProxyCommand))
	}
}

func assertSavedJumpMasksLowerAndTier1CmdOverrides(t *testing.T, mkProxyOpts func(string) *ssh.Options) {
	t.Helper()
	t2 := mkProxyOpts("t2-cmd %h %p")
	t3 := mkProxyOpts("t3-cmd %h %p")
	t4 := mkProxyOpts("t4-cmd %h %p")
	snap := config.ConnectionSnapshot{
		Node:       models.Node{ProxyJump: "saved-jump"},
		Provenance: config.ProvenanceSavedManaged,
	}
	m2, m3, m4, higherCmdWinsNoT1 := solveProxyPrecedence(proxyUnset, nil, snap, true, t2, t3, t4)
	if higherCmdWinsNoT1 {
		t.Fatal("tier3 ProxyCommand must not override saved node ProxyJump")
	}
	if m2.Get(ssh.OptionProxyCommand) != "" || m3.Get(ssh.OptionProxyCommand) != "" || m4.Get(ssh.OptionProxyCommand) != "" {
		t.Fatalf("saved node ProxyJump must mask tier2, tier3, and tier4 ProxyCommand, got m2=%q m3=%q m4=%q",
			m2.Get(ssh.OptionProxyCommand), m3.Get(ssh.OptionProxyCommand), m4.Get(ssh.OptionProxyCommand))
	}
	_, _, _, higherCmdWinsWithT1 := solveProxyPrecedence(proxyUnset, mkProxyOpts("cli-cmd %h %p"), snap, true, t2, t3, t4)
	if !higherCmdWinsWithT1 {
		t.Fatal("tier1 ProxyCommand must override saved node ProxyJump")
	}
	_, _, _, noneCmdNoOverride := solveProxyPrecedence(proxyUnset, mkProxyOpts("none"), snap, true, t2, t3, t4)
	if noneCmdNoOverride {
		t.Fatal("tier1 ProxyCommand=none must not claim higherTierProxyCommandWins")
	}
}

func assertUnpersistedJumpOverriddenByTier3(t *testing.T, mkProxyOpts func(string) *ssh.Options) {
	t.Helper()
	for _, prov := range []config.NodeProvenance{config.ProvenanceOpenSSHVirtual, config.ProvenanceOpenSSHDerived} {
		t3 := mkProxyOpts("global-cmd %h %p")
		t4 := mkProxyOpts("t4-cmd %h %p")
		snap := config.ConnectionSnapshot{
			Node:       models.Node{ProxyJump: "openssh:jump"},
			Provenance: prov,
		}
		_, m3, m4, higherCmdWins := solveProxyPrecedence(proxyUnset, nil, snap, true, nil, t3, t4)
		if !higherCmdWins {
			t.Errorf("%s: expected tier3 global ProxyCommand to override Tier-4 ProxyJump", prov)
		}
		if m3.Get(ssh.OptionProxyCommand) == "" || m4.Get(ssh.OptionProxyCommand) == "" {
			t.Errorf("%s: unpersisted OpenSSH ProxyJump must not mask tier3/tier4 ProxyCommand", prov)
		}
	}
}

func assertUnpersistedJumpMasksTier4(t *testing.T, mkProxyOpts func(string) *ssh.Options) {
	t.Helper()
	for _, prov := range []config.NodeProvenance{config.ProvenanceOpenSSHVirtual, config.ProvenanceOpenSSHDerived} {
		t4 := mkProxyOpts("t4-cmd %h %p")
		snap := config.ConnectionSnapshot{
			Node:       models.Node{ProxyJump: "openssh:jump"},
			Provenance: prov,
		}
		_, _, m4, higherCmdWins := solveProxyPrecedence(proxyUnset, nil, snap, true, nil, nil, t4)
		if higherCmdWins {
			t.Errorf("%s: unpersisted OpenSSH ProxyJump must not report higherTierProxyCommandWins", prov)
		}
		if got := m4.ActiveProxyCommand(); got != "" {
			t.Errorf("%s: unpersisted OpenSSH ProxyJump must mask tier4 ProxyCommand, got %q", prov, got)
		}
	}
}

func TestPolicySolver_BrokenAndInvalidOpenSSHErrorsAndControlProxy(t *testing.T) {
	t.Run("broken ~/.ssh/config fails closed on OpenSSH targets while keeping saved nodes working", func(t *testing.T) {
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.10", Port: 22})
		cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("saved", models.Node{HostRef: "h1", IdentityRef: "id1"})
		prov := config.NewProviderWithOpenSSHParser(cfg, config.NewBrokenOpenSSHParser(errors.New("broken match")))
		adp := NewSSHAdapter(prov)

		if _, err := adp.GetConfig("saved"); err != nil {
			t.Fatalf("saved node failed with broken ssh_config: %v", err)
		}
		if _, err := adp.ResolveControl("missing-openssh", SessionControlOptions{}); err == nil {
			t.Fatal("ResolveControl on non-saved target should fail closed on broken ssh_config")
		}
		if _, err := adp.GetConfig(config.OpenSSHNodePrefix + "web"); err == nil {
			t.Fatal("GetConfig(openssh:web) should fail closed on broken ssh_config")
		}
	})

	t.Run("invalid Tier-4 ControlMaster is propagated instead of swallowed", func(t *testing.T) {
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host edge\n  HostName 10.0.0.1\n  ControlMaster bogus\n"))
		if err != nil {
			t.Fatal(err)
		}
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.Hosts.Set("h1", models.Host{Address: "10.0.0.1", Port: 22})
		cfg.Identities.Set("id1", models.Identity{User: "ops", AuthType: "auto"})
		cfg.Nodes.Set("edge", models.Node{HostRef: "h1", IdentityRef: "id1"})
		adp := NewSSHAdapter(config.NewProviderWithOpenSSHParser(cfg, parser))
		if _, err := adp.ResolveControl("edge", SessionControlOptions{}); err == nil {
			t.Fatal("expected invalid ControlMaster from Tier 4 to fail ResolveControl")
		}
	})

	t.Run("WithControlProxyMode strips ProxyCommand cleanly while preserving session options", func(t *testing.T) {
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host edge\n  HostName 10.0.0.2\n  User ops\n  ProxyCommand nc %h %p\n  RemoteCommand uptime\n  SetEnv APP=prod\n"))
		if err != nil {
			t.Fatal(err)
		}
		adp := NewSSHAdapter(
			config.NewProviderWithOpenSSHParser(config.NewProviderWithoutOpenSSH(nil).Snapshot(), parser),
			WithControlProxyMode(true),
		)
		cfg, err := adp.GetConfig(config.OpenSSHNodePrefix + "edge")
		if err != nil {
			t.Fatalf("GetConfig under WithControlProxyMode: %v", err)
		}
		if cfg.Options == nil || cfg.Options.ActiveProxyCommand() != "" {
			t.Fatalf("expected ProxyCommand stripped, got %+v", cfg.Options)
		}
		if cfg.Options.Get(ssh.OptionRemoteCommand) != "uptime" {
			t.Fatalf("RemoteCommand = %q, want uptime", cfg.Options.Get(ssh.OptionRemoteCommand))
		}
	})

	t.Run("ExpandControlPath reflects Tier 1 HostName, ProxyJump, and ProxyCommand suppression", func(t *testing.T) {
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host edge\n  HostName 10.0.0.2\n  User ops\n  ProxyJump bastion\n"))
		if err != nil {
			t.Fatal(err)
		}
		prov := config.NewProviderWithOpenSSHParser(config.NewProviderWithoutOpenSSH(nil).Snapshot(), parser)
		cliOpts, err := ParseOptionStrings([]string{"ProxyCommand=nc %h %p"})
		if err != nil {
			t.Fatal(err)
		}
		adp := NewSSHAdapter(
			prov,
			WithLocalExecution(true),
			WithSessionAuthOverride("openssh:edge", SessionAuth{HostName: "10.0.0.99"}),
			WithSessionControlOverride("openssh:edge", cliOpts),
		)
		expanded, err := adp.ExpandControlPath("openssh:edge", "/tmp/%h-%j")
		if err != nil {
			t.Fatalf("ExpandControlPath: %v", err)
		}
		if expanded != "/tmp/10.0.0.99-" {
			t.Fatalf("ExpandControlPath = %q, want /tmp/10.0.0.99-", expanded)
		}
	})
}

type countingConfigProvider struct {
	config.ConfigProvider
	resolveCalls atomic.Int32
}

func (c *countingConfigProvider) ResolveConnection(nodeID string) (config.ConnectionSnapshot, error) {
	c.resolveCalls.Add(1)
	return c.ConfigProvider.ResolveConnection(nodeID)
}

func (c *countingConfigProvider) ResolveConnectionWithOrigin(nodeID, originalHost string) (config.ConnectionSnapshot, error) {
	c.resolveCalls.Add(1)
	if origProvider, ok := c.ConfigProvider.(interface {
		ResolveConnectionWithOrigin(string, string) (config.ConnectionSnapshot, error)
	}); ok {
		return origProvider.ResolveConnectionWithOrigin(nodeID, originalHost)
	}
	return c.ConfigProvider.ResolveConnection(nodeID)
}

func (c *countingConfigProvider) GetOpenSSHParser() *config.OpenSSHParser {
	if src, ok := c.ConfigProvider.(interface{ GetOpenSSHParser() *config.OpenSSHParser }); ok {
		return src.GetOpenSSHParser()
	}
	return nil
}

func TestPolicySolverSingleResolveConnectionPerGetConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "xops_config.yaml"), filepath.Join(dir, "xops.key"))

	sshCfg := strings.Join([]string{
		"Host jump-host",
		"  HostName 10.60.0.2",
		"  User ops",
		"",
		"Host edge",
		"  HostName 10.60.0.1",
		"  User ops",
		"  ProxyJump jump-host",
		"  ServerAliveInterval 15",
	}, "\n") + "\n"
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	repo, err := config.NewRepositoryWithOpenSSHParser(config.NewProviderWithoutOpenSSH(nil).Snapshot(), store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}

	if _, err := repo.CreateNodeContext(
		t.Context(),
		"saved-node",
		models.Node{
			HostRef:     "h1",
			IdentityRef: "id1",
			Alias:       []string{"saved"},
			ProxyJump:   "jump-host",
			SSHOptions:  mustParseTestSSHOptions(t, "ConnectTimeout=7"),
		},
		models.Host{Address: "10.60.0.9", Port: 22},
		models.Identity{User: "ops", AuthType: "auto"},
	); err != nil {
		t.Fatalf("CreateNodeContext: %v", err)
	}
	prepDerived, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "edge", User: "override", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(derived): %v", err)
	}
	prepAdHoc, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{Selector: "10.60.0.55", User: "adhoc", HasUser: true},
	})
	if err != nil {
		t.Fatalf("PrepareNodeContext(adhoc): %v", err)
	}

	for _, tc := range []struct {
		name     string
		nodeID   string
		wantOrig string
		wantJump string
	}{
		{name: "saved", nodeID: "saved-node", wantOrig: "", wantJump: "jump-host"},
		{name: "openssh_virtual", nodeID: "openssh:edge", wantOrig: "edge", wantJump: "openssh:jump-host"},
		{name: "openssh_derived", nodeID: prepDerived.NodeID, wantOrig: "edge", wantJump: "openssh:jump-host"},
		{name: "adhoc_pending", nodeID: prepAdHoc.NodeID, wantOrig: "", wantJump: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counting := &countingConfigProvider{ConfigProvider: repo}
			adp := NewSSHAdapter(counting, WithLocalExecution(true))
			cfg, err := adp.GetConfig(tc.nodeID)
			if err != nil {
				t.Fatalf("GetConfig(%q): %v", tc.nodeID, err)
			}
			if got := counting.resolveCalls.Load(); got != 1 {
				t.Fatalf("GetConfig(%q) invoked ResolveConnection %d times, want 1", tc.nodeID, got)
			}
			if cfg.OriginalHost != tc.wantOrig || cfg.ProxyJump != tc.wantJump {
				t.Errorf("cfg = (OriginalHost=%q, ProxyJump=%q), want (%q, %q)",
					cfg.OriginalHost, cfg.ProxyJump, tc.wantOrig, tc.wantJump)
			}
		})
	}
}

func mustParseTestSSHOptions(t *testing.T, kvs ...string) *ssh.Options {
	t.Helper()
	o, err := ssh.NewOptions()
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("invalid kv %q", kv)
		}
		if err := o.Set(k, v); err != nil {
			t.Fatalf("Set(%q, %q): %v", k, v, err)
		}
	}
	return o
}

func TestPolicySolver_Round2CanonicalAndControlInvariants(t *testing.T) {
	t.Run("non-canonicalized OpenSSH alias with HostName IP does not trigger Pass 2 Host IP block", func(t *testing.T) {
		rawCfg := strings.Join([]string{
			"Host prod-db",
			"  HostName 10.20.0.5",
			"  User dbuser",
			"",
			"Host 10.20.*",
			"  ForwardAgent yes",
			"  RemoteCommand id",
		}, "\n") + "\n"
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(rawCfg))
		if err != nil {
			t.Fatal(err)
		}
		store1 := config.NewDefaultStore(filepath.Join(t.TempDir(), "cfg.yaml"), filepath.Join(t.TempDir(), "key"))
		repo, err := config.NewRepositoryWithOpenSSHParser(nil, store1, parser)
		if err != nil {
			t.Fatal(err)
		}
		prep, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
			Target: config.ConnectionTarget{Selector: "prod-db", Port: 2222, HasPort: true},
		})
		if err != nil {
			t.Fatalf("PrepareNodeContext: %v", err)
		}
		adp := NewSSHAdapter(repo, WithLocalExecution(true))
		cfg, err := adp.GetConfig(prep.NodeID)
		if err != nil {
			t.Fatalf("GetConfig: %v", err)
		}
		if cfg.Options != nil && (cfg.Options.Get(ssh.OptionForwardAgent) != "" || cfg.Options.Get(ssh.OptionRemoteCommand) != "") {
			t.Fatalf("non-canonicalized prod-db falsely matched Host 10.20.*: ForwardAgent=%q RemoteCommand=%q",
				cfg.Options.Get(ssh.OptionForwardAgent), cfg.Options.Get(ssh.OptionRemoteCommand))
		}
	})

	t.Run("canonicalized host uses CanonicalHost for Pass 2 rather than concrete IP Host block", func(t *testing.T) {
		rawCfg := strings.Join([]string{
			"Host short",
			"  User alice",
			"",
			"Host short.corp.example.com",
			"  HostName 10.20.0.5",
			"  RemoteCommand /bin/true",
			"",
			"Host *.corp.example.com",
			"  ConnectTimeout 7",
			"",
			"Host 10.20.*",
			"  ForwardAgent yes",
		}, "\n") + "\n"
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(rawCfg))
		if err != nil {
			t.Fatal(err)
		}
		store1 := config.NewDefaultStore(filepath.Join(t.TempDir(), "cfg.yaml"), filepath.Join(t.TempDir(), "key"))
		repo, err := config.NewRepositoryWithOpenSSHParser(nil, store1, parser)
		if err != nil {
			t.Fatal(err)
		}
		prep, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
			Target: config.ConnectionTarget{
				Selector:     "short.corp.example.com",
				OriginalHost: "short",
				Port:         2222,
				HasPort:      true,
			},
		})
		if err != nil {
			t.Fatalf("PrepareNodeContext: %v", err)
		}
		adp := NewSSHAdapter(repo, WithLocalExecution(true))
		cfg, err := adp.GetConfig(prep.NodeID)
		if err != nil {
			t.Fatalf("GetConfig: %v", err)
		}
		if cfg.Address != "10.20.0.5" || cfg.Options == nil || cfg.Options.Get(ssh.OptionConnectTimeout) != "7" {
			t.Fatalf("canonical Pass 2 options wrong: addr=%q opts=%+v", cfg.Address, cfg.Options)
		}
		if cfg.Options.Get(ssh.OptionForwardAgent) != "" {
			t.Fatalf("canonicalized short.corp.example.com falsely matched Host 10.20.*: %q", cfg.Options.Get(ssh.OptionForwardAgent))
		}
	})

	t.Run("controlTargetContext does not double-expand HostName containing %h literal", func(t *testing.T) {
		pol := effectivePolicy{
			snapshot: config.ConnectionSnapshot{
				Host:     models.Host{Address: "fe80::1", Port: 22},
				Identity: models.Identity{User: "ops"},
			},
			hasTier1Auth: true,
			tier1Auth: SessionAuth{
				HostName: "fe80::1%hn0",
			},
		}
		tCtx := pol.controlTargetContext("node-1")
		if tCtx.Host != "fe80::1%hn0" {
			t.Fatalf("controlTargetContext.Host = %q, want %q", tCtx.Host, "fe80::1%hn0")
		}
	})

	t.Run("WithControlProxyMode(true) strips ProxyCommand even when WithLocalExecution(true)", func(t *testing.T) {
		adp := NewSSHAdapter(nil, WithLocalExecution(true), WithControlProxyMode(true))
		opts, err := adp.finalizeEffectiveOptions(mustParseTestSSHOptions(t, ssh.OptionProxyCommand+"=nc %h %p"), nil, nil, nil, false)
		if err != nil {
			t.Fatalf("finalizeEffectiveOptions: %v", err)
		}
		if opts != nil && opts.Get(ssh.OptionProxyCommand) != "" {
			t.Fatalf("WithControlProxyMode(true) kept ProxyCommand=%q with local execution enabled", opts.Get(ssh.OptionProxyCommand))
		}
	})
}
