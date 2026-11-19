package adapter

import (
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
		t2 := mkProxyOpts("t2-cmd %h %p")
		t3 := mkProxyOpts("t3-cmd %h %p")
		t4 := mkProxyOpts("t4-cmd %h %p")
		snap := config.ConnectionSnapshot{
			Node:       models.Node{ProxyJump: "saved-jump"},
			Provenance: config.ProvenanceSavedManaged,
		}
		m2, m3, m4, higherCmdWins := solveProxyPrecedence(true, mkProxyOpts("t1-cmd %h %p"), snap, true, t2, t3, t4)
		if higherCmdWins {
			t.Fatal("tier1 active ProxyJump must not allow higherTierProxyCommandWins")
		}
		if m2.Get(ssh.OptionProxyCommand) != "" || m3.Get(ssh.OptionProxyCommand) != "" || m4.Get(ssh.OptionProxyCommand) != "" {
			t.Fatalf("expected all lower ProxyCommand masked, got m2=%q m3=%q m4=%q",
				m2.Get(ssh.OptionProxyCommand), m3.Get(ssh.OptionProxyCommand), m4.Get(ssh.OptionProxyCommand))
		}
	})

	t.Run("saved_node_jump_masks_tier3_and_tier4_while_tier1_cmd_overrides", func(t *testing.T) {
		t3 := mkProxyOpts("t3-cmd %h %p")
		t4 := mkProxyOpts("t4-cmd %h %p")
		snap := config.ConnectionSnapshot{
			Node:       models.Node{ProxyJump: "saved-jump"},
			Provenance: config.ProvenanceSavedManaged,
		}
		_, m3, m4, higherCmdWinsNoT1 := solveProxyPrecedence(false, nil, snap, true, nil, t3, t4)
		if higherCmdWinsNoT1 {
			t.Fatal("tier3 ProxyCommand must not override saved node ProxyJump")
		}
		if m3.Get(ssh.OptionProxyCommand) != "" || m4.Get(ssh.OptionProxyCommand) != "" {
			t.Fatalf("saved node ProxyJump must mask tier3 and tier4 ProxyCommand")
		}

		_, _, _, higherCmdWinsWithT1 := solveProxyPrecedence(false, mkProxyOpts("cli-cmd %h %p"), snap, true, nil, t3, t4)
		if !higherCmdWinsWithT1 {
			t.Fatal("tier1 ProxyCommand must override saved node ProxyJump")
		}

		_, _, _, noneCmdNoOverride := solveProxyPrecedence(false, mkProxyOpts("none"), snap, true, nil, t3, t4)
		if noneCmdNoOverride {
			t.Fatal("tier1 ProxyCommand=none must not claim higherTierProxyCommandWins")
		}
	})

	t.Run("unpersisted_openssh_jump_overridden_by_tier3_proxycommand", func(t *testing.T) {
		for _, prov := range []config.NodeProvenance{config.ProvenanceOpenSSHVirtual, config.ProvenanceOpenSSHDerived} {
			t3 := mkProxyOpts("global-cmd %h %p")
			t4 := mkProxyOpts("t4-cmd %h %p")
			snap := config.ConnectionSnapshot{
				Node:       models.Node{ProxyJump: "openssh:jump"},
				Provenance: prov,
			}
			_, m3, m4, higherCmdWins := solveProxyPrecedence(false, nil, snap, true, nil, t3, t4)
			if !higherCmdWins {
				t.Errorf("%s: expected tier3 global ProxyCommand to override Tier-4 ProxyJump", prov)
			}
			if m3.Get(ssh.OptionProxyCommand) == "" || m4.Get(ssh.OptionProxyCommand) == "" {
				t.Errorf("%s: unpersisted OpenSSH ProxyJump must not mask tier3/tier4 ProxyCommand", prov)
			}
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
