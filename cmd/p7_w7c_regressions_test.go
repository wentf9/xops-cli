package cmd

import (
	"errors"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W7c_DEF7M1_ControlTargetFailsClosedOnMalformedProxyJump(t *testing.T) {
	t.Parallel()

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Hosts.Set("h-web", models.Host{Address: "10.0.0.2", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops"})
	muxOpts := &ssh.Options{}
	muxOpts.SetControlMaster(ssh.ControlMasterAuto)
	muxOpts.SetControlPath("/tmp/cm-cmd-m1-%h-%p-%r-%j-%C")
	cfg.Nodes.Set("saved-web", models.Node{
		HostRef:     "h-web",
		IdentityRef: "id-ops",
		ProxyJump:   "saved-bastion",
		SSHOptions:  muxOpts,
	})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	for _, bad := range []string{"none\n", "bastion\n", "\n", "   ", "\t", "\r\n", "\u2028", "\u2029"} {
		o := NewSshOptions()
		o.Host = "saved-web"
		o.JumpHost = bad
		if got, err := controlTarget(o, prov, "saved-web"); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("controlTarget(JumpHost=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, got, err)
		}
		if got, err := controlSocketPath(o, prov, "saved-web"); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("controlSocketPath(JumpHost=%q) = (%q, %v), want ErrSSHOptionsValidation", bad, got, err)
		}
	}

	// Explicit HasProxyJump=true with empty ProxyJump="" must fail closed instead of falling back to saved-bastion.
	oEmpty := NewSshOptions()
	oEmpty.Host = "saved-web"
	oEmpty.Target = config.ConnectionTarget{Selector: "saved-web", ProxyJump: "", HasProxyJump: true}
	if got, err := controlTarget(oEmpty, prov, "saved-web"); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
		t.Fatalf("controlTarget(HasProxyJump=true, empty) = (%+v, %v), want ErrSSHOptionsValidation", got, err)
	}
}

func makeP7W7cDEF7M5Provider(bastionProxyCmd, midProxyCmd, appProxyCmd string) config.ConfigProvider {
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.70.0.1", Port: 22})
	cfg.Hosts.Set("h-mid", models.Host{Address: "10.70.0.2", Port: 22})
	cfg.Hosts.Set("h-app", models.Host{Address: "10.70.0.3", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})

	var bastionOpts, midOpts, appOpts *ssh.Options
	if bastionProxyCmd != "" {
		bastionOpts = ssh.MustOptions(ssh.OptionProxyCommand, bastionProxyCmd)
	}
	if midProxyCmd != "" {
		midOpts = ssh.MustOptions(ssh.OptionProxyCommand, midProxyCmd)
	}
	if appProxyCmd != "" {
		appOpts = ssh.MustOptions(ssh.OptionProxyCommand, appProxyCmd)
	}
	cfg.Nodes.Set("bastion", models.Node{
		HostRef:     "h-bastion",
		IdentityRef: "id-ops",
		SSHOptions:  bastionOpts,
	})
	cfg.Nodes.Set("mid", models.Node{
		HostRef:     "h-mid",
		IdentityRef: "id-ops",
		SSHOptions:  midOpts,
	})
	cfg.Nodes.Set("app", models.Node{
		HostRef:     "h-app",
		IdentityRef: "id-ops",
		SSHOptions:  appOpts,
	})
	return config.NewProviderWithoutOpenSSH(cfg)
}

func TestP7W7c_DEF7M5_ProxyCommandCheckScopesTargetOverridesToTargetsOnly(t *testing.T) {
	t.Parallel()

	t.Run("A_no_false_positive_self_cycle_on_persistent_jump_hop_master", testP7W7cDEF7M5NoFalsePositiveSelfCycle)
	t.Run("B_no_false_negative_tier1_jump_shadowing_bastion_tier2_proxycommand", testP7W7cDEF7M5NoTier1JumpShadowing)
	t.Run("C_target_only_dash_o_ProxyCommand_does_not_bleed_onto_jump_hop_master", testP7W7cDEF7M5TargetOnlyProxyCommandIsolation)
	t.Run("D_empty_targetNodeIDs_treats_checked_node_as_target", testP7W7cDEF7M5EmptyTargetNodeIDs)
}

func testP7W7cDEF7M5NoFalsePositiveSelfCycle(t *testing.T) {
	t.Parallel()
	prov := makeP7W7cDEF7M5Provider("", "", "")
	// Simulates: xops scp -J bastion a.txt app:/tmp/a.txt
	opts := NewSshOptions()
	opts.Host = "app"
	opts.JumpHost = "bastion"
	opts.targetNodeIDs = []string{"app"}

	// Checking persistent non-target jump-hop master "bastion" MUST NOT inject
	// target's -J bastion (which caused false-positive ProxyCycleError).
	hasProxy, err := opts.hasActiveProxyCommandForMaster(prov, "bastion", "bastion")
	if err != nil || hasProxy {
		t.Fatalf("hasActiveProxyCommandForMaster(bastion under -J bastion for target app) = (%v, %v), want (false, nil)", hasProxy, err)
	}
	if hasProxy, err := opts.hasActiveProxyCommandInPath(prov, "bastion", nil); err != nil || hasProxy {
		t.Fatalf("hasActiveProxyCommandInPath(bastion) = (%v, %v), want (false, nil)", hasProxy, err)
	}
	// Checking target "app" itself evaluates with -J bastion -> walks clean bastion -> (false, nil).
	if hasProxy, err := opts.hasActiveProxyCommandForMaster(prov, "app", "app"); err != nil || hasProxy {
		t.Fatalf("hasActiveProxyCommandForMaster(app) = (%v, %v), want (false, nil)", hasProxy, err)
	}
}

func testP7W7cDEF7M5NoTier1JumpShadowing(t *testing.T) {
	t.Parallel()
	prov := makeP7W7cDEF7M5Provider("nc %h %p", "", "")
	// Simulates: xops scp -J mid a.txt app:/tmp/a.txt where bastion has Tier-2 ProxyCommand.
	opts := NewSshOptions()
	opts.Host = "app"
	opts.JumpHost = "mid"
	opts.targetNodeIDs = []string{"app"}

	// Checking non-target persistent master "bastion" MUST NOT shadow bastion's
	// Tier-2 ProxyCommand with target's Tier-1 -J mid.
	hasProxy, err := opts.hasActiveProxyCommandForMaster(prov, "bastion", "bastion")
	if err != nil || !hasProxy {
		t.Fatalf("hasActiveProxyCommandForMaster(bastion with Tier-2 ProxyCommand under -J mid) = (%v, %v), want (true, nil)", hasProxy, err)
	}
	if hasProxy, err := opts.hasActiveProxyCommandInPath(prov, "bastion", nil); err != nil || !hasProxy {
		t.Fatalf("hasActiveProxyCommandInPath(bastion) = (%v, %v), want (true, nil)", hasProxy, err)
	}

	// Also verify when mid itself has Tier-2 ProxyCommand and -J mid is passed for app.
	provMidCmd := makeP7W7cDEF7M5Provider("", "nc %h %p", "")
	if hasProxy, err := opts.hasActiveProxyCommandForMaster(provMidCmd, "mid", "mid"); err != nil || !hasProxy {
		t.Fatalf("hasActiveProxyCommandForMaster(mid with Tier-2 ProxyCommand under -J mid) = (%v, %v), want (true, nil)", hasProxy, err)
	}
	if hasProxy, err := opts.hasActiveProxyCommandForMaster(provMidCmd, "app", "app"); err != nil || !hasProxy {
		t.Fatalf("hasActiveProxyCommandForMaster(app -> -J mid with ProxyCommand) = (%v, %v), want (true, nil)", hasProxy, err)
	}
}

func testP7W7cDEF7M5TargetOnlyProxyCommandIsolation(t *testing.T) {
	t.Parallel()
	// 1. Target-only -o ProxyCommand=none must NOT cancel bastion's Tier-2 ProxyCommand.
	provBastionCmd := makeP7W7cDEF7M5Provider("nc %h %p", "", "")
	optsNone := NewSshOptions()
	optsNone.Host = "app"
	optsNone.targetNodeIDs = []string{"app"}
	optsNone.control.Options = []string{"ProxyCommand=none"}
	if hasProxy, err := optsNone.hasActiveProxyCommandForMaster(provBastionCmd, "bastion", "bastion"); err != nil || !hasProxy {
		t.Fatalf("non-target bastion with Tier-2 ProxyCommand under target -o ProxyCommand=none = (%v, %v), want (true, nil)", hasProxy, err)
	}

	// 2. Target-only -o ProxyCommand=nc (or cached target effectiveSSHOptions) must NOT mark
	//    clean non-target bastion as having an active ProxyCommand.
	provClean := makeP7W7cDEF7M5Provider("", "", "")
	optsCmd := NewSshOptions()
	optsCmd.Host = "app"
	optsCmd.targetNodeIDs = []string{"app"}
	optsCmd.control.Options = []string{"ProxyCommand=nc %h %p"}
	optsCmd.effectiveSSHOptions = ssh.MustOptions(ssh.OptionProxyCommand, "nc %h %p")
	if hasProxy, err := optsCmd.hasActiveProxyCommandForMaster(provClean, "bastion", "bastion"); err != nil || hasProxy {
		t.Fatalf("clean non-target bastion under target -o ProxyCommand = (%v, %v), want (false, nil)", hasProxy, err)
	}
	if hasProxy, err := optsCmd.hasActiveProxyCommandForMaster(provClean, "app", "app"); err != nil || !hasProxy {
		t.Fatalf("target app under -o ProxyCommand = (%v, %v), want (true, nil)", hasProxy, err)
	}
}

func testP7W7cDEF7M5EmptyTargetNodeIDs(t *testing.T) {
	t.Parallel()
	provAppCmd := makeP7W7cDEF7M5Provider("", "", "nc %h %p")
	opts := NewSshOptions()
	opts.JumpHost = "bastion"
	// With empty targetNodeIDs, app is treated as target so -J bastion masks app's Tier-2 ProxyCommand.
	if hasProxy, err := opts.hasActiveProxyCommandInPath(provAppCmd, "app", nil); err != nil || hasProxy {
		t.Fatalf("hasActiveProxyCommandInPath(app, empty targetNodeIDs, -J bastion) = (%v, %v), want (false, nil)", hasProxy, err)
	}
}
