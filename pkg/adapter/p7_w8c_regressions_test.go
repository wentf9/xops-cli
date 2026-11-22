package adapter

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func TestP7W8c_DE8M1_InheritedSavedJumpNotCorruptedAndTier4ParserPrefixed(t *testing.T) {
	t.Parallel()

	t.Run("a1_derived_inherits_saved_jump_node_id_matches_post_confirm", func(t *testing.T) {
		t.Parallel()
		assertDE8M1InheritedSavedJump(t, false)
	})

	t.Run("a2_derived_inherits_saved_jump_alias_resolves_and_matches_post_confirm", func(t *testing.T) {
		t.Parallel()
		assertDE8M1InheritedSavedJump(t, true)
	})

	t.Run("b_def7m3_derived_with_saved_direct_prefixes_t4_parser_jump", func(t *testing.T) {
		t.Parallel()
		assertDE8M1DEF7M3Tier4ParserJumpPrefixed(t)
	})

	t.Run("c_prefix_preserves_shadowed_proxycommand_and_disabled_slot", func(t *testing.T) {
		t.Parallel()
		assertDE8M1PrefixPreservesShadowedCommandSlot(t)
	})
}

func assertDE8M1InheritedSavedJump(t *testing.T, bastionIsAlias bool) {
	t.Helper()

	const sshCfg = `
Host app
    HostName 10.0.0.50
    Port 22
    User admin
    ControlMaster auto
    ControlPath /tmp/cm-de8m1-%h-%p-%r-%n-%j-%C
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.0.0.1", Port: 2222})
	cfg.Identities.Set("id-bastion", models.Identity{User: "jumpuser", AuthType: "auto"})
	wantJump := "my-bastion"
	if bastionIsAlias {
		wantJump = "jumpuser@10.0.0.1:2222"
		cfg.Nodes.Set(wantJump, models.Node{
			HostRef:     "h-bastion",
			IdentityRef: "id-bastion",
			Alias:       []string{"my-bastion"},
		})
	} else {
		cfg.Nodes.Set("my-bastion", models.Node{
			HostRef:     "h-bastion",
			IdentityRef: "id-bastion",
		})
	}

	cfg.Hosts.Set("h-app", models.Host{Address: "10.0.0.50", Port: 22})
	cfg.Identities.Set("id-admin", models.Identity{User: "admin", AuthType: "auto"})
	cfg.Nodes.Set("prod-admin", models.Node{
		HostRef:     "h-app",
		IdentityRef: "id-admin",
		ProxyJump:   "my-bastion",
	})

	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "key"))
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	roProv := config.NewProviderWithOpenSSHParser(cfg, parser)

	env := ssh.Environment{
		HomeDir:   "/home/tester",
		LocalUser: "tester",
		LocalHost: "workstation.local",
		LocalUID:  "1000",
	}
	target := config.ConnectionTarget{Selector: "app", User: "deploy", HasUser: true}

	// Control plane before Confirm (read-only).
	ctrlSockPre, ctrlResPre, err := ResolveControlSocketPath(ControlTargetRequest{
		Provider:    roProv,
		Target:      target,
		Environment: &env,
	})
	if err != nil {
		t.Fatalf("ResolveControlSocketPath(pre-confirm): %v", err)
	}
	if ctrlResPre.Target.JumpHost != wantJump {
		t.Fatalf("pre-confirm control Target.JumpHost = %q, want %q", ctrlResPre.Target.JumpHost, wantJump)
	}

	// Dial plane before and after Confirm.
	var confirmedNodeID string
	if err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{
		Target:      target,
		DefaultUser: env.LocalUser,
	}, func(lease config.PendingLease) error {
		confirmedNodeID = lease.NodeID()
		assertDE8M1PreConfirmDialAndControl(t, repo, confirmedNodeID, wantJump, env, ctrlResPre.Target, ctrlSockPre)
		return lease.Confirm(t.Context())
	}); err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}

	assertDE8M1PostConfirmMatches(t, repo, confirmedNodeID, target, wantJump, env)
}

func assertDE8M1PreConfirmDialAndControl(
	t *testing.T,
	repo *config.Repository,
	nodeID, wantJump string,
	env ssh.Environment,
	ctrlTarget ssh.TargetContext,
	ctrlSock string,
) {
	t.Helper()
	snapPre, err := repo.ResolveConnection(nodeID)
	if err != nil {
		t.Fatalf("ResolveConnection(pre-confirm): %v", err)
	}
	if snapPre.Provenance != config.ProvenanceOpenSSHDerived {
		t.Fatalf("pre-confirm provenance = %v, want ProvenanceOpenSSHDerived", snapPre.Provenance)
	}
	adp := NewSSHAdapter(repo)
	polPre, err := adp.Resolve(t.Context(), ResolveRequest{
		NodeID:          nodeID,
		RequireSnapshot: true,
		ResolveProxy:    true,
	})
	if err != nil {
		t.Fatalf("Resolve(pre-confirm): %v", err)
	}
	if polPre.EffectiveJump() != wantJump {
		t.Fatalf("pre-confirm EffectiveJump() = %q, want %q", polPre.EffectiveJump(), wantJump)
	}
	clientCfgPre, err := adp.GetConfig(nodeID)
	if err != nil {
		t.Fatalf("GetConfig(pre-confirm): %v", err)
	}
	if clientCfgPre.ProxyJump != wantJump {
		t.Fatalf("pre-confirm GetConfig.ProxyJump = %q, want %q", clientCfgPre.ProxyJump, wantJump)
	}
	planPre, err := ssh.CapturePlan(t.Context(), adp, nodeID, "de8m1-pre")
	if err != nil {
		t.Fatalf("pre-confirm CapturePlan(%q): %v", nodeID, err)
	}
	if len(planPre.Hops) != 2 || planPre.Hops[0].NodeID != wantJump || planPre.Hops[1].NodeID != nodeID {
		t.Fatalf("pre-confirm CapturePlan hops = %+v, want [%s, %s]", planPre.Hops, wantJump, nodeID)
	}
	dialCtrlPre, err := adp.GetControlConfig(nodeID)
	if err != nil {
		t.Fatalf("GetControlConfig(pre-confirm): %v", err)
	}
	dialTargetPre := ssh.BuildClientTargetContext(nodeID, clientCfgPre, env, nil)
	dialSockPre, err := dialCtrlPre.ResolvePath(env, dialTargetPre)
	if err != nil {
		t.Fatalf("dial ResolvePath(pre-confirm): %v", err)
	}
	if ctrlTarget != dialTargetPre || ctrlSock != dialSockPre {
		t.Fatalf("pre-confirm control vs dial mismatch:\n  target: %+v vs %+v\n  sock:   %q vs %q",
			ctrlTarget, dialTargetPre, ctrlSock, dialSockPre)
	}
}

func assertDE8M1PostConfirmMatches(
	t *testing.T,
	repo *config.Repository,
	confirmedNodeID string,
	target config.ConnectionTarget,
	wantJump string,
	env ssh.Environment,
) {
	t.Helper()
	snapPost, err := repo.ResolveConnection(confirmedNodeID)
	if err != nil {
		t.Fatalf("ResolveConnection(post-confirm): %v", err)
	}
	if snapPost.Provenance != config.ProvenanceSavedManaged {
		t.Fatalf("post-confirm provenance = %v, want ProvenanceSavedManaged", snapPost.Provenance)
	}
	adpPost := NewSSHAdapter(repo)
	polPost, err := adpPost.Resolve(t.Context(), ResolveRequest{
		NodeID:          confirmedNodeID,
		RequireSnapshot: true,
		ResolveProxy:    true,
	})
	if err != nil {
		t.Fatalf("Resolve(post-confirm): %v", err)
	}
	if polPost.EffectiveJump() != wantJump {
		t.Fatalf("post-confirm EffectiveJump() = %q, want %q", polPost.EffectiveJump(), wantJump)
	}
	clientCfgPost, err := adpPost.GetConfig(confirmedNodeID)
	if err != nil {
		t.Fatalf("GetConfig(post-confirm): %v", err)
	}
	if clientCfgPost.ProxyJump != wantJump {
		t.Fatalf("post-confirm GetConfig.ProxyJump = %q, want %q", clientCfgPost.ProxyJump, wantJump)
	}
	ctrlResPost, err := ResolveControlTarget(ControlTargetRequest{
		Provider:    repo,
		Target:      target,
		Environment: &env,
	})
	if err != nil {
		t.Fatalf("ResolveControlTarget(post-confirm): %v", err)
	}
	if ctrlResPost.Target.JumpHost != wantJump {
		t.Fatalf("post-confirm control Target.JumpHost = %q, want %q", ctrlResPost.Target.JumpHost, wantJump)
	}
}

func assertDE8M1DEF7M3Tier4ParserJumpPrefixed(t *testing.T) {
	t.Helper()

	const sshCfg = `
Host jump-box
    HostName 10.30.0.1
    User juser
    Port 2201

Host app-virtual
    HostName 10.30.0.20
    User vuser
    Port 2220
    ProxyJump jump-box
    ControlMaster auto
    ControlPath /tmp/cm-de8m1-b-%h-%p-%r-%n-%j-%C
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-app", models.Host{Address: "10.30.0.20", Port: 2220})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	// Saved direct node at the same endpoint with ProxyJump="" causes
	// resolveJumpForNode to yield "" on ProvenanceOpenSSHDerived, so t4ParserProxy supplies jump-box.
	cfg.Nodes.Set("ops@10.30.0.20:2220", models.Node{
		HostRef:     "h-app",
		IdentityRef: "id-ops",
		ProxyJump:   "",
	})

	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "config.yaml"), filepath.Join(dir, "key"))
	if err := store.Save(cfg); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	repo, err := config.NewRepositoryWithOpenSSHParser(cfg, store, parser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	roProv := config.NewProviderWithOpenSSHParser(cfg, parser)

	env := ssh.Environment{
		HomeDir:   "/home/tester",
		LocalUser: "tester",
		LocalHost: "workstation.local",
		LocalUID:  "1000",
	}
	target := config.ConnectionTarget{Selector: "app-virtual", User: "deploy", HasUser: true}

	ctrlSock, ctrlRes, err := ResolveControlSocketPath(ControlTargetRequest{
		Provider:    roProv,
		Target:      target,
		Environment: &env,
	})
	if err != nil {
		t.Fatalf("ResolveControlSocketPath: %v", err)
	}
	if ctrlRes.Target.JumpHost != "openssh:jump-box" {
		t.Fatalf("control Target.JumpHost = %q, want openssh:jump-box", ctrlRes.Target.JumpHost)
	}

	if err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{
		Target:      target,
		DefaultUser: env.LocalUser,
	}, func(lease config.PendingLease) error {
		assertDE8M1DEF7M3PendingDialAndControl(t, repo, lease.NodeID(), env, ctrlRes.Target, ctrlSock)
		return nil
	}); err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}
}

func assertDE8M1DEF7M3PendingDialAndControl(
	t *testing.T,
	repo *config.Repository,
	nodeID string,
	env ssh.Environment,
	ctrlTarget ssh.TargetContext,
	ctrlSock string,
) {
	t.Helper()
	snap, err := repo.ResolveConnection(nodeID)
	if err != nil {
		t.Fatalf("ResolveConnection: %v", err)
	}
	if snap.Provenance != config.ProvenanceOpenSSHDerived || snap.Node.ProxyJump != "" {
		t.Fatalf("unexpected pending snapshot: prov=%v jump=%q", snap.Provenance, snap.Node.ProxyJump)
	}
	adp := NewSSHAdapter(repo)
	for _, resolveProxy := range []bool{false, true} {
		pol, err := adp.Resolve(t.Context(), ResolveRequest{
			NodeID:          nodeID,
			RequireSnapshot: true,
			ResolveProxy:    resolveProxy,
		})
		if err != nil {
			t.Fatalf("Resolve(ResolveProxy=%v): %v", resolveProxy, err)
		}
		if pol.EffectiveJump() != "openssh:jump-box" {
			t.Fatalf("Resolve(ResolveProxy=%v).EffectiveJump() = %q, want openssh:jump-box", resolveProxy, pol.EffectiveJump())
		}
	}
	clientCfg, err := adp.GetConfig(nodeID)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if clientCfg.ProxyJump != "openssh:jump-box" {
		t.Fatalf("GetConfig.ProxyJump = %q, want openssh:jump-box", clientCfg.ProxyJump)
	}
	plan, err := ssh.CapturePlan(t.Context(), adp, nodeID, "de8m1-b")
	if err != nil {
		t.Fatalf("CapturePlan: %v", err)
	}
	if len(plan.Hops) != 2 || plan.Hops[0].NodeID != "openssh:jump-box" || plan.Hops[1].NodeID != nodeID {
		t.Fatalf("CapturePlan hops = %+v, want [openssh:jump-box, %s]", plan.Hops, nodeID)
	}
	dialCtrl, err := adp.GetControlConfig(nodeID)
	if err != nil {
		t.Fatalf("GetControlConfig: %v", err)
	}
	dialTarget := ssh.BuildClientTargetContext(nodeID, clientCfg, env, nil)
	dialSock, err := dialCtrl.ResolvePath(env, dialTarget)
	if err != nil {
		t.Fatalf("dial ResolvePath: %v", err)
	}
	if ctrlTarget != dialTarget || ctrlSock != dialSock {
		t.Fatalf("DEF7-M3 control vs dial mismatch:\n  target: %+v vs %+v\n  sock:   %q vs %q",
			ctrlTarget, dialTarget, ctrlSock, dialSock)
	}
}

func assertDE8M1PrefixPreservesShadowedCommandSlot(t *testing.T) {
	t.Helper()

	// 1. Direct ProxySetting monoid check: shadowed active ProxyCommand survives prefixing.
	jumpOnly, err := ssh.NewProxyJump("jump-a", "jump-b")
	if err != nil {
		t.Fatalf("NewProxyJump: %v", err)
	}
	cmdOnly, err := ssh.NewProxyCommand("nc %h %p")
	if err != nil {
		t.Fatalf("NewProxyCommand: %v", err)
	}
	withShadowCmd := jumpOnly.Merge(cmdOnly)
	prefixedActive, err := prefixTier4OpenSSHProxySetting(withShadowCmd)
	if err != nil {
		t.Fatalf("prefixTier4OpenSSHProxySetting(shadow active): %v", err)
	}
	gotTargets, ok := prefixedActive.JumpTargets()
	if !ok || strings.Join(gotTargets, ",") != "openssh:jump-a,openssh:jump-b" {
		t.Fatalf("prefixed targets = (%v, %v), want [openssh:jump-a openssh:jump-b]", gotTargets, ok)
	}
	revealed := ssh.DisabledProxyJumpSetting().Merge(prefixedActive)
	if cmd, ok := revealed.Command(); !ok || cmd != "nc %h %p" {
		t.Fatalf("ProxyJump=none over prefixedActive = (%v, %q, %v), want active ProxyCommand 'nc %%h %%p'", revealed, cmd, ok)
	}

	// 2. Direct ProxySetting monoid check: shadowed ProxyCommand=none survives prefixing.
	withShadowNone := jumpOnly.Merge(ssh.DisabledProxySetting())
	prefixedNone, err := prefixTier4OpenSSHProxySetting(withShadowNone)
	if err != nil {
		t.Fatalf("prefixTier4OpenSSHProxySetting(shadow none): %v", err)
	}
	revealedNone := ssh.DisabledProxyJumpSetting().Merge(prefixedNone)
	if !revealedNone.Equal(ssh.DisabledProxySetting()) {
		t.Fatalf("ProxyJump=none over prefixedNone = %q, want DisabledProxySetting", revealedNone)
	}

	// 3. End-to-end with strippingProxyJumpProvider so t4ParserProxy is the sole Tier-4 proxy source.
	const sshCfg = `
Host app-shadow
    HostName 10.77.1.1
    User ops
    ProxyJump jump-box

Host app-shadow-none
    HostName 10.77.1.2
    User ops
    ProxyJump jump-box
    ProxyCommand none

Host *
    ProxyCommand nc %h %p
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := &strippingProxyJumpProvider{
		ConfigProvider: config.NewProviderWithOpenSSHParser(nil, parser),
		parser:         parser,
	}

	// Without -J none: prefixed jump masks shadowed ProxyCommand.
	adpDefault := NewSSHAdapter(prov, WithLocalExecution(false))
	polDefault, err := adpDefault.Resolve(t.Context(), ResolveRequest{NodeID: config.OpenSSHNodePrefix + "app-shadow"})
	if err != nil {
		t.Fatalf("Resolve(app-shadow default): %v", err)
	}
	if polDefault.EffectiveJump() != "openssh:jump-box" {
		t.Fatalf("app-shadow EffectiveJump = %q, want openssh:jump-box", polDefault.EffectiveJump())
	}

	// With -J none: shadowed ProxyCommand is revealed and obeys WithLocalExecution.
	adpNoneExec := NewSSHAdapter(prov,
		WithLocalExecution(true),
		WithSessionAuthOverride(config.OpenSSHNodePrefix+"app-shadow", SessionAuth{ProxyJump: "none"}),
	)
	polRevealed, err := adpNoneExec.Resolve(t.Context(), ResolveRequest{NodeID: config.OpenSSHNodePrefix + "app-shadow"})
	if err != nil {
		t.Fatalf("Resolve(app-shadow -J none, localExec=true): %v", err)
	}
	if cmd, ok := polRevealed.Proxy().Command(); !ok || cmd != "nc %h %p" {
		t.Fatalf("app-shadow -J none Proxy = (%q, %v), want ProxyCommand 'nc %%h %%p'", polRevealed.Proxy(), ok)
	}
	adpNoneDeny := NewSSHAdapter(prov,
		WithLocalExecution(false),
		WithSessionAuthOverride(config.OpenSSHNodePrefix+"app-shadow", SessionAuth{ProxyJump: "none"}),
	)
	if _, err := adpNoneDeny.Resolve(t.Context(), ResolveRequest{NodeID: config.OpenSSHNodePrefix + "app-shadow"}); !errors.Is(err, ErrLocalExecutionDisabled) {
		t.Fatalf("Resolve(app-shadow -J none, localExec=false) err = %v, want ErrLocalExecutionDisabled", err)
	}

	// Shadowed ProxyCommand=none remains disabled under -J none (does not leak Host * ProxyCommand).
	adpShadowNone := NewSSHAdapter(prov,
		WithLocalExecution(false),
		WithSessionAuthOverride(config.OpenSSHNodePrefix+"app-shadow-none", SessionAuth{ProxyJump: "none"}),
	)
	polShadowNone, err := adpShadowNone.Resolve(t.Context(), ResolveRequest{NodeID: config.OpenSSHNodePrefix + "app-shadow-none"})
	if err != nil {
		t.Fatalf("Resolve(app-shadow-none -J none): %v", err)
	}
	if polShadowNone.EffectiveJump() != "" || polShadowNone.Proxy().Kind() != ssh.ProxyDisabled {
		t.Fatalf("app-shadow-none -J none = (jump=%q, proxy=%q), want disabled", polShadowNone.EffectiveJump(), polShadowNone.Proxy())
	}
}

func TestP7W8c_DE8M2_ResolveControlTargetFailClosedTier2AndTier4MalformedProxyJump(t *testing.T) {
	t.Parallel()

	env := ssh.Environment{
		HomeDir:   "/home/tester",
		LocalUser: "tester",
		LocalHost: "workstation.local",
		LocalUID:  "1000",
	}

	muxSession, err := ParseSessionOptions([]string{"ControlMaster=auto", "ControlPath=/tmp/cm-%h-%p-%r-%j-%C"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	t.Run("tier2_malformed_saved_node_proxyjump_fails_closed", func(t *testing.T) {
		t.Parallel()
		badJumps := []string{"bastion\n", "bastion,,hop2", "bastion,none", ",", " , ", "bastion\u2028"}
		for _, bad := range badJumps {
			cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
			cfg.Hosts.Set("h-web", models.Host{Address: "10.0.0.3", Port: 22})
			cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
			cfg.Nodes.Set("saved-web", models.Node{
				HostRef:     "h-web",
				IdentityRef: "id-ops",
				ProxyJump:   bad,
			})
			prov := config.NewProviderWithoutOpenSSH(cfg)

			if res, err := ResolveControlTarget(ControlTargetRequest{
				Provider:       prov,
				Target:         config.ConnectionTarget{Selector: "saved-web"},
				SessionControl: muxSession,
				Environment:    &env,
			}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveControlTarget(tier2=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, res, err)
			}

			if sock, res, err := ResolveControlSocketPath(ControlTargetRequest{
				Provider:       prov,
				Target:         config.ConnectionTarget{Selector: "saved-web"},
				SessionControl: muxSession,
				Environment:    &env,
			}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveControlSocketPath(tier2=%q) = (%q, %+v, %v), want ErrSSHOptionsValidation", bad, sock, res, err)
			}

			if ps, err := resolveControlTier2ProxySetting(
				prov,
				config.ConnectionTarget{Selector: "saved-web"},
				true,
				config.ResolvedTarget{MatchedNodeID: "saved-web", Provenance: config.ProvenanceSavedManaged},
			); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("resolveControlTier2ProxySetting(tier2=%q) = (%q, %v), want ErrSSHOptionsValidation", bad, ps, err)
			}

			// Parity with SSHAdapter.Resolve.
			if _, err := NewSSHAdapter(prov).Resolve(t.Context(), ResolveRequest{NodeID: "saved-web"}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("SSHAdapter.Resolve(tier2=%q) err = %v, want ErrSSHOptionsValidation", bad, err)
			}
		}
	})

	t.Run("tier4_malformed_openssh_proxyjump_fails_closed", func(t *testing.T) {
		t.Parallel()
		const badSSHCfg = `
Host bad-comma
    HostName 10.88.0.1
    User ops
    ProxyJump bastion,,hop2

Host bad-mixed
    HostName 10.88.0.2
    User ops
    ProxyJump bastion,none
`
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(badSSHCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		prov := config.NewProviderWithOpenSSHParser(nil, parser)

		targets := []config.ConnectionTarget{
			{Selector: "bad-comma"},
			{Selector: config.OpenSSHNodePrefix + "bad-comma"},
			{Selector: "bad-comma", User: "deploy", HasUser: true},
			{Selector: "bad-mixed"},
			{Selector: config.OpenSSHNodePrefix + "bad-mixed"},
		}
		for _, tgt := range targets {
			if res, err := ResolveControlTarget(ControlTargetRequest{
				Provider:       prov,
				Target:         tgt,
				SessionControl: muxSession,
				Environment:    &env,
			}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveControlTarget(%+v) = (%+v, %v), want ErrSSHOptionsValidation", tgt, res, err)
			}
			if sock, res, err := ResolveControlSocketPath(ControlTargetRequest{
				Provider:       prov,
				Target:         tgt,
				SessionControl: muxSession,
				Environment:    &env,
			}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveControlSocketPath(%+v) = (%q, %+v, %v), want ErrSSHOptionsValidation", tgt, sock, res, err)
			}
		}

		// Direct resolveControlTier4ProxySetting fail-closed check.
		if ps, err := resolveControlTier4ProxySetting(
			prov,
			config.ConnectionTarget{Selector: config.OpenSSHNodePrefix + "bad-comma"},
			true,
			config.ResolvedTarget{
				NodeID:       config.OpenSSHNodePrefix + "bad-comma",
				OpenSSHAlias: "bad-comma",
				Provenance:   config.ProvenanceOpenSSHVirtual,
			},
		); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Fatalf("resolveControlTier4ProxySetting(bad-comma) = (%q, %v), want ErrSSHOptionsValidation", ps, err)
		}
	})

	t.Run("valid_fallback_host_still_works_when_proxyjump_is_valid", func(t *testing.T) {
		t.Parallel()
		prov := config.NewProviderWithoutOpenSSH(nil)
		res, err := ResolveControlTarget(ControlTargetRequest{
			Provider:       prov,
			FallbackHost:   "10.99.0.10",
			FallbackPort:   2222,
			FallbackUser:   "ops",
			SessionControl: muxSession,
			Environment:    &env,
		})
		if err != nil {
			t.Fatalf("ResolveControlTarget(fallback host): %v", err)
		}
		if res.Target.Host != "10.99.0.10" || res.Target.Port != 2222 || res.Target.User != "ops" || res.Target.JumpHost != "" {
			t.Fatalf("unexpected fallback TargetContext: %+v", res.Target)
		}
	})
}

func TestP7W8c_DE8L1_TwoPassCanonicalizationParityOnNodeIDAndCanonicalOriginalHost(t *testing.T) {
	t.Parallel()

	env := ssh.Environment{
		HomeDir:   "/home/tester",
		LocalUser: "tester",
		LocalHost: "workstation.local",
		LocalUID:  "1000",
	}

	readOnlyProv, repo := buildP3EquivalenceFixtures(t, nil)

	// Compute authoritative dial-plane baseline once.
	var (
		dialTarget ssh.TargetContext
		dialSock   string
	)
	if err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector:     "short.corp.example.com",
			OriginalHost: "short",
		},
		DefaultUser: env.LocalUser,
	}, func(lease config.PendingLease) error {
		nodeID := lease.NodeID()
		adp := NewSSHAdapter(repo, WithSessionAuthOverride(nodeID, SessionAuth{
			OriginalHost:  "short",
			CanonicalHost: "short.corp.example.com",
		}))
		clientCfg, err := adp.GetConfig(nodeID)
		if err != nil {
			return err
		}
		dialCtrl, err := adp.GetControlConfig(nodeID)
		if err != nil {
			return err
		}
		dialTarget = ssh.BuildClientTargetContext(nodeID, clientCfg, env, nil)
		dialSock, err = dialCtrl.ResolvePath(env, dialTarget)
		return err
	}); err != nil {
		t.Fatalf("dial plane baseline: %v", err)
	}

	cases := []struct {
		name string
		req  ControlTargetRequest
	}{
		{
			name: "nodeID_openssh_short_with_canon_orig_and_canon_host",
			req: ControlTargetRequest{
				Provider:              readOnlyProv,
				NodeID:                config.OpenSSHNodePrefix + "short",
				CanonicalOriginalHost: "short",
				CanonicalHost:         "short.corp.example.com",
				Environment:           &env,
			},
		},
		{
			name: "nodeID_openssh_short_with_canon_host_only",
			req: ControlTargetRequest{
				Provider:      readOnlyProv,
				NodeID:        config.OpenSSHNodePrefix + "short",
				CanonicalHost: "short.corp.example.com",
				Environment:   &env,
			},
		},
		{
			name: "target_openssh_short_with_canon_orig_and_canon_host",
			req: ControlTargetRequest{
				Provider:              readOnlyProv,
				Target:                config.ConnectionTarget{Selector: config.OpenSSHNodePrefix + "short"},
				CanonicalOriginalHost: "short",
				CanonicalHost:         "short.corp.example.com",
				Environment:           &env,
			},
		},
		{
			name: "target_canon_host_without_target_original_host_uses_req_canon_orig",
			req: ControlTargetRequest{
				Provider:              readOnlyProv,
				Target:                config.ConnectionTarget{Selector: "short.corp.example.com"},
				CanonicalOriginalHost: "short",
				CanonicalHost:         "short.corp.example.com",
				Environment:           &env,
			},
		},
		{
			name: "target_bare_short_with_canon_orig_and_canon_host",
			req: ControlTargetRequest{
				Provider:              readOnlyProv,
				Target:                config.ConnectionTarget{Selector: "short"},
				CanonicalOriginalHost: "short",
				CanonicalHost:         "short.corp.example.com",
				Environment:           &env,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctrlSock, ctrlRes, err := ResolveControlSocketPath(tc.req)
			if err != nil {
				t.Fatalf("ResolveControlSocketPath: %v", err)
			}
			if ctrlRes.LookupKey != "openssh:short.corp.example.com" {
				t.Fatalf("LookupKey = %q, want openssh:short.corp.example.com", ctrlRes.LookupKey)
			}
			if ctrlRes.SessionAuth.OriginalHost != "short" || ctrlRes.SessionAuth.CanonicalHost != "short.corp.example.com" {
				t.Fatalf("SessionAuth = %+v, want OriginalHost=short CanonicalHost=short.corp.example.com", ctrlRes.SessionAuth)
			}
			if ctrlRes.Target != dialTarget {
				t.Fatalf("TargetContext mismatch:\n  control = %+v\n  dial    = %+v", ctrlRes.Target, dialTarget)
			}
			if ctrlSock != dialSock {
				t.Fatalf("ControlPath mismatch:\n  control = %q\n  dial    = %q", ctrlSock, dialSock)
			}
		})
	}

	// Direct ResolveControlSessionLookup parity on NodeID: "openssh:short".
	lookupKey, auth := ResolveControlSessionLookup(ControlTargetRequest{
		Provider:              readOnlyProv,
		NodeID:                config.OpenSSHNodePrefix + "short",
		CanonicalOriginalHost: "short",
		CanonicalHost:         "short.corp.example.com",
	}, dialTarget)
	if lookupKey != "openssh:short.corp.example.com" || auth.OriginalHost != "short" || auth.CanonicalHost != "short.corp.example.com" {
		t.Fatalf("ResolveControlSessionLookup = (%q, %+v), want (openssh:short.corp.example.com, short/short.corp.example.com)", lookupKey, auth)
	}

	// Saved node ID must not have its CanonicalHost corrupted to the saved node ID.
	savedRes, err := ResolveControlTarget(ControlTargetRequest{
		Provider:              readOnlyProv,
		NodeID:                "web-01",
		CanonicalOriginalHost: "short",
		CanonicalHost:         "short.corp.example.com",
		Environment:           &env,
	})
	if err != nil {
		t.Fatalf("ResolveControlTarget(saved web-01): %v", err)
	}
	if savedRes.Target.CanonicalHost == "web-01" {
		t.Fatalf("saved node CanonicalHost was corrupted to saved node ID: %+v", savedRes.Target)
	}
}
