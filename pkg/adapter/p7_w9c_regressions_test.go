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

func w9cTestEnv() ssh.Environment {
	return ssh.Environment{
		HomeDir:   "/home/tester",
		LocalUser: "tester",
		LocalHost: "workstation.local",
		LocalUID:  "1000",
	}
}

func TestP7W9c_DE9M1_ControlTargetAndConfigFailClosedAndSelfLoopParity(t *testing.T) {
	t.Parallel()

	env := w9cTestEnv()
	muxSession, err := ParseSessionOptions([]string{"ControlMaster=auto", "ControlPath=/tmp/cm-w9c-%h-%p-%r-%j-%C"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	t.Run("non_ErrNodeNotFound_errors_fail_closed_across_control_entry_points", func(t *testing.T) {
		t.Parallel()
		assertDE9M1NonMissingErrorsFailClosed(t, env, muxSession)
	})

	t.Run("self_referential_proxyjump_returns_ProxyCycleError_across_all_tiers", func(t *testing.T) {
		t.Parallel()
		assertDE9M1SelfLoopParity(t, env, muxSession)
	})
}

func assertDE9M1NonMissingErrorsFailClosed(t *testing.T, env ssh.Environment, muxSession SessionControlOptions) {
	t.Helper()

	// 1. Ambiguous saved host alias.
	ambigCfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	ambigCfg.Hosts.Set("h-1", models.Host{Address: "10.93.0.1", Port: 22, Alias: []string{"web"}})
	ambigCfg.Hosts.Set("h-2", models.Host{Address: "10.93.0.2", Port: 22, Alias: []string{"web"}})
	ambigCfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	ambigCfg.Nodes.Set("web-a", models.Node{HostRef: "h-1", IdentityRef: "id-ops"})
	ambigCfg.Nodes.Set("web-b", models.Node{HostRef: "h-2", IdentityRef: "id-ops"})
	ambigProv := config.NewProviderWithoutOpenSSH(ambigCfg)

	var ambigErr *config.AmbiguousNodeError
	if res, err := ResolveControlTarget(ControlTargetRequest{
		Provider:       ambigProv,
		Target:         config.ConnectionTarget{Selector: "web"},
		SessionControl: muxSession,
		Environment:    &env,
	}); !errors.As(err, &ambigErr) {
		t.Errorf("ResolveControlTarget(ambiguous web) = (%+v, %v), want *config.AmbiguousNodeError", res, err)
	}
	if sock, res, err := ResolveControlSocketPath(ControlTargetRequest{
		Provider:       ambigProv,
		Target:         config.ConnectionTarget{Selector: "web"},
		SessionControl: muxSession,
		Environment:    &env,
	}); !errors.As(err, &ambigErr) {
		t.Errorf("ResolveControlSocketPath(ambiguous web) = (%q, %+v, %v), want *config.AmbiguousNodeError", sock, res, err)
	}

	// 2. Broken OpenSSHParser fails closed.
	brokenProv := config.NewProviderWithOpenSSHParser(nil, config.NewBrokenOpenSSHParser(errors.New("broken ssh_config")))
	if res, err := ResolveControlTarget(ControlTargetRequest{
		Provider:       brokenProv,
		Target:         config.ConnectionTarget{Selector: "unmatched.example.com"},
		SessionControl: muxSession,
		Environment:    &env,
	}); err == nil || !strings.Contains(err.Error(), "broken ssh_config") {
		t.Errorf("ResolveControlTarget(broken parser) = (%+v, %v), want broken ssh_config error", res, err)
	}
	if sock, res, err := ResolveControlSocketPath(ControlTargetRequest{
		Provider:       brokenProv,
		Target:         config.ConnectionTarget{Selector: "unmatched.example.com"},
		SessionControl: muxSession,
		Environment:    &env,
	}); err == nil || !strings.Contains(err.Error(), "broken ssh_config") {
		t.Errorf("ResolveControlSocketPath(broken parser) = (%q, %+v, %v), want broken ssh_config error", sock, res, err)
	}

	// 3. Invalid ssh_config Port and invalid openssh: selector fail closed.
	assertDE9M1InvalidOpenSSHAndJumpErrors(t, env, muxSession)
}

func assertDE9M1InvalidOpenSSHAndJumpErrors(t *testing.T, env ssh.Environment, muxSession SessionControlOptions) {
	t.Helper()

	badPortParser, err := config.NewOpenSSHParserFromReader(strings.NewReader("Host badport\n  HostName 10.93.0.3\n  Port 99999\n"))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	badPortProv := config.NewProviderWithOpenSSHParser(nil, badPortParser)
	for _, sel := range []string{"badport", "openssh:badport", "openssh:", "openssh:openssh:badport"} {
		if res, err := ResolveControlTarget(ControlTargetRequest{
			Provider:       badPortProv,
			Target:         config.ConnectionTarget{Selector: sel},
			SessionControl: muxSession,
			Environment:    &env,
		}); err == nil {
			t.Errorf("ResolveControlTarget(%q) unexpectedly succeeded (%+v), want error", sel, res)
		}
		if sock, res, err := ResolveControlSocketPath(ControlTargetRequest{
			Provider:       badPortProv,
			Target:         config.ConnectionTarget{Selector: sel},
			SessionControl: muxSession,
			Environment:    &env,
		}); err == nil {
			t.Errorf("ResolveControlSocketPath(%q) unexpectedly succeeded (%q, %+v), want error", sel, sock, res)
		}
	}

	// Hop-level ParseTargetRef errors and unknown single-label jump fail closed.
	baseCfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	baseCfg.Hosts.Set("h-app", models.Host{Address: "10.93.0.10", Port: 22})
	baseCfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	baseCfg.Nodes.Set("app", models.Node{HostRef: "h-app", IdentityRef: "id-ops"})
	baseProv := config.NewProviderWithoutOpenSSH(baseCfg)

	for _, badHop := range []string{"openssh:openssh:22", "openssh: web", "[::1", "host:99999", "@host"} {
		if res, err := ResolveControlTarget(ControlTargetRequest{
			Provider:       baseProv,
			Target:         config.ConnectionTarget{Selector: "app", ProxyJump: badHop, HasProxyJump: true},
			SessionControl: muxSession,
			Environment:    &env,
		}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveControlTarget(-J %q) = (%+v, %v), want ErrSSHOptionsValidation", badHop, res, err)
		}
	}
	if res, err := ResolveControlTarget(ControlTargetRequest{
		Provider:       baseProv,
		Target:         config.ConnectionTarget{Selector: "app", ProxyJump: "unknown-single-label", HasProxyJump: true},
		SessionControl: muxSession,
		Environment:    &env,
	}); err == nil {
		t.Errorf("ResolveControlTarget(-J unknown-single-label) unexpectedly succeeded (%+v), want error", res)
	}

	// Genuinely unresolved ad-hoc/fallback hosts still succeed.
	fbRes, err := ResolveControlTarget(ControlTargetRequest{
		Provider:       baseProv,
		FallbackHost:   "10.93.0.50",
		FallbackPort:   2222,
		FallbackUser:   "ops",
		SessionControl: muxSession,
		Environment:    &env,
	})
	if err != nil || fbRes.Target.Host != "10.93.0.50" || fbRes.Target.Port != 2222 || fbRes.Target.User != "ops" {
		t.Fatalf("ResolveControlTarget(fallback host) = (%+v, %v), want 10.93.0.50:2222 ops", fbRes, err)
	}
	adhocRes, err := ResolveControlTarget(ControlTargetRequest{
		Provider:       baseProv,
		Target:         config.ConnectionTarget{Selector: "unmanaged.example.com"},
		SessionControl: muxSession,
		Environment:    &env,
	})
	if err != nil || adhocRes.Target.Host != "unmanaged.example.com" {
		t.Fatalf("ResolveControlTarget(unmanaged.example.com) = (%+v, %v), want unmanaged.example.com", adhocRes, err)
	}
}

func assertDE9M1SelfLoopParity(t *testing.T, env ssh.Environment, muxSession SessionControlOptions) {
	t.Helper()

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-t1", models.Host{Address: "10.93.1.1", Port: 22})
	cfg.Hosts.Set("h-t2", models.Host{Address: "10.93.1.2", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	muxOpts := &ssh.Options{}
	muxOpts.SetControlMaster(ssh.ControlMasterAuto)
	muxOpts.SetControlPath("/tmp/cm-loop-%h-%p-%r-%j-%C")
	cfg.Nodes.Set("ops@10.93.1.1:22", models.Node{
		HostRef:     "h-t1",
		IdentityRef: "id-ops",
		Alias:       []string{"self-t1"},
		SSHOptions:  muxOpts.Clone(),
	})
	cfg.Nodes.Set("ops@10.93.1.2:22", models.Node{
		HostRef:     "h-t2",
		IdentityRef: "id-ops",
		Alias:       []string{"self-t2"},
		ProxyJump:   "self-t2",
		SSHOptions:  muxOpts.Clone(),
	})

	const loopCfg = `
Host loop
    HostName 10.93.1.3
    User ops
    ProxyJump loop
    ControlMaster auto
    ControlPath /tmp/cm-loop-%h-%p-%r-%j-%C
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(loopCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(cfg, parser)

	t1OptSession, err := ParseSessionOptions([]string{"ProxyJump=self-t1", "ControlMaster=auto", "ControlPath=/tmp/cm-loop-%h-%p-%r-%j-%C"}, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions: %v", err)
	}

	assertControlSelfLoop(t, ControlTargetRequest{
		Provider:       prov,
		Target:         config.ConnectionTarget{Selector: "self-t1", ProxyJump: "self-t1", HasProxyJump: true},
		SessionControl: muxSession,
		Environment:    &env,
	})
	assertControlSelfLoop(t, ControlTargetRequest{
		Provider:       prov,
		Target:         config.ConnectionTarget{Selector: "self-t1"},
		SessionControl: t1OptSession,
		Environment:    &env,
	})
	assertControlSelfLoop(t, ControlTargetRequest{
		Provider:       prov,
		Target:         config.ConnectionTarget{Selector: "self-t2"},
		SessionControl: muxSession,
		Environment:    &env,
	})
	for _, sel := range []string{"loop", "openssh:loop", "OPENSSH:loop"} {
		assertControlSelfLoop(t, ControlTargetRequest{
			Provider:       prov,
			Target:         config.ConnectionTarget{Selector: sel},
			SessionControl: muxSession,
			Environment:    &env,
		})
	}

	var cycleErr *ssh.ProxyCycleError
	if _, err := ResolveControlConfig(prov, "ops@10.93.1.1:22", "self-t1", SessionAuth{ProxyJump: "self-t1"}, muxSession); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlConfig(tier1 self-t1) err = %v, want *ssh.ProxyCycleError", err)
	}
	if _, err := ResolveControlConfig(prov, "ops@10.93.1.2:22", "self-t2", SessionAuth{}, muxSession); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlConfig(tier2 self-t2) err = %v, want *ssh.ProxyCycleError", err)
	}
	if _, err := ResolveControlConfig(prov, "", "self-t2", SessionAuth{}, muxSession); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlConfig(tier2 alias selector self-t2) err = %v, want *ssh.ProxyCycleError", err)
	}
	if _, err := ResolveControlConfig(prov, "openssh:loop", "openssh:loop", SessionAuth{}, muxSession); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlConfig(tier4 openssh:loop) err = %v, want *ssh.ProxyCycleError", err)
	}
	if _, err := ResolveControlConfig(nil, "self-node", "self-node", SessionAuth{ProxyJump: "self-node"}, SessionControlOptions{}); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlConfig(nil provider self-loop) err = %v, want *ssh.ProxyCycleError", err)
	}
}

func assertControlSelfLoop(t *testing.T, req ControlTargetRequest) {
	t.Helper()
	var cycleErr *ssh.ProxyCycleError
	if res, err := ResolveControlTarget(req); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlTarget(%+v) = (%+v, %v), want *ssh.ProxyCycleError", req.Target, res, err)
	}
	if sock, res, err := ResolveControlSocketPath(req); !errors.As(err, &cycleErr) {
		t.Errorf("ResolveControlSocketPath(%+v) = (%q, %+v, %v), want *ssh.ProxyCycleError", req.Target, sock, res, err)
	}
}

func TestP7W9c_DE9M2_RejectWhitespacePaddedOpenSSHSelectorsInControlAPIs(t *testing.T) {
	t.Parallel()

	env := w9cTestEnv()
	const sshCfg = `
Host web
    HostName 10.94.0.1
    User ops
    Port 2222
    ControlMaster auto
    ControlPath /tmp/cm-w9c-m2-%h-%p-%r-%C
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}
	prov := config.NewProviderWithOpenSSHParser(nil, parser)

	badSelectors := []string{
		" openssh:web",
		"openssh:web ",
		"\u00a0openssh:web",
		"openssh:\u00a0web",
		"openssh:web\n",
		"openssh:web\u2028",
		"OPENSSH: web",
		" OPENSSH:web",
		"openssh:openssh:web",
		"openssh:",
	}

	for _, bad := range badSelectors {
		reqs := []struct {
			name string
			req  ControlTargetRequest
		}{
			{
				name: "NodeID",
				req:  ControlTargetRequest{Provider: prov, NodeID: bad, Environment: &env},
			},
			{
				name: "Target.Selector",
				req:  ControlTargetRequest{Provider: prov, Target: config.ConnectionTarget{Selector: bad}, Environment: &env},
			},
			{
				name: "Target.OriginalHost",
				req:  ControlTargetRequest{Provider: prov, Target: config.ConnectionTarget{Selector: "web", OriginalHost: bad}, Environment: &env},
			},
		}
		for _, rc := range reqs {
			if res, err := ResolveControlTarget(rc.req); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveControlTarget(%s=%q) = (%+v, %v), want ErrSSHOptionsValidation", rc.name, bad, res, err)
			}
			if sock, res, err := ResolveControlSocketPath(rc.req); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("ResolveControlSocketPath(%s=%q) = (%q, %+v, %v), want ErrSSHOptionsValidation", rc.name, bad, sock, res, err)
			}
		}

		if ctrl, err := ResolveControlConfig(prov, bad, "", SessionAuth{}, SessionControlOptions{}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveControlConfig(lookupKey=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, ctrl, err)
		}
		if ctrl, err := ResolveControlConfig(nil, "", bad, SessionAuth{}, SessionControlOptions{}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveControlConfig(nil, selector=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, ctrl, err)
		}
		if ctrl, err := ResolveControlConfig(prov, "openssh:web", "openssh:web", SessionAuth{OriginalHost: bad}, SessionControlOptions{}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveControlConfig(OriginalHost=%q) = (%+v, %v), want ErrSSHOptionsValidation", bad, ctrl, err)
		}
	}

	for _, good := range []string{"openssh:web", "OPENSSH:web"} {
		sock, res, err := ResolveControlSocketPath(ControlTargetRequest{
			Provider:    prov,
			NodeID:      good,
			Environment: &env,
		})
		if err != nil || sock == "" || res.Target.Host != "10.94.0.1" {
			t.Fatalf("ResolveControlSocketPath(%q) = (%q, %+v, %v), want valid socket for 10.94.0.1", good, sock, res, err)
		}
	}
}

func TestP7W9c_DE9L1_PrefixTier4RejectsOpenSSHAndNormalizeUnpersistedHops(t *testing.T) {
	t.Parallel()

	t.Run("prefixTier4OpenSSHProxySetting_rejects_openssh_prefix_and_bad_hops", func(t *testing.T) {
		t.Parallel()
		for _, badHop := range []string{
			"openssh:jump-b",
			"OPENSSH:jump-b",
			"jump box",
			"jump1 jump2",
			"[::1",
			"host:99999",
			"@host",
		} {
			ps, err := ssh.NewProxyJump(badHop)
			if err != nil {
				continue
			}
			if got, err := prefixTier4OpenSSHProxySetting(ps); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("prefixTier4OpenSSHProxySetting(%q) = (%q, %v), want ErrSSHOptionsValidation", badHop, got, err)
			}
		}
	})

	t.Run("resolveUnpersistedOpenSSHJumpChain_normalizes_and_rejects_invalid_hops", func(t *testing.T) {
		t.Parallel()
		got, err := resolveUnpersistedOpenSSHJumpChain(nil, "OPENSSH:10.0.0.1,OPENSSH:alice@[2001:db8::1]:2222")
		if err != nil {
			t.Fatalf("resolveUnpersistedOpenSSHJumpChain(valid): %v", err)
		}
		want := "openssh:10.0.0.1,openssh:alice@[2001:db8::1]:2222"
		if got != want {
			t.Fatalf("resolveUnpersistedOpenSSHJumpChain = %q, want %q", got, want)
		}

		for _, bad := range []string{
			"openssh:jump box",
			"openssh:openssh:jump",
			"openssh:OPENSSH:jump",
			"openssh: web",
			"openssh:host:99999",
		} {
			if out, err := resolveUnpersistedOpenSSHJumpChain(nil, bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
				t.Errorf("resolveUnpersistedOpenSSHJumpChain(%q) = (%q, %v), want ErrSSHOptionsValidation", bad, out, err)
			}
		}
	})

	t.Run("inherited_uppercase_OPENSSH_hop_has_zero_drift_pre_and_post_confirm", func(t *testing.T) {
		t.Parallel()
		assertDE9L1PreAndPostConfirmZeroDrift(t)
	})
}

func assertDE9L1PreAndPostConfirmZeroDrift(t *testing.T) {
	t.Helper()

	env := w9cTestEnv()
	const sshCfg = `
Host app-open
    HostName 10.95.0.20
    Port 22
    User admin
    ControlMaster auto
    ControlPath /tmp/cm-de9l1-%h-%p-%r-%j-%C
`
	parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
	if err != nil {
		t.Fatalf("NewOpenSSHParserFromReader: %v", err)
	}

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-app", models.Host{Address: "10.95.0.20", Port: 22})
	cfg.Identities.Set("id-admin", models.Identity{User: "admin", AuthType: "auto"})
	cfg.Nodes.Set("admin@10.95.0.20:22", models.Node{
		HostRef:     "h-app",
		IdentityRef: "id-admin",
		ProxyJump:   "OPENSSH:10.0.0.1",
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

	target := config.ConnectionTarget{Selector: "app-open", User: "deploy", HasUser: true}
	ctrlSockPre, ctrlResPre, err := ResolveControlSocketPath(ControlTargetRequest{
		Provider:    roProv,
		Target:      target,
		Environment: &env,
	})
	if err != nil {
		t.Fatalf("ResolveControlSocketPath(pre-confirm): %v", err)
	}
	if ctrlResPre.Target.JumpHost != "openssh:10.0.0.1" {
		t.Fatalf("pre-confirm control JumpHost = %q, want openssh:10.0.0.1", ctrlResPre.Target.JumpHost)
	}

	var (
		confirmedNodeID string
		dialSockPre     string
	)
	if err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{
		Target:      target,
		DefaultUser: env.LocalUser,
	}, func(lease config.PendingLease) error {
		confirmedNodeID = lease.NodeID()
		adp := NewSSHAdapter(repo)
		clientCfg, err := adp.GetConfig(confirmedNodeID)
		if err != nil {
			return err
		}
		if clientCfg.ProxyJump != "openssh:10.0.0.1" {
			t.Fatalf("pre-confirm GetConfig.ProxyJump = %q, want openssh:10.0.0.1", clientCfg.ProxyJump)
		}
		ctrl, err := adp.GetControlConfig(confirmedNodeID)
		if err != nil {
			return err
		}
		dialTarget := ssh.BuildClientTargetContext(confirmedNodeID, clientCfg, env, nil)
		dialSockPre, err = ctrl.ResolvePath(env, dialTarget)
		if err != nil {
			return err
		}
		if dialSockPre != ctrlSockPre {
			t.Fatalf("pre-confirm control vs dial ControlPath drift: %q vs %q", ctrlSockPre, dialSockPre)
		}
		return lease.Confirm(t.Context())
	}); err != nil {
		t.Fatalf("WithPendingNode: %v", err)
	}

	adpPost := NewSSHAdapter(repo)
	clientCfgPost, err := adpPost.GetConfig(confirmedNodeID)
	if err != nil {
		t.Fatalf("post-confirm GetConfig: %v", err)
	}
	ctrlPost, err := adpPost.GetControlConfig(confirmedNodeID)
	if err != nil {
		t.Fatalf("post-confirm GetControlConfig: %v", err)
	}
	dialTargetPost := ssh.BuildClientTargetContext(confirmedNodeID, clientCfgPost, env, nil)
	dialSockPost, err := ctrlPost.ResolvePath(env, dialTargetPost)
	if err != nil {
		t.Fatalf("post-confirm ResolvePath: %v", err)
	}
	if clientCfgPost.ProxyJump != "openssh:10.0.0.1" || dialSockPost != dialSockPre {
		t.Fatalf("post-confirm drift: jump=%q sock=%q, want openssh:10.0.0.1 and %q",
			clientCfgPost.ProxyJump, dialSockPost, dialSockPre)
	}
}

func TestP7W9c_DE9L2_TwoPassCanonicalLookupUserHostPortAndSavedAlias(t *testing.T) {
	t.Parallel()

	env := w9cTestEnv()
	readOnlyProv, repo := buildP3EquivalenceFixtures(t, nil)

	t.Run("user_at_host_port_selector_preserves_user_and_port_under_canonicalization", func(t *testing.T) {
		t.Parallel()
		assertDE9L2UserHostPortCanonicalization(t, env, readOnlyProv, repo)
	})

	t.Run("ResolveControlSessionLookup_uses_prepared_connTarget_for_canonicalized_saved_node", func(t *testing.T) {
		t.Parallel()
		assertDE9L2SessionLookupUsesPreparedTarget(t, env, readOnlyProv)
	})

	t.Run("saved_node_and_host_aliases_are_never_overwritten_by_CanonicalHost", func(t *testing.T) {
		t.Parallel()
		assertDE9L2SavedAliasesPreserved(t, env, readOnlyProv)
	})
}

func assertDE9L2UserHostPortCanonicalization(t *testing.T, env ssh.Environment, readOnlyProv *config.Provider, repo *config.Repository) {
	t.Helper()

	var (
		dialTarget ssh.TargetContext
		dialSock   string
	)
	if err := repo.WithPendingNode(t.Context(), config.EnsureNodeOptions{
		Target: config.ConnectionTarget{
			Selector:     "short.corp.example.com",
			OriginalHost: "short",
			User:         "alice",
			HasUser:      true,
			Port:         2222,
			HasPort:      true,
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

	for _, tc := range []struct {
		name string
		req  ControlTargetRequest
	}{
		{
			name: "with_canon_orig_and_canon_host",
			req: ControlTargetRequest{
				Provider:              readOnlyProv,
				Target:                config.ConnectionTarget{Selector: "alice@short:2222"},
				CanonicalOriginalHost: "short",
				CanonicalHost:         "short.corp.example.com",
				Environment:           &env,
			},
		},
		{
			name: "with_canon_host_only",
			req: ControlTargetRequest{
				Provider:      readOnlyProv,
				Target:        config.ConnectionTarget{Selector: "alice@short:2222"},
				CanonicalHost: "short.corp.example.com",
				Environment:   &env,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctrlSock, ctrlRes, err := ResolveControlSocketPath(tc.req)
			if err != nil {
				t.Fatalf("ResolveControlSocketPath: %v", err)
			}
			if ctrlRes.Target.User != "alice" || ctrlRes.Target.Port != 2222 ||
				ctrlRes.Target.Host != "10.40.0.5" ||
				ctrlRes.Target.OriginalHost != "short" ||
				ctrlRes.Target.CanonicalHost != "short.corp.example.com" {
				t.Fatalf("unexpected TargetContext = %+v, want alice@10.40.0.5:2222 (orig=short, canon=short.corp.example.com)", ctrlRes.Target)
			}
			if ctrlRes.Target != dialTarget || ctrlSock != dialSock {
				t.Fatalf("control vs dial mismatch:\n  target: %+v vs %+v\n  sock:   %q vs %q",
					ctrlRes.Target, dialTarget, ctrlSock, dialSock)
			}
		})
	}
}

func assertDE9L2SessionLookupUsesPreparedTarget(t *testing.T, env ssh.Environment, readOnlyProv *config.Provider) {
	t.Helper()

	cfg := readOnlyProv.Snapshot()
	cfg.Hosts.Set("h-canon", models.Host{Address: "10.40.0.5", Port: 2222})
	cfg.Identities.Set("id-alice", models.Identity{User: "alice", AuthType: "auto"})
	cfg.Nodes.Set("saved-canon-alice", models.Node{
		HostRef:       "h-canon",
		IdentityRef:   "id-alice",
		OpenSSHAlias:  "short",
		CanonicalHost: "short.corp.example.com",
	})
	prov := config.NewProviderWithOpenSSHParser(cfg, readOnlyProv.GetOpenSSHParser())

	req := ControlTargetRequest{
		Provider:              prov,
		Target:                config.ConnectionTarget{Selector: "alice@short:2222"},
		CanonicalOriginalHost: "short",
		CanonicalHost:         "short.corp.example.com",
		Environment:           &env,
	}
	res, err := ResolveControlTarget(req)
	if err != nil {
		t.Fatalf("ResolveControlTarget: %v", err)
	}
	lookupKey, auth := ResolveControlSessionLookup(req, res.Target)
	if lookupKey != "saved-canon-alice" || lookupKey != res.LookupKey {
		t.Fatalf("ResolveControlSessionLookup = (%q, %+v), want saved-canon-alice (ResolveControlTarget.LookupKey=%q)",
			lookupKey, auth, res.LookupKey)
	}
}

func assertDE9L2SavedAliasesPreserved(t *testing.T, env ssh.Environment, readOnlyProv *config.Provider) {
	t.Helper()

	cfg := readOnlyProv.Snapshot()
	if h, ok := cfg.Hosts.Get("h-web1"); ok {
		h.Alias = []string{"Prod Host Alias"}
		cfg.Hosts.Set("h-web1", h)
	}
	prov := config.NewProviderWithOpenSSHParser(cfg, readOnlyProv.GetOpenSSHParser())

	for _, sel := range []string{"Prod Web 01", "Prod Host Alias"} {
		for _, tc := range []struct {
			name string
			req  ControlTargetRequest
		}{
			{
				name: "selector_with_canon_orig",
				req: ControlTargetRequest{
					Provider:              prov,
					Target:                config.ConnectionTarget{Selector: sel},
					CanonicalOriginalHost: "short",
					CanonicalHost:         "short.corp.example.com",
					Environment:           &env,
				},
			},
			{
				name: "selector_with_canon_host_only",
				req: ControlTargetRequest{
					Provider:      prov,
					Target:        config.ConnectionTarget{Selector: sel},
					CanonicalHost: "short.corp.example.com",
					Environment:   &env,
				},
			},
			{
				name: "nodeID_with_canon_host_only",
				req: ControlTargetRequest{
					Provider:      prov,
					NodeID:        sel,
					CanonicalHost: "short.corp.example.com",
					Environment:   &env,
				},
			},
		} {
			t.Run(sel+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				res, err := ResolveControlTarget(tc.req)
				if err != nil {
					t.Fatalf("ResolveControlTarget(%q): %v", sel, err)
				}
				if res.Target.Host != "10.10.0.1" || res.LookupKey != "web-01" {
					t.Fatalf("saved alias %q was overwritten by CanonicalHost: res=%+v", sel, res)
				}
				lk, _ := ResolveControlSessionLookup(tc.req, res.Target)
				if lk != "web-01" {
					t.Fatalf("ResolveControlSessionLookup(%q) = %q, want web-01", sel, lk)
				}
			})
		}
	}
}
