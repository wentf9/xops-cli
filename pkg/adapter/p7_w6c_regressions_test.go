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

func TestP7W6c_DEF6M1_ParseSessionOptionsAndResolveRejectControlAndWhitespaceProxyJump(t *testing.T) {
	t.Parallel()

	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Hosts.Set("h-web", models.Host{Address: "10.0.0.2", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("saved-bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-ops"})
	muxOpts := &ssh.Options{}
	muxOpts.SetControlMaster(ssh.ControlMasterAuto)
	muxOpts.SetControlPath("/tmp/cm-%h-%p-%r-%j-%C")
	cfg.Nodes.Set("saved-web", models.Node{
		HostRef:     "h-web",
		IdentityRef: "id-ops",
		ProxyJump:   "saved-bastion",
		SSHOptions:  muxOpts,
	})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	badJumps := []string{
		"none\n",
		"bastion\n",
		"\n",
		"\t",
		"\r\n",
		"\u0085",
		"\v",
		"\f",
		"\u2028",
		"\u2029",
		"   ",
		"none\r\n",
		"none\t",
	}
	for _, bad := range badJumps {
		if got, err := ParseSessionOptions(nil, bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ParseSessionOptions(nil, %q) = (%+v, %v), want ErrSSHOptionsValidation", bad, got, err)
		}
		if got, err := ParseSessionOptions([]string{"ConnectTimeout=5"}, bad); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ParseSessionOptions([ConnectTimeout=5], %q) = (%+v, %v), want ErrSSHOptionsValidation", bad, got, err)
		}

		adp := NewSSHAdapter(prov, WithSessionAuthOverride("saved-web", SessionAuth{ProxyJump: bad}))
		if pol, err := adp.Resolve(t.Context(), ResolveRequest{NodeID: "saved-web", ResolveProxy: true}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("Resolve(saved-web, SessionAuth.ProxyJump=%q) = (proxy=%q, err=%v), want ErrSSHOptionsValidation", bad, pol.Proxy(), err)
		}
		if _, err := adp.GetConfig("saved-web"); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("GetConfig(saved-web, SessionAuth.ProxyJump=%q) err = %v, want ErrSSHOptionsValidation", bad, err)
		}
		if _, _, err := ResolveControlSocketPath(ControlTargetRequest{
			Provider: prov,
			Target:   config.ConnectionTarget{Selector: "saved-web", ProxyJump: bad, HasProxyJump: true},
		}); !errors.Is(err, ssh.ErrSSHOptionsValidation) {
			t.Errorf("ResolveControlSocketPath(Target.ProxyJump=%q) err = %v, want ErrSSHOptionsValidation", bad, err)
		}
	}

	// Exact "" means unset CLI -J and preserves the saved node's mandatory bastion.
	emptyOpts, err := ParseSessionOptions(nil, "")
	if err != nil {
		t.Fatalf("ParseSessionOptions(nil, \"\") unexpected error: %v", err)
	}
	if !emptyOpts.IsEmpty() {
		t.Fatalf("ParseSessionOptions(nil, \"\") = %+v, want empty", emptyOpts)
	}
	adpDefault := NewSSHAdapter(prov)
	cfgDefault, err := adpDefault.GetConfig("saved-web")
	if err != nil {
		t.Fatalf("GetConfig(saved-web): %v", err)
	}
	if cfgDefault.ProxyJump != "saved-bastion" {
		t.Fatalf("saved-web default ProxyJump = %q, want saved-bastion", cfgDefault.ProxyJump)
	}
}

func TestP7W6c_DEF6M2_ControlTargetAndSocketPathEquivalenceWithSessionProxySetting(t *testing.T) {
	t.Parallel()

	env := ssh.Environment{
		HomeDir:   "/home/tester",
		LocalUser: "tester",
		LocalHost: "workstation.local",
		LocalUID:  "1000",
	}
	globalMux := &ssh.Options{}
	globalMux.SetControlMaster(ssh.ControlMasterAuto)
	globalMux.SetControlPath("/tmp/cm-p7w6c-%h-%p-%r-%n-%j-%C")

	type tcSpec struct {
		name            string
		selector        string
		targetProxyJump string
		sessionOpts     SessionControlOptions
		wantJump        string
		wantAuthJump    string
	}

	cases := []tcSpec{
		{
			name:         "dash_o_ProxyJump_none_only_in_SessionControl",
			selector:     "web-01",
			sessionOpts:  mustParseAdapterSessionControl(t, "", "ProxyJump=none"),
			wantJump:     "",
			wantAuthJump: "none",
		},
		{
			name:         "dash_o_ProxyJump_edge_jump_only_in_SessionControl",
			selector:     "web-01",
			sessionOpts:  mustParseAdapterSessionControl(t, "", "ProxyJump=edge-jump"),
			wantJump:     "edge-jump",
			wantAuthJump: "edge-jump",
		},
		{
			name:         "dash_o_ProxyJump_none_with_ProxyCommand_only_in_SessionControl",
			selector:     "web-01",
			sessionOpts:  mustParseAdapterSessionControl(t, "", "ProxyJump=none", "ProxyCommand=nc %h %p"),
			wantJump:     "",
			wantAuthJump: "",
		},
		{
			name:         "dash_o_ProxyJump_edge_jump_with_shadowed_ProxyCommand",
			selector:     "web-01",
			sessionOpts:  mustParseAdapterSessionControl(t, "", "ProxyJump=edge-jump", "ProxyCommand=nc %h %p"),
			wantJump:     "edge-jump",
			wantAuthJump: "edge-jump",
		},
		{
			name:            "target_ProxyJump_none_reveals_shadowed_ProxyCommand_in_SessionControl",
			selector:        "web-01",
			targetProxyJump: "none",
			sessionOpts:     mustParseAdapterSessionControl(t, "", "ProxyJump=edge-jump", "ProxyCommand=nc %h %p"),
			wantJump:        "",
			wantAuthJump:    "none",
		},
		{
			name:         "openssh_virtual_dash_o_ProxyJump_none_clears_tier4_jump",
			selector:     "openssh:app-virtual",
			sessionOpts:  mustParseAdapterSessionControl(t, "", "ProxyJump=none"),
			wantJump:     "",
			wantAuthJump: "none",
		},
		{
			name:         "openssh_virtual_dash_o_ProxyJump_edge_jump_overrides_tier4_jump",
			selector:     "openssh:app-virtual",
			sessionOpts:  mustParseAdapterSessionControl(t, "", "ProxyJump=edge-jump"),
			wantJump:     "edge-jump",
			wantAuthJump: "edge-jump",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			readOnlyProv, repo := buildP3EquivalenceFixtures(t, globalMux)

			connTarget := config.ConnectionTarget{
				Selector:     tc.selector,
				ProxyJump:    tc.targetProxyJump,
				HasProxyJump: tc.targetProxyJump != "",
			}
			ctrlSock, ctrlRes, err := ResolveControlSocketPath(ControlTargetRequest{
				Provider:       readOnlyProv,
				Target:         connTarget,
				SessionControl: tc.sessionOpts,
				Environment:    &env,
			})
			if err != nil {
				t.Fatalf("ResolveControlSocketPath: %v", err)
			}
			if ctrlRes.Target.JumpHost != tc.wantJump {
				t.Fatalf("control Target.JumpHost = %q, want %q", ctrlRes.Target.JumpHost, tc.wantJump)
			}
			if ctrlRes.SessionAuth.ProxyJump != tc.wantAuthJump {
				t.Fatalf("control SessionAuth.ProxyJump = %q, want %q", ctrlRes.SessionAuth.ProxyJump, tc.wantAuthJump)
			}

			// Verify dial-path equivalence against SSHAdapter.GetConfig + GetControlConfig.
			adpOpts := []Option{WithLocalExecution(true)}
			if tc.targetProxyJump != "" {
				adpOpts = append(adpOpts, WithSessionAuthOverride(tc.selector, SessionAuth{ProxyJump: tc.targetProxyJump}))
			}
			if !tc.sessionOpts.IsEmpty() {
				adpOpts = append(adpOpts, WithSessionControlOverride(tc.selector, tc.sessionOpts))
			}
			adp := NewSSHAdapter(repo, adpOpts...)
			clientCfg, err := adp.GetConfig(tc.selector)
			if err != nil {
				t.Fatalf("GetConfig(%q): %v", tc.selector, err)
			}
			dialCtrl, err := adp.GetControlConfig(tc.selector)
			if err != nil {
				t.Fatalf("GetControlConfig(%q): %v", tc.selector, err)
			}
			dialTarget := ssh.BuildClientTargetContext(tc.selector, clientCfg, env, nil)
			dialSock, err := dialCtrl.ResolvePath(env, dialTarget)
			if err != nil {
				t.Fatalf("dial ResolvePath: %v", err)
			}

			if ctrlRes.Target != dialTarget {
				t.Fatalf("TargetContext mismatch:\n  control = %+v\n  dial    = %+v", ctrlRes.Target, dialTarget)
			}
			if ctrlRes.Target.CanonicalTargetIdentity() != dialTarget.CanonicalTargetIdentity() {
				t.Fatalf("CanonicalTargetIdentity mismatch:\n  control = %q\n  dial    = %q",
					ctrlRes.Target.CanonicalTargetIdentity(), dialTarget.CanonicalTargetIdentity())
			}
			if ctrlSock != dialSock {
				t.Fatalf("ControlPath mismatch:\n  control = %q\n  dial    = %q", ctrlSock, dialSock)
			}
		})
	}
}

func TestP7W6c_DEF6M3_Tier2PersistedProxyJumpResolutionAndSecurityInvariants(t *testing.T) {
	t.Parallel()

	t.Run("openssh_import_user_at_alias_resolves_and_dials", testP7W6cDEF6M3OpenSSHImportUserAtAlias)
	t.Run("saved_node_alias_jump_resolves_and_matches_control_plane", testP7W6cDEF6M3SavedNodeAliasJump)
	t.Run("external_fqdn_ip_and_security_fail_closed_invariants", testP7W6cDEF6M3ExternalAndSecurityInvariants)
}

func testP7W6cDEF6M3OpenSSHImportUserAtAlias(t *testing.T) {
	t.Parallel()
	const sshCfg = `
Host bastion
    HostName 10.0.0.1
    User ops

Host app
    HostName 10.0.0.2
    User root
    ProxyJump alice@bastion
`
	hosts, err := config.ParseOpenSSHHosts(strings.NewReader(sshCfg), "defaultuser")
	if err != nil {
		t.Fatalf("ParseOpenSSHHosts: %v", err)
	}
	dir := t.TempDir()
	store := config.NewDefaultStore(filepath.Join(dir, "xops.yaml"), filepath.Join(dir, "xops.key"))
	repo, err := config.NewRepositoryWithoutOpenSSH(nil, store)
	if err != nil {
		t.Fatalf("NewRepositoryWithoutOpenSSH: %v", err)
	}
	res, err := repo.ImportOpenSSHHostsContext(t.Context(), hosts)
	if err != nil {
		t.Fatalf("ImportOpenSSHHostsContext: %v", err)
	}
	if res.Imported != 2 {
		t.Fatalf("Imported = %d, want 2", res.Imported)
	}

	adp := NewSSHAdapter(repo, WithStrictIsolation())
	pol, err := adp.Resolve(t.Context(), ResolveRequest{
		NodeID:          "app",
		RequireSnapshot: true,
		ResolveProxy:    true,
	})
	if err != nil {
		t.Fatalf("Resolve(app): %v", err)
	}
	const wantHop = "openssh:alice@10.0.0.1:22"
	if pol.EffectiveJump() != wantHop {
		t.Fatalf("Resolve(app).EffectiveJump() = %q, want %q", pol.EffectiveJump(), wantHop)
	}

	appCfg, err := adp.GetConfig("app")
	if err != nil {
		t.Fatalf("GetConfig(app): %v", err)
	}
	if appCfg.ProxyJump != wantHop {
		t.Fatalf("GetConfig(app).ProxyJump = %q, want %q", appCfg.ProxyJump, wantHop)
	}

	hopCfg, err := adp.GetConfig(appCfg.ProxyJump)
	if err != nil {
		t.Fatalf("GetConfig(%q): %v", appCfg.ProxyJump, err)
	}
	if hopCfg.Address != "10.0.0.1" || hopCfg.Port != 22 || hopCfg.User != "alice" {
		t.Fatalf("hopCfg = (%s, %d, %s), want (10.0.0.1, 22, alice)", hopCfg.Address, hopCfg.Port, hopCfg.User)
	}

	plan, err := ssh.CapturePlan(t.Context(), adp, "app", "p7-w6c-import")
	if err != nil {
		t.Fatalf("CapturePlan(app): %v", err)
	}
	if len(plan.Hops) != 2 || plan.Hops[0].NodeID != wantHop || plan.Hops[1].NodeID != "app" {
		t.Fatalf("CapturePlan hops = %+v, want [%s, app]", plan.Hops, wantHop)
	}
}

func testP7W6cDEF6M3SavedNodeAliasJump(t *testing.T) {
	t.Parallel()
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-bastion", models.Host{Address: "10.0.0.1", Port: 22})
	cfg.Hosts.Set("h-app", models.Host{Address: "10.0.0.2", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	muxOpts := &ssh.Options{}
	muxOpts.SetControlMaster(ssh.ControlMasterAuto)
	muxOpts.SetControlPath("/tmp/cm-alias-%h-%p-%r-%j-%C")
	cfg.Nodes.Set("ops@10.0.0.1:22", models.Node{
		HostRef:     "h-bastion",
		IdentityRef: "id-ops",
		Alias:       []string{"bastion"},
	})
	cfg.Nodes.Set("app", models.Node{
		HostRef:     "h-app",
		IdentityRef: "id-ops",
		ProxyJump:   "bastion",
		SSHOptions:  muxOpts,
	})
	prov := config.NewProviderWithoutOpenSSH(cfg)

	adp := NewSSHAdapter(prov)
	appCfg, err := adp.GetConfig("app")
	if err != nil {
		t.Fatalf("GetConfig(app): %v", err)
	}
	if appCfg.ProxyJump != "ops@10.0.0.1:22" {
		t.Fatalf("GetConfig(app).ProxyJump = %q, want ops@10.0.0.1:22", appCfg.ProxyJump)
	}
	if _, err := adp.GetConfig(appCfg.ProxyJump); err != nil {
		t.Fatalf("GetConfig(%q): %v", appCfg.ProxyJump, err)
	}

	// Control plane resolves the same alias jump so %j and %C stay byte-for-byte aligned.
	env := ssh.Environment{HomeDir: "/home/tester", LocalUser: "tester", LocalHost: "workstation.local", LocalUID: "1000"}
	ctrlSock, ctrlRes, err := ResolveControlSocketPath(ControlTargetRequest{
		Provider:    prov,
		Target:      config.ConnectionTarget{Selector: "app"},
		Environment: &env,
	})
	if err != nil {
		t.Fatalf("ResolveControlSocketPath(app): %v", err)
	}
	dialCtrl, err := adp.GetControlConfig("app")
	if err != nil {
		t.Fatalf("GetControlConfig(app): %v", err)
	}
	dialTarget := ssh.BuildClientTargetContext("app", appCfg, env, nil)
	dialSock, err := dialCtrl.ResolvePath(env, dialTarget)
	if err != nil {
		t.Fatalf("dial ResolvePath(app): %v", err)
	}
	if ctrlRes.Target != dialTarget || ctrlSock != dialSock {
		t.Fatalf("alias Tier-2 control vs dial mismatch:\n  target: %+v vs %+v\n  sock:   %q vs %q",
			ctrlRes.Target, dialTarget, ctrlSock, dialSock)
	}
}

func testP7W6cDEF6M3ExternalAndSecurityInvariants(t *testing.T) {
	t.Parallel()
	cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
	cfg.Hosts.Set("h-app", models.Host{Address: "10.0.0.2", Port: 22})
	cfg.Identities.Set("id-ops", models.Identity{User: "ops", AuthType: "auto"})
	cfg.Nodes.Set("app-fqdn", models.Node{HostRef: "h-app", IdentityRef: "id-ops", ProxyJump: "jump.corp.example.com"})
	cfg.Nodes.Set("app-ip", models.Node{HostRef: "h-app", IdentityRef: "id-ops", ProxyJump: "10.0.0.99"})
	cfg.Nodes.Set("app-unknown", models.Node{HostRef: "h-app", IdentityRef: "id-ops", ProxyJump: "unknown-typo"})
	cfg.Nodes.Set("ops@10.0.0.2:22", models.Node{
		HostRef:     "h-app",
		IdentityRef: "id-ops",
		Alias:       []string{"self-alias"},
		ProxyJump:   "self-alias",
	})
	prov := config.NewProviderWithoutOpenSSH(cfg)
	adp := NewSSHAdapter(prov)

	fqdnCfg, err := adp.GetConfig("app-fqdn")
	if err != nil || fqdnCfg.ProxyJump != "openssh:jump.corp.example.com" {
		t.Fatalf("GetConfig(app-fqdn) = (%+v, %v), want openssh:jump.corp.example.com", fqdnCfg, err)
	}
	if _, err := adp.GetConfig(fqdnCfg.ProxyJump); err != nil {
		t.Fatalf("GetConfig(%q): %v", fqdnCfg.ProxyJump, err)
	}

	ipCfg, err := adp.GetConfig("app-ip")
	if err != nil || ipCfg.ProxyJump != "openssh:10.0.0.99" {
		t.Fatalf("GetConfig(app-ip) = (%+v, %v), want openssh:10.0.0.99", ipCfg, err)
	}
	if _, err := adp.GetConfig(ipCfg.ProxyJump); err != nil {
		t.Fatalf("GetConfig(%q): %v", ipCfg.ProxyJump, err)
	}

	// Unknown single-label alias MUST fail closed (no silent fallback).
	if got, err := adp.GetConfig("app-unknown"); err == nil {
		t.Fatalf("GetConfig(app-unknown) unexpectedly succeeded with ProxyJump=%q, want error", got.ProxyJump)
	}

	// Self-loop via alias MUST fail closed with ProxyCycleError.
	var cycleErr *ssh.ProxyCycleError
	if _, err := adp.GetConfig("ops@10.0.0.2:22"); !errors.As(err, &cycleErr) {
		t.Fatalf("GetConfig(self-loop alias) err = %v, want *ssh.ProxyCycleError", err)
	}
}
