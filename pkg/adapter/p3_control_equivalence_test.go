package adapter

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func buildP3EquivalenceFixtures(t *testing.T, globalOpts *ssh.Options) (*config.Provider, *config.Repository) {
	t.Helper()

	sshCfg := strings.Join([]string{
		"Host jump-box",
		"  HostName 10.30.0.1",
		"  User juser",
		"  Port 2201",
		"",
		"Host app-virtual",
		"  HostName 10.30.0.20",
		"  User vuser",
		"  Port 2220",
		"  ProxyJump jump-box",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-%h-%p-%r-%n-%j-%C",
		"",
		"Host short",
		"  User ops",
		"",
		"Host *.corp.example.com",
		"  HostName 10.40.0.5",
		"  Port 2222",
		"  ControlMaster auto",
		"  ControlPath /tmp/cm-%n-%h-%p-%r-%j-%C",
		"",
		"Host *",
		"  CanonicalizeHostname yes",
		"  CanonicalDomains corp.example.com",
	}, "\n") + "\n"

	makeCfg := func() (*config.Configuration, *config.OpenSSHParser) {
		parser, err := config.NewOpenSSHParserFromReader(strings.NewReader(sshCfg))
		if err != nil {
			t.Fatalf("NewOpenSSHParserFromReader: %v", err)
		}
		cfg := config.NewProviderWithoutOpenSSH(nil).Snapshot()
		cfg.SSHOptions = globalOpts.Clone()

		// 1. Saved managed node with spaced alias ("Prod Web 01") and jump host.
		cfg.Hosts.Set("h-bastion", models.Host{Address: "10.10.0.254", Port: 22})
		cfg.Identities.Set("id-bastion", models.Identity{User: "jump", AuthType: "auto"})
		cfg.Nodes.Set("bastion", models.Node{HostRef: "h-bastion", IdentityRef: "id-bastion"})

		cfg.Hosts.Set("h-edge-jump", models.Host{Address: "10.10.0.253", Port: 2202})
		cfg.Identities.Set("id-edge-jump", models.Identity{User: "edge", AuthType: "auto"})
		cfg.Nodes.Set("edge-jump", models.Node{HostRef: "h-edge-jump", IdentityRef: "id-edge-jump"})

		muxOpts := &ssh.Options{}
		muxOpts.SetControlMaster(ssh.ControlMasterAuto)
		muxOpts.SetControlPath("/tmp/cm-%h-%p-%r-%n-%j-%C")

		cfg.Hosts.Set("h-web1", models.Host{Address: "10.10.0.1", Port: 2222})
		cfg.Identities.Set("id-web1", models.Identity{User: "ops", AuthType: "auto", KeyPath: "/tmp/id_web1"})
		cfg.Nodes.Set("web-01", models.Node{
			HostRef:     "h-web1",
			IdentityRef: "id-web1",
			Alias:       []string{"Prod Web 01"},
			ProxyJump:   "bastion",
			SSHOptions:  muxOpts.Clone(),
		})

		// Saved node with spaced node ID itself.
		cfg.Hosts.Set("h-web2", models.Host{Address: "10.10.0.2", Port: 22})
		cfg.Identities.Set("id-web2", models.Identity{User: "deploy", AuthType: "auto"})
		cfg.Nodes.Set("Prod Web 02", models.Node{
			HostRef:     "h-web2",
			IdentityRef: "id-web2",
			SSHOptions:  muxOpts.Clone(),
		})

		// Saved bracketed IPv6 literal and link-local IPv6 zone ID nodes.
		cfg.Hosts.Set("h-v6", models.Host{Address: "[2001:db8::1]", Port: 2222})
		cfg.Identities.Set("id-v6", models.Identity{User: "v6ops", AuthType: "auto"})
		cfg.Nodes.Set("v6-saved", models.Node{
			HostRef:     "h-v6",
			IdentityRef: "id-v6",
			SSHOptions:  muxOpts.Clone(),
		})

		cfg.Hosts.Set("h-v6zone", models.Host{Address: "[fe80::1%eth0]", Port: 22})
		cfg.Identities.Set("id-v6zone", models.Identity{User: "zoneops", AuthType: "auto"})
		cfg.Nodes.Set("v6-zone", models.Node{
			HostRef:     "h-v6zone",
			IdentityRef: "id-v6zone",
			SSHOptions:  muxOpts.Clone(),
		})

		return cfg, parser
	}

	roCfg, roParser := makeCfg()
	readOnlyProv := config.NewProviderWithOpenSSHParser(roCfg, roParser)

	repoCfg, repoParser := makeCfg()
	store := config.NewDefaultStore(filepath.Join(t.TempDir(), "config.yaml"), filepath.Join(t.TempDir(), "key"))
	repo, err := config.NewRepositoryWithOpenSSHParser(repoCfg, store, repoParser)
	if err != nil {
		t.Fatalf("NewRepositoryWithOpenSSHParser: %v", err)
	}
	return readOnlyProv, repo
}

func mustParseAdapterSessionControl(t *testing.T, cliJump string, rawOpts ...string) SessionControlOptions {
	t.Helper()
	parsed, err := ParseSessionOptions(rawOpts, cliJump)
	if err != nil {
		t.Fatalf("ParseSessionOptions(%v, %q): %v", rawOpts, cliJump, err)
	}
	return parsed
}

func TestP3_ResolveControlTargetAndSocketPath_EquivalenceWithDialPath(t *testing.T) {
	t.Parallel()

	env := ssh.Environment{
		HomeDir:   "/home/tester",
		LocalUser: "tester",
		LocalHost: "workstation.local",
		LocalUID:  "1000",
	}

	globalMux := &ssh.Options{}
	globalMux.SetControlMaster(ssh.ControlMasterAuto)
	globalMux.SetControlPath("/tmp/cm-global-%h-%p-%r-%n-%j-%C")

	type scenario struct {
		name           string
		globalOpts     *ssh.Options
		target         config.ConnectionTarget
		overrideOrig   string
		overrideHost   string
		canonOrig      string
		canonHost      string
		sessionCtrl    SessionControlOptions
		wantJumpHost   string
		wantHost       string
		wantOrigHost   string
		wantCanonHost  string
		checkExtraPath func(t *testing.T, gotPath string)
	}

	cases := []scenario{
		{
			name:         "1a_saved_managed_node_by_id",
			globalOpts:   globalMux,
			target:       config.ConnectionTarget{Selector: "web-01"},
			wantJumpHost: "bastion",
			wantHost:     "10.10.0.1",
			wantOrigHost: "web-01",
		},
		{
			name:         "1b_saved_managed_node_spaced_alias",
			globalOpts:   globalMux,
			target:       config.ConnectionTarget{Selector: "Prod Web 01"},
			wantJumpHost: "bastion",
			wantHost:     "10.10.0.1",
			wantOrigHost: "web-01",
		},
		{
			name:         "1c_saved_managed_node_spaced_id",
			globalOpts:   globalMux,
			target:       config.ConnectionTarget{Selector: "Prod Web 02"},
			wantJumpHost: "",
			wantHost:     "10.10.0.2",
			wantOrigHost: "Prod Web 02",
		},
		{
			name:         "2a_saved_node_proxyjump_overridden_by_tier1_proxycommand",
			globalOpts:   globalMux,
			target:       config.ConnectionTarget{Selector: "web-01"},
			sessionCtrl:  mustParseAdapterSessionControl(t, "", "ProxyCommand=nc %h %p"),
			wantJumpHost: "",
			wantHost:     "10.10.0.1",
			wantOrigHost: "web-01",
			checkExtraPath: func(t *testing.T, gotPath string) {
				t.Helper()
				// %C hash must reflect JumpHost == "" (not "bastion").
				bastionHash := ssh.ComputeConnectionHash(env.LocalHost, "10.10.0.1", "2222", "ops", "bastion")
				directHash := ssh.ComputeConnectionHash(env.LocalHost, "10.10.0.1", "2222", "ops", "")
				if strings.Contains(gotPath, bastionHash) || !strings.Contains(gotPath, directHash) {
					t.Fatalf("ProxyCommand override path %q did not recompute %%C without bastion (want hash %s, not %s)", gotPath, directHash, bastionHash)
				}
			},
		},
		{
			name:       "2b_saved_node_explicit_tier1_jump_beats_proxycommand",
			globalOpts: globalMux,
			target: config.ConnectionTarget{
				Selector:     "web-01",
				ProxyJump:    "edge-jump",
				HasProxyJump: true,
			},
			sessionCtrl:  mustParseAdapterSessionControl(t, "edge-jump", "ProxyCommand=nc %h %p"),
			wantJumpHost: "edge-jump",
			wantHost:     "10.10.0.1",
			wantOrigHost: "web-01",
		},
		{
			name:         "2c_saved_node_proxycommand_none_disables_node_proxyjump",
			globalOpts:   globalMux,
			target:       config.ConnectionTarget{Selector: "web-01"},
			sessionCtrl:  mustParseAdapterSessionControl(t, "", "ProxyCommand=none"),
			wantJumpHost: "",
			wantHost:     "10.10.0.1",
			wantOrigHost: "web-01",
		},
		{
			name:         "3_openssh_virtual_alias_with_hostname_user_port_proxyjump",
			globalOpts:   globalMux,
			target:       config.ConnectionTarget{Selector: "openssh:app-virtual"},
			overrideOrig: "app-virtual",
			wantJumpHost: "openssh:jump-box",
			wantHost:     "10.30.0.20",
			wantOrigHost: "app-virtual",
		},
		{
			name:       "4_twopass_canonicalize_hostname_pass2_controlpath",
			globalOpts: nil,
			target: config.ConnectionTarget{
				Selector:     "short.corp.example.com",
				OriginalHost: "short",
			},
			overrideOrig:  "short",
			canonOrig:     "short",
			canonHost:     "short.corp.example.com",
			wantJumpHost:  "",
			wantHost:      "10.40.0.5",
			wantOrigHost:  "short",
			wantCanonHost: "short.corp.example.com",
		},
		{
			name:         "5a_saved_bracketed_ipv6_literal",
			globalOpts:   globalMux,
			target:       config.ConnectionTarget{Selector: "v6-saved"},
			wantJumpHost: "",
			wantHost:     "2001:db8::1",
			wantOrigHost: "v6-saved",
		},
		{
			name:         "5b_adhoc_bracketed_ipv6_literal",
			globalOpts:   globalMux,
			target:       config.ConnectionTarget{Selector: "[2001:db8::99]", User: "ops", HasUser: true, Port: 2222, HasPort: true},
			overrideOrig: "[2001:db8::99]",
			wantJumpHost: "",
			wantHost:     "2001:db8::99",
			wantOrigHost: "[2001:db8::99]",
		},
		{
			name:         "5c_saved_ipv6_link_local_zone_id",
			globalOpts:   globalMux,
			target:       config.ConnectionTarget{Selector: "v6-zone"},
			wantJumpHost: "",
			wantHost:     "fe80::1%eth0",
			wantOrigHost: "v6-zone",
		},
		{
			name:         "5d_adhoc_ipv6_link_local_zone_id",
			globalOpts:   globalMux,
			target:       config.ConnectionTarget{Selector: "[fe80::99%eth0]", User: "ops", HasUser: true, Port: 22, HasPort: true},
			overrideOrig: "[fe80::99%eth0]",
			wantJumpHost: "",
			wantHost:     "fe80::99%eth0",
			wantOrigHost: "[fe80::99%eth0]",
		},
		{
			name:       "6a_cli_overrides_on_saved_node",
			globalOpts: globalMux,
			target: config.ConnectionTarget{
				Selector:     "web-01",
				User:         "altuser",
				HasUser:      true,
				Port:         2299,
				HasPort:      true,
				ProxyJump:    "edge-jump",
				HasProxyJump: true,
			},
			overrideHost: "10.10.0.1.internal",
			wantJumpHost: "edge-jump",
			wantHost:     "10.10.0.1.internal",
			wantOrigHost: "altuser@10.10.0.1:2299",
		},
		{
			name:       "6b_cli_overrides_on_openssh_alias",
			globalOpts: globalMux,
			target: config.ConnectionTarget{
				Selector:     "app-virtual",
				User:         "altuser",
				HasUser:      true,
				Port:         2299,
				HasPort:      true,
				ProxyJump:    "edge-jump",
				HasProxyJump: true,
			},
			overrideOrig: "app-virtual",
			overrideHost: "app-virtual.internal",
			wantJumpHost: "edge-jump",
			wantHost:     "app-virtual.internal",
			wantOrigHost: "app-virtual",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			readOnlyProv, repo := buildP3EquivalenceFixtures(t, tc.globalOpts)
			beforeKeys := append([]string(nil), readOnlyProv.Snapshot().Nodes.Keys()...)

			// Control plane (read-only ConfigProvider, zero mutation).
			req := ControlTargetRequest{
				Provider:                 readOnlyProv,
				Target:                   tc.target,
				ApplyTargetNodeOverrides: true,
				OverrideOriginalHost:     tc.overrideOrig,
				OverrideExpandedHost:     tc.overrideHost,
				CanonicalOriginalHost:    tc.canonOrig,
				CanonicalHost:            tc.canonHost,
				SessionControl:           tc.sessionCtrl,
				Environment:              &env,
			}
			ctrlSock, ctrlRes, err := ResolveControlSocketPath(req)
			if err != nil {
				t.Fatalf("ResolveControlSocketPath: %v", err)
			}
			afterKeys := readOnlyProv.Snapshot().Nodes.Keys()
			if len(afterKeys) != len(beforeKeys) {
				t.Fatalf("read-only provider mutated: node count %d -> %d", len(beforeKeys), len(afterKeys))
			}

			// Real dial plane (PrepareNodeContext + SSHAdapter.GetConfig + GetControlConfig + BuildClientTargetContext).
			prep, err := repo.PrepareNodeContext(t.Context(), config.EnsureNodeOptions{
				Target:      tc.target,
				DefaultUser: env.LocalUser,
			})
			if err != nil {
				t.Fatalf("PrepareNodeContext: %v", err)
			}
			adpOpts := []Option{
				WithLocalExecution(true),
				WithSessionAuthOverride(prep.NodeID, SessionAuth{
					HostName:      tc.overrideHost,
					OriginalHost:  tc.overrideOrig,
					CanonicalHost: tc.canonHost,
					ProxyJump:     tc.target.ProxyJump,
				}),
			}
			if !tc.sessionCtrl.IsEmpty() {
				adpOpts = append(adpOpts, WithSessionControlOverride(prep.NodeID, tc.sessionCtrl))
			}
			adp := NewSSHAdapter(repo, adpOpts...)
			clientCfg, err := adp.GetConfig(prep.NodeID)
			if err != nil {
				t.Fatalf("GetConfig(%q): %v", prep.NodeID, err)
			}
			dialCtrl, err := adp.GetControlConfig(prep.NodeID)
			if err != nil {
				t.Fatalf("GetControlConfig(%q): %v", prep.NodeID, err)
			}
			if !dialCtrl.IsEnabled() {
				t.Fatalf("expected dial ControlConfig to be enabled, got %+v", dialCtrl)
			}
			dialTarget := ssh.BuildClientTargetContext(prep.NodeID, clientCfg, env, nil)
			dialSock, err := dialCtrl.ResolvePath(env, dialTarget)
			if err != nil {
				t.Fatalf("dial ControlConfig.ResolvePath: %v", err)
			}

			// Assert 100% byte-for-byte TargetContext equality.
			if ctrlRes.Target != dialTarget {
				t.Fatalf("TargetContext mismatch:\n  control = %+v\n  dial    = %+v", ctrlRes.Target, dialTarget)
			}
			if ctrlRes.Target.Host != tc.wantHost || ctrlRes.Target.JumpHost != tc.wantJumpHost ||
				ctrlRes.Target.OriginalHost != tc.wantOrigHost || ctrlRes.Target.CanonicalHost != tc.wantCanonHost {
				t.Fatalf("TargetContext fields = %+v, want Host=%q JumpHost=%q OriginalHost=%q CanonicalHost=%q",
					ctrlRes.Target, tc.wantHost, tc.wantJumpHost, tc.wantOrigHost, tc.wantCanonHost)
			}
			// Assert 100% byte-for-byte expanded ControlPath equality.
			if ctrlSock != dialSock {
				t.Fatalf("ControlPath mismatch:\n  control = %q\n  dial    = %q", ctrlSock, dialSock)
			}
			if ctrlSock == "" {
				t.Fatal("expected non-empty expanded control socket path")
			}
			if tc.checkExtraPath != nil {
				tc.checkExtraPath(t, ctrlSock)
			}
		})
	}
}

func TestP3_Tier3GlobalProxyCommandBeatsTier4OpenSSHJump(t *testing.T) {
	t.Parallel()

	env := ssh.Environment{
		HomeDir:   "/home/tester",
		LocalUser: "tester",
		LocalHost: "workstation.local",
		LocalUID:  "1000",
	}
	globalOpts := &ssh.Options{}
	globalOpts.SetControlMaster(ssh.ControlMasterAuto)
	globalOpts.SetControlPath("/tmp/cm-%h-%p-%r-%n-%j-%C")
	if err := globalOpts.Set(ssh.OptionProxyCommand, "nc %h %p"); err != nil {
		t.Fatalf("set global ProxyCommand: %v", err)
	}
	readOnlyProv, repo := buildP3EquivalenceFixtures(t, globalOpts)

	req := ControlTargetRequest{
		Provider:                 readOnlyProv,
		Target:                   config.ConnectionTarget{Selector: "openssh:app-virtual"},
		ApplyTargetNodeOverrides: true,
		OverrideOriginalHost:     "app-virtual",
		Environment:              &env,
	}
	ctrlSock, ctrlRes, err := ResolveControlSocketPath(req)
	if err != nil {
		t.Fatalf("ResolveControlSocketPath: %v", err)
	}
	adp := NewSSHAdapter(repo, WithLocalExecution(true), WithSessionAuthOverride("openssh:app-virtual", SessionAuth{OriginalHost: "app-virtual"}))
	cfg, err := adp.GetConfig("openssh:app-virtual")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	dialCtrl, err := adp.GetControlConfig("openssh:app-virtual")
	if err != nil {
		t.Fatalf("GetControlConfig: %v", err)
	}
	dialTarget := ssh.BuildClientTargetContext("openssh:app-virtual", cfg, env, nil)
	dialSock, err := dialCtrl.ResolvePath(env, dialTarget)
	if err != nil {
		t.Fatalf("dial ResolvePath: %v", err)
	}
	if ctrlRes.Target.JumpHost != "" || dialTarget.JumpHost != "" {
		t.Fatalf("expected Tier-3 ProxyCommand to clear Tier-4 ProxyJump: control=%+v dial=%+v", ctrlRes.Target, dialTarget)
	}
	if ctrlRes.Target != dialTarget || ctrlSock != dialSock {
		t.Fatalf("control vs dial mismatch:\n  target: %+v vs %+v\n  sock:   %q vs %q", ctrlRes.Target, dialTarget, ctrlSock, dialSock)
	}
}

func TestP3_ControlTargetContextNormalization(t *testing.T) {
	t.Parallel()

	env := ssh.Environment{
		HomeDir:   "/home/tester",
		LocalUser: "tester",
		LocalHost: "workstation.local",
		LocalUID:  "1000",
	}

	pol := EffectivePolicy{
		snapshot: config.ConnectionSnapshot{
			Host:     models.Host{Address: "[fe80::1%eth0]", Port: 0},
			Identity: models.Identity{User: "   "},
			Node:     models.Node{ProxyJump: " jump1 , none , jump2 "},
		},
		proxySetting:  proxySettingFromJumpString(" jump1 , none , jump2 "),
		originalHost:  "  edge-v6  ",
		canonicalHost: "  edge-v6.corp.example.com  ",
	}
	got := pol.controlTargetContextWithEnv("edge-v6", env)
	want := ssh.TargetContext{
		Host:          "fe80::1%eth0",
		Port:          22,
		User:          "tester",
		OriginalHost:  "edge-v6",
		CanonicalHost: "edge-v6.corp.example.com",
		JumpHost:      "jump1,jump2",
	}
	if got != want {
		t.Fatalf("controlTargetContextWithEnv = %+v, want %+v", got, want)
	}
}
