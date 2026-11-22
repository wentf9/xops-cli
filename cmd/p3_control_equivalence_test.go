package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/wentf9/xops-cli/core/ssh"
	"github.com/wentf9/xops-cli/internal/sshenv"
	"github.com/wentf9/xops-cli/pkg/adapter"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
)

func buildCmdP3EquivalenceFixtures(t *testing.T, globalOpts *ssh.Options) (*config.Provider, *config.Repository) {
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

		cfg.Hosts.Set("h-web2", models.Host{Address: "10.10.0.2", Port: 22})
		cfg.Identities.Set("id-web2", models.Identity{User: "deploy", AuthType: "auto"})
		cfg.Nodes.Set("Prod Web 02", models.Node{
			HostRef:     "h-web2",
			IdentityRef: "id-web2",
			SSHOptions:  muxOpts.Clone(),
		})

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

type cmdP3EquivalenceScenario struct {
	name           string
	globalOpts     *ssh.Options
	makeOpts       func() *SshOptions
	wantJumpHost   string
	wantHost       string
	wantOrigHost   string
	wantCanonHost  string
	checkExtraPath func(t *testing.T, gotPath string)
}

func resolveCmdControlForScenario(t *testing.T, tc cmdP3EquivalenceScenario, readOnlyProv *config.Provider) (ssh.TargetContext, string) {
	t.Helper()
	beforeKeys := append([]string(nil), readOnlyProv.Snapshot().Nodes.Keys()...)
	ctlOpts := tc.makeOpts()
	if err := ctlOpts.ensureArgsParsed(); err != nil {
		t.Fatalf("ctlOpts.ensureArgsParsed: %v", err)
	}
	if err := ctlOpts.applyHostnameCanonicalization(t.Context(), readOnlyProv, nil); err != nil {
		t.Fatalf("ctlOpts.applyHostnameCanonicalization: %v", err)
	}
	ctlNodeID, err := resolveControlNodeID(readOnlyProv, effectiveConnectionTarget(ctlOpts, ""))
	if err != nil {
		t.Fatalf("resolveControlNodeID: %v", err)
	}
	ctlTarget, err := controlTarget(ctlOpts, readOnlyProv, ctlNodeID)
	if err != nil {
		t.Fatalf("controlTarget: %v", err)
	}
	ctlSock, err := controlSocketPath(ctlOpts, readOnlyProv, ctlNodeID)
	if err != nil {
		t.Fatalf("controlSocketPath: %v", err)
	}
	if afterKeys := readOnlyProv.Snapshot().Nodes.Keys(); len(afterKeys) != len(beforeKeys) {
		t.Fatalf("read-only provider mutated during control resolution: %d -> %d", len(beforeKeys), len(afterKeys))
	}
	return ctlTarget, ctlSock
}

func resolveCmdDialForScenario(t *testing.T, tc cmdP3EquivalenceScenario, repo *config.Repository, env ssh.Environment) (ssh.TargetContext, string) {
	t.Helper()
	dialOpts := tc.makeOpts()
	dialOpts.Remember = "never"
	if err := dialOpts.ensureArgsParsed(); err != nil {
		t.Fatalf("dialOpts.ensureArgsParsed: %v", err)
	}
	var (
		dialTarget ssh.TargetContext
		dialSock   string
	)
	if err := dialOpts.withTestPendingNode(t.Context(), repo, func(lease config.PendingLease) error {
		dialNodeID := lease.NodeID()
		adpOpts, err := dialOpts.buildAdapterOptions(dialNodeID, repo.Snapshot(), repo)
		if err != nil {
			t.Fatalf("dialOpts.buildAdapterOptions: %v", err)
		}
		adp := adapter.NewSSHAdapter(repo, adpOpts...)
		clientCfg, err := adp.GetConfig(dialNodeID)
		if err != nil {
			t.Fatalf("adp.GetConfig(%q): %v", dialNodeID, err)
		}
		dialCtrl, err := adp.GetControlConfig(dialNodeID)
		if err != nil {
			t.Fatalf("adp.GetControlConfig(%q): %v", dialNodeID, err)
		}
		if !dialCtrl.IsEnabled() {
			t.Fatalf("expected enabled dial ControlConfig, got %+v", dialCtrl)
		}
		dialTarget = ssh.BuildClientTargetContext(dialNodeID, clientCfg, env, nil)
		var pathErr error
		dialSock, pathErr = dialCtrl.ResolvePath(env, dialTarget)
		if pathErr != nil {
			t.Fatalf("dialCtrl.ResolvePath: %v", pathErr)
		}
		return nil
	}); err != nil {
		t.Fatalf("dialOpts.withTestPendingNode: %v", err)
	}
	return dialTarget, dialSock
}

func runCmdP3EquivalenceScenario(t *testing.T, tc cmdP3EquivalenceScenario, env ssh.Environment) {
	t.Helper()

	readOnlyProv, repo := buildCmdP3EquivalenceFixtures(t, tc.globalOpts)
	ctlTarget, ctlSock := resolveCmdControlForScenario(t, tc, readOnlyProv)
	dialTarget, dialSock := resolveCmdDialForScenario(t, tc, repo, env)

	// Assert 100% byte-for-byte TargetContext equality.
	if ctlTarget != dialTarget {
		t.Fatalf("TargetContext mismatch:\n  control = %+v\n  dial    = %+v", ctlTarget, dialTarget)
	}
	if ctlTarget.Host != tc.wantHost || ctlTarget.JumpHost != tc.wantJumpHost ||
		ctlTarget.OriginalHost != tc.wantOrigHost || ctlTarget.CanonicalHost != tc.wantCanonHost {
		t.Fatalf("TargetContext fields = %+v, want Host=%q JumpHost=%q OriginalHost=%q CanonicalHost=%q",
			ctlTarget, tc.wantHost, tc.wantJumpHost, tc.wantOrigHost, tc.wantCanonHost)
	}

	// Assert 100% byte-for-byte expanded ControlPath equality.
	if ctlSock != dialSock {
		t.Fatalf("ControlPath mismatch:\n  control = %q\n  dial    = %q", ctlSock, dialSock)
	}
	if ctlSock == "" {
		t.Fatal("expected non-empty control socket path")
	}
	if tc.checkExtraPath != nil {
		tc.checkExtraPath(t, ctlSock)
	}
}

func TestP3_CmdControlVsDialPath_ByteForByteEquivalence(t *testing.T) {
	t.Parallel()

	env := sshenv.Discover()
	globalMux := &ssh.Options{}
	globalMux.SetControlMaster(ssh.ControlMasterAuto)
	globalMux.SetControlPath("/tmp/cm-global-%h-%p-%r-%n-%j-%C")

	fakeCanon := &round4FakeCanonicalResolver{
		hosts: map[string][]string{
			"short.corp.example.com": {"10.40.0.5"},
		},
	}

	cases := []cmdP3EquivalenceScenario{
		{
			name:       "1a_saved_managed_node_by_id",
			globalOpts: globalMux,
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.args = []string{"web-01"}
				return o
			},
			wantJumpHost: "bastion",
			wantHost:     "10.10.0.1",
			wantOrigHost: "web-01",
		},
		{
			name:       "1b_saved_managed_node_spaced_alias",
			globalOpts: globalMux,
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.args = []string{"Prod Web 01"}
				return o
			},
			wantJumpHost: "bastion",
			wantHost:     "10.10.0.1",
			wantOrigHost: "web-01",
		},
		{
			name:       "1c_saved_managed_node_spaced_id",
			globalOpts: globalMux,
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.args = []string{"Prod Web 02"}
				return o
			},
			wantJumpHost: "",
			wantHost:     "10.10.0.2",
			wantOrigHost: "Prod Web 02",
		},
		{
			name:       "2_saved_node_proxyjump_overridden_by_cli_proxycommand",
			globalOpts: globalMux,
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.args = []string{"web-01"}
				o.control.Options = []string{"ProxyCommand=nc %h %p"}
				return o
			},
			wantJumpHost: "",
			wantHost:     "10.10.0.1",
			wantOrigHost: "web-01",
			checkExtraPath: func(t *testing.T, gotPath string) {
				t.Helper()
				bastionHash := ssh.ComputeConnectionHash(env.LocalHost, "10.10.0.1", "2222", "ops", "bastion")
				directHash := ssh.ComputeConnectionHash(env.LocalHost, "10.10.0.1", "2222", "ops", "")
				if strings.Contains(gotPath, bastionHash) || !strings.Contains(gotPath, directHash) {
					t.Fatalf("controlSocketPath %q drifted on %%C under -o ProxyCommand: want hash %s, not %s", gotPath, directHash, bastionHash)
				}
			},
		},
		{
			name:       "3_openssh_virtual_alias_with_hostname_user_port_proxyjump",
			globalOpts: globalMux,
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.args = []string{"openssh:app-virtual"}
				return o
			},
			wantJumpHost: "openssh:jump-box",
			wantHost:     "10.30.0.20",
			wantOrigHost: "app-virtual",
		},
		{
			name:       "4_twopass_canonicalize_hostname_pass2_controlpath",
			globalOpts: nil,
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.args = []string{"short"}
				o.canonicalResolver = fakeCanon
				return o
			},
			wantJumpHost:  "",
			wantHost:      "10.40.0.5",
			wantOrigHost:  "short",
			wantCanonHost: "short.corp.example.com",
		},
		{
			name:       "5a_bracketed_ipv6_literal_adhoc",
			globalOpts: globalMux,
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.args = []string{"[2001:db8::99]"}
				o.User = "ops"
				o.Port = 2222
				return o
			},
			wantJumpHost: "",
			wantHost:     "2001:db8::99",
			wantOrigHost: "2001:db8::99",
		},
		{
			name:       "5b_bracketed_ipv6_link_local_zone_id_adhoc",
			globalOpts: globalMux,
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.args = []string{"[fe80::99%eth0]"}
				o.User = "ops"
				o.Port = 22
				return o
			},
			wantJumpHost: "",
			wantHost:     "fe80::99%eth0",
			wantOrigHost: "fe80::99%eth0",
		},
		{
			name:       "5c_saved_bracketed_ipv6_literal",
			globalOpts: globalMux,
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.args = []string{"v6-saved"}
				return o
			},
			wantJumpHost: "",
			wantHost:     "2001:db8::1",
			wantOrigHost: "v6-saved",
		},
		{
			name:       "5d_saved_ipv6_link_local_zone_id",
			globalOpts: globalMux,
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.args = []string{"v6-zone"}
				return o
			},
			wantJumpHost: "",
			wantHost:     "fe80::1%eth0",
			wantOrigHost: "v6-zone",
		},
		{
			name:       "6a_cli_overrides_on_saved_node",
			globalOpts: globalMux,
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.args = []string{"web-01"}
				o.User = "altuser"
				o.Port = 2299
				o.JumpHost = "edge-jump"
				o.control.Options = []string{"HostName=%h.internal"}
				return o
			},
			wantJumpHost: "edge-jump",
			wantHost:     "10.10.0.1.internal",
			wantOrigHost: "altuser@10.10.0.1:2299",
		},
		{
			name:       "6b_cli_overrides_on_openssh_alias",
			globalOpts: globalMux,
			makeOpts: func() *SshOptions {
				o := NewSshOptions()
				o.args = []string{"app-virtual"}
				o.User = "altuser"
				o.Port = 2299
				o.JumpHost = "edge-jump"
				o.control.Options = []string{"HostName=%h.internal"}
				return o
			},
			wantJumpHost: "edge-jump",
			wantHost:     "app-virtual.internal",
			wantOrigHost: "app-virtual",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runCmdP3EquivalenceScenario(t, tc, env)
		})
	}
}
